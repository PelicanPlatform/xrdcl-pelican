/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

#include "CurlOps.hh"

#include <XrdCl/XrdClLog.hh>
#include <XrdCl/XrdClXRootDResponses.hh>
#include <XrdOuc/XrdOucCRC.hh>
#include <XrdSys/XrdSysPageSize.hh>

using namespace XrdClCurl;

CurlReadOp::CurlReadOp(XrdCl::ResponseHandler *handler, const std::string &url, struct timespec timeout,
    const std::pair<uint64_t, uint64_t> &op, char *buffer, XrdCl::Log *logger, CreateConnCalloutType callout) :
        CurlOperation(handler, url, timeout, logger, callout),
        m_op(op),
        m_buffer(buffer),
        m_header_list(nullptr, &curl_slist_free_all)
    {}

bool
CurlReadOp::Setup(CURL *curl, CurlWorker &worker)
{
    if (!CurlOperation::Setup(curl, worker)) {return false;}

    curl_easy_setopt(m_curl.get(), CURLOPT_WRITEFUNCTION, CurlReadOp::WriteCallback);
    curl_easy_setopt(m_curl.get(), CURLOPT_WRITEDATA, this);

    // Note: range requests are inclusive of the end byte, meaning "bytes=0-1023" is a 1024-byte request.
    // This is why we subtract '1' off the end.
    if (m_op.second == 0) {
        Success();
        return true;
    }
    auto range_req = "Range: bytes=" + std::to_string(m_op.first) + "-" + std::to_string(m_op.first + m_op.second - 1);
    m_header_list.reset(curl_slist_append(m_header_list.release(), range_req.c_str()));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, m_header_list.get());

    return true;
}

void
CurlReadOp::Fail(uint16_t errCode, uint32_t errNum, const std::string &msg)
{
    std::string custom_msg = msg;
    SetDone(true);
    if (m_handler == nullptr) {return;}
    if (!custom_msg.empty()) {
        m_logger->Debug(kLogXrdClCurl, "curl operation at offset %llu failed with message: %s", static_cast<long long unsigned>(m_op.first), msg.c_str());
        custom_msg += " (read operation at offset " + std::to_string(static_cast<long long unsigned>(m_op.first)) + ")";
    } else {
        m_logger->Debug(kLogXrdClCurl, "curl operation at offset %llu failed with status code %d", static_cast<long long unsigned>(m_op.first), errNum);
    }
    auto status = new XrdCl::XRootDStatus(XrdCl::stError, errCode, errNum, custom_msg);
    auto handle = m_handler;
    m_handler = nullptr;
    handle->HandleResponse(status, nullptr);
}

void
CurlReadOp::Success()
{
    SetDone(false);
    if (m_handler == nullptr) {return;}
    auto status = new XrdCl::XRootDStatus();
    auto chunk_info = new XrdCl::ChunkInfo(m_op.first, m_written, m_buffer);
    auto obj = new XrdCl::AnyObject();
    obj->Set(chunk_info);
    auto handle = m_handler;
    m_handler = nullptr;
    handle->HandleResponse(status, obj);
}

void
CurlReadOp::ReleaseHandle()
{
    if (m_curl == nullptr) return;
    curl_easy_setopt(m_curl.get(), CURLOPT_WRITEFUNCTION, nullptr);
    curl_easy_setopt(m_curl.get(), CURLOPT_WRITEDATA, nullptr);
    curl_easy_setopt(m_curl.get(), CURLOPT_HTTPHEADER, nullptr);
    curl_easy_setopt(m_curl.get(), CURLOPT_OPENSOCKETFUNCTION, nullptr);
    curl_easy_setopt(m_curl.get(), CURLOPT_OPENSOCKETDATA, nullptr);
    curl_easy_setopt(m_curl.get(), CURLOPT_SOCKOPTFUNCTION, nullptr);
    curl_easy_setopt(m_curl.get(), CURLOPT_SOCKOPTDATA, nullptr);
    m_header_list.reset();
    CurlOperation::ReleaseHandle();
}

size_t
CurlReadOp::WriteCallback(char *buffer, size_t size, size_t nitems, void *this_ptr)
{
    return static_cast<CurlReadOp*>(this_ptr)->Write(buffer, size * nitems);
}

size_t
CurlReadOp::Write(char *buffer, size_t length)
{
    //m_logger->Debug(kLogXrdClCurl, "Received a write of size %ld with offset %lld; total received is %ld; remaining is %ld", static_cast<long>(length), static_cast<long long>(m_op.first), static_cast<long>(length + m_written), static_cast<long>(m_op.second - length - m_written));
    if (m_headers.IsMultipartByterange()) {
        return FailCallback(kXR_ServerError, "Server responded with a multipart byterange which is not supported");
    }
    if (m_written == 0 && (m_headers.GetOffset() != m_op.first)) {
        return FailCallback(kXR_ServerError, "Server did not return content with correct offset");
    }
    if (m_written + length > m_op.second) { // We don't have enough space in the buffer to write the resp.
        return FailCallback(kXR_ServerError, "Server sent back more data than requested");
    }
    memcpy(m_buffer + m_written, buffer, length);
    m_written += length;
    return length;
}

void                
CurlPgReadOp::Success()
{               
    SetDone(false);
    if (m_handler == nullptr) {return;}
    auto status = new XrdCl::XRootDStatus();

    std::vector<uint32_t> cksums;
    size_t nbpages = m_written / XrdSys::PageSize;
    if (m_written % XrdSys::PageSize) ++nbpages;
    cksums.reserve(nbpages);

    auto buffer = m_buffer;
    size_t size = m_written;
    for (size_t pg=0; pg<nbpages; ++pg)
    {
        auto pgsize = static_cast<size_t>(XrdSys::PageSize);
        if (pgsize > size) pgsize = size;
        cksums.push_back(XrdOucCRC::Calc32C(buffer, pgsize));
        buffer += pgsize;
        size -= pgsize;
    }

    auto page_info = new XrdCl::PageInfo(m_op.first, m_written, m_buffer, std::move(cksums));
    auto obj = new XrdCl::AnyObject();
    obj->Set(page_info);
    auto handle = m_handler;
    m_handler = nullptr;
    handle->HandleResponse(status, obj);
}
