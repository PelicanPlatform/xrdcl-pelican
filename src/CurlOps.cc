/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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
#include "CurlUtil.hh"

#include <XrdCl/XrdClDefaultEnv.hh>
#include <XrdCl/XrdClLog.hh>
#include <XrdCl/XrdClXRootDResponses.hh>
#include <XrdOuc/XrdOucCRC.hh>
#include <XrdSys/XrdSysPageSize.hh>

#include <curl/curl.h>

#include <unistd.h>
#include <utility>
#include <sstream>
#include <stdexcept>
#include <iostream>

using namespace Pelican;


CurlOperation::CurlOperation(XrdCl::ResponseHandler *handler, const std::string &url,
    uint16_t timeout, XrdCl::Log *logger) :
    m_timeout(timeout),
    m_url(url),
    m_handler(handler),
    m_curl(nullptr, &curl_easy_cleanup),
    m_logger(logger)
    {}

void
CurlOperation::Fail(uint16_t errCode, uint32_t errNum, const std::string &msg)
{
    if (m_handler == nullptr) {return;}
    m_logger->Debug(kLogXrdClPelican, "curl operation failed with message: %s", msg.c_str());
    auto status = new XrdCl::XRootDStatus(XrdCl::stError, errCode, errNum, msg);
    m_handler->HandleResponse(status, nullptr);
    m_handler = nullptr;
}

size_t
CurlOperation::HeaderCallback(char *buffer, size_t size, size_t nitems, void *this_ptr)
{
    std::string header(buffer, size * nitems);
    auto rv = static_cast<CurlStatOp*>(this_ptr)->Header(header);
    return rv ? (size * nitems) : 0;
}

bool
CurlOperation::Header(const std::string &header)
{
    auto result = m_headers.Parse(header);
    if (!result) {
        m_logger->Debug(kLogXrdClPelican, "Failed to parse response header: %s", header.c_str());
    }
    if (m_headers.HeadersDone() && HTTPStatusIsError(m_headers.GetStatusCode())) {
        auto httpErr = HTTPStatusConvert(m_headers.GetStatusCode());
        Fail(httpErr.first, httpErr.second, m_headers.GetStatusMessage());
    }
    return result;
}

void
CurlOperation::Setup(CURL *curl)
{
    if (curl == nullptr) {
        throw std::runtime_error("Unable to setup curl operation with no handle");
    }
    m_curl.reset(curl);
    curl_easy_setopt(m_curl.get(), CURLOPT_TIMEOUT, m_timeout);
    curl_easy_setopt(m_curl.get(), CURLOPT_URL, m_url.c_str());
    curl_easy_setopt(m_curl.get(), CURLOPT_HEADERFUNCTION, CurlStatOp::HeaderCallback);
    curl_easy_setopt(m_curl.get(), CURLOPT_HEADERDATA, this);
}

void
CurlOperation::ReleaseHandle()
{
    if (m_curl == nullptr) return;
    m_curl.release();
}

void
CurlStatOp::Setup(CURL *curl)
{
    CurlOperation::Setup(curl);
    curl_easy_setopt(m_curl.get(), CURLOPT_NOBODY, 1L);
}

void
CurlStatOp::ReleaseHandle()
{
    if (m_curl == nullptr) return;
    curl_easy_setopt(m_curl.get(), CURLOPT_NOBODY, 0L);
    CurlOperation::ReleaseHandle();
}

void
CurlStatOp::Success()
{
    m_logger->Debug(kLogXrdClPelican, "Successful stat operation on %s", m_url.c_str());
    if (m_handler == nullptr) {return;}
    auto stat_info = new XrdCl::StatInfo("nobody", m_headers.GetContentLength(),
        XrdCl::StatInfo::Flags::IsReadable, time(NULL));
    auto obj = new XrdCl::AnyObject();
    obj->Set(stat_info);

    m_handler->HandleResponse(new XrdCl::XRootDStatus(), obj);
    m_handler = nullptr;
}

CurlReadOp::CurlReadOp(XrdCl::ResponseHandler *handler, const std::string &url, uint16_t timeout,
    const std::pair<uint64_t, uint64_t> &op, char *buffer, XrdCl::Log *logger) :
        CurlOperation(handler, url, timeout, logger),
        m_op(op),
        m_buffer(buffer, &free),
        m_header_list(nullptr, &curl_slist_free_all)
    {}

void
CurlReadOp::Setup(CURL *curl)
{
    CurlOperation::Setup(curl);
    curl_easy_setopt(m_curl.get(), CURLOPT_WRITEFUNCTION, CurlReadOp::WriteCallback);
    curl_easy_setopt(m_curl.get(), CURLOPT_WRITEDATA, this);

    // Note: range requests are inclusive of the end byte, meaning "bytes=0-1023" is a 1024-byte request.
    // This is why we subtract '1' off the end.
    auto range_req = "Range: bytes=" + std::to_string(m_op.first) + "-" + std::to_string(m_op.first + m_op.second - 1);
    m_header_list.reset(curl_slist_append(m_header_list.release(), range_req.c_str()));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, m_header_list.get());
}

void
CurlReadOp::Success()
{
    if (m_handler == nullptr) {return;}
    auto status = new XrdCl::XRootDStatus();
    auto chunk_info = new XrdCl::ChunkInfo(m_op.first, m_op.second, m_buffer.release());
    auto obj = new XrdCl::AnyObject();
    obj->Set(chunk_info);
    m_handler->HandleResponse(status, obj);
    m_handler = nullptr;
}

void
CurlReadOp::ReleaseHandle()
{
    if (m_curl == nullptr) return;
    curl_easy_setopt(m_curl.get(), CURLOPT_WRITEFUNCTION, nullptr);
    curl_easy_setopt(m_curl.get(), CURLOPT_WRITEDATA, nullptr);
    curl_easy_setopt(m_curl.get(), CURLOPT_HTTPHEADER, nullptr);
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
    //m_logger->Debug(kLogXrdClPelican, "Received a write of size %d with offset %d; total received is %d; remaining is %d", length, m_op.first, length + m_written, m_op.second - length - m_written);
    if (m_headers.IsMultipartByterange()) {
        Fail(XrdCl::errErrorResponse, kXR_ServerError, "Server responded with a multipart byterange which is not supported");
        return 0;
    }
    else if (m_headers.GetContentLength() >= 0 && static_cast<uint64_t>(m_headers.GetContentLength()) != m_op.second) {
        std::stringstream ss;
        ss << "Response (size " << m_headers.GetContentLength() << ") is not the same as request size (" << m_op.second << ")";
        Fail(XrdCl::errErrorResponse, kXR_ServerError, ss.str());
        return 0;
    }
    if (m_headers.GetOffset() != m_op.first) {
        Fail(XrdCl::errErrorResponse, kXR_ServerError, "Server did not return content with correct response");
        return 0;
    }
    if (!m_buffer) {
        m_buffer.reset(static_cast<char *>(malloc(m_op.second)));
        if (!m_buffer) {
            Fail(XrdCl::errOSError, ENOMEM, "Failed to allocate read buffer");
            return 0;
        }
    }
    if (m_written + length > m_op.second) {
        Fail(XrdCl::errInternal, 1, "Received more data than requested");
        return 0;
    }
    memcpy(m_buffer.get() + m_written, buffer, length);
    m_written += length;
    return length;
}

void                
CurlPgReadOp::Success()
{               
    if (m_handler == nullptr) {return;}
    auto status = new XrdCl::XRootDStatus();

    std::vector<uint32_t> cksums;
    size_t nbpages = m_op.second / XrdSys::PageSize;
    if (m_op.second % XrdSys::PageSize) ++nbpages;
    cksums.reserve(nbpages);

    auto buffer = m_buffer.get();
    size_t size = m_op.second;
    for (size_t pg=0; pg<nbpages; ++pg)
    {
        auto pgsize = static_cast<size_t>(XrdSys::PageSize);
        if (pgsize > size) pgsize = size;
        cksums.push_back(XrdOucCRC::Calc32C(buffer, pgsize));
        buffer += pgsize;
        size -= pgsize;
    }

    auto page_info = new XrdCl::PageInfo(m_op.first, m_op.second, m_buffer.release(), std::move(cksums));
    auto obj = new XrdCl::AnyObject();
    obj->Set(page_info);
    m_handler->HandleResponse(status, obj);
    m_handler = nullptr;
}               
