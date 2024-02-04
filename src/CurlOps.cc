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
#include "PelicanFile.hh"

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
#include <vector>

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
    if (!msg.empty()) {
        m_logger->Debug(kLogXrdClPelican, "curl operation failed with message: %s", msg.c_str());
    } else {
        m_logger->Debug(kLogXrdClPelican, "curl operation failed with status code %d", errNum);
    }
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
    // m_logger->Debug(kLogXrdClPelican, "Got header: %s", header.c_str());
    if (!result) {
        m_logger->Debug(kLogXrdClPelican, "Failed to parse response header: %s", header.c_str());
    }
    if (m_headers.HeadersDone() && HTTPStatusIsError(m_headers.GetStatusCode())) {
        auto httpErr = HTTPStatusConvert(m_headers.GetStatusCode());
        m_logger->Debug(kLogXrdClPelican, "Status code %d", m_headers.GetStatusCode());
        Fail(httpErr.first, httpErr.second, m_headers.GetStatusMessage());
    }
    return result;
}

bool
CurlOperation::Redirect()
{
    auto broker = m_headers.GetBroker();
    m_broker.reset();
    m_broker_reverse_socket = -1;
    auto location = m_headers.GetLocation();
    if (location.empty()) {
        m_logger->Warning(kLogXrdClPelican, "After request to %s, server returned a redirect with no new location", m_url.c_str());
        Fail(XrdCl::errErrorResponse, kXR_ServerError, "Server returned redirect without updated location");
        return false;
    }
    m_logger->Debug(kLogXrdClPelican, "Request for %s redirected to %s", m_url.c_str(), location.c_str());
    curl_easy_setopt(m_curl.get(), CURLOPT_URL, location.c_str());
    m_headers = HeaderParser();
    if (!broker.empty()) {
        m_broker.reset(new BrokerRequest(m_curl.get(), broker));
        std::string err;
        if (m_broker->StartRequest(err) == -1) {
            auto errMsg = "Failed to start a read request for broker " + broker + ": " + err;
            Fail(XrdCl::errInternal, 1, errMsg.c_str());
            return false;
        }
        curl_easy_setopt(m_curl.get(), CURLOPT_OPENSOCKETFUNCTION, CurlReadOp::OpenSocketCallback);
        curl_easy_setopt(m_curl.get(), CURLOPT_OPENSOCKETDATA, this);
        curl_easy_setopt(m_curl.get(), CURLOPT_SOCKOPTFUNCTION, CurlReadOp::SockOptCallback);
        curl_easy_setopt(m_curl.get(), CURLOPT_SOCKOPTDATA, this);
    }
    return true;
}

namespace {

size_t
NullCallback(char * /*buffer*/, size_t size, size_t nitems, void * /*this_ptr*/)
{
    return size * nitems;
}

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
    curl_easy_setopt(m_curl.get(), CURLOPT_WRITEFUNCTION, NullCallback);
    curl_easy_setopt(m_curl.get(), CURLOPT_WRITEDATA, nullptr);
}

void
CurlOperation::ReleaseHandle()
{
    if (m_curl == nullptr) return;
    m_curl.release();
}

curl_socket_t
CurlOperation::OpenSocketCallback(void *clientp, curlsocktype purpose, struct curl_sockaddr *address)
{
    auto me = reinterpret_cast<CurlReadOp*>(clientp);
    auto fd = me->m_broker_reverse_socket;
    if (fd == -1) {
        return CURL_SOCKET_BAD;
    } else {
        return fd;
    }
}

int
CurlOperation::SockOptCallback(void *clientp, curl_socket_t curlfd, curlsocktype purpose)
{
    return CURL_SOCKOPT_ALREADY_CONNECTED;
}

int
CurlOperation::WaitSocketCallback(std::string &err)
{
    m_broker_reverse_socket = m_broker ? m_broker->FinishRequest(err) : -1;
    m_logger->Debug(kLogXrdClPelican, "Got reverse connection on socket %d", m_broker_reverse_socket);
    return m_broker_reverse_socket;
}

bool
CurlStatOp::Redirect()
{
    auto result = CurlOperation::Redirect();
    if (m_is_pelican) {
        curl_easy_setopt(m_curl.get(), CURLOPT_NOBODY, 1L);
    }
    return result;
}

void
CurlStatOp::Setup(CURL *curl)
{
    CurlOperation::Setup(curl);
    if (m_is_pelican) {
        // In 7.4.0, there's a bug which causes the origin API endpoint
        // to return a 404 on a HEAD request.  Instead, we'll issue a GET now and
        // then, on redirect, switch to the HEAD.
        curl_easy_setopt(m_curl.get(), CURLOPT_NOBODY, 0L);
    } else {
        curl_easy_setopt(m_curl.get(), CURLOPT_NOBODY, 1L);
    }
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

CurlOpenOp::CurlOpenOp(XrdCl::ResponseHandler *handler, const std::string &url, uint16_t timeout,
    XrdCl::Log *logger, File *file)
:
    CurlStatOp(handler, url, timeout, logger, file->IsPelican()),
    m_file(file)
{}

void
CurlOpenOp::ReleaseHandle()
{
    curl_easy_setopt(m_curl.get(), CURLOPT_OPENSOCKETFUNCTION, nullptr);
    curl_easy_setopt(m_curl.get(), CURLOPT_OPENSOCKETDATA, nullptr);
    curl_easy_setopt(m_curl.get(), CURLOPT_SOCKOPTFUNCTION, nullptr);
    curl_easy_setopt(m_curl.get(), CURLOPT_SOCKOPTDATA, nullptr);
    CurlStatOp::ReleaseHandle();
}

void
CurlOpenOp::Success()
{
    char *url = nullptr;
    curl_easy_getinfo(m_curl.get(), CURLINFO_EFFECTIVE_URL, &url);
    if (url && m_file) {
        m_file->SetProperty("LastURL", url);
    }
    CurlStatOp::Success();
}

CurlReadOp::CurlReadOp(XrdCl::ResponseHandler *handler, const std::string &url, uint16_t timeout,
    const std::pair<uint64_t, uint64_t> &op, char *buffer, XrdCl::Log *logger) :
        CurlOperation(handler, url, timeout, logger),
        m_op(op),
        m_buffer(buffer),
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
    auto chunk_info = new XrdCl::ChunkInfo(m_op.first, m_written, m_buffer);
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
    //m_logger->Debug(kLogXrdClPelican, "Received a write of size %d with offset %d; total received is %d; remaining is %d", length, m_op.first, length + m_written, m_op.second - length - m_written);
    if (m_headers.IsMultipartByterange()) {
        Fail(XrdCl::errErrorResponse, kXR_ServerError, "Server responded with a multipart byterange which is not supported");
        return 0;
    }
    if (m_written == 0 && (m_headers.GetOffset() != m_op.first)) {
        Fail(XrdCl::errErrorResponse, kXR_ServerError, "Server did not return content with correct offset");
        return 0;
    }
    if (m_written + length > m_op.second) { // We don't have enough space in the buffer to write the resp.
        Fail(XrdCl::errErrorResponse, kXR_ServerError, "Server sent back more data than requested");
    }
    memcpy(m_buffer + m_written, buffer, length);
    m_written += length;
    return length;
}

void                
CurlPgReadOp::Success()
{               
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
    m_handler->HandleResponse(status, obj);
    m_handler = nullptr;
}               
