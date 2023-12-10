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

#include "XrdClCurlUtil.hh"

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

thread_local std::vector<CURL*> HandlerQueue::m_handles;

namespace {

bool HTTPStatusIsError(unsigned status) {
     return (status < 100) || (status >= 400);
}

std::pair<uint16_t, uint32_t> HTTPStatusConvert(unsigned status) {
    //std::cout << "HTTPStatusConvert: " << status << "\n";
    switch (status) {
        case 400: // Bad Request
            return std::make_pair(XrdCl::errErrorResponse, kXR_InvalidRequest);
        case 401: // Unauthorized (needs authentication)
            return std::make_pair(XrdCl::errErrorResponse, kXR_NotAuthorized);
        case 402: // Payment Required
        case 403: // Forbidden (failed authorization)
            return std::make_pair(XrdCl::errErrorResponse, kXR_NotAuthorized);
        case 404:
            return std::make_pair(XrdCl::errErrorResponse, kXR_NotFound);
        case 405: // Method not allowed
        case 406: // Not acceptable
            return std::make_pair(XrdCl::errErrorResponse, kXR_InvalidRequest);
        case 407: // Proxy Authentication Required
            return std::make_pair(XrdCl::errErrorResponse, kXR_NotAuthorized);
        case 408: // Request timeout
            return std::make_pair(XrdCl::errErrorResponse, kXR_ReqTimedOut);
        case 409: // Conflict
            return std::make_pair(XrdCl::errErrorResponse, kXR_Conflict);
        case 410: // Gone
            return std::make_pair(XrdCl::errErrorResponse, kXR_NotFound);
        case 411: // Length required
        case 412: // Precondition failed
        case 413: // Payload too large
        case 414: // URI too long
        case 415: // Unsupported Media Type
        case 416: // Range Not Satisfiable
        case 417: // Expectation Failed
        case 418: // I'm a teapot
	    return std::make_pair(XrdCl::errErrorResponse, kXR_InvalidRequest);
        case 421: // Misdirected Request
        case 422: // Unprocessable Content
            return std::make_pair(XrdCl::errErrorResponse, kXR_InvalidRequest);
        case 423: // Locked
            return std::make_pair(XrdCl::errErrorResponse, kXR_FileLocked);
        case 424: // Failed Dependency
        case 425: // Too Early
        case 426: // Upgrade Required
        case 428: // Precondition Required
            return std::make_pair(XrdCl::errErrorResponse, kXR_InvalidRequest);
        case 429: // Too Many Requests
            return std::make_pair(XrdCl::errErrorResponse, kXR_Overloaded);
        case 431: // Request Header Fields Too Large
            return std::make_pair(XrdCl::errErrorResponse, kXR_InvalidRequest);
        case 451: // Unavailable For Legal Reasons
            return std::make_pair(XrdCl::errErrorResponse, kXR_Impossible);
        case 500: // Internal Server Error
        case 501: // Not Implemented
        case 502: // Bad Gateway
        case 503: // Service Unavailable
            return std::make_pair(XrdCl::errErrorResponse, kXR_ServerError);
        case 504: // Gateway Timeout
            return std::make_pair(XrdCl::errErrorResponse, kXR_ReqTimedOut);
        case 507: // Insufficient Storage
            return std::make_pair(XrdCl::errErrorResponse, kXR_overQuota);
        case 508: // Loop Detected
        case 510: // Not Extended
        case 511: // Network Authentication Required
            return std::make_pair(XrdCl::errErrorResponse, kXR_ServerError);
    }
    return std::make_pair(XrdCl::errUnknown, status);
}

std::pair<uint16_t, uint32_t> CurlCodeConvert(CURLcode res) {
    switch (res) {
        case CURLE_OK:
            return std::make_pair(XrdCl::errNone, 0);
        case CURLE_COULDNT_RESOLVE_PROXY:
        case CURLE_COULDNT_RESOLVE_HOST:
            return std::make_pair(XrdCl::errInvalidAddr, 0);
        case CURLE_LOGIN_DENIED:
        // Commented-out cases are for platforms (RHEL7) where the error
        // codes are undefined.
        //case CURLE_AUTH_ERROR:
        //case CURLE_SSL_CLIENTCERT:
        case CURLE_REMOTE_ACCESS_DENIED:
            return std::make_pair(XrdCl::errLoginFailed, EACCES);
        case CURLE_SSL_CONNECT_ERROR:
        case CURLE_SSL_ENGINE_NOTFOUND:
        case CURLE_SSL_ENGINE_SETFAILED:
        case CURLE_SSL_CERTPROBLEM:
        case CURLE_SSL_CIPHER:
        case CURLE_PEER_FAILED_VERIFICATION:
        case CURLE_SSL_SHUTDOWN_FAILED:
        case CURLE_SSL_CRL_BADFILE:
        case CURLE_SSL_ISSUER_ERROR:
        //case CURLE_SSL_PINNEDPUBKEYNOTMATCH:
        //case CURLE_SSL_INVALIDCERTSTATUS:
            return std::make_pair(XrdCl::errTlsError, 0);
        case CURLE_SEND_ERROR:
        case CURLE_RECV_ERROR:
            return std::make_pair(XrdCl::errSocketError, EIO);
        case CURLE_COULDNT_CONNECT:
        case CURLE_GOT_NOTHING:
            return std::make_pair(XrdCl::errConnectionError, ECONNREFUSED);
        case CURLE_OPERATION_TIMEDOUT:
            return std::make_pair(XrdCl::errOperationExpired, ETIMEDOUT);
        case CURLE_UNSUPPORTED_PROTOCOL:
        case CURLE_NOT_BUILT_IN:
            return std::make_pair(XrdCl::errNotSupported, ENOSYS);
        case CURLE_FAILED_INIT:
            return std::make_pair(XrdCl::errInternal, 0);
        case CURLE_URL_MALFORMAT:
            return std::make_pair(XrdCl::errInvalidArgs, res);
        //case CURLE_WEIRD_SERVER_REPLY:
        //case CURLE_HTTP2:
        //case CURLE_HTTP2_STREAM:
            return std::make_pair(XrdCl::errCorruptedHeader, res);
        case CURLE_PARTIAL_FILE:
            return std::make_pair(XrdCl::errDataError, res);
        // These two errors indicate a failure in the callback.  That
        // should generate their own failures, meaning this should never
        // get use.
        case CURLE_READ_ERROR:
        case CURLE_WRITE_ERROR:
            return std::make_pair(XrdCl::errInternal, res);
        case CURLE_RANGE_ERROR:
        case CURLE_BAD_CONTENT_ENCODING:
            return std::make_pair(XrdCl::errNotSupported, res);
        case CURLE_TOO_MANY_REDIRECTS:
            return std::make_pair(XrdCl::errRedirectLimit, res);
        default:
            return std::make_pair(XrdCl::errUnknown, res);
    }
}

}

bool HeaderParser::Parse(const std::string &headers)
{
    if (m_recv_all_headers) {
        m_recv_all_headers = false;
        m_recv_status_line = false;
    }

    if (!m_recv_status_line) {
        m_recv_status_line = true;

        std::stringstream ss(headers);
        std::string item;
        if (!std::getline(ss, item, ' ')) return false;
        m_resp_protocol = item;
        if (!std::getline(ss, item, ' ')) return false;
        try {
            m_status_code = std::stol(item);
        } catch (...) {
            return false;
        }
        if (m_status_code < 100 || m_status_code >= 600) {
            return false;
        }
        if (!std::getline(ss, item, '\n')) return false;
        m_resp_message = item;
        return true;
    }

    if (headers.empty() || headers == "\n" || headers == "\r\n") {
        m_recv_all_headers = true;
        return true;
    }

    auto found = headers.find(":");
    if (found == std::string::npos) {
        return false;
    }

    std::string header_name = headers.substr(0, found);
    if (!Canonicalize(header_name)) {
        return false;
    }

    found += 1;
    while (found < headers.size()) {
        if (headers[found] != ' ') {break;}
        found += 1;
    }
    std::string header_value = headers.substr(found);
    // Note: ignoring the fact headers are only supposed to contain ASCII.
    // We should trim out UTF-8.
    header_value.erase(header_value.find_last_not_of(" \r\n\t") + 1);

    auto iter = m_header_map.find("header_name");
    if (iter == m_header_map.end()) {
        m_header_map.emplace(std::make_pair(header_value, std::vector<std::string>({header_value})));
    } else {
        iter->second.emplace_back(header_value);
    }

    if (header_name == "Content-Length") {
         try {
             m_content_length = std::stoll(header_value);
         } catch (...) {
             return false;
         }
    }
    else if (header_name == "Content-Type") {
        auto found = header_value.find(";");
        std::string first_type = header_value.substr(0, found);
        m_multipart_byteranges = first_type == "multipart/byteranges";
    }
    else if (header_name == "Content-Range") {
        auto found = header_value.find(" ");
        if (found == std::string::npos) {
            return false;
        }
        std::string range_unit = header_value.substr(0, found);
        if (range_unit != "bytes") {
            return false;
        }
        auto range_resp = header_value.substr(found + 1);
        found = range_resp.find("/");
        if (found == std::string::npos) {
            return false;
        }
        auto incl_range = range_resp.substr(0, found);
        found = incl_range.find("-");
        if (found == std::string::npos) {
            return false;
        }
        auto first_pos = incl_range.substr(0, found);
        try {
            m_response_offset = std::stoll(first_pos);
        } catch (...) {
           return false;
        }
        auto last_pos = incl_range.substr(found + 1);
        size_t last_byte;
        try {
           last_byte = std::stoll(last_pos);
        } catch (...) {
           return false;
        }
        m_content_length = last_byte - m_response_offset + 1;
    }
    return true;
}

// This clever approach was inspired by golang's net/textproto
bool HeaderParser::validHeaderByte(unsigned char c)
{
    const static uint64_t mask_lower = 0 |
        uint64_t((1<<10)-1) << '0' |
        uint64_t(1) << '!' |
        uint64_t(1) << '#' |
        uint64_t(1) << '$' |
        uint64_t(1) << '%' |
        uint64_t(1) << '&' |
        uint64_t(1) << '\'' |
        uint64_t(1) << '*' |
        uint64_t(1) << '+' |
        uint64_t(1) << '-' |
        uint64_t(1) << '.';

    const static uint64_t mask_upper = 0 |
        uint64_t((1<<26)-1) << ('a'-64) |
        uint64_t((1<<26)-1) << ('A'-64) |
        uint64_t(1) << ('^'-64) |
        uint64_t(1) << ('_'-64) |
        uint64_t(1) << ('`'-64) |
        uint64_t(1) << ('|'-64) |
        uint64_t(1) << ('~'-64);

    if (c >= 128) return false;
    if (c >= 64) return (uint64_t(1)<<(c-64)) & mask_upper;
    return (uint64_t(1) << c) & mask_lower;
}

bool HeaderParser::Canonicalize(std::string &headerName)
{
    auto upper = true;
    const static int toLower = 'a' - 'A';
    for (size_t idx=0; idx<headerName.size(); idx++) {
        char c = headerName[idx];
        if (!validHeaderByte(c)) {
            return false;
        }
        if (upper && 'a' <= c && c <= 'z') {
            c -= toLower;
        } else if (!upper && 'A' <= c && c <= 'Z') {
            c += toLower;
        }
        headerName[idx] = c;
        upper = c == '-';
    }
    return true;
}

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

HandlerQueue::HandlerQueue() {
    int filedes[2];
    auto result = pipe(filedes);
    if (result == -1) {
        throw std::runtime_error(strerror(errno));
    }
    m_read_fd = filedes[0];
    m_write_fd = filedes[1];
};

CURL *
HandlerQueue::GetHandle() {
    if (m_handles.size()) {
        auto result = m_handles.back();
        m_handles.pop_back();
        return result;
    }
    auto result = curl_easy_init();
    if (result == nullptr) {
        return result;
    }

    curl_easy_setopt(result, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(result, CURLOPT_USERAGENT, "xrdcl-pelican/1.0");

    auto env = XrdCl::DefaultEnv::GetEnv();
    std::string ca_file;
    if (!env->GetString("PelicanCAFile", ca_file)) {
        char *x509_ca_file = getenv("X509_CA_FILE");
        if (x509_ca_file) {
            ca_file = std::string(x509_ca_file);
        }
    }
    if (!ca_file.empty()) {
        curl_easy_setopt(result, CURLOPT_CAINFO, ca_file.c_str());
    }
    std::string ca_dir;
    if (!env->GetString("PelicanCADir", ca_dir)) {
        char *x509_ca_dir = getenv("X509_CA_DIR");
        if (x509_ca_dir) {
            ca_dir = std::string(x509_ca_dir);
        }
    }
    if (!ca_dir.empty()) {
        curl_easy_setopt(result, CURLOPT_CAPATH, ca_dir.c_str());
    }

    curl_easy_setopt(result, CURLOPT_BUFFERSIZE, 32*1024);

    return result;
}

void
HandlerQueue::RecycleHandle(CURL *curl) {
    m_handles.push_back(curl);
}

void
HandlerQueue::Produce(std::unique_ptr<CurlOperation> handler)
{
    std::unique_lock<std::mutex> lk{m_mutex};
    m_cv.wait(lk, [&]{return m_ops.size() < m_max_pending_ops;});

    m_ops.push_back(std::move(handler));
    char ready[] = "1";
    while (true) {
        auto result = write(m_write_fd, ready, 1);
        if (result == -1) {
            if (errno == EINTR) {
                continue;
            }
            throw std::runtime_error(strerror(errno));
        }
        break;
    }

    lk.unlock();
    m_cv.notify_one();
}

std::unique_ptr<CurlOperation>
HandlerQueue::Consume()
{
    std::unique_lock<std::mutex> lk(m_mutex);
    m_cv.wait(lk, [&]{return m_ops.size() > 0;});

    auto result = std::move(m_ops.front());
    m_ops.pop_front();

    char ready[1];
    while (true) {
        auto result = read(m_read_fd, ready, 1);
        if (result == -1) {
            if (errno == EINTR) {
                continue;
            }
            throw std::runtime_error(strerror(errno));
        }
        break;
    }

    lk.unlock();
    m_cv.notify_one();

    return result;
}

std::unique_ptr<CurlOperation>
HandlerQueue::TryConsume()
{
    std::unique_lock<std::mutex> lk(m_mutex);
    if (m_ops.size() == 0) {
        std::unique_ptr<CurlOperation> result;
        return result;
    }

    auto result = std::move(m_ops.front());
    m_ops.pop_front();

    char ready[1];
    while (true) {
        auto result = read(m_read_fd, ready, 1); 
        if (result == -1) {
            if (errno == EINTR) {
                continue;
            }   
            throw std::runtime_error(strerror(errno));
        }   
        break;
    }

    lk.unlock();
    m_cv.notify_one();

    return result;
}

void
CurlWorker::RunStatic(CurlWorker *myself)
{
    try {
        myself->Run();
    } catch (...) {
        myself->m_logger->Debug(kLogXrdClPelican, "Curl worker got an exception");
    }
}

void
CurlWorker::Run() {
    auto &queue = *m_queue.get();
    m_logger->Debug(kLogXrdClPelican, "Started a curl worker");

    CURLM *multi_handle = curl_multi_init();
    if (multi_handle == nullptr) {
        throw std::runtime_error("Failed to create curl multi-handle");
    }

    int running_handles = 0;
    time_t last_marker = time(NULL);
    CURLMcode mres = CURLM_OK;

    while (true) {
        while (running_handles < static_cast<int>(m_max_ops)) {
            auto op = running_handles == 0 ? queue.Consume() : queue.TryConsume();
            if (!op) {
                break;
            }
            auto curl = queue.GetHandle();
            if (curl == nullptr) {
                op->Fail(XrdCl::errInternal, ENOMEM, "Unable to get allocate a curl handle");
                continue;
            }
            try {
                op->Setup(curl);
            } catch (...) {
                op->Fail(XrdCl::errInternal, ENOMEM, "Failed to setup the curl handle for the operation");
                continue;
            }
            m_op_map[curl] = std::move(op);
            auto mres = curl_multi_add_handle(multi_handle, curl);
            if (mres != CURLM_OK) {
                op->Fail(XrdCl::errInternal, mres, "Unable to add operation to the curl multi-handle");
                continue;
            }
            running_handles += 1;
        }

        // Maintain the periodic reporting of thread activity
        time_t now = time(NULL);
        time_t next_marker = last_marker + m_marker_period;
        if (now >= next_marker) {
            m_logger->Debug(kLogXrdClPelican, "Curl worker thread is running %d operations",
                running_handles);
            last_marker = now;
        }

        // Wait until there is activity to perform.
        int64_t max_sleep_time = next_marker - now;
        if (max_sleep_time > 0) {
            struct curl_waitfd read_fd;
            read_fd.fd = queue.PollFD();
            read_fd.events = CURL_WAIT_POLLIN;
            read_fd.revents = 0;
            mres = curl_multi_wait(multi_handle, &read_fd, 1, max_sleep_time*1000, nullptr);
            if (mres != CURLM_OK) {
                m_logger->Warning(kLogXrdClPelican, "Failed to wait on multi-handle: %d", mres);
            }
        }

        // Do maintenance on the multi-handle
        int still_running;
        auto mres = curl_multi_perform(multi_handle, &still_running);
        if (mres == CURLM_CALL_MULTI_PERFORM) {
            continue;
        } else if (mres != CURLM_OK) {
            m_logger->Warning(kLogXrdClPelican, "Failed to perform multi-handle operation: %d", mres);
            break;
        }

        CURLMsg *msg;
        do {
            int msgq = 0;
            msg = curl_multi_info_read(multi_handle, &msgq);
            if (msg && (msg->msg == CURLMSG_DONE)) {
                auto iter = m_op_map.find(msg->easy_handle);
                if (iter == m_op_map.end()) {
                    m_logger->Error(kLogXrdClPelican, "Logic error: got a callback for an entry that doesn't exist");
                    mres = CURLM_BAD_EASY_HANDLE;
                    break;
                }
                auto &op = iter->second;
                auto res = msg->data.result;
                if (res == CURLE_OK) {
                    op->Success();
                    op->ReleaseHandle();
                    // If the handle was successful, then we can recycle it.
                    queue.RecycleHandle(iter->first);
                } else {
                    auto xrdCode = CurlCodeConvert(res);
                    op->Fail(xrdCode.first, xrdCode.second, curl_easy_strerror(res));
                    op->ReleaseHandle();
                }
                curl_multi_remove_handle(multi_handle, iter->first);
                if (res != CURLE_OK) {
                    curl_easy_cleanup(iter->first);
                }
                m_op_map.erase(iter);
                running_handles -= 1;
            }
        } while (msg);
    }

    for (auto &map_entry : m_op_map) {
        map_entry.second->Fail(XrdCl::errInternal, mres, curl_multi_strerror(mres));
    }
    m_op_map.clear();
}

