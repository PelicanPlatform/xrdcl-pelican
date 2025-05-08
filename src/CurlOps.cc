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
#include "CurlResponses.hh"
#include "CurlUtil.hh"
#include "CurlWorker.hh"
#include "OptionsCache.hh"
#include "CurlFile.hh"

#include <XrdCl/XrdClDefaultEnv.hh>
#include <XrdCl/XrdClLog.hh>
#include <XrdCl/XrdClXRootDResponses.hh>

#include <curl/curl.h>
#include <tinyxml2.h>

#include <unistd.h>
#include <cmath>
#include <utility>
#include <sstream>
#include <stdexcept>
#include <vector>

using namespace XrdClCurl;

std::chrono::steady_clock::duration CurlOperation::m_stall_interval{CurlOperation::m_default_stall_interval};
int CurlOperation::m_minimum_transfer_rate{CurlOperation::m_default_minimum_rate};

std::chrono::steady_clock::time_point CalculateExpiry(struct timespec timeout) {
    if (timeout.tv_sec == 0 && timeout.tv_nsec == 0) {
        return std::chrono::steady_clock::now() + std::chrono::seconds(30);
    }
    return std::chrono::steady_clock::now() + std::chrono::seconds(timeout.tv_sec) + std::chrono::nanoseconds(timeout.tv_nsec);
}

CurlOperation::CurlOperation(XrdCl::ResponseHandler *handler, const std::string &url,
    struct timespec timeout, XrdCl::Log *logger) :
    CurlOperation::CurlOperation(handler, url, CalculateExpiry(timeout), logger)
    {}

CurlOperation::CurlOperation(XrdCl::ResponseHandler *handler, const std::string &url,
    std::chrono::steady_clock::time_point expiry, XrdCl::Log *logger) :
    m_header_expiry(expiry),
    m_url(url),
    m_handler(handler),
    m_curl(nullptr, &curl_easy_cleanup),
    m_logger(logger)
    {}

CurlOperation::~CurlOperation() {
    if (m_broker_reverse_socket != -1) {
        close(m_broker_reverse_socket);
    }
}

void
CurlOperation::Fail(uint16_t errCode, uint32_t errNum, const std::string &msg)
{
    SetDone(true);
    if (m_handler == nullptr) {return;}
    if (!msg.empty()) {
        m_logger->Debug(kLogXrdClCurl, "curl operation failed with message: %s", msg.c_str());
    } else {
        m_logger->Debug(kLogXrdClCurl, "curl operation failed with status code %d", errNum);
    }
    auto status = new XrdCl::XRootDStatus(XrdCl::stError, errCode, errNum, msg);
    auto handle = m_handler;
    m_handler = nullptr;
    handle->HandleResponse(status, nullptr);
}

int
CurlOperation::FailCallback(XErrorCode ecode, const std::string &emsg) {
    m_callback_error_code = ecode;
    m_callback_error_str = emsg;
    m_error = OpError::ErrCallback;
    m_logger->Debug(kLogXrdClCurl, "%s", emsg.c_str());
    return 0;
}

size_t
CurlOperation::HeaderCallback(char *buffer, size_t size, size_t nitems, void *this_ptr)
{
    std::string header(buffer, size * nitems);
    auto me = static_cast<CurlOperation*>(this_ptr);
    me->m_received_header = true;
    me->m_header_lastop = std::chrono::steady_clock::now();
    auto rv = me->Header(header);
    return rv ? (size * nitems) : 0;
}

bool
CurlOperation::Header(const std::string &header)
{
    auto result = m_headers.Parse(header);
    // m_logger->Debug(kLogXrdClPelican, "Got header: %s", header.c_str());
    if (!result) {
        m_logger->Debug(kLogXrdClCurl, "Failed to parse response header: %s", header.c_str());
    }
    if (m_headers.HeadersDone()) {
        if (!m_response_info) {
            m_response_info.reset(new ResponseInfo());
        }
        m_response_info->AddResponse(m_headers.MoveHeaders());
    }
    return result;
}

CurlOperation::RedirectAction
CurlOperation::Redirect(std::string &target)
{
    auto broker = m_headers.GetBroker();
    m_broker.reset();
    m_broker_reverse_socket = -1;
    auto location = m_headers.GetLocation();
    if (location.empty()) {
        m_logger->Warning(kLogXrdClCurl, "After request to %s, server returned a redirect with no new location", m_url.c_str());
        Fail(XrdCl::errErrorResponse, kXR_ServerError, "Server returned redirect without updated location");
        return RedirectAction::Fail;
    }
    m_logger->Debug(kLogXrdClCurl, "Request for %s redirected to %s", m_url.c_str(), location.c_str());
    target = location;
    curl_easy_setopt(m_curl.get(), CURLOPT_URL, location.c_str());
    std::tie(m_mirror_url, m_mirror_depth) = m_headers.GetMirrorInfo();
    if (m_headers.GetX509Auth()) {
        m_x509_auth = true;
        auto env = XrdCl::DefaultEnv::GetEnv();
        std::string cert, key;
        m_logger->Debug(kLogXrdClCurl, "Will use client X509 auth for future operations");
        env->GetString("PelicanClientCertFile", cert);
        env->GetString("PelicanClientKeyFile", key);
        if (!cert.empty())
            curl_easy_setopt(m_curl.get(), CURLOPT_SSLCERT, cert.c_str());
        if (!key.empty())
            curl_easy_setopt(m_curl.get(), CURLOPT_SSLKEY, key.c_str());
    }
    m_headers = HeaderParser();
    if (!broker.empty()) {
        m_broker_url = broker;
        m_broker.reset(new BrokerRequest(m_curl.get(), broker));
        std::string err;
        if (m_broker->StartRequest(err) == -1) {
            auto errMsg = "Failed to start a read request for broker " + broker + ": " + err;
            Fail(XrdCl::errInternal, 1, errMsg.c_str());
            return RedirectAction::Fail;
        }
        curl_easy_setopt(m_curl.get(), CURLOPT_OPENSOCKETFUNCTION, CurlReadOp::OpenSocketCallback);
        curl_easy_setopt(m_curl.get(), CURLOPT_OPENSOCKETDATA, this);
        curl_easy_setopt(m_curl.get(), CURLOPT_SOCKOPTFUNCTION, CurlReadOp::SockOptCallback);
        curl_easy_setopt(m_curl.get(), CURLOPT_SOCKOPTDATA, this);
    }
    return RedirectAction::Reinvoke;
}

namespace {

size_t
NullCallback(char * /*buffer*/, size_t size, size_t nitems, void * /*this_ptr*/)
{
    return size * nitems;
}

}

bool
CurlOperation::StartBroker(std::string &err)
{
    if (m_broker_url.empty()) {
        err = "Broker URL is not set";
        Fail(XrdCl::errInternal, 1, err.c_str());
        return false;
    }
    if (m_broker->StartRequest(err) == -1) {
        err = "Failed to start a read request for broker " + m_broker_url + ": " + err;
        Fail(XrdCl::errInternal, 1, err.c_str());
        return false;
    }
    return true;
}

bool
CurlOperation::HeaderTimeoutExpired(const std::chrono::steady_clock::time_point &now) {
    if (m_received_header) return false;

    if (now > m_header_expiry) {
        if (m_error == OpError::ErrNone) m_error = OpError::ErrHeaderTimeout;
        return true;
    }
    return false;
}

bool
CurlOperation::OperationTimeoutExpired(const std::chrono::steady_clock::time_point &now) {
    if (m_operation_expiry == std::chrono::steady_clock::time_point{} ||
        !m_received_header) {
        return false;
    }

    if (now > m_operation_expiry) {
        if (m_error == OpError::ErrNone) m_error = OpError::ErrOperationTimeout;
        return true;
    }
    return false;
}

bool
CurlOperation::TransferStalled(uint64_t xfer, const std::chrono::steady_clock::time_point &now)
{
    // First, check to see how long it's been since any data was sent.
    if (m_last_xfer == std::chrono::steady_clock::time_point()) {
        m_last_xfer = m_header_lastop;
    }
    auto elapsed = now - m_last_xfer;
    uint64_t xfer_diff = 0;
    if (xfer > m_last_xfer_count) {
        xfer_diff = xfer - m_last_xfer_count;
        m_last_xfer_count = xfer;
        m_last_xfer = now;
    }
    if (elapsed > m_stall_interval) {
        if (m_error == OpError::ErrNone) m_error = OpError::ErrTransferStall;
        return true;
    }
    if (xfer_diff == 0) {
        // Curl updated us with new timing but the byte count hasn't changed; no need to update the EMA.
        return false;
    }

    // If the transfer is not stalled, then we check to see if the exponentially-weighted
    // moving average of the transfer rate is below the minimum.

    // If the stall interval since the last header hasn't passed, then we don't check for slow transfers.
    auto elapsed_since_last_headerop = now - m_header_lastop;
    if (elapsed_since_last_headerop < m_stall_interval) {
        return false;
    } else if (m_ema_rate < 0) {
        m_ema_rate = xfer / std::chrono::duration<double>(elapsed_since_last_headerop).count();
    }
    // Calculate the exponential moving average of the transfer rate.
    double elapsed_seconds = std::chrono::duration<double>(elapsed).count();
    auto recent_rate = static_cast<double>(xfer_diff) / elapsed_seconds;
    auto alpha = 1.0 - exp(-elapsed_seconds / std::chrono::duration<double>(m_stall_interval).count());
    m_ema_rate = (1.0 - alpha) * m_ema_rate + alpha * recent_rate;
    if (recent_rate < static_cast<double>(m_minimum_rate)) {
        if (m_error == OpError::ErrNone) m_error = OpError::ErrTransferSlow;
        return true;
    }
    return false;
}

void
CurlOperation::Setup(CURL *curl, CurlWorker &worker)
{
    if (curl == nullptr) {
        throw std::runtime_error("Unable to setup curl operation with no handle");
    }
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
        throw std::runtime_error("Unable to get current time");
    }

    m_header_lastop = std::chrono::steady_clock::now();

    m_curl.reset(curl);
    curl_easy_setopt(m_curl.get(), CURLOPT_URL, m_url.c_str());
    curl_easy_setopt(m_curl.get(), CURLOPT_HEADERFUNCTION, CurlStatOp::HeaderCallback);
    curl_easy_setopt(m_curl.get(), CURLOPT_HEADERDATA, this);
    curl_easy_setopt(m_curl.get(), CURLOPT_WRITEFUNCTION, NullCallback);
    curl_easy_setopt(m_curl.get(), CURLOPT_WRITEDATA, nullptr);
    curl_easy_setopt(m_curl.get(), CURLOPT_XFERINFOFUNCTION, CurlOperation::XferInfoCallback);
    curl_easy_setopt(m_curl.get(), CURLOPT_XFERINFODATA, this);
    curl_easy_setopt(m_curl.get(), CURLOPT_NOPROGRESS, 0L);
    // Note: libcurl is not threadsafe unless this option is set.
    // Before we set it, we saw deadlocks (and partial deadlocks) in practice.
    curl_easy_setopt(m_curl.get(), CURLOPT_NOSIGNAL, 1L);

    m_parsed_url.reset(new XrdCl::URL(m_url));
    if (m_x509_auth || worker.UseX509Auth(*m_parsed_url)) {
        auto [cert, key] = worker.ClientX509CertKeyFile();
        curl_easy_setopt(m_curl.get(), CURLOPT_SSLCERT, cert.c_str());
        curl_easy_setopt(m_curl.get(), CURLOPT_SSLKEY, key.c_str());
    }

    if (!m_broker_url.empty()) {
        m_broker.reset(new BrokerRequest(m_curl.get(), m_broker_url));
        curl_easy_setopt(m_curl.get(), CURLOPT_OPENSOCKETFUNCTION, CurlReadOp::OpenSocketCallback);
        curl_easy_setopt(m_curl.get(), CURLOPT_OPENSOCKETDATA, this);
        curl_easy_setopt(m_curl.get(), CURLOPT_SOCKOPTFUNCTION, CurlReadOp::SockOptCallback);
        curl_easy_setopt(m_curl.get(), CURLOPT_SOCKOPTDATA, this);
    }
}

void
CurlOperation::ReleaseHandle()
{
    if (m_curl == nullptr) return;
    curl_easy_setopt(m_curl.get(), CURLOPT_SSLCERT, nullptr);
    curl_easy_setopt(m_curl.get(), CURLOPT_SSLKEY, nullptr);
    m_curl.release();
}

curl_socket_t
CurlOperation::OpenSocketCallback(void *clientp, curlsocktype purpose, struct curl_sockaddr *address)
{
    auto me = reinterpret_cast<CurlReadOp*>(clientp);
    auto fd = me->m_broker_reverse_socket;
    me->m_broker_reverse_socket = -1;
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
CurlOperation::XferInfoCallback(void *clientp, curl_off_t /*dltotal*/, curl_off_t dlnow, curl_off_t /*ultotal*/, curl_off_t ulnow)
{
    auto me = reinterpret_cast<CurlOperation*>(clientp);
    auto now = std::chrono::steady_clock::now();
    if (me->HeaderTimeoutExpired(now) || me->OperationTimeoutExpired(now)) {
        return 1; // return value triggers CURLE_ABORTED_BY_CALLBACK
    }
    uint64_t xfer_bytes = dlnow > ulnow ? dlnow : ulnow;
    if (me->TransferStalled(xfer_bytes, now)) {
        return 1;
    }
    return 0;
}

int
CurlOperation::WaitSocketCallback(std::string &err)
{
    m_broker_reverse_socket = m_broker ? m_broker->FinishRequest(err) : -1;
    if (m_broker && m_broker_reverse_socket == -1) {
        m_logger->Error(kLogXrdClCurl, "Error when getting socket from parent: %s", err.c_str());
    } else if (m_broker) {
        m_logger->Debug(kLogXrdClCurl, "Got reverse connection on socket %d", m_broker_reverse_socket);
    }
    return m_broker_reverse_socket;
}

// OPTIONS information is available.
//
// Reconfigure curl handle, as necessary, to use PROPFIND
void
CurlStatOp::OptionsDone()
{
    auto &instance = VerbsCache::Instance();
    auto verbs = instance.Get(m_url);
    if (verbs.IsSet(VerbsCache::HttpVerb::kPROPFIND)) {
        curl_easy_setopt(m_curl.get(), CURLOPT_CUSTOMREQUEST, "PROPFIND");
        curl_easy_setopt(m_curl.get(), CURLOPT_NOBODY, 0L);
        m_is_propfind = true;
    } else {
        m_is_propfind = false;
        curl_easy_setopt(m_curl.get(), CURLOPT_NOBODY, 1L);
    }
}

CurlOperation::RedirectAction
CurlStatOp::Redirect(std::string &target)
{
    auto headers = m_headers;
    auto result = CurlOperation::Redirect(target);
    if (result == CurlOperation::RedirectAction::Fail) {
        return result;
    }
    auto &instance = VerbsCache::Instance();
    auto verbs = instance.Get(target);
    if (verbs.IsSet(VerbsCache::HttpVerb::kUnset)) {
        m_headers = std::move(headers);
        return CurlOperation::RedirectAction::ReinvokeAfterAllow;
    }

    if (verbs.IsSet(VerbsCache::HttpVerb::kPROPFIND)) {
        curl_easy_setopt(m_curl.get(), CURLOPT_CUSTOMREQUEST, "PROPFIND");
        curl_easy_setopt(m_curl.get(), CURLOPT_NOBODY, 0L);
        m_is_propfind = true;
    } else {
        m_is_propfind = false;
        curl_easy_setopt(m_curl.get(), CURLOPT_NOBODY, 1L);
    }
    return CurlOperation::RedirectAction::Reinvoke;
}

void
CurlStatOp::Setup(CURL *curl, CurlWorker &worker)
{
    CurlOperation::Setup(curl, worker);
    curl_easy_setopt(m_curl.get(), CURLOPT_WRITEFUNCTION, CurlStatOp::WriteCallback);
    curl_easy_setopt(m_curl.get(), CURLOPT_WRITEDATA, this);

    auto &instance = VerbsCache::Instance();
    auto verbs = instance.Get(m_url);
    if (verbs.IsSet(VerbsCache::HttpVerb::kPROPFIND)) {
        curl_easy_setopt(m_curl.get(), CURLOPT_CUSTOMREQUEST, "PROPFIND");
        curl_easy_setopt(m_curl.get(), CURLOPT_NOBODY, 0L);
        m_is_propfind = true;
    } else {
        curl_easy_setopt(m_curl.get(), CURLOPT_NOBODY, 1L);
    }
}

void
CurlStatOp::ReleaseHandle()
{
    if (m_curl == nullptr) return;
    curl_easy_setopt(m_curl.get(), CURLOPT_NOBODY, 0L);
    if (m_is_propfind) {
        curl_easy_setopt(m_curl.get(), CURLOPT_CUSTOMREQUEST, nullptr);
    }
    curl_easy_setopt(m_curl.get(), CURLOPT_WRITEFUNCTION, nullptr);
    curl_easy_setopt(m_curl.get(), CURLOPT_WRITEDATA, nullptr);
    CurlOperation::ReleaseHandle();
}

size_t
CurlStatOp::WriteCallback(char *buffer, size_t size, size_t nitems, void *this_ptr)
{
    auto me = static_cast<CurlStatOp*>(this_ptr);
    if (me->m_is_propfind) {
        if (size * nitems + me->m_response.size() > 1'000'000) {
            me->m_logger->Error(kLogXrdClCurl, "Response too large for PROPFIND operation");
            return 0;
        }
        me->m_response.append(buffer, size * nitems);
    }
    return size * nitems;
}

std::pair<int64_t, bool>
CurlStatOp::ParseProp(tinyxml2::XMLElement *prop) {
    if (prop == nullptr) {
        return {-1, false};
    }
    for (auto child = prop->FirstChildElement(); child != nullptr; child = child->NextSiblingElement()) {
        if (!strcmp(child->Name(), "D:getcontentlength") || !strcmp(child->Name(), "lp1:getcontentlength")) {
            auto len = child->GetText();
            if (len) {
                m_length = std::stoll(len);
            }
        } else if (!strcmp(child->Name(), "D:resourcetype") || !strcmp(child->Name(), "lp1:resourcetype")) {
            m_is_dir = child->FirstChildElement("D:collection") != nullptr;
        }
    }
    return {m_length, m_is_dir};
}

std::pair<int64_t, bool>
CurlStatOp::GetStatInfo() {
    if (!m_is_propfind) {
        m_length = m_headers.GetContentLength();
        return {m_length, false};
    }
    if (m_length >= 0) {
        return {m_length, m_is_dir};
    }

    tinyxml2::XMLDocument doc;
    auto err = doc.Parse(m_response.c_str());
    if (err != tinyxml2::XML_SUCCESS) {
        m_logger->Error(kLogXrdClCurl, "Failed to parse XML response: %s", m_response.substr(0, 1024).c_str());
        return {-1, false};
    }

    auto elem = doc.RootElement();
    if (strcmp(elem->Name(), "D:multistatus")) {
        m_logger->Error(kLogXrdClCurl, "Unexpected XML response: %s", m_response.substr(0, 1024).c_str());
        return {-1, false};
    }
    auto found_response = false;
    for (auto response = elem->FirstChildElement(); response != nullptr; response = response->NextSiblingElement()) {
        if (!strcmp(response->Name(), "D:response")) {
            found_response = true;
            elem = response;
            break;
        }
    }
    if (!found_response) {
        m_logger->Error(kLogXrdClCurl, "Failed to find response element in XML response: %s", m_response.substr(0, 1024).c_str());
        return {-1, false};
    }
    for (auto child = elem->FirstChildElement(); child != nullptr; child = child->NextSiblingElement()) {
		if (strcmp(child->Name(), "D:propstat")) {
            continue;
        }
        for (auto prop = child->FirstChildElement(); prop != nullptr; prop = prop->NextSiblingElement()) {
            if (!strcmp(prop->Name(), "D:prop")) {
                return ParseProp(prop);
            }
        }
	}
    m_logger->Error(kLogXrdClCurl, "Failed to find properties in XML response: %s", m_response.substr(0, 1024).c_str());
    return {-1, false};
}

bool CurlStatOp::RequiresOptions() const
{
    auto &instance = VerbsCache::Instance();
    auto verbs = instance.Get(m_url);
    return verbs.IsSet(VerbsCache::HttpVerb::kUnset);
}

void CurlStatOp::Success()
{
    SuccessImpl(true);
}

void
CurlStatOp::SuccessImpl(bool returnObj)
{
    SetDone(false);
    m_logger->Debug(kLogXrdClCurl, "CurlStatOp::Success");
    if (m_handler == nullptr) {return;}
    XrdCl::AnyObject *obj = nullptr;
    if (returnObj) {
        auto [size, isdir] = GetStatInfo();
        if (size < 0) {
            m_logger->Error(kLogXrdClCurl, "Failed to get stat info for %s", m_url.c_str());
            Fail(XrdCl::errErrorResponse, kXR_FSError, "Server responded without object size");
            return;
        }
        if (m_is_propfind) {
            m_logger->Debug(kLogXrdClCurl, "Successful propfind operation on %s (size %lld, isdir %d)", m_url.c_str(), static_cast<long long>(size), isdir);
        } else {
            m_logger->Debug(kLogXrdClCurl, "Successful stat operation on %s (size %lld)", m_url.c_str(), static_cast<long long>(size));
        }

        XrdCl::StatInfo *stat_info;
        if (m_response_info){
            auto info = new XrdClCurl::StatResponse("nobody", size,
            XrdCl::StatInfo::Flags::IsReadable | (isdir ? XrdCl::StatInfo::Flags::IsDir : 0), time(NULL));
            info->SetResponseInfo(MoveResponseInfo());
            stat_info = info;
        } else {
            stat_info = new XrdCl::StatInfo("nobody", size,
            XrdCl::StatInfo::Flags::IsReadable | (isdir ? XrdCl::StatInfo::Flags::IsDir : 0), time(NULL));
        }
        obj = new XrdCl::AnyObject();
        obj->Set(stat_info);
    } else if (m_response_info) {
        auto info = new XrdClCurl::OpenResponseInfo();
        info->SetResponseInfo(MoveResponseInfo());
        obj = new XrdCl::AnyObject();
    }

    auto handle = m_handler;
    m_handler = nullptr;
    handle->HandleResponse(new XrdCl::XRootDStatus(), obj);
}

CurlOpenOp::CurlOpenOp(XrdCl::ResponseHandler *handler, const std::string &url, struct timespec timeout,
    XrdCl::Log *logger, XrdClCurl::File *file, bool response_info)
:
    CurlStatOp(handler, url, timeout, logger, response_info),
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
CurlOpenOp::SetOpenProperties()
{
    char *url = nullptr;
    curl_easy_getinfo(m_curl.get(), CURLINFO_EFFECTIVE_URL, &url);
    if (url && m_file) {
        m_file->SetProperty("LastURL", url);
    }
    if (UseX509Auth() && m_file) {
        m_file->SetProperty("UseX509Auth", "true");
    }
    const auto &broker = GetBrokerUrl();
    if (!broker.empty() && m_file) {
        m_file->SetProperty("BrokerURL", broker);
    }
}

void
CurlOpenOp::Success()
{
    SetDone(false);
    SetOpenProperties();
    auto [size, isdir] = GetStatInfo();
    if (isdir) {
        m_logger->Error(kLogXrdClCurl, "Cannot open a directory");
        Fail(XrdCl::errErrorResponse, kXR_isDirectory, "Cannot open a directory");
        return;
    }
    if (size >= 0) {
        m_file->SetProperty("ContentLength", std::to_string(size));
    }
    SuccessImpl(false);
}

void
CurlOpenOp::Fail(uint16_t errCode, uint32_t errNum, const std::string &msg)
{
    // Note: OpenFlags::New is equivalent to O_CREAT | O_EXCL; OpenFlags::Write is equivalent to O_WRONLY | O_CREAT;
    // OpenFlags::Delete is equivalent to O_CREAT | O_TRUNC;
    if (errCode == XrdCl::errErrorResponse &&  errNum == kXR_NotFound && (m_file->Flags() & (XrdCl::OpenFlags::New | XrdCl::OpenFlags::Write | XrdCl::OpenFlags::Delete))) {
        m_logger->Debug(kLogXrdClCurl, "CurlOpenOp succeeds as 404 was expected");
        SetOpenProperties();
        SuccessImpl(false);
        m_file->SetProperty("ContentLength", "0");
        return;
    }
    CurlOperation::Fail(errCode, errNum, msg);
}

CurlCopyOp::CurlCopyOp(XrdCl::ResponseHandler *handler, const std::string &source_url, const Headers &source_hdrs,
const std::string &dest_url, const Headers &dest_hdrs, struct timespec timeout, XrdCl::Log *logger) :
    CurlOperation(handler, dest_url, timeout, logger),
    m_source_url(source_url),
    m_header_list(nullptr, &curl_slist_free_all)
{
    m_minimum_rate = 1;

    for (const auto &info : source_hdrs) {
        m_header_list.reset(curl_slist_append(m_header_list.release(),
            (std::string("TransferHeader") + info.first + ": " + info.second).c_str()
        ));
    }
    for (const auto &info : dest_hdrs) {
        m_header_list.reset(curl_slist_append(m_header_list.release(),
            (info.first + ": " + info.second).c_str()
        ));
    }
}

void
CurlCopyOp::Setup(CURL *curl, CurlWorker &worker)
{
    CurlOperation::Setup(curl, worker);
    curl_easy_setopt(m_curl.get(), CURLOPT_WRITEFUNCTION, CurlCopyOp::WriteCallback);
    curl_easy_setopt(m_curl.get(), CURLOPT_WRITEDATA, this);
    curl_easy_setopt(m_curl.get(), CURLOPT_CUSTOMREQUEST, "COPY");
    m_header_list.reset(curl_slist_append(m_header_list.release(), (std::string("Source: ") + m_source_url).c_str()));
    curl_easy_setopt(m_curl.get(), CURLOPT_HTTPHEADER, m_header_list.get());
}

void
CurlCopyOp::Success()
{
    SetDone(false);
    if (m_handler == nullptr) {return;}
    auto status = new XrdCl::XRootDStatus();
    auto obj = new XrdCl::AnyObject();
    auto handle = m_handler;
    m_handler = nullptr;
    handle->HandleResponse(status, obj);
}

void
CurlCopyOp::ReleaseHandle()
{
    if (m_curl == nullptr) return;
    curl_easy_setopt(m_curl.get(), CURLOPT_WRITEFUNCTION, nullptr);
    curl_easy_setopt(m_curl.get(), CURLOPT_WRITEDATA, nullptr);
    curl_easy_setopt(m_curl.get(), CURLOPT_CUSTOMREQUEST, nullptr);
    curl_easy_setopt(m_curl.get(), CURLOPT_HTTPHEADER, nullptr);
    curl_easy_setopt(m_curl.get(), CURLOPT_XFERINFOFUNCTION, nullptr);
    m_header_list.reset();
    CurlOperation::ReleaseHandle();
}

size_t
CurlCopyOp::WriteCallback(char *buffer, size_t size, size_t nitems, void *this_ptr)
{
    auto me = reinterpret_cast<CurlCopyOp*>(this_ptr);
    std::string_view str_data(buffer, size * nitems);
    size_t end_line;
    while ((end_line = str_data.find('\n')) != std::string_view::npos) {
        auto cur_line = str_data.substr(0, end_line);
        if (me->m_line_buffer.empty()) {
            me->HandleLine(cur_line);
        } else {
            me->m_line_buffer += cur_line;
            me->HandleLine(me->m_line_buffer);
            me->m_line_buffer.clear();
        }
        str_data = str_data.substr(end_line + 1);
    }
    me->m_line_buffer = str_data;

    return size * nitems;
}

void
CurlCopyOp::HandleLine(std::string_view line)
{
    if (line == "Perf Marker") {
        m_bytemark = -1;
    } else if (line == "End") {
        if (m_bytemark > -1 && m_callback) {
            m_callback->Progress(m_bytemark);
        }
    } else {
        auto key_end_pos = line.find(':');
        if (key_end_pos == line.npos) {
            return; // All the other callback lines should be of key: value format
        }
        auto key = line.substr(0, key_end_pos);
        auto value = ltrim_view(line.substr(key_end_pos + 1));
        if (key == "Stripe Bytes Transferred") {
            try {
                m_bytemark = std::stoll(std::string(value));
            } catch (...) {
                // TODO: Log failure
            }
        } else if (key == "success") {
            m_sent_success = true;
        } else if (key == "failure") {
            m_failure = value;
        }
    }
}

CurlPutOp::CurlPutOp(XrdCl::ResponseHandler *handler, const std::string &url, const char *buffer, size_t buffer_size, struct timespec timeout, XrdCl::Log *logger)
    : CurlOperation(handler, url, timeout, logger),
    m_data(buffer, buffer_size)
{
}

CurlPutOp::CurlPutOp(XrdCl::ResponseHandler *handler, const std::string &url, XrdCl::Buffer &&buffer, struct timespec timeout, XrdCl::Log *logger)
    : CurlOperation(handler, url, timeout, logger),
    m_owned_buffer(std::move(buffer)),
    m_data(buffer.GetBuffer(), buffer.GetSize())
{

}

void
CurlPutOp::Setup(CURL *curl, CurlWorker &worker)
{
    m_curl_handle = curl;
    CurlOperation::Setup(curl, worker);

    curl_easy_setopt(m_curl.get(), CURLOPT_UPLOAD, 1);
    curl_easy_setopt(m_curl.get(), CURLOPT_READDATA, this);
    curl_easy_setopt(m_curl.get(), CURLOPT_READFUNCTION, CurlPutOp::ReadCallback);
    if (m_object_size >= 0) {
        curl_easy_setopt(m_curl.get(), CURLOPT_INFILESIZE_LARGE, m_object_size);
    }
}

void
CurlPutOp::ReleaseHandle()
{
    curl_easy_setopt(m_curl.get(), CURLOPT_READFUNCTION, nullptr);
    curl_easy_setopt(m_curl.get(), CURLOPT_READDATA, nullptr);
    curl_easy_setopt(m_curl.get(), CURLOPT_UPLOAD, 0);
    // If one uses just `-1` here -- instead of casting it to `curl_off_t`, then on Linux
    // we have observed compilers casting the `-1` to an unsigned, resulting in the file
    // size being set to 4294967295 instead of "unknown".  This causes the second use of the
    // handle to claim to upload a large file, resulting in the client hanging while waiting
    // for more input data (which will never come).
    curl_easy_setopt(m_curl.get(), CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(-1));
    CurlOperation::ReleaseHandle();
}

void
CurlPutOp::Pause()
{
    SetDone(false);
    if (m_handler == nullptr) {
        m_logger->Warning(kLogXrdClCurl, "Put operation paused with no callback handler");
        return;
    }
    auto handle = m_handler;
    auto status = new XrdCl::XRootDStatus();
    m_handler = nullptr;
    m_owned_buffer.Free();
    // Note: As soon as this is invoked, another thread may continue and start to manipulate
    // the CurlPutOp object.  To avoid race conditions, all reads/writes to member data must
    // be done *before* the callback is invoked.
    handle->HandleResponse(status, nullptr);
}

void
CurlPutOp::Success()
{
    SetDone(false);
    if (m_handler == nullptr) {
        m_logger->Warning(kLogXrdClCurl, "Put operation succeeded with no callback handler");
        return;
    }
    auto status = new XrdCl::XRootDStatus();
    auto handle = m_handler;
    m_handler = nullptr;
    handle->HandleResponse(status, nullptr);
}

bool
CurlPutOp::ContinueHandle()
{
    if (!m_curl_handle) {
		return false;
	}

	CURLcode rc;
	if ((rc = curl_easy_pause(m_curl_handle, CURLPAUSE_CONT)) != CURLE_OK) {
		m_logger->Error(kLogXrdClCurl, "Failed to continue a paused handle: %s", curl_easy_strerror(rc));
		return false;
	}
	return m_curl_handle;
}

bool
CurlPutOp::Continue(std::shared_ptr<CurlOperation> op, XrdCl::ResponseHandler *handler, const char *buffer, size_t buffer_size)
{
    if (op.get() != this) {
        Fail(XrdCl::errInternal, 0, "Interface error: must provide shared pointer to self");
        return false;
    }
    m_handler = handler;
    m_data = std::string_view(buffer, buffer_size);
    if (!buffer_size)
    {
        m_final = true;
    }

    try {
        m_continue_queue->Produce(op);
    } catch (...) {
        Fail(XrdCl::errInternal, ENOMEM, "Failed to continue the curl operation");
        return false;
    }
    return true;
}

bool
CurlPutOp::Continue(std::shared_ptr<CurlOperation> op, XrdCl::ResponseHandler *handler, XrdCl::Buffer &&buffer)
{
    if (op.get() != this) {
        Fail(XrdCl::errInternal, 0, "Interface error: must provide shared pointer to self");
        return false;
    }
    m_handler = handler;
    m_data = std::string_view(buffer.GetBuffer(), buffer.GetSize());
    if (!buffer.GetSize())
    {
        m_final = true;
    }

    try {
        m_continue_queue->Produce(op);
    } catch (...) {
        Fail(XrdCl::errInternal, ENOMEM, "Failed to continue the curl operation");
        return false;
    }
    return true;
}

size_t CurlPutOp::ReadCallback(char *buffer, size_t size, size_t n, void *v) {
	// The callback gets the void pointer that we set with CURLOPT_READDATA. In
	// this case, it's a pointer to an HTTPRequest::Payload struct that contains
	// the data to be sent, along with the offset of the data that has already
	// been sent.
	auto op = static_cast<CurlPutOp*>(v);
    //op->m_logger->Debug(kLogXrdClPelican, "Read callback with buffer %ld and avail data %ld", size*n, op->m_data.size());

    // TODO: Check for timeouts.  If there was one, abort the callback function
    // and cause the curl worker thread to handle it.

	if (op->m_data.empty()) {
		if (op->m_final) {
			return 0;
		} else {
			op->Pause();
			return CURL_READFUNC_PAUSE;
		}
	}

	size_t request = size * n;
	if (request > op->m_data.size()) {
		request = op->m_data.size();
	}

	memcpy(buffer, op->m_data.data(), request);
	op->m_data = op->m_data.substr(request);

	return request;
}
