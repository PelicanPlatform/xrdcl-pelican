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

#include "../common/CurlConnectionCallout.hh"
#include "../common/CurlResponses.hh"
#include "ConnectionBroker.hh"
#include "FedInfo.hh"
#include "../common/ParseTimeout.hh"
#include "PelicanFactory.hh"
#include "PelicanFile.hh"
#include "PelicanFilesystem.hh"
#include "DirectorCache.hh"
#include "DirectorCacheResponseHandler.hh"

#include <XrdCl/XrdClConstants.hh>
#include <XrdCl/XrdClDefaultEnv.hh>
#include <XrdCl/XrdClLog.hh>
#include <XrdCl/XrdClStatus.hh>
#include <XrdCl/XrdClURL.hh>

#include <charconv>

using namespace Pelican;

File *File::m_first = nullptr;
std::mutex File::m_list_mutex;
std::string File::m_query_params;

namespace {

class OpenResponseHandler : public XrdCl::ResponseHandler {
public:
    OpenResponseHandler(bool *is_opened, XrdCl::ResponseHandler *handler)
        : m_is_opened(is_opened),
          m_handler(handler)
    {
    }

    virtual void HandleResponse(XrdCl::XRootDStatus *status_raw, XrdCl::AnyObject *response_raw) {
        // Delete the handler; since we're injecting results (hopefully) into a global
        // cache, no one owns our object
        std::unique_ptr<OpenResponseHandler> owner(this);
        std::unique_ptr<XrdCl::XRootDStatus> status(status_raw);
        std::unique_ptr<XrdCl::AnyObject> response(response_raw);

        if (status && status->IsOK()) {
            if (m_is_opened) *m_is_opened = true;
        }
        if (m_handler) m_handler->HandleResponse(status.release(), response.release());
    }

private:
    bool *m_is_opened;

    // A reference to the handler we are wrapping.  Note we don't own the handler
    // so this is not a unique_ptr.
    XrdCl::ResponseHandler *m_handler;
};

} // namespace

// Note: these values are typically overwritten by `PelicanFactory::PelicanFactory`;
// they are set here just to avoid uninitialized globals.
struct timespec Pelican::File::m_min_client_timeout = {2, 0};
struct timespec Pelican::File::m_default_header_timeout = {9, 5};
struct timespec Pelican::File::m_fed_timeout = {5, 0};

File::File(XrdCl::Log *log) :
        m_logger(log),
        m_wrapped_file(new XrdCl::File())
{
    std::unique_lock lock(m_list_mutex);

    if (m_first) {
        m_next = m_first;
        m_first->m_prev = this;
    }
    m_first = this;
}

File::~File() noexcept {
    std::unique_lock lock(m_list_mutex);

    if (m_prev) {
        m_prev->m_next = m_next;
    }
    if (m_next) {
        m_next->m_prev = m_prev;
    }
    if (m_first == this) {
        m_first = m_next;
    }
}

struct timespec
File::ParseHeaderTimeout(const std::string &timeout_string, XrdCl::Log *logger)
{
    struct timespec ts = File::GetDefaultHeaderTimeout();
    if (!timeout_string.empty()) {
        std::string errmsg;
        // Parse the provided timeout and decrease by a second if we can (if it's below a second, halve it).
        // The thinking is that if the client needs a response in N seconds, then we ought to set the internal
        // timeout to (N-1) seconds to provide enough time for our response to arrive at the client.
        if (!XrdClCurl::ParseTimeout(timeout_string, ts, errmsg)) {
            logger->Error(kLogXrdClPelican, "Failed to parse pelican.timeout parameter: %s", errmsg.c_str());
        } else if (ts.tv_sec >= 1) {
                ts.tv_sec--;
        } else {
            ts.tv_nsec /= 2;
        }
    }
    const auto mct = File::GetMinimumHeaderTimeout();
    if (ts.tv_sec < mct.tv_sec ||
        (ts.tv_sec == mct.tv_sec && ts.tv_nsec < mct.tv_nsec))
    {
        ts.tv_sec = mct.tv_sec;
        ts.tv_nsec = mct.tv_nsec;
    }

    return ts;
}

struct timespec
File::GetHeaderTimeoutWithDefault(time_t oper_timeout, const struct timespec &header_timeout)
{
    if (oper_timeout == 0) {
        int val = XrdCl::DefaultRequestTimeout;
        XrdCl::DefaultEnv::GetEnv()->GetInt( "RequestTimeout", val );
        oper_timeout = val;
    }
    if (oper_timeout <= 0) {
        return header_timeout;
    }
    if (oper_timeout == header_timeout.tv_sec) {
        return {header_timeout.tv_sec, 0};
    } else if (header_timeout.tv_sec < oper_timeout) {
        return header_timeout;
    } else { // header timeout is larger than the operation timeout
        return {oper_timeout, 0};
    }
}

struct timespec
File::GetHeaderTimeout(time_t oper_timeout) const
{
    return GetHeaderTimeoutWithDefault(oper_timeout, m_header_timeout);
}

XrdCl::XRootDStatus
File::Open(const std::string      &url,
           XrdCl::OpenFlags::Flags flags,
           XrdCl::Access::Mode     mode,
           XrdCl::ResponseHandler *handler,
           timeout_t               timeout)
{
    if (m_is_opened) {
        m_logger->Error(kLogXrdClPelican, "URL %s already open", url.c_str());
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidOp);
    }

    m_open_flags = flags;

    m_header_timeout.tv_nsec = m_default_header_timeout.tv_nsec;
    m_header_timeout.tv_sec = m_default_header_timeout.tv_sec;
    auto pelican_url = XrdCl::URL();
    pelican_url.SetPort(0);
    if (!pelican_url.FromString(url)) {
        m_logger->Error(kLogXrdClPelican, "Failed to parse pelican:// URL as a valid URL: %s", url.c_str());
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidArgs);
    }
    if (pelican_url.GetProtocol() != "pelican") {
        m_logger->Error(kLogXrdClPelican, "Pelican file opened invoked with non-pelican:// URL: %s", url.c_str());
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidArgs);
    }
    auto pm = pelican_url.GetParams();
    auto iter = pm.find("pelican.timeout");
    std::string timeout_string = (iter == pm.end()) ? "" : iter->second;
    m_header_timeout = ParseHeaderTimeout(timeout_string, m_logger);
    pm["pelican.timeout"] = XrdClCurl::MarshalDuration(m_header_timeout);
    pelican_url.SetParams(pm);

    auto &factory = FederationFactory::GetInstance(*m_logger, m_fed_timeout);
    std::string err;
    std::stringstream ss;
    ss << pelican_url.GetHostName() << ":" << pelican_url.GetPort();

    auto dcache = &DirectorCache::GetCache(ss.str());

    if ((m_url = dcache->Get(url.c_str())).empty()) {
        m_logger->Debug(kLogXrdClPelican, "No cached origin URL available for %s", url.c_str());
        auto info = factory.GetInfo(ss.str(), err);
        if (!info) {
            return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidAddr, 0, err);
        }
        if (!info->IsValid()) {
            return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidAddr, 0, "Failed to look up pelican metadata: " + err);
        }
        m_url = info->GetDirector() + "/api/v1.0/director/origin/" + pelican_url.GetPathWithParams();
    } else {
        m_logger->Debug(kLogXrdClPelican, "Using cached origin URL %s", m_url.c_str());
        dcache = nullptr;
    }

    auto ts = GetHeaderTimeout(timeout);
    m_logger->Debug(kLogXrdClPelican, "Opening %s (with timeout %d)", m_url.c_str(), timeout);

    std::unique_ptr<XrdCl::ResponseHandler> wrapped_handler(
        new DirectorCacheResponseHandler<XrdClCurl::OpenResponseInfo, XrdClCurl::OpenResponseInfo>(
            dcache, *m_logger, handler
        )
    );
    wrapped_handler.reset(new OpenResponseHandler(&m_is_opened, wrapped_handler.release()));

    auto status = m_wrapped_file->Open(m_url, XrdCl::OpenFlags::Compress, XrdCl::Access::None, nullptr, Pelican::File::timeout_t(0));
    XrdClCurl::CreateConnCalloutType callout = ConnectionBroker::CreateCallback;
    auto callout_loc = reinterpret_cast<long long>(callout);
    size_t buf_size = 12;
    char callout_buf[buf_size];
    std::to_chars_result result = std::to_chars(callout_buf, callout_buf + buf_size - 1, callout_loc, 16);
    if (result.ec == std::errc{}) {
        std::string callout_str(callout_buf, result.ptr - callout_buf);
        m_wrapped_file->SetProperty("XrdClConnectionCallout", callout_str);
    }
    m_wrapped_file->SetProperty(ResponseInfoProperty, "true");
    {
        std::unique_lock lock(m_list_mutex);
        m_wrapped_file->SetProperty("XrdClCurlQueryParam", m_query_params);
    }

    status = m_wrapped_file->Open(m_url, flags, mode, wrapped_handler.get(), ts.tv_sec);
    if (status.IsOK()) {
        wrapped_handler.release();
    }
    return status;
}

XrdCl::XRootDStatus
File::Close(XrdCl::ResponseHandler *handler,
                        timeout_t timeout)
{
    if (!m_is_opened) {
        m_logger->Error(kLogXrdClPelican, "Cannot close.  URL isn't open");
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidOp);
    }
    m_url = "";
    m_is_opened = false;
    return m_wrapped_file->Close(handler, timeout);
}

XrdCl::XRootDStatus
File::Stat(bool                    /*force*/,
           XrdCl::ResponseHandler *handler,
           timeout_t               timeout)
{
    if (!m_is_opened) {
        m_logger->Error(kLogXrdClPelican, "Cannot stat.  URL isn't open");
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidOp);
    }

    std::string content_length_str;
    int64_t content_length;
    if (!m_wrapped_file->GetProperty("ContentLength", content_length_str)) {
        m_logger->Error(kLogXrdClPelican, "Content length missing for %s", m_url.c_str());
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidOp);
    }
    try {
        content_length = std::stoll(content_length_str);
    } catch (...) {
        m_logger->Error(kLogXrdClPelican, "Content length not an integer for %s", m_url.c_str());
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidOp);
    }
    if (content_length < 0) {
        m_logger->Error(kLogXrdClPelican, "Content length negative for %s", m_url.c_str());
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidResponse);
    }

    m_logger->Debug(kLogXrdClPelican, "Successful stat operation on %s (size %lld)", m_url.c_str(), static_cast<long long>(content_length));
    auto stat_info = new XrdCl::StatInfo("nobody", content_length,
        XrdCl::StatInfo::Flags::IsReadable, time(NULL));
    auto obj = new XrdCl::AnyObject();
    obj->Set(stat_info);

    handler->HandleResponse(new XrdCl::XRootDStatus(), obj);
    return XrdCl::XRootDStatus();
}

XrdCl::XRootDStatus
File::Read(uint64_t                offset,
           uint32_t                size,
           void                   *buffer,
           XrdCl::ResponseHandler *handler,
           timeout_t               timeout)
{
    return m_wrapped_file->Read(offset, size, buffer, handler, timeout);
}

XrdCl::XRootDStatus
File::VectorRead(const XrdCl::ChunkList &chunks,
                 void                   *buffer,
                 XrdCl::ResponseHandler *handler,
                 timeout_t               timeout )
{
    return m_wrapped_file->VectorRead(chunks, buffer, handler, timeout);
}

XrdCl::XRootDStatus
File::Write(uint64_t                offset,
            uint32_t                size,
            const void             *buffer,
            XrdCl::ResponseHandler *handler,
            timeout_t               timeout)
{
    return m_wrapped_file->Write(offset, size, buffer, handler, timeout);
}

XrdCl::XRootDStatus
File::Write(uint64_t                offset,
            XrdCl::Buffer         &&buffer,
            XrdCl::ResponseHandler *handler,
            timeout_t               timeout)
{
    return m_wrapped_file->Write(offset, std::move(buffer), handler, timeout);
}

XrdCl::XRootDStatus
File::PgRead(uint64_t                offset,
             uint32_t                size,
             void                   *buffer,
             XrdCl::ResponseHandler *handler,
             timeout_t               timeout)
{
    return m_wrapped_file->PgRead(offset, size, buffer, handler, timeout);
}

bool
File::IsOpen() const
{
    return m_is_opened;
}

void
File::SetCacheToken(const std::string &token)
{
    std::unique_lock lock(m_list_mutex);

    if (token.empty()) {
        m_query_params = "";
    } else {
        m_query_params = "access_token=" + token;
    }
    auto next = m_first;
    while (next) {
        if (next->m_wrapped_file) next->m_wrapped_file->SetProperty("XrdClCurlQueryParam", m_query_params);
        next = next->m_next;
    }
}

bool
File::SetProperty(const std::string &name,
                  const std::string &value)
{
    if (name == "CacheToken") {
        SetCacheToken(value);
        return true;
    }
    if (name == "RefreshToken") {
        PelicanFactory::SetTokenLocation(value);
        PelicanFactory::RefreshToken();
        return true;
    }
    m_properties[name] = value;
    return true;
}

bool
File::GetProperty(const std::string &name,
                        std::string &value) const
{
    if (name == "LastURL" || name == "CurrentURL") {
        return m_wrapped_file->GetProperty(name, value);
    }
    const auto p = m_properties.find(name);
    if (p == std::end(m_properties)) {
        return false;
    }

    value = p->second;
    return true;
}

