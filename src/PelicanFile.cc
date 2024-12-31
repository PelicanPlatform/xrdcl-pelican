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

#include "FedInfo.hh"
#include "ParseTimeout.hh"
#include "PelicanFile.hh"
#include "CurlOps.hh"
#include "CurlUtil.hh"
#include "DirectorCache.hh"

#include <XrdCl/XrdClConstants.hh>
#include <XrdCl/XrdClDefaultEnv.hh>
#include <XrdCl/XrdClLog.hh>
#include <XrdCl/XrdClStatus.hh>
#include <XrdCl/XrdClURL.hh>

using namespace Pelican;

// Note: these values are typically overwritten by `PelicanFactory::PelicanFactory`;
// they are set here just to avoid uninitialized globals.
struct timespec Pelican::File::m_min_client_timeout = {2, 0};
struct timespec Pelican::File::m_default_header_timeout = {9, 5};
struct timespec Pelican::File::m_fed_timeout = {5, 0};

struct timespec
File::ParseHeaderTimeout(const std::string &timeout_string, XrdCl::Log *logger)
{
    struct timespec ts = File::GetDefaultHeaderTimeout();
    if (!timeout_string.empty()) {
        std::string errmsg;
        // Parse the provided timeout and decrease by a second if we can (if it's below a second, halve it).
        // The thinking is that if the client needs a response in N seconds, then we ought to set the internal
        // timeout to (N-1) seconds to provide enough time for our response to arrive at the client.
        if (!ParseTimeout(timeout_string, ts, errmsg)) {
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

    if (flags & XrdCl::OpenFlags::Write) {
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errNotSupported);
    }

    m_header_timeout.tv_nsec = m_default_header_timeout.tv_nsec;
    m_header_timeout.tv_sec = m_default_header_timeout.tv_sec;
    auto pelican_url = XrdCl::URL();
    pelican_url.SetPort(0);
    if (!pelican_url.FromString(url)) {
        m_logger->Error(kLogXrdClPelican, "Failed to parse pelican:// URL as a valid URL: %s", url.c_str());
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidArgs);
    }
    auto pm = pelican_url.GetParams();
    auto iter = pm.find("pelican.timeout");
    std::string timeout_string = (iter == pm.end()) ? "" : iter->second;
    m_header_timeout = ParseHeaderTimeout(timeout_string, m_logger);
    pm["pelican.timeout"] = MarshalDuration(m_header_timeout);
    pelican_url.SetParams(pm);

    if (strncmp(url.c_str(), "pelican://", 10) == 0) {
        auto &factory = FederationFactory::GetInstance(*m_logger, m_fed_timeout);
        std::string err;
        std::stringstream ss;
        ss << pelican_url.GetHostName() << ":" << pelican_url.GetPort();

        m_dcache = &DirectorCache::GetCache(ss.str());

        if ((m_url = m_dcache->Get(url.c_str())).empty()) {
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
        }
        m_is_pelican = true;
    } else {
        m_url = url;
    }

    auto ts = GetHeaderTimeout(timeout);
    m_logger->Debug(kLogXrdClPelican, "Opening %s (with timeout %d)", m_url.c_str(), timeout);

    std::unique_ptr<CurlOpenOp> openOp(new CurlOpenOp(handler, m_url, ts, m_logger, this, m_dcache));
    try {
        m_queue->Produce(std::move(openOp));
    } catch (...) {
        m_logger->Warning(kLogXrdClPelican, "Failed to add open op to queue");
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errOSError);
    }

    m_is_opened = true;
    return XrdCl::XRootDStatus();
}

XrdCl::XRootDStatus
File::Close(XrdCl::ResponseHandler *handler,
                        timeout_t /*timeout*/)
{
    if (!m_is_opened) {
        m_logger->Error(kLogXrdClPelican, "Cannot close.  URL isn't open");
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidOp);
    }

    m_logger->Debug(kLogXrdClPelican, "Closed %s", m_url.c_str());

    if (handler) {
        handler->HandleResponse(new XrdCl::XRootDStatus(), nullptr);
    }
    return XrdCl::XRootDStatus();
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
    if (!GetProperty("ContentLength", content_length_str)) {
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
    if (!m_is_opened) {
        m_logger->Error(kLogXrdClPelican, "Cannot read.  URL isn't open");
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidOp);
    }

    std::string url;
    if (!GetProperty("LastURL", url)) {
        url = m_url;
    }

    auto ts = GetHeaderTimeout(timeout);
    m_logger->Debug(kLogXrdClPelican, "Read %s (%d bytes at offset %d with timeout %d)", url.c_str(), size, offset, ts.tv_sec);

    std::unique_ptr<CurlReadOp> readOp(new CurlReadOp(handler, url, ts, std::make_pair(offset, size), static_cast<char*>(buffer), m_logger));
    std::string broker;
    if (GetProperty("BrokerURL", broker) && !broker.empty()) {
        readOp->SetBrokerUrl(broker);
    }
    std::string use_x509;
    if (GetProperty("UseX509Auth", use_x509) && use_x509 == "true") {
        readOp->SetUseX509();
    }
    try {
        m_queue->Produce(std::move(readOp));
    } catch (...) {
        m_logger->Warning(kLogXrdClPelican, "Failed to add read op to queue");
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errOSError);
    }

    return XrdCl::XRootDStatus();
}

XrdCl::XRootDStatus
File::PgRead(uint64_t                offset,
             uint32_t                size,
             void                   *buffer,
             XrdCl::ResponseHandler *handler,
             timeout_t               timeout)
{
    if (!m_is_opened) {
        m_logger->Error(kLogXrdClPelican, "Cannot pgread.  URL isn't open");
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidOp);
    }

    std::string url;
    if (!GetProperty("LastURL", url)) {
        url = m_url;
    }

    auto ts = GetHeaderTimeout(timeout);
    m_logger->Debug(kLogXrdClPelican, "PgRead %s (%d bytes at offset %lld)", url.c_str(), size, offset);

    std::unique_ptr<CurlPgReadOp> readOp(new CurlPgReadOp(handler, url, ts, std::make_pair(offset, size), static_cast<char*>(buffer), m_logger));
    std::string broker;
    if (GetProperty("BrokerURL", broker) && !broker.empty()) {
        readOp->SetBrokerUrl(broker);
    }
    std::string use_x509;
    if (GetProperty("UseX509Auth", use_x509) && use_x509 == "true") {
        readOp->SetUseX509();
    }

    try {
        m_queue->Produce(std::move(readOp));
    } catch (...) {
        m_logger->Warning(kLogXrdClPelican, "Failed to add read op to queue");
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errOSError);
    }

    return XrdCl::XRootDStatus();
}

bool
File::IsOpen() const
{
    return m_is_opened;
}

bool
File::SetProperty(const std::string &name,
                  const std::string &value)
{
    m_properties[name] = value;
    return true;
}

bool
File::GetProperty(const std::string &name,
                        std::string &value) const
{
    const auto p = m_properties.find(name);
    if (p == std::end(m_properties)) {
        return false;
    }

    value = p->second;
    return true;
}

