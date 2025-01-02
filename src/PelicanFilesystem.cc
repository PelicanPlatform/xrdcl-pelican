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
#include "CurlUtil.hh"
#include "FedInfo.hh"
#include "ParseTimeout.hh"
#include "PelicanFile.hh"
#include "PelicanFilesystem.hh"

using namespace Pelican;

Filesystem::Filesystem(const std::string &url, std::shared_ptr<HandlerQueue> queue, XrdCl::Log *log) :
    m_queue(queue),
    m_logger(log),
    m_url(url)
{
    m_logger->Debug(kLogXrdClPelican, "Pelican filesystem constructed with URL: %s.",
        url.c_str());
}

// Resolve the full URL for a given path, including any director cache lookups.
//
// - oper: the operation being performed (e.g., "stat"); used only for log messages
// - path: the path for the URL resource
// - timeout: the timeout for the operation
// - full_url: the output URL
// - return: the status of the operation (possibly indicating failure)
XrdCl::XRootDStatus
Filesystem::ConstructURL(const std::string &oper, const std::string &path, timeout_t timeout, std::string &full_url, const DirectorCache *&dcache, bool &is_pelican, bool &is_cached, struct timespec &ts)
{
    full_url = m_url.GetProtocol() + "://" +
                           m_url.GetHostName() + ":" +
                           std::to_string(m_url.GetPort()) +
                           "/" + path;
    
    auto pelican_url = XrdCl::URL();
    pelican_url.SetPort(0);
    if (!pelican_url.FromString(full_url)) {
        m_logger->Error(kLogXrdClPelican, "Failed to parse URL as a valid URL: %s", full_url.c_str());
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidArgs);
    }
    auto pm = pelican_url.GetParams();
    const auto iter = pm.find("pelican.timeout");
    std::string header_timeout = iter == pm.end() ? "" : iter->second;
    ts = GetHeaderTimeout(timeout, header_timeout);
    pm["pelican.timeout"] = MarshalDuration(ts);
    pelican_url.SetParams(pm);

    is_pelican = strncmp(full_url.c_str(), "pelican://", 10) == 0;
    is_cached = false;
    dcache = nullptr;
    if (is_pelican) {
        auto pelican_url = XrdCl::URL();
        pelican_url.SetPort(0);
        if (!pelican_url.FromString(full_url)) {
            m_logger->Error(kLogXrdClPelican, "Failed to parse pelican:// URL as a valid URL: %s", full_url.c_str());
            return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidArgs);
        }
        auto &factory = FederationFactory::GetInstance(*m_logger, File::GetFederationMetadataTimeout());
        std::string err;
        std::stringstream ss;
        ss << pelican_url.GetHostName() << ":" << pelican_url.GetPort();

        dcache = &DirectorCache::GetCache(ss.str());

        if ((full_url = dcache->Get(full_url.c_str())).empty()) {
            auto info = factory.GetInfo(ss.str(), err);
            if (!info) {
                return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidAddr, 0, err);
            }
            if (!info->IsValid()) {
                return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidAddr, 0, "Failed to look up pelican metadata: " + err);
            }
            full_url = info->GetDirector() + "/api/v1.0/director/origin/" + pelican_url.GetPathWithParams();
        } else {
            m_logger->Debug(kLogXrdClPelican, "Using cached origin URL %s for %s", full_url.c_str(), oper.c_str());
            is_cached = true;
        }
    }

    return XrdCl::XRootDStatus();
}

XrdCl::XRootDStatus
Filesystem::Stat(const std::string      &path,
                 XrdCl::ResponseHandler *handler,
                 timeout_t               timeout)
{
    const DirectorCache *dcache{nullptr};
    std::string full_url;
    bool is_pelican{false};
    bool is_cached{false};
    struct timespec ts;
    auto st = ConstructURL("stat", path, timeout, full_url, dcache, is_pelican, is_cached, ts);
    if (!st.IsOK()) {
        return st;
    }

    m_logger->Debug(kLogXrdClPelican, "Filesystem::Stat path %s", full_url.c_str());
    std::unique_ptr<CurlStatOp> statOp(new CurlStatOp(handler, full_url, ts, m_logger, is_pelican, is_cached, dcache));
    try {
        m_queue->Produce(std::move(statOp));
    } catch (...) {
        m_logger->Warning(kLogXrdClPelican, "Failed to add stat op to queue");
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errOSError);
    }

    return XrdCl::XRootDStatus();
}

struct timespec
Filesystem::GetHeaderTimeout(time_t oper_timeout, const std::string &header_value)
{
    auto ts = File::ParseHeaderTimeout(header_value, m_logger);

    return File::GetHeaderTimeoutWithDefault(oper_timeout, ts);
}

bool
Filesystem::SetProperty(const std::string &name,
                        const std::string &value)
{
    m_properties[name] = value;
    return true;
}

bool
Filesystem::GetProperty(const std::string &name,
                        std::string       &value) const
{
    const auto p = m_properties.find(name);
    if (p == std::end(m_properties)) {
        return false;
    }

    value = p->second;
    return true;
}

XrdCl::XRootDStatus
Filesystem::DirList(const std::string          &path,
                    XrdCl::DirListFlags::Flags  flags,
                    XrdCl::ResponseHandler     *handler,
                    timeout_t                   timeout )
{
    const DirectorCache *dcache{nullptr};
    std::string full_url;
    bool is_pelican{false};
    bool is_origin{false};
    struct timespec ts;
    auto st = ConstructURL("stat", path, timeout, full_url, dcache, is_pelican, is_origin, ts);
    if (!st.IsOK()) {
        return st;
    }

    m_logger->Debug(kLogXrdClPelican, "Filesystem::DirList path %s", full_url.c_str());
    std::unique_ptr<CurlListdirOp> listdirOp(new CurlListdirOp(handler, full_url, m_url.GetHostName() + ":" + std::to_string(m_url.GetPort()), is_origin, ts, m_logger));

    try {
        m_queue->Produce(std::move(listdirOp));
    } catch (...) {
        m_logger->Warning(kLogXrdClPelican, "Failed to add dirlist op to queue");
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errOSError);
    }

    return XrdCl::XRootDStatus();
}

// Trivial implementation of the "locate" call
//
// On Linux, this is invoked by the XrdCl client prior to directory listings.
// Given there's no concept of multiple locations currently, we just return
// the original host and port as the available "location".
XrdCl::XRootDStatus
Filesystem::Locate( const std::string        &path,
                    XrdCl::OpenFlags::Flags   flags,
                    XrdCl::ResponseHandler   *handler,
                    timeout_t                 timeout )
{
    if (!handler) return XrdCl::XRootDStatus();

    auto locateInfo = std::make_unique<XrdCl::LocationInfo>();
    locateInfo->Add(XrdCl::LocationInfo::Location(m_url.GetHostName() + ":" + std::to_string(m_url.GetPort()), XrdCl::LocationInfo::ServerOnline, XrdCl::LocationInfo::Read));

    auto obj = std::make_unique<XrdCl::AnyObject>();
    obj->Set(locateInfo.release());
    handler->HandleResponse(new XrdCl::XRootDStatus(), obj.release());

    return XrdCl::XRootDStatus();
}
