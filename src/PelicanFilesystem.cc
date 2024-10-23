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
    m_logger->Debug(kLogXrdClPelican, "Pelican::Filesystem constructed with URL: %s.",
        url.c_str());
}

XrdCl::XRootDStatus
Filesystem::Stat(const std::string      &path,
                 XrdCl::ResponseHandler *handler,
                 timeout_t               timeout)
{
    auto full_url = m_url.GetProtocol() + "://" +
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
    auto ts = GetHeaderTimeout(timeout, header_timeout);
    pm["pelican.timeout"] = MarshalDuration(ts);
    pelican_url.SetParams(pm);

    bool is_pelican = strncmp(full_url.c_str(), "pelican://", 10) == 0;
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
        auto info = factory.GetInfo(ss.str(), err);
        if (!info) {
            return XrdCl::XRootDStatus(XrdCl::stError, err);
        }
        if (!info->IsValid()) {
            return XrdCl::XRootDStatus(XrdCl::stError, "Failed to look up pelican metadata");
        }
        full_url = info->GetDirector() + "/api/v1.0/director/origin/" + pelican_url.GetPathWithParams();
    }

    m_logger->Debug(kLogXrdClPelican, "Filesystem::Stat path %s", full_url.c_str());

    std::unique_ptr<CurlStatOp> statOp(new CurlStatOp(handler, full_url, ts, m_logger, is_pelican));
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
