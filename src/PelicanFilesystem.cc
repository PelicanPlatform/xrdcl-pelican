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

#include "PelicanFilesystem.hh"
#include "XrdClCurlUtil.hh"

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
                 uint16_t                timeout)
{
    const auto full_path = m_url.GetProtocol() + "://" +
                           m_url.GetHostName() + ":" +
                           std::to_string(m_url.GetPort()) +
                           "/" + m_url.GetPath() + "/" + path;

    m_logger->Debug(kLogXrdClPelican, "Filesystem::Stat path %s", full_path.c_str());

    std::unique_ptr<CurlStatOp> statOp(new CurlStatOp(handler, full_path, timeout, m_logger));
    try {
        m_queue->Produce(std::move(statOp));
    } catch (...) {
        m_logger->Warning(kLogXrdClPelican, "Failed to add stat op to queue");
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errOSError);
    }

    return XrdCl::XRootDStatus();
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
