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
#include "PelicanFile.hh"
#include "CurlOps.hh"
#include "CurlUtil.hh"

#include <XrdCl/XrdClLog.hh>
#include <XrdCl/XrdClStatus.hh>
#include <XrdCl/XrdClURL.hh>

using namespace Pelican;


XrdCl::XRootDStatus
File::Open(const std::string      &url,
           XrdCl::OpenFlags::Flags flags,
           XrdCl::Access::Mode     mode,
           XrdCl::ResponseHandler *handler,
           uint16_t                /*timeout*/)
{
    if (m_is_opened) {
        m_logger->Error(kLogXrdClPelican, "URL %s already open", url.c_str());
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidOp);
    }

    if (flags & XrdCl::OpenFlags::Write) {
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errNotSupported);
    }

    if (strncmp(url.c_str(), "pelican://", 10) == 0) {
        auto pelican_url = XrdCl::URL();
        pelican_url.SetPort(0);
        if (!pelican_url.FromString(url)) {
            m_logger->Error(kLogXrdClPelican, "Failed to parse pelican:// URL as a valid URL");
            return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidArgs);
        }
        auto &factory = FederationFactory::GetInstance(*m_logger);
        std::string err;
        auto info = factory.GetInfo(pelican_url.GetHostName(), err);
        if (!info) {
            return XrdCl::XRootDStatus(XrdCl::stError, err);
        }
        if (!info->IsValid()) {
            return XrdCl::XRootDStatus(XrdCl::stError, "Failed to look up pelican metadata");
        }
        m_url = info->GetDirector() + "/api/v1.0/director/origin/" + pelican_url.GetPath();
        m_is_pelican = true;
    } else {
        m_url = url;
    }

    m_logger->Debug(kLogXrdClPelican, "Opened: %s", m_url.c_str());

    auto status = new XrdCl::XRootDStatus();
    handler->HandleResponse(status, nullptr);

    m_is_opened = true;
    return XrdCl::XRootDStatus();
}

XrdCl::XRootDStatus
File::Close(XrdCl::ResponseHandler *handler,
                          uint16_t  /*timeout*/)
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
           uint16_t                timeout)
{
    if (!m_is_opened) {
        m_logger->Error(kLogXrdClPelican, "Cannot stat.  URL isn't open");
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidOp);
    }

    m_logger->Debug(kLogXrdClPelican, "Stat'd %s (with timeout %d)", m_url.c_str(), timeout);

    std::unique_ptr<CurlOpenOp> openOp(new CurlOpenOp(handler, m_url, timeout, m_logger, this));
    try {
        m_queue->Produce(std::move(openOp));
    } catch (...) {
        m_logger->Warning(kLogXrdClPelican, "Failed to add stat op to queue");
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errOSError);
    }

    return XrdCl::XRootDStatus();
}

XrdCl::XRootDStatus
File::Read(uint64_t                offset,
           uint32_t                size,
           void                   *buffer,
           XrdCl::ResponseHandler *handler,
           uint16_t                timeout)
{
    if (!m_is_opened) {
        m_logger->Error(kLogXrdClPelican, "Cannot read.  URL isn't open");
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidOp);
    }

    std::string url;
    if (!GetProperty("LastURL", url)) {
        url = m_url;
    }

    m_logger->Debug(kLogXrdClPelican, "Read %s (%d bytes at offset %d with timeout %d)", url.c_str(), size, offset, timeout);

    std::unique_ptr<CurlReadOp> readOp(new CurlReadOp(handler, url, timeout, std::make_pair(offset, size), static_cast<char*>(buffer), m_logger));
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
             uint16_t                timeout)
{
    if (!m_is_opened) {
        m_logger->Error(kLogXrdClPelican, "Cannot pgread.  URL isn't open");
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidOp);
    }

    std::string url;
    if (!GetProperty("LastURL", url)) {
        url = m_url;
    }

    m_logger->Debug(kLogXrdClPelican, "PgRead %s (%d bytes at offset %lld)", url.c_str(), size, offset);

    std::unique_ptr<CurlPgReadOp> readOp(new CurlPgReadOp(handler, url, timeout, std::make_pair(offset, size), static_cast<char*>(buffer), m_logger));
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

