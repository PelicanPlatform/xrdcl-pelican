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

#include "CurlFactory.hh"
#include "CurlFilesystem.hh"
#include "CurlOps.hh"
#include "../common/CurlResponses.hh"

using namespace XrdClCurl;

Filesystem::Filesystem(const std::string &url, std::shared_ptr<HandlerQueue> queue, XrdCl::Log *log)
    : m_queue(queue),
      m_logger(log),
      m_url(url)
{}

Filesystem::~Filesystem() noexcept {}

XrdCl::XRootDStatus
Filesystem::DirList(const std::string          &path,
                    XrdCl::DirListFlags::Flags  flags,
                    XrdCl::ResponseHandler     *handler,
                    timeout_t                   timeout )
{
    auto ts = XrdClCurl::Factory::GetHeaderTimeoutWithDefault(timeout);

    m_logger->Debug(kLogXrdClCurl, "Filesystem::DirList path %s", path.c_str());
    std::unique_ptr<XrdClCurl::CurlListdirOp> listdirOp(new XrdClCurl::CurlListdirOp(handler, path, m_url.GetHostName() + ":" + std::to_string(m_url.GetPort()), SendResponseInfo(), ts, m_logger));

    try {
        m_queue->Produce(std::move(listdirOp));
    } catch (...) {
        m_logger->Warning(kLogXrdClCurl, "Failed to add dirlist op to queue");
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errOSError);
    }

    return XrdCl::XRootDStatus();
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

XrdCl::XRootDStatus Filesystem::Query(XrdCl::QueryCode::Code  queryCode,
    const XrdCl::Buffer     &arg,
    XrdCl::ResponseHandler  *handler,
    timeout_t                timeout)
{
    if (queryCode != XrdCl::QueryCode::Checksum) {
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errNotImplemented);
    }
    auto url = m_url.GetURL() + arg.ToString();

    auto ts = XrdClCurl::Factory::GetHeaderTimeoutWithDefault(timeout);

    m_logger->Debug(kLogXrdClCurl, "XrdClCurl::Filesystem::Query checksum path %s", url.c_str());

    XrdClCurl::ChecksumType preferred = XrdClCurl::ChecksumType::kCRC32C;
    XrdCl::URL url_obj;
    url_obj.FromString(url);
    auto iter = url_obj.GetParams().find("cks.type");
    if (iter != url_obj.GetParams().end()) {
        preferred = XrdClCurl::GetTypeFromString(iter->second);
        if (preferred == XrdClCurl::ChecksumType::kUnknown) {
            m_logger->Error(kLogXrdClCurl, "Unknown checksum type %s", iter->second.c_str());
            preferred = XrdClCurl::ChecksumType::kCRC32C;
        }
    }
    // On miss, queue a checksum operation
    std::unique_ptr<CurlChecksumOp> cksumOp(new CurlChecksumOp(handler, url, preferred, ts, m_logger, SendResponseInfo()))  ;
    try {
        m_queue->Produce(std::move(cksumOp));
    } catch (...) {
        m_logger->Warning(kLogXrdClCurl, "Failed to add checksum operation to queue");
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

XrdCl::XRootDStatus
Filesystem::Stat(const std::string      &path,
                 XrdCl::ResponseHandler *handler,
                 timeout_t               timeout)
{
    auto ts = XrdClCurl::Factory::GetHeaderTimeoutWithDefault(timeout);

    auto full_url = m_url.GetURL() + path;
    m_logger->Debug(kLogXrdClCurl, "Filesystem::Stat path %s", full_url.c_str());

    std::unique_ptr<CurlStatOp> statOp(new CurlStatOp(handler, full_url, ts, m_logger, SendResponseInfo()));
    try {
        m_queue->Produce(std::move(statOp));
    } catch (...) {
        m_logger->Warning(kLogXrdClCurl, "Failed to add filesystem stat op to queue");
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errOSError);
    }

    return XrdCl::XRootDStatus();
}

bool Filesystem::SendResponseInfo() const {
    std::string val;
    return GetProperty(ResponseInfoProperty, val) && val == "true";
}
