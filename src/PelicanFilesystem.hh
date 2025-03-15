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

#pragma once

#include <XrdCl/XrdClFileSystem.hh>
#include <XrdCl/XrdClLog.hh>
#include <XrdCl/XrdClPlugInInterface.hh>
#include <XrdCl/XrdClURL.hh>

#include <unordered_map>

namespace XrdCl {

class Log;

}

namespace Pelican {

class DirectorCache;
class HandlerQueue;

class Filesystem final : public XrdCl::FileSystemPlugIn {
public:
#if HAVE_XRDCL_IFACE6
    using timeout_t = time_t;
#else
    using timeout_t = uint16_t;
#endif

    Filesystem(const std::string &, std::shared_ptr<HandlerQueue> queue, XrdCl::Log *log);

    virtual ~Filesystem() noexcept {}

    virtual XrdCl::XRootDStatus Stat(const std::string      &path,
                                     XrdCl::ResponseHandler *handler,
                                     timeout_t               timeout) override;

    virtual XrdCl::XRootDStatus DirList(const std::string          &path,
                                        XrdCl::DirListFlags::Flags  flags,
                                        XrdCl::ResponseHandler     *handler,
                                        timeout_t                   timeout) override;

    virtual bool SetProperty(const std::string &name,
                             const std::string &value) override;

    virtual bool GetProperty(const std::string &name,
                             std::string &value) const override;

    virtual XrdCl::XRootDStatus Locate(const std::string        &path,
                                       XrdCl::OpenFlags::Flags   flags,
                                       XrdCl::ResponseHandler   *handler,
                                       timeout_t                 timeout) override;

    virtual XrdCl::XRootDStatus Query( XrdCl::QueryCode::Code  queryCode,
                                       const XrdCl::Buffer     &arg,
                                       XrdCl::ResponseHandler  *handler,
                                       timeout_t                timeout ) override;

    // Get the header timeout value, taking into consideration the provided command timeout and XrdCl's default values
    struct timespec GetHeaderTimeout(time_t oper_timeout, const std::string &headerValue);

private:
    XrdCl::XRootDStatus ConstructURL(const std::string &oper, const std::string &path, timeout_t timeout, std::string &full_url, const DirectorCache *&dcache, bool &is_pelican, bool &is_cached, struct timespec &ts);

    std::unordered_map<std::string, std::string> properties_;

    std::shared_ptr<HandlerQueue> m_queue;
    XrdCl::Log *m_logger{nullptr};
    XrdCl::URL m_url;
    std::unordered_map<std::string, std::string> m_properties;
};

}
