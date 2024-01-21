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

#pragma once

#include <XrdCl/XrdClFile.hh>
#include <XrdCl/XrdClPlugInInterface.hh>

#include <unordered_map>
#include <string>

namespace XrdCl {

class Log;

}

namespace Pelican {

class HandlerQueue;

class File final : public XrdCl::FilePlugIn {
public:
    File(std::shared_ptr<HandlerQueue> queue, XrdCl::Log *log) :
        m_queue(queue),
        m_logger(log)
    {}

    virtual ~File() noexcept {}

    virtual XrdCl::XRootDStatus Open(const std::string      &url,
                                     XrdCl::OpenFlags::Flags flags,
                                     XrdCl::Access::Mode     mode,
                                     XrdCl::ResponseHandler *handler,
                                     uint16_t                timeout) override;

    virtual XrdCl::XRootDStatus Close(XrdCl::ResponseHandler *handler,
                                      uint16_t                timeout) override;

    virtual XrdCl::XRootDStatus Stat(bool                    force,
                                     XrdCl::ResponseHandler *handler,
                                     uint16_t                timeout) override;

    virtual XrdCl::XRootDStatus Read(uint64_t                offset,
                                     uint32_t                size,
                                     void                   *buffer,
                                     XrdCl::ResponseHandler *handler,
                                     uint16_t                timeout) override;

    virtual XrdCl::XRootDStatus PgRead(uint64_t                offset,
                                       uint32_t                size,
                                       void                   *buffer,
                                       XrdCl::ResponseHandler *handler,
                                       uint16_t                timeout) override;

    virtual bool IsOpen() const override;

    virtual bool SetProperty( const std::string &name,
                            const std::string &value ) override;

    virtual bool GetProperty( const std::string &name,
                            std::string &value ) const override;

    // Returns true if the file URL was derived from a pelican:// URL.
    bool IsPelican() const {return m_is_pelican;}

private:
    bool m_is_opened{false};
    // In Pelican 7.4.0, the director will return a 404 for a HEAD request against the
    // origins API endpoint.  Hence, we track whether this was a `pelican://` URL and, if
    // so, will send a GET to the director instead of a HEAD (relying on the fact we'll get)
    // a redirect.
    bool m_is_pelican{false};
    std::string m_url;
    std::shared_ptr<HandlerQueue> m_queue;
    XrdCl::Log *m_logger{nullptr};
    std::unordered_map<std::string, std::string> m_properties;
};

}
