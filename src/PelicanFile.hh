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

#include <XrdCl/XrdClFile.hh>
#include <XrdCl/XrdClPlugInInterface.hh>

#include <unordered_map>
#include <string>


namespace XrdCl {

class Log;

}

namespace XrdClCurl {

class CurlPutOp;
class HandlerQueue;

}
namespace Pelican {

class DirectorCache;

class File final : public XrdCl::FilePlugIn {
public:
    File(std::shared_ptr<XrdClCurl::HandlerQueue> queue, XrdCl::Log *log) :
        m_queue(queue),
        m_logger(log)
    {}

#if HAVE_XRDCL_IFACE6
    using timeout_t = time_t;
#else
    using timeout_t = uint16_t;
#endif

    virtual ~File() noexcept {}

    virtual XrdCl::XRootDStatus Open(const std::string      &url,
                                     XrdCl::OpenFlags::Flags flags,
                                     XrdCl::Access::Mode     mode,
                                     XrdCl::ResponseHandler *handler,
                                     timeout_t               timeout) override;

    virtual XrdCl::XRootDStatus Close(XrdCl::ResponseHandler *handler,
                                     timeout_t                timeout) override;

    virtual XrdCl::XRootDStatus Stat(bool                    force,
                                     XrdCl::ResponseHandler *handler,
                                     timeout_t               timeout) override;

    virtual XrdCl::XRootDStatus Read(uint64_t                offset,
                                     uint32_t                size,
                                     void                   *buffer,
                                     XrdCl::ResponseHandler *handler,
                                     timeout_t               timeout) override;

    virtual XrdCl::XRootDStatus PgRead(uint64_t                offset,
                                       uint32_t                size,
                                       void                   *buffer,
                                       XrdCl::ResponseHandler *handler,
                                       timeout_t               timeout) override;

    virtual XrdCl::XRootDStatus VectorRead(const XrdCl::ChunkList &chunks,
                                           void                   *buffer,
                                           XrdCl::ResponseHandler *handler,
                                           timeout_t               timeout ) override;

    virtual XrdCl::XRootDStatus Write(uint64_t            offset,
                                  uint32_t                size,
                                  const void             *buffer,
                                  XrdCl::ResponseHandler *handler,
                                  timeout_t               timeout) override;

    virtual XrdCl::XRootDStatus Write(uint64_t             offset,
                                  XrdCl::Buffer          &&buffer,
                                  XrdCl::ResponseHandler  *handler,
                                  timeout_t                timeout) override;

    virtual bool IsOpen() const override;

    virtual bool SetProperty( const std::string &name,
                            const std::string &value ) override;

    virtual bool GetProperty( const std::string &name,
                            std::string &value ) const override;

    // Returns true if the file URL was derived from a pelican:// URL.
    bool IsPelican() const {return m_is_pelican;}

    // Returns true if the origin URL was from the director cache.
    bool IsCachedUrl() const {return m_is_cached;}

    // Returns the flags used to open the file
    XrdCl::OpenFlags::Flags Flags() const {return m_open_flags;}

    // Sets the minimum client timeout
    static void SetMinimumHeaderTimeout(struct timespec &ts) {m_min_client_timeout.tv_sec = ts.tv_sec; m_min_client_timeout.tv_nsec = ts.tv_nsec;}

    // Gets the minimum client timeout
    static const struct timespec &GetMinimumHeaderTimeout() {return m_min_client_timeout;}

    // Sets the default header timeout
    static void SetDefaultHeaderTimeout(struct timespec &ts) {m_default_header_timeout.tv_sec = ts.tv_sec; m_default_header_timeout.tv_nsec = ts.tv_nsec;}

    // Gets the default header timeout
    static const struct timespec &GetDefaultHeaderTimeout() {return m_default_header_timeout;}

    // Sets the open file's header timeout
    void SetHeaderTimeout(const struct timespec &ts) {m_header_timeout.tv_sec = ts.tv_sec; m_header_timeout.tv_nsec = ts.tv_nsec;}

    // Get the header timeout value, taking into consideration the contents of the header and XrdCl's default values
    static struct timespec ParseHeaderTimeout(const std::string &header_value, XrdCl::Log *logger);

    // Get the header timeout value, taking into consideration the provided command timeout, the existing open timeout, and XrdCl's default values
    struct timespec GetHeaderTimeout(time_t oper_timeout) const;

    // Get the header timeout value, taking into consideration the provided command timeout, a default timeout, and XrdCl's default values
    static struct timespec GetHeaderTimeoutWithDefault(time_t oper_timeout, const struct timespec &header_timeout);

    // Set the federation metadata timeout
    static void SetFederationMetadataTimeout(const struct timespec &ts) {m_fed_timeout.tv_sec = ts.tv_sec; m_fed_timeout.tv_nsec = ts.tv_nsec;}

    // Get the federation metadata timeout
    static struct timespec GetFederationMetadataTimeout() {return m_fed_timeout;}

private:
    bool m_is_opened{false};
    // In Pelican 7.4.0, the director will return a 404 for a HEAD request against the
    // origins API endpoint.  Hence, we track whether this was a `pelican://` URL and, if
    // so, will send a GET to the director instead of a HEAD (relying on the fact we'll get)
    // a redirect.
    bool m_is_pelican{false};
    // Whether the URL was derived from the director cache.
    // This is used to determine whether we expect to get a redirect; if we don't, we'll
    // use the PROPFIND verb against the origin instead of HEAD against the director.
    bool m_is_cached{false};

    // The flags used to open the file
    XrdCl::OpenFlags::Flags m_open_flags{XrdCl::OpenFlags::None};

    std::string m_url;
    std::shared_ptr<XrdClCurl::HandlerQueue> m_queue;
    XrdCl::Log *m_logger{nullptr};
    std::unordered_map<std::string, std::string> m_properties;
    const DirectorCache *m_dcache{nullptr};

    // The header timeout for the current file
    struct timespec m_timeout{0, 0};

    // The minimum timeout value requested by a client that we will honor
    static struct timespec m_min_client_timeout;

    // The default header timeout.
    static struct timespec m_default_header_timeout;

    // The per-file header timeout.
    struct timespec m_header_timeout;

    // The federation metadata timeout.
    static struct timespec m_fed_timeout;

    // An in-progress put operation.
    //
    // This shared pointer is also copied to the queue and kept
    // by the curl worker thread.  We will need to refer to the
    // operation later to continue the write.
    std::shared_ptr<XrdClCurl::CurlPutOp> m_put_op;

    // Offset of the next write operation;
    off_t m_offset{0};
};

}
