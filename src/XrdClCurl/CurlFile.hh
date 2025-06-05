/***************************************************************
 *
 * Copyright (C) 2025, Morgridge Institute for Research
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

#ifndef XRDCLCURL_CURLFILE_HH
#define XRDCLCURL_CURLFILE_HH

#include "../common/CurlConnectionCallout.hh"

#include <XrdCl/XrdClFile.hh>
#include <XrdCl/XrdClPlugInInterface.hh>

#include <unordered_map>
#include <shared_mutex>
#include <string>


namespace XrdCl {

class Log;

}

namespace XrdClCurl {

class CurlPutOp;
class HandlerQueue;

}
namespace XrdClCurl {

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

    virtual XrdCl::XRootDStatus Fcntl(const XrdCl::Buffer    &arg,
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
    // The "*Response" variant of the callback response objects defined in DirectorCacheResponse.hh
    // are opt-in; if the caller isn't expecting them, then they will leak memory.  This
    // function determines whether the opt-in is enabled.
    bool SendResponseInfo() const;

    // Returns a pointer to the connection callout function
    CreateConnCalloutType GetConnCallout() const;

    // Get the current URL to use for file operations.
    //
    // The `XrdClCurlQueryParam` property allows for additional query parameters to be added by
    // the owner of the file handle; these can change while the file is open (for example, if there
    // is a credential in the query parameter that might expire) so we must reconstruct the URL,
    // even for `Read`-type calls.
    const std::string GetCurrentURL() const;

    // Calculate the current URL given the query parameter value
    //
    // Must be called with the m_properties_mutex held for write.
    void CalculateCurrentURL(const std::string &value) const;

    bool m_is_opened{false};

    // The flags used to open the file
    XrdCl::OpenFlags::Flags m_open_flags{XrdCl::OpenFlags::None};

    std::string m_url; // The URL as given to the Open() method.
    std::string m_last_url; // The last server the file was connected to after Open() (potentially after redirections)
    mutable std::string m_url_current; // The URL to use for future HTTP requests; may be the last URL plus additional query parameters.
    std::shared_ptr<XrdClCurl::HandlerQueue> m_queue;
    XrdCl::Log *m_logger{nullptr};
    std::unordered_map<std::string, std::string> m_properties;

    // Protects the contents of m_properties
    mutable std::shared_mutex m_properties_mutex;

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

#endif // XRDCLCURL_CURLFILE_HH