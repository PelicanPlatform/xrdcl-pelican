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
#include "../common/CurlHeaderCallout.hh"

#include <XrdCl/XrdClFile.hh>
#include <XrdCl/XrdClPlugInInterface.hh>

#include <atomic>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace XrdCl {

class Log;

}

namespace XrdClCurl {

class CurlPutOp;
class CurlReadOp;
class HandlerQueue;

}
namespace XrdClCurl {

class File final : public XrdCl::FilePlugIn {
public:
    File(std::shared_ptr<XrdClCurl::HandlerQueue> queue, XrdCl::Log *log) :
        m_queue(queue),
        m_logger(log),
        m_default_put_handler(new PutDefaultHandler(*this)),
        m_default_prefetch_handler(new PrefetchDefaultHandler(*this))
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

    // Try to read a buffer via the prefetch mechanism.
    //
    // Returns tuple (status, ok); if `ok` is set to true, then the operation
    // was attempted.  Otherwise, the operation was skipped and `status` should
    // be ignored.
    std::tuple<XrdCl::XRootDStatus, bool> ReadPrefetch(uint64_t offset, uint64_t size, void *buffer, XrdCl::ResponseHandler *handler, timeout_t timeout, bool isPgRead);

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
    std::atomic<bool> m_full_download{false}; // Whether the file was in "full download mode" when opened.

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

    // Ultimate length of the in-progress PUT operation
    off_t m_asize{-1};

    // Handle a failure in the PUT code while there are no outstanding
    // write requests
    class PutDefaultHandler : public XrdCl::ResponseHandler {
    public:
        PutDefaultHandler(File &file) : m_logger(file.m_logger) {}

        virtual void HandleResponse(XrdCl::XRootDStatus *status, XrdCl::AnyObject *response);

    private:
        XrdCl::Log *m_logger{nullptr};
    };

    // The default object for all put failures
    std::shared_ptr<PutDefaultHandler> m_default_put_handler;

    // An in-progress GET operation
    //
    // For the first read from the file, we will issue a GET for
    // the entire rest of the file.  As in-sequence reads are
    // encountered, they will be fed from the prefetch operation instead
    // of standalone reads.
    std::shared_ptr<XrdClCurl::CurlReadOp> m_prefetch_op;

    // Next offset for prefetching.
    // Protected by m_prefetch_mutex
    std::atomic<off_t> m_prefetch_offset{0};

    // Prefetch callback handler class
    //
    // Objects form a linked list of pending prefetch handlers.
    // Once the first entry in the list is completed, it will pass the prefetch
    // operation to the subsequent entry.
    class PrefetchResponseHandler : public XrdCl::ResponseHandler {
    public:
        PrefetchResponseHandler(File &parent,
            off_t offset, size_t size, std::atomic<off_t> *prefetch_offset, char *buffer, XrdCl::ResponseHandler *handler, timeout_t timeout);

        virtual void HandleResponse(XrdCl::XRootDStatus *status, XrdCl::AnyObject *response);

    private:
        // When the prefetch fails, we must resubmit our handler as a non-prefetching read.
        void ResubmitOperation();

        // The open file we are associated with
        File &m_parent;

        // A reference to the handler we are wrapping.  Note we don't own the handler
        // so this is not a unique_ptr.
        XrdCl::ResponseHandler *m_handler;

        // A reference to the next handle in the linked list.
        PrefetchResponseHandler *m_next{nullptr};

        // The buffer for this prefetch callback
        char *m_buffer{nullptr};

        // The size of the prefetch callback buffer
        size_t m_size{0};

        // The offset of the operation within the file.
        off_t m_offset{0};

        // A pointer to the prefetch offset.  When a read successfully increases, this
        // should be incremented
        std::atomic<off_t> *m_prefetch_offset{nullptr};

        // The desired timeout for the operation.
        timeout_t m_timeout{0};
    };

    // Last prefetch handler on the stack.
    PrefetchResponseHandler *m_last_prefetch_handler{nullptr};

    // Size of prefetch operation
    off_t m_prefetch_size{-1};

    // Offset of the next write operation;
    off_t m_offset{0};

    // Handle a failure in the prefetch code while there is no outstanding
    // read requests
    //
    // The status of the File's prefetching is kept in this class because the callback's
    // lifetime is independent of the File and the callback needs to be able to disable
    // prefetching.
    class PrefetchDefaultHandler : public XrdCl::ResponseHandler {
    public:
        PrefetchDefaultHandler(File &file) : m_logger(file.m_logger) {}

        virtual void HandleResponse(XrdCl::XRootDStatus *status, XrdCl::AnyObject *response);

        // Disable prefetching for all future operations
        void DisablePrefetch() {
            auto enabled = m_prefetch_enabled.load(std::memory_order_relaxed);
            if (enabled) {
                std::unique_lock lock(m_prefetch_mutex);
                m_prefetch_enabled.store(false, std::memory_order_relaxed);
            }
        }

        // Determine if we are prefetching
        bool IsPrefetching() const {
            auto enabled = m_prefetch_enabled.load(std::memory_order_relaxed);
            if (enabled) {
                std::unique_lock lock(m_prefetch_mutex);
                return m_prefetch_enabled.load(std::memory_order_relaxed);
            }
            return false;
        }

        XrdCl::Log *m_logger{nullptr};

        // Mutex protecting the state of the in-progress GET operation
        // and relevant callback handlers and state
        mutable std::mutex m_prefetch_mutex;

        // Whether prefetching is active
        //
        // If set to "false", then prefetch is disabled.
        // If set to "true", then you must re-read the value with
        // m_prefetch_mutex held to ensure is actually true and not
        // a spurious reading.
        mutable std::atomic<bool> m_prefetch_enabled{true};
    };

    // "Default" handler for prefetching
    //
    // When there is no outstanding read operation but the prefetch
    // operation fails, this will be called
    std::shared_ptr<PrefetchDefaultHandler> m_default_prefetch_handler;

    // Pointer to the header callout function
    std::atomic<XrdClCurl::HeaderCallout *> m_header_callout;

    // Class for setting up the required HTTP headers for S3 requests
    class HeaderCallout : public XrdClCurl::HeaderCallout {
    public:
        HeaderCallout(File &fs) : m_parent(fs)
        {}

        virtual ~HeaderCallout() noexcept = default;

        virtual std::shared_ptr<HeaderList> GetHeaders(const std::string &verb,
                                                       const std::string &url,
                                                       const HeaderList &headers) override;

    private:
        File &m_parent;
    };

    HeaderCallout m_default_header_callout{*this};
};

}

#endif // XRDCLCURL_CURLFILE_HH
