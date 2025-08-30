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

#include <mutex>
#include <unordered_map>
#include <string>


namespace XrdCl {

class Log;

}

namespace Pelican {

class DirectorCache;

class File final : public XrdCl::FilePlugIn {
public:
    File(XrdCl::Log *log);

#if HAVE_XRDCL_IFACE6
    using timeout_t = time_t;
#else
    using timeout_t = uint16_t;
#endif

    virtual ~File() noexcept;

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

    // Set the cache token value
    static void SetCacheToken(const std::string &token);
private:

    struct WritebackInfo {
        // File descriptor for the writeback file
        int fd{-1};
        // Size of the writeback file
        size_t size{0};
        // Offset inside the writeback file
        off_t offset{0};
        // Memory location inside the writeback file
        void *mmap{nullptr};
        // ID inside the writeback cache, if enabled
        std::string id;
        // Mutex protecting access to the writeback fd offset
        std::mutex mutex;
    };

    class WritebackResponseHandler : public XrdCl::ResponseHandler {
    public:
        virtual ~WritebackResponseHandler() noexcept {};

        static std::shared_ptr<WritebackResponseHandler> CreateHandler(XrdCl::Log &logger) {
            auto handler = std::shared_ptr<WritebackResponseHandler>(new WritebackResponseHandler());
            handler->m_self_ref = handler;
            handler->m_logger = &logger;
            return handler;
        }

        void IncrementRef() {
            m_refcount.fetch_add(1, std::memory_order_acq_rel);
        }

        virtual void HandleResponse(XrdCl::XRootDStatus *status_raw, XrdCl::AnyObject *response_raw);

        bool HadError() const {
            return m_had_error.load(std::memory_order_acquire);
        }

        void SetError() {
            m_had_error.store(true, std::memory_order_release);
        }

        // Initiates the close of the wrapped file and writeback info
        // The actual close will be performed asynchronously once all
        // outstanding writes have completed.
        void Close(std::unique_ptr<XrdCl::File> file, std::unique_ptr<WritebackInfo> info);

    private:
        WritebackResponseHandler() {}

        class CloseHandler : public XrdCl::ResponseHandler {
        public:
            CloseHandler(WritebackResponseHandler &parent) : m_parent(parent) {}
            virtual void HandleResponse(XrdCl::XRootDStatus *status_raw, XrdCl::AnyObject *response_raw);

        private:
            WritebackResponseHandler &m_parent;
        };

        void Shutdown();

        XrdCl::Log *m_logger{nullptr};
        std::atomic<bool> m_had_error{false};
        std::atomic<size_t> m_refcount{0};
        std::shared_ptr<WritebackResponseHandler> m_self_ref;
        std::mutex m_mutex; // Protects access to m_wrapped_file and m_writeback_info
        std::unique_ptr<XrdCl::File> m_wrapped_file;
        std::unique_ptr<WritebackInfo> m_writeback_info;
    };

    // Begins a new writeback file with the given ID
    bool BeginWritebackFile(const std::string &id, size_t file_size);

    bool m_is_opened{false};

    // The flags used to open the file
    XrdCl::OpenFlags::Flags m_open_flags{XrdCl::OpenFlags::None};

    std::string m_url;
    XrdCl::Log *m_logger{nullptr};
    std::unordered_map<std::string, std::string> m_properties;

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

    std::unique_ptr<XrdCl::File> m_wrapped_file;


    // Writeback related information
    std::unique_ptr<WritebackInfo> m_writeback_info;
    // Handler for writeback operations
    std::shared_ptr<WritebackResponseHandler> m_writeback_handler;

    // Linked list for tracking live files.
    //
    // These are needed to push out updates to the cache access token.

    // Next file on the list
    File *m_next{nullptr};
    // Previous file on the list
    File *m_prev{nullptr};
    // First file we are tracking
    static File *m_first;
    // Mutex protecting access to linked lists
    static std::mutex m_list_mutex;
    // Value of the query parameters
    static std::string m_query_params;
};

}
