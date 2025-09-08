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

#include <atomic>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <unordered_map>
#include <utility>
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

    // Return a listing of all known active writeback transfer IDs and bytes written
    static std::deque<std::pair<std::string, uint64_t>> GetWritebackActiveStatuses() {return WritebackResponseHandler::GetActiveStatuses();}

    // Iterate through the writeback transfers and update the mtime on disk to the current time
    // to indicate transfers are still in-progress.  Walk the writeback directory and unlink
    // any file that hasn't been updated recently.
    static void WritebackMaintenance() {WritebackResponseHandler::Maintenance();}

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

    // Wait for all writebacks to complete; necessary to ensure there are no outstanding
    // writebacks at shutdown time.
    static void WaitForAllWritebacks() {return WritebackResponseHandler::WaitForAllWritebacks();}

private:

    struct WritebackInfo {
        // File descriptor for the writeback file
        int fd{-1};
        // Size of the writeback file
        off_t size{0};
        // Offset inside the writeback file
        off_t offset{0};
        // Last write time
        std::atomic<std::chrono::steady_clock::duration::rep> last_write_time{0};
        // Memory location inside the writeback file
        void *mmap{nullptr};
        // ID inside the writeback cache, if enabled
        std::string id;
        // Mutex protecting access to the writeback fd offset
        std::mutex mutex;
    };

    class WritebackResponseHandler : public XrdCl::ResponseHandler {
    public:
        virtual ~WritebackResponseHandler() noexcept;

        static std::shared_ptr<WritebackResponseHandler> CreateHandler(XrdCl::Log &logger, std::unique_ptr<WritebackInfo> writeback_info);

        void IncrementRef() {
            m_refcount.fetch_add(1, std::memory_order_acq_rel);
        }

        const std::string &GetId() const {
            return m_writeback_info->id;
        }

        std::mutex &GetMutex() const {
            return m_writeback_info->mutex;
        }

        std::string GetError() const {
            std::lock_guard lock(m_mutex);
            return m_error_msg;
        }

        int GetFD() const {
            return m_writeback_info->fd;
        }

        void *GetMmap() const {
            return m_writeback_info->mmap;
        }

        off_t GetOffset() const {
            return m_writeback_info->offset;
        }

        void IncOffset(off_t amount);

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
        void Close(std::unique_ptr<XrdCl::File> file);

        static std::deque<std::pair<std::string, uint64_t>> GetActiveStatuses();
        static void Maintenance();

        // Wait for all writebacks to complete.
        // Since XRootD's shutdown can leave OpenSSL in an inconsistent state,
        // one may need to invoke this to prevent XrdClCurl from crashing while
        // invoking OpenSSL code via libcurl.
        static void WaitForAllWritebacks();
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

        // If the XrdCl::File is still open when the library is closed, then
        // we must delay the shutdown until all outstanding writes have completed.
        static void ShutdownAll() __attribute__((destructor));

        bool m_closed{false};
        std::atomic<bool> m_had_error{false};
        std::atomic<size_t> m_refcount{0};
        XrdCl::Log *m_logger{nullptr};

        // GCC version on RHEL9 does not support atomic shared_ptr
        // Hence, we use c++ library feature detection to determine whether we fall
        // back to a mutex-protected shared_ptr until we can drop RHEL9 support.
#if __cpp_lib_atomic_shared_ptr >= 201711L
        std::atomic<std::shared_ptr<WritebackResponseHandler>> m_self_ref;
#else
        std::shared_ptr<WritebackResponseHandler> m_self_ref;
        std::mutex m_self_ref_mutex;
#endif
        std::string m_error_msg; // Error message for the writeback operation
        mutable std::mutex m_mutex; // Protects access to m_closed, m_wrapped_file, m_error_msg, and m_writeback_info
        std::unique_ptr<XrdCl::File> m_wrapped_file;
        std::unique_ptr<WritebackInfo> m_writeback_info;

        // Pointer to the first writeback response handler; used for tracking all
        // the existing writeback operations.  First entry in a linked list.
        static WritebackResponseHandler *m_first;
        // Pointer to the next writeback response handler in the linked list
        WritebackResponseHandler *m_next{nullptr};
        // Pointer to the previous writeback response handler in the linked list
        WritebackResponseHandler *m_prev{nullptr};
        // Mutex protecting access to the linked list and m_shutdown_cv
        static std::mutex m_instance_mutex;
        // If we are shutting down, we need to wait for all outstanding writes to complete;
        // this condition variable is notified when the last writeback operation completes.
        static std::condition_variable m_shutdown_cv;
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
