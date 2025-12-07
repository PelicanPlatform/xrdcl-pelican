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

#include "../common/XrdClCurlConnectionCallout.hh"
#include "../common/XrdClCurlResponses.hh"
#include "ConnectionBroker.hh"
#include "FedInfo.hh"
#include "../common/XrdClCurlParseTimeout.hh"
#include "PelicanFactory.hh"
#include "PelicanFile.hh"
#include "PelicanFilesystem.hh"
#include "DirectorCache.hh"
#include "DirectorCacheResponseHandler.hh"
#include "WritebackDB.hh"

#include <XrdCl/XrdClConstants.hh>
#include <XrdCl/XrdClDefaultEnv.hh>
#include <XrdCl/XrdClLog.hh>
#include <XrdCl/XrdClStatus.hh>
#include <XrdCl/XrdClURL.hh>

#include <charconv>
#include <fcntl.h>
#include <filesystem>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>

using namespace Pelican;

File *File::m_first = nullptr;
std::mutex File::m_list_mutex;
std::string File::m_query_params;
File::WritebackResponseHandler *File::WritebackResponseHandler::m_first = nullptr;
std::mutex File::WritebackResponseHandler::m_instance_mutex;
std::condition_variable File::WritebackResponseHandler::m_shutdown_cv;

namespace {

class OpenResponseHandler : public XrdCl::ResponseHandler {
public:
    OpenResponseHandler(bool *is_opened, XrdCl::ResponseHandler *handler)
        : m_is_opened(is_opened),
          m_handler(handler)
    {
    }

    virtual void HandleResponse(XrdCl::XRootDStatus *status_raw, XrdCl::AnyObject *response_raw) {
        // Delete the handler; since we're injecting results (hopefully) into a global
        // cache, no one owns our object
        std::unique_ptr<OpenResponseHandler> owner(this);
        std::unique_ptr<XrdCl::XRootDStatus> status(status_raw);
        std::unique_ptr<XrdCl::AnyObject> response(response_raw);

        if (status && status->IsOK()) {
            if (m_is_opened) *m_is_opened = true;
        }
        if (m_handler) m_handler->HandleResponse(status.release(), response.release());
    }

private:
    bool *m_is_opened;

    // A reference to the handler we are wrapping.  Note we don't own the handler
    // so this is not a unique_ptr.
    XrdCl::ResponseHandler *m_handler;
};

} // namespace

// Note: these values are typically overwritten by `PelicanFactory::PelicanFactory`;
// they are set here just to avoid uninitialized globals.
struct timespec Pelican::File::m_min_client_timeout = {2, 0};
struct timespec Pelican::File::m_default_header_timeout = {9, 5};
struct timespec Pelican::File::m_fed_timeout = {5, 0};

File::File(XrdCl::Log *log) :
        m_logger(log),
        m_wrapped_file(new XrdCl::File())
{
    std::unique_lock lock(m_list_mutex);

    if (m_first) {
        m_next = m_first;
        m_first->m_prev = this;
    }
    m_first = this;
}

File::~File() noexcept {
    std::unique_lock lock(m_list_mutex);

    if (m_prev) {
        m_prev->m_next = m_next;
    }
    if (m_next) {
        m_next->m_prev = m_prev;
    }
    if (m_first == this) {
        m_first = m_next;
    }
}

bool
File::BeginWritebackFile(const std::string &id, size_t file_size)
{
    if (id.empty()) {
        m_logger->Error(kLogXrdClPelican, "Pelican writeback ID is empty");
        return false;
    }
    if (file_size == 0) {
        m_logger->Debug(kLogXrdClPelican, "Pelican writeback file size is zero; not creating writeback file");
        return false;
    }
    auto location_str = Filesystem::GetWritebackCacheLocation();
    if (location_str.empty()) {
        m_logger->Error(kLogXrdClPelican, "Pelican writeback cache location is not set");
        return false;
    }
    std::filesystem::path location(location_str);

    auto path = location / (id + ".part");
    m_logger->Debug(kLogXrdClPelican, "Creating Pelican writeback file at %s", path.c_str());
    int fd = open(path.c_str(), O_CREAT | O_EXCL | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        m_logger->Error(kLogXrdClPelican, "Failed to create Pelican writeback file at %s: %s", path.c_str(), strerror(errno));
        return false;
    }

    // Set the file to the expected size
    if (ftruncate(fd, file_size) != 0) {
        m_logger->Error(kLogXrdClPelican, "Failed to set size of Pelican writeback file at %s to %zu bytes: %s", path.c_str(), file_size, strerror(errno));
        close(fd);
        unlink(path.c_str());
        return false;
    }

    // Memory map the file so it can be directly read by the wrapped file as a buffer
    auto mmap_location = mmap(nullptr, file_size, PROT_READ, MAP_SHARED, fd, 0);
    if (mmap_location == MAP_FAILED) {
        m_logger->Error(kLogXrdClPelican, "Failed to mmap Pelican writeback file at %s: %s", path.c_str(), strerror(errno));
        close(fd);
        unlink(path.c_str());
        return false;
    }

    std::string err;
    if (!WritebackDB::CreateTransfer(id, path, file_size, err)) {
        m_logger->Error(kLogXrdClPelican, "Failed to create writeback transfer entry in database: %s", err.c_str());
        close(fd);
        unlink(path.c_str());
        return false;
    }

    auto writeback_info = std::make_unique<WritebackInfo>();
    writeback_info->fd = fd;
    writeback_info->mmap = mmap_location;
    writeback_info->size = file_size;
    writeback_info->id = id;
    writeback_info->last_write_time.store(std::chrono::steady_clock::now().time_since_epoch().count(), std::memory_order_relaxed);
    m_writeback_handler = WritebackResponseHandler::CreateHandler(*m_logger, std::move(writeback_info));

    m_logger->Info(kLogXrdClPelican, "Created Pelican writeback file at %s with size %zu bytes", path.c_str(), file_size);
    return true;
}

struct timespec
File::ParseHeaderTimeout(const std::string &timeout_string, XrdCl::Log *logger)
{
    struct timespec ts = File::GetDefaultHeaderTimeout();
    if (!timeout_string.empty()) {
        std::string errmsg;
        // Parse the provided timeout and decrease by a second if we can (if it's below a second, halve it).
        // The thinking is that if the client needs a response in N seconds, then we ought to set the internal
        // timeout to (N-1) seconds to provide enough time for our response to arrive at the client.
        if (!XrdClCurl::ParseTimeout(timeout_string, ts, errmsg)) {
            logger->Error(kLogXrdClPelican, "Failed to parse pelican.timeout parameter: %s", errmsg.c_str());
        } else if (ts.tv_sec >= 1) {
                ts.tv_sec--;
        } else {
            ts.tv_nsec /= 2;
        }
    }
    const auto mct = File::GetMinimumHeaderTimeout();
    if (ts.tv_sec < mct.tv_sec ||
        (ts.tv_sec == mct.tv_sec && ts.tv_nsec < mct.tv_nsec))
    {
        ts.tv_sec = mct.tv_sec;
        ts.tv_nsec = mct.tv_nsec;
    }

    return ts;
}

struct timespec
File::GetHeaderTimeoutWithDefault(time_t oper_timeout, const struct timespec &header_timeout)
{
    if (oper_timeout == 0) {
        int val = XrdCl::DefaultRequestTimeout;
        XrdCl::DefaultEnv::GetEnv()->GetInt( "RequestTimeout", val );
        oper_timeout = val;
    }
    if (oper_timeout <= 0) {
        return header_timeout;
    }
    if (oper_timeout == header_timeout.tv_sec) {
        return {header_timeout.tv_sec, 0};
    } else if (header_timeout.tv_sec < oper_timeout) {
        return header_timeout;
    } else { // header timeout is larger than the operation timeout
        return {oper_timeout, 0};
    }
}

struct timespec
File::GetHeaderTimeout(time_t oper_timeout) const
{
    return GetHeaderTimeoutWithDefault(oper_timeout, m_header_timeout);
}

XrdCl::XRootDStatus
File::Open(const std::string      &url,
           XrdCl::OpenFlags::Flags flags,
           XrdCl::Access::Mode     mode,
           XrdCl::ResponseHandler *handler,
           timeout_t               timeout)
{
    if (m_is_opened) {
        m_logger->Error(kLogXrdClPelican, "URL %s already open", url.c_str());
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidOp);
    }

    m_open_flags = flags;

    m_header_timeout.tv_nsec = m_default_header_timeout.tv_nsec;
    m_header_timeout.tv_sec = m_default_header_timeout.tv_sec;
    auto pelican_url = XrdCl::URL();
    pelican_url.SetPort(0);
    if (!pelican_url.FromString(url)) {
        m_logger->Error(kLogXrdClPelican, "Failed to parse pelican:// URL as a valid URL: %s", url.c_str());
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidArgs);
    }
    if (pelican_url.GetProtocol() != "pelican") {
        m_logger->Error(kLogXrdClPelican, "Pelican file opened invoked with non-pelican:// URL: %s", url.c_str());
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidArgs);
    }
    auto pm = pelican_url.GetParams();
    auto iter = pm.find("pelican.timeout");
    std::string timeout_string = (iter == pm.end()) ? "" : iter->second;
    m_header_timeout = ParseHeaderTimeout(timeout_string, m_logger);
    pm["pelican.timeout"] = XrdClCurl::MarshalDuration(m_header_timeout);
    pelican_url.SetParams(pm);

    m_logger->Debug(kLogXrdClPelican, "Opening pelican:// URL %s with header timeout %ld.%09ld seconds",
                    url.c_str(), m_header_timeout.tv_sec, m_header_timeout.tv_nsec);
    if (((iter = pm.find("pelican.cache_id")) != pm.end()) &&
        (flags & XrdCl::OpenFlags::Write))
    {
        m_logger->Debug(kLogXrdClPelican, "Pelican writeback requested with ID %s", iter->second.c_str());
        auto &id = iter->second;
        auto asize_iter = pm.find("oss.asize");
        size_t asize = 0;
        if (asize_iter != pm.end()) {
            auto [ptr, ec] = std::from_chars(asize_iter->second.data(), asize_iter->second.data() + asize_iter->second.size(), asize, 10);
            if ((ptr == asize_iter->second.data() + asize_iter->second.size()) && (ec == std::errc{})) {
                if (!BeginWritebackFile(id, asize)) {
                    m_logger->Info(kLogXrdClPelican, "Failed to begin Pelican writeback file with ID %s", id.c_str());
                }
            } else {
                m_logger->Error(kLogXrdClPelican, "pelican.cache_id provided but oss.asize is not a valid integer: %s", asize_iter->second.c_str());
            }
        }
    }

    auto &factory = FederationFactory::GetInstance(*m_logger, m_fed_timeout);
    std::string err;
    std::stringstream ss;
    ss << pelican_url.GetHostName() << ":" << pelican_url.GetPort();

    auto dcache = &DirectorCache::GetCache(ss.str());

    if ((m_url = dcache->Get(url.c_str())).empty()) {
        m_logger->Debug(kLogXrdClPelican, "No cached origin URL available for %s", url.c_str());
        auto info = factory.GetInfo(ss.str(), err);
        if (!info) {
            return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidAddr, 0, err);
        }
        if (!info->IsValid()) {
            return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidAddr, 0, "Failed to look up pelican metadata: " + err);
        }
        if (Pelican::Filesystem::GetDirectoryQueryMode() == Pelican::Filesystem::DirectoryQuery::Cache) {
            m_url = "/";
        } else {
            m_url = "/api/v1.0/director/origin/";
        }
        m_url = info->GetDirector() + m_url + pelican_url.GetPathWithParams();
    } else {
        m_logger->Debug(kLogXrdClPelican, "Using cached origin URL %s", m_url.c_str());
        dcache = nullptr;
    }

    auto ts = GetHeaderTimeout(timeout);
    m_logger->Debug(kLogXrdClPelican, "Opening %s (with timeout %ld)", m_url.c_str(), static_cast<long int>(timeout));

    std::unique_ptr<XrdCl::ResponseHandler> wrapped_handler(
        new DirectorCacheResponseHandler<XrdClCurl::OpenResponseInfo, XrdClCurl::OpenResponseInfo>(
            dcache, *m_logger, handler
        )
    );
    wrapped_handler.reset(new OpenResponseHandler(&m_is_opened, wrapped_handler.release()));

    auto status = m_wrapped_file->Open(m_url, XrdCl::OpenFlags::Compress, XrdCl::Access::None, nullptr, Pelican::File::timeout_t(0));
    XrdClCurl::CreateConnCalloutType callout = ConnectionBroker::CreateCallback;
    auto callout_loc = reinterpret_cast<long long>(callout);
    size_t buf_size = 12;
    char callout_buf[buf_size];
    std::to_chars_result result = std::to_chars(callout_buf, callout_buf + buf_size - 1, callout_loc, 16);
    if (result.ec == std::errc{}) {
        std::string callout_str(callout_buf, result.ptr - callout_buf);
        m_wrapped_file->SetProperty("XrdClConnectionCallout", callout_str);
    }
    m_wrapped_file->SetProperty(ResponseInfoProperty, "true");
    {
        std::unique_lock lock(m_list_mutex);
        m_wrapped_file->SetProperty("XrdClCurlQueryParam", m_query_params);
    }

    status = m_wrapped_file->Open(m_url, flags, mode, wrapped_handler.get(), ts.tv_sec);
    if (status.IsOK()) {
        wrapped_handler.release();
    }
    return status;
}

XrdCl::XRootDStatus
File::Close(XrdCl::ResponseHandler *handler,
                        timeout_t timeout)
{
    if (!m_is_opened) {
        m_logger->Error(kLogXrdClPelican, "Cannot close.  URL isn't open");
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidOp);
    }
    m_url = "";
    m_is_opened = false;
    if (m_writeback_handler) {
        m_logger->Debug(kLogXrdClPelican, "Closing Pelican writeback file with ID %s", m_writeback_handler->GetId().c_str());
        m_writeback_handler->Close(std::move(m_wrapped_file));

        // Immediately invoke the handler with success; the actual close will be handled
        // asynchronously by the WritebackResponseHandler
        if (handler) {
            handler->HandleResponse(new XrdCl::XRootDStatus(), nullptr);
        }
        return XrdCl::XRootDStatus();
    } else {
        return m_wrapped_file->Close(handler, timeout);
    }
}

XrdCl::XRootDStatus
File::Stat(bool                    /*force*/,
           XrdCl::ResponseHandler *handler,
           timeout_t               timeout)
{
    if (!m_is_opened) {
        m_logger->Error(kLogXrdClPelican, "Cannot stat.  URL isn't open");
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidOp);
    }

    std::string content_length_str;
    int64_t content_length;
    if (!m_wrapped_file->GetProperty("ContentLength", content_length_str)) {
        m_logger->Error(kLogXrdClPelican, "Content length missing for %s", m_url.c_str());
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidOp);
    }
    try {
        content_length = std::stoll(content_length_str);
    } catch (...) {
        m_logger->Error(kLogXrdClPelican, "Content length not an integer for %s", m_url.c_str());
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidOp);
    }
    if (content_length < 0) {
        m_logger->Error(kLogXrdClPelican, "Content length negative for %s", m_url.c_str());
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidResponse);
    }

    m_logger->Debug(kLogXrdClPelican, "Successful stat operation on %s (size %lld)", m_url.c_str(), static_cast<long long>(content_length));
    auto stat_info = new XrdCl::StatInfo("nobody", content_length,
        XrdCl::StatInfo::Flags::IsReadable, time(NULL));
    auto obj = new XrdCl::AnyObject();
    obj->Set(stat_info);

    handler->HandleResponse(new XrdCl::XRootDStatus(), obj);
    return XrdCl::XRootDStatus();
}

XrdCl::XRootDStatus
File::Read(uint64_t                offset,
           uint32_t                size,
           void                   *buffer,
           XrdCl::ResponseHandler *handler,
           timeout_t               timeout)
{
    return m_wrapped_file->Read(offset, size, buffer, handler, timeout);
}

XrdCl::XRootDStatus
File::VectorRead(const XrdCl::ChunkList &chunks,
                 void                   *buffer,
                 XrdCl::ResponseHandler *handler,
                 timeout_t               timeout )
{
    return m_wrapped_file->VectorRead(chunks, buffer, handler, timeout);
}

XrdCl::XRootDStatus
File::Write(uint64_t                offset,
            uint32_t                size,
            const void             *buffer,
            XrdCl::ResponseHandler *handler,
            timeout_t               timeout)
{
    if (!m_is_opened) {
        m_logger->Error(kLogXrdClPelican, "Cannot write.  URL isn't open");
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidOp);
    }
    auto wb_handler = m_writeback_handler.get();
    if (wb_handler) {
        if (wb_handler->HadError()) {
            return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errErrorResponse, EIO, "Pelican writeback file previously had an error");
        }
        {
            std::unique_lock lock(wb_handler->GetMutex());
            if (offset != static_cast<uint64_t>(wb_handler->GetOffset())) {
                m_logger->Error(kLogXrdClPelican, "Pelican writeback file write at unexpected offset %llu (expected %llu)", static_cast<unsigned long long>(offset), static_cast<unsigned long long>(wb_handler->GetOffset()));
                return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errErrorResponse, EIO, "Pelican writeback file write at unexpected offset");
            }
            m_logger->Debug(kLogXrdClPelican, "Writing %u bytes to Pelican writeback file at offset %llu", size, static_cast<unsigned long long>(offset));
            errno = 0;
            do {
                ssize_t written = pwrite(wb_handler->GetFD(), buffer, size, offset);
                if (written < 0) {
                    m_logger->Error(kLogXrdClPelican, "Failed to write to Pelican writeback file: %s", strerror(errno));
                    return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errErrorResponse, errno);
                }
                if (static_cast<size_t>(written) != size) {
                    m_logger->Error(kLogXrdClPelican, "Short write to Pelican writeback file: wrote %zd of %u bytes", written, size);
                    return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errErrorResponse, EIO, "Short write to Pelican writeback file");
                }
                wb_handler->IncOffset(written);
            } while (errno == EINTR);
        }

        auto status = m_wrapped_file->Write(offset, size, static_cast<char*>(wb_handler->GetMmap()) + offset, m_writeback_handler.get(), timeout);
        if (status.IsOK()) {
            m_writeback_handler->IncrementRef();
        } else {
            m_writeback_handler->SetError();
        }
        if (handler) {
            handler->HandleResponse(new XrdCl::XRootDStatus(), nullptr);
        }
        return status;
    }
    return m_wrapped_file->Write(offset, size, buffer, handler, timeout);
}

XrdCl::XRootDStatus
File::Write(uint64_t                offset,
            XrdCl::Buffer         &&buffer,
            XrdCl::ResponseHandler *handler,
            timeout_t               timeout)
{
    if (m_writeback_handler) {
        return Write(offset, buffer.GetSize(), buffer.GetBuffer(), handler, timeout);
    }
    return m_wrapped_file->Write(offset, std::move(buffer), handler, timeout);
}

XrdCl::XRootDStatus
File::PgRead(uint64_t                offset,
             uint32_t                size,
             void                   *buffer,
             XrdCl::ResponseHandler *handler,
             timeout_t               timeout)
{
    return m_wrapped_file->PgRead(offset, size, buffer, handler, timeout);
}

bool
File::IsOpen() const
{
    return m_is_opened;
}

void
File::SetCacheToken(const std::string &token)
{
    std::unique_lock lock(m_list_mutex);

    if (token.empty()) {
        m_query_params = "";
    } else {
        m_query_params = "access_token=" + token;
    }
    auto next = m_first;
    while (next) {
        if (next->m_wrapped_file) next->m_wrapped_file->SetProperty("XrdClCurlQueryParam", m_query_params);
        next = next->m_next;
    }
}

bool
File::SetProperty(const std::string &name,
                  const std::string &value)
{
    if (name == "CacheToken") {
        SetCacheToken(value);
        return true;
    }
    if (name == "RefreshToken") {
        PelicanFactory::SetTokenLocation(value);
        PelicanFactory::RefreshToken();
        return true;
    }
    m_properties[name] = value;
    return true;
}

bool
File::GetProperty(const std::string &name,
                        std::string &value) const
{
    if (name == "LastURL" || name == "CurrentURL") {
        return m_wrapped_file->GetProperty(name, value);
    }
    const auto p = m_properties.find(name);
    if (p == std::end(m_properties)) {
        return false;
    }

    value = p->second;
    return true;
}

// Destroy the writeback response handler, updating the linked
// list that manages all active handler objects.  Once done,
// it notifies m_shutdown_cv the list has been updated (this
// is needed to prevent a shutdown of the library from occurring
// when there are pending response handlers)
File::WritebackResponseHandler::~WritebackResponseHandler() noexcept
{
    std::lock_guard lock(m_instance_mutex);
    if (m_prev) {
        m_prev->m_next = m_next;
    }
    if (m_next) {
        m_next->m_prev = m_prev;
    }
    if (m_first == this) {
        m_first = m_next;
    }
    m_shutdown_cv.notify_all();
}

std::deque<std::pair<std::string, uint64_t>>
File::WritebackResponseHandler::GetActiveStatuses()
{
    std::lock_guard lock(m_instance_mutex);
    std::deque<std::pair<std::string, uint64_t>> statuses;
    for (auto *curr = m_first; curr; curr = curr->m_next) {
        if (curr->m_writeback_info) {
            statuses.emplace_back(curr->m_writeback_info->id, curr->m_writeback_info->offset);
        }
    }
    return statuses;
}

std::shared_ptr<File::WritebackResponseHandler>
File::WritebackResponseHandler::CreateHandler(XrdCl::Log &logger, std::unique_ptr<WritebackInfo> writeback_info) {
    std::lock_guard lock(m_instance_mutex);
    auto handler = std::shared_ptr<WritebackResponseHandler>(new WritebackResponseHandler());
#if __cpp_lib_atomic_shared_ptr >= 201711L
    handler->m_self_ref.store(handler, std::memory_order_acquire);
#else
    {
        std::lock_guard lock(handler->m_self_ref_mutex);
        handler->m_self_ref = handler;
    }
#endif
    handler->m_logger = &logger;
    handler->m_writeback_info = std::move(writeback_info);
    if (m_first) {
        handler->m_next = m_first;
        m_first->m_prev = handler.get();
    }
    m_first = handler.get();
    return handler;
}

void
File::WritebackResponseHandler::CloseHandler::HandleResponse(XrdCl::XRootDStatus *status_raw, XrdCl::AnyObject *response_raw) {
    std::unique_ptr<XrdCl::XRootDStatus> status(status_raw);
    std::unique_ptr<XrdCl::AnyObject> response(response_raw);
    std::unique_ptr<CloseHandler> self_ref(this);

    if (!status || !status->IsOK()) {
        std::stringstream ss;
        ss << "Error during close of Pelican writeback file: " << status->ToString();
        m_parent.m_logger->Error(kLogXrdClPelican, "%s", ss.str().c_str());
        {
            std::lock_guard lock(m_parent.m_mutex);
            m_parent.m_error_msg = ss.str();
            m_parent.m_had_error.store(true, std::memory_order_relaxed);
        }
    }
    std::string db_err;
    if (m_parent.HadError()) {
        std::string err = m_parent.GetError();
        WritebackDB::FinalizeTransfer(WritebackDB::TransferState::FAILED, m_parent.GetId(), err, m_parent.GetOffset(), db_err);
    } else {
        m_parent.m_logger->Info(kLogXrdClPelican, "Pelican writeback file with ID %s successfully written (%llu bytes)", m_parent.GetId().c_str(), static_cast<unsigned long long>(m_parent.GetOffset()));
        WritebackDB::FinalizeTransfer(WritebackDB::TransferState::SUCCESS, m_parent.GetId(), "", m_parent.GetOffset(), db_err);
    }
    if (!db_err.empty()) {
        m_parent.m_logger->Error(kLogXrdClPelican, "Failed to finalize writeback transfer in database: %s", db_err.c_str());
    }
#if __cpp_lib_atomic_shared_ptr >= 201711L
    m_parent.m_self_ref.store(nullptr, std::memory_order_release);
#else
    {
        std::lock_guard lock(m_parent.m_self_ref_mutex);
        m_parent.m_self_ref.reset();
    }
#endif
    m_shutdown_cv.notify_all();
}

void
File::WritebackResponseHandler::HandleResponse(XrdCl::XRootDStatus *status_raw, XrdCl::AnyObject *response_raw) {
    std::unique_ptr<XrdCl::XRootDStatus> status(status_raw);
    std::unique_ptr<XrdCl::AnyObject> response(response_raw);
    auto count = m_refcount.fetch_sub(1, std::memory_order_acq_rel);
    if (!status || !status->IsOK()) {
        std::stringstream ss;
        ss << "Error during close of Pelican writeback file: " << status->ToString();
        m_logger->Error(kLogXrdClPelican, "%s", ss.str().c_str());

        std::lock_guard lock(m_mutex);
        m_error_msg = ss.str();
        m_had_error.store(true, std::memory_order_relaxed);
    }
    bool closed = false;
    {
        std::unique_lock lock(m_mutex);
        closed = m_closed;
    }
    if (count == 1 && closed) {
        Shutdown();
    }
}

void
File::WritebackResponseHandler::IncOffset(off_t amount) {
    m_writeback_info->offset += amount;
    m_writeback_info->last_write_time.store(std::chrono::steady_clock::now().time_since_epoch().count(), std::memory_order_relaxed);
}

void
File::WritebackResponseHandler::Maintenance()
{
    auto location_str = Filesystem::GetWritebackCacheLocation();
    if (location_str.empty()) {
        return;
    }
    std::filesystem::path locationpath(location_str);

    // Walk through the active writeback handlers, touching the files on disk
    // if they have not been updated recently
    auto now = std::chrono::steady_clock::now();

    // First, walk the linked list building the vector of work to do.
    std::unique_lock lock(m_instance_mutex);
    std::vector<std::string> paths_to_touch;
    for (auto *curr = m_first; curr; curr = curr->m_next) {
        std::unique_lock file_lock(curr->m_mutex);
        auto id = curr->m_writeback_info->id;
        auto last_update_raw = curr->m_writeback_info->last_write_time.load(std::memory_order_relaxed);
        auto last_update = std::chrono::steady_clock::time_point(std::chrono::steady_clock::duration(last_update_raw));
        if (now - last_update > std::chrono::seconds(5)) {
            auto path = locationpath / (id + ".part");
            paths_to_touch.push_back(path);
        }
    }
    // Drop the lock before touching files, potentially allowing destructors to run for
    // the in-progress writeback handlers.  Since the "touch" below is advisory, it is
    // OK if the file completed & was deleted before we get to it.
    lock.unlock();
    for (const auto &path : paths_to_touch) {
        utimes(path.c_str(), nullptr);
    }

    // Walk the directory, remove stale writeback files
    time_t now_unix = time(nullptr);
    for (const auto &entry : std::filesystem::directory_iterator(locationpath)) {
        if (!entry.is_regular_file()) continue;
        const auto &path = entry.path();
        if (path.extension() != ".part") continue;

        struct stat st;
        if (stat(path.c_str(), &st) != 0) continue;

        if (now_unix - st.st_mtime > 300) { // 5 minutes = 300 seconds
            unlink(path.c_str());
        }
    }
}

void
File::WritebackResponseHandler::Close(std::unique_ptr<XrdCl::File> file) {
    {
        std::unique_lock lock(m_mutex);
        m_wrapped_file = std::move(file);
        m_closed = true;
    }
    if (m_refcount.load(std::memory_order_acquire) == 0) {
        Shutdown();
    };
}

void
File::WritebackResponseHandler::Shutdown() {
    m_logger->Debug(kLogXrdClPelican, "Shutting down Pelican writeback handler");
    WritebackInfo *info = nullptr;
    XrdCl::File *file = nullptr;
    {
        std::unique_lock lock(m_mutex);
        info = m_writeback_info.get();
        file = m_wrapped_file.get();
    }
    if (!info || !file) {
        const std::string errmsg = "Pelican writeback handler shutdown invoked with object in invalid state";
        {
            std::lock_guard lock(m_mutex);
            m_error_msg = errmsg;
            m_had_error.store(true, std::memory_order_relaxed);
        }
        m_logger->Error(kLogXrdClPelican, "%s", errmsg.c_str());
#if __cpp_lib_atomic_shared_ptr >= 201711L
        m_self_ref.store(nullptr, std::memory_order_release);
#else
        {
            std::lock_guard lock(m_self_ref_mutex);
            m_self_ref.reset();
        }
#endif
        m_shutdown_cv.notify_all();
        if (info) {
            std::string db_err;
            if (!WritebackDB::FinalizeTransfer(WritebackDB::TransferState::FAILED, info->id, errmsg, info->offset, db_err)) {
                m_logger->Error(kLogXrdClPelican, "Failed to finalize writeback transfer in database: %s", db_err.c_str());
            }
        }
        return;
    }
    m_logger->Debug(kLogXrdClPelican, "Closing Pelican writeback file with ID %s", info->id.c_str());
    if (munmap(info->mmap, info->size) != 0) {
        m_logger->Error(kLogXrdClPelican, "Failed to munmap Pelican writeback file with ID %s: %s", info->id.c_str(), strerror(errno));
    }
    if (close(info->fd) != 0) {
        m_logger->Error(kLogXrdClPelican, "Failed to close Pelican writeback file with ID %s: %s", info->id.c_str(), strerror(errno));
    }
    auto location_str = Filesystem::GetWritebackCacheLocation();
    if (!location_str.empty()) {
        std::filesystem::path location(location_str);
        auto path = location / (info->id + ".part");
        if (unlink(path.c_str()) != 0) {
            m_logger->Error(kLogXrdClPelican, "Failed to unlink Pelican writeback file at %s: %s", path.c_str(), strerror(errno));
        }
    }

    std::string db_err;
    std::string errmsg;
    if (HadError()) {
        {
            std::lock_guard lock(m_mutex);
            errmsg = m_error_msg;
            if (errmsg.empty()) {
                errmsg = "Unknown error during writeback";
                m_error_msg = errmsg;
            }
        }
        std::stringstream ss;
        ss << "Pelican writeback file with ID " << info->id << " had errors during writeback: " << errmsg;
        m_logger->Info(kLogXrdClPelican, "%s", ss.str().c_str());
    } else if (info->offset != info->size) {
        std::stringstream ss;
        ss << "Pelican writeback file with ID " << info->id << " incomplete at close: wrote " << info->offset << " of " << info->size << " bytes";
        m_logger->Info(kLogXrdClPelican, "%s", ss.str().c_str());
        {
            std::lock_guard lock(m_mutex);
            m_error_msg = ss.str();
            m_had_error.store(true, std::memory_order_relaxed);
        }
        errmsg = ss.str();
    }
    if (!db_err.empty()) {
        m_logger->Error(kLogXrdClPelican, "Failed to finalize writeback transfer in database: %s", db_err.c_str());
    }

    auto final_callback = new CloseHandler(*this);
    auto status = file->Close(final_callback);
    if (!status.IsOK()) {
        std::string errmsg = status.ToString();
        {
            errmsg = "Pelican writeback file with ID " + info->id + " failed to close: " + errmsg;
            std::lock_guard lock(m_mutex);
            m_error_msg = errmsg;
            m_had_error.store(true, std::memory_order_relaxed);
        }
        m_logger->Error(kLogXrdClPelican, "Failed to close Pelican writeback file with ID %s: %s", info->id.c_str(), status.ToStr().c_str());
        std::string db_err;
        if (!WritebackDB::FinalizeTransfer(WritebackDB::TransferState::FAILED, info->id, errmsg, info->offset, db_err)) {
            m_logger->Error(kLogXrdClPelican, "Failed to finalize writeback transfer in database: %s", db_err.c_str());
        }
#if __cpp_lib_atomic_shared_ptr >= 201711L
        m_self_ref.store(nullptr, std::memory_order_release);
#else
        {
            std::lock_guard lock(m_self_ref_mutex);
            m_self_ref.reset();
        }
#endif
        m_shutdown_cv.notify_all();
    }
}

// Wait until all writeback response handlers have been deleted;
// at such a point, it is safe to shutdown the library.
void
File::WritebackResponseHandler::ShutdownAll()
{
    std::unique_lock lock(m_instance_mutex);
    m_shutdown_cv.wait(lock, []{ return m_first == nullptr; });
}

// Wait until all writeback response handlers are idle.
//
// This is slightly different from `ShutdownAll` in that the
// deletion isn't necessary.  This is useful if you want to
// get to a quiescent period (no activity) in the process
// but don't assume all the File instances are deleted (as open
// files will be ).
void
File::WritebackResponseHandler::WaitForAllWritebacks()
{
    std::unique_lock lock(m_instance_mutex);
    m_shutdown_cv.wait(lock, []{
        auto cur = m_first;
        while (cur) {
            std::shared_ptr<File::WritebackResponseHandler> self_ref;
#if __cpp_lib_atomic_shared_ptr >= 201711L
            self_ref = cur->m_self_ref.load(std::memory_order_acquire);
#else
            {
                std::lock_guard lock(cur->m_self_ref_mutex);
                self_ref = cur->m_self_ref;
            }
#endif
            // If the self-ref hasn't been reset, then we have an active writeback
            // and must continue to wait
            if (self_ref != nullptr) {
                return false;
            }
            cur = cur->m_next;
        }
        return true;
    });
}
