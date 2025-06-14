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

#include "CurlFile.hh"
#include "CurlFilesystem.hh"
#include "CurlOps.hh"
#include "../common/CurlResponses.hh"
#include "CurlUtil.hh"
#include "../common/ParseTimeout.hh"
#include "CurlWorker.hh"

#include <XrdCl/XrdClConstants.hh>
#include <XrdCl/XrdClDefaultEnv.hh>
#include <XrdCl/XrdClLog.hh>
#include <XrdCl/XrdClStatus.hh>
#include <XrdCl/XrdClURL.hh>
#include <XrdOuc/XrdOucCRC.hh>
#include <XrdSys/XrdSysPageSize.hh>

#include <nlohmann/json.hpp>
#include <iostream>

using namespace XrdClCurl;

namespace {

class PgReadResponseHandler : public XrdCl::ResponseHandler {
public:
    PgReadResponseHandler(XrdCl::ResponseHandler *handler)
        : m_handler(handler)
    {}

    virtual void HandleResponse(XrdCl::XRootDStatus *status, XrdCl::AnyObject *response) {
        std::unique_ptr<PgReadResponseHandler> holder(this);
        if (!status || !status->IsOK()) {
            if (m_handler) m_handler->HandleResponse(status, response);
            else delete response;
            return;
        }
        if (!m_handler) {
            delete response;
            return;
        }

        // Transform the read result ChunkInfo into a PageInfo.
        XrdCl::ChunkInfo *ci = nullptr;
        response->Get(ci);
        if (!ci) {
            delete response;
            if (m_handler) m_handler->HandleResponse(status, nullptr);
            return;
        }
        std::vector<uint32_t> cksums;
        size_t nbpages = ci->GetLength() / XrdSys::PageSize;
        if (ci->GetLength() % XrdSys::PageSize) ++nbpages;
        cksums.reserve(nbpages);

        auto buffer = static_cast<const char *>(ci->GetBuffer());
        size_t size = ci->GetLength();
        for (size_t pg=0; pg<nbpages; ++pg)
        {
            auto pgsize = static_cast<size_t>(XrdSys::PageSize);
            if (pgsize > size) pgsize = size;
            cksums.push_back(XrdOucCRC::Calc32C(buffer, pgsize));
            buffer += pgsize;
            size -= pgsize;
        }

        auto page_info = new XrdCl::PageInfo(ci->GetOffset(), ci->GetLength(), ci->GetBuffer(), std::move(cksums));
        auto obj = new XrdCl::AnyObject();
        obj->Set(page_info);
        delete response;
        auto handle = m_handler;
        m_handler = nullptr;
        handle->HandleResponse(status, obj);
    }

private:
    XrdCl::ResponseHandler *m_handler;
};

}

// Note: these values are typically overwritten by `CurlFactory::CurlFactory`;
// they are set here just to avoid uninitialized globals.
struct timespec XrdClCurl::File::m_min_client_timeout = {2, 0};
struct timespec XrdClCurl::File::m_default_header_timeout = {9, 5};
struct timespec XrdClCurl::File::m_fed_timeout = {5, 0};

CreateConnCalloutType
File::GetConnCallout() const {
    std::string pointer_str;
    if (!GetProperty("XrdClConnectionCallout", pointer_str) && pointer_str.empty()) {
        return nullptr;
    }
    long long pointer;
    try {
        pointer = std::stoll(pointer_str, nullptr, 16);
    } catch (...) {
        return nullptr;
    }
    if (!pointer) {
        return nullptr;
    }
    return reinterpret_cast<CreateConnCalloutType>(pointer);
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
            logger->Error(kLogXrdClCurl, "Failed to parse xrdclcurl.timeout parameter: %s", errmsg.c_str());
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
        m_logger->Error(kLogXrdClCurl, "URL %s already open", url.c_str());
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidOp);
    }

    // Note: workaround for a design flaw of the XrdCl API.
    //
    // Any properties we set on the file *prior* to opening it are sent to the
    // XrdCl base implementation, not the plugin object.  Hence, they are effectively
    // ignored because the later `GetProperty` accesses a different object.  We want
    // the SetProperty calls to take effect because they are needed for successfully
    // `Open`ing the file.  There's no way to "setup the plugin", "set properties", and
    // then "open file" because the first and third operations are part of the same API
    // call.  We thus allow the caller to trigger the plugin loading by doing a special
    // `Open` call (flags set to Compress, access mode None) that is a no-op.
    //
    // Contrast the XrdCl::File plugin loading style with XrdCl::Filesystem; the latter
    // gets a target URL on construction, before any operations are done, allowing
    // the `SetProperty` to work.
    if ((flags == XrdCl::OpenFlags::Compress) && (mode == XrdCl::Access::None) &&
        (handler == nullptr) && (timeout == 0))
    {
        return XrdCl::XRootDStatus();
    }

    m_open_flags = flags;

    m_header_timeout.tv_nsec = m_default_header_timeout.tv_nsec;
    m_header_timeout.tv_sec = m_default_header_timeout.tv_sec;
    auto parsed_url = XrdCl::URL();
    parsed_url.SetPort(0);
    if (!parsed_url.FromString(url)) {
        m_logger->Error(kLogXrdClCurl, "Failed to parse provided URL as a valid URL: %s", url.c_str());
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidArgs);
    }
    auto pm = parsed_url.GetParams();
    auto iter = pm.find("xrdclcurl.timeout");
    std::string timeout_string = (iter == pm.end()) ? "" : iter->second;
    m_header_timeout = ParseHeaderTimeout(timeout_string, m_logger);
    pm["xrdclcurl.timeout"] = XrdClCurl::MarshalDuration(m_header_timeout);
    parsed_url.SetParams(pm);

    m_url = url;
    m_last_url = "";
    m_url_current = "";

    auto ts = GetHeaderTimeout(timeout);
    m_logger->Debug(kLogXrdClCurl, "Opening %s (with timeout %d)", m_url.c_str(), timeout);

    std::shared_ptr<XrdClCurl::CurlOpenOp> openOp(
        new XrdClCurl::CurlOpenOp(
            handler, GetCurrentURL(), ts, m_logger, this, SendResponseInfo(), GetConnCallout()
        )
    );
    try {
        m_queue->Produce(std::move(openOp));
    } catch (...) {
        m_logger->Warning(kLogXrdClCurl, "Failed to add open op to queue");
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errOSError);
    }

    m_is_opened = true;
    return XrdCl::XRootDStatus();
}

XrdCl::XRootDStatus
File::Close(XrdCl::ResponseHandler *handler,
                        timeout_t /*timeout*/)
{
    if (!m_is_opened) {
        m_logger->Error(kLogXrdClCurl, "Cannot close.  URL isn't open");
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidOp);
    }
    m_is_opened = false;

    if (m_put_op && !m_put_op->HasFailed()) {
        m_logger->Debug(kLogXrdClCurl, "Flushing final write buffer on close");
        try {
            m_put_op->Continue(m_put_op, handler, nullptr, 0);
            return XrdCl::XRootDStatus();
        } catch (...) {
            m_logger->Error(kLogXrdClCurl, "Cannot close - sending final buffer");
            return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errOSError);
        }
    }

    m_logger->Debug(kLogXrdClCurl, "Closed %s", m_url.c_str());
    m_url_current = "";
    m_last_url = "";

    if (handler) {
        handler->HandleResponse(new XrdCl::XRootDStatus(), nullptr);
    }
    return XrdCl::XRootDStatus();
}

XrdCl::XRootDStatus
File::Stat(bool                    /*force*/,
           XrdCl::ResponseHandler *handler,
           timeout_t               timeout)
{
    if (!m_is_opened) {
        m_logger->Error(kLogXrdClCurl, "Cannot stat.  URL isn't open");
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidOp);
    }

    std::string content_length_str;
    int64_t content_length;
    if (!GetProperty("ContentLength", content_length_str)) {
        m_logger->Error(kLogXrdClCurl, "Content length missing for %s", m_url.c_str());
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidOp);
    }
    try {
        content_length = std::stoll(content_length_str);
    } catch (...) {
        m_logger->Error(kLogXrdClCurl, "Content length not an integer for %s", m_url.c_str());
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidOp);
    }
    if (content_length < 0) {
        m_logger->Error(kLogXrdClCurl, "Content length negative for %s", m_url.c_str());
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidResponse);
    }

    m_logger->Debug(kLogXrdClCurl, "Successful stat operation on %s (size %lld)", m_url.c_str(), static_cast<long long>(content_length));
    auto stat_info = new XrdCl::StatInfo("nobody", content_length,
        XrdCl::StatInfo::Flags::IsReadable, time(NULL));
    auto obj = new XrdCl::AnyObject();
    obj->Set(stat_info);

    handler->HandleResponse(new XrdCl::XRootDStatus(), obj);
    return XrdCl::XRootDStatus();
}

XrdCl::XRootDStatus
File::Fcntl(const XrdCl::Buffer &arg, XrdCl::ResponseHandler *handler,
           timeout_t               timeout)
{
    if (!m_is_opened) {
        m_logger->Error(kLogXrdClCurl, "Cannot run fcntl.  URL isn't open");
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidOp);
    }

    auto obj = new XrdCl::AnyObject();
    std::string as = arg.ToString();
    try
    {
        XrdCl::QueryCode::Code code = (XrdCl::QueryCode::Code)std::stoi(as);
        if (code == XrdCl::QueryCode::XAttr)
        {
            nlohmann::json xatt;
            std::string etagRes;
            if (GetProperty("ETag", etagRes))
            {
                xatt["ETag"] = etagRes;
            }
            std::string cc;
            if (GetProperty("Cache-Control", cc))
            {
                if (cc.find("must-revalidate") != std::string::npos)
                {
                    xatt["revalidate"] = true;
                }
                size_t fm = cc.find("max-age=");
                if (fm != std::string::npos)
                {
                    fm += 9; // idx of the first character after the make-age= match
                    for (size_t i = fm; i < cc.length(); i++)
                    {
                        if (!std::isdigit(cc[i]))
                        {
                            std::string sa = cc.substr(fm, i);
                            long int a = std::stol(sa);
                            time_t t = time(NULL) + a;
                            xatt["expire"] = t;
                            break;
                        }
                    }
                }
            }
            XrdCl::Buffer *respBuff = new XrdCl::Buffer();
            m_logger->Debug(kLogXrdClCurl, "Fcntl conent %s", xatt.dump().c_str());
            respBuff->FromString(xatt.dump());
            obj->Set(respBuff);
        }
        //
        //   Query codes supported by  XrdCl::File::Fctnl
        //
        else if (code == XrdCl::QueryCode::Stats)
        {
            m_logger->Error(kLogXrdClCurl, "Server status query not supported.");
            return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidOp);
        }
        else if (code == XrdCl::QueryCode::Checksum || code == XrdCl::QueryCode::ChecksumCancel)
        {
            m_logger->Error(kLogXrdClCurl, "Checksum query not supported.");
            return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidOp);
        }
        else if (code == XrdCl::QueryCode::Config)
        {
            m_logger->Error(kLogXrdClCurl, "Server configuration query not supported.");
            return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidOp);
        }
        else if (code == XrdCl::QueryCode::Space)
        {
            m_logger->Error(kLogXrdClCurl, "Local space stats query not supported.");
            return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidOp);
        }
        else if (code == XrdCl::QueryCode::Opaque || code == XrdCl::QueryCode::OpaqueFile)
        {
            // XrdCl implementation dependent
            m_logger->Error(kLogXrdClCurl, "Opaque query not supported.");
            return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidOp);
        }
        else if (code == XrdCl::QueryCode::Prepare)
        {
            m_logger->Error(kLogXrdClCurl, "Prepare status query not supported.");
            return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidOp);
        }
        else
        {
            m_logger->Error(kLogXrdClCurl, "Invalid information query type code");
            return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidArgs);
        }
    }
    catch (const std::exception& e)
    {
        m_logger->Warning(kLogXrdClCurl, "Failed to parse query code %s", e.what());
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errDataError);
    }

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
    if (!m_is_opened) {
        m_logger->Error(kLogXrdClCurl, "Cannot read.  URL isn't open");
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidOp);
    }
    auto [status, ok] = ReadPrefetch(offset, size, buffer, handler, timeout, false);
    if (ok) {
        return status;
    }

    auto ts = GetHeaderTimeout(timeout);
    auto url = GetCurrentURL();
    m_logger->Debug(kLogXrdClCurl, "Read %s (%d bytes at offset %lld with timeout %lld)", url.c_str(), size, static_cast<long long>(offset), static_cast<long long>(ts.tv_sec));

    std::shared_ptr<XrdClCurl::CurlReadOp> readOp(
        new XrdClCurl::CurlReadOp(
            handler, &m_default_handler, url, ts, std::make_pair(offset, size),
            static_cast<char*>(buffer), size, m_logger,
           GetConnCallout()
        )
    );
    try {
        m_queue->Produce(std::move(readOp));
    } catch (...) {
        m_logger->Warning(kLogXrdClCurl, "Failed to add read op to queue");
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errOSError);
    }

    return XrdCl::XRootDStatus();
}

std::tuple<XrdCl::XRootDStatus, bool>
File::ReadPrefetch(uint64_t offset, uint32_t size, void *buffer, XrdCl::ResponseHandler *handler, timeout_t timeout, bool isPgRead)
{
    // Check if prefetching is enabled; if not, return early.
    auto prefetch_enabled = m_prefetch_enabled.load(std::memory_order_relaxed);
    if (!prefetch_enabled) {
        return std::make_tuple(XrdCl::XRootDStatus{}, false);
    }
    std::unique_lock lock(m_prefetch_mutex);
    if (m_prefetch_size == -1) {
        m_logger->Debug(kLogXrdClCurl, "%sRead prefetch skipping due to unknown file size", isPgRead ? "Pg": "");
        m_prefetch_enabled = false;
    }
    prefetch_enabled = m_prefetch_enabled;
    if (!prefetch_enabled) {
        return std::make_tuple(XrdCl::XRootDStatus{}, false);
    }

    if (isPgRead) {
        handler = new PgReadResponseHandler(handler);
    }

    auto url = GetCurrentURL();
    if (!m_prefetch_op) {
        auto ts = GetHeaderTimeout(timeout);
        m_logger->Debug(kLogXrdClCurl, "%sRead %s (%d bytes at offset %lld with timeout %lld; starting prefetch of size %lld)", isPgRead ? "Pg" : "", url.c_str(), size, static_cast<long long>(offset), static_cast<long long>(ts.tv_sec), static_cast<long long>(m_prefetch_size));

        m_last_prefetch_handler = new PrefetchResponseHandler(*this, offset, size, static_cast<char *>(buffer), handler, timeout);
        m_prefetch_op.reset(
            new XrdClCurl::CurlReadOp(
                m_last_prefetch_handler, &m_default_handler, url, ts, std::make_pair(offset, m_prefetch_size),
                static_cast<char*>(buffer), size, m_logger,
                GetConnCallout()
            )
        );
        try {
            m_queue->Produce(m_prefetch_op);
        } catch (...) {
            m_logger->Warning(kLogXrdClCurl, "Failed to add prefetch read op to queue");
            return std::make_tuple(XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errOSError), true);
        }
        m_prefetch_offset += size;
        return std::make_tuple(XrdCl::XRootDStatus{}, true);
    }
    if (m_prefetch_op->IsDone()) {
        // Prefetch operation has completed (maybe failed); cannot re-use it.
        m_prefetch_enabled = false;
        return std::make_tuple(XrdCl::XRootDStatus{}, false);
    }

    if (m_prefetch_offset != static_cast<off_t>(offset)) {
        // Out-of-order read; can't handle the prefetch.
        return std::make_tuple(XrdCl::XRootDStatus{}, false);
    }
    m_prefetch_offset += size;
    if (m_logger->GetLevel() >= XrdCl::Log::LogLevel::DebugMsg) {
        m_logger->Debug(kLogXrdClCurl, "%sRead %s (%d bytes at offset %lld; using ongoing prefetch)", isPgRead ? "Pg" : "", GetCurrentURL().c_str(), size, static_cast<long long>(offset));
    }
    m_last_prefetch_handler = new PrefetchResponseHandler(*this, offset, size, static_cast<char *>(buffer), handler, timeout);

    return std::make_tuple(XrdCl::XRootDStatus{}, true);
}

XrdCl::XRootDStatus
File::VectorRead(const XrdCl::ChunkList &chunks,
                 void                   *buffer,
                 XrdCl::ResponseHandler *handler,
                 timeout_t               timeout )
{
    if (!m_is_opened) {
        m_logger->Error(kLogXrdClCurl, "Cannot do vector read: URL isn't open");
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidOp);
    }
    if (chunks.empty()) {
        if (handler) {
            auto status = new XrdCl::XRootDStatus();
            auto vr = std::make_unique<XrdCl::VectorReadInfo>();
            vr->SetSize(0);
            auto obj = new XrdCl::AnyObject();
            obj->Set(vr.release());
            handler->HandleResponse(status, obj);
        }
        return XrdCl::XRootDStatus();
    }

    auto ts = GetHeaderTimeout(timeout);
    auto url = GetCurrentURL();
    m_logger->Debug(kLogXrdClCurl, "Read %s (%lld chunks; first chunk is %u bytes at offset %lld with timeout %lld)", url.c_str(), static_cast<long long>(chunks.size()), static_cast<unsigned>(chunks[0].GetLength()), static_cast<long long>(chunks[0].GetOffset()), static_cast<long long>(ts.tv_sec));

    std::shared_ptr<XrdClCurl::CurlVectorReadOp> readOp(
        new XrdClCurl::CurlVectorReadOp(
            handler, url, ts, chunks, m_logger, GetConnCallout()
        )
    );
    try {
        m_queue->Produce(std::move(readOp));
    } catch (...) {
        m_logger->Warning(kLogXrdClCurl, "Failed to add vector read op to queue");
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errOSError);
    }

    return XrdCl::XRootDStatus();
}

XrdCl::XRootDStatus
File::Write(uint64_t                offset,
            uint32_t                size,
            const void             *buffer,
            XrdCl::ResponseHandler *handler,
            timeout_t               timeout)
{
    if (!m_is_opened) {
        m_logger->Error(kLogXrdClCurl, "Cannot write: URL isn't open");
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidOp);
    }
    DisablePrefetch();

    auto ts = GetHeaderTimeout(timeout);
    auto url = GetCurrentURL();
    m_logger->Debug(kLogXrdClCurl, "Write %s (%d bytes at offset %lld with timeout %lld)", url.c_str(), size, static_cast<long long>(offset), static_cast<long long>(ts.tv_sec));

    if (!m_put_op) {
        if (offset != 0) {
            m_logger->Warning(kLogXrdClCurl, "Cannot start PUT operation at non-zero offset");
            return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidArgs, 0, "HTTP uploads must start at offset 0");
        }
        m_put_op.reset(new XrdClCurl::CurlPutOp(
            handler, url, static_cast<const char*>(buffer), size, ts, m_logger, GetConnCallout()
        ));
        try {
            m_queue->Produce(m_put_op);
        } catch (...) {
            m_logger->Warning(kLogXrdClCurl, "Failed to add put op to queue");
            return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errOSError);
        }
        m_offset += size;
        return XrdCl::XRootDStatus();
    }

    if (offset != static_cast<uint64_t>(m_offset)) {
        m_logger->Warning(kLogXrdClCurl, "Requested write offset at %lld does not match current file descriptor offset at %lld",
            static_cast<long long>(offset), static_cast<long long>(m_offset));
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidArgs, 0, "Requested write offset does not match current offset");
    }
    if (m_put_op->HasFailed()) {
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidOp, 0, "Cannot continue writing to open file after error");
    }

    m_offset += size;
    try {
        m_put_op->Continue(m_put_op, handler, static_cast<const char *>(buffer), size);
    } catch (...) {
        m_logger->Warning(kLogXrdClCurl, "Failed to add put op to continuation queue");
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errOSError);
    }
    return XrdCl::XRootDStatus();
}

XrdCl::XRootDStatus
File::Write(uint64_t                offset,
            XrdCl::Buffer         &&buffer,
            XrdCl::ResponseHandler *handler,
            timeout_t               timeout)
{
    if (!m_is_opened) {
        m_logger->Error(kLogXrdClCurl, "Cannot write: URL isn't open");
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidOp);
    }
    DisablePrefetch();

    auto ts = GetHeaderTimeout(timeout);
    auto url = GetCurrentURL();
    m_logger->Debug(kLogXrdClCurl, "Write %s (%d bytes at offset %lld with timeout %lld)", url.c_str(), static_cast<int>(buffer.GetSize()), static_cast<long long>(offset), static_cast<long long>(ts.tv_sec));

    if (!m_put_op) {
        if (offset != 0) {
            return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidArgs, 0, "HTTP uploads must start at offset 0");
        }
        m_put_op.reset(new XrdClCurl::CurlPutOp(
            handler, url, std::move(buffer), ts, m_logger, GetConnCallout()
        ));

        try {
            m_queue->Produce(m_put_op);
        } catch (...) {
            m_logger->Warning(kLogXrdClCurl, "Failed to add put op to queue");
            return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errOSError);
        }
        m_offset += buffer.GetSize();
        return XrdCl::XRootDStatus();
    }

    if (offset != static_cast<uint64_t>(m_offset)) {
        m_logger->Warning(kLogXrdClCurl, "Requested write offset at %lld does not match current file descriptor offset at %lld",
            static_cast<long long>(offset), static_cast<long long>(m_offset));
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidArgs, 0, "Requested write offset does not match current offset");
    }
    if (m_put_op->HasFailed()) {
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidOp, 0, "Cannot continue writing to open file after error");
    }

    m_offset += buffer.GetSize();
    try {
        m_put_op->Continue(m_put_op, handler, std::move(buffer));
    } catch (...) {
        m_logger->Warning(kLogXrdClCurl, "Failed to add put op to continuation queue");
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errOSError);
    }
    return XrdCl::XRootDStatus();
}

XrdCl::XRootDStatus
File::PgRead(uint64_t                offset,
             uint32_t                size,
             void                   *buffer,
             XrdCl::ResponseHandler *handler,
             timeout_t               timeout)
{
    if (!m_is_opened) {
        m_logger->Error(kLogXrdClCurl, "Cannot pgread.  URL isn't open");
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidOp);
    }
    auto [status, ok] = ReadPrefetch(offset, size, buffer, handler, timeout, true);
    if (ok) {
        return status;
    }

    auto ts = GetHeaderTimeout(timeout);
    auto url = GetCurrentURL();
    m_logger->Debug(kLogXrdClCurl, "PgRead %s (%d bytes at offset %lld)", url.c_str(), size, static_cast<long long>(offset));

    std::shared_ptr<XrdClCurl::CurlPgReadOp> readOp(
        new XrdClCurl::CurlPgReadOp(
            handler, &m_default_handler, url, ts, std::make_pair(offset, size),
            static_cast<char*>(buffer), size, m_logger,
            GetConnCallout()
        )
    );

    try {
        m_queue->Produce(std::move(readOp));
    } catch (...) {
        m_logger->Warning(kLogXrdClCurl, "Failed to add read op to queue");
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
File::GetProperty(const std::string &name,
                        std::string &value) const
{
    if (name == "CurrentURL") {
        value = GetCurrentURL();
        return true;
    }

    if (name == "IsPrefetching") {
        value = IsPrefetching() ? "true" : "false";
        return true;
    }

    std::shared_lock lock(m_properties_mutex);
    if (name == "LastURL") {
        value = m_last_url;
        return true;
    }

    const auto p = m_properties.find(name);
    if (p == std::end(m_properties)) {
        return false;
    }

    value = p->second;
    return true;
}

bool File::SendResponseInfo() const {
    std::string val;
    return GetProperty(ResponseInfoProperty, val) && val == "true";
}

bool
File::SetProperty(const std::string &name,
                  const std::string &value)
{
    std::unique_lock lock(m_properties_mutex);

    m_properties[name] = value;
    if (name == "LastURL") {
        m_last_url = value;
        m_url_current = "";
    }
    else if (name == "XrdClCurlQueryParam") {
        CalculateCurrentURL(value);
    }
    else if (name == "XrdClCurlMaintenancePeriod") {
        unsigned period;
        auto ec = std::from_chars(value.c_str(), value.c_str() + value.size(), period);
        if ((ec.ec == std::errc()) && (ec.ptr == value.c_str() + value.size()) && period > 0) {
            m_logger->Debug(kLogXrdClCurl, "Setting maintenance period to %u", period);
            CurlWorker::SetMaintenancePeriod(period);
        }
    }
    else if (name == "XrdClCurlStallTimeout") {
        std::string errmsg;
        timespec ts;
        if (!ParseTimeout(value, ts, errmsg)) {
            m_logger->Debug(kLogXrdClCurl, "Failed to parse timeout value (%s): %s", value.c_str(), errmsg.c_str());
        } else {
            CurlOperation::SetStallTimeout(std::chrono::seconds{ts.tv_sec} + std::chrono::nanoseconds{ts.tv_nsec});
        }
    }
    else if (name == "XrdClCurlPrefetchSize") {
        off_t size;
        auto ec = std::from_chars(value.c_str(), value.c_str() + value.size(), size);
        if ((ec.ec == std::errc()) && (ec.ptr == value.c_str() + value.size())) {
            lock.unlock();
            std::unique_lock lock2(m_prefetch_mutex);
            m_prefetch_size = size;
        } else {
            m_logger->Debug(kLogXrdClCurl, "XrdClCurlPrefetchSize value (%s) was not parseable", value.c_str());
        }
    }
    return true;
}

const std::string
File::GetCurrentURL() const {
    {
        std::shared_lock lock(m_properties_mutex);

        if (!m_url_current.empty()) {
            return m_url_current;
        } else if (m_url.empty() && m_last_url.empty()) {
            return "";
        }
    }
    std::unique_lock lock(m_properties_mutex);

    auto iter = m_properties.find("XrdClCurlQueryParam");
    if (iter == m_properties.end()) {
        return m_last_url.empty() ? m_url : m_last_url;
    }
    CalculateCurrentURL(iter->second);

    return m_url_current;
}

void
File::CalculateCurrentURL(const std::string &value) const {
    const auto &last_url = m_last_url.empty() ? m_url : m_last_url;
    if (value.empty()) {
        m_url_current = last_url;
    } else {
        auto loc = last_url.find('?');
        if (loc == std::string::npos) {
            m_url_current = last_url + '?' + value;
        } else {
            XrdCl::URL url(last_url);
            auto map = url.GetParams(); // Make a copy of the pre-existing parameters
            url.SetParams(value); // Parse the new value
            auto update_map = url.GetParams();
            for (const auto &entry : map) {
                if (update_map.find(entry.first) == update_map.end()) {
                    update_map[entry.first] = entry.second;
                }
            }
            bool first = true;
            std::stringstream ss;
            for (const auto &entry : update_map) {
                ss << (first ? "?" : "&") << entry.first << "=" << entry.second;
                first = false;
            }
            m_url_current = last_url.substr(0, loc) + ss.str();
        }
    }
}

File::PrefetchResponseHandler::PrefetchResponseHandler(
    File &parent, off_t offset, size_t size, char *buffer,
    XrdCl::ResponseHandler *handler, timeout_t timeout
)
    : m_parent(parent),
    m_handler(handler),
    m_buffer(buffer),
    m_size(size),
    m_offset(offset),
    m_timeout(timeout)
{
    if (parent.m_last_prefetch_handler) {
        parent.m_last_prefetch_handler->m_next = this;
    } else {
        m_parent.m_last_prefetch_handler = this;
        if (m_parent.m_prefetch_op) m_parent.m_prefetch_op->Continue(m_parent.m_prefetch_op, this, buffer, size);
    }
}

void
File::PrefetchResponseHandler::HandleResponse(XrdCl::XRootDStatus *status, XrdCl::AnyObject *response) {
    // Ensure that we are deleted once the callback is done.
    std::unique_ptr<PrefetchResponseHandler> owner(this);

    PrefetchResponseHandler *next;
    {
        std::unique_lock lock(m_parent.m_prefetch_mutex);
        next = m_next;
    }
    if (next) {
        if (status && status->IsOK()) {
            m_parent.m_prefetch_op->Continue(m_parent.m_prefetch_op, next, next->m_buffer, next->m_size);
        } else {
            m_parent.DisablePrefetch();
            next->ResubmitOperation();
        }
    }

    {
        std::unique_lock lock(m_parent.m_prefetch_mutex);
        if (m_parent.m_last_prefetch_handler == this) {
            m_parent.m_last_prefetch_handler = nullptr;
        }
        if (!status || !status->IsOK()) {
            m_parent.m_prefetch_op.reset();
            m_parent.m_prefetch_enabled = false;
        }
    }

    if (m_handler) m_handler->HandleResponse(status, response);
    else delete response;
}

void
File::PrefetchResponseHandler::ResubmitOperation()
{
    m_parent.m_logger->Debug(kLogXrdClCurl, "Resubmitting waiting prefetch operations as new reads due to prefetch failure");
    PrefetchResponseHandler *next = this;
    while (next) {
        auto cur = next;
        auto st = next->m_parent.Read(next->m_offset, next->m_size, next->m_buffer, next->m_handler, next->m_timeout);
        if (!st.IsOK() && next->m_handler) {
            next->m_handler->HandleResponse(new XrdCl::XRootDStatus(st), nullptr);
        }
        {
            std::unique_lock lock(next->m_parent.m_prefetch_mutex);
            next = next->m_next;
        }
        delete cur;
    }
}

void
File::PrefetchDefaultHandler::HandleResponse(XrdCl::XRootDStatus *status, XrdCl::AnyObject *response) {
    delete response;
    if (status) {
        m_file.m_logger->Warning(kLogXrdClCurl, "Disabling prefetch due to error: %s", status->ToStr().c_str());
    }
    m_file.DisablePrefetch();
}
