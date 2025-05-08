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

#include <XrdCl/XrdClConstants.hh>
#include <XrdCl/XrdClDefaultEnv.hh>
#include <XrdCl/XrdClLog.hh>
#include <XrdCl/XrdClStatus.hh>
#include <XrdCl/XrdClURL.hh>

using namespace XrdClCurl;

// Note: these values are typically overwritten by `PelicanFactory::PelicanFactory`;
// they are set here just to avoid uninitialized globals.
struct timespec XrdClCurl::File::m_min_client_timeout = {2, 0};
struct timespec XrdClCurl::File::m_default_header_timeout = {9, 5};
struct timespec XrdClCurl::File::m_fed_timeout = {5, 0};

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

    m_open_flags = flags;

    m_header_timeout.tv_nsec = m_default_header_timeout.tv_nsec;
    m_header_timeout.tv_sec = m_default_header_timeout.tv_sec;
    auto parsed_url = XrdCl::URL();
    parsed_url.SetPort(0);
    if (!parsed_url.FromString(url)) {
        m_logger->Error(kLogXrdClCurl, "Failed to parse provifded URL as a valid URL: %s", url.c_str());
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidArgs);
    }
    auto pm = parsed_url.GetParams();
    auto iter = pm.find("xrdclcurl.timeout");
    std::string timeout_string = (iter == pm.end()) ? "" : iter->second;
    m_header_timeout = ParseHeaderTimeout(timeout_string, m_logger);
    pm["xrdclcurl.timeout"] = XrdClCurl::MarshalDuration(m_header_timeout);
    parsed_url.SetParams(pm);

    m_url = url;

    auto ts = GetHeaderTimeout(timeout);
    m_logger->Debug(kLogXrdClCurl, "Opening %s (with timeout %d)", m_url.c_str(), timeout);

    std::shared_ptr<XrdClCurl::CurlOpenOp> openOp(new XrdClCurl::CurlOpenOp(handler, m_url, ts, m_logger, this, SendResponseInfo()));
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

    std::string url;
    if (!GetProperty("LastURL", url)) {
        url = m_url;
    }

    auto ts = GetHeaderTimeout(timeout);
    m_logger->Debug(kLogXrdClCurl, "Read %s (%d bytes at offset %lld with timeout %lld)", url.c_str(), size, static_cast<long long>(offset), static_cast<long long>(ts.tv_sec));

    std::shared_ptr<XrdClCurl::CurlReadOp> readOp(new XrdClCurl::CurlReadOp(handler, url, ts, std::make_pair(offset, size), static_cast<char*>(buffer), m_logger));
    std::string broker;
    if (GetProperty("BrokerURL", broker) && !broker.empty()) {
        readOp->SetBrokerUrl(broker);
    }
    std::string use_x509;
    if (GetProperty("UseX509Auth", use_x509) && use_x509 == "true") {
        readOp->SetUseX509();
    }
    try {
        m_queue->Produce(std::move(readOp));
    } catch (...) {
        m_logger->Warning(kLogXrdClCurl, "Failed to add read op to queue");
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errOSError);
    }

    return XrdCl::XRootDStatus();
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

    std::string url;
    if (!GetProperty("LastURL", url)) {
        url = m_url;
    }

    auto ts = GetHeaderTimeout(timeout);
    m_logger->Debug(kLogXrdClCurl, "Read %s (%lld chunks; first chunk is %u bytes at offset %lld with timeout %lld)", url.c_str(), static_cast<long long>(chunks.size()), static_cast<unsigned>(chunks[0].GetLength()), static_cast<long long>(chunks[0].GetOffset()), static_cast<long long>(ts.tv_sec));

    std::shared_ptr<XrdClCurl::CurlVectorReadOp> readOp(new XrdClCurl::CurlVectorReadOp(handler, url, ts, chunks, m_logger));
    std::string broker;
    if (GetProperty("BrokerURL", broker) && !broker.empty()) {
        readOp->SetBrokerUrl(broker);
    }
    std::string use_x509;
    if (GetProperty("UseX509Auth", use_x509) && use_x509 == "true") {
        readOp->SetUseX509();
    }
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

    std::string url;
    if (!GetProperty("LastURL", url)) {
        url = m_url;
    }

    auto ts = GetHeaderTimeout(timeout);
    m_logger->Debug(kLogXrdClCurl, "Write %s (%d bytes at offset %lld with timeout %lld)", url.c_str(), size, static_cast<long long>(offset), static_cast<long long>(ts.tv_sec));

    if (!m_put_op) {
        if (offset != 0) {
            m_logger->Warning(kLogXrdClCurl, "Cannot start PUT operation at non-zero offset");
            return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidArgs, 0, "HTTP uploads must start at offset 0");
        }
        m_put_op.reset(new XrdClCurl::CurlPutOp(handler, url, static_cast<const char*>(buffer), size, ts, m_logger));
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

    std::string url;
    if (!GetProperty("LastURL", url)) {
        url = m_url;
    }

    auto ts = GetHeaderTimeout(timeout);
    m_logger->Debug(kLogXrdClCurl, "Write %s (%d bytes at offset %lld with timeout %lld)", url.c_str(), static_cast<int>(buffer.GetSize()), static_cast<long long>(offset), static_cast<long long>(ts.tv_sec));

    if (!m_put_op) {
        if (offset != 0) {
            return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidArgs, 0, "HTTP uploads must start at offset 0");
        }
        m_put_op.reset(new XrdClCurl::CurlPutOp(handler, url, std::move(buffer), ts, m_logger));

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

    std::string url;
    if (!GetProperty("LastURL", url)) {
        url = m_url;
    }

    auto ts = GetHeaderTimeout(timeout);
    m_logger->Debug(kLogXrdClCurl, "PgRead %s (%d bytes at offset %lld)", url.c_str(), size, static_cast<long long>(offset));

    std::shared_ptr<XrdClCurl::CurlPgReadOp> readOp(new XrdClCurl::CurlPgReadOp(handler, url, ts, std::make_pair(offset, size), static_cast<char*>(buffer), m_logger));
    std::string broker;
    if (GetProperty("BrokerURL", broker) && !broker.empty()) {
        readOp->SetBrokerUrl(broker);
    }
    std::string use_x509;
    if (GetProperty("UseX509Auth", use_x509) && use_x509 == "true") {
        readOp->SetUseX509();
    }

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
    m_properties[name] = value;
    return true;
}
