/****************************************************************
 *
 * xrdcl-pelican implements an XRootD client plugin for interacting with the Pelican Platform
 * Copyright (C) 2026 Morgridge Institute for Research
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <https://www.gnu.org/licenses/>.
 *
 ***************************************************************/

// A mock XrdCl file plugin for exercising XrdClS3's download error paths.
//
// The final path component of the URL selects the behavior:
//
// - `fail-first-read`: the first Read() fails synchronously.
// - `fail-second-read`: the first Read() returns a few bytes; the second fails
//   synchronously.
//
// Open() and Close() always succeed.  Like the real XrdCl, callbacks are
// delivered from another thread (see MockDispatcher.hh), never from within the
// call that requested them; the caller may destroy the file object from inside
// the callback.

#include "MockDispatcher.hh"
#include "XrdClS3/XrdClS3Filesystem.hh"

#include <XrdCl/XrdClPlugInInterface.hh>
#include <XrdCl/XrdClURL.hh>
#include <XrdCl/XrdClXRootDResponses.hh>
#include <XrdVersion.hh>

#include <atomic>
#include <cerrno>
#include <cstring>
#include <string>

XrdVERSIONINFO(XrdClGetPlugIn, XrdClS3MockFile)

namespace {

using timeout_t = XrdClS3::Filesystem::timeout_t;

// Bytes returned by a successful mock read.
constexpr uint32_t kMockReadLength = 4;

class MockFile final : public XrdCl::FilePlugIn {
public:
    XrdCl::XRootDStatus Open(const std::string &url, XrdCl::OpenFlags::Flags flags, XrdCl::Access::Mode,
                             XrdCl::ResponseHandler *handler, timeout_t) override
    {
        // XrdClS3 issues a no-op open (flags Compress, no handler) to instantiate the
        // plugin so it can set properties before the real open.
        if (flags == XrdCl::OpenFlags::Compress && handler == nullptr) {
            return XrdCl::XRootDStatus{};
        }
        XrdCl::URL parsed(url);
        auto path = parsed.GetPath();
        auto pos = path.rfind('/');
        m_behavior = (pos == std::string::npos) ? path : path.substr(pos + 1);
        m_open.store(true, std::memory_order_release);
        XrdClS3Mock::Dispatch(handler, new XrdCl::XRootDStatus{}, nullptr);
        return XrdCl::XRootDStatus{};
    }

    XrdCl::XRootDStatus Close(XrdCl::ResponseHandler *handler, timeout_t) override
    {
        m_open.store(false, std::memory_order_release);
        XrdClS3Mock::Dispatch(handler, new XrdCl::XRootDStatus{}, nullptr);
        return XrdCl::XRootDStatus{};
    }

    XrdCl::XRootDStatus Read(uint64_t offset, uint32_t size, void *buffer,
                             XrdCl::ResponseHandler *handler, timeout_t) override
    {
        auto read_idx = m_reads.fetch_add(1, std::memory_order_acq_rel);
        if (m_behavior == "fail-first-read" ||
            (m_behavior == "fail-second-read" && read_idx >= 1))
        {
            return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errOSError, EIO, "mock synchronous read failure");
        }
        auto length = size < kMockReadLength ? size : kMockReadLength;
        memset(buffer, 'x', length);
        auto obj = new XrdCl::AnyObject();
        obj->Set(new XrdCl::ChunkInfo(offset, length, buffer));
        XrdClS3Mock::Dispatch(handler, new XrdCl::XRootDStatus{}, obj);
        return XrdCl::XRootDStatus{};
    }

    bool IsOpen() const override { return m_open.load(std::memory_order_acquire); }

    bool SetProperty(const std::string &, const std::string &) override { return true; }

    bool GetProperty(const std::string &, std::string &) const override { return false; }

private:
    std::string m_behavior;
    std::atomic<bool> m_open{false};
    std::atomic<unsigned> m_reads{0};
};

class MockFactory final : public XrdCl::PlugInFactory {
public:
    XrdCl::FilePlugIn *CreateFile(const std::string &) override { return new MockFile(); }
    XrdCl::FileSystemPlugIn *CreateFileSystem(const std::string &) override { return nullptr; }
};

} // namespace

extern "C"
{
    void *XrdClGetPlugIn(const void *)
    {
        return static_cast<void *>(new MockFactory());
    }
}
