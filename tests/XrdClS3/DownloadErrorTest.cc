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

// Error-path tests for XrdClS3::DownloadUrl().
//
// The download is served by the mock file plugin in MockFilePlugIn.cc, loaded
// through XRD_PLUGINCONFDIR for `mocks3://` URLs, whose Read() fails
// synchronously on demand.

#include "MockDispatcher.hh"
#include "XrdClS3/XrdClS3DownloadHandler.hh"

#include <XrdCl/XrdClXRootDResponses.hh>

#include <gtest/gtest.h>

#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>

using namespace std::chrono_literals;

namespace {

class WaitHandler final : public XrdCl::ResponseHandler {
public:
    void HandleResponse(XrdCl::XRootDStatus *status, XrdCl::AnyObject *response) override
    {
        std::lock_guard lock(m_mutex);
        m_status.reset(status);
        m_response.reset(response);
        m_done = true;
        m_cv.notify_all();
    }

    // Returns false if no response arrived before the timeout.
    bool Wait(std::chrono::seconds timeout)
    {
        std::unique_lock lock(m_mutex);
        return m_cv.wait_for(lock, timeout, [&] { return m_done; });
    }

    const XrdCl::XRootDStatus *Status() const { return m_status.get(); }

private:
    std::mutex m_mutex;
    std::condition_variable m_cv;
    bool m_done{false};
    std::unique_ptr<XrdCl::XRootDStatus> m_status;
    std::unique_ptr<XrdCl::AnyObject> m_response;
};

void ExpectReadFailure(const std::string &url)
{
    WaitHandler handler;
    auto st = XrdClS3::DownloadUrl(url, nullptr, &handler, 30);
    ASSERT_TRUE(st.IsOK()) << "Failed to start download of " << url << ": " << st.ToString();
    auto completed = handler.Wait(30s);

    // The download chain keeps running on the dispatcher thread after the final
    // callback, tearing down the file object.  Let it finish before any return
    // so it cannot race XrdCl's finalization at process exit.
    ASSERT_TRUE(XrdClS3Mock::Drain(30s)) << "Mock callbacks for " << url << " never finished";
    ASSERT_TRUE(completed) << "Download of " << url << " never completed";

    auto status = handler.Status();
    ASSERT_NE(status, nullptr);
    EXPECT_FALSE(status->IsOK()) << "Download of " << url << " reported success after a failed read";
    EXPECT_EQ(status->code, XrdCl::errOSError) << status->ToString();
    EXPECT_EQ(status->errNo, static_cast<uint32_t>(EIO)) << status->ToString();
}

} // namespace

// The first read fails synchronously.  The download handler had already moved
// its ownership into the read handler, so the close handler received a null
// parent and crashed when the close completed.
TEST(S3DownloadError, FirstReadFailsSynchronously)
{
    ExpectReadFailure("mocks3://mock.invalid/bucket/fail-first-read");
}

// A follow-on read fails synchronously.  The download must report the read
// error rather than delivering the partially filled buffer as a success.
TEST(S3DownloadError, SecondReadFailsSynchronously)
{
    ExpectReadFailure("mocks3://mock.invalid/bucket/fail-second-read");
}
