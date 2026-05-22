/****************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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

// Regression test for the bug where prefetch operations lingered in a paused
// libcurl state after File::Close(), accumulating worker slots until they
// expired via the transfer-stall timeout (default 60s).  Under repeated
// open/read/close traffic this exhausted the worker thread's max-ops budget
// and made the file system unresponsive — subsequent Open() calls would block
// in HandlerQueue::Produce on the producer CV until a slot freed up.

#include "XrdClCurl/XrdClCurlFile.hh"
#include "../XrdClCurlCommon/TransferTest.hh"

#include <XrdCl/XrdClDefaultEnv.hh>
#include <XrdCl/XrdClFile.hh>
#include <XrdCl/XrdClLog.hh>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <iostream>
#include <memory>
#include <string>

class CloseDuringPrefetchFixture : public TransferFixture {};

namespace {

struct PrefetchCounters {
    uint64_t count{0};
    uint64_t cancelled{0};
    uint64_t expired{0};
    uint64_t failed{0};
};

// Read the plugin's per-process prefetch counters via the
// "XrdClCurlMonitoringJson" pseudo-property exposed by File::GetProperty.  We
// route through the property bag (rather than calling File::GetMonitoringJson
// directly) because XrdCl loads libXrdClCurl-5.so as a private plugin
// (RTLD_LOCAL) and the test binary links a separate copy of the library —
// only the property path crosses the plugin boundary into the right counters.
PrefetchCounters ReadPrefetchCounters(XrdCl::File &fh) {
    std::string js_str;
    EXPECT_TRUE(fh.GetProperty("XrdClCurlMonitoringJson", js_str));
    auto js = nlohmann::json::parse(js_str);
    const auto &pf = js.at("prefetch");
    PrefetchCounters c;
    c.count = pf.at("count").get<uint64_t>();
    c.cancelled = pf.at("cancelled").get<uint64_t>();
    c.expired = pf.at("expired").get<uint64_t>();
    c.failed = pf.at("failed").get<uint64_t>();
    return c;
}

} // namespace

// Open a file, read enough chunks to trigger prefetch, then Close() before
// the prefetch has finished.  Repeat many times.
//
// We use a body well over a megabyte so the prefetch op cannot complete in
// the gap between the second Read() returning and Close() running, even on
// loopback — this guarantees the op is still in libcurl (running or paused)
// at the moment Close fires.
TEST_F(CloseDuringPrefetchFixture, RapidCloseCancelsPrefetch)
{
    constexpr size_t chunk_size = 64 * 1024;       // 64 KB per Read
    constexpr off_t file_size = 64 * 1024 * 1024;  // 64 MB body

    // The worker's per-thread budget is 20 in-flight ops (XrdClCurlWorker.hh
    // m_max_ops); we deliberately exceed it so that the bug — paused ops
    // pinning slots until the 60s stall timeout — would surface as a hang.
    constexpr int kIterations = 40;
    constexpr unsigned char starting_char = 'a';

    auto url_base = GetOriginURL() + "/test/close_during_prefetch";
    ASSERT_NO_FATAL_FAILURE(WritePattern(url_base, file_size, starting_char, chunk_size));

    auto url = url_base + "?authz=" + GetReadToken();

    // Read the baseline once via a throwaway file — this also forces the
    // plugin to load now so the counters are zero-relative to this point.
    PrefetchCounters before;
    {
        XrdCl::File fh;
        auto rv = fh.Open(url, XrdCl::OpenFlags::Read, XrdCl::Access::Mode(0755),
                          static_cast<XrdClCurl::File::timeout_t>(10));
        ASSERT_TRUE(rv.IsOK()) << "baseline Open failed: " << rv.ToString();
        before = ReadPrefetchCounters(fh);
        ASSERT_TRUE(fh.Close().IsOK());
    }

    auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < kIterations; ++i) {
        XrdCl::File fh;
        auto rv = fh.Open(url, XrdCl::OpenFlags::Read, XrdCl::Access::Mode(0755),
                          static_cast<XrdClCurl::File::timeout_t>(10));
        ASSERT_TRUE(rv.IsOK()) << "Iteration " << i << " Open failed: " << rv.ToString();

        // Two synchronous reads engage the prefetch mechanism (the second
        // read appends a new handler to the in-flight op).  After the
        // second read returns, the prefetch op is left running in the
        // background with hundreds of times the just-consumed bytes still
        // to transfer.
        std::string buf1(chunk_size, '\0');
        std::string buf2(chunk_size, '\0');
        uint32_t got = 0;
        rv = fh.Read(0, chunk_size, buf1.data(), got);
        ASSERT_TRUE(rv.IsOK()) << "Iteration " << i << " Read#1 failed";
        rv = fh.Read(chunk_size, chunk_size, buf2.data(), got);
        ASSERT_TRUE(rv.IsOK()) << "Iteration " << i << " Read#2 failed";

        // Close immediately while the prefetch op is still outstanding.
        // This is the line that, pre-fix, would silently leave a paused op
        // pinned to a worker slot for up to 60s.
        rv = fh.Close();
        ASSERT_TRUE(rv.IsOK()) << "Iteration " << i << " Close failed: " << rv.ToString();
    }
    auto elapsed = std::chrono::steady_clock::now() - t0;
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();

    // Re-read the counters via a fresh open; we cannot reuse the loop's
    // `fh` because it's been closed.
    PrefetchCounters after;
    {
        XrdCl::File fh;
        auto rv = fh.Open(url, XrdCl::OpenFlags::Read, XrdCl::Access::Mode(0755),
                          static_cast<XrdClCurl::File::timeout_t>(10));
        ASSERT_TRUE(rv.IsOK());
        after = ReadPrefetchCounters(fh);
        ASSERT_TRUE(fh.Close().IsOK());
    }
    auto count_delta = after.count - before.count;
    auto cancelled_delta = after.cancelled - before.cancelled;
    auto expired_delta = after.expired - before.expired;
    auto failed_delta = after.failed - before.failed;
    std::cerr << "Prefetch counters delta: count=" << count_delta
              << " cancelled=" << cancelled_delta
              << " expired=" << expired_delta
              << " failed=" << failed_delta
              << " elapsed_ms=" << elapsed_ms
              << std::endl;

    // Confirm prefetch fired in roughly every iteration.  If it didn't, the
    // body of the test isn't exercising the cancel path — perhaps the file
    // size threshold changed or the read pattern stopped triggering prefetch.
    EXPECT_GE(count_delta, static_cast<uint64_t>(kIterations) / 2)
        << "Expected at least " << (kIterations / 2)
        << " prefetch ops to start; saw " << count_delta;

    // The prefetch-cancel counter should have advanced by roughly the
    // iteration count.  Not every iteration is guaranteed to leave the op
    // outstanding (a very fast origin can finish before Close runs), so we
    // require a majority rather than all.
    EXPECT_GE(cancelled_delta, static_cast<uint64_t>(kIterations) / 2)
        << "Expected at least " << (kIterations / 2)
        << " prefetch cancellations; saw " << cancelled_delta;

    // The stall-expiry path is the *old* behavior we replaced.  If it
    // fires, it means Close failed to deliver the cancellation and the op
    // sat until libcurl's 60s transfer-stall timer expired.
    EXPECT_LT(expired_delta, cancelled_delta)
        << "Stall-expiry count (" << expired_delta
        << ") exceeded cancellation count (" << cancelled_delta
        << "); the close-cancel path is not winning the race.";

    // Wall-clock budget.  With the fix, this completes in a few seconds on
    // localhost.  Without the fix, the worker queue fills after ~20
    // iterations and every subsequent Open blocks for ~60s waiting for a
    // paused op to stall-expire.
    EXPECT_LT(elapsed_ms, 30'000)
        << "Rapid open/read/close took " << elapsed_ms
        << " ms; expected <30s.";
}
