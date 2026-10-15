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

// Regression tests for the teardown of a PrefetchResponseHandler chain.
//
// When a prefetch leg fails (or short-reads), PrefetchResponseHandler::
// HandleResponse hands the rest of the chain to ResubmitOperation, which walks
// it and deletes every node.  Before the fix, File::m_last_prefetch_handler was
// left pointing at the freed tail, and prefetching was disabled in a *separate*
// acquisition of m_prefetch_mutex than the one that consumed m_next.  Both are
// problems:
//
//   * A ReadPrefetch blocked on m_prefetch_mutex can be handed the lock in the
//     gap, still observe m_prefetch_enabled == true, and link its handler onto
//     a node ResubmitOperation is about to free.  Nothing ever invokes that
//     handler, so the caller blocks forever -- in a cache that is an XrdPfc
//     thread parked on an untimed condition variable.
//   * The stale tail pointer itself survives the teardown, so any later path
//     that re-enables prefetching on the same File dereferences freed memory.
//
// The fix performs the teardown -- disable prefetch, clear the tail, drop the
// op -- inside the same critical section that decides to tear down, so a racing
// reader either appends to a live chain or takes the non-prefetch path.

#include "../XrdClCurlCommon/TransferTest.hh"

#include <XrdCl/XrdClFile.hh>

#include <gtest/gtest.h>

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

class PrefetchChainTeardownFixture : public TransferFixture {};

namespace {

// Records completion so the test can assert that every issued read was
// answered.  A handler that is stranded by the teardown bug never fires.
class CountingHandler : public XrdCl::ResponseHandler {
public:
    void HandleResponse(XrdCl::XRootDStatus *status, XrdCl::AnyObject *response) override {
        delete response;
        std::unique_lock lock(m_mutex);
        m_status.reset(status);
        m_done = true;
        m_cv.notify_all();
    }

    // Returns false if the handler was never invoked within the timeout.
    bool WaitDone(std::chrono::milliseconds timeout) {
        std::unique_lock lock(m_mutex);
        return m_cv.wait_for(lock, timeout, [&]{ return m_done; });
    }

private:
    std::mutex m_mutex;
    std::condition_variable m_cv;
    bool m_done{false};
    std::unique_ptr<XrdCl::XRootDStatus> m_status;
};

constexpr size_t kChunk = 1024 * 1024;
// Deliberately not a multiple of kChunk: the leg starting at 4 MiB asks for a
// full chunk and can only be given 512 KiB, which is what drives
// HandleResponse down the mismatched-size teardown path.
constexpr off_t kFileSize = 4 * 1024 * 1024 + 512 * 1024;

} // namespace

// Build a prefetch chain deep enough that the short-reading leg still has a
// successor queued behind it (the `next != nullptr` teardown), then re-enable
// prefetching on the same File and read again.
//
// Pre-fix, the re-enabled read reaches
//     parent.m_last_prefetch_handler->m_next = this;
// in the PrefetchResponseHandler constructor with a tail that ResubmitOperation
// already freed -- an ASan heap-use-after-free write.  Post-fix the tail was
// cleared during teardown, so the read starts a fresh chain.
//
// This case needs ASan to show the defect; the stranded-read case below is what
// catches it without instrumentation.
TEST_F(PrefetchChainTeardownFixture, StaleTailAfterChainTeardown)
{
    auto url_base = GetOriginURL() + "/test/prefetch_chain_teardown";
    ASSERT_NO_FATAL_FAILURE(WritePattern(url_base, kFileSize, 'a', kChunk));
    auto url = url_base + "?authz=" + GetReadToken();

    XrdCl::File fh;
    auto rv = fh.Open(url, XrdCl::OpenFlags::Read, XrdCl::Access::Mode(0755),
                      static_cast<uint16_t>(10));
    ASSERT_TRUE(rv.IsOK()) << "Open failed: " << rv.ToString();

    // Every leg starts past EOF, so the prefetch op's ranged GET comes back 416
    // and the operation fails outright.  That matters: only the failure path
    // (status not OK) drops File::m_prefetch_op, and a null m_prefetch_op is what
    // sends the next ReadPrefetch down the "start a new prefetch" branch, where
    // the PrefetchResponseHandler constructor dereferences m_last_prefetch_handler.
    // A merely short read leaves m_prefetch_op set and ReadPrefetch bails on
    // IsDone() before ever touching the tail.
    //
    // The legs are issued back-to-back and asynchronously so legs 2..N are queued
    // behind leg 1 when it fails: the teardown has to have a successor
    // (next != nullptr) or the tail retirement added in a1476f371 already covers it.
    constexpr int kLegs = 4;
    std::vector<std::unique_ptr<CountingHandler>> handlers;
    std::vector<std::vector<char>> buffers;
    for (int i = 0; i < kLegs; ++i) {
        handlers.emplace_back(new CountingHandler());
        buffers.emplace_back(kChunk, '\0');
    }
    for (int i = 0; i < kLegs; ++i) {
        auto offset = static_cast<uint64_t>(kFileSize) + static_cast<uint64_t>(i) * kChunk;
        rv = fh.Read(offset, kChunk, buffers[i].data(), handlers[i].get(),
                     static_cast<uint16_t>(10));
        ASSERT_TRUE(rv.IsOK()) << "async Read " << i << " failed: " << rv.ToString();
    }
    for (int i = 0; i < kLegs; ++i) {
        EXPECT_TRUE(handlers[i]->WaitDone(std::chrono::seconds(30)))
            << "leg " << i << " was never completed; its handler was stranded by "
            << "the chain teardown";
    }

    // Re-enable prefetching on this File.  Pre-fix the teardown left
    // m_last_prefetch_handler pointing at a node ResubmitOperation freed, so the
    // read below writes through it inside the PrefetchResponseHandler constructor.
    ASSERT_TRUE(fh.SetProperty("XrdClCurlFullDownload", "true"));

    std::vector<char> tail_buf(kChunk, '\0');
    uint32_t got = 0;
    // The status is not the point -- reaching the constructor is.
    fh.Read(0, kChunk, tail_buf.data(), got, static_cast<uint16_t>(10));

    ASSERT_TRUE(fh.Close().IsOK());
}
