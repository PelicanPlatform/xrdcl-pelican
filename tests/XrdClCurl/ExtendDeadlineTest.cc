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

// Unit tests for CurlOperation::ExtendDeadline().
//
// A streamed PUT is one curl operation spanning every client Write(), and the
// server sends no response header until the body is complete.  Each write
// pushes the header deadline out so the upload is not capped by the timeout
// of the first write.  HeaderTimeoutExpired() takes the current time as an
// argument, so these tests check the deadline arithmetic without waiting.

#include "XrdClCurl/XrdClCurlOps.hh"

#include <XrdCl/XrdClDefaultEnv.hh>
#include <XrdCl/XrdClLog.hh>

#include <gtest/gtest.h>

#include <chrono>
#include <string>
#include <thread>
#include <vector>

using namespace XrdClCurl;
using namespace std::chrono_literals;

namespace {

class DeadlineOp final : public CurlOperation {
public:
    DeadlineOp(std::chrono::steady_clock::time_point expiry)
        : CurlOperation(nullptr, "https://example.com/obj", expiry, XrdCl::DefaultEnv::GetLog(), nullptr, nullptr) {}

    void Success() override {}
    HttpVerb GetVerb() const override { return HttpVerb::PUT; }
};

} // namespace

// Without an extension, the header deadline from construction is enforced.
TEST(CurlExtendDeadline, HeaderTimeoutEnforcedWithoutExtension)
{
    auto start = std::chrono::steady_clock::now();
    DeadlineOp op(start + 2s);

    EXPECT_FALSE(op.HeaderTimeoutExpired(start + 1s));
    EXPECT_TRUE(op.HeaderTimeoutExpired(start + 3s));
}

// A later write's timeout moves the header deadline past the original one.
TEST(CurlExtendDeadline, ExtendsDeadline)
{
    auto start = std::chrono::steady_clock::now();
    DeadlineOp op(start + 2s);

    op.ExtendDeadline({60, 0});
    EXPECT_GE(op.GetHeaderExpiry(), start + 60s);
    EXPECT_FALSE(op.HeaderTimeoutExpired(start + 3s));
    EXPECT_TRUE(op.HeaderTimeoutExpired(op.GetHeaderExpiry() + 1s));

    // Before any header or payload byte, the operation expiry tracks the
    // header deadline, so the queue sweeps see the extension too.
    EXPECT_EQ(op.GetOperationExpiry(), op.GetHeaderExpiry());
}

// A write with a shorter timeout never pulls the deadline in.
TEST(CurlExtendDeadline, NeverShortensDeadline)
{
    auto start = std::chrono::steady_clock::now();
    DeadlineOp op(start + 60s);
    auto original = op.GetHeaderExpiry();

    op.ExtendDeadline({1, 0});
    EXPECT_EQ(op.GetHeaderExpiry(), original);
    EXPECT_FALSE(op.HeaderTimeoutExpired(start + 30s));
}

// Writes extend the deadline from client threads while the worker reads it;
// concurrent extensions must settle on the latest deadline requested.
TEST(CurlExtendDeadline, ConcurrentExtensionsKeepLatest)
{
    auto start = std::chrono::steady_clock::now();
    DeadlineOp op(start + 1s);

    constexpr int kThreads = 8;
    constexpr int kIterations = 1000;
    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (int idx = 0; idx < kThreads; ++idx) {
        threads.emplace_back([&op, idx] {
            for (int iter = 0; iter < kIterations; ++iter) {
                op.ExtendDeadline({10 + idx, 0});
            }
        });
    }
    for (auto &thread : threads) {
        thread.join();
    }

    // The longest timeout requested was 10 + (kThreads - 1) seconds.
    EXPECT_GE(op.GetHeaderExpiry(), start + std::chrono::seconds(10 + kThreads - 1));
    EXPECT_LT(op.GetHeaderExpiry(), std::chrono::steady_clock::now() + std::chrono::seconds(10 + kThreads));
}
