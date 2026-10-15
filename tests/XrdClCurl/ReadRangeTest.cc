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

// Unit tests for the Range header CurlReadOp sends.
//
// Full-download mode reads the whole object with one GET.  File marks that
// with an off_t-sized "whole object" prefetch size; CurlReadOp must recognize
// that same value and send no Range header.  The two once used different
// sentinels (INT64_MAX vs UINT64_MAX), so every full download sent
// "Range: bytes=0-9223372036854775806".

#include "XrdClCurl/XrdClCurlOps.hh"
#include "XrdClCurl/XrdClCurlOptionsCache.hh"
#include "XrdClCurl/XrdClCurlUtil.hh"
#include "XrdClCurl/XrdClCurlWorker.hh"

#include <XrdCl/XrdClDefaultEnv.hh>
#include <XrdCl/XrdClLog.hh>

#include <gtest/gtest.h>

#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace {

// Exposes the request headers CurlReadOp::Setup() computes.
class TestReadOp final : public XrdClCurl::CurlReadOp {
public:
    TestReadOp(uint64_t offset, uint64_t size, std::vector<char> &buffer)
        : XrdClCurl::CurlReadOp(nullptr, nullptr, "https://example.com/obj", {30, 0},
                                {offset, size}, buffer.data(), buffer.size(),
                                XrdCl::DefaultEnv::GetLog(), nullptr, nullptr)
    {}

    std::optional<std::string> GetRangeHeader() const {
        for (const auto &[name, value] : m_headers_list) {
            if (name == "Range") return value;
        }
        return std::nullopt;
    }
};

// CurlOperation::Setup() takes a worker only to look up client credentials.
// Workers register themselves in process-wide monitoring state and never
// deregister, so keep this one alive for the life of the process.
XrdClCurl::CurlWorker &GetWorker() {
    static auto *worker = new XrdClCurl::CurlWorker(
        std::make_shared<XrdClCurl::HandlerQueue>(10), XrdClCurl::VerbsCache::Instance(),
        XrdCl::DefaultEnv::GetLog());
    return *worker;
}

std::optional<std::string> RangeHeaderFor(uint64_t offset, uint64_t size) {
    std::vector<char> buffer(1024);
    TestReadOp op(offset, size, buffer);
    EXPECT_TRUE(op.Setup(curl_easy_init(), GetWorker()));
    return op.GetRangeHeader();
}

} // namespace

TEST(CurlReadRange, PartialReadSendsInclusiveRange)
{
    auto range = RangeHeaderFor(1024, 4096);
    ASSERT_TRUE(range.has_value());
    EXPECT_EQ(*range, "bytes=1024-5119");
}

TEST(CurlReadRange, WholeObjectSendsNoRange)
{
    auto range = RangeHeaderFor(0, XrdClCurl::CurlReadOp::kWholeObject);
    EXPECT_FALSE(range.has_value()) << "Unexpected Range: " << *range;
}

// The value File's full-download mode actually stores as its prefetch size.
TEST(CurlReadRange, FullDownloadPrefetchSizeSendsNoRange)
{
    auto full_download_size = static_cast<uint64_t>(std::numeric_limits<off_t>::max());
    auto range = RangeHeaderFor(0, full_download_size);
    EXPECT_FALSE(range.has_value()) << "Unexpected Range: " << *range;
}
