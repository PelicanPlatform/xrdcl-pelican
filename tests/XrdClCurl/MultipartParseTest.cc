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

// Unit tests for the multipart/byteranges parser in CurlVectorReadOp::Write().
//
// Curl may end a write callback at any byte of the response body, so the
// parser must produce identical results however the body is split.  These
// tests drive Write() directly and need no running server.

#include "XrdClCurl/XrdClCurlOps.hh"

#include <XrdCl/XrdClDefaultEnv.hh>
#include <XrdCl/XrdClLog.hh>

#include <gtest/gtest.h>

#include <cstring>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr const char *kBoundary = "123456";

struct Part {
    off_t offset;
    std::string payload;
};

// Format one part the way XrdHttp does, including the CRLF it emits in front
// of every boundary line.
std::string MakeXrdHttpPart(off_t start, std::string_view payload, off_t filesize)
{
    const off_t end = start + static_cast<off_t>(payload.size()) - 1;
    std::string part;
    part += "\r\n--";
    part += kBoundary;
    part += "\r\n";
    part += "Content-type: text/plain; charset=UTF-8\r\n";
    part += "Content-Range: bytes ";
    part += std::to_string(start);
    part += "-";
    part += std::to_string(end);
    part += "/";
    part += std::to_string(filesize);
    part += "\r\n\r\n";
    part.append(payload.data(), payload.size());
    return part;
}

std::string MakeXrdHttpMultipart(const std::vector<Part> &parts, off_t filesize)
{
    std::string body;
    for (const auto &part : parts) {
        body += MakeXrdHttpPart(part.offset, part.payload, filesize);
    }
    body += "\r\n--";
    body += kBoundary;
    body += "--\r\n";
    return body;
}

// Feed `body` to a fresh vector read op as a sequence of writes that end at
// the offsets in `splits`, then check every requested chunk received its
// expected payload.
void ExpectMultipartBody(const std::string &body, const std::vector<Part> &expected,
                         const std::vector<size_t> &splits = {})
{
    std::vector<std::vector<char>> bufs;
    bufs.reserve(expected.size());
    XrdCl::ChunkList chunks;
    chunks.reserve(expected.size());
    for (const auto &part : expected) {
        bufs.emplace_back(part.payload.size(), '\0');
        chunks.emplace_back(part.offset, static_cast<uint32_t>(part.payload.size()), bufs.back().data());
    }

    auto logger = XrdCl::DefaultEnv::GetLog();
    XrdClCurl::CurlVectorReadOp vr(nullptr, "https://example.com", {10, 0}, chunks, logger, nullptr, nullptr);
    vr.SetStatusCode(206);
    vr.SetSeparator(kBoundary);

    std::string data(body);
    size_t start = 0;
    auto feed = [&](size_t end) {
        auto len = end - start;
        ASSERT_EQ(len, vr.Write(data.data() + start, len)) << "Write of bytes [" << start << ", " << end << ") failed";
        start = end;
    };
    for (auto split : splits) {
        if (split <= start || split >= data.size()) continue;
        feed(split);
        if (::testing::Test::HasFatalFailure()) return;
    }
    feed(data.size());
    if (::testing::Test::HasFatalFailure()) return;

    for (size_t i = 0; i < expected.size(); ++i) {
        ASSERT_EQ(expected[i].payload, std::string(bufs[i].data(), bufs[i].size())) << "Mismatch in chunk " << i;
    }
}

std::string SplitDescription(const std::vector<size_t> &splits)
{
    std::string result;
    for (auto split : splits) {
        if (!result.empty()) result += ",";
        result += std::to_string(split);
    }
    return result;
}

} // namespace

// A Content-Range line split across three writes, where the middle write
// contains no CRLF at all.
TEST(CurlMultipartParse, SplitHeaderLineAcrossWrites)
{
    const std::string part1 =
        "\r\n--123456\r\n"
        "Content-type: text/plain; charset=UTF-8\r\n"
        "Content-Range: by";
    const std::string part2 = "tes 0-";
    const std::string part3 =
        "1/8\r\n"
        "\r\n"
        "aa"
        "\r\n--123456\r\n"
        "Content-type: text/plain; charset=UTF-8\r\n"
        "Content-Range: bytes 2-3/8\r\n"
        "\r\n"
        "bb"
        "\r\n--123456--\r\n";
    ExpectMultipartBody(part1 + part2 + part3, {{0, "aa"}, {2, "bb"}},
                        {part1.size(), part1.size() + part2.size()});
}

// Curl often ends a write after the Content-Range line, with the blank line
// that terminates the part headers in the next write.  The parser must not
// treat that blank line as payload.
TEST(CurlMultipartParse, SplitAfterContentRangeBeforeBody)
{
    const std::string part1 =
        "\r\n--123456\r\n"
        "Content-type: text/plain; charset=UTF-8\r\n"
        "Content-Range: bytes 0-1/8\r\n";
    const std::string part2 =
        "\r\n"
        "aa"
        "\r\n--123456\r\n"
        "Content-type: text/plain; charset=UTF-8\r\n"
        "Content-Range: bytes 2-3/8\r\n"
        "\r\n"
        "bb"
        "\r\n--123456--\r\n";
    ExpectMultipartBody(part1 + part2, {{0, "aa"}, {2, "bb"}}, {part1.size()});
}

// The CRLF that ends the boundary line is split across writes.
TEST(CurlMultipartParse, SplitCRLFAfterBoundary)
{
    const std::string part1 = "\r\n--123456\r";
    const std::string part2 =
        "\n"
        "Content-type: text/plain; charset=UTF-8\r\n"
        "Content-Range: bytes 0-1/8\r\n"
        "\r\n"
        "aa"
        "\r\n--123456\r\n"
        "Content-type: text/plain; charset=UTF-8\r\n"
        "Content-Range: bytes 2-3/8\r\n"
        "\r\n"
        "bb"
        "\r\n--123456--\r\n";
    ExpectMultipartBody(part1 + part2, {{0, "aa"}, {2, "bb"}}, {part1.size()});
}

// The server emits parts in offset order while the client's request list is
// shuffled.
TEST(CurlMultipartParse, OutOfOrderChunks)
{
    const std::vector<Part> requested{
        {6, "dd"},
        {0, "aa"},
        {2, "bb"},
    };
    const std::vector<Part> server_parts{
        {0, "aa"},
        {2, "bb"},
        {6, "dd"},
    };
    ExpectMultipartBody(MakeXrdHttpMultipart(server_parts, 8), requested);
}

// Extra CRLFs before boundaries, as permitted by RFC 7233 and emitted by XrdHttp.
TEST(CurlMultipartParse, ExtraCRLFBeforeBoundary)
{
    const std::vector<Part> parts{
        {0, "aa"},
        {2, "bb"},
        {6, "dd"},
    };
    std::string body = "\r\n\r\n";
    for (const auto &part : parts) {
        body += MakeXrdHttpPart(part.offset, part.payload, 8);
    }
    body += "\r\n\r\n--";
    body += kBoundary;
    body += "--\r\n";
    ExpectMultipartBody(body, parts);
}

// The server coalesced two adjacent requested ranges into one Content-Range.
TEST(CurlMultipartParse, CoalescedRange)
{
    std::string body = MakeXrdHttpPart(0, "aabb", 8);
    body += "\r\n--";
    body += kBoundary;
    body += "--\r\n";
    ExpectMultipartBody(body, {{0, "aa"}, {2, "bb"}});
}

// Payload bytes that look like framing (CRLF, boundary lines, NULs) must be
// copied as data.
TEST(CurlMultipartParse, BinaryPayloadLooksLikeFraming)
{
    std::string p0(16, '\0');
    p0[0] = '\r';
    p0[1] = '\n';
    p0.replace(2, 8, "--123456");
    p0[10] = '\xff';
    p0[11] = '\r';
    p0[12] = '\n';
    p0.replace(13, 3, "xyz");

    std::string p1(16, '\xaa');
    p1.replace(0, 10, "--123456--");
    p1[10] = '\r';
    p1[11] = '\n';
    p1[12] = '\0';
    p1[13] = '\xff';

    const std::vector<Part> parts{
        {0, std::move(p0)},
        {100, std::move(p1)},
    };
    ExpectMultipartBody(MakeXrdHttpMultipart(parts, 1024), parts);
}

// Split the response at every byte offset.  This covers every place curl could
// end a write: inside a boundary line, a header line, a CRLF, the blank line
// that ends the part headers, and the payload.
TEST(CurlMultipartParse, SplitAtEveryOffset)
{
    const std::vector<Part> parts{
        {0, "aa"},
        {2, "bb"},
        {6, "dd"},
    };
    const auto body = MakeXrdHttpMultipart(parts, 8);
    for (size_t split = 1; split < body.size(); ++split) {
        SCOPED_TRACE("split at " + std::to_string(split));
        ExpectMultipartBody(body, parts, {split});
        if (HasFatalFailure()) return;
    }
}

// Deliver the response in fixed-size writes of every size, down to one byte
// per write, so a single part's headers span many writes.
TEST(CurlMultipartParse, FixedSizeWrites)
{
    const std::vector<Part> parts{
        {0, "aa"},
        {2, "bb"},
        {6, "dd"},
    };
    const auto body = MakeXrdHttpMultipart(parts, 8);
    for (size_t size = 1; size < body.size(); ++size) {
        std::vector<size_t> splits;
        for (size_t offset = size; offset < body.size(); offset += size) {
            splits.push_back(offset);
        }
        SCOPED_TRACE("write size " + std::to_string(size) + " (splits " + SplitDescription(splits) + ")");
        ExpectMultipartBody(body, parts, splits);
        if (HasFatalFailure()) return;
    }
}
