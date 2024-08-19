/****************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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


#include "CurlUtil.hh"

#include <gtest/gtest.h>

TEST(HeaderParser, ParseInt) {
    {
        auto entry = "1234; ";
        auto [remainder, result, ok] = Pelican::HeaderParser::ParseInt(entry);
        EXPECT_EQ(remainder, "; ");
        EXPECT_EQ(result, 1234);
        EXPECT_EQ(ok, true);
    }

    {
        auto entry = "-1foo";
        auto [remainder, result, ok] = Pelican::HeaderParser::ParseInt(entry);
        EXPECT_EQ(remainder, "foo");
        EXPECT_EQ(result, -1);
        EXPECT_EQ(ok, true);
    }

    {
        auto entry = "0";
        auto [remainder, result, ok] = Pelican::HeaderParser::ParseInt(entry);
        EXPECT_EQ(remainder, "");
        EXPECT_EQ(result, 0);
        EXPECT_EQ(ok, true);
    }

    {
        auto entry = "foo";
        auto [remainder, result, ok] = Pelican::HeaderParser::ParseInt(entry);
        EXPECT_EQ(ok, false);
    }

    {
        auto entry = "18446744073709551615";
        auto [remainder, result, ok] = Pelican::HeaderParser::ParseInt(entry);
        EXPECT_EQ(ok, false);
    }
}

TEST(HeaderParser, ParseString) {
    {
        auto entry = R"("foo")";
        auto [remainder, result, ok] = Pelican::HeaderParser::ParseString(entry);
        EXPECT_EQ(ok, true);
        EXPECT_EQ(remainder, "");
        EXPECT_EQ(result, "foo");
    }

    {
        auto entry = R"("foo" )";
        auto [remainder, result, ok] = Pelican::HeaderParser::ParseString(entry);
        EXPECT_EQ(ok, true);
        EXPECT_EQ(remainder, " ");
        EXPECT_EQ(result, "foo");
    }

    {
        auto entry = R"("fo\"o" )";
        auto [remainder, result, ok] = Pelican::HeaderParser::ParseString(entry);
        EXPECT_EQ(ok, true);
        EXPECT_EQ(remainder, " ");
        EXPECT_EQ(result, R"(fo"o)");
    }

    {
        auto entry = R"("fo\ro";)";
        auto [remainder, result, ok] = Pelican::HeaderParser::ParseString(entry);
        EXPECT_EQ(ok, true);
        EXPECT_EQ(remainder, ";");
        EXPECT_EQ(result, "fo\ro");
    }

    {
        auto entry = R"("fo\zo";)";
        auto [remainder, result, ok] = Pelican::HeaderParser::ParseString(entry);
        EXPECT_EQ(ok, false);
    }

    {
        auto entry = R"("fo\zo;)";
        auto [remainder, result, ok] = Pelican::HeaderParser::ParseString(entry);
        EXPECT_EQ(ok, false);
    }

    {
        auto entry = "z";
        auto [remainder, result, ok] = Pelican::HeaderParser::ParseString(entry);
        EXPECT_EQ(ok, false);
    }
}

TEST(HeaderParser, LinkEntry) {
    {
        auto entry = R"(<https://example.com:8443/user/ligo/foo.txt>; rel="duplicate"; pri=15; depth=42)";
        auto [remainder, hdr, ok] = Pelican::HeaderParser::LinkEntry::IterFromHeaderValue(entry);
        EXPECT_EQ(ok, true);
        EXPECT_EQ(hdr.GetDepth(), 42);
        EXPECT_EQ(hdr.GetPrio(), 15);
    }


    {
        auto entry = R"(<https://example.com:8443/user/ligo/foo.txt>; rel="duplicate"; pri=15; depth=42, foo)";
        auto [remainder, hdr, ok] = Pelican::HeaderParser::LinkEntry::IterFromHeaderValue(entry);
        EXPECT_EQ(ok, true);
        EXPECT_EQ(hdr.GetDepth(), 42);
        EXPECT_EQ(hdr.GetPrio(), 15);
        EXPECT_EQ(remainder, " foo");
    }

    {
        auto entry = R"(<https://example.com:8443/user/ligo/foo.txt>; rel="blah"; pri=15; depth=42, foo)";
        auto [remainder, hdr, ok] = Pelican::HeaderParser::LinkEntry::IterFromHeaderValue(entry);
        EXPECT_EQ(ok, false);
        EXPECT_EQ(remainder, " foo");
    }

    {
        auto entry = R"(rel="duplicate"; pri=15; depth=42, foo)";
        auto [remainder, hdr, ok] = Pelican::HeaderParser::LinkEntry::IterFromHeaderValue(entry);
        EXPECT_EQ(ok, true);
        EXPECT_EQ(hdr.GetLink(), "");
        EXPECT_EQ(remainder, " foo");
    }

    {
        auto entry = R"(rel foo)";
        auto [remainder, hdr, ok] = Pelican::HeaderParser::LinkEntry::IterFromHeaderValue(entry);
        EXPECT_EQ(ok, false);
    }

    {
        auto entry = R"(rel="duplicate"; foo)";
        auto [remainder, hdr, ok] = Pelican::HeaderParser::LinkEntry::IterFromHeaderValue(entry);
        EXPECT_EQ(ok, false);
    }

    {
        auto entry = R"(<https://example.com:8443/user/ligo/foo.txt>; rel="duplicate"; pri=15; depth=42)";
        auto [hdrList, ok] = Pelican::HeaderParser::LinkEntry::FromHeaderValue(entry);
        EXPECT_EQ(ok, true);
        ASSERT_EQ(hdrList.size(), 1);
        EXPECT_EQ(hdrList[0].GetLink(), "https://example.com:8443/user/ligo/foo.txt");
        EXPECT_EQ(hdrList[0].GetDepth(), 42);
        EXPECT_EQ(hdrList[0].GetPrio(), 15);
    }

    {
        auto entry = R"(<https://example.com:8443/user/ligo/foo.txt>; rel="duplicate"; pri=15; depth=42, <https://example2.com:8443/foo.txt>; rel="duplicate"; pri=5; depth=1)";
        auto [hdrList, ok] = Pelican::HeaderParser::LinkEntry::FromHeaderValue(entry);
        EXPECT_EQ(ok, true);
        ASSERT_EQ(hdrList.size(), 2);
        EXPECT_EQ(hdrList[1].GetLink(), "https://example.com:8443/user/ligo/foo.txt");
        EXPECT_EQ(hdrList[1].GetDepth(), 42);
        EXPECT_EQ(hdrList[1].GetPrio(), 15);
        EXPECT_EQ(hdrList[0].GetLink(), "https://example2.com:8443/foo.txt");
        EXPECT_EQ(hdrList[0].GetDepth(), 1);
        EXPECT_EQ(hdrList[0].GetPrio(), 5);
    }
}