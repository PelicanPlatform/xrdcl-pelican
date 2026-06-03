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


#include "XrdClPelican/PelicanHeaders.hh"

#include <gtest/gtest.h>

TEST(HeaderParser, ParseInt) {
    {
        auto entry = "1234; ";
        auto [remainder, result, ok] = Pelican::ParseInt(entry);
        EXPECT_EQ(remainder, "; ");
        EXPECT_EQ(result, 1234);
        EXPECT_EQ(ok, true);
    }

    {
        auto entry = "-1foo";
        auto [remainder, result, ok] = Pelican::ParseInt(entry);
        EXPECT_EQ(remainder, "foo");
        EXPECT_EQ(result, -1);
        EXPECT_EQ(ok, true);
    }

    {
        auto entry = "0";
        auto [remainder, result, ok] = Pelican::ParseInt(entry);
        EXPECT_EQ(remainder, "");
        EXPECT_EQ(result, 0);
        EXPECT_EQ(ok, true);
    }

    {
        auto entry = "foo";
        auto [remainder, result, ok] = Pelican::ParseInt(entry);
        EXPECT_EQ(ok, false);
    }

    {
        auto entry = "18446744073709551615";
        auto [remainder, result, ok] = Pelican::ParseInt(entry);
        EXPECT_EQ(ok, false);
    }
}

TEST(HeaderParser, ParseString) {
    {
        auto entry = R"("foo")";
        auto [remainder, result, ok] = Pelican::ParseString(entry);
        EXPECT_EQ(ok, true);
        EXPECT_EQ(remainder, "");
        EXPECT_EQ(result, "foo");
    }

    {
        auto entry = R"("foo" )";
        auto [remainder, result, ok] = Pelican::ParseString(entry);
        EXPECT_EQ(ok, true);
        EXPECT_EQ(remainder, " ");
        EXPECT_EQ(result, "foo");
    }

    {
        auto entry = R"("fo\"o" )";
        auto [remainder, result, ok] = Pelican::ParseString(entry);
        EXPECT_EQ(ok, true);
        EXPECT_EQ(remainder, " ");
        EXPECT_EQ(result, R"(fo"o)");
    }

    {
        auto entry = R"("fo\ro";)";
        auto [remainder, result, ok] = Pelican::ParseString(entry);
        EXPECT_EQ(ok, true);
        EXPECT_EQ(remainder, ";");
        EXPECT_EQ(result, "fo\ro");
    }

    {
        auto entry = R"("fo\zo";)";
        auto [remainder, result, ok] = Pelican::ParseString(entry);
        EXPECT_EQ(ok, false);
    }

    {
        auto entry = R"("fo\zo;)";
        auto [remainder, result, ok] = Pelican::ParseString(entry);
        EXPECT_EQ(ok, false);
    }

    {
        auto entry = "z";
        auto [remainder, result, ok] = Pelican::ParseString(entry);
        EXPECT_EQ(ok, false);
    }
}

TEST(HeaderParser, LinkEntry) {
    {
        auto entry = R"(<https://example.com:8443/user/ligo/foo.txt>; rel="duplicate"; pri=15; depth=42)";
        auto [remainder, hdr, ok] = Pelican::LinkEntry::IterFromHeaderValue(entry);
        EXPECT_EQ(ok, true);
        EXPECT_EQ(hdr.GetDepth(), 42);
        EXPECT_EQ(hdr.GetPrio(), 15);
    }


    {
        auto entry = R"(<https://example.com:8443/user/ligo/foo.txt>; rel="duplicate"; pri=15; depth=42, foo)";
        auto [remainder, hdr, ok] = Pelican::LinkEntry::IterFromHeaderValue(entry);
        EXPECT_EQ(ok, true);
        EXPECT_EQ(hdr.GetDepth(), 42);
        EXPECT_EQ(hdr.GetPrio(), 15);
        EXPECT_EQ(remainder, " foo");
    }

    {
        auto entry = R"(<https://example.com:8443/user/ligo/foo.txt>; rel="blah"; pri=15; depth=42, foo)";
        auto [remainder, hdr, ok] = Pelican::LinkEntry::IterFromHeaderValue(entry);
        EXPECT_EQ(ok, false);
        EXPECT_EQ(remainder, " foo");
    }

    {
        auto entry = R"(rel="duplicate"; pri=15; depth=42, foo)";
        auto [remainder, hdr, ok] = Pelican::LinkEntry::IterFromHeaderValue(entry);
        EXPECT_EQ(ok, true);
        EXPECT_EQ(hdr.GetLink(), "");
        EXPECT_EQ(remainder, " foo");
    }

    {
        auto entry = R"(rel foo)";
        auto [remainder, hdr, ok] = Pelican::LinkEntry::IterFromHeaderValue(entry);
        EXPECT_EQ(ok, false);
    }

    {
        auto entry = R"(rel="duplicate"; foo)";
        auto [remainder, hdr, ok] = Pelican::LinkEntry::IterFromHeaderValue(entry);
        EXPECT_EQ(ok, false);
    }

    {
        auto entry = R"(<https://example.com:8443/user/ligo/foo.txt>; rel="duplicate"; pri=15; depth=42)";
        auto [hdrList, ok] = Pelican::LinkEntry::FromHeaderValue(entry);
        EXPECT_EQ(ok, true);
        ASSERT_EQ(hdrList.size(), 1);
        EXPECT_EQ(hdrList[0].GetLink(), "https://example.com:8443/user/ligo/foo.txt");
        EXPECT_EQ(hdrList[0].GetDepth(), 42);
        EXPECT_EQ(hdrList[0].GetPrio(), 15);
    }

    {
        auto entry = R"(<https://example.com:8443/user/ligo/foo.txt>; rel="duplicate"; pri=15; depth=42, <https://example2.com:8443/foo.txt>; rel="duplicate"; pri=5; depth=1)";
        auto [hdrList, ok] = Pelican::LinkEntry::FromHeaderValue(entry);
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
