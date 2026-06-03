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

#include "XrdClPelican/PelicanFilesystem.hh"

#include <gtest/gtest.h>

TEST(EndpointOverride, ParseEmpty) {
    auto result = Pelican::Filesystem::ParseEndpointOverride("");
    EXPECT_TRUE(result.empty());
}

TEST(EndpointOverride, ParseSingleEndpoint) {
    auto result = Pelican::Filesystem::ParseEndpointOverride("https://cache.example.com:8443");
    ASSERT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], "https://cache.example.com:8443");
}

TEST(EndpointOverride, ParseDirectorOnly) {
    auto result = Pelican::Filesystem::ParseEndpointOverride("+");
    ASSERT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], "+");
}

TEST(EndpointOverride, ParseMultipleEndpoints) {
    auto result = Pelican::Filesystem::ParseEndpointOverride("https://cache1.example.com:8443,https://cache2.example.com:8443");
    ASSERT_EQ(result.size(), 2);
    EXPECT_EQ(result[0], "https://cache1.example.com:8443");
    EXPECT_EQ(result[1], "https://cache2.example.com:8443");
}

TEST(EndpointOverride, ParseEndpointWithDirectorFallback) {
    auto result = Pelican::Filesystem::ParseEndpointOverride("https://cache1.example.com:8443,+,https://cache2.example.com:8443");
    ASSERT_EQ(result.size(), 3);
    EXPECT_EQ(result[0], "https://cache1.example.com:8443");
    EXPECT_EQ(result[1], "+");
    EXPECT_EQ(result[2], "https://cache2.example.com:8443");
}

TEST(EndpointOverride, ParseWithWhitespace) {
    auto result = Pelican::Filesystem::ParseEndpointOverride("  https://cache1.example.com:8443 , + , https://cache2.example.com:8443  ");
    ASSERT_EQ(result.size(), 3);
    EXPECT_EQ(result[0], "https://cache1.example.com:8443");
    EXPECT_EQ(result[1], "+");
    EXPECT_EQ(result[2], "https://cache2.example.com:8443");
}

TEST(EndpointOverride, ParseSkipsEmptyEntries) {
    auto result = Pelican::Filesystem::ParseEndpointOverride("https://cache1.example.com:8443,,https://cache2.example.com:8443");
    ASSERT_EQ(result.size(), 2);
    EXPECT_EQ(result[0], "https://cache1.example.com:8443");
    EXPECT_EQ(result[1], "https://cache2.example.com:8443");
}

TEST(EndpointOverride, ParseWhitespaceOnly) {
    auto result = Pelican::Filesystem::ParseEndpointOverride("  ,  ,  ");
    EXPECT_TRUE(result.empty());
}

TEST(EndpointOverride, SetAndGet) {
    Pelican::Filesystem::SetEndpointOverride("https://cache.example.com:8443,+");
    auto result = Pelican::Filesystem::GetEndpointOverride();
    ASSERT_EQ(result.size(), 2);
    EXPECT_EQ(result[0], "https://cache.example.com:8443");
    EXPECT_EQ(result[1], "+");

    // Reset to empty
    Pelican::Filesystem::SetEndpointOverride("");
    result = Pelican::Filesystem::GetEndpointOverride();
    EXPECT_TRUE(result.empty());
}
