/****************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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
