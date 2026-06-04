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


#include "XrdClPelican/DirectorCache.hh"

#include <gtest/gtest.h>

#include <chrono>

TEST(DirectorCache, BasicPutGet) {
    auto now = std::chrono::steady_clock::now();

    std::string director = "example.com";
    auto &cache = Pelican::DirectorCache::GetCache(director, now);

    cache.Put("https://example.com:8443/obj1/obj2/obj3", 1, now);
    auto url = cache.Get("https://director.com:8443/obj1/obj2/foo", now);
    EXPECT_EQ(url, "https://example.com:8443/obj1/obj2/foo");
    url = cache.Get("https://director.com/obj1/obj2", now);
    EXPECT_EQ(url, "https://example.com:8443/obj1/obj2");
    url = cache.Get("https://director.com/obj1/obj22", now);
    EXPECT_EQ(url, "");
    url = cache.Get("https://director.com/obj1", now);
    EXPECT_EQ(url, "");
}

TEST(DirectorCache, MultiplePutGet) {
    auto now = std::chrono::steady_clock::now();

    std::string director = "example.com";
    auto &cache = Pelican::DirectorCache::GetCache(director, now);

    cache.Put("https://example.com:8443/obj1/obj2/obj3", 1, now);
    cache.Put("https://example2.com:8443/obj1/obj2", 1, now);
    cache.Put("https://example3.com:8443/foo", 0, now);
    auto url = cache.Get("https://director.com:8443/obj1/obj2/foo", now);
    EXPECT_EQ(url, "https://example.com:8443/obj1/obj2/foo");
    url = cache.Get("https://director.com/obj1/obj2", now);
    EXPECT_EQ(url, "https://example.com:8443/obj1/obj2");
    url = cache.Get("https://director.com/obj1/obj22", now);
    EXPECT_EQ(url, "https://example2.com:8443/obj1/obj22");
    url = cache.Get("https://director.com/obj1", now);
    EXPECT_EQ(url, "https://example2.com:8443/obj1");
    url = cache.Get("https://director.com/foo/bar", now);
    EXPECT_EQ(url, "https://example3.com:8443/foo/bar");

    now += std::chrono::minutes(2);
    url = cache.Get("https://director.com/foo/bar", now);
    EXPECT_EQ(url, "");
    url = cache.Get("https://director.com/obj1/obj2", now);
    EXPECT_EQ(url, "");
}

TEST(DirectorCache, ExpiredPutGet) {
    auto now = std::chrono::steady_clock::now();

    std::string director = "example.com";
    auto &cache = Pelican::DirectorCache::GetCache(director, now);

    cache.Put("https://example.com:8443/obj1/obj2/obj3", 0, now);
    now += std::chrono::seconds(30);
    auto url = cache.Get("https://director.com:8443/obj1/obj2/obj3", now);
    EXPECT_EQ(url, "https://example.com:8443/obj1/obj2/obj3");
    cache.Put("https://example2.com:8443/obj1/obj2", 0, now);
    now += std::chrono::seconds(35);
    url = cache.Get("https://director.com:8443/obj1/obj2/obj3", now);
    EXPECT_EQ(url, "https://example2.com:8443/obj1/obj2/obj3");
}

TEST(DirectorCache, ComputePathAndUrl) {
    std::string test_url = "https://example.com:8443/first/namespace";
    auto [path, url, ok] = Pelican::DirectorCache::ComputePathAndUrl(test_url, 3);
    EXPECT_FALSE(ok);

    std::tie(path, url, ok) = Pelican::DirectorCache::ComputePathAndUrl(test_url, 2);
    EXPECT_TRUE(ok);
    EXPECT_STREQ(std::string(url).c_str(), "https://example.com:8443/");
    EXPECT_EQ(path, "/");

    std::tie(path, url, ok) = Pelican::DirectorCache::ComputePathAndUrl(test_url, 1);
    EXPECT_TRUE(ok);
    EXPECT_STREQ(std::string(url).c_str(), "https://example.com:8443/first");
    EXPECT_EQ(path, "/first");

    std::tie(path, url, ok) = Pelican::DirectorCache::ComputePathAndUrl(test_url, 0);
    EXPECT_TRUE(ok);
    EXPECT_STREQ(std::string(url).c_str(), "https://example.com:8443/first/namespace");
    EXPECT_EQ(path, "/first/namespace");

    test_url = "https://example.com:8443/";
    std::tie(path, url, ok) = Pelican::DirectorCache::ComputePathAndUrl(test_url, 0);
    EXPECT_TRUE(ok);
    EXPECT_STREQ(std::string(url).c_str(), "https://example.com:8443/");
    EXPECT_EQ(path, "/");

    std::tie(path, url, ok) = Pelican::DirectorCache::ComputePathAndUrl(test_url, 1);
    EXPECT_FALSE(ok);

    test_url = "https://example.com:8443";
    std::tie(path, url, ok) = Pelican::DirectorCache::ComputePathAndUrl(test_url, 0);
    EXPECT_FALSE(ok);


    test_url = "https://example.com:8443?foo=/";
    std::tie(path, url, ok) = Pelican::DirectorCache::ComputePathAndUrl(test_url, 0);
    EXPECT_FALSE(ok);

    test_url = "https://example.com:8443/path1/path2?foo=/bar/baz";
    std::tie(path, url, ok) = Pelican::DirectorCache::ComputePathAndUrl(test_url, 1);
    EXPECT_TRUE(ok);
    EXPECT_STREQ(std::string(url).c_str(), "https://example.com:8443/path1");
    EXPECT_EQ(path, "/path1");

    test_url = "https://example.com:8443/path1//path2";
    std::tie(path, url, ok) = Pelican::DirectorCache::ComputePathAndUrl(test_url, 1);
    EXPECT_TRUE(ok);
    EXPECT_STREQ(std::string(url).c_str(), "https://example.com:8443/path1");
    EXPECT_EQ(path, "/path1");

    test_url = "https://example.com:8443/path1//path2/";
    std::tie(path, url, ok) = Pelican::DirectorCache::ComputePathAndUrl(test_url, 1);
    EXPECT_TRUE(ok);
    EXPECT_STREQ(std::string(url).c_str(), "https://example.com:8443/path1//path2");
    EXPECT_EQ(path, "/path1//path2");
}
