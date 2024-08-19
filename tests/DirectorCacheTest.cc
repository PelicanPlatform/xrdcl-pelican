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


#include "DirectorCache.hh"

#include <gtest/gtest.h>

#include <chrono>

TEST(DirectorCache, BasicPutGet) {
    auto now = std::chrono::steady_clock::now();

    auto &cache = Pelican::DirectorCache::GetCache("example.com", now);

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

    auto &cache = Pelican::DirectorCache::GetCache("example.com", now);

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

    auto &cache = Pelican::DirectorCache::GetCache("example.com", now);

    cache.Put("https://example.com:8443/obj1/obj2/obj3", 0, now);
    now += std::chrono::seconds(30);
    auto url = cache.Get("https://director.com:8443/obj1/obj2/obj3", now);
    EXPECT_EQ(url, "https://example.com:8443/obj1/obj2/obj3");
    cache.Put("https://example2.com:8443/obj1/obj2", 0, now);
    now += std::chrono::seconds(35);
    url = cache.Get("https://director.com:8443/obj1/obj2/obj3", now);
    EXPECT_EQ(url, "https://example2.com:8443/obj1/obj2/obj3");
}