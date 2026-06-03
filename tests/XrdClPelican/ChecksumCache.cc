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

#include "XrdClPelican/ChecksumCache.hh"
#include "XrdClPelican/PelicanHeaders.hh"

#include <gtest/gtest.h>

using namespace Pelican;

TEST(ChecksumCache, Bitmask) {
    ChecksumTypeBitmask mask;
    EXPECT_FALSE(mask.Test(XrdClCurl::ChecksumType::kCRC32C));
    EXPECT_FALSE(mask.Test(XrdClCurl::ChecksumType::kMD5));
    EXPECT_FALSE(mask.Test(XrdClCurl::ChecksumType::kSHA1));
    EXPECT_FALSE(mask.Test(XrdClCurl::ChecksumType::kSHA256));

    mask.Set(XrdClCurl::ChecksumType::kCRC32C);
    EXPECT_TRUE(mask.Test(XrdClCurl::ChecksumType::kCRC32C));
    EXPECT_FALSE(mask.Test(XrdClCurl::ChecksumType::kMD5));
    EXPECT_FALSE(mask.Test(XrdClCurl::ChecksumType::kSHA1));
    EXPECT_FALSE(mask.Test(XrdClCurl::ChecksumType::kSHA256));

    mask.Set(XrdClCurl::ChecksumType::kMD5);
    EXPECT_TRUE(mask.Test(XrdClCurl::ChecksumType::kCRC32C));
    EXPECT_TRUE(mask.Test(XrdClCurl::ChecksumType::kMD5));
    EXPECT_FALSE(mask.Test(XrdClCurl::ChecksumType::kSHA1));
    EXPECT_FALSE(mask.Test(XrdClCurl::ChecksumType::kSHA256));

    mask.Clear(XrdClCurl::ChecksumType::kCRC32C);
    EXPECT_FALSE(mask.Test(XrdClCurl::ChecksumType::kCRC32C));
    EXPECT_TRUE(mask.Test(XrdClCurl::ChecksumType::kMD5));
    EXPECT_FALSE(mask.Test(XrdClCurl::ChecksumType::kSHA1));
    EXPECT_FALSE(mask.Test(XrdClCurl::ChecksumType::kSHA256));

    mask.SetAll();
    EXPECT_TRUE(mask.Test(XrdClCurl::ChecksumType::kCRC32C));
    EXPECT_TRUE(mask.Test(XrdClCurl::ChecksumType::kMD5));
    EXPECT_TRUE(mask.Test(XrdClCurl::ChecksumType::kSHA1));
    EXPECT_TRUE(mask.Test(XrdClCurl::ChecksumType::kSHA256));

    mask.ClearAll();
    EXPECT_FALSE(mask.Test(XrdClCurl::ChecksumType::kCRC32C));
    EXPECT_FALSE(mask.Test(XrdClCurl::ChecksumType::kMD5));
    EXPECT_FALSE(mask.Test(XrdClCurl::ChecksumType::kSHA1));
    EXPECT_FALSE(mask.Test(XrdClCurl::ChecksumType::kSHA256));

    mask.Set(XrdClCurl::ChecksumType::kCRC32C);
    EXPECT_TRUE(mask.TestAny());
    mask.Clear(XrdClCurl::ChecksumType::kCRC32C);
    EXPECT_FALSE(mask.TestAny());


    mask.SetAll();
    EXPECT_TRUE(mask.TestAny());
    mask.ClearAll();
    EXPECT_FALSE(mask.TestAny());

    mask.Set(XrdClCurl::ChecksumType::kCRC32C);
    mask.Set(XrdClCurl::ChecksumType::kMD5);
    EXPECT_EQ(mask.Count(), 2);
    mask.Clear(XrdClCurl::ChecksumType::kMD5);
    EXPECT_EQ(mask.Count(), 1);
    mask.Clear(XrdClCurl::ChecksumType::kCRC32C);
    EXPECT_EQ(mask.Count(), 0);

    mask.Set(XrdClCurl::ChecksumType::kCRC32C);
    EXPECT_EQ(mask.GetFirst(), XrdClCurl::ChecksumType::kCRC32C);
    mask.Set(XrdClCurl::ChecksumType::kMD5);
    EXPECT_EQ(mask.GetFirst(), XrdClCurl::ChecksumType::kCRC32C);
    mask.Clear(XrdClCurl::ChecksumType::kCRC32C);
    EXPECT_EQ(mask.GetFirst(), XrdClCurl::ChecksumType::kMD5);
    mask.Clear(XrdClCurl::ChecksumType::kMD5);
    EXPECT_EQ(mask.GetFirst(), XrdClCurl::ChecksumType::kUnknown);

    mask.Set(XrdClCurl::ChecksumType::kCRC32C);
    mask.Set(XrdClCurl::ChecksumType::kMD5);
    EXPECT_EQ(mask.Get(), 0b11);
}

TEST(ChecksumCache, GetUrlKey) {
    std::string key(ChecksumCache::GetUrlKey("https://example.com/foo/bar?query=val"));
    EXPECT_EQ(key, "example.com/foo/bar");
    key = ChecksumCache::GetUrlKey("https://example.com/foo/bar");
    EXPECT_EQ(key, "example.com/foo/bar");
    key = ChecksumCache::GetUrlKey("https://example.com/foo/bar/");
    EXPECT_EQ(key, "example.com/foo/bar/");
    key = ChecksumCache::GetUrlKey("https://example.com/foo/bar?query=val#fragment");
    EXPECT_EQ(key, "example.com/foo/bar");
    key = ChecksumCache::GetUrlKey("https://user:foo@example.com/foo");
    EXPECT_EQ(key, "example.com/foo");
}

TEST(ChecksumCache, Info) {
    XrdClCurl::ChecksumInfo info;
    EXPECT_FALSE(info.IsSet(XrdClCurl::ChecksumType::kCRC32C));
    EXPECT_FALSE(info.IsSet(XrdClCurl::ChecksumType::kMD5));
    EXPECT_FALSE(info.IsSet(XrdClCurl::ChecksumType::kSHA1));
    EXPECT_FALSE(info.IsSet(XrdClCurl::ChecksumType::kSHA256));

    std::array<unsigned char, 32> testVal;
    for (size_t idx = 0; idx < 16; idx++) {
        testVal[idx] = idx;
    }
    info.Set(XrdClCurl::ChecksumType::kMD5, testVal);
    EXPECT_FALSE(info.IsSet(XrdClCurl::ChecksumType::kCRC32C));
    EXPECT_TRUE(info.IsSet(XrdClCurl::ChecksumType::kMD5));
    auto val = info.Get(XrdClCurl::ChecksumType::kMD5);
    for (size_t idx = 0; idx < 16; idx++) {
        EXPECT_EQ(val[idx], idx);
    }
}

TEST(ChecksumCache, GetPut) {
    XrdClCurl::ChecksumInfo info;
    Pelican::ParseDigest("md5=ZajifYh5KDgxtmS9i38K1A==,CRC32c=A72A4DF", info);
    ASSERT_TRUE(info.IsSet(XrdClCurl::ChecksumType::kMD5));
    ASSERT_TRUE(info.IsSet(XrdClCurl::ChecksumType::kCRC32C));

    auto now = std::chrono::steady_clock::now();
    Pelican::ChecksumCache::Instance().Put("https://example.com/foo/bar?query=val", info, now);
    ChecksumTypeBitmask mask;
    mask.Set(XrdClCurl::ChecksumType::kMD5);
    auto info2 = Pelican::ChecksumCache::Instance().Get("https://example.com/foo/bar", mask, now);
    ASSERT_TRUE(info2.IsSet(XrdClCurl::ChecksumType::kMD5));
    ASSERT_FALSE(info2.IsSet(XrdClCurl::ChecksumType::kCRC32C));
    auto val = info2.Get(XrdClCurl::ChecksumType::kMD5);
    EXPECT_EQ(val, info.Get(XrdClCurl::ChecksumType::kMD5));

    mask.Set(XrdClCurl::ChecksumType::kCRC32C);
    info2 = Pelican::ChecksumCache::Instance().Get("https://user:foo@example.com/foo/bar?setting", mask, now);
    EXPECT_TRUE(info2.IsSet(XrdClCurl::ChecksumType::kMD5));
    EXPECT_TRUE(info2.IsSet(XrdClCurl::ChecksumType::kCRC32C));
    val = info2.Get(XrdClCurl::ChecksumType::kCRC32C);
    EXPECT_EQ(val, info.Get(XrdClCurl::ChecksumType::kCRC32C));

    info2 = Pelican::ChecksumCache::Instance().Get("https://example.com/foo/bar?query=val", mask, now + std::chrono::minutes(30));
    EXPECT_FALSE(info2.IsSet(XrdClCurl::ChecksumType::kMD5));
    EXPECT_FALSE(info2.IsSet(XrdClCurl::ChecksumType::kCRC32C));

    mask.ClearAll();
    info2 = Pelican::ChecksumCache::Instance().Get("https://example.com/foo/bar2", mask, now);
    EXPECT_FALSE(info2.IsSet(XrdClCurl::ChecksumType::kMD5));
    EXPECT_FALSE(info2.IsSet(XrdClCurl::ChecksumType::kCRC32C));

    mask.Set(XrdClCurl::ChecksumType::kMD5);
    info2 = Pelican::ChecksumCache::Instance().Get("https://example.com/foo/bar2", mask, now);
    EXPECT_FALSE(info2.IsSet(XrdClCurl::ChecksumType::kMD5));
}

TEST(ChecksumCache, Base64Decode) {
    // base64 encoded string "Hello, World!"
    std::string_view input = "SGVsbG8sIFdvcmxkIQ==";
    std::array<unsigned char, 32> output;
    EXPECT_TRUE(Pelican::Base64Decode(input, output));
    std::string output_str(reinterpret_cast<const char *>(output.data()), 13);
    EXPECT_EQ(output_str, "Hello, World!");

    // Invalid base64 encoded string
    input = "SGVsbG8sIFd`vcmxkIQ";
    EXPECT_FALSE(Pelican::Base64Decode(input, output));

    // Empty base64 encoded string
    input = "";
    output[0] = 0;
    EXPECT_TRUE(Pelican::Base64Decode(input, output));
    EXPECT_EQ(output[0], 0);

    // base64 encoded string "a"
    input = "YQ==";
    EXPECT_TRUE(Pelican::Base64Decode(input, output));
    EXPECT_EQ(output[0], 'a');

    // base64 encoded string "aa"
    input = "YWE=";
    EXPECT_TRUE(Pelican::Base64Decode(input, output));
    EXPECT_EQ(output[0], 'a');
    EXPECT_EQ(output[1], 'a');

    // base64 encoded string "aaa"
    input = "YWFh";
    EXPECT_TRUE(Pelican::Base64Decode(input, output));
    EXPECT_EQ(output[0], 'a');
    EXPECT_EQ(output[1], 'a');
    EXPECT_EQ(output[2], 'a');
}

TEST(ChecksumCache, Digest) {
    XrdClCurl::ChecksumInfo info;
    Pelican::ParseDigest("md5=ZajifYh5KDgxtmS9i38K1A==,foo=bar", info);
    ASSERT_TRUE(info.IsSet(XrdClCurl::ChecksumType::kMD5));
    EXPECT_FALSE(info.IsSet(XrdClCurl::ChecksumType::kCRC32C));
    auto val = info.Get(XrdClCurl::ChecksumType::kMD5);
    EXPECT_EQ(val[0], 101);
    EXPECT_EQ(val[1], 168);
    EXPECT_EQ(val[2], 226);
    EXPECT_EQ(val[14], 10);
    EXPECT_EQ(val[15], 212);

    // Example CRC32c value from https://www.iana.org/assignments/http-dig-alg/http-dig-alg.xhtml
    // Note that IANA says the leading '0' is not required.
    Pelican::ParseDigest("CRC32c=A72A4DF", info);
    EXPECT_TRUE(info.IsSet(XrdClCurl::ChecksumType::kMD5));
    EXPECT_TRUE(info.IsSet(XrdClCurl::ChecksumType::kCRC32C));
    val = info.Get(XrdClCurl::ChecksumType::kCRC32C);
    EXPECT_EQ(val[0], 0x0A);
    EXPECT_EQ(val[1], 0x72);
    EXPECT_EQ(val[2], 0xA4);
    EXPECT_EQ(val[3], 0xDF);
}
