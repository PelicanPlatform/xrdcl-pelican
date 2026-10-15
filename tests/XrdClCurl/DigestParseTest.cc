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

// Unit tests for parsing the RFC 3230 `Digest` response header.

#include "XrdClCurl/XrdClCurlUtil.hh"

#include <gtest/gtest.h>

namespace {

// Each test value encodes the bytes 0, 1, 2, ...; check the first `size` of them.
void ExpectSequentialChecksum(const XrdClCurl::ChecksumInfo &checksums,
                              XrdClCurl::ChecksumType type, std::size_t size)
{
    ASSERT_TRUE(checksums.IsSet(type)) << XrdClCurl::GetTypeString(type);
    const auto &value = checksums.Get(type);
    for (std::size_t index = 0; index < size; ++index) {
        EXPECT_EQ(value[index], index) << XrdClCurl::GetTypeString(type) << " byte " << index;
    }
}

} // namespace

TEST(DigestParse, ParsesSupportedDigestAlgorithms)
{
    XrdClCurl::ChecksumInfo checksums;
    XrdClCurl::HeaderParser::ParseDigest(
        "adler32=00010203, crc32=00010203, CRC32c=AAECAw==, "
        "MD5=AAECAwQFBgcICQoLDA0ODw==, "
        "SHA=AAECAwQFBgcICQoLDA0ODxAREhM=, "
        "SHA-256=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        checksums);

    ExpectSequentialChecksum(checksums, XrdClCurl::ChecksumType::kADLER32, 4);
    ExpectSequentialChecksum(checksums, XrdClCurl::ChecksumType::kCRC32, 4);
    ExpectSequentialChecksum(checksums, XrdClCurl::ChecksumType::kCRC32C, 4);
    ExpectSequentialChecksum(checksums, XrdClCurl::ChecksumType::kMD5, 16);
    ExpectSequentialChecksum(checksums, XrdClCurl::ChecksumType::kSHA1, 20);
    ExpectSequentialChecksum(checksums, XrdClCurl::ChecksumType::kSHA256, 32);
}

// RFC 3230 permits whitespace around list entries; Pelican origins send none,
// but other servers commonly put a space after each comma.
TEST(DigestParse, IgnoresWhitespaceAroundEntries)
{
    XrdClCurl::ChecksumInfo checksums;
    XrdClCurl::HeaderParser::ParseDigest(" md5 = AAECAwQFBgcICQoLDA0ODw== ,\tcrc32c=00010203\t", checksums);

    ExpectSequentialChecksum(checksums, XrdClCurl::ChecksumType::kMD5, 16);
    ExpectSequentialChecksum(checksums, XrdClCurl::ChecksumType::kCRC32C, 4);
}

// Malformed and unknown entries are skipped without affecting the others.
TEST(DigestParse, SkipsMalformedAndUnknownEntries)
{
    XrdClCurl::ChecksumInfo checksums;
    XrdClCurl::HeaderParser::ParseDigest("md5,foo=bar,=,crc32c=00010203,", checksums);

    EXPECT_FALSE(checksums.IsSet(XrdClCurl::ChecksumType::kMD5));
    ExpectSequentialChecksum(checksums, XrdClCurl::ChecksumType::kCRC32C, 4);
}

TEST(DigestParse, AcceptsAdlerDigestAlias)
{
    XrdClCurl::ChecksumInfo checksums;
    XrdClCurl::HeaderParser::ParseDigest("adler=00010203", checksums);
    ExpectSequentialChecksum(checksums, XrdClCurl::ChecksumType::kADLER32, 4);
}

TEST(DigestParse, AcceptsBase64Crc32Digest)
{
    XrdClCurl::ChecksumInfo checksums;
    XrdClCurl::HeaderParser::ParseDigest("crc32=AAECAw==", checksums);
    ExpectSequentialChecksum(checksums, XrdClCurl::ChecksumType::kCRC32, 4);
}

// Servers may omit the leading zeros of a 32-bit hex checksum.
TEST(DigestParse, ZeroPadsShortHexValues)
{
    XrdClCurl::ChecksumInfo checksums;
    XrdClCurl::HeaderParser::ParseDigest("crc32c=A72A4DF,adler32=1", checksums);

    ASSERT_TRUE(checksums.IsSet(XrdClCurl::ChecksumType::kCRC32C));
    const auto &crc32c = checksums.Get(XrdClCurl::ChecksumType::kCRC32C);
    EXPECT_EQ(crc32c[0], 0x0a);
    EXPECT_EQ(crc32c[1], 0x72);
    EXPECT_EQ(crc32c[2], 0xa4);
    EXPECT_EQ(crc32c[3], 0xdf);

    ASSERT_TRUE(checksums.IsSet(XrdClCurl::ChecksumType::kADLER32));
    const auto &adler32 = checksums.Get(XrdClCurl::ChecksumType::kADLER32);
    EXPECT_EQ(adler32[0], 0);
    EXPECT_EQ(adler32[1], 0);
    EXPECT_EQ(adler32[2], 0);
    EXPECT_EQ(adler32[3], 1);
}

TEST(DigestParse, PreservesShortHexCrc32WhenBase64IsAmbiguous)
{
    XrdClCurl::ChecksumInfo checksums;
    XrdClCurl::HeaderParser::ParseDigest("crc32=AAAAAA", checksums);

    ASSERT_TRUE(checksums.IsSet(XrdClCurl::ChecksumType::kCRC32));
    const auto &value = checksums.Get(XrdClCurl::ChecksumType::kCRC32);
    EXPECT_EQ(value[0], 0);
    EXPECT_EQ(value[1], 0xaa);
    EXPECT_EQ(value[2], 0xaa);
    EXPECT_EQ(value[3], 0xaa);
}

TEST(DigestParse, UsesPaddingToDisambiguateBase64Crc32)
{
    XrdClCurl::ChecksumInfo checksums;
    XrdClCurl::HeaderParser::ParseDigest("crc32=AAAAAA==", checksums);

    ASSERT_TRUE(checksums.IsSet(XrdClCurl::ChecksumType::kCRC32));
    const auto &value = checksums.Get(XrdClCurl::ChecksumType::kCRC32);
    EXPECT_EQ(value[0], 0);
    EXPECT_EQ(value[1], 0);
    EXPECT_EQ(value[2], 0);
    EXPECT_EQ(value[3], 0);
}

TEST(DigestParse, RejectsMalformedCrc32Digest)
{
    for (const auto *digest : {"crc32=", "crc32=0001020300", "crc32=AAEC?w==",
                               "crc32=AAECAw", "crc32=AAECAw=", "crc32=AAECAw===",
                               "crc32=AAECAwA=", "crc32=0x010203"})
    {
        XrdClCurl::ChecksumInfo checksums;
        XrdClCurl::HeaderParser::ParseDigest(digest, checksums);
        EXPECT_FALSE(checksums.IsSet(XrdClCurl::ChecksumType::kCRC32)) << digest;
    }
}

// A base64 value whose length does not match the algorithm is rejected rather
// than recorded as a truncated or overlong checksum.
TEST(DigestParse, RejectsWrongLengthBase64Digests)
{
    for (const auto *digest : {"md5=AAECAw==", "sha=AAECAwQFBgcICQoLDA0ODw==",
                               "sha-256=AAECAwQFBgcICQoLDA0ODxAREhM="})
    {
        XrdClCurl::ChecksumInfo checksums;
        XrdClCurl::HeaderParser::ParseDigest(digest, checksums);
        auto [type, value, ok] = checksums.GetFirst();
        EXPECT_FALSE(ok) << digest << " set " << XrdClCurl::GetTypeString(type);
    }
}

TEST(DigestParse, ChecksumNegotiationValues)
{
    EXPECT_EQ(XrdClCurl::GetTypeFromString("adler"), XrdClCurl::ChecksumType::kADLER32);
    EXPECT_EQ(XrdClCurl::GetTypeFromString("adler32"), XrdClCurl::ChecksumType::kADLER32);
    EXPECT_EQ(XrdClCurl::GetTypeFromString("crc32"), XrdClCurl::ChecksumType::kCRC32);
    EXPECT_EQ(XrdClCurl::HeaderParser::ChecksumTypeToDigestName(XrdClCurl::ChecksumType::kADLER32), "adler32");
    EXPECT_EQ(XrdClCurl::HeaderParser::ChecksumTypeToDigestName(XrdClCurl::ChecksumType::kCRC32), "crc32");
}

// The new types are appended to the enum so that, when a response carries
// several checksums, crc32c remains the first one reported.
TEST(DigestParse, GetFirstPrefersCrc32c)
{
    XrdClCurl::ChecksumInfo checksums;
    XrdClCurl::HeaderParser::ParseDigest("adler32=00010203,crc32=00010203,crc32c=00010203", checksums);
    auto [type, value, ok] = checksums.GetFirst();
    ASSERT_TRUE(ok);
    EXPECT_EQ(type, XrdClCurl::ChecksumType::kCRC32C);
}
