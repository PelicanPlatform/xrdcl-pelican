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

#include "XrdClCurlDigest.hh"

#include <openssl/bio.h>
#include <openssl/evp.h>

#include <algorithm>
#include <cctype>
#include <memory>
#include <string>

namespace {

std::string_view TrimWhitespace(std::string_view input) {
    while (!input.empty() && (input.front() == ' ' || input.front() == '\t')) {
        input.remove_prefix(1);
    }
    while (!input.empty() && (input.back() == ' ' || input.back() == '\t')) {
        input.remove_suffix(1);
    }
    return input;
}

int HexValue(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Parse a 32-bit checksum written as up to 8 hex digits.  Servers may omit
// leading zeros, so shorter values are zero-padded on the left.
bool ParseHex32(std::string_view value, std::array<unsigned char, XrdClCurl::g_max_checksum_length> &output) {
    if (value.empty() || value.size() > 8) return false;
    uint32_t result = 0;
    for (auto c : value) {
        auto digit = HexValue(c);
        if (digit < 0) return false;
        result = (result << 4) | static_cast<uint32_t>(digit);
    }
    output[0] = (result >> 24) & 0xFF;
    output[1] = (result >> 16) & 0xFF;
    output[2] = (result >> 8) & 0xFF;
    output[3] = result & 0xFF;
    return true;
}

// A four-byte checksum in padded base64 is exactly 8 characters ending in "==".
// Requiring the padding distinguishes it from a short hex value, which may
// also be valid unpadded base64.
bool LooksLikeBase64Of4Bytes(std::string_view value) {
    return value.size() == 8 && value[6] == '=' && value[7] == '=';
}

} // namespace

bool
XrdClCurl::DecodeBase64(std::string_view input, std::array<unsigned char, g_max_checksum_length> &output) {
    if (input.size() > 4 * ((output.size() + 2) / 3) || input.size() % 4 != 0) return false;
    if (input.size() == 0) return true;

    std::unique_ptr<BIO, decltype(&BIO_free_all)> b64(BIO_new(BIO_f_base64()), &BIO_free_all);
    BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);
    std::unique_ptr<BIO, decltype(&BIO_free_all)> bmem(
        BIO_new_mem_buf(const_cast<char *>(input.data()), input.size()), &BIO_free_all);
    bmem.reset(BIO_push(b64.release(), bmem.release()));

    // Compute expected length of output; used to verify BIO_read consumes all input
    size_t expectedLen = input.size() / 4 * 3;
    if (input[input.size() - 1] == '=') {
        expectedLen -= 1;
        if (input[input.size() - 2] == '=') {
            expectedLen -= 1;
        }
    }
    if (expectedLen > output.size()) return false;

    auto len = BIO_read(bmem.get(), &output[0], output.size());

    return len >= 0 && static_cast<size_t>(len) == expectedLen;
}

void
XrdClCurl::ParseDigestHeader(std::string_view digest, ChecksumInfo &info) {
    std::string name_lower;
    while (!digest.empty()) {
        auto nextsep = digest.find(',');
        auto entry = digest.substr(0, nextsep);
        digest = (nextsep == std::string_view::npos) ? std::string_view() : digest.substr(nextsep + 1);

        auto eq = entry.find('=');
        if (eq == std::string_view::npos) continue;
        auto name = TrimWhitespace(entry.substr(0, eq));
        auto value = TrimWhitespace(entry.substr(eq + 1));
        name_lower.assign(name.begin(), name.end());
        std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), [](unsigned char c) {
            return std::tolower(c);
        });

        std::array<unsigned char, g_max_checksum_length> checksum_value{};
        auto setHex32 = [&](ChecksumType type) {
            if (ParseHex32(value, checksum_value)) {
                info.Set(type, checksum_value);
            }
        };
        auto setBase64 = [&](ChecksumType type) {
            const auto decoded_size = GetChecksumLength(type);
            const auto encoded_size = 4 * ((decoded_size + 2) / 3);
            if (value.size() == encoded_size && DecodeBase64(value, checksum_value)) {
                info.Set(type, checksum_value);
            }
        };
        // XRootD incorrectly base64-encodes crc32c checksums (see
        // https://github.com/xrootd/xrootd/issues/2456) and legacy GFAL clients
        // expect base64 crc32; accept either form for the 32-bit checksums.
        auto setHexOrBase64 = [&](ChecksumType type) {
            if (LooksLikeBase64Of4Bytes(value)) {
                setBase64(type);
            } else {
                setHex32(type);
            }
        };

        if (name_lower == "adler" || name_lower == "adler32") {
            setHex32(ChecksumType::kADLER32);
        } else if (name_lower == "crc32") {
            setHexOrBase64(ChecksumType::kCRC32);
        } else if (name_lower == "crc32c") {
            setHexOrBase64(ChecksumType::kCRC32C);
        } else if (name_lower == "md5") {
            setBase64(ChecksumType::kMD5);
        } else if (name_lower == "sha" || name_lower == "sha1") {
            setBase64(ChecksumType::kSHA1);
        } else if (name_lower == "sha-256" || name_lower == "sha256") {
            setBase64(ChecksumType::kSHA256);
        }
    }
}
