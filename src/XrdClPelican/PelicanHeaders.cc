/***************************************************************
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

#include "PelicanHeaders.hh"
#include "../common/XrdClCurlChecksum.hh"

#include <openssl/bio.h>
#include <openssl/evp.h>

#include <algorithm>
#include <charconv>
#include <memory>
#include <string_view>

using namespace Pelican;

namespace {

// Trim the left side of a string_view for space
std::string_view LtrimView(const std::string_view &input_view) {
    for (size_t idx = 0; idx < input_view.size(); idx++) {
        if (!isspace(input_view[idx])) {
            return input_view.substr(idx);
        }
    }
    return "";
}

// Trim left and righit side of a string_view for space characters
std::string_view TrimView(const std::string_view &input_view) {
    auto view = LtrimView(input_view);
    for (size_t idx = 0; idx < input_view.size(); idx++) {
        if (!isspace(view[view.size() - 1 - idx])) {
            return view.substr(0, view.size() - idx);
        }
    }
    return "";
}

} // namespace


bool
Pelican::Base64Decode(std::string_view input, std::array<unsigned char, 32> &output) {
    if (input.size() > 44 || input.size() % 4 != 0) return false;
    if (input.size() == 0) return true;

    std::unique_ptr<BIO, decltype(&BIO_free_all)> b64(BIO_new(BIO_f_base64()), &BIO_free_all);
    BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);
    std::unique_ptr<BIO, decltype(&BIO_free_all)> bmem(
        BIO_new_mem_buf(const_cast<char *>(input.data()), input.size()), &BIO_free_all);
    bmem.reset(BIO_push(b64.release(), bmem.release()));

    // Compute expected length of output; used to verify BIO_read consumes all input
    size_t expectedLen = static_cast<size_t>(input.size() * 0.75);
    if (input[input.size() - 1] == '=') {
        expectedLen -= 1;
        if (input[input.size() - 2] == '=') {
            expectedLen -= 1;
        }
    }

    auto len = BIO_read(bmem.get(), &output[0], output.size());

    if (len == -1 || static_cast<size_t>(len) != expectedLen) return false;

    return true;
}

// Parse a HTTP-header-style integer
//
// Returns a tuple consisting of the remainder of the input data, the integer value,
// and a boolean indicating whether the parsing was successful.
std::tuple<std::string_view, int, bool> Pelican::ParseInt(const std::string_view &val) {
    if (val.empty()) {
        return std::make_tuple("", 0, false);
    }
    int result{};
    auto [ptr, ec] = std::from_chars(val.data(), val.data() + val.size(), result);
    if (ec == std::errc()) {
        return std::make_tuple(val.substr(ptr - val.data()), result, true);
    }
    return std::make_tuple("", 0, false);
}

// Parse a HTTP-header-style quoted string
//
// Returns a tuple consisting of the remainder of the input data, the quoted string contents,
// and a boolean indicating whether the parsing was successful.
std::tuple<std::string_view, std::string, bool> Pelican::ParseString(const std::string_view &val) {
    if (val.empty() || val[0] != '"') {
        return std::make_tuple("", "", false);
    }
    std::string result;
    auto endLoc = val.find('"');
    if (endLoc == std::string_view::npos) {
        return std::make_tuple("", "", false);
    }
    result.reserve(endLoc);
    for (size_t idx = 1; idx < val.size(); idx++) {
        if (val[idx] == '\\') {
            idx++;
            if (idx == val.size()) {
                return std::make_tuple("", "", false);
            }
            switch (val[idx]) {
            case '\\':
                result.push_back('\\');
                break;
            case 'r':
                result.push_back('\r');
                break;
            case 'n':
                result.push_back('\n');
                break;
            case '"':
                result.push_back('"');
                break;
            default:
                return std::make_tuple("", "", false);
            }
        } else if (val[idx] == '"') {
            return std::make_tuple(val.substr(idx + 1), result, true);
        } else {
            result.push_back(val[idx]);
        }
    }
    return std::make_tuple("", "", false);
}

std::tuple<std::vector<LinkEntry>, bool> Pelican::LinkEntry::FromHeaderValue(const std::string_view value) {
    std::string_view remainder = value;
    bool ok;
    std::vector<LinkEntry> result;
    do {
        LinkEntry entry;
        std::tie(remainder, entry, ok) = IterFromHeaderValue(remainder);
        if (ok) {
            result.emplace_back(std::move(entry));
        } else if (!ok && remainder.empty()) {
            return std::make_tuple(result, false);
        }
    } while (!remainder.empty());
    std::sort(result.begin(), result.end(), [](const LinkEntry &left, const LinkEntry &right){return left.GetPrio() < right.GetPrio();});
    return std::make_tuple(result, true);
}

std::tuple<std::string_view, LinkEntry, bool> Pelican::LinkEntry::IterFromHeaderValue(const std::string_view &value) {
    LinkEntry curEntry;
    bool isValid{true};
    std::string_view entry = LtrimView(value);
    while (true) {
        entry = LtrimView(entry);
        if (entry.empty()) {
            return std::make_tuple("", curEntry, false);
        } else if (entry[0] == '<') {
            auto endLoc = entry.find('>', 1);
            if (endLoc == std::string_view::npos) {
                return std::make_tuple("", curEntry, false);
            }
            curEntry.m_link = entry.substr(1, endLoc - 1);
            entry = LtrimView(entry.substr(endLoc + 1));
        } else {
            auto keyEndLoc = entry.find('=');
            if (keyEndLoc == std::string_view::npos) {
                return std::make_tuple("", curEntry, false);
            }
            auto key = TrimView(entry.substr(0, keyEndLoc));
            auto val = LtrimView(entry.substr(keyEndLoc + 1));
            if (val.empty()) {
                return std::make_tuple("", curEntry, false);
            }
            std::string stringValue;
            int intValue{-1};
            bool ok{false}, isStr{false};
            if (val[0] == '"') {
                isStr = true;
                std::tie(entry, stringValue, ok) = ParseString(val);
            } else {
                std::tie(entry, intValue, ok) = ParseInt(val);
            }
            if (!ok) {
                return std::make_tuple("", curEntry, false);
            }
            if (key == "pri" && !isStr) {
                curEntry.m_prio = intValue;
            }
            if (key == "depth" && !isStr) {
                curEntry.m_depth = intValue;
            }
            if (key == "rel" && isStr && stringValue != "duplicate") {
                isValid = false;
            }
        }
        if (entry.empty()) {
            return std::make_tuple("", curEntry, isValid);
        } else if (entry[0] == ',') {
            return std::make_tuple(entry.substr(1), curEntry, isValid);
        } else if (entry[0] != ';') {
            return std::make_tuple("", curEntry, false);
        }
        entry = entry.substr(1);
    }
    return std::make_tuple(entry, curEntry, isValid);
}

// Parse a RFC 3230 header into the checksum info structure
//
// If the parsing fails, the second element of the tuple will be false.
void Pelican::ParseDigest(const std::string &digest, XrdClCurl::ChecksumInfo &info) {
    std::string_view view(digest);
    std::array<unsigned char, 32> checksum_value;
    std::string digest_lower;
    while (!view.empty()) {
        auto nextsep = view.find(',');
        auto entry = view.substr(0, nextsep);
        if (nextsep == std::string_view::npos) {
            view = "";
        } else {
            view = view.substr(nextsep + 1);
        }
        nextsep = entry.find('=');
        auto name = entry.substr(0, nextsep);
        auto value = entry.substr(nextsep + 1);
        digest_lower.clear();
        digest_lower.resize(name.size());
        std::transform(name.begin(), name.end(), digest_lower.begin(), [](unsigned char c) {
            return std::tolower(c);
        });
        if (digest_lower == "md5") {
            if (value.size() != 24) {
                continue;
            }
            if (Base64Decode(value, checksum_value)) {
                info.Set(XrdClCurl::ChecksumType::kMD5, checksum_value);
            }
        } else if (digest_lower == "crc32c") {
            // XRootD currently incorrectly base64-encodes crc32c checksums; see
            // https://github.com/xrootd/xrootd/issues/2456
            // For backward comaptibility, if this looks like base64 encoded (8
            // bytes long and last two bytes are padding), then we base64 decode.
            if (value.size() == 8 && value[6] == '=' && value[7] == '=') {
                if (Base64Decode(value, checksum_value)) {
                    info.Set(XrdClCurl::ChecksumType::kCRC32C, checksum_value);
                }
                continue;
            }
            std::size_t pos{0};
            unsigned long val;
            try {
                val = std::stoul(value.data(), &pos, 16);
            } catch (...) {
                continue;
            }
            if (pos == value.size()) {
                checksum_value[0] = (val >> 24) & 0xFF;
                checksum_value[1] = (val >> 16) & 0xFF;
                checksum_value[2] = (val >> 8) & 0xFF;
                checksum_value[3] = val & 0xFF;
                info.Set(XrdClCurl::ChecksumType::kCRC32C, checksum_value);
            }
        }
    }
}
