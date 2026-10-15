/***************************************************************
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

#include "PelicanHeaders.hh"
#include "../common/XrdClCurlChecksum.hh"
#include "../common/XrdClCurlDigest.hh"


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
    return XrdClCurl::DecodeBase64(input, output);
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
    XrdClCurl::ParseDigestHeader(digest, info);
}
