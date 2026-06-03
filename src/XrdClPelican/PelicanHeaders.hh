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

// This file contains various helper functions for parsing the
// Pelican-specific headers returned by the HTTP server.  Currently,
// there's duplication with the XrdClCurl header parsing -- the intent
// is the duplication shrinks as we remove Pelican-specific pieces from
// XrdClCurl.

#pragma once

#include <string>
#include <string_view>
#include <tuple>
#include <vector>

namespace XrdClCurl {
    class ChecksumInfo;
}

namespace Pelican {

// An entry in the `link` header, as defined by RFC 5988 and used by RFC 6249
class LinkEntry {
    public:
        static std::tuple<std::vector<LinkEntry>, bool> FromHeaderValue(const std::string_view value);
        static std::tuple<std::string_view, LinkEntry, bool> IterFromHeaderValue(const std::string_view &value);
        unsigned GetPrio() const {return m_prio;}
        unsigned GetDepth() const {return m_depth;}
        const std::string &GetLink() const {return m_link;}

    private:
        unsigned m_prio{999999};
        unsigned m_depth{0};
        std::string m_link;
};

// Decode base64 string input to binary output
bool Base64Decode(std::string_view input, std::array<unsigned char, 32> &output);

// Parse the "Digest" header in an HTTP response.
//
// Done explicitly by Pelican instead of relying on XrdClCurl because this allows
// us to parse multiple digests that may have come back.
void ParseDigest(const std::string &digest, XrdClCurl::ChecksumInfo &info);

// Parse an integer value in a HTTP header
std::tuple<std::string_view, int, bool> ParseInt(const std::string_view &val);

// Parse a string value in a HTTP header according to HTTP's quoting rules
std::tuple<std::string_view, std::string, bool> ParseString(const std::string_view &val);

} // namespace Pelican
