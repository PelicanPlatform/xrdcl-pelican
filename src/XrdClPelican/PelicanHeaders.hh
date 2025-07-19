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
