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

#ifndef XRDCLCURL_CURLRESPONSEINFO_HH
#define XRDCLCURL_CURLRESPONSEINFO_HH

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace XrdClCurl {

// Representation of the information contained in a response.
class ResponseInfo {
public:
    // Force the response information to be virtual, allowing RTTI and easing potential ABI changes
    virtual ~ResponseInfo() {};

    // A list of header values in the order they occurred in the response.
    // Typically, only one element is in the vector.
    using HeaderValues = std::vector<std::string>;

    // Map of header key to header value(s).  The header key is *case sensitive*;
    // queries should be done using the "canonical" form (see
    // https://cs.opensource.google/go/go/+/refs/tags/go1.24.2:src/net/textproto/reader.go;l=647)
    using HeaderMap = std::unordered_map<std::string, HeaderValues>;

    // List of response headers, one entry per response received through the
    // operation; potentially there are multiple if there was a redirect
    using HeaderResponses = std::vector<HeaderMap>;

    const HeaderResponses &GetHeaderResponse() const {return m_header_responses;}

    // Adds a set of headers to the internal response object.
    void AddResponse(HeaderMap &&map) {m_header_responses.emplace_back(map);}

private:
    std::vector<std::unordered_map<std::string, std::vector<std::string>>> m_header_responses;
};

} // namespace XrdClCurl

#endif // XRDCLCURL_CURLRESPONSEINFO_HH
