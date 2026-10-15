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

#ifndef XRDCLCURLDIGEST_HH_
#define XRDCLCURLDIGEST_HH_

#include "XrdClCurlChecksum.hh"

#include <array>
#include <string_view>

// Parsing of the RFC 3230 `Digest` response header, shared by the XrdClCurl
// and XrdClPelican plugins so the two cannot drift apart.

namespace XrdClCurl {

// Decode a base64-encoded string into a binary buffer.
//
// Returns false if the input is not valid, padded base64 or decodes to more
// bytes than fit in `output`.  An empty input decodes successfully to nothing.
bool DecodeBase64(std::string_view input, std::array<unsigned char, g_max_checksum_length> &output);

// Parse the value of a `Digest` header, setting each recognized checksum in `info`.
//
// The header is a comma-separated list of `algorithm=value` entries; whitespace
// around entries, names and values is ignored, and algorithm names are
// case-insensitive.  Entries that are malformed or name an unknown algorithm
// are skipped.
void ParseDigestHeader(std::string_view digest, ChecksumInfo &info);

} // namespace XrdClCurl

#endif // XRDCLCURLDIGEST_HH_
