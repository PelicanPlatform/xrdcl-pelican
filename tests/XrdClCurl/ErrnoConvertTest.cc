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

//
// Unit tests for the error-conversion helpers, enforcing the XRootDStatus
// errNo contract described in
// https://github.com/PelicanPlatform/xrdcl-pelican/issues/117 :
//
//   * if code == errErrorResponse, errNo must be a kXR_* server error code
//     (XrdPosixMap maps it through XProtocol::toErrno());
//   * for every other code, errNo must be a real POSIX errno (or 0), because
//     XrdPosixMap::Result() uses it verbatim as the errno.
//
// Storing a raw CURLcode / HTTP status / XrdCl err* constant in the errNo slot
// (the original defect) is what these tests guard against.
//

#include "XrdClCurl/XrdClCurlUtil.hh"

#include <XrdCl/XrdClStatus.hh>
#include <XProtocol/XProtocol.hh>

#include <curl/curl.h>
#include <gtest/gtest.h>

#include <cerrno>

// CurlCodeConvert() has external linkage but is an internal helper not exposed
// through a public header; declare it here for white-box testing.  (Its sibling
// HTTPStatusConvert() is declared in XrdClCurlUtil.hh.)
std::pair<uint16_t, uint32_t> CurlCodeConvert(CURLcode res);

namespace {

// kXR_* server error codes occupy [kXR_ArgInvalid, ...) = [3000, 3100).  Used to
// distinguish a (valid) kXR_* code from a (valid) POSIX errno, which is small.
bool LooksLikeKxrCode(uint32_t v) { return v >= 3000 && v < 3100; }

// A POSIX errno is a small positive value (or 0 meaning "defer to mapCode").
bool LooksLikePosixErrno(uint32_t v) { return v < 256; }

// Assert that a (code, errNo) pair honors the issue #117 contract.
void ExpectContract(const std::pair<uint16_t, uint32_t> &p, const char *what) {
    if (p.first == XrdCl::errErrorResponse) {
        EXPECT_TRUE(LooksLikeKxrCode(p.second))
            << what << ": errErrorResponse requires a kXR_* code in errNo, got " << p.second;
    } else {
        EXPECT_TRUE(LooksLikePosixErrno(p.second))
            << what << ": code " << p.first
            << " (!= errErrorResponse) requires a POSIX errno in errNo, got " << p.second;
    }
}

} // namespace

// The motivating bug: CURLE_PARTIAL_FILE (value 18) must not leak 18 into errNo,
// where it would be reinterpreted as EXDEV ("invalid cross-device link").
TEST(ErrnoConvert, PartialFileIsNotExdev) {
    auto p = CurlCodeConvert(CURLE_PARTIAL_FILE);
    EXPECT_NE(p.first, XrdCl::errErrorResponse);
    EXPECT_EQ(p.second, static_cast<uint32_t>(EIO));
    EXPECT_NE(p.second, static_cast<uint32_t>(CURLE_PARTIAL_FILE));
}

// Every CURLcode the converter might see must satisfy the contract: no raw
// CURLcode ends up in the errNo slot paired with a non-errErrorResponse code.
TEST(ErrnoConvert, CurlCodeConvertHonorsContract) {
    for (int i = 0; i <= CURL_LAST; ++i) {
        auto res = static_cast<CURLcode>(i);
        auto p = CurlCodeConvert(res);
        ExpectContract(p, curl_easy_strerror(res));
    }
    // Explicit anchors for every arm that previously leaked the raw CURLcode
    // into errNo.  A raw CURLcode is numerically small, so it would also satisfy
    // the generic contract check above; these pin the specific errno instead.
    EXPECT_EQ(CurlCodeConvert(CURLE_URL_MALFORMAT).second, static_cast<uint32_t>(EINVAL));
    EXPECT_EQ(CurlCodeConvert(CURLE_PARTIAL_FILE).second, static_cast<uint32_t>(EIO));
    EXPECT_EQ(CurlCodeConvert(CURLE_READ_ERROR).second, static_cast<uint32_t>(EIO));
    EXPECT_EQ(CurlCodeConvert(CURLE_WRITE_ERROR).second, static_cast<uint32_t>(EIO));
    EXPECT_EQ(CurlCodeConvert(CURLE_RANGE_ERROR).second, static_cast<uint32_t>(ENOTSUP));
    EXPECT_EQ(CurlCodeConvert(CURLE_BAD_CONTENT_ENCODING).second, static_cast<uint32_t>(ENOTSUP));
    EXPECT_EQ(CurlCodeConvert(CURLE_TOO_MANY_REDIRECTS).second, static_cast<uint32_t>(ELOOP));
    EXPECT_EQ(CurlCodeConvert(CURLE_UNSUPPORTED_PROTOCOL).first, XrdCl::errNotSupported);
    // The default arm (an unmapped CURLcode) yields a generic I/O errno, not the
    // raw code.
    EXPECT_EQ(CurlCodeConvert(CURLE_LDAP_CANNOT_BIND).first, XrdCl::errUnknown);
    EXPECT_EQ(CurlCodeConvert(CURLE_LDAP_CANNOT_BIND).second, static_cast<uint32_t>(EIO));
    // CURLE_OK is the no-error pair.
    EXPECT_EQ(CurlCodeConvert(CURLE_OK).first, XrdCl::errNone);
    EXPECT_EQ(CurlCodeConvert(CURLE_OK).second, 0u);
}

// Every HTTP status code must satisfy the contract: explicit arms pair
// errErrorResponse with a kXR_* code, and the default arm must NOT leak the raw
// HTTP status into the errNo slot.
TEST(ErrnoConvert, HttpStatusConvertHonorsContract) {
    for (unsigned status = 100; status < 600; ++status) {
        auto p = XrdClCurl::HTTPStatusConvert(status);
        ExpectContract(p, ("HTTP " + std::to_string(status)).c_str());
    }
    // An unmapped error status must not surface the status number as the errno.
    auto p = XrdClCurl::HTTPStatusConvert(599);
    EXPECT_NE(p.first, XrdCl::errErrorResponse);
    EXPECT_EQ(p.second, static_cast<uint32_t>(EIO));
    EXPECT_NE(p.second, 599u);

    // A representative explicit arm still maps to a kXR_* code.
    EXPECT_EQ(XrdClCurl::HTTPStatusConvert(404).first, XrdCl::errErrorResponse);
    EXPECT_EQ(XrdClCurl::HTTPStatusConvert(404).second, static_cast<uint32_t>(kXR_NotFound));
}
