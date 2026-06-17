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

// Unit tests for CurlOperation::Redirect().
//
// See https://github.com/PelicanPlatform/xrdcl-pelican/issues/116 : a
// host-relative Location header (one starting with '/') must be resolved
// against the *effective* (most recent) request URL, not the *original*
// target.  These tests exercise Redirect() directly, with no network I/O.

#include "XrdClCurl/XrdClCurlOps.hh"

#include <XrdCl/XrdClDefaultEnv.hh>
#include <XrdCl/XrdClLog.hh>

#include <gtest/gtest.h>

using namespace XrdClCurl;

namespace {

// A minimal concrete CurlOperation so we can drive Redirect() directly.
//
// CurlOperation is abstract (Success()/GetVerb() are pure virtual) and its
// response-header state (m_headers) is protected, so the test subclass both
// provides the missing virtuals and exposes a helper to feed in a synthetic
// redirect response.
class TestRedirectOp final : public CurlOperation {
public:
    TestRedirectOp(const std::string &url, XrdCl::Log *log)
        : CurlOperation(nullptr, url, timespec{30, 0}, log, nullptr, nullptr)
    {
        // Give the operation a real (if unconnected) curl handle so the
        // CURLOPT_URL set inside Redirect() exercises the real code path.
        m_curl.reset(curl_easy_init());
    }

    void Success() override {}
    HttpVerb GetVerb() const override {return HttpVerb::GET;}

    // Feed the operation a synthetic redirect response, the way libcurl's
    // header callback would, one header line at a time.
    void InjectRedirect(int status, const std::string &location) {
        m_headers = HeaderParser();
        m_headers.Parse("HTTP/1.1 " + std::to_string(status) + " Redirect\r\n");
        m_headers.Parse("Location: " + location + "\r\n");
        m_headers.Parse("\r\n");
    }
};

XrdCl::Log *GetLog() {
    return XrdCl::DefaultEnv::GetLog();
}

} // namespace

// The regression test for issue #116: after an absolute cross-host redirect
// (host-a -> host-b), a host-relative Location returned by host-b must resolve
// against host-b, not the original host-a target.
TEST(Redirect, HostRelativeLocationResolvedAgainstEffectiveUrl) {
    TestRedirectOp op("https://host-a:443/namespace/file", GetLog());

    // Step (a): host-a issues an absolute redirect to host-b.
    op.InjectRedirect(307, "https://host-b:443/namespace/file");
    std::string target;
    ASSERT_EQ(op.Redirect(target), CurlOperation::RedirectAction::Reinvoke);
    EXPECT_EQ(target, "https://host-b:443/namespace/file");

    // Step (b): host-b returns a host-relative Location.  This must be resolved
    // against the effective base (host-b), NOT the original target (host-a).
    op.InjectRedirect(307, "/namespace/file/");
    ASSERT_EQ(op.Redirect(target), CurlOperation::RedirectAction::Reinvoke);
    EXPECT_EQ(target, "https://host-b:443/namespace/file/");
}

// A host-relative redirect with no prior cross-host hop still resolves against
// the original target (the effective URL equals the original URL at that point).
TEST(Redirect, HostRelativeLocationOnFirstHop) {
    TestRedirectOp op("https://origin.example:8443/namespace", GetLog());

    op.InjectRedirect(307, "/namespace/");
    std::string target;
    ASSERT_EQ(op.Redirect(target), CurlOperation::RedirectAction::Reinvoke);
    EXPECT_EQ(target, "https://origin.example:8443/namespace/");
}

// The Pelican POSIX v2 ping-pong from issue #116: origin.example redirects
// "/namespace" -> "/namespace/" (host-relative) while a cache in front keeps
// bouncing the request.  Without a redirect cap on the manual reinvoke path
// such a cycle is unbounded; the cap must eventually fail the operation.
TEST(Redirect, RepeatedRedirectsAreCapped) {
    TestRedirectOp op("https://origin.example:8443/namespace", GetLog());

    // Drive a long chain of host-relative redirects; at some point the
    // operation must give up rather than reinvoke forever.
    bool capped = false;
    for (int i = 0; i < 100; ++i) {
        op.InjectRedirect(307, "/namespace/");
        std::string target;
        if (op.Redirect(target) == CurlOperation::RedirectAction::Fail) {
            capped = true;
            break;
        }
    }
    EXPECT_TRUE(capped) << "Redirect() never failed; the manual reinvoke path has no redirect cap";
}
