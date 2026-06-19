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

// Unit tests for error-string propagation out of CurlReadOp.
//
// See https://github.com/PelicanPlatform/xrdcl-pelican/issues/117 and
// reference/error-string-propagation.md.  When the origin returns an HTTP
// error, CurlReadOp::Write() captures the response body into m_err_msg.  These
// tests verify CurlReadOp::Fail() folds that captured body into the
// XRootDStatus error message so it can travel up the XrdCl interface (and, on
// XRootD >= 6, out the proxy/cache's own HTTP error response).
//
// These tests drive CurlReadOp directly, with no network I/O.

#include "XrdClCurl/XrdClCurlOps.hh"

#include <XrdCl/XrdClDefaultEnv.hh>
#include <XrdCl/XrdClLog.hh>
#include <XrdCl/XrdClXRootDResponses.hh>
#include <XProtocol/XProtocol.hh>

#include <gtest/gtest.h>

using namespace XrdClCurl;

namespace {

// A ResponseHandler that records the delivered XRootDStatus so the test can
// inspect the error message the operation produced.
class CapturingHandler final : public XrdCl::ResponseHandler {
public:
    void HandleResponse(XrdCl::XRootDStatus *status, XrdCl::AnyObject *response) override {
        m_called = true;
        m_code = status->code;
        m_errNo = status->errNo;
        m_message = status->GetErrorMessage();
        delete status;
        delete response;
    }

    bool m_called{false};
    uint16_t m_code{0};
    uint32_t m_errNo{0};
    std::string m_message;
};

// A minimal concrete CurlReadOp that lets the test stand in for the data the
// libcurl write callback would have captured from an origin error response.
class TestReadOp final : public CurlReadOp {
public:
    TestReadOp(XrdCl::ResponseHandler *handler, XrdCl::Log *log)
        : CurlReadOp(handler, nullptr, "https://origin.example:8443/test/file",
                     timespec{30, 0}, {0, 4096}, nullptr, 0, log, nullptr, nullptr)
    {}

    // Stand in for the body Write() copies into m_err_msg on an HTTP error.
    void SetCapturedErrorBody(const std::string &body) { m_err_msg = body; }
};

XrdCl::Log *GetLog() {
    return XrdCl::DefaultEnv::GetLog();
}

} // namespace

// The captured origin error body must appear in the propagated error message.
TEST(ErrorMessage, ReadFailureIncludesOriginResponseBody) {
    CapturingHandler handler;
    TestReadOp op(&handler, GetLog());

    op.SetCapturedErrorBody("Origin refused widget 42: storage backend offline");
    op.Fail(XrdCl::errErrorResponse, kXR_ServerError, "Internal Server Error");

    ASSERT_TRUE(handler.m_called);
    EXPECT_EQ(handler.m_code, XrdCl::errErrorResponse);
    EXPECT_EQ(handler.m_errNo, static_cast<uint32_t>(kXR_ServerError));
    // Both the high-level reason and the origin's detailed body should be present.
    EXPECT_NE(handler.m_message.find("Internal Server Error"), std::string::npos)
        << handler.m_message;
    EXPECT_NE(handler.m_message.find("Origin refused widget 42: storage backend offline"),
              std::string::npos)
        << handler.m_message;
}

// Multi-line / padded origin bodies are collapsed to a single tidy line.
TEST(ErrorMessage, OriginResponseBodyIsSanitized) {
    CapturingHandler handler;
    TestReadOp op(&handler, GetLog());

    op.SetCapturedErrorBody("  Unable to open /test/file;\r\n   permission denied\n");
    op.Fail(XrdCl::errErrorResponse, kXR_NotAuthorized, "Forbidden");

    ASSERT_TRUE(handler.m_called);
    EXPECT_NE(handler.m_message.find("Unable to open /test/file; permission denied"),
              std::string::npos)
        << handler.m_message;
    // No embedded carriage returns or newlines should survive.
    EXPECT_EQ(handler.m_message.find('\n'), std::string::npos) << handler.m_message;
    EXPECT_EQ(handler.m_message.find('\r'), std::string::npos) << handler.m_message;
}

// With no captured body, the message is just the high-level reason (no dangling
// "; origin response:" suffix).
TEST(ErrorMessage, ReadFailureWithoutBodyHasNoOriginSuffix) {
    CapturingHandler handler;
    TestReadOp op(&handler, GetLog());

    op.Fail(XrdCl::errErrorResponse, kXR_NotFound, "Not Found");

    ASSERT_TRUE(handler.m_called);
    EXPECT_NE(handler.m_message.find("Not Found"), std::string::npos) << handler.m_message;
    EXPECT_EQ(handler.m_message.find("origin response"), std::string::npos) << handler.m_message;
}

// An oversized origin body must be capped rather than copied verbatim.
TEST(ErrorMessage, OriginResponseBodyIsLengthCapped) {
    CapturingHandler handler;
    TestReadOp op(&handler, GetLog());

    op.SetCapturedErrorBody(std::string(8192, 'x'));
    op.Fail(XrdCl::errErrorResponse, kXR_ServerError, "Internal Server Error");

    ASSERT_TRUE(handler.m_called);
    // The sanitizer caps the embedded body at 1024 bytes; the whole message must
    // therefore stay comfortably bounded.
    EXPECT_LT(handler.m_message.size(), static_cast<size_t>(2048)) << handler.m_message.size();
}
