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

#include "XrdClPelican/PelicanFile.hh"
#include "XrdClPelican/RetryThread.hh"

#include <XrdCl/XrdClStatus.hh>
#include <XProtocol/XProtocol.hh>

#include <gtest/gtest.h>

//
// Tests for IsRetryable: verifies that targeted errors are correctly identified
//

TEST(IsRetryable, SuccessIsNotRetryable) {
    XrdCl::XRootDStatus status;
    EXPECT_FALSE(Pelican::IsRetryable(status));
}

TEST(IsRetryable, SocketErrorIsRetryable) {
    // TCP socket closed mid-transfer (CURLE_SEND_ERROR / CURLE_RECV_ERROR)
    XrdCl::XRootDStatus status(XrdCl::stError, XrdCl::errSocketError, EIO);
    EXPECT_TRUE(Pelican::IsRetryable(status));
}

TEST(IsRetryable, DataErrorIsRetryable) {
    // Partial file / truncated response (CURLE_PARTIAL_FILE)
    XrdCl::XRootDStatus status(XrdCl::stError, XrdCl::errDataError, 0);
    EXPECT_TRUE(Pelican::IsRetryable(status));
}

TEST(IsRetryable, ServerErrorIsRetryable) {
    // HTTP 500 Internal Server Error
    XrdCl::XRootDStatus status(XrdCl::stError, XrdCl::errErrorResponse, kXR_ServerError);
    EXPECT_TRUE(Pelican::IsRetryable(status));
}

TEST(IsRetryable, NotFoundIsNotRetryable) {
    // HTTP 404 should not be retried
    XrdCl::XRootDStatus status(XrdCl::stError, XrdCl::errErrorResponse, kXR_NotFound);
    EXPECT_FALSE(Pelican::IsRetryable(status));
}

TEST(IsRetryable, NotAuthorizedIsNotRetryable) {
    // HTTP 403 should not be retried
    XrdCl::XRootDStatus status(XrdCl::stError, XrdCl::errErrorResponse, kXR_NotAuthorized);
    EXPECT_FALSE(Pelican::IsRetryable(status));
}

TEST(IsRetryable, InvalidRequestIsNotRetryable) {
    // HTTP 400 should not be retried
    XrdCl::XRootDStatus status(XrdCl::stError, XrdCl::errErrorResponse, kXR_InvalidRequest);
    EXPECT_FALSE(Pelican::IsRetryable(status));
}

TEST(IsRetryable, InvalidOpIsNotRetryable) {
    // Internal errors like "URL isn't open" should not be retried
    XrdCl::XRootDStatus status(XrdCl::stError, XrdCl::errInvalidOp);
    EXPECT_FALSE(Pelican::IsRetryable(status));
}

TEST(IsRetryable, TlsErrorIsNotRetryable) {
    XrdCl::XRootDStatus status(XrdCl::stError, XrdCl::errTlsError, 0);
    EXPECT_FALSE(Pelican::IsRetryable(status));
}

//
// Tests for retry count configuration
//

TEST(RetryConfig, DefaultRetryCount) {
    // Default retry count should be 1
    EXPECT_EQ(Pelican::File::GetRetryCount(), 1);
}

TEST(RetryConfig, SetRetryCount) {
    auto original = Pelican::File::GetRetryCount();
    Pelican::File::SetRetryCount(3);
    EXPECT_EQ(Pelican::File::GetRetryCount(), 3);

    Pelican::File::SetRetryCount(0);
    EXPECT_EQ(Pelican::File::GetRetryCount(), 0);

    // Restore original
    Pelican::File::SetRetryCount(original);
}

TEST(RetryConfig, DefaultBaseDelay) {
    // Default base delay should be 100ms
    EXPECT_EQ(Pelican::RetryThread::GetBaseDelay(), std::chrono::milliseconds(100));
}

TEST(RetryConfig, SetBaseDelay) {
    auto original = Pelican::RetryThread::GetBaseDelay();
    Pelican::RetryThread::SetBaseDelay(std::chrono::milliseconds(250));
    EXPECT_EQ(Pelican::RetryThread::GetBaseDelay(), std::chrono::milliseconds(250));

    Pelican::RetryThread::SetBaseDelay(std::chrono::milliseconds(50));
    EXPECT_EQ(Pelican::RetryThread::GetBaseDelay(), std::chrono::milliseconds(50));

    // Restore original
    Pelican::RetryThread::SetBaseDelay(original);

    // Clean up heap-allocated RetryState so ASAN doesn't report a leak.
    Pelican::RetryThread::Shutdown();
}
