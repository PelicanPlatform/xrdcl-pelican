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
// Integration tests for the Pelican retry policy.
//
// These tests exercise the retry mechanism end-to-end by injecting real errors
// at the XRootD origin (via the XrdOssSlowOpen module) and verifying that the
// Pelican client correctly retries and either recovers or propagates the error.
//
// Error injection paths (handled by XrdOssSlowOpen):
//   /test/retry_read.txt            - first Read() returns -EIO, subsequent succeed
//   /test/retry_open.txt            - first Open() returns -EIO (→ HTTP 500), subsequent succeed
//   /test/retry_read_persistent.txt - all Read() calls return -EIO
//

#include "../XrdClCurlCommon/TransferTest.hh"

#include <XrdCl/XrdClFile.hh>
#include <XrdCl/XrdClFileSystem.hh>
#include <gtest/gtest.h>

#include <cstring>
#include <string>

class PelicanRetryFixture : public TransferFixture {
protected:
    void SetUp() override {
        TransferFixture::SetUp();

        auto pelican_url = GetEnv("PELICAN_URL");
        m_fs = std::make_unique<XrdCl::FileSystem>(XrdCl::URL(pelican_url));

        // Save original retry count, then reset counters
        std::string val;
        auto ok = m_fs->GetProperty("PelicanRetryCount", val);
        ASSERT_TRUE(ok) << "FileSystem::GetProperty(PelicanRetryCount) returned false; "
                        << "plugin may not be dispatching GetProperty";
        m_original_retry_count = std::stoi(val);
        m_fs->SetProperty("PelicanResetRetryCounters", "1");
    }

    void TearDown() override {
        m_fs->SetProperty("PelicanRetryCount", std::to_string(m_original_retry_count));
        TransferFixture::TearDown();
    }

    int GetReadRetryCount() {
        std::string val;
        m_fs->GetProperty("PelicanReadRetryCount", val);
        return std::stoi(val);
    }

    int GetOpenRetryCount() {
        std::string val;
        m_fs->GetProperty("PelicanOpenRetryCount", val);
        return std::stoi(val);
    }

    std::unique_ptr<XrdCl::FileSystem> m_fs;
    int m_original_retry_count{1};
};

// Verify that a transient read error (truncated response / CURLE_PARTIAL_FILE)
// is retried and the read ultimately succeeds.
//
// The origin's OSS module fails the first Read() for /test/retry_read.txt,
// causing the HTTP response to be truncated.  The ReadRetryHandler should
// re-issue the read, which succeeds on the second attempt.
TEST_F(PelicanRetryFixture, ReadRetryOnTransientError) {
    auto pelican_url = GetEnv("PELICAN_URL");
    ASSERT_FALSE(pelican_url.empty()) << "PELICAN_URL not set in test environment";

    m_fs->SetProperty("PelicanRetryCount", "1");

    XrdCl::File fh;
    auto url = pelican_url + "/test/retry_read.txt?directread&authz=" + GetReadToken();
    auto rv = fh.Open(url, XrdCl::OpenFlags::Read, XrdCl::Access::Mode(0755));
    ASSERT_TRUE(rv.IsOK()) << "Open failed: " << rv.ToString();

    // The first server-side read will fail; the retry handler should re-issue
    // the read transparently and return the correct data.
    char buffer[4096];
    uint32_t bytesRead = 0;
    rv = fh.Read(0, sizeof(buffer), buffer, bytesRead);
    ASSERT_TRUE(rv.IsOK()) << "Read failed despite retry being enabled: " << rv.ToString();
    ASSERT_GT(bytesRead, 0u) << "Expected data from retry_read.txt";

    // The OSS module fills successful reads with 'r'.
    for (uint32_t i = 0; i < bytesRead; i++) {
        ASSERT_EQ(buffer[i], 'r') << "Data mismatch at offset " << i;
    }

    // Verify that exactly one read retry was performed.  Without this check,
    // the test could pass if the error injection never fired.
    ASSERT_EQ(GetReadRetryCount(), 1)
        << "Expected exactly 1 read retry, but got " << GetReadRetryCount();
    ASSERT_EQ(GetOpenRetryCount(), 0)
        << "No open retries should have occurred";

    rv = fh.Close();
    ASSERT_TRUE(rv.IsOK()) << "Close failed: " << rv.ToString();
}

// Verify that an HTTP 500 from the origin during Open is retried and the
// file is ultimately opened successfully.
//
// The origin's OSS module fails the first Open() for /test/retry_open.txt
// with -EIO, which XRootD translates to HTTP 500.  The OpenRetryHandler
// should create a fresh connection and re-issue the open.
TEST_F(PelicanRetryFixture, OpenRetryOnServerError) {
    auto pelican_url = GetEnv("PELICAN_URL");
    ASSERT_FALSE(pelican_url.empty()) << "PELICAN_URL not set in test environment";

    m_fs->SetProperty("PelicanRetryCount", "1");

    XrdCl::File fh;
    auto url = pelican_url + "/test/retry_open.txt?directread&authz=" + GetReadToken();
    auto rv = fh.Open(url, XrdCl::OpenFlags::Read, XrdCl::Access::Mode(0755));
    ASSERT_TRUE(rv.IsOK()) << "Open failed despite retry being enabled: " << rv.ToString();

    // Verify we can read data after the retried open.
    char buffer[4096];
    uint32_t bytesRead = 0;
    rv = fh.Read(0, sizeof(buffer), buffer, bytesRead);
    ASSERT_TRUE(rv.IsOK()) << "Read failed after retried open: " << rv.ToString();
    ASSERT_GT(bytesRead, 0u) << "Expected data from retry_open.txt";

    for (uint32_t i = 0; i < bytesRead; i++) {
        ASSERT_EQ(buffer[i], 'r') << "Data mismatch at offset " << i;
    }

    // Verify that exactly one open retry was performed.
    ASSERT_EQ(GetOpenRetryCount(), 1)
        << "Expected exactly 1 open retry, but got " << GetOpenRetryCount();

    rv = fh.Close();
    ASSERT_TRUE(rv.IsOK()) << "Close failed: " << rv.ToString();
}

// Verify that when retries are exhausted (all attempts fail), the error
// propagates to the caller.
//
// The origin's OSS module fails every Read() for /test/retry_read_persistent.txt.
// With retry_count=1, the handler retries once, but the second read also fails.
// The error should be returned to the caller.
TEST_F(PelicanRetryFixture, ReadRetryExhausted) {
    auto pelican_url = GetEnv("PELICAN_URL");
    ASSERT_FALSE(pelican_url.empty()) << "PELICAN_URL not set in test environment";

    m_fs->SetProperty("PelicanRetryCount", "1");

    XrdCl::File fh;
    auto url = pelican_url + "/test/retry_read_persistent.txt?directread&authz=" + GetReadToken();
    auto rv = fh.Open(url, XrdCl::OpenFlags::Read, XrdCl::Access::Mode(0755));
    ASSERT_TRUE(rv.IsOK()) << "Open failed (should succeed for persistent-fail read path): " << rv.ToString();

    // Both the initial read and the retry should fail, so the error must
    // propagate to the caller.
    char buffer[4096];
    uint32_t bytesRead = 0;
    rv = fh.Read(0, sizeof(buffer), buffer, bytesRead);
    ASSERT_FALSE(rv.IsOK()) << "Read should have failed when all retries are exhausted";

    // Verify that the retry handler did attempt a retry before giving up.
    ASSERT_EQ(GetReadRetryCount(), 1)
        << "Expected exactly 1 read retry (exhausted), but got " << GetReadRetryCount();
}
