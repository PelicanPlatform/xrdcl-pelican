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

#include "XrdClPelican/PelicanFactory.hh"
#include "XrdClPelican/PelicanFile.hh"
#include "../XrdClCurlCommon/TransferTest.hh"

#include <gtest/gtest.h>

#include <fcntl.h>

class CacheTokenFixture : public TransferFixture {

protected:
    CacheTokenFixture() = default;

    void SetUp() override {
        TransferFixture::SetUp();

        char token_path[] = "xrdcl_pelican_test_token.XXXXXX";
        ASSERT_NE(-1, mkstemp(token_path));
        m_token_path = std::string(token_path);
    }

    void TearDown() override {
        TransferFixture::TearDown();

        if (!m_token_path.empty()) {
            ASSERT_NE(-1, unlink(m_token_path.c_str()));
        }
    }

    void WriteTokenFile(const std::string &contents) const {
        int fd;
        fd = open(m_token_path.c_str(), O_TRUNC|O_WRONLY);
        ASSERT_NE(-1, fd);

        off_t offset = 0;
        auto remaining = contents.length();
        while (remaining) {
            int rc = write(fd, contents.data() + offset, remaining);
            if (rc == -1) {
                if (errno == EAGAIN || errno == EINTR) {
                    continue;
                }
                ASSERT_NE(-1, rc) << "Write failed with " << strerror(errno);
            }
            remaining -= static_cast<size_t>(rc);
            offset += rc;
        }
        ASSERT_NE(-1, close(fd));
    }

    const std::string & GetTokenPath() const {return m_token_path;}

private:
    std::string m_token_path;
};


TEST_F(CacheTokenFixture, TokenSet) {
    auto pelican_url = GetEnv("PELICAN_URL");
    ASSERT_FALSE(pelican_url.empty());
    auto fname = std::string("/test-public/cache_token");
    WritePattern(pelican_url + fname, 2*1024, 'a', 1023);

    auto fh = XrdCl::File();
    auto st = fh.Open(pelican_url + fname, XrdCl::OpenFlags::Read);
    ASSERT_TRUE(st.IsOK());

    std::string value;
    ASSERT_TRUE(fh.GetProperty("CurrentURL", value));
    ASSERT_EQ(value, GetOriginURL() + fname + "?xrdclcurl.timeout=9s500ms");

    fh.SetProperty("CacheToken", "foo");

    fh.GetProperty("CurrentURL", value);
    ASSERT_EQ(value, GetOriginURL() + fname + "?access_token=foo&xrdclcurl.timeout=9s500ms");

    st = fh.Close();
    ASSERT_TRUE(st.IsOK());
    st = fh.Open(pelican_url + fname + "?test", XrdCl::OpenFlags::Read);
    ASSERT_TRUE(st.IsOK());
    fh.GetProperty("CurrentURL", value);
    ASSERT_EQ(value, GetOriginURL() + fname + "?access_token=foo&test=&xrdclcurl.timeout=9s500ms");
}


TEST_F(CacheTokenFixture, RefreshToken) {
    auto pelican_url = GetEnv("PELICAN_URL");
    ASSERT_FALSE(pelican_url.empty());
    auto fname = std::string("/test-public/cache_token_refresh");
    WritePattern(pelican_url + fname, 2*1024, 'a', 1023);

    auto fh = XrdCl::File();
    auto st = fh.Open(pelican_url + fname, XrdCl::OpenFlags::Read);
    ASSERT_TRUE(st.IsOK());

    WriteTokenFile("REDACTED");

    fh.SetProperty("RefreshToken", GetTokenPath());
    std::string value;
    fh.GetProperty("CurrentURL", value);
    ASSERT_EQ(value, GetOriginURL() + fname + "?access_token=REDACTED&xrdclcurl.timeout=9s500ms");

    WriteTokenFile("\n#test\n\tfoo ");
    fh.SetProperty("RefreshToken", GetTokenPath());
    fh.GetProperty("CurrentURL", value);
    ASSERT_EQ(value, GetOriginURL() + fname + "?access_token=foo&xrdclcurl.timeout=9s500ms");

    WriteTokenFile("");
    fh.SetProperty("RefreshToken", GetTokenPath());
    fh.GetProperty("CurrentURL", value);
    ASSERT_EQ(value, GetOriginURL() + fname + "?xrdclcurl.timeout=9s500ms");

    WriteTokenFile("foo\nbar");
    fh.SetProperty("RefreshToken", GetTokenPath());
    fh.GetProperty("CurrentURL", value);
    ASSERT_EQ(value, GetOriginURL() + fname + "?access_token=bar&xrdclcurl.timeout=9s500ms");
}
