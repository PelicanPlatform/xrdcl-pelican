/****************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

#include "CurlWorker.hh"

#include <XrdCl/XrdClDefaultEnv.hh>
#include <XrdCl/XrdClLog.hh>

#include <gtest/gtest.h>

#include <fcntl.h>

#include <thread>

class CurlWorkerFixture : public testing::Test {

protected:
    CurlWorkerFixture()
      : m_log(XrdCl::DefaultEnv::GetLog())
    {
        std::call_once(m_init, []{
            curl_global_init(CURL_GLOBAL_DEFAULT);
        });
    }

    void SetUp() override {
        char token_path[] = "xrdcl_pelican_test_token.XXXXXX";
        ASSERT_NE(-1, mkstemp(token_path));
        m_token_path = std::string(token_path);
        m_curl = curl_easy_init();
        ASSERT_NE(nullptr, m_curl);
    }

    void TearDown() override {
        if (m_curl) {curl_easy_cleanup(m_curl);}
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

    void CheckCurlUrl(const std::string &expected) const {
        ASSERT_NE(nullptr, m_curl);
        char *url_char{nullptr};
        ASSERT_EQ(CURLE_OK, curl_easy_getinfo(m_curl, CURLINFO_EFFECTIVE_URL, &url_char));
        ASSERT_NE(nullptr, url_char);
        ASSERT_NE('\0', url_char[0]);
        ASSERT_EQ(expected ,std::string(url_char));
    }

    XrdCl::Log *GetLog() const {return m_log;}
    const std::string &GetTokenPath() const {return m_token_path;}
    CURL *GetCurl() const {return m_curl;}

private:
    XrdCl::Log *m_log{nullptr};
    std::string m_token_path;
    CURL *m_curl{nullptr};
    static std::once_flag m_init;
};

decltype(CurlWorkerFixture::m_init) CurlWorkerFixture::m_init;

TEST_F(CurlWorkerFixture, RefreshToken) {
    WriteTokenFile("REDACTED");

    auto [success, contents] = Pelican::CurlWorker::RefreshCacheTokenStatic(GetTokenPath(), GetLog());
    ASSERT_TRUE(success);
    ASSERT_EQ("REDACTED", contents);

    WriteTokenFile("\n#test\n\tfoo ");
    std::tie(success, contents) = Pelican::CurlWorker::RefreshCacheTokenStatic(GetTokenPath(), GetLog());
    ASSERT_TRUE(success);
    ASSERT_EQ("foo", contents);

    std::tie(success, contents) = Pelican::CurlWorker::RefreshCacheTokenStatic("", GetLog());
    ASSERT_TRUE(success);

    contents = "foo-test";
    std::tie(success, contents) = Pelican::CurlWorker::RefreshCacheTokenStatic(GetTokenPath() + "DoesNotExist", GetLog());
    ASSERT_FALSE(success);
    ASSERT_EQ("", contents);

    WriteTokenFile("");
    std::tie(success, contents) = Pelican::CurlWorker::RefreshCacheTokenStatic(GetTokenPath(), GetLog());
    ASSERT_TRUE(success);
    ASSERT_EQ("", contents);

    WriteTokenFile("foo\nbar");
    std::tie(success, contents) = Pelican::CurlWorker::RefreshCacheTokenStatic(GetTokenPath(), GetLog());
    ASSERT_TRUE(success);
    ASSERT_EQ("bar", contents);
}

TEST_F(CurlWorkerFixture, CurlSetup) {
    auto curl = GetCurl();

    ASSERT_EQ(CURLE_OK, curl_easy_setopt(curl, CURLOPT_URL, "https://test.com"));
    ASSERT_TRUE(Pelican::CurlWorker::SetupCacheTokenStatic("", curl, GetLog()));
    CheckCurlUrl("https://test.com");

    ASSERT_EQ(CURLE_OK, curl_easy_setopt(curl, CURLOPT_URL, "https://test.com"));
    ASSERT_TRUE(Pelican::CurlWorker::SetupCacheTokenStatic("foo", curl, GetLog()));
    CheckCurlUrl("https://test.com?access_token=foo");

    ASSERT_EQ(CURLE_OK, curl_easy_setopt(curl, CURLOPT_URL, "https://test.com/prefix?test"));
    ASSERT_TRUE(Pelican::CurlWorker::SetupCacheTokenStatic("foo", curl, GetLog()));
    CheckCurlUrl("https://test.com/prefix?test&access_token=foo");
}
