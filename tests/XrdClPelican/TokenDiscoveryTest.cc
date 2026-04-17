/****************************************************************
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

#include "XrdClPelican/PelicanFactory.hh"

#include <gtest/gtest.h>

#include <cstdlib>
#include <map>
#include <string>

class TokenDiscoveryFixture : public ::testing::Test {
protected:
    void SetUp() override {
        // Save original env var values so we can restore them in TearDown
        SaveEnv("BEARER_TOKEN");
        SaveEnv("BEARER_TOKEN_FILE");

        // Clear both vars to start each test with a clean slate
        unsetenv("BEARER_TOKEN");
        unsetenv("BEARER_TOKEN_FILE");
    }

    void TearDown() override {
        // Restore original env var values
        RestoreEnv("BEARER_TOKEN");
        RestoreEnv("BEARER_TOKEN_FILE");
    }

private:
    void SaveEnv(const char *name) {
        auto val = std::getenv(name);
        if (val) {
            m_saved_env[name] = val;
        }
    }

    void RestoreEnv(const char *name) {
        auto it = m_saved_env.find(name);
        if (it != m_saved_env.end()) {
            setenv(name, it->second.c_str(), 1);
        } else {
            unsetenv(name);
        }
    }

    std::map<std::string, std::string> m_saved_env;
};

TEST_F(TokenDiscoveryFixture, NeitherSet) {
    auto [contents, file] = Pelican::PelicanFactory::DiscoverWLCGToken();
    EXPECT_TRUE(contents.empty());
    EXPECT_TRUE(file.empty());
}

TEST_F(TokenDiscoveryFixture, BearerTokenSet) {
    setenv("BEARER_TOKEN", "my-secret-token", 1);
    auto [contents, file] = Pelican::PelicanFactory::DiscoverWLCGToken();
    EXPECT_EQ(contents, "my-secret-token");
    EXPECT_TRUE(file.empty());
}

TEST_F(TokenDiscoveryFixture, BearerTokenFileSet) {
    setenv("BEARER_TOKEN_FILE", "/tmp/my-token-file", 1);
    auto [contents, file] = Pelican::PelicanFactory::DiscoverWLCGToken();
    EXPECT_TRUE(contents.empty());
    EXPECT_EQ(file, "/tmp/my-token-file");
}

TEST_F(TokenDiscoveryFixture, BearerTokenTakesPrecedence) {
    setenv("BEARER_TOKEN", "my-secret-token", 1);
    setenv("BEARER_TOKEN_FILE", "/tmp/my-token-file", 1);
    auto [contents, file] = Pelican::PelicanFactory::DiscoverWLCGToken();
    EXPECT_EQ(contents, "my-secret-token");
    EXPECT_TRUE(file.empty());
}

TEST_F(TokenDiscoveryFixture, BearerTokenEmptyFallsThrough) {
    setenv("BEARER_TOKEN", "", 1);
    setenv("BEARER_TOKEN_FILE", "/tmp/my-token-file", 1);
    auto [contents, file] = Pelican::PelicanFactory::DiscoverWLCGToken();
    EXPECT_TRUE(contents.empty());
    EXPECT_EQ(file, "/tmp/my-token-file");
}

TEST_F(TokenDiscoveryFixture, BearerTokenFileEmpty) {
    setenv("BEARER_TOKEN_FILE", "", 1);
    auto [contents, file] = Pelican::PelicanFactory::DiscoverWLCGToken();
    EXPECT_TRUE(contents.empty());
    EXPECT_TRUE(file.empty());
}
