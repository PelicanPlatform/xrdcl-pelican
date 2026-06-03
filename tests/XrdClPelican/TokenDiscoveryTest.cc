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
