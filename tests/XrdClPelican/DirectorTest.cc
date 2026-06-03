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

#include "XrdClPelican/PelicanFilesystem.hh"
#include "../XrdClCurlCommon/TransferTest.hh"

#include <gtest/gtest.h>

class DirectoryTransferFixture : public TransferFixture {
};


TEST_F(DirectoryTransferFixture, QueryModeTest) {
    auto chunk_ctr = 10;

    auto pelican_url = GetEnv("PELICAN_URL");

    auto url = pelican_url + "/test/query_mode_" + std::to_string(chunk_ctr);
    ASSERT_NO_FATAL_FAILURE(WritePattern(url, chunk_ctr * 100'000, 'a', chunk_ctr * 10'000));

    // Open the file for reads and ensure we were redirected to the origin
    XrdCl::File fh;
    auto read_url = url + "?authz=" + GetReadToken();
    auto rv = fh.Open(read_url, XrdCl::OpenFlags::Read, XrdCl::Access::Mode(0755), static_cast<Pelican::Filesystem::timeout_t>(10));
    ASSERT_TRUE(rv.IsOK()) << "Failed to open " << read_url << " for read: " << rv.ToString();
    std::string location;
    ASSERT_TRUE(fh.GetProperty("LastURL", location)) << "Failed to get LastURL property";
    ASSERT_EQ(location, GetOriginURL() + "/test/query_mode_" + std::to_string(chunk_ctr)+ "?authz=" + GetReadToken() + "&xrdclcurl.timeout=9s500ms") << "Expected to be redirected to origin, but LastURL is " << location;
    rv = fh.Close();
    ASSERT_TRUE(rv.IsOK());

    // Empty the query cache to ensure we actually re-query
    XrdCl::FileSystem fs(pelican_url);
    XrdCl::Buffer buffer;
    buffer.FromString("pelican.directorcache reset");
    auto status = fs.Query(XrdCl::QueryCode::Opaque, buffer, nullptr, static_cast<Pelican::Filesystem::timeout_t>(10));
    ASSERT_TRUE(status.IsOK()) << "Failed to reset director cache: " << status.ToString();

    // Change the query mode to always use cache
    ASSERT_TRUE(fs.SetProperty("PelicanDirectorQueryMode", "cache"));

    // Open the file for reads and ensure we were redirected to the cache
    XrdCl::File fh2;
    rv = fh2.Open(read_url, XrdCl::OpenFlags::Read, XrdCl::Access::Mode(0755), static_cast<Pelican::Filesystem::timeout_t>(10));
    ASSERT_TRUE(rv.IsOK()) << "Failed to open " << read_url << " for read: " << rv.ToString();
    ASSERT_TRUE(fh2.GetProperty("LastURL", location)) << "Failed to get LastURL property";
    ASSERT_EQ(location, GetCacheURL() + "/test/query_mode_" + std::to_string(chunk_ctr)+ "?authz=" + GetReadToken() + "&pelican.timeout=9s500ms&xrdclcurl.timeout=9s500ms") << "Expected to be redirected to cache, but LastURL is " << location;
    rv = fh2.Close();
    ASSERT_TRUE(rv.IsOK());
}
