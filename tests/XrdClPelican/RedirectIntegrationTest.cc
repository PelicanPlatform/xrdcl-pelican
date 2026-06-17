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
// Integration test for https://github.com/PelicanPlatform/xrdcl-pelican/issues/116 :
// a host-relative redirect Location must be resolved against the *effective*
// (most recent) request URL, not the original one.
//
// In-the-wild trigger: a Pelican origin running the POSIX backend answers a
// request for a federation-prefix path WITHOUT a trailing slash (e.g.
// "/test-public") with a host-relative redirect (Location: "/test-public/").
// This is produced by Gin's default RedirectTrailingSlash: the origin's web
// engine registers the export as the route group "/test-public" with a
// "/*path" wildcard child, so a request to the bare prefix "/test-public" has
// no exact match and Gin redirects it to "/test-public/".  (A subdirectory such
// as "/test-public/subdir" is matched by the wildcard and is NOT redirected --
// which is why this test lists the namespace root specifically.)
//
// To exhibit the bug, the client must reach that origin via a prior cross-host
// redirect: the request is issued to the director (PELICAN_URL), which redirects
// to the origin (a different host) before the origin emits its host-relative
// Location.  Before the fix, the client resolved "/test-public/" against the
// director (the original m_url), reissued the request to the wrong host, and the
// listing failed (in the worst case ping-ponging until a timeout).  After the
// fix it resolves against the origin (the effective URL) and the listing
// succeeds.
//

#include "../XrdClCurlCommon/TransferTest.hh"

#include <XrdCl/XrdClFileSystem.hh>

#include <gtest/gtest.h>

class PelicanRedirectFixture : public TransferFixture {};

// List the federation-prefix root with no trailing slash, via the director, so
// the director -> origin cross-host hop precedes the origin's host-relative
// trailing-slash redirect.  "/test-public" is a public, listable export in the
// test federation, so no token is required.
TEST_F(PelicanRedirectFixture, ListNamespaceRootWithoutTrailingSlash) {
    auto pelican_url = GetEnv("PELICAN_URL");
    XrdCl::FileSystem fs{XrdCl::URL(pelican_url)};

    XrdCl::DirectoryList *listing{nullptr};
    auto st = fs.DirList("/test-public", XrdCl::DirListFlags::Stat, listing,
                         static_cast<uint16_t>(10));
    ASSERT_TRUE(st.IsOK())
        << "DirList of the namespace root without a trailing slash failed; the "
           "origin's host-relative redirect was likely resolved against the "
           "director instead of the origin (issue #116): " << st.ToString();
    ASSERT_NE(listing, nullptr);
    EXPECT_GT(listing->GetSize(), 0u)
        << "Expected a non-empty listing of the /test-public namespace root";
    delete listing;
}
