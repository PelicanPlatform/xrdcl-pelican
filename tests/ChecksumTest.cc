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

#include "ChecksumCache.hh"
#include "PelicanFactory.hh"
#include "PelicanFile.hh"
#include "PelicanFilesystem.hh"
#include "TransferTest.hh"

#include <gtest/gtest.h>
#include <XrdCl/XrdClBuffer.hh>

class ChecksumFixture : public TransferFixture{
protected:
    void WriteString(const std::string &name, const std::string &contents);
    void VerifyString(const std::string &name, const std::string &contents);
};

void
ChecksumFixture::WriteString(const std::string &name, const std::string &contents)
{
    XrdCl::File fh;

    auto url = name + "?authz=" + GetWriteToken();
    auto rv = fh.Open(url, XrdCl::OpenFlags::Write, XrdCl::Access::Mode(0755), static_cast<Pelican::File::timeout_t>(0));
    ASSERT_TRUE(rv.IsOK()) << "Failed to open " << name << " for write: " << rv.ToString();

    rv = fh.Write(0, contents.size(), contents.data(), static_cast<Pelican::File::timeout_t>(0));
    ASSERT_TRUE(rv.IsOK()) << "Failed to write " << name << ": " << rv.ToString();

    rv = fh.Close();
    ASSERT_TRUE(rv.IsOK());

    VerifyString(name, contents);
}

void
ChecksumFixture::VerifyString(const std::string &name, const std::string &contents)
{
    XrdCl::File fh;

    auto url = name + "?authz=" + GetReadToken();
    auto rv = fh.Open(url, XrdCl::OpenFlags::Read, XrdCl::Access::Mode(0755), static_cast<Pelican::File::timeout_t>(0));
    ASSERT_TRUE(rv.IsOK()) << "Failed to open " << name << " for read: " << rv.ToString();

    uint32_t bytesRead;
    std::string result;
    result.resize(contents.size());
    rv = fh.Read(0, contents.size(), result.data(), bytesRead, static_cast<Pelican::File::timeout_t>(0));
    ASSERT_TRUE(rv.IsOK()) << "Failed to read " << name << ": " << rv.ToString();
    ASSERT_EQ(contents.size(), bytesRead);

    ASSERT_EQ(result, contents);
}

TEST_F(ChecksumFixture, Basic)
{
    auto &ccache = Pelican::ChecksumCache::Instance();
    auto hits = ccache.GetCacheHits();
    auto misses = ccache.GetCacheMisses();

    auto source_url = std::string("/test/checksum_md5");
    WritePattern(GetOriginURL() + source_url, 2*1024, 'a', 1023);

    // MD5 hand-calculated:
    // >>> o = hashlib.md5()
    // >>> o.update(("a"*1023).encode())
    // >>> o.update(("b"*1023).encode())
    // >>> o.update("cc".encode())
    // >>> o.hexdigest()
    // '4a42dabcf0c6233b3dac41196313e748'
    const std::string expected_response = "md5 4a42dabcf0c6233b3dac41196313e748";

    // To query the checksum, we use the Checksum query code and put the desired
    // URL in the buffer.  The preferred checksum type is specified in the URL
    // query string by the parameter `cks.type`.
    //
    // The expected response is the checksum type followed by the checksum value.
    auto fs = m_factory->CreateFileSystem(GetOriginURL());
    XrdCl::Buffer buffer;
    buffer.FromString(source_url + "?cks.type=md5&authz=" + GetReadToken());
    SyncResponseHandler srh;
    fs->Query(XrdCl::QueryCode::Checksum, buffer, &srh, 0);
    srh.Wait();
    auto [status, obj] = srh.Status();
    ASSERT_EQ(status->IsOK(), true);
    XrdCl::Buffer *resp{nullptr};
    obj->Get(resp);

    ASSERT_EQ(resp->ToString(), expected_response);

    source_url = "/test/checksum_crc32c";
    WriteString(GetOriginURL() + source_url, "dog");
    
    // From https://www.iana.org/assignments/http-dig-alg/http-dig-alg.xhtml, the
    // crc32c of the string `dog` should be 0a72a4df.
    buffer.FromString(source_url + "?cks.type=adler32&authz=" + GetReadToken());
    fs->Query(XrdCl::QueryCode::Checksum, buffer, &srh, 0);
    srh.Wait();
    auto [status2, obj2] = srh.Status();
    ASSERT_EQ(status2->IsOK(), true);
    resp = nullptr;
    obj2->Get(resp);
    // NOTE: As of 18 March 2025, `pelican` binaries do not enable crc32c.  Patch sent 
    // in https://github.com/PelicanPlatform/pelican/pull/2106
    // Uncomment when the corresponding version is widely available.
    // ASSERT_EQ(resp->ToString(), "crc32c 0a72a4df");

    fs->Query(XrdCl::QueryCode::Checksum, buffer, &srh, 0);
    srh.Wait();
    std::tie(status2, obj2) = srh.Status();
    ASSERT_EQ(status2->IsOK(), true);

    ASSERT_EQ(hits + 1, ccache.GetCacheHits());
    ASSERT_EQ(misses + 2, ccache.GetCacheMisses());
}
