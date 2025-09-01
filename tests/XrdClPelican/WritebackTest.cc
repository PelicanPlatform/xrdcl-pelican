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

#include "../XrdClCurlCommon/TransferTest.hh"
#include "XrdClCurl/XrdClCurlFile.hh"

#include <XrdCl/XrdClConstants.hh>
#include <XrdCl/XrdClFile.hh>
#include <XrdCl/XrdClLog.hh>
#include <gtest/gtest.h>

#include <fstream>

class WritebackFixture : public TransferFixture {
};

// Upload a small file using the writeback mechanism
// Verifies the intermediate file is created and then removed
// Verifies the contents of the uploaded file
TEST_F(WritebackFixture, Basic) {

    auto writedir = GetEnv("PELICAN_WRITEBACKDIR");
    ASSERT_FALSE(writedir.empty()) << "PELICAN_WRITEBACKDIR environment variable not set";

    std::string pelican_url = GetEnv("PELICAN_URL");
    ASSERT_FALSE(pelican_url.empty()) << "PELICAN_URL environment variable not set";

    XrdCl::FileSystem fs(pelican_url);
    ASSERT_TRUE(fs.SetProperty("PelicanWritebackLocation", writedir)) << "Failed to set PelicanWritebackLocation property on FileSystem";

    XrdCl::File fh;

    std::string cache_id = "1234";
    size_t chunkSize = 1024;
    auto writeSize = 2 * chunkSize;
    auto url = pelican_url + "/test/writeback?authz=" + GetWriteToken() + "&oss.asize=" + std::to_string(writeSize)
        + "&pelican.cache_id=" + cache_id;

    auto rv = fh.Open(url, XrdCl::OpenFlags::Write, XrdCl::Access::Mode(0755), static_cast<XrdClCurl::File::timeout_t>(0));
    ASSERT_TRUE(rv.IsOK()) << "Failed to open " << url << " for write: " << rv.ToString();

    std::string writeBuffer(chunkSize, 'a');
    rv = fh.Write(0, chunkSize, writeBuffer.data(), static_cast<XrdClCurl::File::timeout_t>(10));
    ASSERT_TRUE(rv.IsOK()) << "Failed to write " << url << ": " << rv.ToString();

    // Ensure the intermediate file exists
    std::string intermediate_file = writedir + "/" + cache_id + ".part";
    struct stat st;
    ASSERT_EQ(stat(intermediate_file.c_str(), &st), 0) << "Intermediate writeback file " << intermediate_file << " does not exist after write";
    ASSERT_EQ(st.st_size, writeSize) << "Intermediate writeback file " << intermediate_file << " has incorrect size after write";

    // Check the contents of the intermediate file
    std::string file_contents(writeSize, '\0');
    std::ifstream ifs(intermediate_file, std::ios::binary);
    ASSERT_TRUE(ifs.good()) << "Failed to open intermediate writeback file " << intermediate_file << " for read";
    ifs.read(file_contents.data(), chunkSize);
    ASSERT_EQ(file_contents.substr(0, chunkSize), writeBuffer) << "Intermediate writeback file " << intermediate_file << " has incorrect contents";

    // Write the second chunk
    std::fill(writeBuffer.begin(), writeBuffer.end(), 'b');
    rv = fh.Write(chunkSize, chunkSize, writeBuffer.data(), static_cast<XrdClCurl::File::timeout_t>(10));
    ASSERT_TRUE(rv.IsOK()) << "Failed to write second chunk to " << url << ": " << rv.ToString();

    GetLogger()->Debug(XrdCl::UtilityMsg, "Finished writing transfer pattern to %s", url.c_str());

    rv = fh.Close();
    ASSERT_TRUE(rv.IsOK()) << "Failed to close " << url << ": " << rv.ToString();

    // Loop until the intermediate file is removed, sleeping 50ms between checks
    int retries = 20;
    while (retries-- > 0) {
        if (stat(intermediate_file.c_str(), &st) != 0 && errno == ENOENT) {
            // File is gone, success
            break;
        }
        usleep(50000);
    }
    ASSERT_NE(retries, 0) << "Intermediate writeback file " << intermediate_file << " still exists after writeback close";

    // Verify the contents of the uploaded file
    url = GetOriginURL() + "/test/writeback?authz=" + GetReadToken();
    VerifyContents(url, writeSize, 'a', chunkSize);
}