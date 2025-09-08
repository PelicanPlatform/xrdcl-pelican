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
#include "XrdClPelican/WritebackDB.hh"

#include <XrdCl/XrdClConstants.hh>
#include <XrdCl/XrdClFile.hh>
#include <XrdCl/XrdClLog.hh>
#include <gtest/gtest.h>

#include <fstream>
#include <thread>

class WritebackFixture : public TransferFixture {
protected:
    void TearDown() override {
        // Wait for all writebacks to complete.
        std::string pelican_url = GetEnv("PELICAN_URL");
        if (!pelican_url.empty()) {
            XrdCl::FileSystem fs(pelican_url);
            XrdCl::Buffer buf;
            buf.FromString("pelican.waitwriteback");
            auto rv = fs.Query(XrdCl::QueryCode::Opaque, buf, nullptr, static_cast<XrdClCurl::File::timeout_t>(0));
            ASSERT_TRUE(rv.IsOK()) << "Failed to issue pelican.waitwriteback command: " << rv.ToString();
            fprintf(stderr, "Pelican writeback completed successfully\n");
        }
        TransferFixture::TearDown();
    }
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

    // Check to see if the DB has the writeback entry
    Pelican::WritebackDB db(writedir + "/writeback.db", *GetLogger());
    std::string message, err;
    uint64_t writeSizeDB = 0;
    Pelican::WritebackDB::TransferState state;
    ASSERT_TRUE(db.GetTransferStatus(cache_id, state, writeSizeDB, message, err)) << "Failed to get writeback status from DB: " << err;
    ASSERT_TRUE(message.empty()) << "Expected an empty message for new transfer; got: " << message;
    ASSERT_EQ(state, Pelican::WritebackDB::TransferState::ACTIVE) << "Expected transfer state ACTIVE for new transfer; got: " << Pelican::WritebackDB::GetStateString(state);
    ASSERT_EQ(writeSizeDB, 0) << "Expected 0 bytes transferred for new transfer; got: " << writeSizeDB;

    std::string writeBuffer(chunkSize, 'a');
    rv = fh.Write(0, chunkSize, writeBuffer.data(), static_cast<XrdClCurl::File::timeout_t>(10));
    ASSERT_TRUE(rv.IsOK()) << "Failed to write " << url << ": " << rv.ToString();

    fs.SetProperty("PelicanMaintenanceInterval", "100ms");
    // Sleep for 2x maintenance interval
    std::this_thread::sleep_for(2 * std::chrono::milliseconds(100));

    ASSERT_TRUE(db.GetTransferStatus(cache_id, state, writeSizeDB, message, err)) << "Failed to get writeback status from DB: " << err;
    ASSERT_TRUE(message.empty()) << "Expected an empty message for new transfer; got: " << message;
    ASSERT_EQ(state, Pelican::WritebackDB::TransferState::ACTIVE) << "Expected transfer state ACTIVE for new transfer; got: " << Pelican::WritebackDB::GetStateString(state);
    ASSERT_EQ(writeSizeDB, chunkSize) << "Expected " << chunkSize << " bytes transferred for new transfer; got: " << writeSizeDB;

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

    // Check that the writeback entry has a SUCCESS status
    ASSERT_TRUE(db.GetTransferStatus(cache_id, state, writeSizeDB, message, err)) << "Failed to get writeback status from DB: " << err;
    ASSERT_EQ(state, Pelican::WritebackDB::TransferState::SUCCESS) << "Expected transfer state SUCCESS for completed transfer; got: " << Pelican::WritebackDB::GetStateString(state);
    ASSERT_EQ(writeSizeDB, 2*chunkSize) << "Expected " << chunkSize << " bytes transferred for completed transfer; got: " << writeSizeDB;

    // Verify the contents of the uploaded file
    url = GetOriginURL() + "/test/writeback?authz=" + GetReadToken();
    VerifyContents(url, writeSize, 'a', chunkSize);
}