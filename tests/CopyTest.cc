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

#include "CurlUtil.hh"
#include "CurlWorker.hh"
#include "PelicanFactory.hh"
#include "PelicanFile.hh"

#include <XrdCl/XrdClDefaultEnv.hh>
#include <XrdCl/XrdClLog.hh>

#include <gtest/gtest.h>

#include <fstream>
#include <mutex>

namespace {

class SyncResponseHandler: public XrdCl::ResponseHandler {
public:
    SyncResponseHandler() {}

    virtual ~SyncResponseHandler() {}

    virtual void HandleResponse( XrdCl::XRootDStatus *status, XrdCl::AnyObject *response ) {
        std::unique_lock lock(m_mutex);
        m_status.reset(status);
        m_obj.reset(response);
        m_cv.notify_one();
    }

    void Wait() {
        std::unique_lock lock(m_mutex);
        m_cv.wait(lock, [&]{return m_status.get() != nullptr;});
    }

    std::unique_ptr<XrdCl::XRootDStatus> Status() {
        return std::move(m_status);
    }

private:
    std::mutex m_mutex;
    std::condition_variable m_cv;

    std::unique_ptr<XrdCl::XRootDStatus> m_status;
    std::unique_ptr<XrdCl::AnyObject> m_obj;
};

} // namespace

class CurlCopyFixture : public testing::Test {

protected:
    CurlCopyFixture()
      : m_log(XrdCl::DefaultEnv::GetLog())
    {}

    void SetUp() override;

    // Helper function to write a file with a given pattern of contents.
    //
    // Useful for making large files with known contents that are varying from
    // call-to-call (useful in detection of off-by-one errors).
    // - `writeSize`: Total size of the uploaded object
    // - `chunkByte`: Byte value of the first character in the file.
    // - `chunkSize`: Number of bytes to repeat the first `chunkByte`.  Afterward,
    //   the function will write `chunkByte + 1` for `chunkSize` characters and so on.
    void WritePattern(const std::string &name, const off_t writeSize,
                      const unsigned char chunkByte, const size_t chunkSize);

    // Helper function to verify the contents of a given object..
    //
    // Useful for verifying the contents of an object created with `WritePattern`
    // - `writeSize`: Total size of the uploaded object
    // - `chunkByte`: Byte value of the first character in the file.
    // - `chunkSize`: Number of bytes to repeat the first `chunkByte`.  Afterward,
    //   the function will write `chunkByte + 1` for `chunkSize` characters and so on.
    void VerifyContents(const std::string &name, const off_t writeSize,
                        const unsigned char chunkByte, const size_t chunkSize);

    const std::string &GetOriginURL() const {return m_origin_url;}
    const std::string &GetReadToken() const {return m_read_token;}
    const std::string &GetWriteToken() const {return m_write_token;}

    // Factory object; creating one will initialize the worker threads
    static std::unique_ptr<Pelican::PelicanFactory> m_factory;

private:
    void ReadTokenFromFile(const std::string &fname, std::string &token);

    // Flag for initializing the global settings inherited from the text fixture.
    static std::once_flag m_init;

    // Log object to help debug test runs
    XrdCl::Log *m_log{nullptr};

    // Whether the test fixture globals were initialized
    static bool m_initialized;

    // Location of the read token file
    static std::string m_read_token_location;

    // Contents of the read token
    static std::string m_read_token;

    // Location of the write token file
    static std::string m_write_token_location;

    // Contents of the write token
    static std::string m_write_token;

    // Location of the custom CA file used by the test
    static std::string m_ca_file;

    // URL prefix to contact the origin
    std::string m_origin_url;

    void parseEnvFile(const std::string &fname);
};

std::once_flag CurlCopyFixture::m_init;
bool CurlCopyFixture::m_initialized = false;
std::string CurlCopyFixture::m_read_token_location;
std::string CurlCopyFixture::m_read_token;
std::string CurlCopyFixture::m_write_token_location;
std::string CurlCopyFixture::m_write_token;
std::string CurlCopyFixture::m_ca_file;
std::unique_ptr<Pelican::PelicanFactory> CurlCopyFixture::m_factory;

void
CurlCopyFixture::ReadTokenFromFile(const std::string &fname, std::string &token)
{
    std::ifstream fh(fname);
    ASSERT_TRUE(fh.is_open());
    std::string line;
    while (std::getline(fh, line)) {
        auto contents = Pelican::trim_view(line);
        if (contents.empty()) {continue;}
        if (contents[0] == '#') {continue;}
        token = contents;
        return;
    }
    ASSERT_FALSE(fh.fail());
    FAIL() << "No token found in file " << fname;
}

void
CurlCopyFixture::SetUp()
{
    std::call_once(m_init, [&] {
        ASSERT_EQ(curl_global_init(CURL_GLOBAL_DEFAULT), 0);
        char *env_file = getenv("ENV_FILE");

        ASSERT_NE(env_file, nullptr) << "$ENV_FILE environment variable "
                                        "not set; required to run test; this variable is set "
                                        "automatically when test is run via `ctest`.";
        parseEnvFile(env_file);
        m_factory.reset(new Pelican::PelicanFactory());
        m_initialized = true;
    });
    ASSERT_TRUE(m_initialized) << "Environment initialization failed";
}

void
CurlCopyFixture::WritePattern(const std::string &name, const off_t writeSize,
                                          const unsigned char chunkByte, const size_t chunkSize)
{
    XrdCl::File fh;

    auto url = name + "?authz=" + GetWriteToken();
    auto rv = fh.Open(url, XrdCl::OpenFlags::Write, XrdCl::Access::Mode(0755), static_cast<Pelican::File::timeout_t>(0));
    ASSERT_TRUE(rv.IsOK()) << "Failed to open " << name << " for write: " << rv.ToString();

    size_t sizeToWrite = (static_cast<off_t>(chunkSize) >= writeSize)
                                                        ? static_cast<size_t>(writeSize)
                                                        : chunkSize;
    off_t curWriteSize = writeSize;
    auto curChunkByte = chunkByte;
    off_t offset = 0;
    while (sizeToWrite) {
        std::string writeBuffer(sizeToWrite, curChunkByte);

        rv = fh.Write(offset, sizeToWrite, writeBuffer.data(), static_cast<Pelican::File::timeout_t>(0));
        ASSERT_TRUE(rv.IsOK()) << "Failed to write " << name << ": " << rv.ToString();
        
        curWriteSize -= sizeToWrite;
        offset += sizeToWrite;
        sizeToWrite = (static_cast<off_t>(chunkSize) >= curWriteSize)
                                            ? static_cast<size_t>(curWriteSize)
                                            : chunkSize;
        curChunkByte += 1;
    }

    rv = fh.Close();
    ASSERT_TRUE(rv.IsOK());

    VerifyContents(name, writeSize, chunkByte, chunkSize);
}

void
CurlCopyFixture::VerifyContents(const std::string &obj,
                                off_t expectedSize, unsigned char chunkByte,
                                size_t chunkSize) {
    XrdCl::File fh;

    auto url = obj + "?authz=" + GetReadToken();
    auto rv = fh.Open(url, XrdCl::OpenFlags::Read, XrdCl::Access::Mode(0755), static_cast<Pelican::File::timeout_t>(0));
    ASSERT_TRUE(rv.IsOK());
        
    size_t sizeToRead = (static_cast<off_t>(chunkSize) >= expectedSize)
                                                    ? expectedSize
                                                    : chunkSize;
    unsigned char curChunkByte = chunkByte;
    off_t offset = 0;
    while (sizeToRead) {
        std::string readBuffer(sizeToRead, curChunkByte - 1);
        uint32_t bytesRead;
        rv = fh.Read(offset, sizeToRead, readBuffer.data(), bytesRead, static_cast<Pelican::File::timeout_t>(0));
        ASSERT_TRUE(rv.IsOK());
        ASSERT_EQ(bytesRead, sizeToRead);
        readBuffer.resize(sizeToRead);

        std::string correctBuffer(sizeToRead, curChunkByte);
        ASSERT_EQ(readBuffer, correctBuffer);

        expectedSize -= sizeToRead;
        offset += sizeToRead;
        sizeToRead = (static_cast<off_t>(chunkSize) >= expectedSize)
                                            ? expectedSize
                                            : chunkSize;
        curChunkByte += 1;
    }

    rv = fh.Close();
    ASSERT_TRUE(rv.IsOK());
}

void
CurlCopyFixture::parseEnvFile(const std::string &fname) {
    std::ifstream fh(fname);
    if (!fh.is_open()) {
        std::cerr << "Failed to open env file: " << strerror(errno);
        exit(1);
    }
    std::string line;
    while (std::getline(fh, line)) {
        auto idx = line.find("=");
        if (idx == std::string::npos) {
            continue;
        }
        auto key = line.substr(0, idx);
        auto val = line.substr(idx + 1);
        if (key == "X509_CA_FILE") {
            m_ca_file = val;
            setenv("X509_CERT_FILE", m_ca_file.c_str(), 1);
        } else if (key == "ORIGIN_URL") {
            m_origin_url = val;
        } else if (key == "WRITE_TOKEN") {
            m_write_token_location = val;
            ReadTokenFromFile(m_write_token_location, m_write_token);
        } else if (key == "READ_TOKEN") {
            m_read_token_location = val;
            ReadTokenFromFile(m_read_token_location, m_read_token);
        } else if (key == "XRD_PLUGINCONFDIR") {
            setenv("XRD_PLUGINCONFDIR", val.c_str(), 1);
        }
    }
}

TEST_F(CurlCopyFixture, Test)
{
    auto source_url = GetOriginURL() + "/test/source_file";
    WritePattern(source_url, 2*1024, 'a', 1023);

    auto dest_url = GetOriginURL() + "/test/dest_file";
    Pelican::CurlCopyOp::Headers source_headers;
    source_headers.emplace_back("Authorization", "Bearer " + GetReadToken());
    Pelican::CurlCopyOp::Headers dest_headers;
    dest_headers.emplace_back("Authorization", "Bearer " + GetWriteToken());
    SyncResponseHandler srh;
    auto logger = XrdCl::DefaultEnv::GetLog();
    std::unique_ptr<Pelican::CurlCopyOp> op(new Pelican::CurlCopyOp(&srh, source_url, source_headers, dest_url, dest_headers, {10, 0}, logger));
    m_factory->Produce(std::move(op));
    srh.Wait();
    auto status = srh.Status();
    ASSERT_TRUE(status->IsOK()) << "Copy command failed with error: " << status->ToString();

    VerifyContents(dest_url, 2*1024, 'a', 1023);
}
