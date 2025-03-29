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

#include "TransferTest.hh"

#include "CurlUtil.hh"
#include "PelicanFactory.hh"
#include "PelicanFile.hh"

#include <curl/curl.h>
#include <XrdCl/XrdClDefaultEnv.hh>

#include <fstream>

std::once_flag TransferFixture::m_init;
bool TransferFixture::m_initialized = false;
std::string TransferFixture::m_read_token_location;
std::string TransferFixture::m_read_token;
std::string TransferFixture::m_write_token_location;
std::string TransferFixture::m_write_token;
std::string TransferFixture::m_ca_file;
std::unique_ptr<Pelican::PelicanFactory> TransferFixture::m_factory;

TransferFixture::TransferFixture()
      : m_log(XrdCl::DefaultEnv::GetLog())
    {}

void TransferFixture::SetUp() {
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
TransferFixture::WritePattern(const std::string &name, const off_t writeSize,
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
TransferFixture::VerifyContents(const std::string &obj,
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
TransferFixture::ReadTokenFromFile(const std::string &fname, std::string &token)
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
TransferFixture::parseEnvFile(const std::string &fname) {
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

void
TransferFixture::SyncResponseHandler::HandleResponse( XrdCl::XRootDStatus *status, XrdCl::AnyObject *response ) {
    std::unique_lock lock(m_mutex);
    m_status.reset(status);
    m_obj.reset(response);
    m_cv.notify_one();
}

void
TransferFixture::SyncResponseHandler::Wait() {
    std::unique_lock lock(m_mutex);
    m_cv.wait(lock, [&]{return m_status.get() != nullptr;});
}

std::tuple<std::unique_ptr<XrdCl::XRootDStatus>, std::unique_ptr<XrdCl::AnyObject>>
TransferFixture::SyncResponseHandler::Status() {
    return std::make_tuple(std::move(m_status), std::move(m_obj));
}
