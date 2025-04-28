/***************************************************************
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

#include "CurlOps.hh"
#include "CurlUtil.hh"

#include <XrdCl/XrdClLog.hh>
#include <XrdCl/XrdClXRootDResponses.hh>

#include <iomanip>
#include <sstream>

using namespace XrdClCurl;

const std::string XrdClCurl::GetTypeString(ChecksumType ctype) {
    switch (ctype) {
        case ChecksumType::kCRC32C:
            return "crc32c";
        case ChecksumType::kMD5:
            return "md5";
        case ChecksumType::kSHA1:
            return "sha1";
        case ChecksumType::kSHA256:
            return "sha256";
        case ChecksumType::kUnknown:
            return "unknown";
    }
    return "unknown";
}

const size_t XrdClCurl::GetChecksumLength(ChecksumType ctype) {
    switch (ctype) {
        case ChecksumType::kCRC32C:
            return 4;
        case ChecksumType::kMD5:
            return 16;
        case ChecksumType::kSHA1:
            return 20;
        case ChecksumType::kSHA256:
            return 32;
        case ChecksumType::kUnknown:
            return 0;
    }
    return 0;
}

ChecksumType XrdClCurl::GetTypeFromString(const std::string &str) {
    if (str == "crc32c") {
        return ChecksumType::kCRC32C;
    } else if (str == "md5") {
        return ChecksumType::kMD5;
    } else if (str == "sha1") {
        return ChecksumType::kSHA1;
    } else if (str == "sha256") {
        return ChecksumType::kSHA256;
    }
    return ChecksumType::kUnknown;
}

CurlChecksumOp::CurlChecksumOp(XrdCl::ResponseHandler *handler, const std::string &url, XrdClCurl::ChecksumType preferred,
    bool is_pelican, bool is_origin, struct timespec timeout, XrdCl::Log *logger, const Pelican::DirectorCache *dcache)
:
    // note we set is_origin to false (triggers a HEAD) and is_pelican to false (does not switch to PROPFIND on redirect)
    CurlStatOp(handler, url, timeout, logger, is_origin, dcache),
    m_is_pelican(is_pelican),
    m_preferred_cksum(preferred),
    m_header_list(nullptr, &curl_slist_free_all)
{}

void
CurlChecksumOp::Setup(CURL *curl, CurlWorker &worker)
{
    CurlStatOp::Setup(curl, worker);
    curl_easy_setopt(m_curl.get(), CURLOPT_NOBODY, 1L);
    curl_easy_setopt(m_curl.get(), CURLOPT_CUSTOMREQUEST, nullptr);

    std::string digest_header = "Want-Digest: " + XrdClCurl::HeaderParser::ChecksumTypeToDigestName(m_preferred_cksum);
    m_header_list.reset(curl_slist_append(m_header_list.release(), digest_header.c_str()));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, m_header_list.get());
}

CurlOperation::RedirectAction
CurlChecksumOp::Redirect(std::string &target)
{
    auto result = CurlOperation::Redirect(target);
    curl_easy_setopt(m_curl.get(), CURLOPT_NOBODY, 1L);
    return result;
}

void
CurlChecksumOp::ReleaseHandle()
{
    if (m_curl == nullptr) return;
    curl_easy_setopt(m_curl.get(), CURLOPT_HTTPHEADER, nullptr);
    m_header_list.reset();

    CurlStatOp::ReleaseHandle();
}

void
CurlChecksumOp::Success()
{
    SetDone(false);
    auto checksums = m_headers.GetChecksums();

    if (m_is_pelican) {
        Pelican::ChecksumCache::Instance().Put(m_url, checksums, std::chrono::steady_clock::now());
    }

    std::array<unsigned char, XrdClCurl::g_max_checksum_length> value;
    auto type = XrdClCurl::ChecksumType::kUnknown;
    if (checksums.IsSet(m_preferred_cksum)) {
        value = checksums.Get(m_preferred_cksum);
        type = m_preferred_cksum;
    } else {
        bool isset;
        std::tie(type, value, isset) = checksums.GetFirst();
        if (!isset) {
            m_logger->Error(kLogXrdClCurl, "Checksums not found in response for %s", m_url.c_str());
            auto handle = m_handler;
            m_handler = nullptr;
            handle->HandleResponse(new XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errCheckSumError), nullptr);
            return; 
        }
    }
    std::stringstream ss;
    for (size_t idx = 0; idx < XrdClCurl::GetChecksumLength(type); ++idx) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(value[idx]);
    }

    std::string response = XrdClCurl::GetTypeString(type) + " " + ss.str();
    auto buf = new XrdCl::Buffer();
    buf->FromString(response);
    
    auto obj = new XrdCl::AnyObject();
    obj->Set(buf);

    auto handle = m_handler;
    m_handler = nullptr;
    handle->HandleResponse(new XrdCl::XRootDStatus(), obj);
    // Does not call CurlStatOp::Success() as we don't need to invoke a stat info callback
}
