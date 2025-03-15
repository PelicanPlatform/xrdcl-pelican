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

#include <XrdCl/XrdClLog.hh>
#include <XrdCl/XrdClXRootDResponses.hh>

#include <iomanip>
#include <sstream>

using namespace Pelican;

CurlChecksumOp::CurlChecksumOp(XrdCl::ResponseHandler *handler, const std::string &url, ChecksumCache::ChecksumType preferred,
    bool is_pelican, bool is_origin, struct timespec timeout, XrdCl::Log *logger, const DirectorCache *dcache)
:
    // note we set is_origin to false (triggers a HEAD) and is_pelican to false (does not switch to PROPFIND on redirect)
    CurlStatOp(handler, url, timeout, logger, is_pelican, is_origin, dcache),
    m_preferred_cksum(preferred),
    m_header_list(nullptr, &curl_slist_free_all)
{}

void
CurlChecksumOp::Setup(CURL *curl, CurlWorker &worker)
{
    CurlStatOp::Setup(curl, worker);
    // When we are talking directly to a Pelican origin, force a HEAD.
    // Otherwise, we'll do whatever the default stat op does.
    if (IsPelican() && IsOrigin()) {
        curl_easy_setopt(m_curl.get(), CURLOPT_NOBODY, 1L);
        curl_easy_setopt(m_curl.get(), CURLOPT_CUSTOMREQUEST, nullptr);
    }

    std::string digest_header = "Want-Digest: " + HeaderParser::ChecksumTypeToDigestName(m_preferred_cksum);
    m_header_list.reset(curl_slist_append(m_header_list.release(), digest_header.c_str()));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, m_header_list.get());
}

bool
CurlChecksumOp::Redirect()
{
    auto result = CurlOperation::Redirect();
    curl_easy_setopt(m_curl.get(), CURLOPT_NOBODY, 1L);
    return result;
}

void
CurlChecksumOp::ReleaseHandle()
{
    CurlStatOp::ReleaseHandle();
    m_header_list.reset();

    if (m_curl == nullptr) return;
    curl_easy_setopt(m_curl.get(), CURLOPT_HTTPHEADER, nullptr);
}

void
CurlChecksumOp::Success()
{
    SetDone();
    auto checksums = m_headers.GetChecksums();

    ChecksumCache::Instance().Put(m_url, checksums, std::chrono::steady_clock::now());

    std::array<unsigned char, ChecksumCache::g_max_checksum_length> value;
    auto type = ChecksumCache::kUnknown; 
    if (checksums.IsSet(m_preferred_cksum)) {
        value = checksums.Get(m_preferred_cksum);
        type = m_preferred_cksum;
    } else {
        bool isset;
        std::tie(type, value, isset) = checksums.GetFirst();
        if (!isset) {
            m_logger->Error(kLogXrdClPelican, "Checksums not found in response for %s", m_url.c_str());
            m_handler->HandleResponse(new XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errCheckSumError), nullptr);
            return; 
        }
    }
    std::stringstream ss;
    for (size_t idx = 0; idx < ChecksumCache::GetChecksumLength(type); ++idx) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(value[idx]);
    }

    std::string response = ChecksumCache::GetTypeString(type) + " " + ss.str();
    auto buf = new XrdCl::Buffer();
    buf->FromString(response);
    
    auto obj = new XrdCl::AnyObject();
    obj->Set(buf);

    m_handler->HandleResponse(new XrdCl::XRootDStatus(), obj);
    m_handler = nullptr;
    // Does not call CurlStatOp::Success() as we don't need to invoke a stat info callback
}
