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

#include "CurlFile.hh"
#include "CurlOps.hh"

#include <XrdCl/XrdClLog.hh>
#include "../common/CurlResponseInfo.hh"
#include "../common/CurlResponses.hh"

using namespace XrdClCurl;

CurlOpenOp::CurlOpenOp(XrdCl::ResponseHandler *handler, const std::string &url, struct timespec timeout,
    XrdCl::Log *logger, XrdClCurl::File *file, bool response_info, CreateConnCalloutType callout)
:
    CurlStatOp(handler, url, timeout, logger, response_info, callout),
    m_file(file)
{}

void
CurlOpenOp::ReleaseHandle()
{
    curl_easy_setopt(m_curl.get(), CURLOPT_OPENSOCKETFUNCTION, nullptr);
    curl_easy_setopt(m_curl.get(), CURLOPT_OPENSOCKETDATA, nullptr);
    curl_easy_setopt(m_curl.get(), CURLOPT_SOCKOPTFUNCTION, nullptr);
    curl_easy_setopt(m_curl.get(), CURLOPT_SOCKOPTDATA, nullptr);
    CurlStatOp::ReleaseHandle();
}

void
CurlOpenOp::SetOpenProperties(bool setSize)
{
    char *url = nullptr;
    curl_easy_getinfo(m_curl.get(), CURLINFO_EFFECTIVE_URL, &url);
    if (url && m_file) {
        m_file->SetProperty("LastURL", url);
    }

    if (setSize) {
        auto [size, isdir] = GetStatInfo();
        if (!isdir && size >= 0) {
            m_file->SetProperty("XrdClCurlPrefetchSize", std::to_string(size));
        }
    }

    if (!m_headers.GetETag().empty())
    {
        std::string etag = m_headers.GetETag();
        m_file->SetProperty("ETag", etag);
    }
    m_file->SetProperty("Cache-Control", m_headers.GetCacheControl());
}

void
CurlOpenOp::Success()
{
    SetDone(false);
    SetOpenProperties(true);
    auto [size, isdir] = GetStatInfo();
    if (isdir) {
        m_logger->Error(kLogXrdClCurl, "Cannot open a directory");
        Fail(XrdCl::errErrorResponse, kXR_isDirectory, "Cannot open a directory");
        return;
    }
    if (size >= 0) {
        m_file->SetProperty("ContentLength", std::to_string(size));
    }
    SuccessImpl(false);
}

void
CurlOpenOp::Fail(uint16_t errCode, uint32_t errNum, const std::string &msg)
{
    // Note: OpenFlags::New is equivalent to O_CREAT | O_EXCL; OpenFlags::Write is equivalent to O_WRONLY | O_CREAT;
    // OpenFlags::Delete is equivalent to O_CREAT | O_TRUNC;
    if (errCode == XrdCl::errErrorResponse &&  errNum == kXR_NotFound && (m_file->Flags() & (XrdCl::OpenFlags::New | XrdCl::OpenFlags::Write | XrdCl::OpenFlags::Delete))) {
        m_logger->Debug(kLogXrdClCurl, "CurlOpenOp succeeds as 404 was expected");
        SetOpenProperties(false);
        SuccessImpl(false);
        m_file->SetProperty("ContentLength", "0");
        return;
    }
    CurlOperation::Fail(errCode, errNum, msg);
}
