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

#include "XrdClCurl/CurlFactory.hh"
#include "XrdClCurl/CurlFile.hh"
#include "XrdClCurl/CurlUtil.hh"
#include "XrdClCurl/CurlWorker.hh"
#include "XrdClPelican/PelicanFactory.hh"
#include "XrdClPelican/PelicanFilesystem.hh"
#include "TransferTest.hh"

#include <XrdCl/XrdClDefaultEnv.hh>
#include <XrdCl/XrdClLog.hh>

#include <gtest/gtest.h>

class CurlCopyFixture : public TransferFixture {};

TEST_F(CurlCopyFixture, Test)
{
    auto source_url = GetOriginURL() + "/test/source_file";
    WritePattern(source_url, 2*1024, 'a', 1023);

    auto dest_url = GetOriginURL() + "/test/dest_file";
    XrdClCurl::CurlCopyOp::Headers source_headers;
    source_headers.emplace_back("Authorization", "Bearer " + GetReadToken());
    XrdClCurl::CurlCopyOp::Headers dest_headers;
    dest_headers.emplace_back("Authorization", "Bearer " + GetWriteToken());
    SyncResponseHandler srh;
    auto logger = XrdCl::DefaultEnv::GetLog();
    logger->Debug(Pelican::kLogXrdClPelican, "About to start copy operation");
    std::unique_ptr<XrdClCurl::CurlCopyOp> op(new XrdClCurl::CurlCopyOp(&srh, source_url, source_headers, dest_url, dest_headers, {10, 0}, logger));
    m_factory->Produce(std::move(op));
    logger->Debug(Pelican::kLogXrdClPelican, "Will wait on copy operation");
    srh.Wait();
    logger->Debug(Pelican::kLogXrdClPelican, "Copy operation complete");
    auto [status, obj] = srh.Status();
    ASSERT_TRUE(status->IsOK()) << "Copy command failed with error: " << status->ToString();

    VerifyContents(dest_url, 2*1024, 'a', 1023);
}
