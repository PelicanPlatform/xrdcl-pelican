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
#include "TransferTest.hh"

#include <XrdCl/XrdClDefaultEnv.hh>
#include <XrdCl/XrdClLog.hh>

#include <gtest/gtest.h>

#include <fstream>
#include <mutex>

class CurlCopyFixture : public TransferFixture {};

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
    auto [status, obj] = srh.Status();
    ASSERT_TRUE(status->IsOK()) << "Copy command failed with error: " << status->ToString();

    VerifyContents(dest_url, 2*1024, 'a', 1023);
}
