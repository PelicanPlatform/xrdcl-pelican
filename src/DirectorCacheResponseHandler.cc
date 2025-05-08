/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

#include "CurlResponses.hh"
#include "DirectorCache.hh"
#include "DirectorCacheResponseHandler.hh"
#include "PelicanFilesystem.hh"
#include "PelicanHeaders.hh"

#include <XrdCl/XrdClLog.hh>
#include <XrdCl/XrdClXRootDResponses.hh>

using namespace Pelican;

template<class ResponseObj, class ResponseInfoObj>
void DirectorCacheResponseHandler<ResponseObj, ResponseInfoObj>::HandleResponse(
    XrdCl::XRootDStatus *status, XrdCl::AnyObject *response)
{
    // Delete the handler; since we're injecting results (hopefully) into a global
    // cache, no one owns our object
    std::unique_ptr<DirectorCacheResponseHandler<ResponseObj, ResponseInfoObj>> owner(this);

    ResponseObj *dlist{nullptr};
    if (!response) {
        if (m_handler) m_handler->HandleResponse(status, response);
        return;
    }
    response->Get(dlist);
    if (dlist == nullptr) {
        if (m_handler) m_handler->HandleResponse(status, response);
        else delete response;
        return;
    }
    
    auto dlist_resp = reinterpret_cast<ResponseInfoObj*>(dlist);
    auto info = dlist_resp->GetResponseInfo();
    auto &responses = info->GetHeaderResponse();
    if (!responses.empty() && m_dcache) {
        auto &headers = responses[0];
        auto iter = headers.find("Link");
        if (iter != headers.end() && !iter->second.empty()) {
            auto &value = iter->second[0];
            auto [entries, ok] = LinkEntry::FromHeaderValue(value);
            if (ok && !entries.empty()) {
                m_dcache->Put(entries[0].GetLink(), entries[0].GetDepth());
            }
        }
    }

    if (m_handler) {
        m_handler->HandleResponse(status, response);
    } else {
        delete response;
    }
}

template class Pelican::DirectorCacheResponseHandler<XrdCl::DirectoryList, XrdClCurl::DirectoryListResponse>;
template class Pelican::DirectorCacheResponseHandler<XrdCl::StatInfo, XrdClCurl::StatResponse>;
template class Pelican::DirectorCacheResponseHandler<XrdClCurl::OpenResponseInfo, XrdClCurl::OpenResponseInfo>;
