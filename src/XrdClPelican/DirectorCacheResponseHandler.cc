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

#include "../common/XrdClCurlResponses.hh"
#include "DirectorCache.hh"
#include "DirectorCacheResponseHandler.hh"
#include "PelicanFilesystem.hh"
#include "PelicanHeaders.hh"

#include <XrdCl/XrdClLog.hh>
#include <XrdCl/XrdClXRootDResponses.hh>

using namespace Pelican;

template<class ResponseObj, class ResponseInfoObj>
void DirectorCacheResponseHandler<ResponseObj, ResponseInfoObj>::HandleResponse(
    XrdCl::XRootDStatus *status_raw, XrdCl::AnyObject *response_raw)
{
    // Delete the handler; since we're injecting results (hopefully) into a global
    // cache, no one owns our object
    std::unique_ptr<DirectorCacheResponseHandler<ResponseObj, ResponseInfoObj>> owner(this);
    std::unique_ptr<XrdCl::XRootDStatus> status(status_raw);
    std::unique_ptr<XrdCl::AnyObject> response(response_raw);

    ResponseObj *dlist{nullptr};
    if (!response) {
        if (m_handler) m_handler->HandleResponse(status.release(), response.release());
        return;
    }
    response->Get(dlist);
    if (dlist == nullptr) {
        if (m_handler) m_handler->HandleResponse(status.release(), response.release());
        return;
    }
    
    auto dlist_resp = reinterpret_cast<ResponseInfoObj*>(dlist);
    auto info = dlist_resp->GetResponseInfo();
    auto &responses = info->GetHeaderResponse();
    auto now = std::chrono::steady_clock::now();
    if (!responses.empty() && m_dcache) {
        auto &headers = responses[0];
        auto iter = headers.find("Link");
        if (iter != headers.end() && !iter->second.empty()) {
            auto &value = iter->second[0];
            auto [entries, ok] = LinkEntry::FromHeaderValue(value);
            if (ok && !entries.empty()) {
                m_dcache->Put(entries[0].GetLink(), entries[0].GetDepth(), now);
            }
        }
    }
    if (!responses.empty()) {
        auto &headers = responses[0];
        auto iter = headers.find("Location");
        if (iter != headers.end() && !iter->second.empty()) {
            auto &location = iter->second[0];
            auto iter = headers.find("X-Pelican-Broker");
            if (iter != headers.end() && !iter->second.empty()) {
                auto &value = iter->second[0];
                m_bcache.Put(location, value, now);
            }
        }
    }

    if (std::is_same<ResponseObj, XrdClCurl::OpenResponseInfo>::value) {
        if (m_handler) m_handler->HandleResponse(status.release(), nullptr);
    } else if (std::is_same<ResponseObj, XrdCl::DirectoryList>::value && m_handler) {
        // While XrdCl::DirectoryList has a move constructor, it doesn't function.  This
        // is a simple implementation.
        auto new_dlist = new XrdCl::DirectoryList();
        XrdCl::DirectoryList *dl = reinterpret_cast<XrdCl::DirectoryList*>(dlist);
        for (uint32_t idx = 0; idx < dl->GetSize(); idx++) {
            const auto li = dl->At(idx);
            auto new_si = new XrdCl::StatInfo(*li->GetStatInfo());
            auto new_li = new XrdCl::DirectoryList::ListEntry(li->GetHostAddress(), li->GetName(), new_si);
            new_dlist->Add(new_li);
        }
        XrdCl::AnyObject *new_response(new XrdCl::AnyObject());
        new_response->Set(new_dlist);
        m_handler->HandleResponse(status.release(), new_response);
    } else if (m_handler) {
        XrdCl::AnyObject *new_response(new XrdCl::AnyObject());
        ResponseObj *new_obj(new ResponseObj(std::move(*dlist_resp)));
        new_response->Set(new_obj);
        m_handler->HandleResponse(status.release(), new_response);
    }
    delete dlist_resp;
    dlist = nullptr;
    response->Set(dlist);
}

template class Pelican::DirectorCacheResponseHandler<XrdCl::DirectoryList, XrdClCurl::DirectoryListResponse>;
template class Pelican::DirectorCacheResponseHandler<XrdCl::StatInfo, XrdClCurl::StatResponse>;
template class Pelican::DirectorCacheResponseHandler<XrdClCurl::OpenResponseInfo, XrdClCurl::OpenResponseInfo>;
