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

#include <tinyxml2.h>

using namespace Pelican;

bool CurlListdirOp::ParseProp(DavEntry &entry, tinyxml2::XMLElement *prop)
{
    for (auto child = prop->FirstChildElement(); child != nullptr; child = child->NextSiblingElement()) {
        if (!strcmp(child->Name(), "D:resourcetype") || !strcmp(child->Name(), "lp1:resourcetype")) {
            auto collection = child->FirstChildElement("D:collection");
            entry.m_isdir = collection != nullptr;
        } else if (!strcmp(child->Name(), "D:getcontentlength") || !strcmp(child->Name(), "lp1:getcontentlength")) {
            auto size = child->GetText();
            if (size == nullptr) {
                return false;
            }
            try {
                entry.m_size = std::stoll(size);
            } catch (std::invalid_argument &e) {
                return false;
            }
        } else if (!strcmp(child->Name(), "D:getlastmodified") || !strcmp(child->Name(), "lp1:getlastmodified")) {
            auto lastmod = child->GetText();
            if (lastmod == nullptr) {
                return false;
            }
            struct tm tm;
            if (strptime(lastmod, "%a, %d %b %Y %H:%M:%S %Z", &tm) == nullptr) {
                return false;
            }
            entry.m_lastmodified = mktime(&tm);
        } else if (strcmp(child->Name(), "D:href") == 0) {
            auto href = child->GetText();
            if (href == nullptr) {
                return false;
            }
            entry.m_name = href;
        } else if (!strcmp(child->Name(), "D:executable") || !strcmp(child->Name(), "lp1:executable")) {
            auto val = child->GetText();
            if (val == nullptr) {
                return false;
            }
            if (strcmp(val, "T") == 0) {
                entry.m_isexec = true;
            }
        }
    }
    return true;    
}

std::pair<CurlListdirOp::DavEntry, bool>
CurlListdirOp::ParseResponse(tinyxml2::XMLElement *response)
{
    DavEntry entry;
    bool success = false;
    for (auto child = response->FirstChildElement(); child != nullptr; child = child->NextSiblingElement()) {
        if (!strcmp(child->Name(), "D:href")) {
            auto href = child->GetText();
            if (href == nullptr) {
                return {entry, false};
            }
            // NOTE: This is not particularly robust; it assumes that the server is only returning
            // a depth of exactly one and is not using a trailing slash to indicate a directory.
            std::string_view href_str(href);
            auto last_slash = href_str.find_last_of('/');
            if (last_slash != std::string_view::npos) {
                entry.m_name = href_str.substr(last_slash + 1);
            } else {
                entry.m_name = href;
            }
            continue;
        }
        if (strcmp(child->Name(), "D:propstat")) {
            continue;
        }
        for (auto propstat = child->FirstChildElement(); propstat != nullptr; propstat = propstat->NextSiblingElement()) {
            if (strcmp(propstat->Name(), "D:prop")) {
                continue;
            }
            success = ParseProp(entry, propstat);
            if (!success) {
                return {entry, success};
            }
        }
    }
    return {entry, success};
}

void
CurlListdirOp::Success()
{
    SetDone();
    m_logger->Debug(kLogXrdClPelican, "CurlListdirOp::Success");

    std::unique_ptr<XrdCl::DirectoryList> dirlist(new XrdCl::DirectoryList());

    tinyxml2::XMLDocument doc;
    auto err = doc.Parse(m_response.c_str());
    if (err != tinyxml2::XML_SUCCESS) {
        m_logger->Error(kLogXrdClPelican, "Failed to parse XML response: %s", m_response.substr(0, 1024).c_str());
        Fail(XrdCl::errErrorResponse, kXR_FSError, "Server responded to directory listing with invalid XML");
        return;
    }

    auto elem = doc.RootElement();
    if (strcmp(elem->Name(), "D:multistatus")) {
        m_logger->Error(kLogXrdClPelican, "Unexpected XML response: %s", m_response.substr(0, 1024).c_str());
        Fail(XrdCl::errErrorResponse, kXR_FSError, "Server responded to directory listing unexpected XML root");
        return;
    }
    bool skip = true;
    for (auto response = elem->FirstChildElement(); response != nullptr; response = response->NextSiblingElement()) {
        if (strcmp(response->Name(), "D:response")) {
            continue;
        }

        auto [entry, success] = ParseResponse(response);
        if (!success) {
            m_logger->Error(kLogXrdClPelican, "Failed to parse response element in XML response: %s", m_response.substr(0, 1024).c_str());
            Fail(XrdCl::errErrorResponse, kXR_FSError, "Server responded with invalid directory listing");
            return;
        }
        // Skip the first entry in the response, which is the directory itself
        if (skip) {
            skip = false;
        } else {
            uint32_t flags = XrdCl::StatInfo::Flags::IsReadable;
            if (entry.m_isdir) {
                flags |= XrdCl::StatInfo::Flags::IsDir;
            }
            if (entry.m_isexec) {
                flags |= XrdCl::StatInfo::Flags::XBitSet;
            }
            dirlist->Add(new XrdCl::DirectoryList::ListEntry(m_host_addr, entry.m_name, new XrdCl::StatInfo("nobody", entry.m_size, flags, entry.m_lastmodified)));
        }
    }

    m_logger->Debug(kLogXrdClPelican, "Successful propfind directory listing operation on %s (%u items)", m_url.c_str(), static_cast<unsigned>(dirlist->GetSize()));
    if (m_handler == nullptr) {return;}
    auto obj = new XrdCl::AnyObject();
    obj->Set(dirlist.release());

    m_handler->HandleResponse(new XrdCl::XRootDStatus(), obj);
    m_handler = nullptr;
}
