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

#include "ChecksumCache.hh"
#include "CurlResponses.hh"
#include "DirectorCache.hh"
#include "DirectorCacheResponseHandler.hh"
#include "FedInfo.hh"
#include "ParseTimeout.hh"
#include "PelicanFile.hh"
#include "PelicanHeaders.hh"
#include "PelicanFilesystem.hh"

#include <chrono>
#include <iomanip>
#include <sstream>

using namespace Pelican;

namespace {

class ChecksumResponseHandler : public XrdCl::ResponseHandler {
public:
    ChecksumResponseHandler(ChecksumCache &cache, XrdCl::ResponseHandler *handler, XrdCl::Log &log, const std::string &url)
        : m_cache(cache),
        m_handler(handler),
        m_log(log),
        m_url(url)
    {}

    virtual void HandleResponse(XrdCl::XRootDStatus *status, XrdCl::AnyObject *response) {
        // Delete the handler; since we're injecting results (hopefully) into a global
        // cache, no one owns our object
        std::unique_ptr<ChecksumResponseHandler> owner(this);
        std::unique_ptr<XrdCl::AnyObject> response_owner;

        XrdCl::Buffer *buf{nullptr};
        if (!response) {
            if (m_handler) m_handler->HandleResponse(status, response);
            return;
        }
        response->Get(buf);
        if (buf == nullptr) {
            if (m_handler) m_handler->HandleResponse(status, response);
            else delete response;
            return;
        }
        auto dlist_resp = reinterpret_cast<XrdClCurl::QueryResponse*>(buf);
        auto info = dlist_resp->GetResponseInfo();
        auto &responses = info->GetHeaderResponse();
        if (!responses.empty()) {
            auto &headers = responses[0];
            auto iter = headers.find("Digest");
            if (iter != headers.end()) {
                for (const auto &value : iter->second) {
                    XrdClCurl::ChecksumInfo info;
                    ParseDigest(value, info);
                    auto [type, val, ok] = info.GetFirst();
                    if (ok) {
                        m_cache.Put(m_url, info);
                    }
                }
            }
        }

        if (m_handler) m_handler->HandleResponse(status, response);
        else delete response;
    }

private:
    ChecksumCache &m_cache;

    // A reference to the handler we are wrapping.  Note we don't own the handler
    // so this is not a unique_ptr.
    XrdCl::ResponseHandler *m_handler;

    XrdCl::Log &m_log;
    const std::string m_url;
};

} // namespace

Filesystem::Filesystem(const std::string &url, XrdCl::Log *log) :
    m_logger(log),
    m_url(url)
{
    m_logger->Debug(kLogXrdClPelican, "Pelican filesystem constructed with URL: %s.",
        url.c_str());
}

// Resolve the full URL for a given path, including any director cache lookups.
//
// - oper: the operation being performed (e.g., "stat"); used only for log messages
// - path: the path for the URL resource
// - timeout: the timeout for the operation
// - full_url: the output URL
// - https_fs: the XrdCl::FileSystem object representing the filesystem (output)
// - dcache: A reference to the director cache object used to lookup the http_fs.
// - return: the status of the operation (possibly indicating failure)
XrdCl::XRootDStatus
Filesystem::ConstructURL(const std::string &oper, const std::string &path, timeout_t timeout, std::string &full_url, XrdCl::FileSystem *&http_fs, const DirectorCache *&dcache, struct timespec &ts)
{
    full_url = m_url.GetProtocol() + "://" +
                           m_url.GetHostName() + ":" +
                           std::to_string(m_url.GetPort()) +
                           "/" + path;
    
    auto pelican_url = XrdCl::URL();
    pelican_url.SetPort(0);
    if (!pelican_url.FromString(full_url)) {
        m_logger->Error(kLogXrdClPelican, "Failed to parse pelican:// URL as a valid URL: %s", full_url.c_str());
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidArgs);
    }
    if (pelican_url.GetProtocol() != "pelican") {
        m_logger->Error(kLogXrdClPelican, "Pelican filesystem invoked with non-pelican:// URL: %s", full_url.c_str());
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidArgs);
    }
    auto pm = pelican_url.GetParams();
    const auto iter = pm.find("pelican.timeout");
    std::string header_timeout = iter == pm.end() ? "" : iter->second;
    ts = GetHeaderTimeout(timeout, header_timeout);
    pm["pelican.timeout"] = XrdClCurl::MarshalDuration(ts);
    pelican_url.SetParams(pm);

    dcache = nullptr;

    auto &factory = FederationFactory::GetInstance(*m_logger, File::GetFederationMetadataTimeout());
    std::string err;
    std::stringstream ss;
    ss << pelican_url.GetHostName() << ":" << pelican_url.GetPort();

    dcache = &DirectorCache::GetCache(ss.str());

    if ((full_url = dcache->Get(full_url.c_str())).empty()) {
        auto info = factory.GetInfo(ss.str(), err);
        if (!info) {
            m_logger->Debug(kLogXrdClPelican, "Factory did not return URL.");
            return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidAddr, 0, err);
        }
        if (!info->IsValid()) {
            m_logger->Debug(kLogXrdClPelican, "Factory did not return valid URL.");
            return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidAddr, 0, "Failed to look up pelican metadata: " + err);
        }
        full_url = info->GetDirector() + "/api/v1.0/director/origin/" + pelican_url.GetPathWithParams();
    } else {
        m_logger->Debug(kLogXrdClPelican, "Using cached origin URL %s for %s", full_url.c_str(), oper.c_str());
    }

    XrdCl::URL endpoint_url;
    if (!endpoint_url.FromString(full_url)) {
        m_logger->Error(kLogXrdClPelican, "Failed to parse endpoint URL as a valid URL: %s", full_url.c_str());
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errInvalidArgs);
    }

    auto fs_key = std::string(endpoint_url.GetHostName()) + ":" + std::to_string(endpoint_url.GetPort());
    auto iter2 = m_url_map.find(fs_key);
    if (iter2 == m_url_map.end()) {
        m_logger->Debug(kLogXrdClPelican, "Creating HTTPS filesystem at https://%s from %s", fs_key.c_str(), full_url.c_str());
        auto new_fs = std::make_unique<XrdCl::FileSystem>(XrdCl::URL("https://" + fs_key));
        http_fs = new_fs.get();
        http_fs->SetProperty(ResponseInfoProperty, "true");
        m_url_map.insert(iter2, {fs_key, std::move(new_fs)});
    } else {
        http_fs = iter2->second.get();
    }

    return XrdCl::XRootDStatus();
}

XrdCl::XRootDStatus
Filesystem::Stat(const std::string      &path,
                 XrdCl::ResponseHandler *handler,
                 timeout_t               timeout)
{
    const DirectorCache *dcache{nullptr};
    std::string full_url;
    XrdCl::FileSystem *http_fs{nullptr};
    struct timespec ts;
    auto st = ConstructURL("stat", path, timeout, full_url, http_fs, dcache, ts);
    if (!st.IsOK()) {
        return st;
    }

    handler = new DirectorCacheResponseHandler<XrdCl::StatInfo, XrdClCurl::StatResponse>(dcache, *m_logger, handler);

    m_logger->Debug(kLogXrdClPelican, "Filesystem::Stat path %s", full_url.c_str());
    return http_fs->Stat(path, handler, ts.tv_sec);
}

struct timespec
Filesystem::GetHeaderTimeout(time_t oper_timeout, const std::string &header_value)
{
    auto ts = File::ParseHeaderTimeout(header_value, m_logger);

    return File::GetHeaderTimeoutWithDefault(oper_timeout, ts);
}

XrdCl::XRootDStatus
Filesystem::DirList(const std::string          &path,
                    XrdCl::DirListFlags::Flags  flags,
                    XrdCl::ResponseHandler     *handler,
                    timeout_t                   timeout )
{
    const DirectorCache *dcache{nullptr};
    XrdCl::FileSystem *http_fs{nullptr};
    std::string full_url;
    struct timespec ts;
    auto st = ConstructURL("stat", path, timeout, full_url, http_fs, dcache, ts);
    if (!st.IsOK()) {
        return st;
    }

    m_logger->Debug(kLogXrdClPelican, "Filesystem::DirList path %s", full_url.c_str());
    auto new_handler = std::make_unique<DirectorCacheResponseHandler<XrdCl::DirectoryList, XrdClCurl::DirectoryListResponse>>(dcache, *m_logger, handler);

    return http_fs->DirList(full_url, flags, new_handler.release(), ts.tv_sec);
}

bool
Filesystem::GetProperty(const std::string &name,
                        std::string       &value) const
{
    const auto p = m_properties.find(name);
    if (p == std::end(m_properties)) {
        return false;
    }

    value = p->second;
    return true;
}

XrdCl::XRootDStatus
Filesystem::Query( XrdCl::QueryCode::Code  queryCode,
                   const XrdCl::Buffer     &arg,
                   XrdCl::ResponseHandler  *handler,
                   timeout_t                timeout )
{
    if (queryCode != XrdCl::QueryCode::Checksum) {
        return XrdCl::XRootDStatus(XrdCl::stError, XrdCl::errNotImplemented);
    }
    auto path = arg.ToString();
    m_logger->Debug(kLogXrdClPelican, "Filesystem::Query checksum path %s", path.c_str());

    XrdClCurl::ChecksumType preferred = XrdClCurl::ChecksumType::kCRC32C;
    XrdCl::URL url_obj;
    url_obj.FromString(path);
    auto iter = url_obj.GetParams().find("cks.type");
    if (iter != url_obj.GetParams().end()) {
        preferred = XrdClCurl::GetTypeFromString(iter->second);
        if (preferred == XrdClCurl::ChecksumType::kUnknown) {
            m_logger->Error(kLogXrdClPelican, "Unknown checksum type %s", iter->second.c_str());
            preferred = XrdClCurl::ChecksumType::kCRC32C;
        }
    }
    std::string full_url;
    const DirectorCache *dcache{nullptr};
    XrdCl::FileSystem *http_fs{nullptr};
    struct timespec ts;
    auto st = ConstructURL("checksum", path, timeout, full_url, http_fs, dcache, ts);
    if (!st.IsOK()) {
        m_logger->Debug(kLogXrdClPelican, "Statis is failed");
        return st;
    }

    // First, check the cache for the known object
    XrdClCurl::ChecksumTypeBitmask mask;
    mask.Set(preferred);
    auto &cache = ChecksumCache::Instance();
    auto checksums = cache.Get(full_url, mask, std::chrono::steady_clock::now());
    if (checksums.IsSet(preferred)) {
        std::array<unsigned char, XrdClCurl::g_max_checksum_length> value = checksums.Get(preferred);
        std::stringstream ss;
        for (size_t idx = 0; idx < XrdClCurl::GetChecksumLength(preferred); ++idx) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(value[idx]);
        }
        std::string response = XrdClCurl::GetTypeString(preferred) + " " + ss.str();
        auto buf = new XrdCl::Buffer();
        buf->FromString(response);

        auto obj = new XrdCl::AnyObject();
        obj->Set(buf);

        handler->HandleResponse(new XrdCl::XRootDStatus(), obj);
        return XrdCl::XRootDStatus();
    }

    auto wrap1 = std::make_unique<ChecksumResponseHandler>(cache, handler, *m_logger, full_url);
    handler = new DirectorCacheResponseHandler<XrdCl::DirectoryList, XrdClCurl::DirectoryListResponse>(dcache, *m_logger, wrap1.release());

    return http_fs->Query(queryCode, arg, handler, ts.tv_sec);
}

bool
Filesystem::SetProperty(const std::string &name,
                        const std::string &value)
{
    m_properties[name] = value;
    return true;
}
