/****************************************************************
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

#include "FedInfo.hh"
#include "PelicanFilesystem.hh"

#include <nlohmann/json.hpp>
#include <curl/curl.h>
#include <XrdCl/XrdClDefaultEnv.hh>
#include <XrdCl/XrdClLog.hh>

#include <thread>
#include <unistd.h>

using namespace Pelican;

namespace {

// Simple debug function for getting information from libcurl; to enable, you need to
// recompile with GetHandle(true);
int DumpHeader(CURL *handle, curl_infotype type, char *data, size_t size, void *clientp) {
    (void)handle;
    (void)clientp;

    switch (type) {
    case CURLINFO_HEADER_OUT:
        printf("Header > %s\n", std::string(data, size).c_str());
        break;
    default:
        printf("Info: %s", std::string(data, size).c_str());
        break;
    }
    return 0;
}

CURL *GetHandle(bool verbose) {
    auto result = curl_easy_init();
    if (result == nullptr) {
        return result;
    }

    curl_easy_setopt(result, CURLOPT_USERAGENT, "xrdcl-pelican/1.3.1");
    curl_easy_setopt(result, CURLOPT_DEBUGFUNCTION, DumpHeader);
    if (verbose)
        curl_easy_setopt(result, CURLOPT_VERBOSE, 1L);

    auto env = XrdCl::DefaultEnv::GetEnv();
    std::string ca_file;
    if (!env->GetString("CurlCertFile", ca_file) || ca_file.empty()) {
        char *x509_ca_file = getenv("X509_CERT_FILE");
        if (x509_ca_file) {
            ca_file = std::string(x509_ca_file);
        }
    }
    if (!ca_file.empty()) {
        curl_easy_setopt(result, CURLOPT_CAINFO, ca_file.c_str());
    }
    std::string ca_dir;
    if (!env->GetString("CurlCertDir", ca_dir) || ca_dir.empty()) {
        char *x509_ca_dir = getenv("X509_CERT_DIR");
        if (x509_ca_dir) {
            ca_dir = std::string(x509_ca_dir);
        }
    }
    if (!ca_dir.empty()) {
        curl_easy_setopt(result, CURLOPT_CAPATH, ca_dir.c_str());
    }
    curl_easy_setopt(result, CURLOPT_NOSIGNAL, 1L);

    return result;
}

} // namespace

std::unique_ptr<FederationFactory> FederationFactory::m_singleton;
std::once_flag FederationFactory::m_init_once;

std::mutex FederationFactory::m_shutdown_lock;
std::condition_variable FederationFactory::m_shutdown_requested_cv;
bool FederationFactory::m_shutdown_requested = false;
std::condition_variable FederationFactory::m_shutdown_complete_cv;
bool FederationFactory::m_shutdown_complete = true;

FederationFactory &
FederationFactory::GetInstance(XrdCl::Log &logger, const struct timespec &fed_timeout)
{
    std::call_once(m_init_once, [&] {
        m_singleton.reset(new FederationFactory(logger, fed_timeout));
    });
    return *m_singleton.get();
}

FederationFactory::FederationFactory(XrdCl::Log &logger, const struct timespec &fed_timeout)
    : m_log(logger), m_fed_timeout(fed_timeout)
{
    {
        std::unique_lock lock(m_shutdown_lock);
        m_shutdown_complete = false;
    }
    std::thread refresh_thread(FederationFactory::RefreshThreadStatic, this);
    refresh_thread.detach();
}

void
FederationFactory::RefreshThreadStatic(FederationFactory *me)
{
    me->RefreshThread();
}

void
FederationFactory::RefreshThread()
{
    m_log.Debug(kLogXrdClPelican, "Starting background metadata refresh thread");
    while (true)
    {
        {
            std::unique_lock lock(m_shutdown_lock);
            m_shutdown_requested_cv.wait_for(
                lock,
                std::chrono::seconds(60),
                []{return m_shutdown_requested;}
            );
            if (m_shutdown_requested) {
                break;
            }
        }
        m_log.Debug(kLogXrdClPelican, "Refreshing Pelican metadata");
        std::vector<std::pair<std::string, std::shared_ptr<FederationInfo>>> updates;
        std::vector<std::string> deletions;
        std::time_t now = time(nullptr);

        auto handle = GetHandle(false);
        if (!handle) {
            m_log.Warning(kLogXrdClPelican, "Failed to create a curl handle for refresh thread; ignoring error");
            continue;
        }
        curl_easy_setopt(handle, CURLOPT_TIMEOUT_MS, m_fed_timeout.tv_sec * 1'000 + m_fed_timeout.tv_nsec / 1'000'000);
        curl_easy_setopt(handle, CURLOPT_FAILONERROR, 1L);

        for (const auto &entry : m_info_cache) {
            if (entry.second->IsExpired(now) && entry.second->IsValid()) {
                if (entry.second->TimeSinceLastUse(now) > m_discard_unused_time) {
                    // If it's not frequently used, instead of renewing it, remove it.
                    deletions.emplace_back(entry.first);
                } else {
                    // Final attempt to update expired entry; delete from cache on failure
                    std::string err;
                    auto new_info = LookupInfo(handle, entry.first, err);
                    if (!new_info) {
                        m_log.Warning(kLogXrdClPelican, "RefreshThread: Failed to update expired federation %s: %s; will delete the entry", entry.first.c_str(), err.c_str());
                        deletions.emplace_back(entry.first);
                    } else {
                        m_log.Debug(kLogXrdClPelican, "Successfully updated federation metadata for %s", entry.first.c_str());
                        updates.emplace_back(entry.first, new_info);
                    }
                }
            } else if (entry.second->IsExpired(now) && !entry.second->IsValid()) {
                // Remove negative cache entry
                deletions.emplace_back(entry.first);
            } else if (entry.second->Age(now) > m_stale_time) {
                // Try to renew once the data is stale.
                std::string err;
                auto new_info = LookupInfo(handle, entry.first, err);
                if (!new_info) {
                    m_log.Warning(kLogXrdClPelican, "RefreshThread: Failed to update federation %s: %s; will keep the stale entry", entry.first.c_str(), err.c_str());
                } else {
                    m_log.Debug(kLogXrdClPelican, "Successfully updated federation metadata for %s", entry.first.c_str());
                    updates.emplace_back(entry.first, new_info);
                }
            }
        }

        curl_easy_cleanup(handle);

        // Bulk update all entries
        std::lock_guard<std::mutex> lock(m_cache_mutex);
        for (const auto &entry : updates) {
            m_info_cache[entry.first] = entry.second;
        }
        for (const auto &entry : deletions) {
            m_info_cache.erase(entry);
        }
    }
    std::unique_lock lock(m_shutdown_lock);
    m_shutdown_complete = true;
    m_shutdown_complete_cv.notify_one();
}

std::shared_ptr<FederationInfo>
FederationFactory::GetInfo(const std::string &federation, std::string &err)
{
    {
        std::lock_guard<std::mutex> lock(m_cache_mutex);
        auto it = m_info_cache.find(federation);
        if (it != m_info_cache.end()) {
            return it->second;
        }
    }

    auto handle = GetHandle(false);
    if (!handle) {
        m_log.Warning(kLogXrdClPelican, "Failed to create a curl handle for refresh thread; ignoring error");
        return std::shared_ptr<FederationInfo>(nullptr);
    }
    curl_easy_setopt(handle, CURLOPT_TIMEOUT_MS, m_fed_timeout.tv_sec * 1'000 + m_fed_timeout.tv_nsec / 1'000'000);
    curl_easy_setopt(handle, CURLOPT_FAILONERROR, 1L);

    auto result = LookupInfo(handle, federation, err);
    if (!result || !result->IsValid()) {
        m_log.Warning(kLogXrdClPelican, "Failed to lookup federation info at %s due to error: %s", federation.c_str(), err.c_str());
    }
    std::lock_guard<std::mutex> lock(m_cache_mutex);
    m_info_cache[federation] = result;
    curl_easy_cleanup(handle);
    return result;
}

std::string
FederationInfo::GetDirector() const
{
    m_last_use.store(time(nullptr), std::memory_order_relaxed);
    return m_director;
}

namespace {

class SmallCurlBuffer {
public:
    SmallCurlBuffer() {}

    static size_t WriteCallback(char *buffer, size_t size, size_t nitems, void *this_ptr) {
        auto me = reinterpret_cast<SmallCurlBuffer*>(this_ptr);
        if (size * nitems + me->m_buffer.size() > m_max_size) {
            return 0;
        }
        me->m_buffer += std::string(buffer, size * nitems);
        return size * nitems;
    }

    const std::string &Get() const {return m_buffer;}
private:
    static const size_t m_max_size = 1024 * 1024;
    std::string m_buffer;
};

}

std::shared_ptr<FederationInfo>
FederationFactory::LookupInfo(CURL *handle, const std::string &federation, std::string &err)
{
    m_log.Info(kLogXrdClPelican, "Looking up federation metadata for URL %s", federation.c_str());

    auto now = time(nullptr);
    std::shared_ptr<FederationInfo> result(new FederationInfo(now));

    std::string federation_url = "https://" + federation + "/.well-known/pelican-configuration";
    curl_easy_setopt(handle, CURLOPT_URL, federation_url.c_str());

    SmallCurlBuffer sbuff;
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, SmallCurlBuffer::WriteCallback);
    curl_easy_setopt(handle, CURLOPT_WRITEDATA, &sbuff);

    char errbuf[CURL_ERROR_SIZE];
    curl_easy_setopt(handle, CURLOPT_ERRORBUFFER, errbuf);

    auto code = curl_easy_perform(handle);
    if (code != CURLE_OK) {
        auto len = strlen(errbuf);
        if (len) {
            err = errbuf;
        } else {
            err = curl_easy_strerror(code);
        }
        return result;
    }
    auto results = sbuff.Get();
    if (!results.size()) {
        err = "Federation metadata discovery URL returned an empty response";
        return result;
    }

    m_log.Debug(kLogXrdClPelican, "Federation %s metadata discovery lookup successful", federation.c_str());

    nlohmann::json jobj;
    try {
        jobj = nlohmann::json::parse(results);
    } catch (nlohmann::json::exception &jexc) {
        err = std::string("Error when deserializing the metadata discovery response JSON: ") + jexc.what();
        return result;
    }

    std::string director;
    try {
        director = jobj["director_endpoint"].get<std::string>();
    } catch (nlohmann::json::exception &jexc) {
        err = std::string("Error when fetching the director_endpoint string from metedata JSON: ") + jexc.what();
    }
    result.reset(new FederationInfo(director, now));
    return result;
}

void
FederationFactory::Shutdown()
{
    std::unique_lock lock(m_shutdown_lock);
    m_shutdown_requested = true;
    m_shutdown_requested_cv.notify_one();

    m_shutdown_complete_cv.wait(lock, []{return m_shutdown_complete;});
}
