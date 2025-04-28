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

#include "CurlUtil.hh"
#include "FedInfo.hh"
#include "PelicanFilesystem.hh"

#include <nlohmann/json.hpp>
#include <curl/curl.h>
#include <XrdCl/XrdClLog.hh>

#include <thread>
#include <unistd.h>

using namespace Pelican;

std::unique_ptr<FederationFactory> FederationFactory::m_singleton;
std::once_flag FederationFactory::m_init_once;

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
        sleep(60);
        m_log.Debug(kLogXrdClPelican, "Refreshing Pelican metadata");
        std::vector<std::pair<std::string, std::shared_ptr<FederationInfo>>> updates;
        std::vector<std::string> deletions;
        std::time_t now = time(nullptr);

        auto handle = XrdClCurl::GetHandle(false);
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

    auto handle = XrdClCurl::GetHandle(false);
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
