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

#include "BrokerCache.hh"

#include <thread>

using namespace Pelican;

BrokerCache *BrokerCache::m_cache{nullptr};
std::chrono::steady_clock::duration BrokerCache::m_entry_lifetime{std::chrono::minutes(1) + std::chrono::seconds(10)};
std::once_flag BrokerCache::m_cache_init;
std::mutex BrokerCache::m_shutdown_lock;
std::condition_variable BrokerCache::m_shutdown_requested_cv;
bool BrokerCache::m_shutdown_requested = false;
std::condition_variable BrokerCache::m_shutdown_complete_cv;
bool BrokerCache::m_shutdown_complete = true; // Starts in "true" state as the thread hasn't started

BrokerCache::BrokerCache() {}

const BrokerCache &
BrokerCache::GetCache() {
    std::call_once(m_cache_init, []{
        m_cache = new BrokerCache();
        {
            std::unique_lock lock(m_shutdown_lock);
            m_shutdown_complete = false;
        }
        std::thread t(BrokerCache::ExpireThread);
        t.detach();
    });
    return *m_cache;
}

std::string_view
BrokerCache::GetUrlKey(const std::string &url, std::string &modified_url) {
    auto authority_loc = url.find("://");
    if (authority_loc == std::string::npos) {
        return std::string_view();
    }
    auto path_loc = url.find('/', authority_loc + 3);
    if (path_loc == std::string::npos) {
        path_loc = url.length();
    }

    std::string_view url_view{url};
    auto host_loc = url_view.substr(authority_loc + 3, path_loc - authority_loc - 3).find('@');
    if (host_loc == std::string::npos) {
        return url_view.substr(0, path_loc);
    }
    host_loc += authority_loc + 3;
    modified_url = url.substr(0, authority_loc + 3) + std::string(url_view.substr(host_loc + 1, path_loc - host_loc - 1));
    return modified_url;
}

void
BrokerCache::Expire(std::chrono::steady_clock::time_point now)
{
    std::unique_lock lock(m_mutex);
    for (auto iter = m_url_broker.begin(); iter != m_url_broker.end();) {
        if (iter->second.m_expiry < now) {
            iter = m_url_broker.erase(iter);
        } else {
            ++iter;
        }
    }
}

void
BrokerCache::ExpireThread()
{
    while (true) {
        {
            std::unique_lock lock(m_shutdown_lock);
            m_shutdown_requested_cv.wait_for(
                lock,
                std::chrono::seconds(30),
                []{return m_shutdown_requested;}
            );
            if (m_shutdown_requested) {
                break;
            }
        }
        auto now = std::chrono::steady_clock::now();
        m_cache->Expire(now);
    }
    std::unique_lock lock(m_shutdown_lock);
    m_shutdown_complete = true;
    m_shutdown_complete_cv.notify_one();
}

void
BrokerCache::Put(const std::string &url, const std::string &broker_url, std::chrono::steady_clock::time_point now) const {
    std::string modified_url;
    auto key = GetUrlKey(url, modified_url);

    const std::unique_lock sentry(m_mutex);

    auto iter = m_url_broker.find(key);
    auto expiry = now + m_entry_lifetime;
    if (iter == m_url_broker.end()) {
        m_url_broker.emplace(key, CacheEntry{broker_url, expiry});
    } else {
        iter->second.m_broker_url = url;
        iter->second.m_expiry = expiry;
    }
}

std::string
BrokerCache::Get(const std::string &url, const std::chrono::steady_clock::time_point now) const {
    std::string modified_url;
    auto key = GetUrlKey(url, modified_url);

    const std::shared_lock sentry(m_mutex);
    auto iter = m_url_broker.find(key);
    if (iter == m_url_broker.end()) {
        return "";
    }
    if (iter->second.m_expiry < now) {
        return "";
    }
    return iter->second.m_broker_url;
}

void
BrokerCache::Shutdown()
{
    std::unique_lock lock(m_shutdown_lock);
    m_shutdown_requested = true;
    m_shutdown_requested_cv.notify_one();

    m_shutdown_complete_cv.wait(lock, []{return m_shutdown_complete;});
}
