/***************************************************************
 *
 * xrdcl-pelican implements an XRootD client plugin for interacting with the Pelican Platform
 * Copyright (C) 2026 Morgridge Institute for Research
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <https://www.gnu.org/licenses/>.
 *
 ***************************************************************/

#include "BrokerCache.hh"

#include <thread>

using namespace Pelican;

std::unique_ptr<BrokerCache> BrokerCache::m_cache{nullptr};
std::chrono::steady_clock::duration BrokerCache::m_entry_lifetime{std::chrono::minutes(1) + std::chrono::seconds(10)};
std::once_flag BrokerCache::m_cache_init;
std::mutex BrokerCache::m_shutdown_lock;
std::condition_variable BrokerCache::m_shutdown_requested_cv;
bool BrokerCache::m_shutdown_requested = false;
std::thread BrokerCache::m_expire_tid;

// shutdown trigger, must be last of the static members
BrokerCache::shutdown_s BrokerCache::m_shutdowns;

BrokerCache::BrokerCache() {}

const BrokerCache &
BrokerCache::GetCache() {
    std::unique_lock lock(m_shutdown_lock);
    std::call_once(m_cache_init, []{
        m_cache.reset(new BrokerCache());
        if (!m_shutdown_requested) {
            std::thread t(BrokerCache::ExpireThread);
            m_expire_tid = std::move(t);
        }
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
    {
        std::unique_lock lock(m_shutdown_lock);
        m_shutdown_requested = true;
        m_shutdown_requested_cv.notify_one();
    }

    if (m_expire_tid.joinable()) {
        m_expire_tid.join();
    }
}
