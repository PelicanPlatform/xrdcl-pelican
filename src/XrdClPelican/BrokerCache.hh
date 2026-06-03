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

#pragma once

#include <condition_variable>
#include <chrono>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string_view>
#include <unordered_map>

namespace Pelican {

class BrokerCache {
public:
    static const BrokerCache &GetCache();

    void Put(const std::string &url, const std::string &broker_url,
        std::chrono::steady_clock::time_point now=std::chrono::steady_clock::now()) const;

    std::string Get(const std::string &url, const std::chrono::steady_clock::time_point now=std::chrono::steady_clock::now()) const;

    void Expire(const std::chrono::steady_clock::time_point now=std::chrono::steady_clock::now());

private:
    // Helper templates to allow string_view as a map key
    template<typename ... Bases>
    struct overload : Bases ...
    {
        using is_transparent = void;
        using Bases::operator() ... ;
    };
    using transparent_string_hash = overload<
        std::hash<std::string>,
        std::hash<std::string_view>
    >;

    struct CacheEntry {
        std::string m_broker_url; // URL for the broker to use.
        std::chrono::steady_clock::time_point m_expiry; // Expiration time of the entry
    };

    BrokerCache();

    static std::string_view GetUrlKey(const std::string &url, std::string &modified_url);

    // Thread for periodically calling the cache expiration.
    static void ExpireThread();
    static void Shutdown() __attribute__((destructor));

    // Lifetime of entries within the broker cache
    static std::chrono::steady_clock::duration m_entry_lifetime;

    // Initializer flag
    static std::once_flag m_cache_init;

    // Mutex protecting the data in m_url_broker
    mutable std::shared_mutex m_mutex;

    // Map from a URL key to the corresponding broker to use
    mutable std::unordered_map<std::string, CacheEntry, transparent_string_hash, std::equal_to<>> m_url_broker;

    // Singleton instance of the broker cache
    static std::unique_ptr<BrokerCache> m_cache;

    // Mutex for managing the shutdown of the background thread
    static std::mutex m_shutdown_lock;
    // Condition variable managing the requested shutdown of the background thread.
    static std::condition_variable m_shutdown_requested_cv;
    // Flag indicating that a shutdown was requested.
    static bool m_shutdown_requested;
    // Condition variable for the background thread to indicate it has completed.
    static std::condition_variable m_shutdown_complete_cv;
    // Flag indicating that the shutdown has completed.
    static bool m_shutdown_complete;
};

} // namespace Pelican
