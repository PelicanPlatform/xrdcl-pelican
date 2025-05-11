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

#pragma once

#include <chrono>
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

    // Lifetime of entries within the broker cache
    static std::chrono::steady_clock::duration m_entry_lifetime;

    // Initializer flag
    static std::once_flag m_cache_init;

    // Mutex protecting the data in m_url_broker
    mutable std::shared_mutex m_mutex;

    // Map from a URL key to the corresponding broker to use
    mutable std::unordered_map<std::string, CacheEntry, transparent_string_hash, std::equal_to<>> m_url_broker;

    // Singleton instance of the broker cache
    static BrokerCache *m_cache;
};

} // namespace Pelican
