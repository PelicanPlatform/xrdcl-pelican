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

/**
 * The "FedInfo" classes return metadata about a Pelican federation.
 * The instances are heavily cached (and the caches periodically updated
 * in a separate thread), allowing efficient lookups for popular federations.
*/

#pragma once
#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

// Forward dec'ls
namespace XrdCl {
        class Log;
}
typedef void CURL;

namespace Pelican {

// Information about a single federation's services.
class FederationInfo final {
public:
    std::string GetDirector() const;
    bool IsValid() const {return !m_invalid;}
    bool IsExpired(const std::time_t now) const {return now > m_expiry;}
    std::time_t Age(const std::time_t now) const {return now - m_nbf;}
    std::time_t TimeSinceLastUse(const std::time_t now) const {return now - m_last_use.load(std::memory_order_relaxed);}

private:
    friend class FederationFactory;
    FederationInfo(const std::string &director) : m_director(director) {}

    bool m_invalid{false};
    std::time_t m_expiry{0};
    std::time_t m_nbf{0};
    mutable std::atomic<std::time_t> m_last_use;
    std::string m_director;
};

// Manages lookup of federation metadata and a corresponding cache
class FederationFactory final {
public:
    // Returns the singleton instance of the federation factory.
    static FederationFactory &GetInstance(XrdCl::Log &logger);

    // Returns a FederationInfo associated with a federation hostname.
    // Federation data may be downloaded or come from a cache.
    std::shared_ptr<FederationInfo> GetInfo(const std::string &federation, std::string &err);

private:
    FederationFactory(XrdCl::Log &logger);

    // Background thread to periodically refresh the contents of the federation cache
    void RefreshThread();
    static void RefreshThreadStatic(FederationFactory *me);

    // Internal lookup function for a federation; no caching involved
    std::shared_ptr<FederationInfo> LookupInfo(CURL *, const std::string &federation, std::string &err);

    XrdCl::Log &m_log;

    static std::once_flag m_init_once;
    static std::unique_ptr<FederationFactory> m_singleton;

    std::mutex m_cache_mutex;
    std::unordered_map<std::string, std::shared_ptr<FederationInfo>> m_info_cache;
};

}