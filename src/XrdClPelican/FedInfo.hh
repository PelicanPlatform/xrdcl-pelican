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

/**
 * The "FedInfo" classes return metadata about a Pelican federation.
 * The instances are heavily cached (and the caches periodically updated
 * in a separate thread), allowing efficient lookups for popular federations.
*/

#pragma once
#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

// Forward dec'ls
namespace XrdCl {
        class Log;
}
typedef void CURL;

namespace Pelican {

class FederationInfo;

// Manages lookup of federation metadata and a corresponding cache
class FederationFactory final {
public:
    // Federation factory is not copyable or movable
    FederationFactory(const FederationFactory &) = delete;
    FederationFactory(FederationFactory &&) = delete;

    // Returns the singleton instance of the federation factory.
    static FederationFactory &GetInstance(XrdCl::Log &logger, const struct timespec &fed_timeout);

    // Returns a FederationInfo associated with a federation hostname.
    // Federation data may be downloaded or come from a cache.
    std::shared_ptr<FederationInfo> GetInfo(const std::string &federation, std::string &err);

    // Maximum lifetime of metadata information; after this point, we refuse to serve up
    // old data.
    static const int m_max_lifetime = 4 * 60 * 60;
    // If the metadata is unused after this amount of time, remove it from the cache.
    static const int m_discard_unused_time = 60 * 60;
    // If metadata lookup fails, cache the failure for this amount of time.
    static const int m_negative_cache_time = 5 * 60;
    // Start attempting to renew once the data is at least this age.
    static const int m_stale_time = 15 * 60;

private:
    FederationFactory(XrdCl::Log &logger, const struct timespec &fed_timeout);

    // Background thread to periodically refresh the contents of the federation cache
    void RefreshThread();
    static void RefreshThreadStatic(FederationFactory *me);
    // Invoked by the destructor of a static member. Triggered when the library
    // is shutting down or is unloaded from the process.
    static void Shutdown();

    // Internal lookup function for a federation; no caching involved
    std::shared_ptr<FederationInfo> LookupInfo(CURL *, const std::string &federation, std::string &err);

    XrdCl::Log &m_log;

    // Timeout for the federation metadata lookup operation
    const struct timespec m_fed_timeout{0, 0};

    static std::once_flag m_init_once;
    static std::unique_ptr<FederationFactory> m_singleton;

    std::mutex m_cache_mutex;
    std::unordered_map<std::string, std::shared_ptr<FederationInfo>> m_info_cache;

    // Mutex for managing the shutdown of the background thread
    static std::mutex m_shutdown_lock;
    // Condition variable managing the requested shutdown of the background thread.
    static std::condition_variable m_shutdown_requested_cv;
    // Flag indicating that a shutdown was requested.
    static bool m_shutdown_requested;
    // The background refresh thread
    static std::thread m_refresh_tid;
    // shutdown trigger
    static struct shutdown_s {
      ~shutdown_s() { Shutdown(); }
    } m_shutdowns;
};


// Information about a single federation's services.
class FederationInfo final {
public:
    // Return the director service URL used by this federation.
    std::string GetDirector() const;
    // Returns true if the entry is valid; false means a negative-cached entry.
    bool IsValid() const {return !m_invalid;}
    // Returns true if the data is expired.
    bool IsExpired(const std::time_t now) const {return now > m_expiry;}
    // Returns the age of the data.
    std::time_t Age(const std::time_t now) const {return now - m_nbf;}
    std::time_t TimeSinceLastUse(const std::time_t now) const {return now - m_last_use.load(std::memory_order_relaxed);}

private:
    friend class FederationFactory;

    FederationInfo(const std::string &director, std::time_t now) :
        m_expiry(now + FederationFactory::m_max_lifetime),
        m_nbf(now),
        m_director(director)
    {}

    // Constructor for an invalid (negative cache) entry.
    FederationInfo(std::time_t now) :
        m_invalid(true),
        m_expiry(now + FederationFactory::m_negative_cache_time),
        m_nbf(now)
    {}

    bool m_invalid{false};
    std::time_t m_expiry{0};
    std::time_t m_nbf{0};
    mutable std::atomic<std::time_t> m_last_use;
    std::string m_director;
};

}
