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

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <memory>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_map>

namespace Pelican {

class DirectorCache {
public:
    static const DirectorCache &GetCache(const std::string &director, const std::chrono::steady_clock::time_point &now=std::chrono::steady_clock::now()) {
        std::shared_lock guard(m_caches_lock);
        const auto iter = m_caches.find(director);
        if (iter == m_caches.end()) {
            guard.unlock();
            std::unique_lock write_guard(m_caches_lock);
            std::unique_ptr<DirectorCache> dcache(new DirectorCache(now));
            auto [diter, _] = m_caches.emplace(director, std::move(dcache));
            return *diter->second;
        }
        return *iter->second;
    }

    // Given a URL and a path depth, return string views of the base path and
    // URL, stripped to the depth.
    //
    // This is used to determine the base of the mirroring in a Link header.
    // Examples:
    // - https://example.com/foo/bar, 2 -> https://example.com/, /, true
    // - https://example.com/foo/bar, 1 -> https://example.com/foo, /foo, true
    // - https://example.com/foo/bar, 0 -> https://example.com/foo/bar, /foo/bar, true
    // - https://example.com/foo/bar, 3 -> false (error -- depth is larger than the path)
    static std::tuple<std::string_view, std::string_view, bool> ComputePathAndUrl(const std::string &url, unsigned depth) {
        auto loc = url.find("://");
        if (loc == std::string::npos) {
            return std::make_tuple(std::string_view(), std::string_view(), false);
        }
        auto query_loc = url.find('?', loc + 3);
        loc = url.find('/', loc + 3);
        if (loc == std::string::npos || ((query_loc != std::string::npos) && (loc > query_loc))) {
            return std::make_tuple(std::string_view(), std::string_view(), false);
        }
        auto path_view = std::string_view(url).substr(loc, query_loc - loc);

        auto url_end = path_view.size();
        unsigned consumed = 0; // Count of path components already processed
        while (depth--) {
            url_end = path_view.find_last_of('/', url_end);
            if (url_end == 0) {
                if (depth || !consumed) // If original depth=1 and there were no path components to process, then we had path=/ depth=1, which is an error
                    return std::make_tuple(std::string_view(), std::string_view(), false);
                else
                    url_end++;
            }
            consumed++;
            url_end = path_view.find_last_not_of('/', url_end - 1);
            if (url_end == 0 || url_end == std::string_view::npos) {
                // Handle case where we consume all components except for '/'; if we need
                // to loop more, then we are in an error condition; otherwise, we just
                // bump by one to have the '/'
                if (depth)
                    return std::make_tuple(std::string_view(), std::string_view(), false);
                else
                    url_end++;
            }
        }
        path_view = path_view.substr(0, url_end + 1);
        std::string_view url_base{url};
        url_base = url_base.substr(0, loc + url_end + 1);

        //std::cout << "Putting path " << path_view << " at server URL " << url_base << std::endl;
        return std::make_tuple(path_view, url_base, true);
    }

    void Put(const std::string &url, unsigned depth, const std::chrono::steady_clock::time_point &now=std::chrono::steady_clock::now()) const {
        auto [path_view, url_base, ok] = ComputePathAndUrl(url, depth);
        if (!ok) {
            return;
        }

        const std::unique_lock sentry(m_mutex);

        m_root.Put(path_view, url_base, now);
    }

    std::string Get(const std::string &url, const std::chrono::steady_clock::time_point &now=std::chrono::steady_clock::now()) const {
        auto loc = url.find("://");
        if (loc == std::string::npos) {
            return "";
        }
        loc = url.find('/', loc + 3);
        if (loc == std::string::npos) {
            return "";
        }
        auto path = std::string_view(url).substr(loc);

        const std::shared_lock sentry(m_mutex);

        return m_root.Get(path, now);
    }

    void Expire(const std::chrono::steady_clock::time_point &now=std::chrono::steady_clock::now()) {
        const std::unique_lock sentry(m_mutex);

        m_root.Expire(now);
    }

    void Reset() const {
        const std::unique_lock sentry(m_mutex);

        m_root = CacheEntry(std::chrono::steady_clock::now());
    }

    static void ResetAll() {
        std::vector<DirectorCache*> dcache;
        {
            std::shared_lock read_guard(m_caches_lock);
            dcache.reserve(m_caches.size());
            for (const auto &entry : m_caches) {
                dcache.push_back(entry.second.get());
            }
        }
        for (auto &entry : dcache) {
            entry->Reset();
        }
    }

private:

    DirectorCache(const std::chrono::steady_clock::time_point &now);

    class CacheEntry {
    public:
        CacheEntry(const std::chrono::steady_clock::time_point &now) :
            m_expiry(now + std::chrono::minutes(1))
        {}

        void Put(std::string_view &path, const std::string_view &url, const std::chrono::steady_clock::time_point &now) {
            auto loc = path.find_first_not_of('/');
            m_expiry = now + std::chrono::minutes(1);
            if (loc == std::string_view::npos) {
                m_value = url;
                return;
            }
            auto end_loc = path.find_first_of('/', loc);
            auto first_entry = path.substr(loc, end_loc - loc);
            //std::cout << "First entry in put: " << first_entry << std::endl;
            auto [iter, inserted] = m_subdirs.emplace(first_entry, std::make_unique<CacheEntry>(now));
            auto next_path = end_loc == std::string_view::npos ? "" : path.substr(end_loc);
            iter->second->Put(next_path, url, now);
        }

        std::string Get(const std::string_view path, const std::chrono::steady_clock::time_point &now) {
            //std::cout << "Get with path " << path << std::endl;
            auto loc = path.find_first_not_of('/');
            if (loc == std::string_view::npos) {
                //std::cout << "Returning URL starting with base " << m_value << std::endl;
                return m_value.empty() ? m_value : (m_value + std::string(path));
            }
            auto end_loc = path.find_first_of('/', loc);
            auto first_entry = path.substr(loc, end_loc - loc);
            auto iter = m_subdirs.find(std::string(first_entry));
            if (iter == m_subdirs.end()) {
                //std::cout << "Returning URL starting with base " << m_value << std::endl; 
                return m_value.empty() ? m_value : (m_value + std::string(path));
            }
            if (iter->second->IsExpired(now)) {
                // We cannot erase the expired entry here as `Get` is called with the shared
                // lock while we need the
                return m_value.empty() ? m_value : (m_value + std::string(path));
            }
            auto remainder = end_loc == std::string_view::npos ? "" : path.substr(end_loc);
            auto result = iter->second->Get(remainder, now);
            if (result.empty()) {
                return m_value.empty() ? m_value : (m_value + std::string(path));
            }
            return result;
        }

        void Expire(const std::chrono::steady_clock::time_point &now) {
            std::erase_if(m_subdirs, [&](const auto & item) {return item.second->IsExpired(now);});
            if (IsExpired(now)) {
                m_value = "";
            }
        }

        bool IsExpired(const std::chrono::steady_clock::time_point &now) const {
            return now > m_expiry;
        }

    private:
        std::unordered_map<std::string, std::unique_ptr<CacheEntry>> m_subdirs;
        std::string m_value;
        std::chrono::time_point<std::chrono::steady_clock> m_expiry;
    };

    // Invoked by the destructor of a static member on the shutdown of the library,
    // will trigger the background threads to wrap up and have a clean exit.
    static void Shutdown();

    static void ExpireThread();

    static std::unordered_map<std::string, std::unique_ptr<DirectorCache>> m_caches;
    static std::shared_mutex m_caches_lock;
    static std::once_flag m_expiry_launch;

    // Mutex for managing the shutdown of the background thread
    static std::mutex m_shutdown_lock;
    // Condition variable managing the requested shutdown of the background thread.
    static std::condition_variable m_shutdown_requested_cv;
    // Flag indicating that a shutdown was requested.
    static bool m_shutdown_requested;
    // The cache expire thread
    static std::thread m_expire_tid;
    // shutdown trigger
    static struct shutdown_s {
      ~shutdown_s() { Shutdown(); }
    } m_shutdowns;

    mutable CacheEntry m_root;

    mutable std::shared_mutex m_mutex;
};

}
