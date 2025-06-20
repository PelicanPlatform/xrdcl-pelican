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

#pragma once

#include <algorithm>
#include <chrono>
#include <mutex>
#include <memory>
#include <shared_mutex>
#include <string>
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


    static void ExpireThread();

    static std::unordered_map<std::string, std::unique_ptr<DirectorCache>> m_caches;
    static std::shared_mutex m_caches_lock;
    static std::once_flag m_expiry_launch;

    mutable CacheEntry m_root;

    mutable std::shared_mutex m_mutex;
};

}
