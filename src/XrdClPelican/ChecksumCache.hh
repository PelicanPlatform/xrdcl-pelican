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

#include "../common/XrdClCurlChecksum.hh"

#include <array>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_map>

namespace Pelican {

class ChecksumTypeBitmask {
public:
    void Set(XrdClCurl::ChecksumType ctype) {
        if (ctype == XrdClCurl::ChecksumType::kAll) {
            SetAll();
            return;
        } else if (ctype == XrdClCurl::ChecksumType::kUnknown) {
            return;
        }
        m_mask |= 1 << static_cast<int>(ctype);
    }
    void Clear(XrdClCurl::ChecksumType ctype) {
        if (ctype == XrdClCurl::ChecksumType::kAll) {
            ClearAll();
            return;
        } else if (ctype == XrdClCurl::ChecksumType::kUnknown) {
            return;
        }
        m_mask &= ~(1 << static_cast<int>(ctype));
    }
    bool Test(XrdClCurl::ChecksumType ctype) const {
        if (ctype == XrdClCurl::ChecksumType::kAll) {
            auto all = (1 << static_cast<int>(XrdClCurl::ChecksumType::kAll)) - 1;
            return (m_mask & all) == all;
        } else if (ctype == XrdClCurl::ChecksumType::kUnknown) {
            return false;
        }
        return m_mask & (1 << static_cast<int>(ctype));
    }
    bool TestAny() const {
        return m_mask != 0;
    }
    void SetAll() {
        m_mask = (1 << static_cast<int>(XrdClCurl::ChecksumType::kAll)) - 1;
    }
    void ClearAll() {
        m_mask = 0;
    }
    unsigned Count() const {
        unsigned count = 0;
        for (int idx=0; idx < static_cast<int>(XrdClCurl::ChecksumType::kAll); ++idx) {
            if (m_mask & (1 << idx)) {
                ++count;
            }
        }
        return count;
    }
    unsigned Get() const {
        return m_mask;
    }
    XrdClCurl::ChecksumType GetFirst() const {
        for (int idx=0; idx < static_cast<int>(XrdClCurl::ChecksumType::kAll); ++idx) {
            if (m_mask & (1 << idx)) {
                return static_cast<XrdClCurl::ChecksumType>(idx);
            }
        }
        return XrdClCurl::ChecksumType::kUnknown;
    }
private:
    char m_mask{0};
};

// A cache holding the checksums of objects in a given
// data federation.
class ChecksumCache {
public:
    static constexpr std::chrono::steady_clock::duration g_expiry_duration = std::chrono::minutes(5);
    static constexpr std::chrono::steady_clock::duration g_negative_expiry_duration = std::chrono::minutes(1);

    void Put(const std::string &url, const XrdClCurl::ChecksumInfo &cinfo, const std::chrono::steady_clock::time_point &now=std::chrono::steady_clock::now()) const {
        auto host_and_path = GetUrlKey(url);

        const std::unique_lock sentry(m_mutex);
        CEntry centry;

        auto has_checksum = false;
        for (int idx=0; idx < static_cast<int>(XrdClCurl::ChecksumType::kUnknown); ++idx) {
            auto ctype = static_cast<XrdClCurl::ChecksumType>(idx);
            if (!cinfo.IsSet(ctype)) {
                continue;
            }
            if (!has_checksum) {
                centry.m_last_checksum = static_cast<char>(ctype);
                auto &entry = cinfo.Get(ctype);
                std::copy(entry.begin(), entry.end(), centry.m_checksum_entry.begin());
            }
            centry.m_available_checksums.Set(ctype);
            has_checksum = true;
        }
        for (int idx=0; idx < static_cast<int>(XrdClCurl::ChecksumType::kUnknown); ++idx) {
            auto ctype = static_cast<XrdClCurl::ChecksumType>(idx);
            if (!centry.m_available_checksums.Test(ctype)) {
                continue;
            }
            auto &cmap = m_checksum_map[idx];
            auto iter = cmap.find(host_and_path);
            if (iter == cmap.end()) {
                cmap.emplace(host_and_path, cinfo.Get(ctype));
            } else {
                iter->second = cinfo.Get(ctype);
            }
        }
        centry.m_expiry = has_checksum ? now + g_expiry_duration : now + g_negative_expiry_duration;
        m_checksums.emplace(host_and_path, centry);
    }

    XrdClCurl::ChecksumInfo Get(const std::string &url, ChecksumTypeBitmask mask, const std::chrono::steady_clock::time_point &now=std::chrono::steady_clock::now()) const {
        auto host_and_path = GetUrlKey(url);

        const std::shared_lock sentry(m_mutex);
        auto iter = m_checksums.find(host_and_path);
        XrdClCurl::ChecksumInfo cinfo;
        if (iter == m_checksums.end()) {
            m_cache_miss++;
            return cinfo;
        }
        if (iter->second.m_expiry < now) {
            m_cache_miss++;
            return cinfo;
        }
        if (mask.Count() == 1) {
            auto ctype = mask.GetFirst();
            if (!iter->second.m_available_checksums.Test(ctype)) {
                m_cache_miss++;
                return cinfo;
            }
            if (iter->second.m_last_checksum == static_cast<unsigned char>(ctype)) {
                cinfo.Set(ctype, iter->second.m_checksum_entry);
                m_cache_hit++;
                return cinfo;
            }
            auto &cmap = m_checksum_map[static_cast<int>(ctype)];
            auto citer = cmap.find(host_and_path);
            if (citer == cmap.end()) {
                m_cache_miss++;
                return cinfo;
            }
            iter->second.m_last_checksum = static_cast<unsigned char>(ctype);
            std::copy(citer->second.begin(), citer->second.end(), iter->second.m_checksum_entry.begin());
            cinfo.Set(ctype, citer->second);
            m_cache_hit++;
            return cinfo;
        }
        for (int idx=0; idx < static_cast<int>(XrdClCurl::ChecksumType::kUnknown); ++idx) {
            auto ctype = static_cast<XrdClCurl::ChecksumType>(idx);
            if (!iter->second.m_available_checksums.Test(ctype)) {
                continue;
            }
            auto &cmap = m_checksum_map[idx];
            auto iter = cmap.find(host_and_path);
            if (iter != cmap.end()) {
                cinfo.Set(ctype, iter->second);
                m_cache_hit++;
            } else {
                m_cache_miss++;
            }
        }
        return cinfo;
    }

    // Get the cache key for a given URL
    //
    // Cache key should consist of the host and path portion of the URL.
    static std::string_view GetUrlKey(const std::string &url) {
        auto authority_loc = url.find("://");
        if (authority_loc == std::string::npos) {
            return std::string_view();
        }
        auto path_loc = url.find('/', authority_loc + 3);
        if (path_loc == std::string::npos) {
            return std::string_view();
        }
        auto query_loc = url.find('?', path_loc + 3);

        std::string_view url_view{url};
        auto host_loc = url_view.substr(authority_loc + 3, path_loc - authority_loc - 3).find('@');
        if (host_loc == std::string::npos) {
            return url_view.substr(authority_loc + 3, query_loc - authority_loc - 3);
        }
        host_loc += authority_loc + 3;
        return url_view.substr(host_loc + 1, query_loc - host_loc - 1);
    }

    uint64_t GetCacheHits() const {return m_cache_hit;}
    uint64_t GetCacheMisses() const {return m_cache_miss;}

    // Expire all entries in the cache whose expiration is older than `now`.
    void Expire(std::chrono::steady_clock::time_point now);

    // Return the global instance of the checksum cache.
    static ChecksumCache &Instance();

private:
    ChecksumCache() = default;
    ChecksumCache(const ChecksumCache &) = delete;
    ChecksumCache(ChecksumCache &&) = delete;

    // Background thread periodically invoking `Expire` on the cache.
    static void ExpireThread();

    static void Shutdown() __attribute__((destructor));

    // A space-optimized entry in the checksum cache.
    // The last-used checksum is stored internal to this structure;
    // otherwise, the checksums are stored in a dedicated map per type.
    struct CEntry {
        ChecksumTypeBitmask m_available_checksums; // Bitmask of available checksums
        unsigned char m_last_checksum{0}; // Type of last used checksum
        std::chrono::steady_clock::time_point m_expiry; // Time when this entry expires
        std::array<unsigned char, XrdClCurl::g_max_checksum_length> m_checksum_entry; // Last used checksum value
    }; 

    mutable std::atomic<uint64_t> m_cache_hit{0};
    mutable std::atomic<uint64_t> m_cache_miss{0};

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

    mutable std::shared_mutex m_mutex;
    mutable std::unordered_map<std::string, CEntry, ChecksumCache::transparent_string_hash, std::equal_to<>> m_checksums;
    using ChecksumMap = std::unordered_map<std::string, std::array<unsigned char, XrdClCurl::g_max_checksum_length>, transparent_string_hash, std::equal_to<>>;
    mutable std::array<ChecksumMap, static_cast<int>(XrdClCurl::ChecksumType::kUnknown)> m_checksum_map;

    static std::once_flag m_expiry_launch;
    static ChecksumCache g_cache;

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
