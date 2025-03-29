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

#include <array>
#include <chrono>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_map>

namespace Pelican {

// A cache holding the checksums of objects in a given
// data federation.
class ChecksumCache {
public:
    static constexpr size_t g_max_checksum_length = 32;
    static constexpr std::chrono::steady_clock::duration g_expiry_duration = std::chrono::minutes(5);
    static constexpr std::chrono::steady_clock::duration g_negative_expiry_duration = std::chrono::minutes(1);

    // Checksum types known to this cache
    enum ChecksumType {
        kCRC32C = 0,
        kMD5 = 1,
        kSHA1 = 2,
        kSHA256 = 3,
        kUnknown = 4,
        kAll = 4
    };

    static const std::string GetTypeString(ChecksumType ctype) {
        switch (ctype) {
            case kCRC32C:
                return "crc32c";
            case kMD5:
                return "md5";
            case kSHA1:
                return "sha1";
            case kSHA256:
                return "sha256";
            case kUnknown:
                return "unknown";
        }
        return "unknown";
    }

    static const size_t GetChecksumLength(ChecksumType ctype) {
        switch (ctype) {
            case kCRC32C:
                return 4;
            case kMD5:
                return 16;
            case kSHA1:
                return 20;
            case kSHA256:
                return 32;
            case kUnknown:
                return 0;
        }
        return 0;
    }

    static ChecksumType GetTypeFromString(const std::string &str) {
        if (str == "crc32c") {
            return kCRC32C;
        } else if (str == "md5") {
            return kMD5;
        } else if (str == "sha1") {
            return kSHA1;
        } else if (str == "sha256") {
            return kSHA256;
        }
        return kUnknown;
    }

    class ChecksumTypeBitmask {
    public:
        void Set(ChecksumType ctype) {
            m_mask |= 1 << ctype;
        }
        void Clear(ChecksumType ctype) {
            m_mask &= ~(1 << ctype);
        }
        bool Test(ChecksumType ctype) const {
            return m_mask & (1 << ctype);
        }
        bool TestAny() const {
            return m_mask != 0;
        }
        void SetAll() {
            m_mask = (1 << kAll) - 1;
        }
        void ClearAll() {
            m_mask = 0;
        }
        unsigned Count() const {
            unsigned count = 0;
            for (int idx=0; idx < kAll; ++idx) {
                if (m_mask & (1 << idx)) {
                    ++count;
                }
            }
            return count;
        }
        unsigned Get() const {
            return m_mask;
        }
        ChecksumType GetFirst() const {
            for (int idx=0; idx < kAll; ++idx) {
                if (m_mask & (1 << idx)) {
                    return static_cast<ChecksumType>(idx);
                }
            }
            return kUnknown;
        }
    private:
        char m_mask{0}; 
    };

    // A single checksum type / value pair
    // Value is stored as raw bytes in memory.
    struct ChecksumEntry {
        ChecksumType type{kUnknown};
        std::array<unsigned char, g_max_checksum_length> value;
    };

    // All known checksums for a given object
    //
    // If the checksum is not available, then checksums[ctype].type == kUnknown.
    // Otherwise, checksums[type].value contains the checksum and checksums[ctype].type
    // is set to ctype for a given ctype in the ChecksumType enum.
    class ChecksumInfo {
    public:
        bool IsSet(ChecksumType ctype) const {
            return checksums[ctype].type != kUnknown;
        }
        const std::array<unsigned char, g_max_checksum_length> &Get(ChecksumType ctype) const {
            return checksums[ctype].value;
        }
        void Set(ChecksumType ctype, const std::array<unsigned char, g_max_checksum_length> &value) {
            checksums[ctype] = ChecksumEntry{ctype, value};
        }

        std::tuple<ChecksumType, std::array<unsigned char, g_max_checksum_length>, bool> GetFirst() const {
            for (int idx=0; idx < kUnknown; ++idx) {
                if (checksums[idx].type != kUnknown) {
                    return std::make_tuple(static_cast<ChecksumType>(idx), checksums[idx].value, true);
                }
            }
            return std::make_tuple(kUnknown, std::array<unsigned char, g_max_checksum_length>(), false);
        }

    private:
        std::array<ChecksumEntry, kUnknown> checksums;
    };

    void Put(const std::string &url, const ChecksumInfo &cinfo, const std::chrono::steady_clock::time_point &now=std::chrono::steady_clock::now()) const {
        auto host_and_path = GetUrlKey(url);
        
        const std::unique_lock sentry(m_mutex);
        CEntry centry;

        auto has_checksum = false;
        for (int idx=0; idx < kUnknown; ++idx) {
            auto ctype = static_cast<ChecksumType>(idx);
            if (!cinfo.IsSet(ctype)) {
                continue;
            }
            if (!has_checksum) {
                centry.m_last_checksum = ctype;
                auto &entry = cinfo.Get(ctype);
                std::copy(entry.begin(), entry.end(), centry.m_checksum_entry.begin());
            }
            centry.m_available_checksums.Set(ctype);
            has_checksum = true;
        }
        for (int idx=0; idx < kUnknown; ++idx) {
            auto ctype = static_cast<ChecksumType>(idx);
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

    ChecksumInfo Get(const std::string &url, ChecksumTypeBitmask mask, const std::chrono::steady_clock::time_point &now=std::chrono::steady_clock::now()) const {
        auto host_and_path = GetUrlKey(url);
        
        const std::shared_lock sentry(m_mutex);
        auto iter = m_checksums.find(host_and_path);
        ChecksumInfo cinfo;
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
            if (iter->second.m_last_checksum == ctype) {
                cinfo.Set(ctype, iter->second.m_checksum_entry);
                m_cache_hit++;
                return cinfo;
            }
            auto &cmap = m_checksum_map[ctype];
            auto citer = cmap.find(host_and_path);
            if (citer == cmap.end()) {
                m_cache_miss++;
                return cinfo;
            }
            iter->second.m_last_checksum = ctype;
            std::copy(citer->second.begin(), citer->second.end(), iter->second.m_checksum_entry.begin());
            cinfo.Set(ctype, citer->second);
            m_cache_hit++;
            return cinfo;
        }
        for (int idx=0; idx < kUnknown; ++idx) {
            auto ctype = static_cast<ChecksumType>(idx);
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

    // A space-optimized entry in the checksum cache.
    // The last-used checksum is stored internal to this structure;
    // otherwise, the checksums are stored in a dedicated map per type.
    struct CEntry {
        ChecksumTypeBitmask m_available_checksums; // Bitmask of available checksums
        unsigned char m_last_checksum{0}; // Type of last used checksum
        std::chrono::steady_clock::time_point m_expiry; // Time when this entry expires
        std::array<unsigned char, g_max_checksum_length> m_checksum_entry; // Last used checksum value
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
    using ChecksumMap = std::unordered_map<std::string, std::array<unsigned char, g_max_checksum_length>, transparent_string_hash, std::equal_to<>>;
    mutable std::array<ChecksumMap, kUnknown> m_checksum_map;

    static std::once_flag m_expiry_launch;
    static ChecksumCache g_cache;
};

} // namespace Pelican
