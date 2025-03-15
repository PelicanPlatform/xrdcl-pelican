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

 #include "ChecksumCache.hh"

#include <thread>

Pelican::ChecksumCache Pelican::ChecksumCache::g_cache;
std::once_flag Pelican::ChecksumCache::m_expiry_launch;

Pelican::ChecksumCache & Pelican::ChecksumCache::Instance() {
    std::call_once(m_expiry_launch, [] {
        std::thread t(ChecksumCache::ExpireThread);
        t.detach();
    });
    return g_cache;
}

void Pelican::ChecksumCache::ExpireThread()
{
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        auto now = std::chrono::steady_clock::now();
        g_cache.Expire(now);
    }
}

void Pelican::ChecksumCache::Expire(std::chrono::steady_clock::time_point now)
{
    std::unique_lock lock(m_mutex);
    for (auto iter = m_checksums.begin(); iter != m_checksums.end();) {
        if (iter->second.m_expiry < now) {
            for (int idx = 0; idx < kUnknown; ++idx) {
                if (iter->second.m_available_checksums.Test(static_cast<ChecksumType>(idx))) {
                    m_checksum_map[idx].erase(iter->first);
                }
            }
            iter = m_checksums.erase(iter);
        } else {
            ++iter;
        }
    }
}