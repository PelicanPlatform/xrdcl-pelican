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

#include "DirectorCache.hh"

#include <thread>

std::unordered_map<std::string, std::unique_ptr<Pelican::DirectorCache>> Pelican::DirectorCache::m_caches;
std::shared_mutex Pelican::DirectorCache::m_caches_lock;
std::once_flag Pelican::DirectorCache::m_expiry_launch;

Pelican::DirectorCache::DirectorCache(const std::chrono::steady_clock::time_point &now) :
    m_root{now}
{
    std::call_once(m_expiry_launch, [] {
        std::thread t(DirectorCache::ExpireThread);
        t.detach();
    });
}

void Pelican::DirectorCache::ExpireThread()
{
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        std::vector<DirectorCache*> dcache;
        auto now = std::chrono::steady_clock::now();
        {
            std::unique_lock lock(m_caches_lock);
            for (const auto &entry : m_caches) {
                dcache.push_back(entry.second.get());
            }
        }
        for (const auto &entry : dcache) {
            entry->Expire(now);
        }
    }
}
