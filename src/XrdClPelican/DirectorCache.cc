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
#include <vector>

std::unordered_map<std::string, std::unique_ptr<Pelican::DirectorCache>> Pelican::DirectorCache::m_caches;
std::shared_mutex Pelican::DirectorCache::m_caches_lock;
std::once_flag Pelican::DirectorCache::m_expiry_launch;
std::mutex Pelican::DirectorCache::m_shutdown_lock;
std::condition_variable Pelican::DirectorCache::m_shutdown_requested_cv;
bool Pelican::DirectorCache::m_shutdown_requested = false;
std::condition_variable Pelican::DirectorCache::m_shutdown_complete_cv;
bool Pelican::DirectorCache::m_shutdown_complete = true; // Starts in "true" state as the thread hasn't started

Pelican::DirectorCache::DirectorCache(const std::chrono::steady_clock::time_point &now) :
    m_root{now}
{
    std::call_once(m_expiry_launch, [] {
        {
            std::unique_lock lock(m_shutdown_lock);
            m_shutdown_complete = false;
        }
        std::thread t(DirectorCache::ExpireThread);
        t.detach();
    });
}

void Pelican::DirectorCache::ExpireThread()
{
    while (true) {
        {
            std::unique_lock lock(m_shutdown_lock);
            m_shutdown_requested_cv.wait_for(
                lock,
                std::chrono::seconds(5),
                []{return m_shutdown_requested;}
            );
            if (m_shutdown_requested) {
                break;
            }
        }
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
    std::unique_lock lock(m_shutdown_lock);
    m_shutdown_complete = true;
    m_shutdown_complete_cv.notify_one();
}

void
Pelican::DirectorCache::Shutdown()
{
    std::unique_lock lock(m_shutdown_lock);
    m_shutdown_requested = true;
    m_shutdown_requested_cv.notify_one();

    m_shutdown_complete_cv.wait(lock, []{return m_shutdown_complete;});
}
