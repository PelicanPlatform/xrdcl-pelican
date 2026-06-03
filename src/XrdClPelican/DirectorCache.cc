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
