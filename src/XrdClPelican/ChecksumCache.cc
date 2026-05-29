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

#include "ChecksumCache.hh"

#include <thread>

Pelican::ChecksumCache Pelican::ChecksumCache::g_cache;
std::once_flag Pelican::ChecksumCache::m_expiry_launch;
std::mutex Pelican::ChecksumCache::m_shutdown_lock;
std::condition_variable Pelican::ChecksumCache::m_shutdown_requested_cv;
bool Pelican::ChecksumCache::m_shutdown_requested = false;
std::thread Pelican::ChecksumCache::m_expire_tid;

// shutdown trigger, must be last of the static members
Pelican::ChecksumCache::shutdown_s Pelican::ChecksumCache::m_shutdowns;

Pelican::ChecksumCache & Pelican::ChecksumCache::Instance() {
    std::unique_lock lock(m_shutdown_lock);
    if (!m_shutdown_requested) {
        std::call_once(m_expiry_launch, [] {
            std::thread t(ChecksumCache::ExpireThread);
            m_expire_tid = std::move(t);
        });
    }
    return g_cache;
}

void Pelican::ChecksumCache::ExpireThread()
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
        auto now = std::chrono::steady_clock::now();
        g_cache.Expire(now);
    }
}

void Pelican::ChecksumCache::Expire(std::chrono::steady_clock::time_point now)
{
    std::unique_lock lock(m_mutex);
    for (auto iter = m_checksums.begin(); iter != m_checksums.end();) {
        if (iter->second.m_expiry < now) {
            for (int idx = 0; idx < static_cast<int>(XrdClCurl::ChecksumType::kUnknown); ++idx) {
                if (iter->second.m_available_checksums.Test(static_cast<XrdClCurl::ChecksumType>(idx))) {
                    m_checksum_map[idx].erase(iter->first);
                }
            }
            iter = m_checksums.erase(iter);
        } else {
            ++iter;
        }
    }
}

void
Pelican::ChecksumCache::Shutdown()
{
    {
        std::unique_lock lock(m_shutdown_lock);
        m_shutdown_requested = true;
        m_shutdown_requested_cv.notify_one();
    }

    if (m_expire_tid.joinable()) {
        m_expire_tid.join();
    }
}
