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

#include "XrdClCurlOptionsCache.hh"

#include <curl/curl.h>

#include <thread>

XrdClCurl::VerbsCache XrdClCurl::VerbsCache::g_cache;
std::once_flag XrdClCurl::VerbsCache::m_expiry_launch;
std::mutex XrdClCurl::VerbsCache::m_shutdown_lock;
std::condition_variable XrdClCurl::VerbsCache::m_shutdown_requested_cv;
bool XrdClCurl::VerbsCache::m_shutdown_requested = false;
std::thread XrdClCurl::VerbsCache::m_expire_tid;

// shutdown trigger, must be last of the static members
XrdClCurl::VerbsCache::shutdown_s XrdClCurl::VerbsCache::m_shutdowns;

XrdClCurl::VerbsCache & XrdClCurl::VerbsCache::Instance() {
    std::unique_lock lk(m_shutdown_lock);
    if (!m_shutdown_requested) {
        std::call_once(m_expiry_launch, [] {
            std::thread t(VerbsCache::ExpireThread);
            m_expire_tid = std::move(t);
        });
    }
    return g_cache;
}

void XrdClCurl::VerbsCache::ExpireThread()
{
    while (true) {
        {
            std::unique_lock lock(m_shutdown_lock);
            m_shutdown_requested_cv.wait_for(
                lock,
                std::chrono::seconds(30),
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

void XrdClCurl::VerbsCache::Expire(std::chrono::steady_clock::time_point now)
{
    std::unique_lock lock(m_mutex);
    for (auto iter = m_verbs_map.begin(); iter != m_verbs_map.end();) {
        if (iter->second.m_expiry < now) {
            iter = m_verbs_map.erase(iter);
        } else {
            ++iter;
        }
    }
}

void
XrdClCurl::VerbsCache::Shutdown()
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
