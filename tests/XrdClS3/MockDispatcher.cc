/****************************************************************
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

#include "MockDispatcher.hh"

#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>

namespace {

class Dispatcher {
public:
    Dispatcher() {
        // Detached: the dispatcher is never destroyed, and its thread idles in
        // Run() once drained, so it does not hold up process exit.
        std::thread(&Dispatcher::Run, this).detach();
    }

    void Enqueue(std::function<void()> work) {
        std::lock_guard lock(m_mutex);
        m_queue.emplace_back(std::move(work));
        m_cv.notify_all();
    }

    bool Drain(std::chrono::milliseconds timeout) {
        std::unique_lock lock(m_mutex);
        return m_cv.wait_for(lock, timeout, [&] { return m_queue.empty() && !m_busy; });
    }

private:
    void Run() {
        std::unique_lock lock(m_mutex);
        while (true) {
            m_cv.wait(lock, [&] { return !m_queue.empty(); });
            auto work = std::move(m_queue.front());
            m_queue.pop_front();
            m_busy = true;
            lock.unlock();
            work();
            // Destroy the callable before reporting idle so nothing it holds
            // outlives a successful Drain().
            work = nullptr;
            lock.lock();
            m_busy = false;
            m_cv.notify_all();
        }
    }

    std::mutex m_mutex;
    std::condition_variable m_cv;
    std::deque<std::function<void()>> m_queue;
    bool m_busy{false};
};

Dispatcher &GetDispatcher() {
    // Intentionally leaked; see the constructor.
    static auto *dispatcher = new Dispatcher();
    return *dispatcher;
}

} // namespace

void
XrdClS3Mock::Dispatch(XrdCl::ResponseHandler *handler, XrdCl::XRootDStatus *status, XrdCl::AnyObject *response)
{
    if (!handler) {
        delete status;
        delete response;
        return;
    }
    GetDispatcher().Enqueue([handler, status, response] {
        handler->HandleResponse(status, response);
    });
}

bool
XrdClS3Mock::Drain(std::chrono::milliseconds timeout)
{
    return GetDispatcher().Drain(timeout);
}
