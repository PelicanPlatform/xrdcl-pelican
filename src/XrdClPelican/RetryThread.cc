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

#include "RetryThread.hh"

#include <algorithm>
#include <thread>

using namespace Pelican;

// Use heap-allocated state to avoid static destruction order issues —
// other static destructors may call into RetryThread after a normal
// static would have been destroyed.
namespace {

struct RetryState {
    std::mutex mutex;
    std::condition_variable cv;
    bool started = false;
    bool shutdown = false;
    std::thread thread;
    std::priority_queue<RetryThread::Entry, std::vector<RetryThread::Entry>,
                        std::greater<RetryThread::Entry>> queue;
    std::chrono::steady_clock::duration base_delay = std::chrono::milliseconds(100);
};

// Returns a reference to the state pointer so Shutdown() can delete and
// null it.  If called after Shutdown(), allocates a fresh (idle) state
// so late callers don't dereference nullptr.
RetryState *&statePtr() {
    static RetryState *s = new RetryState;
    return s;
}

RetryState &state() {
    auto *&p = statePtr();
    if (!p) p = new RetryState;
    return *p;
}

} // namespace

void
RetryThread::Start()
{
    auto &s = state();
    std::unique_lock lock(s.mutex);
    s.started = true;
    s.thread = std::thread(RetryThread::Run);
}

void
RetryThread::Shutdown()
{
    auto *&p = statePtr();
    if (!p) return;
    auto &s = *p;
    {
        std::unique_lock lock(s.mutex);
        if (!s.started) {
            delete p;
            p = nullptr;
            return;
        }
        s.shutdown = true;
        s.cv.notify_all();
    }
    s.thread.join();
    delete p;
    p = nullptr;
}

void
RetryThread::Submit(std::chrono::steady_clock::duration delay,
                    std::function<void()> operation)
{
    auto &s = state();
    {
        std::unique_lock lock(s.mutex);
        s.queue.push({Clock::now() + delay, std::move(operation)});
    }
    s.cv.notify_one();
}

void
RetryThread::SetBaseDelay(std::chrono::steady_clock::duration base)
{
    auto &s = state();
    std::unique_lock lock(s.mutex);
    s.base_delay = base;
}

std::chrono::steady_clock::duration
RetryThread::GetBaseDelay()
{
    auto &s = state();
    std::unique_lock lock(s.mutex);
    return s.base_delay;
}

std::chrono::steady_clock::duration
RetryThread::ComputeDelay(int attempt)
{
    static constexpr auto max_delay = std::chrono::duration_cast<std::chrono::steady_clock::duration>(std::chrono::seconds(30));
    auto base = GetBaseDelay();
    // base * 2^attempt, capped at max_delay
    auto delay = base * (1 << std::min(attempt, 15));
    return std::min(delay, max_delay);
}

void
RetryThread::Run()
{
    auto &s = state();
    while (true) {
        std::function<void()> op;
        {
            std::unique_lock lock(s.mutex);
            if (s.shutdown && s.queue.empty()) {
                return;
            }
            if (s.queue.empty()) {
                s.cv.wait(lock, [&s] { return s.shutdown || !s.queue.empty(); });
                if (s.shutdown && s.queue.empty()) {
                    return;
                }
            }
            // Wait until the earliest deadline or until woken for new work.
            auto deadline = s.queue.top().deadline;
            s.cv.wait_until(lock, deadline, [&s] {
                return s.shutdown ||
                       (!s.queue.empty() && s.queue.top().deadline <= Clock::now());
            });
            if (s.shutdown && s.queue.empty()) {
                return;
            }
            // Fire all entries whose deadlines have passed.
            if (!s.queue.empty() && s.queue.top().deadline <= Clock::now()) {
                op = std::move(const_cast<Entry &>(s.queue.top()).operation);
                s.queue.pop();
            } else {
                // Spurious wakeup or new entry pushed with an earlier deadline;
                // go back and recalculate.
                continue;
            }
        }
        // Invoke outside the lock.
        if (op) {
            op();
        }
    }
}
