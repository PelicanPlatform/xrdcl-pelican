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

#include "RetryThread.hh"

#include <algorithm>
#include <thread>

using namespace Pelican;

// Use function-local statics to control destruction order and avoid
// accessing destroyed mutexes during static teardown.
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

// Intentionally leaked so the mutex/cv survive static destruction.
RetryState &state() {
    static auto *s = new RetryState;
    return *s;
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
    auto &s = state();
    {
        std::unique_lock lock(s.mutex);
        if (!s.started) {
            return;
        }
        s.shutdown = true;
        s.cv.notify_all();
    }
    s.thread.join();
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
