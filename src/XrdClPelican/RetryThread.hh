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

#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <vector>

namespace Pelican {

// A singleton thread that fires deferred retry operations at their scheduled
// deadlines.  Operations are kept in a min-heap ordered by deadline.
//
// Usage:
//   RetryThread::Submit(std::chrono::milliseconds(200), [=]{ ... });
//
class RetryThread {
public:
    using Clock = std::chrono::steady_clock;

    struct Entry {
        Clock::time_point deadline;
        std::function<void()> operation;

        // Min-heap: earliest deadline has highest priority.
        bool operator>(const Entry &other) const {
            return deadline > other.deadline;
        }
    };

    // Submit an operation to be invoked after `delay` from now.
    static void Submit(std::chrono::steady_clock::duration delay,
                       std::function<void()> operation);

    // Start the background thread (called once during plugin init).
    static void Start();

    // Request shutdown and wait for the thread to drain.
    static void Shutdown();

    // Set the base delay for exponential backoff (default 100ms).
    static void SetBaseDelay(std::chrono::steady_clock::duration base);

    // Get the base delay.
    static std::chrono::steady_clock::duration GetBaseDelay();

    // Compute the delay for a given attempt number (0-based) using
    // exponential backoff: base_delay * 2^attempt, capped at 30s.
    static std::chrono::steady_clock::duration ComputeDelay(int attempt);

private:
    static void Run();
};

} // namespace Pelican
