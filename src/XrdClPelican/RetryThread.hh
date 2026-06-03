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
