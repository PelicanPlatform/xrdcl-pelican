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

#ifndef XRDCLCURLTAGSCHEDULER_HH
#define XRDCLCURLTAGSCHEDULER_HH

// TagScheduler: per-tag admission and dispatch for CurlOperation.
//
// A single unresponsive upstream origin ("black-holed" TCP connection
// that accepts SYN but never sends bytes) will otherwise hold every
// worker's slot until each curl handle hits the header timeout, on
// the order of a minute.  During that window a cache serving many
// origins looks unresponsive to everyone.
//
// This scheduler sits in front of HandlerQueue: producers Admit()
// operations under a tag (currently the origin hostname); a
// background dispatch happens on Consume() using a weighted random
// draw across eligible tags.  Two caps bound how much of the worker
// pool one tag can hold:
//
//   * PerTagStarvingPercent (default 25%) — while a transfer has
//     not yet received the first byte of response (via HeaderCallback)
//     it counts against this smaller cap.
//   * PerTagActivePercent (default 90%) — total (starving + active)
//     ceiling; even healthy tags cannot fully monopolise the pool.
//
// When either the global PendingBufferSize or the PerTagPendingSize
// is exceeded on submit, Admit() returns false and the caller must
// synthesise a "too many requests" error to the client.
//
// Weighting: each eligible tag is drawn with weight 1 / (1 + EMA)
// where EMA is the tag's exponentially-weighted average of active-
// worker count.  Lower EMA → more likely to be picked next, so tags
// that have been quiet get priority.  FIFO order within a tag is
// preserved.
//
// See docs/tag-scheduler-design.md for the full design; the
// "Contention and scaling" section justifies the single-mutex
// design and describes the sharding escape hatch.

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <unordered_map>
#include <vector>

namespace XrdCl {
    class Log;
}

namespace XrdClCurl {

class CurlOperation;

class TagScheduler {
public:
    struct Config {
        // Fractions expressed as integer percentages 0-100. Setting
        // a value to 0 or ≥100 disables that cap.
        int per_tag_starving_percent = 25;
        int per_tag_active_percent   = 90;
        // Total pending across all tags before we shed with a
        // TooManyRequests error. Setting to 0 leaves the scheduler
        // ENABLED but with an unbounded queue — dangerous; almost
        // always want a real value.
        int pending_buffer_size      = 200;
        // Per-tag pending cap. Setting to 0 disables the per-tag
        // FIFO cap (global cap alone applies).
        int per_tag_pending_size     = 50;
        // Time constant of the per-tag active-worker EMA.
        std::chrono::seconds ema_window{30};
    };

    // Construct a scheduler sized for `worker_count` workers.
    TagScheduler(unsigned worker_count, const Config &cfg, XrdCl::Log *logger);

    TagScheduler(const TagScheduler &) = delete;
    TagScheduler &operator=(const TagScheduler &) = delete;

    ~TagScheduler();

    // Attempt to admit `op` into the FIFO for `tag`.
    //
    // Returns true on accept: the scheduler now owns `op` and it
    // will be handed to a worker via Consume() at some future point.
    // The scheduler installs first-byte and done hooks on the op so
    // its own counters stay in sync.
    //
    // Returns false when either the global pending cap or the tag's
    // per-tag pending cap is exceeded; the caller must synthesise a
    // "too many requests" error for `op` and NOT enqueue it into any
    // other queue.
    bool Admit(std::string tag, std::shared_ptr<CurlOperation> op);

    // Block until an operation becomes dispatchable or `timeout`
    // elapses or the scheduler shuts down.  Returns nullptr on
    // timeout / shutdown.
    std::shared_ptr<CurlOperation> Consume(std::chrono::steady_clock::duration timeout);

    // Non-blocking variant.  Returns nullptr if nothing is
    // dispatchable right now.
    std::shared_ptr<CurlOperation> TryConsume();

    // Remove every queued operation whose deadline has passed and return
    // them so the caller can fail them outside the scheduler's lock (the
    // failure handler may submit new work, which would re-enter Admit).
    //
    // Without this an operation parked here has no deadline at all:
    // HandlerQueue::Expire() only walks HandlerQueue::m_ops, which stays
    // empty once a scheduler is attached, and nothing above the plugin
    // supplies one either -- an XrdPfc read waits untimed.  A dispatch that
    // never happens would otherwise be a permanently stuck caller.
    //
    // Returned operations have had their scheduler hooks cleared: they never
    // reached a worker, so they hold no active/starving slot and must not
    // release one when they are failed.
    std::vector<std::shared_ptr<CurlOperation>> Expire();

    // Called from the central monitor thread (Factory::Monitor) at
    // roughly its 5-second cadence, or more frequently if desired.
    // Advances the per-tag active-worker EMA snapshot.
    void OnMonitorTick();

    // Signals the scheduler to wake any parked Consume() calls and
    // stop accepting new admits.  In-flight ops are unaffected.
    void Shutdown();

    // JSON summary of the scheduler's current state; suitable for
    // inclusion in Factory::Monitor's per-tick rollup.
    std::string GetMonitoringJson() const;

    // Total pending count across all tags.  Cheap; takes m_mu.
    int Pending() const;

private:
    struct TagState {
        // FIFO of operations queued for this tag.
        std::deque<std::shared_ptr<CurlOperation>> pending;
        // In-flight totals. `starving` <= `active` always.
        int active   = 0;
        int starving = 0;
        // Monotonic per-tag lifetime counters — exposed via
        // GetMonitoringJson for operator visibility into which
        // origin drove the 429s.
        std::uint64_t admits  = 0;
        std::uint64_t rejects = 0;
    };

    using EmaMap = std::unordered_map<std::string, double>;

    // Set once by the constructor; never mutated afterwards.
    unsigned m_worker_count;
    Config   m_cfg;
    int      m_starving_cap;
    int      m_active_cap;
    XrdCl::Log *m_logger;

    // Everything below is protected by m_mu.
    mutable std::mutex m_mu;
    std::condition_variable m_cv;
    std::unordered_map<std::string, TagState> m_tags;
    int m_total_pending = 0;
    bool m_shutdown = false;
    // Time we last computed the EMA snapshot; used to compute the
    // decay factor for the next update.
    std::chrono::steady_clock::time_point m_last_tick;
    // For the weighted random draw.  mt19937_64 is fine here — it's
    // called at most once per dispatch, not per byte.
    std::mt19937_64 m_rng;
    // Rejection / admission stats for GetMonitoringJson.
    std::uint64_t m_admits          = 0;
    std::uint64_t m_rejects         = 0;
    std::uint64_t m_rejects_global  = 0; // subset: global pending full
    std::uint64_t m_rejects_per_tag = 0; // subset: per-tag FIFO full

    // Per-tag active-worker EMA; updated by OnMonitorTick and read
    // by PickTag_locked. Refreshed every monitor tick.
    EmaMap m_ema_snapshot;

    // Liveness handle shared with the per-op completion hooks. A hook holds
    // m_life->mu while calling OnFirstByte/OnDone; the destructor clears
    // m_life->self under the same mutex first, so a hook can never dispatch
    // into a destroyed scheduler.
    struct Liveness {
        std::mutex    mu;
        TagScheduler *self = nullptr;
    };
    std::shared_ptr<Liveness> m_life{std::make_shared<Liveness>()};

    // Convert a percentage of m_worker_count into an absolute cap,
    // with a floor of 1 so tiny worker pools always dispatch
    // something. 0 / ≥100 percent map to "no cap" (== m_worker_count).
    static int PercentToCap(unsigned worker_count, int percent);

    // Called with m_mu held.  Iterates m_tags, considers each one's
    // caps and EMA, and picks a tag by weighted random draw.
    // Returns "" if nothing is dispatchable right now.
    std::string PickTag_locked();

    // Hooks the scheduler installs on each admitted op.
    void OnFirstByte(const std::string &tag);
    void OnDone(const std::string &tag, bool still_starving);
};

}

#endif // XRDCLCURLTAGSCHEDULER_HH
