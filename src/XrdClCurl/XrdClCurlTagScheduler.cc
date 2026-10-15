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

#include "XrdClCurlTagScheduler.hh"

#include "XrdClCurlOps.hh"
#include "XrdClCurlUtil.hh"  // For kLogXrdClCurl

#include <XrdCl/XrdClLog.hh>

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <sstream>

using XrdClCurl::TagScheduler;

TagScheduler::TagScheduler(unsigned worker_count, const Config &cfg, XrdCl::Log *logger)
  : m_worker_count(std::max<unsigned>(worker_count, 1u))
  , m_cfg(cfg)
  , m_starving_cap(PercentToCap(m_worker_count, cfg.per_tag_starving_percent))
  , m_active_cap(PercentToCap(m_worker_count, cfg.per_tag_active_percent))
  , m_logger(logger)
  , m_last_tick(std::chrono::steady_clock::now())
  , m_rng(std::random_device{}())
{
    m_life->self = this;
    if (m_logger) {
        m_logger->Debug(kLogXrdClCurl,
            "TagScheduler: worker_count=%u starving_cap=%d active_cap=%d "
            "pending_buffer=%d per_tag_pending=%d ema_seconds=%lld",
            m_worker_count, m_starving_cap, m_active_cap,
            m_cfg.pending_buffer_size, m_cfg.per_tag_pending_size,
            static_cast<long long>(m_cfg.ema_window.count()));
    }
}

TagScheduler::~TagScheduler()
{
    // Stop the completion hooks from dispatching into this scheduler before
    // we tear anything down.
    {
        std::lock_guard<std::mutex> life_lock(m_life->mu);
        m_life->self = nullptr;
    }
    Shutdown();
}

int TagScheduler::PercentToCap(unsigned worker_count, int percent)
{
    // Percent <=0 or >=100 disables the cap (any tag may hold the
    // entire pool). Positive percentages are ceiling-divided so a
    // small pool (say 4 workers × 25%) still allows at least 1 slot.
    if (percent <= 0 || percent >= 100) {
        return static_cast<int>(worker_count);
    }
    int cap = static_cast<int>((worker_count * static_cast<unsigned>(percent) + 99u) / 100u);
    return std::max(cap, 1);
}

bool TagScheduler::Admit(std::string tag, std::shared_ptr<CurlOperation> op)
{
    if (!op) {
        return false;
    }
    // Reason for a rejection, captured under the lock and reported to
    // the logger after we release it. Logging is I/O and can call
    // arbitrary sinks; we don't want it inside the scheduler's hot
    // path critical section.
    enum class RejectReason { Accepted, GlobalFull, PerTagFull };
    RejectReason reject_reason = RejectReason::Accepted;
    int total_pending_at_reject = 0;
    size_t per_tag_pending_at_reject = 0;

    std::unique_lock<std::mutex> lock(m_mu);
    if (m_shutdown) {
        return false;
    }
    if (m_cfg.pending_buffer_size > 0 && m_total_pending >= m_cfg.pending_buffer_size) {
        ++m_rejects;
        ++m_rejects_global;
        ++m_tags[tag].rejects;
        reject_reason = RejectReason::GlobalFull;
        total_pending_at_reject = m_total_pending;
        lock.unlock();
        if (m_logger) {
            m_logger->Debug(kLogXrdClCurl,
                "TagScheduler: rejecting admit for tag '%s' — global pending %d reached cap %d",
                tag.c_str(), total_pending_at_reject, m_cfg.pending_buffer_size);
        }
        return false;
    }
    auto &state = m_tags[tag];
    if (m_cfg.per_tag_pending_size > 0 &&
        static_cast<int>(state.pending.size()) >= m_cfg.per_tag_pending_size) {
        ++m_rejects;
        ++m_rejects_per_tag;
        ++state.rejects;
        reject_reason = RejectReason::PerTagFull;
        per_tag_pending_at_reject = state.pending.size();
        lock.unlock();
        if (m_logger) {
            m_logger->Debug(kLogXrdClCurl,
                "TagScheduler: rejecting admit for tag '%s' — per-tag pending %zu reached cap %d",
                tag.c_str(), per_tag_pending_at_reject, m_cfg.per_tag_pending_size);
        }
        return false;
    }
    (void)reject_reason; // Reserved for future use if we ever fall through.

    // Install hooks BEFORE enqueue so a Consume racing on this
    // thread cannot pull the op out and start work before the hooks
    // are set.  Both hooks share a shared_ptr<atomic<bool>> so the
    // OnDone hook can tell whether the op ever moved out of the
    // starving bucket, without cross-file coupling to CurlOperation
    // internals.
    auto first_byte = std::make_shared<std::atomic<bool>>(false);
    auto live = m_life;
    op->m_on_first_byte = [live, tag, first_byte]() {
        if (!first_byte->exchange(true, std::memory_order_relaxed)) {
            std::lock_guard<std::mutex> life_lock(live->mu);
            if (live->self) live->self->OnFirstByte(tag);
        }
    };
    op->m_on_done = [live, tag, first_byte]() {
        bool still_starving = !first_byte->load(std::memory_order_relaxed);
        std::lock_guard<std::mutex> life_lock(live->mu);
        if (live->self) live->self->OnDone(tag, still_starving);
    };

    state.pending.emplace_back(std::move(op));
    ++m_total_pending;
    ++m_admits;
    ++state.admits;
    m_cv.notify_one();
    return true;
}

std::shared_ptr<XrdClCurl::CurlOperation>
TagScheduler::Consume(std::chrono::steady_clock::duration timeout)
{
    auto deadline = std::chrono::steady_clock::now() + timeout;
    std::unique_lock<std::mutex> lock(m_mu);
    while (true) {
        if (m_shutdown) {
            return nullptr;
        }
        auto tag = PickTag_locked();
        if (!tag.empty()) {
            auto &state = m_tags[tag];
            auto op = std::move(state.pending.front());
            state.pending.pop_front();
            --m_total_pending;
            state.active++;
            state.starving++;
            if (state.pending.empty() && state.active == 0 && state.starving == 0) {
                m_tags.erase(tag);
            }
            return op;
        }
        if (m_cv.wait_until(lock, deadline) == std::cv_status::timeout) {
            return nullptr;
        }
    }
}

std::shared_ptr<XrdClCurl::CurlOperation> TagScheduler::TryConsume()
{
    std::unique_lock<std::mutex> lock(m_mu);
    if (m_shutdown) return nullptr;
    auto tag = PickTag_locked();
    if (tag.empty()) {
        return nullptr;
    }
    auto &state = m_tags[tag];
    auto op = std::move(state.pending.front());
    state.pending.pop_front();
    --m_total_pending;
    state.active++;
    state.starving++;
    return op;
}

std::vector<std::shared_ptr<XrdClCurl::CurlOperation>> TagScheduler::Expire()
{
    std::vector<std::shared_ptr<CurlOperation>> expired;
    auto now = std::chrono::steady_clock::now();

    std::unique_lock<std::mutex> lock(m_mu);
    for (auto it = m_tags.begin(); it != m_tags.end(); ) {
        auto &state = it->second;
        for (auto pit = state.pending.begin(); pit != state.pending.end(); ) {
            auto &op = *pit;
            if (!op || op->GetOperationExpiry() >= now) {
                ++pit;
                continue;
            }
            // The op never reached Consume(), so it holds no active/starving
            // slot.  Drop the hooks before handing it back: otherwise the
            // Fail() the caller is about to issue fires OnDone and decrements
            // counters belonging to some other, genuinely in-flight op.
            op->m_on_first_byte = nullptr;
            op->m_on_done = nullptr;
            expired.push_back(std::move(op));
            pit = state.pending.erase(pit);
            --m_total_pending;
        }
        if (state.pending.empty() && state.active == 0 && state.starving == 0) {
            it = m_tags.erase(it);
        } else {
            ++it;
        }
    }
    lock.unlock();

    if (!expired.empty() && m_logger) {
        m_logger->Debug(kLogXrdClCurl,
            "TagScheduler: expired %zu queued operation(s) past their deadline",
            expired.size());
    }
    return expired;
}

std::string TagScheduler::PickTag_locked()
{
    // Build eligibility list and cumulative weight.
    struct Candidate {
        const std::string *tag;
        double weight;
    };
    // Small-vector optimisation: 32 tags is more than a realistic
    // cache is talking to at any one moment.
    Candidate cands[32];
    size_t n = 0;
    double total_weight = 0.0;
    for (auto &entry : m_tags) {
        auto &state = entry.second;
        if (state.pending.empty()) continue;
        if (state.starving >= m_starving_cap) continue;
        if (state.active   >= m_active_cap)   continue;
        double ema = 0.0;
        auto it = m_ema_snapshot.find(entry.first);
        if (it != m_ema_snapshot.end()) ema = it->second;
        double w = 1.0 / (1.0 + ema);
        if (n < sizeof(cands) / sizeof(cands[0])) {
            cands[n++] = { &entry.first, w };
        }
        total_weight += w;
    }
    if (n == 0) return {};

    std::uniform_real_distribution<double> dist(0.0, total_weight);
    double r = dist(m_rng);
    for (size_t i = 0; i < n; ++i) {
        r -= cands[i].weight;
        if (r <= 0.0) return *cands[i].tag;
    }
    // Floating-point drift; fall back to last candidate.
    return *cands[n - 1].tag;
}

void TagScheduler::OnFirstByte(const std::string &tag)
{
    std::unique_lock<std::mutex> lock(m_mu);
    auto it = m_tags.find(tag);
    if (it == m_tags.end()) return;
    if (it->second.starving > 0) {
        it->second.starving--;
        m_cv.notify_one(); // freeing a starving slot may unblock dispatch
    }
}

void TagScheduler::OnDone(const std::string &tag, bool still_starving)
{
    std::unique_lock<std::mutex> lock(m_mu);
    auto it = m_tags.find(tag);
    if (it == m_tags.end()) return;
    auto &state = it->second;
    if (state.active > 0) {
        state.active--;
    }
    if (still_starving && state.starving > 0) {
        state.starving--;
    }
    if (state.pending.empty() && state.active == 0 && state.starving == 0) {
        m_tags.erase(it);
    }
    m_cv.notify_one();
}

void TagScheduler::OnMonitorTick()
{
    // Compute the decay factor and update the EMA under m_mu.
    // The critical section is short: at most `m_tags.size() +
    // m_ema_snapshot.size()` hash operations. See "Contention and
    // scaling" in docs/tag-scheduler-design.md for why this is
    // acceptable at the scales we care about.
    std::unique_lock<std::mutex> lock(m_mu);
    auto now = std::chrono::steady_clock::now();
    auto dt = now - m_last_tick;
    m_last_tick = now;
    if (dt <= std::chrono::steady_clock::duration::zero() || m_cfg.ema_window.count() <= 0) {
        return;
    }
    double window_seconds = static_cast<double>(m_cfg.ema_window.count());
    double dt_seconds =
        std::chrono::duration_cast<std::chrono::duration<double>>(dt).count();
    double alpha = 1.0 - std::exp(-dt_seconds / window_seconds);

    // Decay all known EMAs first.
    for (auto &kv : m_ema_snapshot) {
        kv.second *= (1.0 - alpha);
    }
    // Fold in the current active counts.
    for (auto &entry : m_tags) {
        double &e = m_ema_snapshot[entry.first]; // inserts 0 if absent
        e += alpha * static_cast<double>(entry.second.active);
    }
    // Drop tags that have decayed to noise.
    for (auto it = m_ema_snapshot.begin(); it != m_ema_snapshot.end(); ) {
        if (it->second < 1e-6) it = m_ema_snapshot.erase(it);
        else ++it;
    }
}

void TagScheduler::Shutdown()
{
    std::unique_lock<std::mutex> lock(m_mu);
    if (m_shutdown) return;
    m_shutdown = true;
    m_cv.notify_all();
}

// Escape a tag key for JSON string context. Origins are hostnames, so
// this only needs to guard against the handful of characters that
// break JSON parsing; we do not attempt full unicode escaping.
static void AppendJsonString(std::ostringstream &os, const std::string &s)
{
    os << '"';
    for (char c : s) {
        switch (c) {
            case '"':  os << "\\\""; break;
            case '\\': os << "\\\\"; break;
            case '\b': os << "\\b";  break;
            case '\f': os << "\\f";  break;
            case '\n': os << "\\n";  break;
            case '\r': os << "\\r";  break;
            case '\t': os << "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x",
                                  static_cast<unsigned int>(static_cast<unsigned char>(c)));
                    os << buf;
                } else {
                    os << c;
                }
        }
    }
    os << '"';
}

std::string TagScheduler::GetMonitoringJson() const
{
    std::unique_lock<std::mutex> lock(m_mu);
    std::ostringstream os;
    os << "{"
       << "\"pending\":" << m_total_pending
       << ",\"tags\":" << m_tags.size()
       << ",\"admits\":" << m_admits
       << ",\"rejects\":" << m_rejects
       << ",\"rejects_global\":" << m_rejects_global
       << ",\"rejects_per_tag\":" << m_rejects_per_tag
       << ",\"starving_cap\":" << m_starving_cap
       << ",\"active_cap\":" << m_active_cap;
    // Per-tag detail: emit an array of {origin, pending, active,
    // starving, ema, admits, rejects} objects, one per tracked
    // origin. This is what operators grep to see WHICH origin
    // drove the 429s.
    os << ",\"per_tag\":[";
    bool first = true;
    for (const auto &entry : m_tags) {
        if (!first) os << ",";
        first = false;
        const auto &st = entry.second;
        double ema = 0.0;
        auto ema_it = m_ema_snapshot.find(entry.first);
        if (ema_it != m_ema_snapshot.end()) ema = ema_it->second;
        os << "{\"origin\":";
        AppendJsonString(os, entry.first);
        os << ",\"pending\":" << st.pending.size()
           << ",\"active\":" << st.active
           << ",\"starving\":" << st.starving
           << ",\"ema\":" << ema
           << ",\"admits\":" << st.admits
           << ",\"rejects\":" << st.rejects
           << "}";
    }
    os << "]}";
    return os.str();
}

int TagScheduler::Pending() const
{
    std::unique_lock<std::mutex> lock(m_mu);
    return m_total_pending;
}
