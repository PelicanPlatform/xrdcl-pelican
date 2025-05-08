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

#include "CurlFactory.hh"
#include "CurlFile.hh"
#include "CurlUtil.hh"
#include "CurlOps.hh"
#include "CurlWorker.hh"
#include "CurlFilesystem.hh"
#include "ParseTimeout.hh"

#include "XrdCl/XrdClConstants.hh"
#include "XrdCl/XrdClDefaultEnv.hh"
#include "XrdCl/XrdClLog.hh"
#include "XrdVersion.hh"

XrdVERSIONINFO(XrdClGetPlugIn, XrdClGetPlugIn)

using namespace XrdClCurl;

struct timespec
Factory::GetHeaderTimeoutWithDefault(time_t oper_timeout)
{
    if (oper_timeout == 0) {
        int val = XrdCl::DefaultRequestTimeout;
        XrdCl::DefaultEnv::GetEnv()->GetInt( "RequestTimeout", val );
        oper_timeout = val;
    }
    if (oper_timeout <= 0) {
        return {0, 0};
    }
    return {oper_timeout, 0};
}

bool Factory::m_initialized = false;
std::shared_ptr<XrdClCurl::HandlerQueue> Factory::m_queue;
std::vector<std::unique_ptr<XrdClCurl::CurlWorker>> Factory::m_workers;
XrdCl::Log *Factory::m_log = nullptr;
std::once_flag Factory::m_init_once;

Factory::Factory() {
    std::call_once(m_init_once, [&] {
        m_log = XrdCl::DefaultEnv::GetLog();
        if (!m_log) {
            return;
        }
        m_log->SetTopicName(kLogXrdClCurl, "XrdClCurl");

        auto env = XrdCl::DefaultEnv::GetEnv();
        if (!env) {
            return;
        }
        // The default location of the CA certificate file and/or directory
        // TODO: Align with upstream XrdCl
        env->PutString("CurlCertFile", "");
        env->ImportString("CurlCertFile", "XRD_PELICANCERTFILE");
        env->ImportString("CurlCertFile", "XRD_CURLCERTFILE");
        env->PutString("CurlCertDir", "");
        env->ImportString("CurlCertDir", "XRD_PELICANCERTDIR");
        env->ImportString("CurlCertDir", "XRD_CURLCERTDIR");

        // The default location of the connection broker socket
        env->PutString("PelicanBrokerSocket", "");
        env->ImportString("PelicanBrokerSocket", "XRD_PELICANBROKERSOCKET");

        // The minimum value we will accept from the request for a header timeout.
        // (i.e., the amount of time the plugin will wait to receive headers from the remote server)
        env->PutString("CurlMinimumHeaderTimeout", "");
        env->ImportString("CurlMinimumHeaderTimeout", "XRD_PELICANMINIMUMHEADERTIMEOUT");
        env->ImportString("CurlMinimumHeaderTimeout", "XRD_CURLMINIMUMHEADERTIMEOUT");

        // The default value of the header timeout (the amount of time the plugin will wait)
        // to receive headers from the remote server.
        env->PutString("CurlDefaultHeaderTimeout", "");
        env->ImportString("CurlDefaultHeaderTimeout", "XRD_PELICANDEFAULTHEADERTIMEOUT");
        env->ImportString("CurlDefaultHeaderTimeout", "XRD_CURLDEFAULTHEADERTIMEOUT");

        // The default location of the cache token
        env->PutString("PelicanCacheTokenLocation", "");
        env->ImportString("PelicanCacheTokenLocation", "XRD_PELICANCACHETOKENLOCATION");

        // The number of pending operations allowed in the global work queue.
        env->PutInt("CurlMaxPendingOps", XrdClCurl::HandlerQueue::GetDefaultMaxPendingOps());
        env->ImportInt("CurlMaxPendingOps", "XRD_CURLMAXPENDINGOPS");
        int max_pending = XrdClCurl::HandlerQueue::GetDefaultMaxPendingOps();
        if (env->GetInt("CurlMaxPendingOps", max_pending)) {
            if (max_pending <= 0 || max_pending > 10'000'000) {
                m_log->Error(kLogXrdClCurl,
                    "Invalid value for the maximum number of pending operations in the global work queue (%d); using default value of %d",
                    max_pending,
                    XrdClCurl::HandlerQueue::GetDefaultMaxPendingOps());
                max_pending = XrdClCurl::HandlerQueue::GetDefaultMaxPendingOps();
                env->PutInt("CurlMaxPendingOps", max_pending);
            }
            m_log->Debug(kLogXrdClCurl, "Using %d pending operations in the global work queue", max_pending);
        }
        m_queue.reset(new XrdClCurl::HandlerQueue(max_pending));

        // The number of threads to use for curl operations.
        env->PutInt("CurlNumThreads", m_poll_threads);
        env->ImportInt("CurlNumThreads", "XRD_CURLNUMTHREADS");
        int num_threads = m_poll_threads;
        if (env->GetInt("CurlNumThreads", num_threads)) {
            if (num_threads <= 0 || num_threads > 1'000) {
                m_log->Error(kLogXrdClCurl, "Invalid value for the number of threads to use for curl operations (%d); using default value of %d", num_threads, m_poll_threads);
                num_threads = m_poll_threads;
                env->PutInt("CurlNumThreads", num_threads);
            }
            m_log->Debug(kLogXrdClCurl, "Using %d threads for curl operations", num_threads);
        }

        // The stall timeout to use for transfer operations.
        env->PutInt("CurlStallTimeout", XrdClCurl::CurlOperation::GetDefaultStallTimeout());
        env->ImportInt("CurlStallTimeout", "XRD_CURLSTALLTIMEOUT");
        int stall_timeout = XrdClCurl::CurlOperation::GetDefaultStallTimeout();
        if (env->GetInt("CurlStallTimeout", stall_timeout)) {
            if (stall_timeout < 0 || stall_timeout > 86'400) {
                m_log->Error(kLogXrdClCurl, "Invalid value for the stall timeout (%d); using default value of %d", stall_timeout, XrdClCurl::CurlOperation::GetDefaultStallTimeout());
                stall_timeout = XrdClCurl::CurlOperation::GetDefaultStallTimeout();
                env->PutInt("CurlStallTimeout", stall_timeout);
            }
            m_log->Debug(kLogXrdClCurl, "Using %d seconds for the stall timeout", stall_timeout);
        }
        XrdClCurl::CurlOperation::SetStallTimeout(stall_timeout);

        // The slow transfer rate, in bytes per second, for timing out slow uploads/downloads.
        env->PutInt("CurlSlowRateBytesSec", XrdClCurl::CurlOperation::GetDefaultSlowRateBytesSec());
        env->ImportInt("CurlSlowRateBytesSec", "XRD_CURLSLOWRATEBYTESSEC");
        int slow_xfer_rate = XrdClCurl::CurlOperation::GetDefaultSlowRateBytesSec();
        if (env->GetInt("CurlSlowRateBytesSec", slow_xfer_rate)) {
            if (slow_xfer_rate < 0 || slow_xfer_rate > (1024 * 1024 * 1024)) {
                m_log->Error(kLogXrdClCurl, "Invalid value for the slow transfer rate threshold (%d); using default value of %d", stall_timeout, XrdClCurl::CurlOperation::GetDefaultSlowRateBytesSec());
                slow_xfer_rate = XrdClCurl::CurlOperation::GetDefaultSlowRateBytesSec();
                env->PutInt("CurlSlowRateBytesSec", slow_xfer_rate);
            }
            m_log->Debug(kLogXrdClCurl, "Using %d bytes/sec for the slow transfer rate threshold", slow_xfer_rate);
        }
        XrdClCurl::CurlOperation::SetSlowRateBytesSec(slow_xfer_rate);

        // Note several of these also import from the Pelican variant of the environment variable
        // as a backward compatibility mechanism.
        env->PutString("CurlClientCertFile", "");
        env->ImportString("CurlClientCertFile", "XRD_PELICANCLIENTCERTFILE");
        env->ImportString("CurlClientCertFile", "XRD_CURLCLIENTCERTFILE");
        env->PutString("CurlClientKeyFile", "");
        env->ImportString("CurlClientKeyFile", "XRD_PELICANCLIENTKEYFILE");
        env->ImportString("CurlClientKeyFile", "XRD_CURLCLIENTKEYFILE");

        // Determine the minimum header timeout.  It's somewhat arbitrarily defaulted to 2s; below
        // that and timeouts could be caused by OS scheduling noise.  If the client has unreasonable
        // expectations of the origin, we don't want to cause it to generate lots of origin-side load.
        std::string val;
        struct timespec mct{2, 0};
        if (env->GetString("CurlMinimumHeaderTimeout", val) && !val.empty()) {
            std::string errmsg;
            if (!ParseTimeout(val, mct, errmsg)) {
                m_log->Error(kLogXrdClCurl, "Failed to parse the minimum client timeout (%s): %s", val.c_str(), errmsg.c_str());
            }
        }
        XrdClCurl::File::SetMinimumHeaderTimeout(mct);

        // Pelican-specific code: in the future, simply use the XrdCl-provided timeout for this layer
        //
        // The pelican client has historically used 10s as its header timeout (waiting for a response from the cache).
        // Have the cache's default header timeout for the origin be slightly less than this to better support older
        // clients that don't specify the timeout in their request.
        struct timespec dht{9, 500'000'000};
        if (env->GetString("PelicanDefaultHeaderTimeout", val)) {
            std::string errmsg;
            if (!ParseTimeout(val, dht, errmsg)) {
                m_log->Error(kLogXrdClCurl, "Failed to parse the default header timeout (%s): %s", val.c_str(), errmsg.c_str());
            }
        }
        XrdClCurl::File::SetDefaultHeaderTimeout(dht);

        // Start up the cache for the OPTIONS response
        auto &cache = XrdClCurl::VerbsCache::Instance();

        // Startup curl workers after we've set the configs to avoid race conditions
        for (unsigned idx=0; idx<m_poll_threads; idx++) {
            m_workers.emplace_back(new XrdClCurl::CurlWorker(m_queue, cache, m_log));
            std::thread t(XrdClCurl::CurlWorker::RunStatic, m_workers.back().get());
            t.detach();
        }

        m_initialized = true;
    });
}

void
Factory::Produce(std::unique_ptr<XrdClCurl::CurlOperation> operation)
{
    m_queue->Produce(std::move(operation));
}

XrdCl::FilePlugIn *
Factory::CreateFile(const std::string & /*url*/) {
    if (!m_initialized) {return nullptr;}
    return new File(m_queue, m_log);
}

XrdCl::FileSystemPlugIn *
Factory::CreateFileSystem(const std::string & url) {
    if (!m_initialized) {return nullptr;}
    return new Filesystem(url, m_queue, m_log);
}

extern "C"
{
    void *XrdClGetPlugIn(const void*)
    {
        return static_cast<void*>(new Factory());
    }
}
