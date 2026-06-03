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

#include "../common/XrdClCurlParseTimeout.hh"
#include "PelicanFactory.hh"
#include "PelicanFile.hh"
#include "PelicanFilesystem.hh"
#include "RetryThread.hh"
#include "WritebackDB.hh"

#include <XrdCl/XrdClDefaultEnv.hh>
#include <XrdCl/XrdClLog.hh>
#include <XrdCl/XrdClPlugInInterface.hh>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <thread>

XrdVERSIONINFO(XrdClGetPlugIn, XrdClGetPlugIn)

using namespace Pelican;

std::atomic<std::chrono::steady_clock::duration::rep> PelicanFactory::m_maintenance_interval = std::chrono::steady_clock::duration(std::chrono::seconds(5)).count();
bool PelicanFactory::m_maintenance_update = false;
bool PelicanFactory::m_initialized = false;
XrdCl::Log *PelicanFactory::m_log = nullptr;
std::string PelicanFactory::m_token_contents;
std::string PelicanFactory::m_token_file;
std::mutex PelicanFactory::m_token_mutex;
std::once_flag PelicanFactory::m_init_once;
std::mutex PelicanFactory::m_shutdown_lock;
std::condition_variable PelicanFactory::m_shutdown_requested_cv;
bool PelicanFactory::m_shutdown_requested = false;
std::thread PelicanFactory::m_maintenance_thread;

namespace {

void ltrim(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
}

inline void rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), s.end());
}

}

PelicanFactory::PelicanFactory() {
    std::call_once(m_init_once, [&] {
        m_log = XrdCl::DefaultEnv::GetLog();
        if (!m_log) {
            return;
        }
        m_log->SetTopicName(kLogXrdClPelican, "XrdClPelican");

        auto env = XrdCl::DefaultEnv::GetEnv();
        if (!env) {
            return;
        }
        env->PutString("PelicanCertFile", "");
        env->ImportString( "PelicanCertFile", "XRD_PELICANCERTFILE");
        env->PutString("PelicanCertDir", "");
        env->ImportString("PelicanCertDir", "XRD_PELICANCERTDIR");
        env->PutString("PelicanBrokerSocket", "");
        env->ImportString("PelicanBrokerSocket", "XRD_PELICANBROKERSOCKET");

        // The minimum value we will accept from the request for a header timeout.
        // (i.e., the amount of time the plugin will wait to receive headers from the origin)
        env->PutString("PelicanMinimumHeaderTimeout", "");
        env->ImportString("PelicanMinimumHeaderTimeout", "XRD_PELICANMINIMUMHEADERTIMEOUT");
        // The default value of the header timeout (the amount of time the plugin will wait)
        // to receive headers from the origin.
        env->PutString("PelicanDefaultHeaderTimeout", "");
        env->ImportString("PelicanDefaultHeaderTimeout", "XRD_PELICANDEFAULTHEADERTIMEOUT");

	    // The default values of the federation metadata lookup timeout.
        env->PutString("PelicanFederationMetadataTimeout", "");
        env->ImportString("PelicanFederationMetadataTimeout", "XRD_PELICANFEDERATIONMETADATATIMEOUT");

        // The default location of the cache token
        env->PutString("PelicanCacheTokenLocation", "");
        env->ImportString("PelicanCacheTokenLocation", "XRD_PELICANCACHETOKENLOCATION");

        // The default location of the database file
        env->PutString("PelicanDatabaseLocation", "");
        env->ImportString("PelicanDatabaseLocation", "XRD_PELICANDATABASELOCATION");

        // The default behavior of the pelican client is to query for origins to
        // download objects from.  This can be switched to querying for caches
        // to download from instead.
        // - `auto` (or empty): Default behavior for the current release; currently, query for origins.
        // - `origin`: Always query for origins.
        // - `cache`: Always query for caches.
        env->PutString("PelicanDirectoryQueryMode", "auto");
        env->ImportString("PelicanDirectoryQueryMode", "XRD_PELICANDIRECTORYQUERYMODE");
        std::string val;
        if (!env->GetString("PelicanDirectoryQuery", val) || val.empty()) {
            val = "auto";
        }
        if (val == "cache") {
            Filesystem::SetDirectoryQueryMode(Filesystem::DirectoryQuery::Cache);
        } else {
            if (val != "auto" && val != "origin") {
                m_log->Warning(kLogXrdClPelican, "Unrecognized PelicanDirectoryQuery value (%s); defaulting to 'auto'", val.c_str());
            }
            Filesystem::SetDirectoryQueryMode(Filesystem::DirectoryQuery::Origin);
        }

        // A comma-separated list of endpoint URLs to use as overrides instead of
        // contacting the director.  The special value "+" indicates that the
        // director should be used at that position in the list.
        env->PutString("PelicanEndpointOverride", "");
        env->ImportString("PelicanEndpointOverride", "XRD_PELICANENDPOINTOVERRIDE");
        val = "";
        if (env->GetString("PelicanEndpointOverride", val) && !val.empty()) {
            Filesystem::SetEndpointOverride(val);
            m_log->Info(kLogXrdClPelican, "Endpoint override configured: %s", val.c_str());
        }

        SetupX509();

        // Determine the minimum header timeout.  It's somewhat arbitrarily defaulted to 2s; below
        // that and timeouts could be caused by OS scheduling noise.  If the client has unreasonable
        // expectations of the origin, we don't want to cause it to generate lots of origin-side load.
        struct timespec mct{2, 0};
        val = "";
        if (env->GetString("PelicanMinimumHeaderTimeout", val) && !val.empty()) {
            std::string errmsg;
            if (!XrdClCurl::ParseTimeout(val, mct, errmsg)) {
                m_log->Error(kLogXrdClPelican, "Failed to parse the minimum client timeout (%s): %s", val.c_str(), errmsg.c_str());
            }
        }
        File::SetMinimumHeaderTimeout(mct);

        // The pelican client has historically used 10s as its header timeout (waiting for a response from the cache).
        // Have the cache's default header timeout for the origin be slightly less than this to better support older
        // clients that don't specify the timeout in their request.
        struct timespec dht{9, 500'000'000};
        val = "";
        if (env->GetString("PelicanDefaultHeaderTimeout", val) && !val.empty()) {
            std::string errmsg;
            if (!XrdClCurl::ParseTimeout(val, dht, errmsg)) {
                m_log->Error(kLogXrdClPelican, "Failed to parse the default header timeout (%s): %s", val.c_str(), errmsg.c_str());
            }
        }
        File::SetDefaultHeaderTimeout(dht);

        // Set some curl timeouts using Pelican env vars for backward compatibility.
        val = "";
        if (!env->GetString("CurlDefaultHeaderTimeout", val) || val.empty()) {
            env->PutString("CurlDefaultHeaderTimeout", "");
            env->ImportString("CurlDefaultHeaderTimeout", "XRD_PELICANDEFAULTHEADERTIMEOUT");
        }
        val = "";
        if (!env->GetString("CurlMinimumHeaderTimeout", val) || val.empty()) {
            env->PutString("CurlMinimumHeaderTimeout", "");
            env->ImportString("CurlMinimumHeaderTimeout", "XRD_PELICANMINIMUMHEADERTIMEOUT");
        }

        struct timespec fedTimeout{5, 0};
        val = "";
        if (env->GetString("PelicanFederationMetadataTimeout", val) && !val.empty()) {
            std::string errmsg;
            if (!XrdClCurl::ParseTimeout(val, fedTimeout, errmsg)) {
                m_log->Error(kLogXrdClPelican, "Failed to parse the federation metadata timeout (%s): %s", val.c_str(), errmsg.c_str());
            }
        }
        File::SetFederationMetadataTimeout(fedTimeout);

        // The number of retries for retryable errors (default 1).
        // Retryable errors include TCP socket closed mid-transfer,
        // partial file responses, and HTTP 500 Internal Server Error.
        env->PutInt("PelicanRetryCount", 1);
        env->ImportInt("PelicanRetryCount", "XRD_PELICANRETRYCOUNT");
        int retryCount = 1;
        env->GetInt("PelicanRetryCount", retryCount);
        if (retryCount < 0) {
            m_log->Warning(kLogXrdClPelican, "PelicanRetryCount is negative (%d); setting to 0", retryCount);
            retryCount = 0;
        }
        File::SetRetryCount(retryCount);
        m_log->Info(kLogXrdClPelican, "Pelican retry count set to %d", retryCount);

        // The initial backoff delay for exponential retry backoff.
        // Each subsequent retry doubles the delay, capped at 30 seconds.
        // Accepts Go-style duration strings (e.g., "100ms", "1s", "500us").
        struct timespec retryBackoff{0, 100'000'000}; // 100ms default
        env->PutString("PelicanRetryBackoff", "");
        env->ImportString("PelicanRetryBackoff", "XRD_PELICANRETRYBACKOFF");
        val = "";
        if (env->GetString("PelicanRetryBackoff", val) && !val.empty()) {
            std::string errmsg;
            if (!XrdClCurl::ParseTimeout(val, retryBackoff, errmsg)) {
                m_log->Error(kLogXrdClPelican, "Failed to parse the retry backoff (%s): %s", val.c_str(), errmsg.c_str());
            }
        }
        if (retryBackoff.tv_sec == 0 && retryBackoff.tv_nsec < 1'000'000) {
            m_log->Warning(kLogXrdClPelican, "PelicanRetryBackoff is less than 1ms; setting to 1ms");
            retryBackoff = {0, 1'000'000};
        }
        auto backoff_dur = std::chrono::seconds(retryBackoff.tv_sec) +
                           std::chrono::nanoseconds(retryBackoff.tv_nsec);
        RetryThread::SetBaseDelay(std::chrono::duration_cast<std::chrono::steady_clock::duration>(backoff_dur));
        m_log->Info(kLogXrdClPelican, "Pelican retry backoff set to %s", XrdClCurl::MarshalDuration(retryBackoff).c_str());

        // The default location of the cache token
        env->PutString("PelicanCacheTokenLocation", "");
        env->ImportString("PelicanCacheTokenLocation", "XRD_PELICANCACHETOKENLOCATION");

        env->GetString("PelicanCacheTokenLocation", m_token_file);

        // If XRD_PELICANCACHETOKENLOCATION is not set, fall back to WLCG token discovery:
        //   1. BEARER_TOKEN env var (token value directly)
        //   2. BEARER_TOKEN_FILE env var (path to token file)
        if (m_token_file.empty()) {
            auto [contents, file] = DiscoverWLCGToken();
            if (!contents.empty()) {
                m_token_contents = contents;
                File::SetCacheToken(m_token_contents);
                Filesystem::SetCacheToken(m_token_contents);
                m_log->Info(kLogXrdClPelican, "Using token from BEARER_TOKEN environment variable");
            } else if (!file.empty()) {
                m_token_file = file;
                m_log->Info(kLogXrdClPelican, "Using token file from BEARER_TOKEN_FILE environment variable: %s", m_token_file.c_str());
            }
        }

        // The location of the writeback cache
        env->PutString("PelicanWritebackLocation", "");
        env->ImportString("PelicanWritebackLocation", "XRD_PELICANWRITEBACKLOCATION");

        std::string db_location;
        bool writeback_enabled = false;
        if (env->GetString("PelicanDatabaseLocation", val) && !val.empty()) {
            db_location = val;
        }
        if (!db_location.empty()) {
            try {
                WritebackDB db(db_location, *m_log);
                writeback_enabled = true;
            } catch (const std::exception &e) {
                m_log->Error(kLogXrdClPelican, "Failed to initialize writeback database (%s): %s", db_location.c_str(), e.what());
                db_location = "";
            }
        } else {
            m_log->Info(kLogXrdClPelican, "Pelican writeback database location is not set; writeback support is disabled");
        }

        if (writeback_enabled) {
            std::string location;
            if (env->GetString("PelicanWritebackLocation", location) && !location.empty()) {
                Filesystem::SetWritebackCacheLocation(location);
            }
            location = Filesystem::GetWritebackCacheLocation();
            if (!location.empty()) {
                std::error_code ec;
                std::filesystem::create_directories(Filesystem::GetWritebackCacheLocation(), ec);
                if (ec) {
                    m_log->Error(kLogXrdClPelican, "Failed to create Pelican writeback cache location (%s): %s", location.c_str(), strerror(ec.value()));
                }
            } else {
                writeback_enabled = false;
            }
        }

        if (!m_token_file.empty()) {
            RefreshToken();
        }
        m_maintenance_thread = std::thread(PelicanFactory::MaintenanceThread);

        RetryThread::Start();

        m_initialized = true;
    });
}

void
PelicanFactory::SetMaintenanceInterval(std::chrono::steady_clock::duration interval)
{
    std::unique_lock lock(m_shutdown_lock);
    m_maintenance_interval.store(interval.count(), std::memory_order_relaxed);
    m_maintenance_update = true;
    m_shutdown_requested_cv.notify_all();
}

void
PelicanFactory::MaintenanceThread() {
    while (true) {
        {
            std::chrono::steady_clock::duration interval = std::chrono::steady_clock::duration(std::chrono::seconds(m_maintenance_interval.load(std::memory_order_relaxed)));
            std::unique_lock lock(m_shutdown_lock);
            m_shutdown_requested_cv.wait_for(
                lock,
                interval,
                []{return m_shutdown_requested || m_maintenance_update;}
            );
            m_maintenance_update = false;
            if (m_shutdown_requested) {
                break;
            }
        }
        RefreshToken();
        File::WritebackMaintenance();
        WritebackDB::Maintenance();
    }
}

void
PelicanFactory::RefreshToken() {
    std::string token_contents, token_file;
    {
        std::unique_lock lock(m_token_mutex);
        token_contents = m_token_contents;
        token_file = m_token_file;
    }
    if (token_file.empty()) {
        return;
    }
    auto [success, contents] = ReadCacheToken(token_file, m_log);
    if (success && (contents != token_contents)) {
        File::SetCacheToken(contents);
        Filesystem::SetCacheToken(contents);
        std::unique_lock lock(m_token_mutex);
        m_token_contents = contents;
    }
}

std::pair<bool, std::string>
PelicanFactory::ReadCacheToken(const std::string &token_location, XrdCl::Log *log) {
    if (token_location.empty()) {
        return {true, ""};
    }

    std::string line;
    std::ifstream fhandle;
    fhandle.open(token_location);
    if (!fhandle) {
        log->Error(kLogXrdClPelican, "Cache token location is set (%s) but failed to open: %s", token_location.c_str(), strerror(errno));
        return {false, ""};
    }

    std::string result;
    while (std::getline(fhandle, line)) {
        rtrim(line);
        ltrim(line);
        if (line.empty() || line[0] == '#') {continue;}

        result = line;
    }
    if (!fhandle.eof() && fhandle.fail()) {
        log->Error(kLogXrdClPelican, "Reading of token file (%s) failed: %s", token_location.c_str(), strerror(errno));
        return {false, ""};
    }
    return {true, result};
}

void
PelicanFactory::SetTokenLocation(const std::string &filename) {
    std::unique_lock lock(m_token_mutex);
    m_token_file = filename;
}

std::pair<std::string, std::string>
PelicanFactory::DiscoverWLCGToken() {
    auto bearer_token = std::getenv("BEARER_TOKEN");
    if (bearer_token && bearer_token[0] != '\0') {
        return {std::string(bearer_token), ""};
    }
    auto bearer_token_file = std::getenv("BEARER_TOKEN_FILE");
    if (bearer_token_file && bearer_token_file[0] != '\0') {
        return {"", std::string(bearer_token_file)};
    }
    return {"", ""};
}

namespace {

void SetIfEmpty(XrdCl::Env *env, const std::string &optName, const std::string &envName) {
    std::string val;
    if (!env->GetString(optName, val) || val.empty()) {
        env->PutString(optName, "");
        env->ImportString(optName, envName);
    }
}

} // namespace

void
PelicanFactory::SetupX509() {
    std::string filename;
    auto env = XrdCl::DefaultEnv::GetEnv();
    SetIfEmpty(env, "CurlClientCertFile", "XRD_PELICANCLIENTCERTFILE");
    SetIfEmpty(env, "CurlClientKeyFile", "XRD_PELICANCLIENTKEYFILE");
    SetIfEmpty(env, "CurlCertFile", "XRD_PELICANCERTFILE");
    SetIfEmpty(env, "CurlCertDir", "XRD_PELICANCERTDIR");
}

void
PelicanFactory::Shutdown()
{
    {
        std::unique_lock lock(m_shutdown_lock);
        m_shutdown_requested = true;
        m_shutdown_requested_cv.notify_one();
    }
    if (m_maintenance_thread.joinable()) {
        m_maintenance_thread.join();
    }
    RetryThread::Shutdown();
}

XrdCl::FilePlugIn *
PelicanFactory::CreateFile(const std::string & /*url*/) {
    if (!m_initialized) {return nullptr;}
    return new Pelican::File(m_log);
}

XrdCl::FileSystemPlugIn *
PelicanFactory::CreateFileSystem(const std::string & url) {
    if (!m_initialized) {return nullptr;}
    return new Pelican::Filesystem(url, m_log);
}

extern "C"
{
    void *XrdClGetPlugIn(const void*)
    {
        return static_cast<void*>(new PelicanFactory());
    }
}
