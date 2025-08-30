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

#include "../common/XrdClCurlParseTimeout.hh"
#include "PelicanFactory.hh"
#include "PelicanFile.hh"
#include "PelicanFilesystem.hh"

#include <XrdCl/XrdClDefaultEnv.hh>
#include <XrdCl/XrdClLog.hh>
#include <XrdCl/XrdClPlugInInterface.hh>

#include <fstream>
#include <thread>

XrdVERSIONINFO(XrdClGetPlugIn, XrdClGetPlugIn)

using namespace Pelican;

bool PelicanFactory::m_initialized = false;
XrdCl::Log *PelicanFactory::m_log = nullptr;
std::string PelicanFactory::m_token_contents;
std::string PelicanFactory::m_token_file;
std::mutex PelicanFactory::m_token_mutex;
std::once_flag PelicanFactory::m_init_once;
std::mutex PelicanFactory::m_shutdown_lock;
std::condition_variable PelicanFactory::m_shutdown_requested_cv;
bool PelicanFactory::m_shutdown_requested = false;
std::condition_variable PelicanFactory::m_shutdown_complete_cv;
bool PelicanFactory::m_shutdown_complete = true;

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


        // The default location of the cache token
        env->PutString("PelicanCacheTokenLocation", "");
        env->ImportString("PelicanCacheTokenLocation", "XRD_PELICANCACHETOKENLOCATION");

        env->GetString("PelicanCacheTokenLocation", m_token_file);
        if (!m_token_file.empty()) {
            RefreshToken();
            {
                std::unique_lock lock(m_shutdown_lock);
                m_shutdown_complete = false;
            }
            std::thread t(PelicanFactory::CacheTokenThread);

            t.detach();
        }
        m_initialized = true;
    });
}


void
PelicanFactory::CacheTokenThread() {
    while (true) {
        {
            std::unique_lock lock(m_shutdown_lock);
            m_shutdown_requested_cv.wait_for(
                lock,
                std::chrono::seconds(15),
                []{return m_shutdown_requested;}
            );
            if (m_shutdown_requested) {
                break;
            }
        }
        RefreshToken();
    }
    std::unique_lock lock(m_shutdown_lock);
    m_shutdown_complete = true;
    m_shutdown_complete_cv.notify_one();
}

void
PelicanFactory::RefreshToken() {
    std::string token_contents, token_file;
    {
        std::unique_lock lock(m_token_mutex);
        token_contents = m_token_contents;
        token_file = m_token_file;
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
    std::unique_lock lock(m_shutdown_lock);
    m_shutdown_requested = true;
    m_shutdown_requested_cv.notify_one();

    m_shutdown_complete_cv.wait(lock, []{return m_shutdown_complete;});
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
