
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

#include <XrdCl/XrdClPlugInInterface.hh>

#include <condition_variable>
#include <mutex>
#include <thread>
#include <utility>

namespace XrdCl {
    class Log;
}

namespace Pelican {

class PelicanFactory final : public XrdCl::PlugInFactory {
public:
    PelicanFactory();
    virtual ~PelicanFactory() {}
    PelicanFactory(const PelicanFactory &) = delete;

    virtual XrdCl::FilePlugIn *CreateFile(const std::string &url) override;
    virtual XrdCl::FileSystemPlugIn *CreateFileSystem(const std::string &url) override;

    // Read the cache token from the file and load it into the cache
    static void RefreshToken();

    // Set the cache token location, overriding the environment defaults.
    static void SetTokenLocation(const std::string &filename);

    // Set the frequency of the maintenance tasks.  If not specified, defaults to 5 seconds.
    static void SetMaintenanceInterval(std::chrono::steady_clock::duration interval);

    // Discover a bearer token using the WLCG token discovery profile.
    // Checks BEARER_TOKEN (token value) and BEARER_TOKEN_FILE (file path) env vars.
    // Returns {token_contents, token_file} where at most one is non-empty.
    static std::pair<std::string, std::string> DiscoverWLCGToken();

private:
    // Set the configuration variables for X509 credentials in the default environment.
    void SetupX509();

    // Read filename to fetch a new cache token
    static std::pair<bool, std::string> ReadCacheToken(const std::string &token_location, XrdCl::Log *log);

    // Periodically read the cache token, update the in-memory token contents, and perform other
    // maintenance tasks for the Pelican plugin
    static void MaintenanceThread();
    static void Shutdown() __attribute__((destructor));

    // How frequently to perform maintenance tasks
    static std::atomic<std::chrono::steady_clock::duration::rep> m_maintenance_interval;
    static bool m_maintenance_update;

    static bool m_initialized;
    static XrdCl::Log *m_log;
    const static unsigned m_poll_threads{8};
    static std::once_flag m_init_once;
    static std::string m_token_contents; // Contents of the cache token, if used.
    static std::string m_token_file; // Location of the cache token.
    static std::mutex m_token_mutex; // Mutex protecting the m_token_contents & m_token_file

    // Mutex for managing the shutdown of the background thread
    static std::mutex m_shutdown_lock;
    // Condition variable managing the requested shutdown of the background thread.
    static std::condition_variable m_shutdown_requested_cv;
    // Flag indicating that a shutdown was requested.
    static bool m_shutdown_requested;
    // The background maintenance thread.
    static std::thread m_maintenance_thread;
};

}
