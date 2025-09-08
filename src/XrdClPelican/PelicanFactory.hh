
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

#include <XrdCl/XrdClPlugInInterface.hh>

#include <condition_variable>
#include <mutex>
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
    // Condition variable for the background thread to indicate it has completed.
    static std::condition_variable m_shutdown_complete_cv;
    // Flag indicating that the shutdown has completed.
    static bool m_shutdown_complete;
};

}
