
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

#include <mutex>

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

private:
    // Set the configuration variables for X509 credentials in the default environment.
    void SetupX509();

    static bool m_initialized;
    static XrdCl::Log *m_log;
    const static unsigned m_poll_threads{8};
    static std::once_flag m_init_once;
};

}
