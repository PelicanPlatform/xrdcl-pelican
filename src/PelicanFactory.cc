/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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

#include "PelicanFile.hh"
#include "PelicanFilesystem.hh"
#include "CurlOps.hh"
#include "CurlUtil.hh"
#include "CurlWorker.hh"

#include <XrdCl/XrdClDefaultEnv.hh>
#include <XrdCl/XrdClLog.hh>
#include <XrdCl/XrdClPlugInInterface.hh>

#include <thread>

XrdVERSIONINFO(XrdClGetPlugIn, XrdClGetPlugIn)

using namespace Pelican;

namespace {

class PelicanFactory final : public XrdCl::PlugInFactory {
public:
    PelicanFactory();
    virtual ~PelicanFactory() {}
    PelicanFactory(const PelicanFactory &) = delete;

    virtual XrdCl::FilePlugIn *CreateFile(const std::string &url) override;
    virtual XrdCl::FileSystemPlugIn *CreateFileSystem(const std::string &url) override;
private:
    void init();

    static bool m_initialized;
    static std::shared_ptr<HandlerQueue> m_queue;
    static XrdCl::Log *m_log;
    static std::vector<std::unique_ptr<CurlWorker>> m_workers;
    const static unsigned m_poll_threads{3};
    static std::once_flag m_init_once;
};

bool PelicanFactory::m_initialized = false;
std::shared_ptr<HandlerQueue> PelicanFactory::m_queue;
std::vector<std::unique_ptr<CurlWorker>> PelicanFactory::m_workers;
XrdCl::Log *PelicanFactory::m_log = nullptr;
std::once_flag PelicanFactory::m_init_once;

}

PelicanFactory::PelicanFactory() {
    std::call_once(m_init_once, [&] {
        m_queue.reset(new HandlerQueue());
        m_log = XrdCl::DefaultEnv::GetLog();
        if (!m_log) {
            return;
        }

        auto env = XrdCl::DefaultEnv::GetEnv();
        if (!env) {
            return;
        }
        env->PutString("PelicanCertFile", "");
        env->ImportString( "PelicanCertFile", "XRD_PELICANCERTFILE");
        env->PutString("PelicanCertDir", "");
        env->ImportString( "PelicanCertDir", "XRD_PELICANCERTDIR");

        m_log->SetTopicName(kLogXrdClPelican, "XrdClPelican");
        for (unsigned idx=0; idx<m_poll_threads; idx++) {
            m_workers.emplace_back(new CurlWorker(m_queue, m_log));
            std::thread t(CurlWorker::RunStatic, m_workers.back().get());
            t.detach();
        }
        m_initialized = true;
    });
}

XrdCl::FilePlugIn *
PelicanFactory::CreateFile(const std::string & /*url*/) {
    if (!m_initialized) {return nullptr;}
    return new Pelican::File(m_queue, m_log);
}

XrdCl::FileSystemPlugIn *
PelicanFactory::CreateFileSystem(const std::string & url) {
    if (!m_initialized) {return nullptr;}
    return new Pelican::Filesystem(url, m_queue, m_log);
}

extern "C"
{
    void *XrdClGetPlugIn(const void*)
    {
        return static_cast<void*>(new PelicanFactory());
    }
}
