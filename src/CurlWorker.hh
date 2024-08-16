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

#pragma once

#include "CurlOps.hh"

#include <memory>
#include <unordered_map>
#include <unordered_set>

typedef void CURL;

namespace XrdCl {

class Env;
class Log;
class ResponseHandler;
class URL;

}

namespace Pelican {

class HandlerQueue;

class CurlWorker {
public:
    CurlWorker(std::shared_ptr<HandlerQueue> queue, XrdCl::Log* logger);

    CurlWorker(const CurlWorker &) = delete;

    void Run();
    static void RunStatic(CurlWorker *myself);

    // Returns true if the given URL should be using X.509 authentication,
    // based on the URL and configuration of the curl worker
    bool UseX509Auth(XrdCl::URL &url);

    // Returns the configured X509 client certificate and key file name
    std::tuple<std::string, std::string> ClientX509CertKeyFile() const;

private:
    // Reload the list of prefixes needing X509 authentication
    //
    // Each curl worker keeps a list of prefixes which require X509 authentication
    // in addition to or instead of token-based authorization.  This function,
    // meant to be called periodically, refreshes the list from a configured
    // file with newline-separated entries.
    //
    // Returns false on failure.
    bool RefreshX509Prefixes(XrdCl::Env *env);

    bool m_x509_all{false};
    std::chrono::steady_clock::time_point m_last_prefix_log;
    std::shared_ptr<HandlerQueue> m_queue;
    std::unordered_map<CURL*, std::unique_ptr<CurlOperation>> m_op_map;
    std::unordered_set<std::string> m_x509_prefixes;
    XrdCl::Log* m_logger;
    std::string m_x509_client_cert_file;
    std::string m_x509_client_key_file;

    const static unsigned m_max_ops{20};
    const static unsigned m_marker_period{5};
 
};

}