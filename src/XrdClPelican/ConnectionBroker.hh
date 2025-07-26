/***************************************************************
 *
 * Copyright (C) 2025, Morgridge Institute for Research
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

#ifndef XRDCLPELICAN_CONNECTIONBROKER_HH
#define XRDCLPELICAN_CONNECTIONBROKER_HH

#include "../common/XrdClCurlConnectionCallout.hh"

#include <chrono>
#include <string>

namespace XrdClCurl {
class ResponseInfo;
}

namespace Pelican {

// A class implementing a callout to the Pelican connection broker.
class ConnectionBroker final : public XrdClCurl::ConnectionCallout {
public:

    virtual ~ConnectionBroker();
    ConnectionBroker(const ConnectionBroker&) = delete;

    static XrdClCurl::ConnectionCallout *CreateCallback(const std::string &url,
        const XrdClCurl::ResponseInfo &info);

    // Start a request to get a URL connection from the broker.
    virtual int BeginCallout(std::string &err,
        std::chrono::steady_clock::time_point &expiration) override;
    
    // Finish the socket connection callout.
    virtual int FinishCallout(std::string &err) override;

private:
    ConnectionBroker(const std::string &url);

    int GetBrokerSock() const {return m_req;}

    std::string m_url; // URL for the broker to use.
    std::string m_origin; // "URL" for the origin.
    int m_req{-1};
    int m_rev{-1};
};

} // namespace XrdClPelican

#endif // XRDCLPELICAN_CONNECTIONBROKER_HH
