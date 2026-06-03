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
