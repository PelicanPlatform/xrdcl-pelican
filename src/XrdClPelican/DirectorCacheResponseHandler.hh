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

#pragma once

#include "BrokerCache.hh"

#include <XrdCl/XrdClXRootDResponses.hh>

#include <memory>

namespace XrdCl {
    class Log;
}

namespace Pelican {

class DirectorCache;

template <class ResponseObj, class ResponseInfoObj>
class DirectorCacheResponseHandler : public XrdCl::ResponseHandler {
public:
    DirectorCacheResponseHandler(const DirectorCache *dcache, XrdCl::Log &log, XrdCl::ResponseHandler *handler)
      : m_bcache(BrokerCache::GetCache()),
        m_dcache(dcache),
        m_handler(handler),
        m_log(log)
    {}

    virtual void HandleResponse(XrdCl::XRootDStatus *status, XrdCl::AnyObject *response);

private:
    const BrokerCache &m_bcache;
    const DirectorCache *m_dcache;
    XrdCl::ResponseHandler *m_handler;
    XrdCl::Log &m_log;
};

} // namespace Pelican
