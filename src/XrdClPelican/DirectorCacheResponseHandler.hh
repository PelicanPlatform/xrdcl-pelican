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
