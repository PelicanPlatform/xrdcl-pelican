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

#include "XrdClCurlOps.hh"

#include <XrdCl/XrdClFileSystem.hh>
#include <XrdCl/XrdClLog.hh>

#include <nlohmann/json.hpp>

#include <cctype>
#include <cerrno>

using namespace XrdClCurl;

#ifdef HAVE_XRDCL_FCNTL_QUERYCODE
namespace {

// Build the Cache-Control / ETag information document XrdPfc stores to manage
// mutable objects.  May contain "ETag", "max-age" (freshness seconds), and
// "revalidate" (true for must-revalidate / no-cache).  Keep in sync with the
// fields consumed by XrdPfc::Cache::Prepare.
std::string BuildCacheControlJson(const std::string &etag, const std::string &cache_control)
{
    nlohmann::json info;
    if (!etag.empty()) {
        info["ETag"] = etag;
    }
    if (!cache_control.empty()) {
        if (cache_control.find("must-revalidate") != std::string::npos ||
            cache_control.find("no-cache") != std::string::npos) {
            info["revalidate"] = true;
        }
        auto fm = cache_control.find("max-age=");
        if (fm != std::string::npos) {
            fm += 8; // length of "max-age="
            auto end = fm;
            while (end < cache_control.length() &&
                   std::isdigit(static_cast<unsigned char>(cache_control[end]))) {
                end++;
            }
            if (end > fm) {
                try {
                    info["max-age"] = std::stol(cache_control.substr(fm, end - fm));
                } catch (const std::exception &) {
                    // Unparseable max-age: leave freshness unknown.
                }
            }
        }
    }
    return info.dump();
}

} // namespace
#endif // HAVE_XRDCL_FCNTL_QUERYCODE

void CurlQueryOp::Success()
{
    SetDone(false);
    m_logger->Debug(kLogXrdClCurl, "CurlQueryOp::Success");

#ifdef HAVE_XRDCL_FCNTL_QUERYCODE
    if (m_queryCode == XrdCl::QueryCode::FInfo) {
        // XrdPfc's FInfo "head" query stores the object's Cache-Control / ETag.
        auto respBuff = new XrdCl::Buffer();
        respBuff->FromString(BuildCacheControlJson(m_headers.GetETag(), m_headers.GetCacheControl()));
        auto obj = new XrdCl::AnyObject();
        obj->Set(respBuff);
        m_handler->HandleResponse(new XrdCl::XRootDStatus(), obj);
        m_handler = nullptr;
        return;
    }
#endif

    bool returns_etag = (m_queryCode == XrdCl::QueryCode::XAttr);
#ifdef HAVE_XRDCL_FCNTL_QUERYCODE
    // XrdPfc's FSInfo "head" revalidation query expects the bare current ETag.
    returns_etag = returns_etag || (m_queryCode == XrdCl::QueryCode::FSInfo);
#endif
    if (returns_etag) {
        XrdCl::Buffer *qInfo = new XrdCl::Buffer();
        qInfo->FromString(m_headers.GetETag());
        auto obj = new XrdCl::AnyObject();
        obj->Set(qInfo);

        m_handler->HandleResponse(new XrdCl::XRootDStatus(), obj);
        m_handler = nullptr;
    }
    else {
        m_logger->Error(kLogXrdClCurl, "Invalid information query type code");
        // errNo must be a POSIX errno here (issue #117); errErrorResponse (400) is
        // an XrdCl error code, not an errno.  errInvalidArgs maps to EINVAL.
        Fail(XrdCl::errInvalidArgs, EINVAL, "Unsupported query code");
    }
}
