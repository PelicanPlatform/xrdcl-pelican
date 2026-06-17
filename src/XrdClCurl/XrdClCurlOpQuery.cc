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

#include <cerrno>

using namespace XrdClCurl;

void CurlQueryOp::Success()
{
    SetDone(false);
    m_logger->Debug(kLogXrdClCurl, "CurlQueryOp::Success");

    if (m_queryCode == XrdCl::QueryCode::XAttr) {
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
