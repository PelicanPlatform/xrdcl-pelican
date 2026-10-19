/****************************************************************
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

#ifndef XRDCLS3_TESTS_MOCKDISPATCHER_HH
#define XRDCLS3_TESTS_MOCKDISPATCHER_HH

#include <XrdCl/XrdClXRootDResponses.hh>

#include <chrono>

// Delivers the mock file plugin's callbacks on a dedicated thread.
//
// The dispatcher lives in a shared library linked by both the mock plugin and
// the test binary, so its thread never runs code from the plugin module after
// the test has drained it; XrdCl unloads the plugin module at exit.
namespace XrdClS3Mock {

// Invoke handler->HandleResponse(status, response) on the dispatcher thread.
void Dispatch(XrdCl::ResponseHandler *handler, XrdCl::XRootDStatus *status, XrdCl::AnyObject *response);

// Block until every dispatched callback, including any callbacks dispatched
// while running earlier ones, has returned.  Returns false on timeout.
bool Drain(std::chrono::milliseconds timeout);

} // namespace XrdClS3Mock

#endif // XRDCLS3_TESTS_MOCKDISPATCHER_HH
