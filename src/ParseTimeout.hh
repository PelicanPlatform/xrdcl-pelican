/****************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

#include <string>

#include <time.h>

namespace Pelican {

// Parse a given string as a duration, returning the parsed value as a timespec.
//
// The implementation is based on the Go duration format which is a signed sequence of
// decimal numbers with a unit suffix.
//
// Examples:
// - 30ms
// - 1h5m
// Valid time units are "ns", "us", "ms", "s", "m", "h".  Unlike go, UTF-8 for microsecond is not accepted
//
// If an invalid value is given, false is returned and the errmsg is set.
bool ParseTimeout(const std::string &duration, struct timespec &, std::string &errmsg);

}