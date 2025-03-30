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

#include "CurlOps.hh"

#include <XrdCl/XrdClLog.hh>
#include <XrdCl/XrdClXRootDResponses.hh>
#include <XrdOuc/XrdOucCRC.hh>
#include <XrdSys/XrdSysPageSize.hh>

using namespace Pelican;

CurlVectorReadOp::CurlVectorReadOp(XrdCl::ResponseHandler *handler, const std::string &url, struct timespec timeout,
    const XrdCl::ChunkList &op_list, XrdCl::Log *logger) :
        CurlOperation(handler, url, timeout, logger),
        m_vr(new XrdCl::VectorReadInfo()),
        m_chunk_list(op_list),
        m_header_list(nullptr, &curl_slist_free_all)        
    {}

void
CurlVectorReadOp::Setup(CURL *curl, CurlWorker &worker)
{
    CurlOperation::Setup(curl, worker);
    curl_easy_setopt(m_curl.get(), CURLOPT_WRITEFUNCTION, CurlVectorReadOp::WriteCallback);
    curl_easy_setopt(m_curl.get(), CURLOPT_WRITEDATA, this);

    std::stringstream ss;
    auto multiple = false;
    for (const auto &chunk : m_chunk_list) {
        if (!chunk.GetLength()) continue;
        if (multiple) {ss << ",";}
        ss << chunk.GetOffset() << "-" << chunk.GetOffset() + chunk.GetLength() - 1;
        multiple = true;
    }
    auto byte_range_val = ss.str();
    if (byte_range_val.size()) {
        auto range_req = std::string("Range: bytes=") + byte_range_val.c_str();
        m_header_list.reset(curl_slist_append(m_header_list.release(), range_req.c_str()));
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, m_header_list.get());
    }
}

void
CurlVectorReadOp::Fail(uint16_t errCode, uint32_t errNum, const std::string &msg)
{
    std::string custom_msg = msg;
    SetDone();
    if (m_handler == nullptr) {return;}
    std::string offset = "(unknown)";
    std::string length = "(unknown)";
    if (!m_chunk_list.empty()) {
        offset = std::to_string(m_chunk_list[0].GetOffset());
        length = std::to_string(m_chunk_list[0].GetLength());
    }
    if (!custom_msg.empty()) {
        m_logger->Debug(kLogXrdClPelican, "curl operation with vector starting offset %s / length %s failed with message: %s", offset.c_str(), length.c_str(), custom_msg.c_str());
        custom_msg += " (vector read operation starting at offset " + offset + " / length " + length + ")";
    } else {
        m_logger->Debug(kLogXrdClPelican, "curl vector operation starting at offset %s / length %s failed with status code %d", offset.c_str(), length.c_str(), errNum);
    }
    auto status = new XrdCl::XRootDStatus(XrdCl::stError, errCode, errNum, custom_msg);
    m_handler->HandleResponse(status, nullptr);
    m_handler = nullptr;
}

void
CurlVectorReadOp::Success()
{
    SetDone();
    if (m_handler == nullptr) {return;}

    // If there's a partial last response, give it to the client.
    if (m_chunk_buffer_idx) {
        auto &chunk = m_chunk_list[m_response_idx];
        m_vr->GetChunks().emplace_back(chunk.GetOffset(), m_chunk_buffer_idx, chunk.GetBuffer());
        m_bytes_consumed += m_chunk_buffer_idx;
    }

    auto status = new XrdCl::XRootDStatus();
    m_vr->SetSize(m_bytes_consumed);
    auto obj = new XrdCl::AnyObject();
    obj->Set(m_vr.release());
    m_handler->HandleResponse(status, obj);
    m_handler = nullptr;
}

void
CurlVectorReadOp::ReleaseHandle()
{
    if (m_curl == nullptr) return;
    curl_easy_setopt(m_curl.get(), CURLOPT_WRITEFUNCTION, nullptr);
    curl_easy_setopt(m_curl.get(), CURLOPT_WRITEDATA, nullptr);
    curl_easy_setopt(m_curl.get(), CURLOPT_HTTPHEADER, nullptr);
    curl_easy_setopt(m_curl.get(), CURLOPT_OPENSOCKETFUNCTION, nullptr);
    curl_easy_setopt(m_curl.get(), CURLOPT_OPENSOCKETDATA, nullptr);
    curl_easy_setopt(m_curl.get(), CURLOPT_SOCKOPTFUNCTION, nullptr);
    curl_easy_setopt(m_curl.get(), CURLOPT_SOCKOPTDATA, nullptr);
    m_header_list.reset();
    CurlOperation::ReleaseHandle();
}

size_t
CurlVectorReadOp::WriteCallback(char *buffer, size_t size, size_t nitems, void *this_ptr)
{
    return static_cast<CurlVectorReadOp*>(this_ptr)->Write(buffer, size * nitems);
}

// Given a buffer of data from curl, parse it and write it to the response buffers.
size_t
CurlVectorReadOp::Write(char *orig_buffer, size_t orig_length)
{
    //m_logger->Debug(kLogXrdClPelican, "Received a write of size %ld with contents:\n%s", static_cast<long>(orig_length), std::string(orig_buffer, orig_length).c_str());

    // Handle the (hopefully uncommon) cases where the server responds to a vector read op
    // with a single response.  We set the length of the response to the max as we
    // don't care how many bytes the server actually sends.
    if (GetStatusCode() == 200) {
        m_current_op.first = 0;
        m_current_op.second = std::numeric_limits<off_t>::max();
    } else if (HTTPStatusIsError(GetStatusCode())) {
        return orig_length;
    } else if (!m_headers.IsMultipartByterange()) {
        m_current_op.first = m_headers.GetOffset();
        m_current_op.second = std::numeric_limits<off_t>::max();
    }

    auto buffer = orig_buffer;
    auto length = orig_length;

    while (length) {
        // If we're in the middle of a response chunk, copy as much data as possible.
        if (m_current_op.first != -1 && m_current_op.second != -1) {
            //m_logger->Debug(kLogXrdClPelican, "Processing response buffer of (%lld, %lld)", static_cast<long long>(m_current_op.first), static_cast<long long>(m_current_op.second));
            if (m_skip_bytes) {
                //m_logger->Debug(kLogXrdClPelican, "Skipping %lld bytes", static_cast<long long>(m_skip_bytes));
                auto to_skip = (m_skip_bytes < length) ? m_skip_bytes : length;
                buffer += to_skip;
                length -= to_skip;
                m_skip_bytes -= to_skip;
                continue;
            } else {
                auto &chunk = m_chunk_list[m_response_idx];
                auto remaining = static_cast<off_t>(chunk.GetLength()) - m_chunk_buffer_idx;
                if (remaining < 0) {return 0;}
                auto to_copy = (static_cast<size_t>(remaining) < length) ? static_cast<size_t>(remaining) : length;
                //m_logger->Debug(kLogXrdClPelican, "Copying %lld bytes to request buffer %ld at offset %lld", static_cast<long long>(to_copy), m_response_idx, static_cast<long long>(m_chunk_buffer_idx));
                memcpy(static_cast<char *>(chunk.GetBuffer()) + m_chunk_buffer_idx, buffer, to_copy);
                m_chunk_buffer_idx += to_copy;
                buffer += to_copy;
                length -= to_copy;
                // Handle cases where the requested or response chunk is complete
                if (chunk.GetLength() == m_chunk_buffer_idx) {
                    m_vr->GetChunks().emplace_back(chunk.GetOffset(), m_chunk_buffer_idx, chunk.GetBuffer());
                    m_bytes_consumed += m_chunk_buffer_idx;
                    m_chunk_buffer_idx = 0;
                    m_response_idx++;
                    if (m_current_op.second == chunk.GetLength()) {
                        m_current_op.first = m_current_op.second = -1;
                    } else {
                        // We may need to skip the remaining bytes or, potentially, the server
                        // coalesced two adjacent requests into one larger response.
                        m_current_op.first += chunk.GetLength();
                        m_current_op.second -= chunk.GetLength();
                        CalculateNextBuffer();
                        continue;
                    }
                } else if (m_current_op.second == m_chunk_buffer_idx) {
                    // There are no more bytes in the response but the requested chunk hasn't finished.
                    // Add what we have to the results and create a new chunk on the request list from the remainder; perhaps
                    // the server will send it in the future.
                    m_chunk_list.emplace_back(chunk.GetOffset() + m_chunk_buffer_idx, chunk.GetLength() - m_chunk_buffer_idx, static_cast<char*>(chunk.GetBuffer()) + m_chunk_buffer_idx);
                    m_vr->GetChunks().emplace_back(chunk.GetOffset(), m_chunk_buffer_idx, chunk.GetBuffer());
                    m_bytes_consumed += m_chunk_buffer_idx;
                    m_chunk_buffer_idx = 0;
                    m_current_op.first = m_current_op.second = -1;
                    m_response_idx++;
                }
            }
        }
        if (m_skip_bytes) {
            continue;
        }

        // We are at the boundary between chunks; we must parse header lines to understand the
        // next thing to do.

        // The following lambda function returns a string view to the next complete header line,
        // potentially partially from the previous buffer from curl.  If the second item in
        // the returned pair is false, then we ran out of buffer from curl before finding a
        // complete line.
        auto get_next_line = [&]() {
            std::string_view chunk_header(buffer, length);
            auto pos = chunk_header.find("\r\n");
            if (pos == std::string_view::npos) {
                m_response_headers += chunk_header;
                length = 0;
                return std::make_pair(std::string_view(), false);
            } else {
                auto line = chunk_header.substr(0, pos);
                if (!m_response_headers.empty()) {
                    m_response_headers += line;
                    line = m_response_headers;
                }
                buffer += pos + 2;
                length -= pos + 2;
                return std::make_pair(line, true);
            }
        };

        // Consume the boundary line.
        bool last_segment = false;
        while (true) {
            auto [line, ok] = get_next_line();
            if (!ok) {
                return orig_length;
            }
            // Per RFC7233, Appendix A, Implementation note 1, multiple CRLF might precede the
            // first boundary string in the body.  However, the XRootD server appears to have an
            // extra CRLF in front of every boundary string.
            if (line.empty()) {continue;}
            if (line == m_headers.MultipartSeparator()) {
                break;
            }
            if (line == m_headers.MultipartSeparator() + "--") {
                last_segment = true;
                break;
            }
            m_logger->Debug(kLogXrdClPelican, "Server has responded with an invalid boundary line: '%s' (expected '%s')", std::string(line).c_str(), m_headers.MultipartSeparator().c_str());
            // TODO: stash error message.
            return 0;
        }
        if (last_segment) {
            length = 0;
            break;
        }
        // Consume the header lines
        while (true) {
            auto [line, ok] = get_next_line();
            if (!ok) {
                return orig_length;
            }
            if (line.empty()) {
                break;
            }
            auto header_name_end = line.find(':');
            if (header_name_end == std::string_view::npos) {
                m_logger->Debug(kLogXrdClPelican, "Invalid header line in response from server: %s", std::string(line).c_str());
                return -1;
            }
            auto header_name = line.substr(0, header_name_end);
            // Cannot use strcasecmp here as a string_view's data is not necessarily nul-terminated.
            // len("content-type") == 13
            if (header_name.size() != 13 || strncasecmp(header_name.data(), "content-range", 13)) {
                continue;
            }
            // We are parsing a Content-Range value.
            // Example: Content-Range: bytes 7000-7999/8000
            auto value = line.substr(header_name_end + 1);
        
            // Advance whitespace
            while (!value.empty() && value[0] == ' ') {
                value = value.substr(1);
            }

            if (value.substr(0, 5) != "bytes") {
                m_logger->Debug(kLogXrdClPelican, "Invalid Content-Range value (no 'bytes' unit): %s", std::string(value).c_str());
                return 0;
            }

            value = value.substr(5);
            while (!value.empty() && value[0] == ' ') {
                value = value.substr(1);
            }

            // Example: 500-999/8000
            size_t count;
            long long bytes_val;
            try {
                // It may seem strange to see the string_view data being passed to std::stoll here
                // as it's not guaranteed to be null-terminated.  However, by this point, we do know
                // there's a CRLF in the buffer -- that is sufficient to guarantee the stoll search
                // terminates before it goes out-of-bounds. 
                bytes_val = std::stoll(value.data(), &count);
            } catch (std::invalid_argument &) {
                m_logger->Debug(kLogXrdClPelican, "Invalid Content-Range value (no integer in range start): %s", std::string(value).c_str());
                return 0;
            } catch (std::out_of_range &) {
                m_logger->Debug(kLogXrdClPelican, "Invalid Content-Range value (out of range): %s", std::string(value).c_str());
                return 0;
            }
            if (value.size() <= count || value[count] != '-') {
                m_logger->Debug(kLogXrdClPelican, "Invalid Content-Range value (no dash in range): %s", std::string(value).c_str());
                return 0;
            }
            m_current_op.first = bytes_val;
            value = value.substr(count + 1);
            try {
                bytes_val = std::stoll(value.data(), &count);
            } catch (std::invalid_argument &) {
                m_logger->Debug(kLogXrdClPelican, "Invalid Content-Range value (no integer in range end): %s", std::string(value).c_str());
                return 0;
            } catch (std::out_of_range &) {
                m_logger->Debug(kLogXrdClPelican, "Invalid Content-Range value (out of range in range end): %s", std::string(value).c_str());
                return 0;
            }
            if (value.size() <= count || value[count] != '/') {
                m_logger->Debug(kLogXrdClPelican, "Invalid Content-Range value (no trailing /): %s", std::string(value).c_str());
                return 0;
            }
            auto length = bytes_val + 1 - m_current_op.first;
            if (length < 0) {
                m_logger->Debug(kLogXrdClPelican, "Invalid Content-Range value (negative length): %s", std::string(line).c_str());
                return 0;
            }
            if (length > std::numeric_limits<decltype(m_current_op.second)>::max()) {
                m_logger->Debug(kLogXrdClPelican, "Invalid Content-Range value (length too long): %s", std::string(line).c_str());
                return 0;
            }
            m_current_op.second = length;

            // We now have a valid response range; locate a buffer where we will copy the bytes into.
            CalculateNextBuffer();
        }
        // Check to see if the Content-Range was missing.
        if (!last_segment && (m_current_op.first == -1 || m_current_op.second == -1)) {
            m_logger->Debug(kLogXrdClPelican, "Response segment is missing a Content-Range header");
            return 0;
        }
    }
    return orig_length;
}

void CurlVectorReadOp::CalculateNextBuffer() {
    // Strategy is to select the index where we will throw away the fewest bytes.
    off_t distance = std::numeric_limits<off_t>::max();
    auto starting_idx = m_response_idx;
    for (decltype(m_chunk_list)::size_type ctr=0; ctr<m_chunk_list.size(); ctr++) {
        auto idx = (starting_idx + ctr) % m_chunk_list.size();
        if (static_cast<uint64_t>(m_current_op.first) == m_chunk_list[idx].GetOffset()) {
            m_response_idx = idx;
            distance = 0;
            break;
        }
        off_t bytes_to_skip = static_cast<off_t>(m_chunk_list[idx].GetOffset()) - m_current_op.first;
        //m_logger->Debug(kLogXrdClPelican, "Using client request at index %lu would require us to skip %lld bytes", idx, static_cast<long long>(bytes_to_skip));
        if (bytes_to_skip > 0 && bytes_to_skip < distance) {
            distance = bytes_to_skip;
            m_response_idx = idx;
            // Note we don't break; some other request might be a better fit.
        }
    }
    m_chunk_buffer_idx = 0;
    if (distance > 0) {
        m_skip_bytes = distance;
    } else {
        m_skip_bytes = 0;
    }
}