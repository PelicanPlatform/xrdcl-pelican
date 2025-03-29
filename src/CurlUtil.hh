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

#include "ChecksumCache.hh"

#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

// Forward dec'ls
typedef void CURL;
struct curl_slist;

namespace XrdCl {

class ResponseHandler;
class Log;

}

namespace Pelican {

class CurlOperation;

const uint64_t kLogXrdClPelican = 73172;

bool HTTPStatusIsError(unsigned status);

std::pair<uint16_t, uint32_t> HTTPStatusConvert(unsigned status);

// Trim the left side of a string_view for space
std::string_view ltrim_view(const std::string_view &input_view);

// Trim the left and right side of a string_view of whitespace
std::string_view trim_view(const std::string_view &input_view);

// Returns a newly-created curl handle (no internal caching) with the
// various Pelican configurations
CURL *GetHandle(bool verbose);

// Connect to the broker socket and start callback request.
class BrokerRequest {
public:
    BrokerRequest(CURL *curl, const std::string &url);
    ~BrokerRequest();
    BrokerRequest(const BrokerRequest&) = delete;

    // Start a request to get a socket connection.
    // Returns a socket FD to monitor for reads on success or -1 on failure.
    // On failure, err is set to the error message.
    int StartRequest(std::string &err);

    // Finish the socket connection request.
    // Should only be called when the resulting socket from StartRequest is
    // ready for read.
    // On success, returns a FD connected to the requested server.
    // Returns -1 on failure and sets err to the error message.
    int FinishRequest(std::string &err);

    int GetBrokerSock() const {return m_req;}
private:
    std::string m_url;
    std::string m_origin;
    int m_req{-1};
    int m_rev{-1};
};

// Parser for headers as emitted by libcurl.
//
// Records specific headers known to be used by the project but ignores others.
class HeaderParser {
public:
    HeaderParser() {}

    bool Parse(const std::string &headers);

    int64_t GetContentLength() const {return m_content_length;}

    uint64_t GetOffset() const {return m_response_offset;}

    static bool Canonicalize(std::string &headerName);

    bool HeadersDone() const {return m_recv_all_headers;}

    int GetStatusCode() const {return m_status_code;}

    bool IsMultipartByterange() const {return m_multipart_byteranges;}

    std::string GetStatusMessage() const {return m_resp_message;}

    const std::string &GetLocation() const {return m_location;}

    const std::string &GetBroker() const {return m_broker;}

    const std::tuple<std::string, unsigned> GetMirrorInfo() const {return std::make_tuple(m_mirror_url, m_mirror_depth);}

    static std::tuple<std::string_view, int, bool> ParseInt(const std::string_view &val);
    static std::tuple<std::string_view, std::string, bool> ParseString(const std::string_view &val);

    // An entry in the `link` header, as defined by RFC 5988 and used by RFC 6249
    class LinkEntry {
    public:
        static std::tuple<std::vector<LinkEntry>, bool> FromHeaderValue(const std::string_view value);
        static std::tuple<std::string_view, LinkEntry, bool> IterFromHeaderValue(const std::string_view &value);
        unsigned GetPrio() const {return m_prio;}
        unsigned GetDepth() const {return m_depth;}
        const std::string &GetLink() const {return m_link;}

    private:
        unsigned m_prio{999999};
        unsigned m_depth{0};
        std::string m_link;
    };
    // Returns true if the headers indicate that X509 auth should be used
    // for the redirected URL (`X-Osdf-X509: true` is set).
    const bool GetX509Auth() const {return m_x509_auth;}

    // Returns a reference to the checksums parsed from the headers.
    const ChecksumCache::ChecksumInfo &GetChecksums() const {return m_checksums;}

    // Parse a RFC 3230 header, updating the checksum info structure.
    static void ParseDigest(const std::string &digest, ChecksumCache::ChecksumInfo &info);

    // Decode a base64-encoded string into a binary buffer.
    static bool Base64Decode(std::string_view input, std::array<unsigned char, 32> &output);

    // Convert a checksum type to a RFC 3230 digest name.
    static std::string ChecksumTypeToDigestName(ChecksumCache::ChecksumType type);
private:

    static bool validHeaderByte(unsigned char c);

    std::unordered_map<std::string, std::vector<std::string>> m_header_map;
    int64_t m_content_length{-1};
    uint64_t m_response_offset{0};

    ChecksumCache::ChecksumInfo m_checksums;

    bool m_recv_all_headers{false};
    bool m_recv_status_line{false};
    bool m_multipart_byteranges{false};
    bool m_x509_auth{false};

    int m_status_code{-1};
    unsigned m_mirror_depth{0};
    std::string m_resp_protocol;
    std::string m_resp_message;
    std::string m_location;
    std::string m_broker;
    std::string m_mirror_url;
};

/**
 * HandlerQueue is a deque of curl operations that need
 * to be performed.  The object is thread safe and can
 * be waited on via poll().
 *
 * The fact that it's poll'able is necessary because the
 * multi-curl driver thread is based on polling FD's
 */
class HandlerQueue {
public:
    HandlerQueue();

    void Produce(std::unique_ptr<CurlOperation> handler);

    std::unique_ptr<CurlOperation> Consume();
    std::unique_ptr<CurlOperation> TryConsume();

    int PollFD() const {return m_read_fd;}

    CURL *GetHandle();
    void RecycleHandle(CURL *);

private:
    std::deque<std::unique_ptr<CurlOperation>> m_ops;
    thread_local static std::vector<CURL*> m_handles;
    std::condition_variable m_consumer_cv;
    std::condition_variable m_producer_cv;
    std::mutex m_mutex;
    const static unsigned m_max_pending_ops{20};
    int m_read_fd{-1};
    int m_write_fd{-1};
};

}
