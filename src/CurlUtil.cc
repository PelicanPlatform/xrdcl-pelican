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
#include "CurlUtil.hh"
#include "CurlWorker.hh"

#include <XProtocol/XProtocol.hh>
#include <XrdCl/XrdClDefaultEnv.hh>
#include <XrdCl/XrdClLog.hh>
#include <XrdCl/XrdClURL.hh>
#include <XrdCl/XrdClXRootDResponses.hh>
#include <XrdOuc/XrdOucCRC.hh>
#include <XrdSys/XrdSysPageSize.hh>

#include <nlohmann/json.hpp>
#include <curl/curl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include <fstream>
#include <sys/un.h>
#ifdef __APPLE__
#include <pthread.h>
#else
#include <sys/syscall.h>
#include <sys/types.h>
#endif
#include <unistd.h>

#include <charconv>
#include <sstream>
#include <stdexcept>
#include <utility>

using namespace Pelican;

thread_local std::vector<CURL*> HandlerQueue::m_handles;

struct WaitingForBroker {
    CURL *curl{nullptr};
    time_t expiry{0};
};

namespace {

pid_t getthreadid() {
#ifdef __APPLE__
    auto self = pthread_self();
    uint64_t pth_threadid;
    pthread_threadid_np(pthread_self(), &pth_threadid);
    return pth_threadid;
#else
    // NOTE: glibc 2.30 finally provides a gettid() wrapper; however,
    // we currently support RHEL 8, which is based on glibc 2.28.  Until
    // we drop that platform, it's easier to do the syscall directly on Linux
    // instead of additional ifdef calls.
    return syscall(SYS_gettid);
#endif
}

void ltrim(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
}

inline void rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), s.end());
}

}

bool Pelican::HTTPStatusIsError(unsigned status) {
     return (status < 100) || (status >= 400);
}

std::pair<uint16_t, uint32_t> Pelican::HTTPStatusConvert(unsigned status) {
    //std::cout << "HTTPStatusConvert: " << status << "\n";
    switch (status) {
        case 400: // Bad Request
            return std::make_pair(XrdCl::errErrorResponse, kXR_InvalidRequest);
        case 401: // Unauthorized (needs authentication)
            return std::make_pair(XrdCl::errErrorResponse, kXR_NotAuthorized);
        case 402: // Payment Required
        case 403: // Forbidden (failed authorization)
            return std::make_pair(XrdCl::errErrorResponse, kXR_NotAuthorized);
        case 404:
            return std::make_pair(XrdCl::errErrorResponse, kXR_NotFound);
        case 405: // Method not allowed
        case 406: // Not acceptable
            return std::make_pair(XrdCl::errErrorResponse, kXR_InvalidRequest);
        case 407: // Proxy Authentication Required
            return std::make_pair(XrdCl::errErrorResponse, kXR_NotAuthorized);
        case 408: // Request timeout
            return std::make_pair(XrdCl::errErrorResponse, kXR_ReqTimedOut);
        case 409: // Conflict
            return std::make_pair(XrdCl::errErrorResponse, kXR_Conflict);
        case 410: // Gone
            return std::make_pair(XrdCl::errErrorResponse, kXR_NotFound);
        case 411: // Length required
        case 412: // Precondition failed
        case 413: // Payload too large
        case 414: // URI too long
        case 415: // Unsupported Media Type
        case 416: // Range Not Satisfiable
        case 417: // Expectation Failed
        case 418: // I'm a teapot
	    return std::make_pair(XrdCl::errErrorResponse, kXR_InvalidRequest);
        case 421: // Misdirected Request
        case 422: // Unprocessable Content
            return std::make_pair(XrdCl::errErrorResponse, kXR_InvalidRequest);
        case 423: // Locked
            return std::make_pair(XrdCl::errErrorResponse, kXR_FileLocked);
        case 424: // Failed Dependency
        case 425: // Too Early
        case 426: // Upgrade Required
        case 428: // Precondition Required
            return std::make_pair(XrdCl::errErrorResponse, kXR_InvalidRequest);
        case 429: // Too Many Requests
            return std::make_pair(XrdCl::errErrorResponse, kXR_Overloaded);
        case 431: // Request Header Fields Too Large
            return std::make_pair(XrdCl::errErrorResponse, kXR_InvalidRequest);
        case 451: // Unavailable For Legal Reasons
            return std::make_pair(XrdCl::errErrorResponse, kXR_Impossible);
        case 500: // Internal Server Error
        case 501: // Not Implemented
        case 502: // Bad Gateway
        case 503: // Service Unavailable
            return std::make_pair(XrdCl::errErrorResponse, kXR_ServerError);
        case 504: // Gateway Timeout
            return std::make_pair(XrdCl::errErrorResponse, kXR_ReqTimedOut);
        case 507: // Insufficient Storage
            return std::make_pair(XrdCl::errErrorResponse, kXR_overQuota);
        case 508: // Loop Detected
        case 510: // Not Extended
        case 511: // Network Authentication Required
            return std::make_pair(XrdCl::errErrorResponse, kXR_ServerError);
    }
    return std::make_pair(XrdCl::errUnknown, status);
}

std::pair<uint16_t, uint32_t> CurlCodeConvert(CURLcode res) {
    switch (res) {
        case CURLE_OK:
            return std::make_pair(XrdCl::errNone, 0);
        case CURLE_COULDNT_RESOLVE_PROXY:
        case CURLE_COULDNT_RESOLVE_HOST:
            return std::make_pair(XrdCl::errInvalidAddr, 0);
        case CURLE_LOGIN_DENIED:
        // Commented-out cases are for platforms (RHEL7) where the error
        // codes are undefined.
        //case CURLE_AUTH_ERROR:
        //case CURLE_SSL_CLIENTCERT:
        case CURLE_REMOTE_ACCESS_DENIED:
            return std::make_pair(XrdCl::errLoginFailed, EACCES);
        case CURLE_SSL_CONNECT_ERROR:
        case CURLE_SSL_ENGINE_NOTFOUND:
        case CURLE_SSL_ENGINE_SETFAILED:
        case CURLE_SSL_CERTPROBLEM:
        case CURLE_SSL_CIPHER:
        case 51: // In old curl versions, this is CURLE_PEER_FAILED_VERIFICATION; that constant was changed to be 60 / CURLE_SSL_CACERT
        case CURLE_SSL_SHUTDOWN_FAILED:
        case CURLE_SSL_CRL_BADFILE:
        case CURLE_SSL_ISSUER_ERROR:
        case CURLE_SSL_CACERT: // value is 60; merged with CURLE_PEER_FAILED_VERIFICATION
        //case CURLE_SSL_PINNEDPUBKEYNOTMATCH:
        //case CURLE_SSL_INVALIDCERTSTATUS:
            return std::make_pair(XrdCl::errTlsError, 0);
        case CURLE_SEND_ERROR:
        case CURLE_RECV_ERROR:
            return std::make_pair(XrdCl::errSocketError, EIO);
        case CURLE_COULDNT_CONNECT:
        case CURLE_GOT_NOTHING:
            return std::make_pair(XrdCl::errConnectionError, ECONNREFUSED);
        case CURLE_OPERATION_TIMEDOUT:
#ifdef HAVE_XPROTOCOL_TIMEREXPIRED
            return std::make_pair(XrdCl::errErrorResponse, XErrorCode::kXR_TimerExpired);
#else
            return std::make_pair(XrdCl::errOperationExpired, ESTALE);
#endif
        case CURLE_UNSUPPORTED_PROTOCOL:
        case CURLE_NOT_BUILT_IN:
            return std::make_pair(XrdCl::errNotSupported, ENOSYS);
        case CURLE_FAILED_INIT:
            return std::make_pair(XrdCl::errInternal, 0);
        case CURLE_URL_MALFORMAT:
            return std::make_pair(XrdCl::errInvalidArgs, res);
        //case CURLE_WEIRD_SERVER_REPLY:
        //case CURLE_HTTP2:
        //case CURLE_HTTP2_STREAM:
            return std::make_pair(XrdCl::errCorruptedHeader, res);
        case CURLE_PARTIAL_FILE:
            return std::make_pair(XrdCl::errDataError, res);
        // These two errors indicate a failure in the callback.  That
        // should generate their own failures, meaning this should never
        // get use.
        case CURLE_READ_ERROR:
        case CURLE_WRITE_ERROR:
            return std::make_pair(XrdCl::errInternal, res);
        case CURLE_RANGE_ERROR:
        case CURLE_BAD_CONTENT_ENCODING:
            return std::make_pair(XrdCl::errNotSupported, res);
        case CURLE_TOO_MANY_REDIRECTS:
            return std::make_pair(XrdCl::errRedirectLimit, res);
        default:
            return std::make_pair(XrdCl::errUnknown, res);
    }
}

bool HeaderParser::Base64Decode(std::string_view input, std::array<unsigned char, 32> &output) {
    if (input.size() > 44 || input.size() % 4 != 0) return false;
    if (input.size() == 0) return true;

    std::unique_ptr<BIO, decltype(&BIO_free_all)> b64(BIO_new(BIO_f_base64()), &BIO_free_all);
    BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);
    std::unique_ptr<BIO, decltype(&BIO_free_all)> bmem(
        BIO_new_mem_buf(const_cast<char *>(input.data()), input.size()), &BIO_free_all);
    bmem.reset(BIO_push(b64.release(), bmem.release()));

    // Compute expected length of output; used to verify BIO_read consumes all input
    size_t expectedLen = static_cast<size_t>(input.size() * 0.75);
    if (input[input.size() - 1] == '=') {
        expectedLen -= 1;
        if (input[input.size() - 2] == '=') {
            expectedLen -= 1;
        }
    }

    auto len = BIO_read(bmem.get(), &output[0], output.size());

    if (len == -1 || static_cast<size_t>(len) != expectedLen) return false;

    return true;
}

bool HeaderParser::Parse(const std::string &headers)
{
    if (m_recv_all_headers) {
        m_recv_all_headers = false;
        m_recv_status_line = false;
    }

    if (!m_recv_status_line) {
        m_recv_status_line = true;

        std::stringstream ss(headers);
        std::string item;
        if (!std::getline(ss, item, ' ')) return false;
        m_resp_protocol = item;
        if (!std::getline(ss, item, ' ')) return false;
        try {
            m_status_code = std::stol(item);
        } catch (...) {
            return false;
        }
        if (m_status_code < 100 || m_status_code >= 600) {
            return false;
        }
        if (!std::getline(ss, item, '\n')) return false;
        m_resp_message = item;
        return true;
    }

    if (headers.empty() || headers == "\n" || headers == "\r\n") {
        m_recv_all_headers = true;
        return true;
    }

    auto found = headers.find(":");
    if (found == std::string::npos) {
        return false;
    }

    std::string header_name = headers.substr(0, found);
    if (!Canonicalize(header_name)) {
        return false;
    }

    found += 1;
    while (found < headers.size()) {
        if (headers[found] != ' ') {break;}
        found += 1;
    }
    std::string header_value = headers.substr(found);
    // Note: ignoring the fact headers are only supposed to contain ASCII.
    // We should trim out UTF-8.
    header_value.erase(header_value.find_last_not_of(" \r\n\t") + 1);

    auto iter = m_header_map.find("header_name");
    if (iter == m_header_map.end()) {
        m_header_map.emplace(std::make_pair(header_value, std::vector<std::string>({header_value})));
    } else {
        iter->second.emplace_back(header_value);
    }

    if (header_name == "Content-Length") {
         try {
             m_content_length = std::stoll(header_value);
         } catch (...) {
             return false;
         }
    }
    else if (header_name == "Content-Type") {
        auto found = header_value.find(";");
        std::string first_type = header_value.substr(0, found);
        m_multipart_byteranges = first_type == "multipart/byteranges";
    }
    else if (header_name == "Content-Range") {
        auto found = header_value.find(" ");
        if (found == std::string::npos) {
            return false;
        }
        std::string range_unit = header_value.substr(0, found);
        if (range_unit != "bytes") {
            return false;
        }
        auto range_resp = header_value.substr(found + 1);
        found = range_resp.find("/");
        if (found == std::string::npos) {
            return false;
        }
        auto incl_range = range_resp.substr(0, found);
        found = incl_range.find("-");
        if (found == std::string::npos) {
            return false;
        }
        auto first_pos = incl_range.substr(0, found);
        try {
            m_response_offset = std::stoll(first_pos);
        } catch (...) {
           return false;
        }
        auto last_pos = incl_range.substr(found + 1);
        size_t last_byte;
        try {
           last_byte = std::stoll(last_pos);
        } catch (...) {
           return false;
        }
        m_content_length = last_byte - m_response_offset + 1;
    }
    else if (header_name == "Location") {
        m_location = header_value;
    }
    else if (header_name == "X-Pelican-Broker") {
        m_broker = header_value;
    }
    else if (header_name == "Link") {
        auto [entries, ok] = LinkEntry::FromHeaderValue(header_value);
        if (ok && !entries.empty()) {
            m_mirror_depth = entries[0].GetDepth();
            m_mirror_url = entries[0].GetLink();
        }
    } else if (header_name == "Digest") {
        ParseDigest(header_value, m_checksums);
    } else if (header_name == "X-Osdf-X509" && header_value == "true") {
        m_x509_auth = true;
    }

    return true;
}

// Parse a RFC 3230 header into the checksum info structure
//
// If the parsing fails, the second element of the tuple will be false.
void HeaderParser::ParseDigest(const std::string &digest, ChecksumCache::ChecksumInfo &info) {
    std::string_view view(digest);
    std::array<unsigned char, 32> checksum_value;
    std::string digest_lower;
    while (!view.empty()) {
        auto nextsep = view.find(',');
        auto entry = view.substr(0, nextsep);
        if (nextsep == std::string_view::npos) {
            view = "";
        } else {
            view = view.substr(nextsep + 1);
        }
        nextsep = entry.find('=');
        auto name = entry.substr(0, nextsep);
        auto value = entry.substr(nextsep + 1);
        digest_lower.clear();
        digest_lower.resize(name.size());
        std::transform(name.begin(), name.end(), digest_lower.begin(), [](unsigned char c) {
            return std::tolower(c);
        });
        if (digest_lower == "md5") {
            if (value.size() != 24) {
                continue;
            }
            if (Base64Decode(value, checksum_value)) {
                info.Set(ChecksumCache::ChecksumType::kMD5, checksum_value);
            }
        } else if (digest_lower == "crc32c") {
            // XRootD currently incorrectly base64-encodes crc32c checksums; see
            // https://github.com/xrootd/xrootd/issues/2456
            // For backward comaptibility, if this looks like base64 encoded (8
            // bytes long and last two bytes are padding), then we base64 decode.
            if (value.size() == 8 && value[6] == '=' && value[7] == '=') {
                if (Base64Decode(value, checksum_value)) {
                    info.Set(ChecksumCache::ChecksumType::kCRC32C, checksum_value);
                }
                continue;
            }
            std::size_t pos{0};
            unsigned long val;
            try {
                val = std::stoul(value.data(), &pos, 16);
            } catch (...) {
                continue;
            }
            if (pos == value.size()) {
                checksum_value[0] = (val >> 24) & 0xFF;
                checksum_value[1] = (val >> 16) & 0xFF;
                checksum_value[2] = (val >> 8) & 0xFF;
                checksum_value[3] = val & 0xFF;
                info.Set(ChecksumCache::ChecksumType::kCRC32C, checksum_value);
            }
        }
    }
}

// Convert the checksum type to a RFC 3230 digest name as recorded by IANA here:
// https://www.iana.org/assignments/http-dig-alg/http-dig-alg.xhtml
std::string HeaderParser::ChecksumTypeToDigestName(ChecksumCache::ChecksumType type) {
    switch (type) {
        case ChecksumCache::ChecksumType::kMD5:
            return "MD5";
        case ChecksumCache::ChecksumType::kCRC32C:
            return "CRC32c";
        case ChecksumCache::ChecksumType::kSHA1:
            return "SHA";
        case ChecksumCache::ChecksumType::kSHA256:
            return "SHA-256";
        default:
            return "";
    }
}

// This clever approach was inspired by golang's net/textproto
bool HeaderParser::validHeaderByte(unsigned char c)
{
    const static uint64_t mask_lower = 0 |
        uint64_t((1<<10)-1) << '0' |
        uint64_t(1) << '!' |
        uint64_t(1) << '#' |
        uint64_t(1) << '$' |
        uint64_t(1) << '%' |
        uint64_t(1) << '&' |
        uint64_t(1) << '\'' |
        uint64_t(1) << '*' |
        uint64_t(1) << '+' |
        uint64_t(1) << '-' |
        uint64_t(1) << '.';

    const static uint64_t mask_upper = 0 |
        uint64_t((1<<26)-1) << ('a'-64) |
        uint64_t((1<<26)-1) << ('A'-64) |
        uint64_t(1) << ('^'-64) |
        uint64_t(1) << ('_'-64) |
        uint64_t(1) << ('`'-64) |
        uint64_t(1) << ('|'-64) |
        uint64_t(1) << ('~'-64);

    if (c >= 128) return false;
    if (c >= 64) return (uint64_t(1)<<(c-64)) & mask_upper;
    return (uint64_t(1) << c) & mask_lower;
}

bool HeaderParser::Canonicalize(std::string &headerName)
{
    auto upper = true;
    const static int toLower = 'a' - 'A';
    for (size_t idx=0; idx<headerName.size(); idx++) {
        char c = headerName[idx];
        if (!validHeaderByte(c)) {
            return false;
        }
        if (upper && 'a' <= c && c <= 'z') {
            c -= toLower;
        } else if (!upper && 'A' <= c && c <= 'Z') {
            c += toLower;
        }
        headerName[idx] = c;
        upper = c == '-';
    }
    return true;
}

HandlerQueue::HandlerQueue() {
    int filedes[2];
    auto result = pipe(filedes);
    if (result == -1) {
        throw std::runtime_error(strerror(errno));
    }
    m_read_fd = filedes[0];
    m_write_fd = filedes[1];
};

// Parse a HTTP-header-style integer
//
// Returns a tuple consisting of the remainder of the input data, the integer value,
// and a boolean indicating whether the parsing was successful.
std::tuple<std::string_view, int, bool> HeaderParser::ParseInt(const std::string_view &val) {
    if (val.empty()) {
        return std::make_tuple("", 0, false);
    }
    int result{};
    auto [ptr, ec] = std::from_chars(val.data(), val.data() + val.size(), result);
    if (ec == std::errc()) {
        return std::make_tuple(val.substr(ptr - val.data()), result, true);
    }
    return std::make_tuple("", 0, false);
}

// Parse a HTTP-header-style quoted string
//
// Returns a tuple consisting of the remainder of the input data, the quoted string contents,
// and a boolean indicating whether the parsing was successful.
std::tuple<std::string_view, std::string, bool> HeaderParser::ParseString(const std::string_view &val) {
    if (val.empty() || val[0] != '"') {
        return std::make_tuple("", "", false);
    }
    std::string result;
    auto endLoc = val.find('"');
    if (endLoc == std::string_view::npos) {
        return std::make_tuple("", "", false);
    }
    result.reserve(endLoc);
    for (size_t idx = 1; idx < val.size(); idx++) {
        if (val[idx] == '\\') {
            idx++;
            if (idx == val.size()) {
                return std::make_tuple("", "", false);
            }
            switch (val[idx]) {
            case '\\':
                result.push_back('\\');
                break;
            case 'r':
                result.push_back('\r');
                break;
            case 'n':
                result.push_back('\n');
                break;
            case '"':
                result.push_back('"');
                break;
            default:
                return std::make_tuple("", "", false);
            }
        } else if (val[idx] == '"') {
            return std::make_tuple(val.substr(idx + 1), result, true);
        } else {
            result.push_back(val[idx]);
        }
    }
    return std::make_tuple("", "", false);
}

namespace {

// Simple debug function for getting information from libcurl; to enable, you need to
// recompile with GetHandle(true);
int dump_header(CURL *handle, curl_infotype type, char *data, size_t size, void *clientp) {
    (void)handle;
    (void)clientp;

    switch (type) {
    case CURLINFO_HEADER_OUT:
        printf("Header > %s\n", std::string(data, size).c_str());
        break;
    default:
        printf("Info: %s", std::string(data, size).c_str());
        break;
    }
    return 0;
}

std::string UrlDecode(CURL *curl, const std::string &src) {
    int decodelen;
    char *decoded = curl_easy_unescape(curl, src.c_str(), src.size(), &decodelen);
    std::string result(decoded, decodelen);
    curl_free(decoded);
    return result;
}

}

// Trim left and righit side of a string_view for space characters
std::string_view Pelican::trim_view(const std::string_view &input_view) {
    auto view = ltrim_view(input_view);
    for (size_t idx = 0; idx < input_view.size(); idx++) {
        if (!isspace(view[view.size() - 1 - idx])) {
            return view.substr(0, view.size() - idx);
        }
    }
    return "";
}

// Trim the left side of a string_view for space
std::string_view Pelican::ltrim_view(const std::string_view &input_view) {
    for (size_t idx = 0; idx < input_view.size(); idx++) {
        if (!isspace(input_view[idx])) {
            return input_view.substr(idx);
        }
    }
    return "";
}

std::tuple<std::string_view, HeaderParser::LinkEntry, bool> HeaderParser::LinkEntry::IterFromHeaderValue(const std::string_view &value) {
    LinkEntry curEntry;
    bool isValid{true};
    std::string_view entry = ltrim_view(value);
    while (true) {
        entry = ltrim_view(entry);
        if (entry.empty()) {
            return std::make_tuple("", curEntry, false);
        } else if (entry[0] == '<') {
            auto endLoc = entry.find('>', 1);
            if (endLoc == std::string_view::npos) {
                return std::make_tuple("", curEntry, false);
            }
            curEntry.m_link = entry.substr(1, endLoc - 1);
            entry = ltrim_view(entry.substr(endLoc + 1));
        } else {
            auto keyEndLoc = entry.find('=');
            if (keyEndLoc == std::string_view::npos) {
                return std::make_tuple("", curEntry, false);
            }
            auto key = trim_view(entry.substr(0, keyEndLoc));
            auto val = ltrim_view(entry.substr(keyEndLoc + 1));
            if (val.empty()) {
                return std::make_tuple("", curEntry, false);
            }
            std::string stringValue;
            int intValue{-1};
            bool ok{false}, isStr{false};
            if (val[0] == '"') {
                isStr = true;
                std::tie(entry, stringValue, ok) = HeaderParser::ParseString(val);
            } else {
                std::tie(entry, intValue, ok) = HeaderParser::ParseInt(val);
            }
            if (!ok) {
                return std::make_tuple("", curEntry, false);
            }
            if (key == "pri" && !isStr) {
                curEntry.m_prio = intValue;
            }
            if (key == "depth" && !isStr) {
                curEntry.m_depth = intValue;
            }
            if (key == "rel" && isStr && stringValue != "duplicate") {
                isValid = false;
            }
        }
        if (entry.empty()) {
            return std::make_tuple("", curEntry, isValid);
        } else if (entry[0] == ',') {
            return std::make_tuple(entry.substr(1), curEntry, isValid);
        } else if (entry[0] != ';') {
            return std::make_tuple("", curEntry, false);
        }
        entry = entry.substr(1);
    }
    return std::make_tuple(entry, curEntry, isValid);
}

CURL *
Pelican::GetHandle(bool verbose) {
    auto result = curl_easy_init();
    if (result == nullptr) {
        return result;
    }

    curl_easy_setopt(result, CURLOPT_USERAGENT, "xrdcl-pelican/1.0.2");
    curl_easy_setopt(result, CURLOPT_DEBUGFUNCTION, dump_header);
    if (verbose)
        curl_easy_setopt(result, CURLOPT_VERBOSE, 1L);

    auto env = XrdCl::DefaultEnv::GetEnv();
    std::string ca_file;
    if (!env->GetString("PelicanCertFile", ca_file) || ca_file.empty()) {
        char *x509_ca_file = getenv("X509_CERT_FILE");
        if (x509_ca_file) {
            ca_file = std::string(x509_ca_file);
        }
    }
    if (!ca_file.empty()) {
        curl_easy_setopt(result, CURLOPT_CAINFO, ca_file.c_str());
    }
    std::string ca_dir;
    if (!env->GetString("PelicanCertDir", ca_dir) || ca_dir.empty()) {
        char *x509_ca_dir = getenv("X509_CERT_DIR");
        if (x509_ca_dir) {
            ca_dir = std::string(x509_ca_dir);
        }
    }
    if (!ca_dir.empty()) {
        curl_easy_setopt(result, CURLOPT_CAPATH, ca_dir.c_str());
    }

    curl_easy_setopt(result, CURLOPT_BUFFERSIZE, 32*1024);

    return result;
}

std::tuple<std::vector<HeaderParser::LinkEntry>, bool> HeaderParser::LinkEntry::FromHeaderValue(const std::string_view value) {
    std::string_view remainder = value;
    bool ok;
    std::vector<LinkEntry> result;
    do {
        LinkEntry entry;
        std::tie(remainder, entry, ok) = IterFromHeaderValue(remainder);
        if (ok) {
            result.emplace_back(std::move(entry));
        } else if (!ok && remainder.empty()) {
            return std::make_tuple(result, false);
        }
    } while (!remainder.empty());
    std::sort(result.begin(), result.end(), [](const LinkEntry &left, const LinkEntry &right){return left.GetPrio() < right.GetPrio();});
    return std::make_tuple(result, true);
}

CURL *
HandlerQueue::GetHandle() {
    if (m_handles.size()) {
        auto result = m_handles.back();
        m_handles.pop_back();
        return result;
    }

    return ::GetHandle(false);
}

void
HandlerQueue::RecycleHandle(CURL *curl) {
    m_handles.push_back(curl);
}

void
HandlerQueue::Produce(std::unique_ptr<CurlOperation> handler)
{
    std::unique_lock<std::mutex> lk{m_mutex};
    m_producer_cv.wait(lk, [&]{return m_ops.size() < m_max_pending_ops;});

    m_ops.push_back(std::move(handler));
    char ready[] = "1";
    while (true) {
        auto result = write(m_write_fd, ready, 1);
        if (result == -1) {
            if (errno == EINTR) {
                continue;
            }
            throw std::runtime_error(strerror(errno));
        }
        break;
    }

    lk.unlock();
    m_consumer_cv.notify_one();
}

std::unique_ptr<CurlOperation>
HandlerQueue::Consume()
{
    std::unique_lock<std::mutex> lk(m_mutex);
    m_consumer_cv.wait(lk, [&]{return m_ops.size() > 0;});

    auto result = std::move(m_ops.front());
    m_ops.pop_front();

    char ready[1];
    while (true) {
        auto result = read(m_read_fd, ready, 1);
        if (result == -1) {
            if (errno == EINTR) {
                continue;
            }
            throw std::runtime_error(strerror(errno));
        }
        break;
    }

    lk.unlock();
    m_producer_cv.notify_one();

    return result;
}

std::unique_ptr<CurlOperation>
HandlerQueue::TryConsume()
{
    std::unique_lock<std::mutex> lk(m_mutex);
    if (m_ops.size() == 0) {
        std::unique_ptr<CurlOperation> result;
        return result;
    }

    auto result = std::move(m_ops.front());
    m_ops.pop_front();

    char ready[1];
    while (true) {
        auto result = read(m_read_fd, ready, 1); 
        if (result == -1) {
            if (errno == EINTR) {
                continue;
            }   
            throw std::runtime_error(strerror(errno));
        }   
        break;
    }

    lk.unlock();
    m_producer_cv.notify_one();

    return result;
}

CurlWorker::CurlWorker(std::shared_ptr<HandlerQueue> queue, XrdCl::Log* logger) :
    m_queue(queue),
    m_logger(logger)
{
    // Handle setup of the X509 authentication
    auto env = XrdCl::DefaultEnv::GetEnv();
    RefreshX509Prefixes(env);
    env->GetString("PelicanClientCertFile", m_x509_client_cert_file);
    env->GetString("PelicanClientKeyFile", m_x509_client_key_file);
    env->GetString("PelicanCacheTokenLocation", m_token_file);

    if (m_token_file.empty()) {
        m_logger->Debug(kLogXrdClPelican, "Cache token location is not set; will skip cache token usage");
    }
    RefreshCacheToken();
}

bool CurlWorker::UseX509Auth(XrdCl::URL &url)
{
    if (m_x509_all) {
        return true;
    }
    auto &path = url.GetPath();
    for (const auto &x509_path : m_x509_prefixes) {
        std::string_view path_view{path};
        if (path_view.substr(0, x509_path.size()) == x509_path) {
            return true;
        }
    }
    return false;
}

std::tuple<std::string, std::string> CurlWorker::ClientX509CertKeyFile() const
{
    return std::make_tuple(m_x509_client_cert_file, m_x509_client_key_file);
}


void
CurlWorker::RunStatic(CurlWorker *myself)
{
    try {
        myself->Run();
    } catch (...) {
        myself->m_logger->Warning(kLogXrdClPelican, "Curl worker got an exception");
    }
}

void
CurlWorker::Run() {
    // Create a copy of the shared_ptr here.  Otherwise, when the main thread's destructors
    // run, there won't be any other live references to the shared_ptr, triggering cleanup
    // of the condition variable.  Because we purposely don't shutdown the worker threads,
    // those threads may be waiting on the condition variable; destroying a condition variable
    // while a thread is waiting on it is undefined behavior.
    auto queue_ref = m_queue;
    m_continue_queue.reset(new HandlerQueue());
    auto &queue = *queue_ref.get();
    m_logger->Debug(kLogXrdClPelican, "Started a curl worker");

    CURLM *multi_handle = curl_multi_init();
    if (multi_handle == nullptr) {
        throw std::runtime_error("Failed to create curl multi-handle");
    }

    int running_handles = 0;
    time_t last_marker = time(NULL);
    CURLMcode mres = CURLM_OK;

    // Map from a file descriptor that has an outstanding broker request
    // to the corresponding CURL handle.
    std::unordered_map<int, WaitingForBroker> broker_reqs;
    std::vector<struct curl_waitfd> waitfds;

    auto env = XrdCl::DefaultEnv::GetEnv();

    while (true) {
        while (running_handles < static_cast<int>(m_max_ops)) {
            auto op = m_continue_queue->TryConsume();
            if (!op) {
                break;
            }
            op->ContinueHandle();
            // The operation is owned by the worker, even when it's paused; this ownership
            // is a lie so we need to release (and not delete) ownership.
            op.release();
		}
        while (running_handles < static_cast<int>(m_max_ops)) {
            auto op = running_handles == 0 ? queue.Consume() : queue.TryConsume();
            if (!op) {
                break;
            }
            auto curl = queue.GetHandle();
            if (curl == nullptr) {
                m_logger->Debug(kLogXrdClPelican, "Unable to allocate a curl handle");
                op->Fail(XrdCl::errInternal, ENOMEM, "Unable to get allocate a curl handle");
                continue;
            }
            try {
                op->Setup(curl, *this);
            } catch (...) {
                m_logger->Debug(kLogXrdClPelican, "Unable to setup the curl handle");
                op->Fail(XrdCl::errInternal, ENOMEM, "Failed to setup the curl handle for the operation");
                continue;
            }
            op->SetContinueQueue(m_continue_queue);

            if (!SetupCacheToken(curl)) {
                m_logger->Warning(kLogXrdClPelican, "Failed to setup cache token for curl handle");
                op->Fail(XrdCl::errInternal, 0, "Failed to setup cache token for curl handle");
            }
            if (op->IsDone()) {
                continue;
            }
            m_op_map[curl] = std::move(op);
            auto mres = curl_multi_add_handle(multi_handle, curl);
            if (mres != CURLM_OK) {
                m_logger->Debug(kLogXrdClPelican, "Unable to add operation to the curl multi-handle");
                op->Fail(XrdCl::errInternal, mres, "Unable to add operation to the curl multi-handle");
                continue;
            }
            running_handles += 1;
        }

        // Maintain the periodic reporting of thread activity
        time_t now = time(NULL);
        time_t next_marker = last_marker + m_marker_period;
        if (now >= next_marker) {
            m_logger->Debug(kLogXrdClPelican, "Curl worker thread %d is running %d operations",
                getthreadid(), running_handles);
            last_marker = now;
            std::vector<std::pair<int, CURL *>> expired_ops;
            for (const auto &entry : broker_reqs) {
                if (entry.second.expiry < now) {
                    expired_ops.emplace_back(entry.first, entry.second.curl);
                }
            }
            for (const auto &entry : expired_ops) {
                auto iter = m_op_map.find(entry.second);
                if (iter == m_op_map.end()) {
                    m_logger->Warning(kLogXrdClPelican, "Found an expired curl handle with no corresponding operation!");
                } else {
                    iter->second->Fail(XrdCl::errConnectionError, 1, "Timeout: broker never provided connection to origin");
                    iter->second->ReleaseHandle();
                    m_op_map.erase(entry.second);
                    curl_easy_cleanup(entry.second);
                    running_handles -= 1;
                }
                broker_reqs.erase(entry.first);
            }
            RefreshX509Prefixes(env);
            RefreshCacheToken();
        }

        // Wait until there is activity to perform.
        int64_t max_sleep_time = next_marker - now;
        if (max_sleep_time < 0) max_sleep_time = 0;

        waitfds.clear();
        waitfds.resize(2 + broker_reqs.size());

        waitfds[0].fd = queue.PollFD();
        waitfds[0].events = CURL_WAIT_POLLIN;
        waitfds[0].revents = 0;
        waitfds[1].fd = m_continue_queue->PollFD();
        waitfds[1].events = CURL_WAIT_POLLIN;
        waitfds[1].revents = 0;

        int idx = 2;
        for (const auto &entry : broker_reqs) {
            waitfds[idx].fd = entry.first;
            waitfds[idx].events = CURL_WAIT_POLLIN|CURL_WAIT_POLLPRI;
            waitfds[idx].revents = 0;
            idx += 1;
        }

        long timeo;
        curl_multi_timeout(multi_handle, &timeo);
        // These commented-out lines are purposely left; will need to revisit after the 0.9.1 release;
        // for now, they are too verbose on RHEL7.
        //m_logger->Debug(kLogXrdClPelican, "Curl advises a timeout of %ld ms", timeo);
        if (running_handles && timeo == -1) {
            // Bug workaround: we've seen RHEL7 libcurl have a race condition where it'll not
            // set a timeout while doing the DNS lookup; assume that if there are running handles
            // but no timeout, we've hit this bug.
            //m_logger->Debug(kLogXrdClPelican, "Will sleep for up to 50ms");
            mres = curl_multi_wait(multi_handle, &waitfds[0], waitfds.size(), 50, nullptr);
        } else {
            //m_logger->Debug(kLogXrdClPelican, "Will sleep for up to %d seconds", max_sleep_time);
            //mres = curl_multi_wait(multi_handle, &waitfds[0], waitfds.size(), max_sleep_time*1000, nullptr);
            // Temporary test: we've been seeing DNS lookups timeout on additional platforms.  Switch to always
            // poll as curl_multi_wait doesn't seem to get notified when DNS lookups are done.
            mres = curl_multi_wait(multi_handle, &waitfds[0], waitfds.size(), 50, nullptr);
        }
        if (mres != CURLM_OK) {
            m_logger->Warning(kLogXrdClPelican, "Failed to wait on multi-handle: %d", mres);
        }

        // Iterate through the waiting broker callbacks.
        for (const auto &entry : waitfds) {
            // Ignore the queue's poll fd.
            if (waitfds[0].fd == entry.fd || waitfds[1].fd == entry.fd) {
                continue;
            }
            if ((entry.revents & CURL_WAIT_POLLIN) != CURL_WAIT_POLLIN) {
                continue;
            }
            auto handle = broker_reqs[entry.fd].curl;
            auto iter = m_op_map.find(handle);
            if (iter == m_op_map.end()) {
                m_logger->Warning(kLogXrdClPelican, "Internal error: broker responded on FD %d but no corresponding curl operation", entry.fd);
                broker_reqs.erase(entry.fd);
                continue;
            }
            std::string err;
            auto result = iter->second->WaitSocketCallback(err);
            if (result == -1) {
                m_logger->Warning(kLogXrdClPelican, "Error when invoking the broker callback: %s", err.c_str());
                iter->second->Fail(XrdCl::errErrorResponse, 1, err);
                m_op_map.erase(handle);
                broker_reqs.erase(entry.fd);
                running_handles -= 1;
            } else {
                broker_reqs.erase(entry.fd);
                curl_multi_add_handle(multi_handle, handle);
            }
        }

        // Do maintenance on the multi-handle
        int still_running;
        auto mres = curl_multi_perform(multi_handle, &still_running);
        if (mres == CURLM_CALL_MULTI_PERFORM) {
            continue;
        } else if (mres != CURLM_OK) {
            m_logger->Warning(kLogXrdClPelican, "Failed to perform multi-handle operation: %d", mres);
            break;
        }

        CURLMsg *msg;
        do {
            int msgq = 0;
            msg = curl_multi_info_read(multi_handle, &msgq);
            if (msg && (msg->msg == CURLMSG_DONE)) {
                if (!msg->easy_handle) {
                    m_logger->Warning(kLogXrdClPelican, "Logic error: got a callback for a null handle");
                    mres = CURLM_BAD_EASY_HANDLE;
                    break;
                }
                auto iter = m_op_map.find(msg->easy_handle);
                if (iter == m_op_map.end()) {
                    m_logger->Error(kLogXrdClPelican, "Logic error: got a callback for an entry that doesn't exist");
                    mres = CURLM_BAD_EASY_HANDLE;
                    break;
                }
                auto &op = iter->second;
                auto res = msg->data.result;
                bool keep_handle = false;
                bool waiting_on_broker = false;
                if (res == CURLE_OK) {
                    if (HTTPStatusIsError(op->GetStatusCode())) {
                        auto httpErr = HTTPStatusConvert(op->GetStatusCode());
                        m_logger->Debug(kLogXrdClPelican, "Operation failed with status code %d", op->GetStatusCode());
                        op->Fail(httpErr.first, httpErr.second, op->GetStatusMessage());
                        op->ReleaseHandle();
                        // The curl operation was successful, it's just the HTTP request failed; recycle the handle.
                        queue.RecycleHandle(iter->first);
                    } else {
                        if (op->IsRedirect()) {
                            keep_handle = op->Redirect();
                            int broker_socket = op->WaitSocket();
                            if ((waiting_on_broker = broker_socket >= 0)) {
                                auto expiry = time(nullptr) + 20;
                                m_logger->Debug(kLogXrdClPelican, "Creating a broker wait request on socket %d", broker_socket);
                                broker_reqs[broker_socket] = {iter->first, expiry};
                            }
                        }
                        if (keep_handle) {
                            curl_multi_remove_handle(multi_handle, iter->first);
                            if (!waiting_on_broker) curl_multi_add_handle(multi_handle, iter->first);
                        } else {
                            op->Success();
                            op->ReleaseHandle();
                            // If the handle was successful, then we can recycle it.
                            queue.RecycleHandle(iter->first);
                        }
                    }
                } else if (res == CURLE_COULDNT_CONNECT && !op->GetBrokerUrl().empty() && !op->GetTriedBoker()) {
                    // In this case, we need to use the broker and the curl handle couldn't reuse
                    // an existing socket.
                    keep_handle = true;
                    op->SetTriedBoker(); // Flag to ensure we try a connection only once per operation.
                    std::string err;
                    int wait_socket = -1;
                    if (!op->StartBroker(err) || (wait_socket=op->WaitSocket()) == -1) {
                        m_logger->Error(kLogXrdClPelican, "Failed to start broker-based connection: %s", err.c_str());
                        op->ReleaseHandle();
                        keep_handle = false;
                    } else {
                        curl_multi_remove_handle(multi_handle, iter->first);
                        auto expiry = time(nullptr) + 20;
                        m_logger->Debug(kLogXrdClPelican, "Curl operation requires a new TCP socket; waiting on broker on socket %d", wait_socket);
                        broker_reqs[wait_socket] = {iter->first, expiry};
                    }
                } else {
                    if (res == CURLE_ABORTED_BY_CALLBACK && op->GetError() == CurlOperation::OpError::ErrHeaderTimeout) {
#ifdef HAVE_XPROTOCOL_TIMEREXPIRED
                        op->Fail(XrdCl::errOperationExpired, XErrorCode::kXR_TimerExpired, "Origin did not respond within timeout");
#else
                        op->Fail(XrdCl::errOperationExpired, 0, "Origin did not respond within timeout");
#endif
                    } else {
                        auto xrdCode = CurlCodeConvert(res);
                        m_logger->Debug(kLogXrdClPelican, "Curl generated an error: %s (%d)", curl_easy_strerror(res), res);
                        op->Fail(xrdCode.first, xrdCode.second, curl_easy_strerror(res));
                    }
                    op->ReleaseHandle();
                }
                if (!keep_handle) {
                    curl_multi_remove_handle(multi_handle, iter->first);
                    if (res != CURLE_OK) {
                        curl_easy_cleanup(iter->first);
                    }
                    for (auto &req : broker_reqs) {
                        if (req.second.curl == iter->first) {
                            m_logger->Warning(kLogXrdClPelican, "Curl handle finished while a broker operation was outstanding");
                        }
                    }
                    m_op_map.erase(iter);
                    running_handles -= 1;
                }
            }
        } while (msg);
    }

    for (auto &map_entry : m_op_map) {
        map_entry.second->Fail(XrdCl::errInternal, mres, curl_multi_strerror(mres));
    }
    m_op_map.clear();
}

bool
CurlWorker::RefreshCacheToken() {
    auto [success, contents] = RefreshCacheTokenStatic(m_token_file, m_logger);
    if (success && !contents.empty()) {
        m_cache_token = contents;
    }
    return success;
}

std::pair<bool, std::string>
CurlWorker::RefreshCacheTokenStatic(const std::string &token_location, XrdCl::Log *log) {
    if (token_location.empty()) {
        return {true, ""};
    }

    std::string line;
    std::ifstream fhandle;
    fhandle.open(token_location);
    if (!fhandle) {
        log->Error(kLogXrdClPelican, "Cache token location is set (%s) but failed to open (worker PID %d): %s", token_location.c_str(), getthreadid(), strerror(errno));
        return {false, ""};
    }

    std::string result;
    while (std::getline(fhandle, line)) {
        rtrim(line);
        ltrim(line);
        if (line.empty() || line[0] == '#') {continue;}

        result = line;
    }
    if (!fhandle.eof() && fhandle.fail()) {
        log->Error(kLogXrdClPelican, "Reading of token file (%s) failed: %s", token_location.c_str(), strerror(errno));
        return {false, ""};
    }
    return {true, result};
}

bool
CurlWorker::SetupCacheToken(CURL *curl) {
    return SetupCacheTokenStatic(m_cache_token, curl, m_logger);
}

bool
CurlWorker::SetupCacheTokenStatic(const std::string &token, CURL *curl, XrdCl::Log *log) {
    if (!curl) {return false;}
    if (token.empty()) {return true;}

    char *url_char = nullptr;
    CURLcode errnum;
    if ((errnum = curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &url_char)) != CURLE_OK) {
        log->Error(kLogXrdClPelican, "Failed to get the CURL handle's current URL: %s", curl_easy_strerror(errnum));
        return false;
    }
    if ((url_char == nullptr) || !url_char[0]) {
        log->Error(kLogXrdClPelican, "Curl handle returned an empty URL");
        return false;
    }

    std::string_view url{url_char};
    auto has_query_string = url.find('?') != std::string::npos;
    std::string final_url{url};
    final_url += has_query_string ? "&" : "?";
    final_url += "access_token=";
    final_url += token;

    if ((errnum = curl_easy_setopt(curl, CURLOPT_URL, final_url.c_str())) != CURLE_OK) {
        log->Error(kLogXrdClPelican, "Failed to set updated curl URL: %s", curl_easy_strerror(errnum));
        return false;
    }

    return true;
}


bool
CurlWorker::RefreshX509Prefixes(XrdCl::Env *env) {
    std::string location;
    // If no file is configured, we consider the refresh a success
    if (!env->GetString("PelicanX509AuthPrefixesFile", location) || location.empty()) {
        return true;
    }

    std::string line;
    std::ifstream fhandle;
    fhandle.open(location);
    if (!fhandle) {
        m_logger->Error(kLogXrdClPelican, "Opening of prefixes X.509 authentication file (%s) failed (worker PID %d): %s", location.c_str(), getthreadid(), strerror(errno));
        return false;
    }
    m_x509_prefixes.clear();
    m_x509_all = false;

    auto now = std::chrono::steady_clock::now();
    if (now - m_last_prefix_log > std::chrono::minutes(5)) {
        m_logger->Info(kLogXrdClPelican, "Loading X.509-authenticated prefixes from file (worker PID %d): %s", getthreadid(), location.c_str());
    }
    while (std::getline(fhandle, line)) {
        rtrim(line);
        ltrim(line);
        if (line.empty() || line[0] == '#') {continue;}
        if (now - m_last_prefix_log > std::chrono::minutes(5)) {
            m_logger->Debug(kLogXrdClPelican, "Prefix requiring X.509 authentication (worker PID %d): %s", getthreadid(), line.c_str());
        }
        if (line == "*") {
            m_x509_all = true;
        }
        // When we parse the URL to compare against the prefix, XrdCl::URL will remove the '/' prefix.
        // Remove it here as well to allow a simple string comparison.
        std::string_view line_view{line};
        while (!line_view.empty() && line_view[0] == '/') {
            line_view = line_view.substr(1);
        }
        m_x509_prefixes.emplace(std::string(line_view));
    }
    m_last_prefix_log = now;
    if (!fhandle.eof() && fhandle.fail()) {
        m_logger->Error(kLogXrdClPelican, "Reading of prefixes X.509 authentication file (%s) failed: %s", location.c_str(), strerror(errno));
        return false;
    }
    return true;
}

BrokerRequest::BrokerRequest(CURL *curl, const std::string &url) {
    auto xrd_url = XrdCl::URL(url);
    auto pmap = xrd_url.GetParams();
    auto iter = pmap.find("origin");
    if (iter == pmap.end()) {
        return;
    }
    m_origin = UrlDecode(curl, iter->second);
    pmap.clear();
    xrd_url.SetParams(pmap);
    m_url = xrd_url.GetURL();
}

BrokerRequest::~BrokerRequest() {
    if (m_req >= 0) {
        close(m_req);
        m_req = -1;
    }
}

int
BrokerRequest::StartRequest(std::string &err)
{
    if (m_url.size() == 0) {
        err = "Invalid URL passed by broker request";
        return -1;
    }
    auto env = XrdCl::DefaultEnv::GetEnv();
    if (!env) {
        err = "Failed to find Xrootd environment object";
        return -1;
    }

    std::string brokersocket;
    if (!env->GetString("PelicanBrokerSocket", brokersocket)) {
        err = "XRD_PELICANBROKERSOCKET environment variable is not set";
        return -1;
    }

    struct sockaddr_un addr_un;
    addr_un.sun_family = AF_UNIX;
    struct sockaddr *addr = reinterpret_cast<struct sockaddr *>(&addr_un);
    if (brokersocket.size() >= sizeof(addr_un.sun_path)) {
        err = "Location of broker socket (" + brokersocket + ") longer than maximum socket path name";
        return -1;
    }

    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock == -1) {
        err = "Failed to create new broker socket: " + std::string(strerror(errno));
        return -1;
    }

    strcpy(addr_un.sun_path, brokersocket.c_str());
    socklen_t len = SUN_LEN(&addr_un);
#ifdef __APPLE__
    addr_un.sun_len = SUN_LEN(&addr_un);
#endif
    if (connect(sock, addr, len) == -1) {
        err = "Failed to connect to broker socket: " + std::string(strerror(errno));
        close(sock);
        return -1;
    }

    nlohmann::json jobj;
    jobj["broker_url"] = m_url;
    jobj["origin"] = m_origin;
    std::string msg_val = jobj.dump() + "\n";
    if (send(sock, msg_val.c_str(), msg_val.size(), 0) == -1) {
        err = "Failed to send request to broker socket: " + std::string(strerror(errno));
        close(sock);
        return -1;
    }

    m_req = sock;
    return sock;
}

int
BrokerRequest::FinishRequest(std::string &err)
{
    struct msghdr msg;
    memset(&msg, '\0', sizeof(msg));
    std::vector<char> response_buffer;
    response_buffer.resize(2048);
    struct iovec iov[1];
    iov[0].iov_base = &response_buffer[0];
    iov[0].iov_len = response_buffer.size();

    struct cmsghdr *cmsghdr;
    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } controlMsg;
    memset(controlMsg.buf, '\0', sizeof(controlMsg.buf));
    cmsghdr = &controlMsg.align;
    cmsghdr->cmsg_len = CMSG_LEN(sizeof(int));
    cmsghdr->cmsg_level = SOL_SOCKET;
    cmsghdr->cmsg_type = SCM_RIGHTS;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsghdr;
    msg.msg_controllen = CMSG_LEN(sizeof(int));
    msg.msg_flags = 0;

    if (recvmsg(m_req, &msg, 0) == -1) {
        err = "Failed to receive broker response: " + std::string(strerror(errno));
        close(m_req);
        m_req = -1;
        return -1;
    }
    close(m_req);
    m_req = -1;

    nlohmann::json jobj;
    try {
        jobj = nlohmann::json::parse(reinterpret_cast<char *>(iov->iov_base), reinterpret_cast<char *>(iov->iov_base) + iov->iov_len);
    } catch (const nlohmann::json::parse_error &exc) {
        err = "Failed to parse response as JSON: " + std::string(exc.what());
        return -1;
    }
    if (!jobj.is_object()) {
        err = "Response not a valid JSON object";
        return -1;
    }
    if (!jobj["status"].is_string()) {
        err = "Returned JSON object does not have a status object";
        return -1;
    }
    auto status = jobj["status"].get<std::string>();
    if (status != "success") {
        err = status;
        return -1;
    }

    int *fd_ptr = reinterpret_cast<int *>(CMSG_DATA(&controlMsg.align));

    return *fd_ptr;
}
