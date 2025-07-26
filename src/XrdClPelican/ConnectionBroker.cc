/***************************************************************
 *
 * Copyright (C) 2025, Morgridge Institute for Research
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

#include "BrokerCache.hh"
#include "ConnectionBroker.hh"
#include "../common/XrdClCurlResponseInfo.hh"

#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <XrdCl/XrdClDefaultEnv.hh>
#include <XrdCl/XrdClURL.hh>

#include <sys/socket.h>
#include <sys/un.h>

using namespace Pelican;

namespace {

std::string UrlDecode(const std::string &src) {
    int decodelen;
    auto curl = curl_easy_init();
    char *decoded = curl_easy_unescape(curl, src.c_str(), src.size(), &decodelen);
    std::string result(decoded, decodelen);
    curl_free(decoded);
    curl_easy_cleanup(curl);
    return result;
}

} // namespace

extern "C" {

XrdClCurl::ConnectionCallout *
ConnectionBroker::CreateCallback(const std::string &url, const XrdClCurl::ResponseInfo &info) {
    auto &bcache = BrokerCache::GetCache();
    auto cache_url = bcache.Get(url);
    if (!cache_url.empty()) {
        return new ConnectionBroker(cache_url);
    }

    auto &responses = info.GetHeaderResponse();
    if (responses.empty()) return nullptr;

    auto &headers = responses[0];
    auto iter = headers.find("X-Pelican-Broker");
    if (iter == headers.end()) return nullptr;

    auto &broker_values = iter->second;
    if (broker_values.empty()) return nullptr;

    return new ConnectionBroker(broker_values[0]);
}

}

ConnectionBroker::ConnectionBroker(const std::string &url)
{
    auto xrd_url = XrdCl::URL(url);
    auto pmap = xrd_url.GetParams();
    auto iter = pmap.find("origin");
    if (iter == pmap.end()) {
        return;
    }
    m_origin = UrlDecode(iter->second);
    pmap.clear();
    xrd_url.SetParams(pmap);
    m_url = xrd_url.GetURL();
}

ConnectionBroker::~ConnectionBroker() {
    if (m_req >= 0) {
        close(m_req);
        m_req = -1;
    }
}

int
ConnectionBroker::BeginCallout(std::string &err,
    std::chrono::steady_clock::time_point & /*expiration*/)
{
    if (m_req != -1) return m_req;

    if (m_url.empty() || m_origin.empty()) {
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
ConnectionBroker::FinishCallout(std::string &err)
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
