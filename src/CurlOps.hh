/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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

#include "CurlUtil.hh"

#include <memory>
#include <string>

#include <curl/curl.h>

namespace XrdCl {

class ResponseHandler;
class Log;

}

namespace Pelican {

class File;

class CurlOperation {
public:
    CurlOperation(XrdCl::ResponseHandler *handler, const std::string &url, uint16_t timeout,
        XrdCl::Log *log);

    virtual ~CurlOperation() {}

    CurlOperation(const CurlOperation &) = delete;

    virtual void Setup(CURL *curl);

    void Fail(uint16_t errCode, uint32_t errNum, const std::string &);

    virtual void ReleaseHandle();

    virtual void Success() = 0;

    // Handle a redirect to a different URL.
    // Returns true if the curl handle should be invoked again.
    // Implementations must call Fail() if the handler should not re-invoke the curl handle.
    virtual bool Redirect();

    bool IsRedirect() const {return m_headers.GetStatusCode() >= 300 && m_headers.GetStatusCode() < 400;}

    // If returns non-negative, the result is a FD that should be waited on after a failure.
    virtual int WaitSocket() {return -1;}
    // Callback when the `WaitSocket` is active for read.
    virtual int WaitSocketCallback(std::string &err) {return -1;}

private:
    bool Header(const std::string &header);
    static size_t HeaderCallback(char *buffer, size_t size, size_t nitems, void *data);

    uint16_t m_timeout{0};

protected:
    const std::string m_url;
    XrdCl::ResponseHandler *m_handler{nullptr};
    std::unique_ptr<CURL, void(*)(CURL *)> m_curl;
    HeaderParser m_headers;
    XrdCl::Log *m_logger;
};

class CurlStatOp : public CurlOperation {
public:
    CurlStatOp(XrdCl::ResponseHandler *handler, const std::string &url, uint16_t timeout,
        XrdCl::Log *log, bool is_pelican) :
    CurlOperation(handler, url, timeout, log),
    m_is_pelican(is_pelican)
    {}

    virtual ~CurlStatOp() {}

    void Setup(CURL *curl) override;
    void Success() override;
    bool Redirect() override;
    void ReleaseHandle() override;

private:
    bool m_is_pelican{false};
};

class CurlOpenOp final : public CurlStatOp {
public:
    CurlOpenOp(XrdCl::ResponseHandler *handler, const std::string &url, uint16_t timeout,
        XrdCl::Log *logger, File *file);

    virtual ~CurlOpenOp() {}

    bool Redirect() override;
    void ReleaseHandle() override;
    void Success() override;
    int WaitSocket() override {return m_broker ? m_broker->GetBrokerSock() : -1;}
    int WaitSocketCallback(std::string &err) override;

private:
    static curl_socket_t OpenSocketCallback(void *clientp, curlsocktype purpose, struct curl_sockaddr *address);
    static int SockOptCallback(void *clientp, curl_socket_t curlfd, curlsocktype purpose);

    File *m_file{nullptr};
    std::unique_ptr<BrokerRequest> m_broker;
    int m_broker_reverse_socket{-1};

};

class CurlReadOp : public CurlOperation {
public:
    CurlReadOp(XrdCl::ResponseHandler *handler, const std::string &url, uint16_t timeout,
        const std::pair<uint64_t, uint64_t> &op, char *buffer, XrdCl::Log *logger);

    virtual ~CurlReadOp() {}

    void Setup(CURL *curl) override;
    void Success() override;
    void ReleaseHandle() override;
    int WaitSocket() override {return m_broker ? m_broker->GetBrokerSock() : -1;}
    int WaitSocketCallback(std::string &err) override;
    bool Redirect() override;


private:
    static size_t WriteCallback(char *buffer, size_t size, size_t nitems, void *this_ptr);
    size_t Write(char *buffer, size_t size);

    static curl_socket_t OpenSocketCallback(void *clientp, curlsocktype purpose, struct curl_sockaddr *address);
    static int SockOptCallback(void *clientp, curl_socket_t curlfd, curlsocktype purpose);

    std::unique_ptr<BrokerRequest> m_broker;
    int m_broker_reverse_socket{-1};

protected:
    std::pair<uint64_t, uint64_t> m_op;
    uint64_t m_written{0};
    char* m_buffer{nullptr}; // Buffer passed by XrdCl; we do not own it.
    std::unique_ptr<struct curl_slist, void(*)(struct curl_slist *)> m_header_list;
};

class CurlPgReadOp final : public CurlReadOp {
public:
    CurlPgReadOp(XrdCl::ResponseHandler *handler, const std::string &url, uint16_t timeout,
        const std::pair<uint64_t, uint64_t> &op, char *buffer, XrdCl::Log *logger)
    :
        CurlReadOp(handler, url, timeout, op, buffer, logger)
    {}

    virtual ~CurlPgReadOp() {}

    void Success() override;
};

}
