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

#include <condition_variable>
#include <deque>
#include <mutex>
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

const uint64_t kLogXrdClPelican = 73172;

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

private:
    static bool validHeaderByte(unsigned char c);

    std::unordered_map<std::string, std::vector<std::string>> m_header_map;
    int64_t m_content_length{-1};
    uint64_t m_response_offset{0};

    bool m_recv_all_headers{false};
    bool m_recv_status_line{false};
    bool m_multipart_byteranges{false};

    int m_status_code{-1};
    std::string m_resp_protocol;
    std::string m_resp_message;
};

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

class CurlStatOp final : public CurlOperation {
public:
    CurlStatOp(XrdCl::ResponseHandler *handler, const std::string &url, uint16_t timeout,
        XrdCl::Log *log) :
    CurlOperation(handler, url, timeout, log)
    {}

    virtual ~CurlStatOp() {}

    void Setup(CURL *curl) override;
    void Success() override;
    void ReleaseHandle() override;
};

class CurlReadOp : public CurlOperation {
public:
    CurlReadOp(XrdCl::ResponseHandler *handler, const std::string &url, uint16_t timeout,
        const std::pair<uint64_t, uint64_t> &op, char *buffer, XrdCl::Log *logger);

    virtual ~CurlReadOp() {}

    void Setup(CURL *curl) override;
    void Success() override;
    void ReleaseHandle() override;

private:
    static size_t WriteCallback(char *buffer, size_t size, size_t nitems, void *this_ptr);
    size_t Write(char *buffer, size_t size);

protected:
    std::pair<uint64_t, uint64_t> m_op;
    uint64_t m_written{0};
    std::unique_ptr<char, void(*)(void*)> m_buffer;
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
    std::condition_variable m_cv;
    std::mutex m_mutex;
    const static unsigned m_max_pending_ops{20};
    int m_read_fd{-1};
    int m_write_fd{-1};
};

class CurlWorker {
public:
    CurlWorker(std::shared_ptr<HandlerQueue> queue, XrdCl::Log* logger) :
        m_queue(queue),
        m_logger(logger)
    {}

    CurlWorker(const CurlWorker &) = delete;

    void Run();
    static void RunStatic(CurlWorker *myself);

private:
    std::shared_ptr<HandlerQueue> m_queue;
    std::unordered_map<CURL*, std::unique_ptr<CurlOperation>> m_op_map;
    XrdCl::Log* m_logger;

    const static unsigned m_max_ops{20};
    const static unsigned m_marker_period{5};
 
};

}
