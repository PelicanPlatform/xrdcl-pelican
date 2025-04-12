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

#include <XrdCl/XrdClBuffer.hh>
#include <XrdCl/XrdClXRootDResponses.hh>

#include "CurlUtil.hh"
#include "DirectorCache.hh"

#include <memory>
#include <string>

#include <curl/curl.h>

namespace XrdCl {

class Log;
class ResponseHandler;
class URL;

}
namespace tinyxml2 {

class XMLElement;

}

namespace Pelican {

class File;
class CurlWorker;

class CurlOperation {
public:
    CurlOperation(XrdCl::ResponseHandler *handler, const std::string &url, struct timespec timeout,
        XrdCl::Log *log);

    virtual ~CurlOperation();

    CurlOperation(const CurlOperation &) = delete;

    virtual void Setup(CURL *curl, CurlWorker &);

    virtual void Fail(uint16_t errCode, uint32_t errNum, const std::string &);

    virtual void ReleaseHandle();

    virtual void Success() = 0;

    // Returns when the curl header timeout expires.
    //
    // The first byte of the header must be received before this time.
    std::chrono::steady_clock::time_point GetHeaderExpiry() const {return m_header_expiry;}

    // Invoked when the worker thread is ready to resume a request after a pause.
    //
    // Pauses occur when a PUT request has started but is waiting on more data
    // from the client; when additional data has arrived, the operation will
    // be continued and this function called by the worker thread.
	virtual bool ContinueHandle() {return true;}

    // Set the continue queue to use for when a paused handle is ready to
    // be re-run.
	virtual void SetContinueQueue(std::shared_ptr<HandlerQueue> queue) {}

    // Handle a redirect to a different URL.
    // Returns true if the curl handle should be invoked again.
    // Implementations must call Fail() if the handler should not re-invoke the curl handle.
    virtual bool Redirect();

    bool IsRedirect() const {return m_headers.GetStatusCode() >= 300 && m_headers.GetStatusCode() < 400;}

    // If returns non-negative, the result is a FD that should be waited on after a broker connection request.
    virtual int WaitSocket() {return m_broker ? m_broker->GetBrokerSock() : -1;}
    // Callback when the `WaitSocket` is active for read.
    virtual int WaitSocketCallback(std::string &err);

    // Connection broker-related functionality.
    // When the broker URL is set, the operation will use the connection broker to get a TCP socket
    // to the remote server.  Note that we will try the operation initially without in case the curl
    // handle has an existing socket it can reuse.  If reuse fails, then the operation is going to fail
    // with CURLE_COULDNT_CONNECT and we will retry (once) to connect via the broker.  This is all
    // done outside curl's open socket callback to ensure the event loop stays non-blocking.

    // Returns the broker URL that will be utilized for connecting the socket for the curl operation.
    const std::string &GetBrokerUrl() const {return m_broker_url;}
    void SetBrokerUrl(const std::string &broker) {m_broker_url = broker;}
    void SetUseX509() {m_x509_auth = true;}
    bool StartBroker(std::string &err); // Start the broker connection process.
    bool GetTriedBoker() const {return m_tried_broker;} // Returns true if the connection broker has been tried.
    void SetTriedBoker() {m_tried_broker = true;} // Note that the connection broker has been attempted.

    const std::string &GetMirrorUrl() const {return m_mirror_url;}
    unsigned GetMirrorDepth() const {return m_mirror_depth;}

    // Returns true if the header timeout has expired.
    //
    // The "header timeout" fires if the remote service has not returned any
    // headers or data within the specified time.
    // If the header timeout has expired - and no error has already been set -
    // the m_error will be set
    bool HeaderTimeoutExpired(const std::chrono::steady_clock::time_point &now);

    // Returns true if the operation timeout has expired.
    //
    // Some operations (HEAD, PROPFIND for open) return nearly no data and thus have
    // no need for adaptive timeouts.  Instead, we use a fixed timeout.
    // If the header timeout has expired - and no error has already been set -
    // the m_error will be set
    bool OperationTimeoutExpired(const std::chrono::steady_clock::time_point &now);

    // Returns true if the body timeout has expired.
    //
    // The "body timeout" fires if the remote service has not returned any
    // data within the specified time.
    // If the body timeout has expired - and no error has already been set -
    // the m_error will be set
    bool TransferStalled(uint64_t xfer_bytes, const std::chrono::steady_clock::time_point &now);

    enum OpError {
        ErrNone,             // No error
        ErrHeaderTimeout,    // Header was not sent back in time
        ErrCallback,         // Error in the read/write callback (e.g., response too large for propfind)
        ErrOperationTimeout, // Entire curl request operation has timed out
        ErrTransferStall,    // Transfer has stalled, not receiving any data within 60 seconds
        ErrTransferSlow,     // Average transfer rate is below the minimum
    };

    // Return the error generated by the operation itself (separate from a curl error)
    OpError GetError() const {return m_error;}

    // Return the error generated by the callback (e.g., server has incorrect multipart framing)
    std::pair<XErrorCode, const std::string &> GetCallbackError() const {return std::make_pair(m_callback_error_code, m_callback_error_str);}

    // Returns the HTTP status code (-1 if the response has not been parsed)
    int GetStatusCode() const {return m_headers.GetStatusCode();}

    // Returns the HTTP status message (empty if the response has not been parsed)
    std::string GetStatusMessage() const {return m_headers.GetStatusMessage();}

    // Return true if the transfer is done
    bool IsDone() const {return m_done;}

    // Returns true if the operation has been marked as failed.
    bool HasFailed() const {return m_has_failed;}

    // Client X509 status; returns true if the director requested X509 client auth be used.
    bool UseX509Auth() const {return m_x509_auth;}

    // Sets the stall timeout for the operation.
    static void SetStallTimeout(int stall_interval)
    {
        std::chrono::seconds seconds{stall_interval};
        m_stall_interval = std::chrono::duration_cast<std::chrono::steady_clock::duration>(seconds);
    }

    // Gets the code's default stall timeout
    static int GetDefaultStallTimeout()
    {
        return std::chrono::duration_cast<std::chrono::seconds>(m_default_stall_interval).count();
    }

    // Gets the code's default slow transfer rate
    static int GetDefaultSlowRateBytesSec()
    {
        return m_default_minimum_rate;
    }

    // Sets the slow transfer rate for transfer operations.
    static void SetSlowRateBytesSec(int rate)
    {
        m_minimum_transfer_rate = rate;
    }

protected:

    // Set failure from a callback function.
    // The Fail() function may invoke libcurl functions and hence cannot be invoked from a
    // libcurl callback.  This stores the failure in the object itself and the worker
    // thread will invoke the `Fail()` after libcurl fails the handle.
    int FailCallback(XErrorCode ecode, const std::string &emsg);

    // The default minimum transfer rate for the operation, in bytes / sec
    static constexpr int m_default_minimum_rate{1024 * 1024 * 256}; // 256 KB/sec

    // The current global instance's minimum transfer rate for "transfer type"
    // operations (GET, PUT).  Defaults to the m_default_minimum_rate but can be
    // overridden by configuration.
    static int m_minimum_transfer_rate;

    // The minimum transfer rate for this operation, in bytes / sec
    int m_minimum_rate{m_minimum_transfer_rate};

    // The expiration of the entire operation.
    std::chrono::steady_clock::time_point m_operation_expiry;

    // The expiration time for receiving the first header.
    std::chrono::steady_clock::time_point m_header_expiry;

private:
    bool Header(const std::string &header);
    static size_t HeaderCallback(char *buffer, size_t size, size_t nitems, void *data);

    // The "stall time" for the body transfer.
    // If the body transfer has not been updated in this time, the operation
    // will be marked as expired.
    //
    // This is also used for the calculation of the interval of the EMA rate
    static constexpr std::chrono::steady_clock::duration m_default_stall_interval{std::chrono::seconds(60)};
    static std::chrono::steady_clock::duration m_stall_interval;

    OpError m_error{ErrNone};
    XErrorCode m_callback_error_code{kXR_noErrorYet}; // Stored error that occurred in a callback.
    std::string m_callback_error_str; // Stored error message that occurred in a callback.
    bool m_tried_broker{false};
    bool m_received_header{false};
    bool m_done{false};
    bool m_has_failed{false};
    bool m_x509_auth{false};
    int m_broker_reverse_socket{-1};
 
    unsigned m_mirror_depth{0};
    std::string m_mirror_url;

    // The last time header data was received.
    std::chrono::steady_clock::time_point m_header_lastop;

    // The last time data was transferred.
    std::chrono::steady_clock::time_point m_last_xfer;

    // The last recorded number of bytes that had been transferred.
    uint64_t m_last_xfer_count{0};

    // The exponential moving average of the transfer rate
    double m_ema_rate{-1.0};

    std::unique_ptr<BrokerRequest> m_broker;
    std::string m_broker_url;
    std::unique_ptr<XrdCl::URL> m_parsed_url{nullptr};

    static curl_socket_t OpenSocketCallback(void *clientp, curlsocktype purpose, struct curl_sockaddr *address);
    static int SockOptCallback(void *clientp, curl_socket_t curlfd, curlsocktype purpose);

    // Periodic transfer info callback function invoked by curl; used for more fine-grained timeouts.
    static int XferInfoCallback(void *clientp, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow);

protected:
    void SetDone(bool has_failed) {m_done = true; m_has_failed = has_failed;}
    const std::string m_url;
    XrdCl::ResponseHandler *m_handler{nullptr};
    std::unique_ptr<CURL, void(*)(CURL *)> m_curl;
    HeaderParser m_headers;
    XrdCl::Log *m_logger;
};

class CurlStatOp : public CurlOperation {
public:
    CurlStatOp(XrdCl::ResponseHandler *handler, const std::string &url, struct timespec timeout,
        XrdCl::Log *log, bool is_pelican, bool is_origin, const DirectorCache *dcache) :
    CurlOperation(handler, url, timeout, log),
    m_is_pelican(is_pelican),
    m_is_origin(is_origin),
    m_dcache(dcache)
    {
        m_operation_expiry = m_header_expiry;
    }

    virtual ~CurlStatOp() {}

    void Setup(CURL *curl, CurlWorker &) override;
    void Success() override;
    bool Redirect() override;
    void ReleaseHandle() override;
    std::pair<int64_t, bool> GetStatInfo();

protected:
    // Mark the operation as a success and, as requested, return the stat info back
    // to the object handler.
    //
    // Returning the info is optional as the CurlOpenOp derives from this clasa and
    // if stat info is returned from an open without being requested then the
    // object is leaked
    void SuccessImpl(bool returnObj);

    // Returns whether the URL for the stat operation was originally for a pelican director
    bool IsPelican() const {return m_is_pelican;}

    // Returns whether the URL was from the DirectorCache (and hence an origin)
    bool IsOrigin() const {return m_is_origin;}

private:
    // Parse the properties element of a PROPFIND response.
    std::pair<int64_t, bool> ParseProp(tinyxml2::XMLElement *prop);
    // Callback for writing the response body to the internal buffer.
    static size_t WriteCallback(char *buffer, size_t size, size_t nitems, void *this_ptr);

    // Whether the provided URL is a Pelican URL.
    const bool m_is_pelican{false};
    // Whether the provided URL is an origin URL.
    // If so, we'll use PROPFIND instead of HEAD.  PROPFIND can't
    // be used against the director as the director will interpret the
    // request as a directory listing.
    const bool m_is_origin{false};
    // Whether the stat request is made using the PROPFIND verb.
    bool m_is_propfind{false};
    // Whether the stat response indicated that the object is a directory.
    bool m_is_dir{false};
    const DirectorCache *m_dcache{nullptr};
    std::string m_response; // Body of the response (if using PROPFIND)
    int64_t m_length{-1}; // Length of the object from the response
};

class CurlOpenOp final : public CurlStatOp {
public:
    CurlOpenOp(XrdCl::ResponseHandler *handler, const std::string &url, struct timespec timeout,
        XrdCl::Log *logger, File *file, const DirectorCache *dcache);

    virtual ~CurlOpenOp() {}

    void ReleaseHandle() override;
    void Success() override;

private:
    File *m_file{nullptr};
};

// Query the origin for a checksum via a HEAD request.
//
// Since the open op is a PROPFIND, we need a second operation for checksums.
// We expect the checksum only is done after a successful transfer.
class CurlChecksumOp final : public CurlStatOp {
    public:
        CurlChecksumOp(XrdCl::ResponseHandler *handler, const std::string &url, ChecksumCache::ChecksumType preferred,
            bool is_pelican, bool is_origin, struct timespec timeout, XrdCl::Log *logger, const DirectorCache *dcache);

        virtual ~CurlChecksumOp() {}

        void Setup(CURL *curl, CurlWorker &) override;
        bool Redirect() override;
        void ReleaseHandle() override;
        void Success() override;

    private:
        ChecksumCache::ChecksumType m_preferred_cksum{ChecksumCache::ChecksumType::kCRC32C};
        File *m_file{nullptr};
        std::unique_ptr<struct curl_slist, void(*)(struct curl_slist *)> m_header_list;
    };

class CurlReadOp : public CurlOperation {
public:
    CurlReadOp(XrdCl::ResponseHandler *handler, const std::string &url, struct timespec timeout,
        const std::pair<uint64_t, uint64_t> &op, char *buffer, XrdCl::Log *logger);

    virtual ~CurlReadOp() {}

    void Setup(CURL *curl, CurlWorker &) override;
    void Fail(uint16_t errCode, uint32_t errNum, const std::string &msg) override;
    void Success() override;
    void ReleaseHandle() override;

private:
    static size_t WriteCallback(char *buffer, size_t size, size_t nitems, void *this_ptr);
    size_t Write(char *buffer, size_t size);

protected:
    std::pair<uint64_t, uint64_t> m_op;
    uint64_t m_written{0};
    char* m_buffer{nullptr}; // Buffer passed by XrdCl; we do not own it.
    std::unique_ptr<struct curl_slist, void(*)(struct curl_slist *)> m_header_list;
};

class CurlVectorReadOp : public CurlOperation {
    public:

        CurlVectorReadOp(XrdCl::ResponseHandler *handler, const std::string &url, struct timespec timeout,
            const XrdCl::ChunkList &op_list, XrdCl::Log *logger);

        virtual ~CurlVectorReadOp() {}

        void Setup(CURL *curl, CurlWorker &) override;
        void Fail(uint16_t errCode, uint32_t errNum, const std::string &msg) override;
        void Success() override;
        void ReleaseHandle() override;

        // Set the expected separator between parts of a response;
        // not expected to be used externally except by unit tests.
        void SetSeparator(const std::string &sep) {
            m_headers.SetMultipartSeparator(sep);
        }

        // Set the status code for the operation
        void SetStatusCode(int sc) {m_headers.SetStatusCode(sc);}

        // Invoke the write callback for the vector read.
        //
        // Note: made public to help unit testing of the class; not intended for direct invocation.
        size_t Write(char *buffer, size_t size);

    private:
        static size_t WriteCallback(char *buffer, size_t size, size_t nitems, void *this_ptr);

        // Calculate the next request buffer the current response buffer will service.
        // Sets the m_response_idx and m_skip_bytes
        void CalculateNextBuffer();

    protected:
        size_t m_response_idx{0}; // The offset in the m_chunk_list which the current response chunk will write into.
        off_t m_chunk_buffer_idx{0}; // Current offset in requested chunk where we are writing bytes.
        off_t m_bytes_consumed{0}; // Total number of bytes used for results serving the request.
        uint64_t m_skip_bytes{0}; // Count of bytes to skip in the next response (if response chunk contains unneeded bytes).
        std::string m_response_headers; // Buffer of an incomplete response line from a prior curl write operation.
        std::pair<off_t, off_t> m_current_op{-1, -1}; // The (offset, length) of the current response chunk.
        std::unique_ptr<XrdCl::VectorReadInfo> m_vr; // The response buffers for the client.
        XrdCl::ChunkList m_chunk_list; // The requested chunks from the client.

        std::unique_ptr<struct curl_slist, void(*)(struct curl_slist *)> m_header_list;
};

class CurlPgReadOp final : public CurlReadOp {
public:
    CurlPgReadOp(XrdCl::ResponseHandler *handler, const std::string &url, struct timespec timeout,
        const std::pair<uint64_t, uint64_t> &op, char *buffer, XrdCl::Log *logger)
    :
        CurlReadOp(handler, url, timeout, op, buffer, logger)
    {}

    virtual ~CurlPgReadOp() {}

    void Success() override;
};

class CurlListdirOp final : public CurlOperation {
public:
    CurlListdirOp(XrdCl::ResponseHandler *handler, const std::string &url, const std::string &host_addr, bool is_origin, struct timespec timeout,
        XrdCl::Log *logger);

    virtual ~CurlListdirOp() {}

    void Setup(CURL *curl, CurlWorker &) override;
    void Success() override;
    void ReleaseHandle() override;

private:
    struct DavEntry {
        std::string m_name;
        bool m_isdir{false};
        bool m_isexec{false};
        int64_t m_size{-1};
        time_t m_lastmodified{-1};
    };
    // Parses the properties element of a PROPFIND response into a DavEntry object
    //
    // - prop: The properties element to parse
    // - Returns: A pair containing the DavEntry object and a boolean indicating success or not
    bool ParseProp(DavEntry &entry, tinyxml2::XMLElement *prop);

    // Parses the response element of a PROPFIND
    std::pair<DavEntry, bool> ParseResponse(tinyxml2::XMLElement *response);

    // Callback for writing the response body to the internal buffer.
    static size_t WriteCallback(char *buffer, size_t size, size_t nitems, void *this_ptr);

    // Whether the provided URL is an origin URL (and hence PROPFIND can be done directly).
    bool m_is_origin{false};

    // Response body from the PROPFIND request.
    std::string m_response;

    // Host address (hostname:port) of the data federation
    std::string m_host_addr;

    // Headers to be sent with the request
    std::unique_ptr<struct curl_slist, void(*)(struct curl_slist *)> m_header_list;
};

// A third-party-copy operation
//
// Invoke the COPY verb to move a file between two HTTP endpoints.
class CurlCopyOp final : public CurlOperation {
public:
    using Headers = std::vector<std::pair<std::string, std::string>>;

    CurlCopyOp(XrdCl::ResponseHandler *handler, const std::string &source_url, const Headers &source_hdrs, const std::string &dest_url, const Headers &dest_hdrs, struct timespec timeout,
        XrdCl::Log *logger);

    virtual ~CurlCopyOp() {}

    void Setup(CURL *curl, CurlWorker &) override;
    void Success() override;
    void ReleaseHandle() override;

    class CurlProgressCallback {
    public:
        virtual ~CurlProgressCallback() {}
        virtual void Progress(off_t bytemark) = 0;
    };

    void SetCallback(std::unique_ptr<CurlProgressCallback> callback);

private:
    // Callback for writing the response body to the internal buffer.
    static size_t WriteCallback(char *buffer, size_t size, size_t nitems, void *this_ptr);

    // Handle a line of information in the control channel.
    void HandleLine(std::string_view line);

    // Returns true if the control channel has not gotten data recently enough.
    bool ControlChannelTimeoutExpired() const;

    // Source of the TPC transfer
    std::string m_source_url;

    // Buffer of current response line
    std::string m_line_buffer;

    // Headers to be sent with the request
    std::unique_ptr<struct curl_slist, void(*)(struct curl_slist *)> m_header_list;

    // A callback object for when a performance marker is received
    std::unique_ptr<CurlProgressCallback> m_callback;

    // The performance marker indication of bytes processed.
    off_t m_bytemark{-1};

    // Whether the COPY operation indicated a success status in the control channel:
    bool m_sent_success{false};

    // Failure string sent back in the control channel:
    std::string m_failure;
};

// An upload operation
//
// Invoke a PUT on the remote HTTP server; assumes that Writes are done
// in a single-stream
class CurlPutOp final : public CurlOperation {
public:
    CurlPutOp(XrdCl::ResponseHandler *handler, const std::string &url, const char *buffer, size_t buffer_size, struct timespec timeout, XrdCl::Log *logger);
    CurlPutOp(XrdCl::ResponseHandler *handler, const std::string &url, XrdCl::Buffer &&buffer, struct timespec timeout, XrdCl::Log *logger);

    virtual ~CurlPutOp() {}

    void Setup(CURL *curl, CurlWorker &) override;
    void Success() override;
    void ReleaseHandle() override;
    bool ContinueHandle() override;

	virtual void SetContinueQueue(std::shared_ptr<HandlerQueue> queue) override {
		m_continue_queue = queue;
	}

    // Start continuation of a previously-started operation with additional data.
    //
    // Since the CurlPutOp itself is kept as a reference-counted pointer by the
    // Pelican::File handle, we need to pass a shared pointer to the continue queue.
    // Hence the awkward interface of needing to be provided a shared pointer to oneself.
    bool Continue(std::shared_ptr<CurlOperation> op, XrdCl::ResponseHandler *handler, const char *buffer, size_t buffer_size);
    bool Continue(std::shared_ptr<CurlOperation> op, XrdCl::ResponseHandler *handler, XrdCl::Buffer &&buffer);

    // Pause the put operation; indicates the current buffer was sent successfully
    // but the operation is not yet complete.
    void Pause();

private:

    // Callback function for libcurl when it would like to read data from m_data
    // (and write it to the remote socket).
    static size_t ReadCallback(char *buffer, size_t size, size_t n, void *v);

    // Handle that represents the current operation to libcurl
    CURL *m_curl_handle{nullptr};

    // Reference to the continue queue to use when the operation should be resumed.
    std::shared_ptr<HandlerQueue> m_continue_queue;

    // The buffer of data to upload (if the CurlPutOp owns the buffer).
    XrdCl::Buffer m_owned_buffer;

    // The non-owned view of the data to upload.
    // This may reference m_owned_buffer or an externally-owned `const char *`.
    std::string_view m_data;

    // File pointer offset
    off_t m_offset{0};

    // The final size of the object to be uploaded; -1 if not known
    off_t m_object_size{-1};

    bool m_final{false};
};

} // namespace Pelican
