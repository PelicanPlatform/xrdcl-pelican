/****************************************************************
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

// This file contains a mockup of the connection callout.  The gtest
// fixture will launch a server thread that will take connection requests
// over a unix socket, create the desired connection, and then write the
// response using Unix file descriptor passing back to the curl worker thread.
// This mimics what an external connection helper process might do.

#include "XrdClCurl/XrdClCurlConnectionCallout.hh"
#include "XrdClCurl/XrdClCurlResponses.hh"
#include "XrdClCurl/XrdClCurlFile.hh"
#include "../XrdClCurlCommon/TransferTest.hh"

#include <atomic>
#include <charconv>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <XrdCl/XrdClFile.hh>

#include <fcntl.h>
#include <memory>
#include <mutex>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <thread>

class SyncResponseHandler: public XrdCl::ResponseHandler {
public:
    SyncResponseHandler() {}

    virtual ~SyncResponseHandler() {}

    virtual void HandleResponse( XrdCl::XRootDStatus *status, XrdCl::AnyObject *response );

    void Wait();

    std::tuple<std::unique_ptr<XrdCl::XRootDStatus>, std::unique_ptr<XrdCl::AnyObject>> Status();

private:
    std::mutex m_mutex;
    std::condition_variable m_cv;

    std::unique_ptr<XrdCl::XRootDStatus> m_status;
    std::unique_ptr<XrdCl::AnyObject> m_obj;
};

void
SyncResponseHandler::HandleResponse( XrdCl::XRootDStatus *status, XrdCl::AnyObject *response ) {
    std::unique_lock lock(m_mutex);
    m_status.reset(status);
    m_obj.reset(response);
    m_cv.notify_one();
}

void
SyncResponseHandler::Wait() {
    std::unique_lock lock(m_mutex);
    m_cv.wait(lock, [&]{return m_status.get() != nullptr;});
}

std::tuple<std::unique_ptr<XrdCl::XRootDStatus>, std::unique_ptr<XrdCl::AnyObject>>
SyncResponseHandler::Status() {
    return std::make_tuple(std::move(m_status), std::move(m_obj));
}


// A class implementing the connection callout protocol.
//
// This will launch a server thread that will receive the connection
// request, sleep for 10ms, connect to the desired endpoint, and send
// the response back to the main thread.
class ConnectionBroker final : public XrdClCurl::ConnectionCallout {
public:

    virtual ~ConnectionBroker();
    ConnectionBroker(const ConnectionBroker&) = delete;

    static XrdClCurl::ConnectionCallout *CreateCallback(const std::string &url,
        const XrdClCurl::ResponseInfo & /*info*/);

    // Start a request to get a URL connection from the broker.
    virtual int BeginCallout(std::string &err,
        std::chrono::steady_clock::time_point &expiration) override;
    
    // Finish the socket connection callout.
    virtual int FinishCallout(std::string &err) override;

private:
    ConnectionBroker(const std::string &hostname, int port, const std::string &commsock);

    int m_port; // port for the connection.
    int m_sock{-1}; // Socket connected to the server thread; response is read from here
    std::string m_commsock; // Unix socket name for the connection.
    std::string m_hostname; // hostname for the connection.
};

// Test fixture for the class.  Launches the server thread needed for testing
// out the connection callout functionality.
class CurlCalloutFixture : public TransferFixture {
public:

    // Actual invocation of the callout setup is done in the subprocess to avoid multiple threads
    // prior to forking.
    void SubprocessSetUp(std::tuple<int, int, int, int> comm);

    // Returns the Unix socket filename used for callouts
    static std::string GetCommFilename() {return m_comm_filename;}

    // Returns the count of successful callouts
    size_t SuccessfulCalloutResponses() {return m_successful_callouts.load(std::memory_order_acquire);}

    void SubprocessTearDown();

    // Getter for the communication pipes from the parent to the child.
    // The returned values are, in order,
    // - stdout write side to parent
    // - stderr write side to parent
    // - stdout read side from parent
    // - stderr read side from parent
    std::tuple<int, int, int, int> GetCommPipes() const {
        return {m_stdout_from_child[1], m_stderr_from_child[1], m_stdout_to_child[0], m_stderr_to_child[0]};
    }

protected:
    void SetUp() override;

    void TearDown() override;

    // Teardown the "tee" thread in the child
    void SubprocessTearDownTee();

    // The actual callout test itself.  We use EXPECT_DEATH to force gtest to fork off a
    // separate process for this invocation.  This allows process-wide event processing to avoid
    // prior test runs from leaking state across.
    void RunTest(bool doExit, std::tuple<int, int, int, int> alt_stderr);

private:
    static void ConnectionThread(CurlCalloutFixture *, int server_sock);

    // Thread run by the parent that reads from the alternate stderr/out pipes,
    // captures their output, and writes the results back to the child
    std::unique_ptr<std::thread> m_parent_reader;
    // Pipe pair for reading stderr from the child.
    int m_stderr_from_child[2] {-1, -1};
    // Pipe pair for writing stderr back to the child.
    int m_stderr_to_child[2] {-1, -1};
    // Pipe pair for reading stdout from the child.
    int m_stdout_from_child[2] {-1, -1};
    // Pipe pair for writing stdout back to the child.
    int m_stdout_to_child[2] {-1, -1};
    // Pipe pair for the child to indicate a clean shutdown is desired
    int m_child_teardown[2] {-1, -1};
    // Buffer for capturing child stderr output in the parent
    std::string m_child_stderr;

    std::atomic<bool> m_shutdown{false};
    std::atomic<size_t> m_successful_callouts{0};
    std::once_flag m_thread_launched;
    static std::string m_comm_filename;
    std::unique_ptr<std::thread> m_server_thread;
    std::unique_ptr<std::thread> m_tee_thread;
};

std::string CurlCalloutFixture::m_comm_filename;

XrdClCurl::ConnectionCallout *
ConnectionBroker::CreateCallback(const std::string &url, const XrdClCurl::ResponseInfo &) {
    XrdCl::URL parsed_url(url.c_str());
    auto host = parsed_url.GetHostName();
    auto port = parsed_url.GetPort();
    auto hostname_iter = parsed_url.GetParams().find("x-hostname");
    if (hostname_iter != parsed_url.GetParams().end()) {
        host = hostname_iter->second;
    }
    // For the OPTIONS verb, the query string is stripped off - hardcode
    // the hostname to localhost for testing.
    if (host == "blah.example.com" || host == "blah-cache.example.com") {
        host = "localhost";
    }
    auto comm = CurlCalloutFixture::GetCommFilename();
    std::cout << "CreateCallback in unit test for URL: " << url << std::endl;

    return new ConnectionBroker(host, port, comm);
}

ConnectionBroker::ConnectionBroker(const std::string &hostname, int port, const std::string &commsock)
    : m_port(port),
      m_commsock(commsock),
      m_hostname(hostname)
{}

ConnectionBroker::~ConnectionBroker() {
    if (m_sock >= 0) {
        close(m_sock);
    }
}

// Open a connection to the server thread and send a connection request.
int
ConnectionBroker::BeginCallout(std::string &err,
    std::chrono::steady_clock::time_point & /*expiration*/)
{
    if (m_sock != -1) return m_sock;
    struct sockaddr_un addr_un;
    addr_un.sun_family = AF_UNIX;
    struct sockaddr *addr = reinterpret_cast<struct sockaddr *>(&addr_un);
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    strcpy(addr_un.sun_path, m_commsock.c_str());
    socklen_t len = SUN_LEN(&addr_un);
#ifdef __APPLE__
    addr_un.sun_len = SUN_LEN(&addr_un);
#endif
    auto rv = connect(sock, addr, len);
    if (rv == -1) {
        fprintf(stderr, "Failed to connect to server unix socket: %s\n", strerror(errno));
        close(sock);
        return -1;
    }

    nlohmann::json jobj;
    jobj["host"] = m_hostname;
    jobj["port"] = m_port;
    std::string msg_val = jobj.dump();
    union {
        char length_buff[4];
        uint32_t length;
    } length_obj;
    length_obj.length = htonl(msg_val.size());
    if (send(sock, length_obj.length_buff, 4, 0) == -1) {
        fprintf(stderr, "Failed to send message length to server socket: %s\n", strerror(errno));
        close(sock);
        return -1;
    }
    if (send(sock, msg_val.c_str(), msg_val.size(), 0) == -1) {
        fprintf(stderr, "Failed to send message to server socket: %s\n", strerror(errno));
        close(sock);
        return -1;
    }
    m_sock = sock;
    return sock;
}

int
ConnectionBroker::FinishCallout(std::string &err)
{
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    char iobuf[1];
    struct iovec io = {
        .iov_base = iobuf,
        .iov_len = sizeof(iobuf)
    };
    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } u;

    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = u.buf;
    msg.msg_controllen = sizeof(u.buf);

    auto n = recvmsg(m_sock, &msg, 0);
    if (n == -1) {
        fprintf(stderr, "Failed to receive message from server thread: %s\n", strerror(errno));
        close(m_sock);
        m_sock = -1;
        return -1;
    }
    auto resp = CMSG_FIRSTHDR(&msg);
    if (resp == nullptr || resp->cmsg_len != CMSG_LEN(sizeof(int)) || resp->cmsg_level != SOL_SOCKET || resp->cmsg_type != SCM_RIGHTS) {
        if (resp == nullptr) {
            fprintf(stderr, "Server thread returned no response\n");
        } else {
            fprintf(stderr, "Server thread returned invalid response: len=%lu level=%d type=%d\n",
                static_cast<long unsigned>(resp->cmsg_len), resp->cmsg_level, resp->cmsg_type);
        }
        fprintf(stderr, "Server thread returned unexpected response\n");
        close(m_sock);
        m_sock = -1l;
        return -1;
    }

    int result_fd;
    memcpy(&result_fd, CMSG_DATA(resp), sizeof(int));
    return result_fd;
}

// Set up a pipe for capturing stderr and launch a thread to read from it.
void CurlCalloutFixture::SetUp() {
    int pipefd[2];
    ASSERT_NE(pipe(pipefd), -1) << "Failed to create pipe for stderr from child";
    m_stderr_from_child[0] = pipefd[0];
    m_stderr_from_child[1] = pipefd[1];
    ASSERT_NE(pipe(pipefd), -1) << "Failed to create pipe for stdout from child";
    m_stdout_from_child[0] = pipefd[0];
    m_stdout_from_child[1] = pipefd[1];
    ASSERT_NE(pipe(pipefd), -1) << "Failed to create pipe for stderr to child";
    m_stderr_to_child[0] = pipefd[0];
    m_stderr_to_child[1] = pipefd[1];
    ASSERT_NE(pipe(pipefd), -1) << "Failed to create pipe for stdout to child";
    m_stdout_to_child[0] = pipefd[0];
    m_stdout_to_child[1] = pipefd[1];
    ASSERT_NE(pipe(pipefd), -1) << "Failed to create pipe for child shutdown signal";
    m_child_teardown[0] = pipefd[0];
    m_child_teardown[1] = pipefd[1];

    m_child_stderr.clear();

    m_parent_reader = std::make_unique<std::thread>([this]() {
        // Set the input FDs to non-blocking mode
        int flags;
        flags = fcntl(m_stderr_from_child[0], F_GETFL, 0);
        if (flags != -1) fcntl(m_stderr_from_child[0], F_SETFL, flags | O_NONBLOCK);
        flags = fcntl(m_stdout_from_child[0], F_GETFL, 0);
        if (flags != -1) fcntl(m_stdout_from_child[0], F_SETFL, flags | O_NONBLOCK);

        struct pollfd pfds[3];
        pfds[0].fd = m_stderr_from_child[0];
        pfds[0].events = POLLIN;
        pfds[1].fd = m_stdout_from_child[0];
        pfds[1].events = POLLIN;
        pfds[2].fd = m_child_teardown[0];
        pfds[2].events = POLLIN;

        bool stderr_open = true, stdout_open = true, teardown_open = true;
        while (stderr_open || stdout_open) {
            if (stderr_open) {
                pfds[0].events = POLLIN;
            } else {
                pfds[0].fd = -1;
            }
            if (stdout_open) {
                pfds[1].events = POLLIN;
            } else {
                pfds[1].fd = -1;
            }
            if (teardown_open) {
                pfds[2].events = POLLIN;
            } else {
                pfds[2].fd = -1;
            }

            int ret = poll(pfds, 3, -1);
            if (ret <= 0) break;

            for (int i = 0; i < 2; ++i) {
                if ((pfds[i].revents & POLLIN) != 0) {
                    char buffer[4096];
                    ssize_t n = read(pfds[i].fd, buffer, sizeof(buffer));
                    if (n <= 0) {
                        if (i == 0) stderr_open = false;
                        else stdout_open = false;
                        continue;
                    }
                    m_child_stderr.append(buffer, n);
                    // Write back to the corresponding pipe to the child
                    int out_fd = (i == 0) ? m_stderr_to_child[1] : m_stdout_to_child[1];
                    ssize_t written = 0;
                    while (written < n) {
                        ssize_t w = write(out_fd, buffer + written, n - written);
                        if (w <= 0) break;
                        written += w;
                    }
                } else if ((pfds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                    if (i == 0) stderr_open = false;
                    else stdout_open = false;
                }
            }
            // We have no opportunity to close the parent's copy of the write pipes the
            // child is using; hence, the child has to signal it's done with them and we'll
            // then close them.  That'll trigger a clean shutdown of the other two listeners
            // in this thread and the final thread shutdown.
            if (teardown_open && (pfds[2].revents)) {
                teardown_open = false;
                close(m_child_teardown[1]);
                close(m_stderr_from_child[1]);
                m_stderr_from_child[1] = -1;
                close(m_stdout_from_child[1]);
                m_stdout_from_child[1] = -1;
            }
        }
        close(m_stderr_to_child[1]);
        close(m_stdout_to_child[1]);
    });
}

void CurlCalloutFixture::TearDown() {
    if (m_stderr_from_child[1] != -1) {
        close(m_stderr_from_child[1]);
        m_stderr_from_child[1] = -1;
    }
    if (m_stdout_from_child[1] != -1) {
        close(m_stdout_from_child[1]);
        m_stdout_from_child[1] = -1;
    }
    if (m_parent_reader && m_parent_reader->joinable()) {
        m_parent_reader->join();
        m_parent_reader.reset();
    }
    if (!m_child_stderr.empty()) {
        fprintf(stderr, "Stderr/out contents from child process:\n%s", m_child_stderr.c_str());
    } else {
        fprintf(stderr, "No stderr output from child process\n");
    }
}

void CurlCalloutFixture::ConnectionThread(CurlCalloutFixture *me, int server_sock) {
    while (true) {
        struct sockaddr_un remote_addr;
        socklen_t addr_len = sizeof(remote_addr);

        struct pollfd pfd;
        pfd.fd = server_sock;
        pfd.events = POLLIN;
        bool shutdown = false;
        while (true) {
            int poll_ret = poll(&pfd, 1, 5);
            if (me->m_shutdown.load(std::memory_order_acquire)) {
                shutdown = true;
                break;
            }
            if (poll_ret == 0) {
                continue; // timeout, check shutdown and poll again
            }
            if (poll_ret < 0) {
                fprintf(stderr, "Poll error on server_sock: %s\n", strerror(errno));
                break;
            }
            if (pfd.revents & POLLIN) {
                break; // ready to accept
            }
        }
        if (shutdown) {
            break;
        }

        int conn = accept(server_sock, (struct sockaddr *)&remote_addr, &addr_len);
        if (conn == -1) {
            fprintf(stderr, "Connection thread received error when listening: %s\n", strerror(errno));
            continue;
        }
        union {
            char char_buff[4];
            uint32_t network;
        } length_buff;
        ssize_t n = recv(conn, length_buff.char_buff, 4, 0);
        if (n == -1) {
            close(conn);
            fprintf(stderr, "Connection thread received error when waiting for message size: %s\n", strerror(errno));
            continue;
        }
        if (length_buff.network == 0) { // shutdown signal.
            fprintf(stderr, "Shutting down server thread.\n");
            break;
        }

        uint32_t msg_size = ntohl(length_buff.network);
        std::vector<char> msg;
        msg.resize(msg_size);

        n = recv(conn, msg.data(), msg_size, 0);
        if (n == -1) {
            close(conn);
            fprintf(stderr, "Connection thread received error when waiting for message: %s\n", strerror(errno));
            continue;
        }

        nlohmann::json jobj;
        try {
            jobj = nlohmann::json::parse(std::string(msg.data(), msg_size));
        } catch (const nlohmann::json::parse_error &exc) {
            close(conn);
            fprintf(stderr, "Failed to parse response as JSON: %s\n", std::string(exc.what()).c_str());
            continue;
        }
        if (!jobj.is_object()) {
            close(conn);
            fprintf(stderr, "Message not a valid JSON object\n");
            continue;
        }
        if (!jobj["host"].is_string()) {
            close(conn);
            fprintf(stderr, "Message host is not a string\n");
            continue;
        }
        if (!jobj["port"].is_number_integer()) {
            close(conn);
            fprintf(stderr, "Message port is not an integer\n");
            continue;
        }
        std::string host = jobj["host"];
        int port = jobj["port"];

        struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;
        struct addrinfo *result;
        auto rv = getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &result);
        if (rv == -1) {
            close(conn);
            fprintf(stderr, "Failed server lookup for %s: %s\n", host.c_str(), gai_strerror(rv));
        }
        int server_fd = -1;
        for (auto rp = result; rp != NULL; rp = rp->ai_next) {
            auto sfd = socket(rp->ai_family, rp->ai_socktype,
                         rp->ai_protocol);
            if (sfd == -1)
                continue;

            if (connect(sfd, rp->ai_addr, rp->ai_addrlen) == 0) {
                server_fd = sfd;
                break;
            }
            fprintf(stderr, "Failed to connect to server: %s\n", strerror(errno));
            close(sfd);
        }
        freeaddrinfo(result);
        if (server_fd == -1) {
            close(conn);
            fprintf(stderr, "Failed to connect to server (no IPs found in DNS): %s.\n", host.c_str());
            continue;
        }

        // Sleep 10ms to ensure client runs through the event loop.
        usleep(10'000);

        char message[2] = "0";
        struct iovec iov = {
            .iov_base = message,
            .iov_len = 1
        };

        union {
            char buf[CMSG_SPACE(sizeof(server_fd))];
            struct cmsghdr align;
        } u;

        struct msghdr msghd;
        memset(&msghd, 0, sizeof(msghd));
        msghd.msg_iov = &iov;
        msghd.msg_iovlen = 1;
        msghd.msg_control = u.buf;
        msghd.msg_controllen = sizeof(u.buf);

        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msghd);
        *cmsg = (struct cmsghdr){.cmsg_len = CMSG_LEN(sizeof(server_fd)),
                                 .cmsg_level = SOL_SOCKET,
                                 .cmsg_type = SCM_RIGHTS
                                };

        memcpy(CMSG_DATA(cmsg), &server_fd, sizeof(server_fd));

        rv = sendmsg(conn, &msghd, MSG_NOSIGNAL);
        if (rv == -1) {
            fprintf(stderr, "Failed to send FD as response: %s\n", strerror(errno));
        }
        close(conn);
        me->m_successful_callouts.fetch_add(1, std::memory_order_acq_rel);
    }
}

void CurlCalloutFixture::SubprocessSetUp(std::tuple<int, int, int, int> comm_pipes) {
    if (std::get<0>(comm_pipes) != -1) {
        close(m_stderr_to_child[1]);
        close(m_stdout_to_child[1]);

        // Duplicate the current stderr/out; stderr/out will be written to the parent and
        // then read back to the child and tee'd to these descriptors.
        int stdout_dup = dup(STDOUT_FILENO);
        ASSERT_NE(stdout_dup, -1) << "Failed to duplicate stdout: " << strerror(errno);
        int stderr_dup = dup(STDERR_FILENO);
        ASSERT_NE(stderr_dup, -1) << "Failed to duplicate stderr: " << strerror(errno);

        // Replace stderr/out with the write end of the pipe
        ASSERT_EQ(dup2(std::get<0>(comm_pipes), STDOUT_FILENO), STDOUT_FILENO) << "Failed to redirect stdout: " << strerror(errno);
        close(std::get<0>(comm_pipes)); // Close the original write end, as it's now duplicated to stdout
        ASSERT_EQ(dup2(std::get<1>(comm_pipes), STDERR_FILENO), STDERR_FILENO) << "Failed to redirect stderr: " << strerror(errno);
        close(std::get<1>(comm_pipes)); // Close the original write end, as it's now duplicated to stderr
        // We won't be writing to these anymore as stdout/err are used; close them.

        // Start the tee thread to read from the parent pipes and write to the original stdout/err
        auto TeeOutput = [=]() {
            struct pollfd pfds[2];
            pfds[0].fd = std::get<2>(comm_pipes);
            pfds[0].events = POLLIN;
            pfds[1].fd = std::get<3>(comm_pipes);
            pfds[1].events = POLLIN;
            int flags;
            flags = fcntl(std::get<2>(comm_pipes), F_GETFL, 0);
            if (flags != -1) fcntl(std::get<2>(comm_pipes), F_SETFL, flags | O_NONBLOCK);
            flags = fcntl(std::get<3>(comm_pipes), F_GETFL, 0);
            if (flags != -1) fcntl(std::get<3>(comm_pipes), F_SETFL, flags | O_NONBLOCK);

            bool stderr_open = true, stdout_open = true;
            while (stderr_open || stdout_open) {
                if (stdout_open) {
                    pfds[0].events = POLLIN;
                } else {
                    pfds[0].fd = -1;
                }
                if (stderr_open) {
                    pfds[1].events = POLLIN;
                } else {
                    pfds[1].fd = -1;
                }

                int ret = poll(pfds, 2, -1);
                if (ret <= 0) break;

                for (int i = 0; i < 2; ++i) {
                    if ((pfds[i].revents & POLLIN) != 0) {
                        char buffer[4096];
                        ssize_t n = read(pfds[i].fd, buffer, sizeof(buffer));
                        if (n <= 0) {
                            if (i == 0) stdout_open = false;
                            else stderr_open = false;
                            continue;
                        }
                        // Write to the appropriate original fd
                        int out_fd = (i == 0) ? stdout_dup : stderr_dup;
                        ssize_t written = 0;
                        while (written < n) {
                            ssize_t w = write(out_fd, buffer + written, n - written);
                            if (w <= 0) break;
                            written += w;
                        }
                    } else if ((pfds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                        if (i == 0) stdout_open = false;
                        else stderr_open = false;
                    }
                }
            }
        };
        m_tee_thread.reset(new std::thread(TeeOutput));
    }

    TransferFixture::SetUp();

    std::string rundir = GetEnv("XROOTD_RUNDIR");
    ASSERT_FALSE(rundir.empty());
    m_comm_filename = rundir + "/comm.sock." + std::to_string(getpid());

    struct sockaddr_un addr_un;
    addr_un.sun_family = AF_UNIX;
    struct sockaddr *addr = reinterpret_cast<struct sockaddr *>(&addr_un);
    ASSERT_FALSE(m_comm_filename.size() >= sizeof(addr_un.sun_path)) <<
        "Location of communication socket (" << m_comm_filename << ") longer than maximum socket path name";
    
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    ASSERT_NE(sock, -1) << "Failed to create new communication socket: " << strerror(errno);

    strcpy(addr_un.sun_path, m_comm_filename.c_str());
    socklen_t len = SUN_LEN(&addr_un);
#ifdef __APPLE__
    addr_un.sun_len = SUN_LEN(&addr_un);
#endif
    auto rv = bind(sock, addr, len);
    ASSERT_NE(rv, -1) << "Failed to connect to communication socket: " << strerror(errno);

    rv = listen(sock, 50);
    ASSERT_NE(rv, -1) << "Failed to list on communication socket: " << strerror(errno);

    m_server_thread.reset(new std::thread(ConnectionThread, this, sock));
}

void CurlCalloutFixture::SubprocessTearDown() {
    struct sockaddr_un addr_un;
    addr_un.sun_family = AF_UNIX;
    struct sockaddr *addr = reinterpret_cast<struct sockaddr *>(&addr_un);
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    strcpy(addr_un.sun_path, m_comm_filename.c_str());
    socklen_t len = SUN_LEN(&addr_un);
#ifdef __APPLE__
    addr_un.sun_len = SUN_LEN(&addr_un);
#endif
    auto rv = connect(sock, addr, len);
    ASSERT_NE(rv, -1) << "Failed to connect to server unix socket at " << m_comm_filename.c_str() << ": " << strerror(errno);

    char message[4] = {0, 0, 0, 0};
    rv = send(sock, message, 4, 0);
    ASSERT_NE(rv, -1) << "Failed to send message length to server socket: " << strerror(errno);

    close(sock);
    m_shutdown.store(true, std::memory_order_release);
    m_server_thread->join();

    rv = unlink(m_comm_filename.c_str());
    ASSERT_NE(rv, -1) << "Failed to unlink old server unix socket at " << m_comm_filename << ": " << strerror(errno);
}

void CurlCalloutFixture::SubprocessTearDownTee() {
    if (m_tee_thread) {
        close(STDERR_FILENO);
        close(STDOUT_FILENO);
        write(m_child_teardown[1], "\0", 1);
        close(m_child_teardown[1]);
        m_tee_thread->join();
    }
}

void
CurlCalloutFixture::RunTest(bool doExit, std::tuple<int, int, int, int> comm_pipes)
{
    ASSERT_NO_FATAL_FAILURE(SubprocessSetUp(doExit ? comm_pipes : std::make_tuple(-1, -1, -1, -1)));

    auto start_val = CurlCalloutFixture::SuccessfulCalloutResponses();

    auto url = GetOriginURL() + "/test/connection_callout_file." + std::to_string(getpid());
    WritePattern(url, 32, 'a', 30);

    XrdCl::File fh;
    XrdCl::URL parsed_cache_url(GetCacheURL().c_str());
    auto host = parsed_cache_url.GetHostName();
    auto port = parsed_cache_url.GetPort();
    auto cache_url = "https://blah-cache.example.com:" + std::to_string(port) + "/test/connection_callout_file." + std::to_string(getpid()) + "?x-hostname=" + host;
    url = cache_url + "&authz=" + GetReadToken();

    auto rv = fh.Open(cache_url, XrdCl::OpenFlags::Compress, XrdCl::Access::None, nullptr, XrdClCurl::File::timeout_t(0));
    ASSERT_TRUE(rv.IsOK());

    XrdClCurl::CreateConnCalloutType callout = ConnectionBroker::CreateCallback;
    auto callout_loc = reinterpret_cast<long long>(callout);
    size_t buf_size = 15;
    char callout_buf[buf_size];
    std::to_chars_result result = std::to_chars(callout_buf, callout_buf + buf_size - 1, callout_loc, 16);
    if (result.ec == std::errc{}) {
        std::string callout_str(callout_buf, result.ptr - callout_buf);
        fh.SetProperty("XrdClConnectionCallout", callout_str);
    }
    fh.SetProperty(ResponseInfoProperty, "true");

    auto now = std::chrono::steady_clock::now();

    SyncResponseHandler handler;
    rv = fh.Open(url, XrdCl::OpenFlags::Read, XrdCl::Access::Mode(0755), &handler, XrdClCurl::File::timeout_t(10));
    ASSERT_TRUE(rv.IsOK());

    handler.Wait();
    auto [status, obj] = handler.Status();

    VerifyContents(fh, 32, 'a', 30);
    
    // Note we cannot determine how many callouts there will be: there will be ~2 per curl worker thread,
    // assuming the curl worker thread picks up any work.
    ASSERT_TRUE(CurlCalloutFixture::SuccessfulCalloutResponses() > start_val + 1) <<
        "Expected at least 2 successful callouts, got " << CurlCalloutFixture::SuccessfulCalloutResponses() - start_val;

    ASSERT_NO_FATAL_FAILURE(SubprocessTearDown());

    auto duration = std::chrono::steady_clock::now() - now;
    if (duration > std::chrono::seconds(10)) {
        fprintf(stderr, "Too slow\n");
    } else {
        fprintf(stderr, "Success\n");
    }

    ASSERT_NO_FATAL_FAILURE(SubprocessTearDownTee());

    if (doExit)
        exit(0);
}

// The test itself is relatively simple:
// - Write and read from the origin, triggering a connection callout.
// - Read from the cache, triggering a second connection callout.
TEST_F(CurlCalloutFixture, Test)
{
    try {
        EXPECT_EXIT(RunTest(true, GetCommPipes()), testing::ExitedWithCode(0), "Success");
    } catch (std::exception &exc) {
        // Suppress the exception coming from the child to allow TearDown to print out
        // the child's stderr.  This way, we actually print the underlying ASSERT!
        return;
    }
}

// Non-death-test version.  This avoids the fork, runs only once, and
// streams the output to stderr to allow for easier debugging.
// Commented out by default; enable for debugging purposes.
/*
TEST_F(CurlCalloutFixture, SimpleTest)
{
    RunTest(false, GetCommPipes());
}
*/
