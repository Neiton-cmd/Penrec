#include "scanner.h"

using namespace std;
// =================== Constructor ===================
Scanner::Scanner(const std::string& target, int start_port, int end_port,
                 int threads, int timeout_ms)
    : target_(target),
      start_port_(start_port),
      end_port_(end_port),
      max_threads_(std::max(1, threads)),
      timeout_ms_(std::max(100, timeout_ms))
{ }

// =================== Public run ===================
// Replace the entire Scanner::run() with this implementation
// --- debug-enabled run() (insert or replace your existing run())
void Scanner::run() {
    // Resolve once (IPv4)
    struct addrinfo hints;
    struct addrinfo *res = nullptr;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    int gai = getaddrinfo(target_.c_str(), nullptr, &hints, &res);
    if (gai != 0 || res == nullptr) {
        std::lock_guard<std::mutex> lk(results_mutex_);
        if (res) freeaddrinfo(res);
        return;
    }

    struct sockaddr_in base_addr;
    memset(&base_addr, 0, sizeof(base_addr));
    if (res->ai_addr && res->ai_addrlen >= (socklen_t)sizeof(sockaddr_in)) {
        memcpy(&base_addr, res->ai_addr, sizeof(sockaddr_in));
    } else {
        base_addr.sin_family = AF_INET;
        base_addr.sin_addr.s_addr = INADDR_ANY;
    }

    const int BATCH_SIZE = 500;
    for (int batchStart = start_port_; batchStart <= end_port_; batchStart += BATCH_SIZE) {
        int batchEnd = std::min(batchStart + BATCH_SIZE - 1, end_port_);

        int epfd = epoll_create1(0);
        if (epfd < 0) {
            freeaddrinfo(res);
            return;
        }

        std::unordered_map<int,int> fd_to_port;

        // Create non-blocking sockets and register
        for (int port = batchStart; port <= batchEnd; ++port) {
            int sockfd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
            if (sockfd < 0) {
                ScanResult r; r.port = port; r.open = false; r.error_code = errno;
                pushResult(r);
                continue;
            }

            int flags = fcntl(sockfd, F_GETFL, 0);
            if (flags == -1) flags = 0;
            fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

            struct sockaddr_in addr = base_addr;
            addr.sin_port = htons(port);

            int rc = connect(sockfd, (struct sockaddr*)&addr, sizeof(addr));
            if (rc == 0) {
                ScanResult r; r.port = port; r.open = true; r.error_code = 0;
                r.banner = tryBannerGrab(sockfd, timeout_ms_);
                pushResult(r);
                close(sockfd);
                continue;
            } else if (errno != EINPROGRESS) {
                ScanResult r; r.port = port; r.open = false; r.error_code = errno;
                pushResult(r);
                close(sockfd);
                continue;
            }

            struct epoll_event ev;
            ev.events = EPOLLOUT | EPOLLERR | EPOLLET;
            ev.data.fd = sockfd;
            if (epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev) < 0) {
                ScanResult r; r.port = port; r.open = false; r.error_code = errno;
                pushResult(r);
                close(sockfd);
                continue;
            }
            fd_to_port[sockfd] = port;
        }

        if (fd_to_port.empty()) {
            close(epfd);
            continue;
        }

        const int MAX_EVENTS = 4096;
        std::vector<struct epoll_event> events(MAX_EVENTS);

        while (!fd_to_port.empty()) {
            int n = epoll_wait(epfd, events.data(), (int)events.size(), timeout_ms_);
            if (n < 0) {
                if (errno == EINTR) continue;
                break;
            }
            if (n == 0) {
                for (auto &p : fd_to_port) {
                    ScanResult r; r.port = p.second; r.open = false; r.error_code = ETIMEDOUT;
                    pushResult(r);
                    close(p.first);
                }
                fd_to_port.clear();
                break;
            }

            for (int i = 0; i < n; ++i) {
                int fd = events[i].data.fd;
                auto it = fd_to_port.find(fd);
                if (it == fd_to_port.end()) {
                    epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr);
                    close(fd);
                    continue;
                }
                int port = it->second;

                int so_error = 0;
                socklen_t len = sizeof(so_error);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0) so_error = errno;

                ScanResult r;
                r.port = port;
                r.open = (so_error == 0);
                if (r.open) {
                    r.banner = tryBannerGrab(fd, timeout_ms_);
                } else {
                    r.error_code = so_error;
                }
                pushResult(r);

                epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr);
                close(fd);
                fd_to_port.erase(it);
            }
        }

        close(epfd);
    }

    freeaddrinfo(res);
}


    // // final cleanup
    // for (int fd : fds_to_close) {
    //     // if still open (in case not removed), try to close
    //     // but we already closed in loop, so ignore errors
    //     // close(fd);
    //     (void)fd;
    // }
    // close(epfd);
    // freeaddrinfo(res);


std::vector<ScanResult> Scanner::getResults() {
    std::lock_guard<std::mutex> lk(results_mutex_);
    return results_;
}


std::string Scanner::resultsToTextOpenOnly() {
    std::lock_guard<std::mutex> lk(results_mutex_);
    std::ostringstream oss;
    for (const auto &r : results_) {
        if (r.open) {  // only open ports
            oss << "[+] port:   " << r.port << "        status:      open";
            oss << "\n";
        }
    }
    return oss.str();
}




// =================== connectWithTimeout ===================
// returns sockfd >=0 on success (socket is blocking when returned)
// or -1 on failure and err set to errno
int Scanner::connectWithTimeout(const struct addrinfo* addr, int timeout_ms, int &err) {
    int sockfd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    if (sockfd < 0) {
        err = errno;
        return -1;
    }

    // set non-blocking
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1) flags = 0;
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    int rc = connect(sockfd, addr->ai_addr, addr->ai_addrlen);
    if (rc == 0) {
        // connected immediately
        // restore flags to blocking
        fcntl(sockfd, F_SETFL, flags);
        return sockfd;
    } else if (errno != EINPROGRESS) {
        // immediate error
        err = errno;
        close(sockfd);
        return -1;
    }

    // wait for writable with timeout
    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(sockfd, &wfds);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int sel = select(sockfd + 1, nullptr, &wfds, nullptr, &tv);
    if (sel <= 0) {
        // timeout or select error
        if (sel == 0) err = ETIMEDOUT;
        else err = errno;
        close(sockfd);
        return -1;
    }

    // check socket error
    int so_error = 0;
    socklen_t len = sizeof(so_error);
    if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0) {
        err = errno;
        close(sockfd);
        return -1;
    }
    if (so_error != 0) {
        err = so_error;
        close(sockfd);
        return -1;
    }

    // connected; restore blocking mode
    fcntl(sockfd, F_SETFL, flags);
    return sockfd;
}

// =================== tryBannerGrab ===================
std::string Scanner::tryBannerGrab(int sockfd, int timeout_ms) {
    // simple banner grab rules:
    // - for HTTP-like ports: send HEAD and read response
    // - for others: attempt to recv (many services send initial banner like SSH)
    std::string out;
    // set small recv timeout via select
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(sockfd, &rfds);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    // Attempt to identify by port? We don't have port here; upper level could pass port if needed.
    // We'll attempt a non-blocking recv first (some servers send banner).
    int sel = select(sockfd + 1, &rfds, nullptr, nullptr, &tv);
    if (sel > 0 && FD_ISSET(sockfd, &rfds)) {
        char buf[1024];
        ssize_t n = recv(sockfd, buf, sizeof(buf) - 1, 0);
        if (n > 0) {
            buf[n] = '\0';
            out.assign(buf, buf + n);
            // trim CRLFs
            while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) out.pop_back();
            return out;
        }
    }

    // If nothing received, try a very small write/read for HTTP-like behavior:
    const char *httpReq = "HEAD / HTTP/1.0\r\n\r\n";
    send(sockfd, httpReq, strlen(httpReq), 0);

    // wait again for response
    FD_ZERO(&rfds);
    FD_SET(sockfd, &rfds);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    sel = select(sockfd + 1, &rfds, nullptr, nullptr, &tv);
    if (sel > 0 && FD_ISSET(sockfd, &rfds)) {
        char buf[2048];
        ssize_t n = recv(sockfd, buf, sizeof(buf) - 1, 0);
        if (n > 0) {
            buf[n] = '\0';
            out.assign(buf, buf + n);
            while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) out.pop_back();
            return out;
        }
    }

    return out; // empty if not obtained
}

// =================== pushResult ===================
void Scanner::pushResult(const ScanResult& r) {
    std::lock_guard<std::mutex> lk(results_mutex_);
    results_.push_back(r);
}



