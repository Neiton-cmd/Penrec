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
void Scanner::run() {
    // prepare ports queue
    for (int p = start_port_; p <= end_port_; ++p) {
        ports_queue_.push_back(p);
    }

    // start workers
    stop_workers_ = false;
    for (int i = 0; i < max_threads_; ++i) {
        workers_.emplace_back(&Scanner::workerLoop, this);
    }

    // notify workers
    queue_cv_.notify_all();

    // wait for workers to finish
    for (auto &t : workers_) {
        if (t.joinable()) t.join();
    }
    workers_.clear();
}

// =================== Get results ===================
std::vector<ScanResult> Scanner::getResults() {
    std::lock_guard<std::mutex> lk(results_mutex_);
    return results_;
}

std::string Scanner::resultsToText() {
    std::lock_guard<std::mutex> lk(results_mutex_);
    std::ostringstream oss;
    oss << "[\n";
    for (const auto &r : results_){
        oss << "[+] port:    " << r.port << "       status    " << 
            (r.open ? "open" : "closed") << endl;
    }
    return oss.str();
}

// =================== workerLoop ===================
void Scanner::workerLoop() {
    while (true) {
        int port = -1;
        {   // pop a port from queue
            std::unique_lock<std::mutex> lk(queue_mutex_);
            queue_cv_.wait(lk, [this] { return !ports_queue_.empty() || stop_workers_; });
            if (ports_queue_.empty() && stop_workers_) {
                return;
            }
            if (!ports_queue_.empty()) {
                port = ports_queue_.back();
                ports_queue_.pop_back();
            } else {
                continue;
            }
        }

        // scan
        ScanResult r = scanPort(port);
        pushResult(r);

        // if queue empty now and all threads idle, signal stopping condition
        {
            std::unique_lock<std::mutex> lk(queue_mutex_);
            if (ports_queue_.empty()) {
                // set stop flag only when all tasks picked (simple approach)
                stop_workers_ = true;
                queue_cv_.notify_all();
            }
        }
    }
}

// =================== scanPort (core) ===================
ScanResult Scanner::scanPort(int port) {
    ScanResult res;
    res.port = port;
    res.open = false;
    res.error_code = 0;

    struct addrinfo hints;
    struct addrinfo *servinfo = nullptr;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_INET; // allow IPv4 

    std::string portStr = std::to_string(port);
    int gai = getaddrinfo(target_.c_str(), portStr.c_str(), &hints, &servinfo);
    if (gai != 0) {
        res.error_code = gai; // store getaddrinfo error
        return res;
    }

    // try each addr until success
    for (struct addrinfo *p = servinfo; p != nullptr; p = p->ai_next) {
        int err = 0;
        int sockfd = connectWithTimeout(p, timeout_ms_, err);
        if (sockfd >= 0) {
            // success
            res.open = true;
            res.banner = tryBannerGrab(sockfd, timeout_ms_);
            close(sockfd);
            break;
        } else {
            res.open = false;
            // record last error
            res.error_code = err;
            // try next address
        }
    }

    freeaddrinfo(servinfo);
    return res;
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



