#ifndef SCANNER_H
#define SCANNER_H

#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <cstring>
#include <cerrno>
#include <sstream>
#include <chrono>
#include <algorithm>
#include <iostream>

struct ScanResult {
    int port = 0;
    bool open = false;
    std::string banner;   // optional
    int error_code = 0;   // errno-like
};

class Scanner {
public:
    // target: hostname or IP, start/end ports inclusive
    // threads: number of worker threads
    // timeout_ms: connect timeout in milliseconds
    Scanner(const std::string& target, int start_port, int end_port,
            int threads = 100, int timeout_ms = 500);

    // run scan and block until finished
    void run();

    // Get results (thread-safe after run finished)
    std::vector<ScanResult> getResults();

    // Optional: produce simple JSON string of results
    std::string resultsToText(); // IGNORE

    std::string resultsToTextOpenOnly(); 

    
private:
    std::string target_;
    int start_port_;
    int end_port_;
    int max_threads_;
    int timeout_ms_;

    std::vector<ScanResult> results_;
    std::mutex results_mutex_;

    // Thread-pool + task queue
    std::vector<std::thread> workers_;
    std::vector<int> ports_queue_;
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    bool stop_workers_ = false;

    // worker loop
    void workerLoop();

    // scan single port (core logic)
    ScanResult scanPort(int port);

    // helper: non-blocking connect with timeout (returns socket fd >=0 on success, or -1 on failure and sets err)
    int connectWithTimeout(const struct addrinfo* addr, int timeout_ms, int &err);

    // helper: try to read banner with recv + select timeout
    std::string tryBannerGrab(int sockfd, int timeout_ms);

    // push result into results_ with mutex
    void pushResult(const ScanResult& r);
};

#endif // SCANNER_H
