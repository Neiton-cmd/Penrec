#include "scanner.h"
//#include <getopt.h>
#include <cstdlib>
#include "cxxopts.hpp"
using namespace std;


void print_usage(const char* prog);

int main(int argc, char* argv[]) {
    
    cxxopts::Options options("Penrec", "Port Scanner");

    options.add_options()
      ("t,target", "Target IP/hostname", cxxopts::value<std::string>())
      ("s,start",  "Start port", cxxopts::value<int>()->default_value("1"))
      ("e,end",    "End port", cxxopts::value<int>()->default_value("1024"))
      ("n,threads","Threads", cxxopts::value<int>()->default_value("100"))
      ("o,timeout","Timeout ms", cxxopts::value<int>()->default_value("500"))
      ("m,mode",   "Mode (open|closed|all)", cxxopts::value<std::string>()->default_value("open"))
      ("h,help", "Print help");
    

    auto result = options.parse(argc, argv);
    if (result.count("help") || !result.count("target")) {
        print_usage(argv[0]);
        std::cout << options.help() << std::endl;
        return 0;
    }
    std::string target = result["target"].as<std::string>();
    int start = result["start"].as<int>();
    int end = result["end"].as<int>();
    int threads = result["threads"].as<int>();
    int timeout_ms = result["timeout"].as<int>();
    std::string mode = result["mode"].as<std::string>();

    if (end < start) std::swap(start, end);

    Scanner sc(target, start, end, threads, timeout_ms);
    sc.run();

    auto results = sc.getResults();
    std::sort(results.begin(), results.end(), [](const ScanResult&a, const ScanResult&b){ return a.port < b.port; });

    if (mode == "open") {
        for (auto &r : results) if (r.open) std::cout << "[+] port:      " << r.port << "   open\n";
    } else if (mode == "closed") {
        for (auto &r : results) if (!r.open) std::cout << "[-] port " << r.port << " CLOSED\n";
    } else {
        for (auto &r : results) std::cout << (r.open?"[+]":"[-]") << " port " << r.port << (r.open?" OPEN\n":" CLOSED\n");
    }
    // if (argc < 4) {
    //     std::cerr << "Usage: " << argv[0] << " <target> <start_port> <end_port> [threads] [timeout_ms]\n";
    //     return 1;
    // }

    // std::string target = argv[1];
    // int start = std::stoi(argv[2]);
    // int end = std::stoi(argv[3]);
    // int threads = 100;
    // int timeout_ms = 500;

    // if (argc >= 5) threads = std::stoi(argv[4]);
    // if (argc >= 6) timeout_ms = std::stoi(argv[5]);

    // Scanner sc(target, start, end, threads, timeout_ms);
    // sc.run();

    // auto results = sc.getResults();
    // // sort results by port before printing
    // std::sort(results.begin(), results.end(), [](const ScanResult&a, const ScanResult&b){ return a.port < b.port; });

    

    // // print text file
    // std::string text = sc.resultsToTextOpenOnly();
    // std::cout << text << std::endl;
    

    return 0;
}

void print_usage(const char* prog){
    std::cout << "Usage: " << prog << " [OPTIONS]\n\n"
              << "Options:\n"
              << "  -t, --target    <target>      target host (IP or hostname)\n"
              << "  -s, --start     <port>        start port (default 1)\n"
              << "  -e, --end       <port>        end port (default 1024)\n"
              << "  -n, --threads   <num>         threads (default 100)\n"
              << "  -o, --timeout   <ms>          timeout ms (default 500)\n"
              << "  -m, --mode      <open|closed|all> output mode (default open)\n"
              << "  -h, --help                     show this help\n";
}
