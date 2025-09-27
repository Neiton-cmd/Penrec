#include "scanner.h"
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <target> <start_port> <end_port> [threads] [timeout_ms]\n";
        return 1;
    }

    std::string target = argv[1];
    int start = std::stoi(argv[2]);
    int end = std::stoi(argv[3]);
    int threads = 100;
    int timeout_ms = 500;

    if (argc >= 5) threads = std::stoi(argv[4]);
    if (argc >= 6) timeout_ms = std::stoi(argv[5]);

    Scanner sc(target, start, end, threads, timeout_ms);
    sc.run();

    auto results = sc.getResults();
    // sort results by port before printing
    std::sort(results.begin(), results.end(), [](const ScanResult&a, const ScanResult&b){ return a.port < b.port; });

    

    // print text file
    std::string text = sc.resultsToTextOpenOnly();
    std::cout << text << std::endl;
    

    return 0;
}


