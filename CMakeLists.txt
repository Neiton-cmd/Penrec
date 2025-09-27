cmake_minimum_required(VERSION 3.16)
project(penrec LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(penrec cpp/src/main.cpp)

add_library(scanner cpp/src/scanner.cpp)
add_library(sniffer cpp/src/sniffer.cpp)

target_link_libraries(penrec PRIVATE scanner sniffer pcap)

