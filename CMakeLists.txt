cmake_minimum_required(VERSION 3.16)
project(PacketAnalyzer VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Header files location
include_directories(${CMAKE_SOURCE_DIR}/include)

# Find thread library for the multi-threaded DPI engine
find_package(Threads REQUIRED)

# 1. Packet Analyzer (Basic)
add_executable(packet_analyzer
    src/main.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
)

# 2. DPI Simple (Single-threaded DPI Engine)
add_executable(dpi_simple
    src/main_working.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/types.cpp
)

# 3. DPI Engine (Multi-threaded DPI Engine)
add_executable(dpi_engine
    src/dpi_mt.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/types.cpp
    src/connection_tracker.cpp
    src/fast_path.cpp
    src/load_balancer.cpp
    src/rule_manager.cpp
    src/dpi_engine.cpp
)
target_link_libraries(dpi_engine PRIVATE Threads::Threads)
