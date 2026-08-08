cmake_minimum_required(VERSION 3.20)
project(voipscope VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_compile_options(-Wall -Wextra -Wpedantic)

# libpcap system dependency (apt install libpcap-dev)
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

include(cmake/FetchDependencies.cmake)

# Static library (everything except main.cpp)
add_library(voipscope_lib STATIC
    src/pcap/PcapReader.cpp
    src/sip/SipParser.cpp
    src/sip/SdpParser.cpp
    src/sip/DialogManager.cpp
    src/rtp/RtpParser.cpp
    src/rtp/RtcpParser.cpp
    src/rtp/RtpTracker.cpp
    src/quality/MosEstimator.cpp
    src/output/CdrEmitter.cpp
)
target_include_directories(voipscope_lib PUBLIC src/)
target_include_directories(voipscope_lib PRIVATE ${PCAP_INCLUDE_DIRS})
target_link_libraries(voipscope_lib
    PUBLIC  nlohmann_json::nlohmann_json
    PRIVATE ${PCAP_LIBRARIES}
)

# Main executable
add_executable(voipscope src/main.cpp)
target_link_libraries(voipscope PRIVATE voipscope_lib)

# Tests
enable_testing()
add_subdirectory(tests)
