#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace voipscope {

struct UdpPacket {
    std::chrono::system_clock::time_point timestamp;
    std::string  srcIp;
    std::string  dstIp;
    uint16_t     srcPort{0};
    uint16_t     dstPort{0};
    std::vector<uint8_t> payload;
};

class PcapReader {
public:
    explicit PcapReader(const std::string& path);
    ~PcapReader();

    PcapReader(const PcapReader&)            = delete;
    PcapReader& operator=(const PcapReader&) = delete;

    // Returns std::nullopt at EOF; silently skips non-UDP packets (FR-03).
    std::optional<UdpPacket> next();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace voipscope
