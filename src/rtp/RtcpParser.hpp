#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace voipscope {

struct RtcpReportBlock {
    uint32_t sourceSsrc{0};
    uint8_t  fractionLost{0};
    uint32_t cumulativeLost{0}; // 24-bit, stored in 32-bit
    uint32_t extHighestSeq{0};
    uint32_t jitter{0};         // interarrival jitter, RTP clock units
    uint32_t lsr{0};            // last SR timestamp
    uint32_t dlsr{0};           // delay since last SR
};

struct RtcpPacket {
    uint8_t  type{0};           // 200 = SR, 201 = RR
    uint32_t senderSsrc{0};
    std::vector<RtcpReportBlock> reportBlocks;
};

// Parses a potentially compound RTCP UDP payload.
// Returns an empty vector on malformed input.
std::vector<RtcpPacket> parseRtcp(std::span<const uint8_t> payload);

} // namespace voipscope
