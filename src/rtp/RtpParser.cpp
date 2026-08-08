#include "RtpParser.hpp"

#include <arpa/inet.h>
#include <cstring>

namespace voipscope {

std::optional<RtpHeader> parseRtp(std::span<const uint8_t> payload) {
    if (payload.size() < 12) return std::nullopt;

    const uint8_t* p = payload.data();

    uint8_t byte0 = p[0];
    uint8_t version = (byte0 >> 6) & 0x03;
    if (version != 2) return std::nullopt;

    RtpHeader hdr;
    hdr.version   = version;
    hdr.padding   = (byte0 >> 5) & 0x01;
    hdr.extension = (byte0 >> 4) & 0x01;
    hdr.csrcCount = byte0 & 0x0F;

    uint8_t byte1     = p[1];
    hdr.marker        = (byte1 >> 7) & 0x01;
    hdr.payloadType   = byte1 & 0x7F;

    uint16_t seq{};
    std::memcpy(&seq, p + 2, 2);
    hdr.sequenceNumber = ntohs(seq);

    uint32_t ts{};
    std::memcpy(&ts, p + 4, 4);
    hdr.timestamp = ntohl(ts);

    uint32_t ssrc{};
    std::memcpy(&ssrc, p + 8, 4);
    hdr.ssrc = ntohl(ssrc);

    // Validate minimum length including CSRC list
    std::size_t minLen = 12 + static_cast<std::size_t>(hdr.csrcCount) * 4;
    if (payload.size() < minLen) return std::nullopt;

    return hdr;
}

} // namespace voipscope
