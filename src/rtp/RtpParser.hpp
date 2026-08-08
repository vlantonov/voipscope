#pragma once

#include <cstdint>
#include <optional>
#include <span>

namespace voipscope {

struct RtpHeader {
    uint8_t  version{0};
    bool     padding{false};
    bool     extension{false};
    uint8_t  csrcCount{0};
    bool     marker{false};
    uint8_t  payloadType{0};
    uint16_t sequenceNumber{0};
    uint32_t timestamp{0};
    uint32_t ssrc{0};
};

// Returns std::nullopt when the payload is too short or version != 2.
std::optional<RtpHeader> parseRtp(std::span<const uint8_t> payload);

} // namespace voipscope
