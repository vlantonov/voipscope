#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace voipscope {

struct StreamStats {
    std::string direction; // "caller_to_callee" or "callee_to_caller"
    uint32_t    ssrc{0};
    double      mos{0.0};
    double      meanJitterMs{0.0};
    double      lossPercent{0.0};
};

struct Cdr {
    std::string callId;
    std::string caller;   // From AOR
    std::string callee;   // To AOR

    std::chrono::system_clock::time_point startTime;
    std::chrono::system_clock::time_point endTime;

    std::string codec;
    uint8_t     payloadType{0};

    // Per-stream quality metrics (0, 1, or 2 entries)
    std::vector<StreamStats> streams;

    // Top-level convenience fields (null when streams is empty, CA-07)
    std::optional<double>   mos;
    std::optional<double>   meanJitterMs;
    std::optional<double>   lossPercent;
    std::optional<uint32_t> ssrc;

    // "complete" or "incomplete" (OQ-07)
    std::string status{"complete"};
};

} // namespace voipscope
