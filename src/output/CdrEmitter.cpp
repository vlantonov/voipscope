#include "CdrEmitter.hpp"

#include <cmath>
#include <ctime>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <sstream>

namespace voipscope {

namespace {

// Format a time_point as ISO 8601 UTC with milliseconds: "2024-03-15T10:23:45.123Z"
std::string formatIso8601(std::chrono::system_clock::time_point tp) {
    // Convert to time_t for calendar fields
    auto secs   = std::chrono::floor<std::chrono::seconds>(tp);
    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(
                      tp - secs).count();
    std::time_t tt = std::chrono::system_clock::to_time_t(secs);
    std::tm tmUtc{};
    ::gmtime_r(&tt, &tmUtc);

    char buf[32]{};
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tmUtc);

    std::ostringstream oss;
    oss << buf << '.' << std::setw(3) << std::setfill('0') << millis << 'Z';
    return oss.str();
}

double roundTo2(double v) {
    return std::round(v * 100.0) / 100.0;
}

// nlohmann::json serialise std::optional<T>: nullopt → null
template<typename T>
void addOptional(nlohmann::json& j, const char* key, const std::optional<T>& opt) {
    if (opt.has_value()) {
        j[key] = *opt;
    } else {
        j[key] = nullptr;
    }
}

} // namespace

void emitCdr(const Cdr& cdr, std::ostream& out) {
    nlohmann::json j;

    j["call_id"] = cdr.callId;
    j["caller"]  = cdr.caller;
    j["callee"]  = cdr.callee;

    j["start_time"] = formatIso8601(cdr.startTime);
    j["end_time"]   = formatIso8601(cdr.endTime);

    auto durationSec = std::chrono::duration<double>(cdr.endTime - cdr.startTime).count();
    j["duration_sec"] = std::round(durationSec * 1000.0) / 1000.0;

    j["codec"]        = cdr.codec;
    j["payload_type"] = static_cast<int>(cdr.payloadType);

    // Per-stream array (FR-39)
    nlohmann::json streamsArr = nlohmann::json::array();
    for (const auto& s : cdr.streams) {
        nlohmann::json entry;
        entry["direction"]       = s.direction;
        entry["ssrc"]            = s.ssrc;
        entry["mos"]             = roundTo2(s.mos);
        entry["mean_jitter_ms"]  = roundTo2(s.meanJitterMs);
        entry["packet_loss_pct"] = roundTo2(s.lossPercent);
        streamsArr.push_back(std::move(entry));
    }
    j["streams"] = std::move(streamsArr);

    // Top-level convenience fields (FR-37, §10.2)
    addOptional(j, "mos",             cdr.mos);
    addOptional(j, "mean_jitter_ms",  cdr.meanJitterMs);
    addOptional(j, "packet_loss_pct", cdr.lossPercent);
    addOptional(j, "ssrc",            cdr.ssrc);

    j["status"] = cdr.status;

    out << j.dump() << '\n';
}

} // namespace voipscope
