#include "SdpParser.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <string_view>

namespace voipscope {

namespace {

// Advance past "\r\n" or "\n"; returns empty string_view at end of input.
std::string_view nextLine(std::string_view& remaining) {
    if (remaining.empty()) return {};

    auto pos = remaining.find('\n');
    std::string_view line;
    if (pos == std::string_view::npos) {
        line      = remaining;
        remaining = {};
    } else {
        line = remaining.substr(0, pos);
        remaining = remaining.substr(pos + 1);
        // Strip trailing \r
        if (!line.empty() && line.back() == '\r') {
            line.remove_suffix(1);
        }
    }
    return line;
}

// Parse an unsigned integer from the front of sv; returns 0 on failure.
template<typename T>
T parseUint(std::string_view sv) {
    T value{};
    auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), value);
    if (ec != std::errc{}) return T{};
    return value;
}

// Case-insensitive comparison of ASCII strings
bool iequal(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) return false;
    }
    return true;
}

// Static payload type table (FR-19)
struct StaticPt { uint8_t pt; const char* name; uint32_t clockRate; };
constexpr std::array<StaticPt, 4> kStaticPtTable{{
    {0,  "PCMU", 8000},
    {8,  "PCMA", 8000},
    {9,  "G722", 8000}, // RFC 3551: RTP clock rate 8 kHz despite 16 kHz sample rate
    {18, "G729", 8000},
}};

} // namespace

std::optional<SdpInfo> parseSdp(std::string_view body) {
    SdpInfo sdp;
    bool foundAudio = false;

    std::string_view remaining = body;

    while (!remaining.empty()) {
        std::string_view line = nextLine(remaining);
        if (line.empty()) continue;

        if (line.size() < 2 || line[1] != '=') continue;
        char type = line[0];
        std::string_view value = line.substr(2);

        switch (type) {
        case 'c': {
            // c=IN IP4 <addr>
            // Skip "IN IP4 " prefix
            auto p1 = value.find(' ');
            if (p1 == std::string_view::npos) break;
            auto p2 = value.find(' ', p1 + 1);
            if (p2 == std::string_view::npos) break;
            sdp.connectionAddress = std::string(value.substr(p2 + 1));
            break;
        }
        case 'm': {
            // m=<media> <port> <proto> <fmt-list>
            auto p1 = value.find(' ');
            if (p1 == std::string_view::npos) break;
            std::string_view mediaType = value.substr(0, p1);
            if (!iequal(mediaType, "audio")) break; // ignore non-audio

            foundAudio = true;
            sdp.mediaType = std::string(mediaType);

            std::string_view rest = value.substr(p1 + 1);
            auto p2 = rest.find(' ');
            if (p2 == std::string_view::npos) break;
            sdp.mediaPort = parseUint<uint16_t>(rest.substr(0, p2));

            // Skip protocol token
            rest = rest.substr(p2 + 1);
            auto p3 = rest.find(' ');
            std::string_view fmtList;
            if (p3 == std::string_view::npos) {
                fmtList = rest;
            } else {
                fmtList = rest.substr(p3 + 1);
            }

            // First payload type (OQ-02: first only)
            auto ptEnd = fmtList.find(' ');
            std::string_view ptSv = (ptEnd == std::string_view::npos)
                                        ? fmtList
                                        : fmtList.substr(0, ptEnd);
            sdp.payloadType = parseUint<uint8_t>(ptSv);

            // Apply static table immediately (may be overridden by a=rtpmap below)
            for (const auto& entry : kStaticPtTable) {
                if (entry.pt == sdp.payloadType) {
                    sdp.codecName   = entry.name;
                    sdp.clockRateHz = entry.clockRate;
                    break;
                }
            }
            break;
        }
        case 'a': {
            if (!foundAudio) break;
            // a=rtpmap:<pt> <codec>/<rate>[/<channels>]
            if (value.starts_with("rtpmap:")) {
                std::string_view rest = value.substr(7);
                auto spacePos = rest.find(' ');
                if (spacePos == std::string_view::npos) break;
                uint8_t pt = parseUint<uint8_t>(rest.substr(0, spacePos));
                if (pt != sdp.payloadType) break;

                std::string_view codecStr = rest.substr(spacePos + 1);
                auto slashPos = codecStr.find('/');
                if (slashPos == std::string_view::npos) {
                    sdp.codecName = std::string(codecStr);
                } else {
                    sdp.codecName = std::string(codecStr.substr(0, slashPos));
                    std::string_view rateStr = codecStr.substr(slashPos + 1);
                    // Strip optional /channels
                    auto s2 = rateStr.find('/');
                    if (s2 != std::string_view::npos) rateStr = rateStr.substr(0, s2);
                    uint32_t rate = parseUint<uint32_t>(rateStr);
                    if (rate > 0) sdp.clockRateHz = rate;
                }
                // Convert codec name to uppercase for consistency
                for (auto& ch : sdp.codecName) {
                    ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
                }
            }
            break;
        }
        default:
            break;
        }
    }

    if (!foundAudio) return std::nullopt;
    return sdp;
}

} // namespace voipscope
