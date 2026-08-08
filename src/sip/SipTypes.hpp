#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace voipscope {

// ---------------------------------------------------------------------------
// SDP information extracted from INVITE offer / 200 OK answer bodies
// ---------------------------------------------------------------------------
struct SdpInfo {
    std::string connectionAddress; // from c=IN IP4 <addr>
    uint16_t    mediaPort{0};      // from m= line
    std::string mediaType;         // "audio"
    uint8_t     payloadType{0};    // first PT in m= line
    std::string codecName;         // from a=rtpmap or static table (FR-19)
    uint32_t    clockRateHz{8000};
};

// ---------------------------------------------------------------------------
// SIP method enum
// ---------------------------------------------------------------------------
enum class SipMethod {
    INVITE, ACK, BYE, CANCEL, OPTIONS, REGISTER, Unknown
};

inline SipMethod sipMethodFromString(std::string_view s) {
    if (s == "INVITE")   return SipMethod::INVITE;
    if (s == "ACK")      return SipMethod::ACK;
    if (s == "BYE")      return SipMethod::BYE;
    if (s == "CANCEL")   return SipMethod::CANCEL;
    if (s == "OPTIONS")  return SipMethod::OPTIONS;
    if (s == "REGISTER") return SipMethod::REGISTER;
    return SipMethod::Unknown;
}

inline std::string_view sipMethodToString(SipMethod m) {
    switch (m) {
        case SipMethod::INVITE:   return "INVITE";
        case SipMethod::ACK:      return "ACK";
        case SipMethod::BYE:      return "BYE";
        case SipMethod::CANCEL:   return "CANCEL";
        case SipMethod::OPTIONS:  return "OPTIONS";
        case SipMethod::REGISTER: return "REGISTER";
        default:                  return "UNKNOWN";
    }
}

// ---------------------------------------------------------------------------
// Parsed SIP message (request or response)
// ---------------------------------------------------------------------------
struct SipMessage {
    // Request fields (empty/zero for responses)
    SipMethod   method{SipMethod::Unknown};
    std::string requestUri;

    // Response fields (zero for requests)
    int         statusCode{0};
    std::string reasonPhrase;

    // Mandatory headers (FR-06, FR-07)
    std::string callId;
    std::string from;       // full From header value
    std::string fromTag;    // extracted tag= parameter
    std::string to;         // full To header value
    std::string toTag;
    uint32_t    cseqNumber{0};
    SipMethod   cseqMethod{SipMethod::Unknown};
    std::string viaBranch;  // branch= param of topmost Via (CA-08)

    // Optional headers
    std::string contact;
    std::string contentType;
    uint32_t    contentLength{0};

    // Body — populated when Content-Type: application/sdp (FR-08)
    std::optional<SdpInfo> sdp;

    // Filled by dispatcher in main.cpp
    std::string srcIp;
    uint16_t    srcPort{0};
    std::string dstIp;
    uint16_t    dstPort{0};
    std::chrono::system_clock::time_point captureTime;

    bool isRequest()  const noexcept { return statusCode == 0; }
    bool isResponse() const noexcept { return !isRequest(); }
};

// ---------------------------------------------------------------------------
// Dialog FSM states (FR-10)
// ---------------------------------------------------------------------------
enum class DialogState {
    TRYING,
    RINGING,
    ESTABLISHED,
    TERMINATED
};

// ---------------------------------------------------------------------------
// Per-dialog tracking context
// ---------------------------------------------------------------------------
struct DialogContext {
    std::string callId;
    std::string fromTag;
    std::string toTag;

    std::string callerUri;
    std::string calleeUri;

    DialogState state{DialogState::TRYING};

    std::optional<SdpInfo> offerSdp;
    std::optional<SdpInfo> answerSdp;

    std::chrono::system_clock::time_point inviteTime;
    std::chrono::system_clock::time_point startTime;  // 200 OK timestamp (FR-15)
    std::chrono::system_clock::time_point endTime;    // BYE / error timestamp

    // Retransmission dedup: "viaBranch/cseqNumber" strings (CA-08)
    std::unordered_set<std::string> seenTransactions;

    // Last CSeq number of the active INVITE transaction
    uint32_t inviteCseq{0};

    bool emitCdr{false};     // true = TERMINATED via BYE → emit CDR
    bool isIncomplete{false};
};

} // namespace voipscope
