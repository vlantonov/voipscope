#pragma once

#include "RtcpParser.hpp"
#include "RtpParser.hpp"
#include "../pcap/PcapReader.hpp"
#include "../sip/SipTypes.hpp"

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

namespace voipscope {

// Statistics accumulated per RTP stream (keyed by SSRC + 5-tuple)
struct RtpStreamStats {
    uint32_t    ssrc{0};
    std::string srcIp;
    uint16_t    srcPort{0};
    std::string dstIp;
    uint16_t    dstPort{0};
    std::string callId;
    std::string direction; // "caller_to_callee" or "callee_to_caller"
    uint32_t    clockRateHz{8000};

    // Sequence-number tracking
    uint64_t receivedCount{0};
    uint16_t firstSeq{0};
    uint16_t highestSeq{0};
    bool     seqInitialized{false};

    // RFC 3550 §A.8 jitter estimator (in RTP clock units)
    double  jitter{0.0};
    double  jitterSum{0.0};
    int64_t prevTransit{0};
    bool    hasTransit{false};

    // RTCP-authoritative loss (FR-31)
    std::optional<uint32_t> rtcpCumulativeLost;

    // Last packet arrival time (for incomplete CDR end_time)
    std::chrono::system_clock::time_point lastArrival;

    // Derived metrics computed at CDR time
    double meanJitterMs() const;
    double lossPercent()  const;
};

class RtpTracker {
public:
    // Called by DialogManager when a dialog reaches ESTABLISHED (FR-21).
    // srcIp/srcPort is the media address from offerSdp (caller side).
    void associate(const std::string& callId,
                   const SdpInfo& offerSdp,
                   const SdpInfo& answerSdp);

    // Called by main for every RTP-classified UDP packet.
    void ingest(const UdpPacket& pkt, const RtpHeader& hdr);

    // Called by main for every RTCP block (FR-27).
    void ingestRtcp(const RtcpReportBlock& block);

    // Returns all streams associated with the given call_id.
    std::vector<RtpStreamStats> getStreams(const std::string& callId) const;

    // Returns the last arrival time seen for any stream of the given call.
    // Returns a zero time_point if no RTP arrived for that call.
    std::chrono::system_clock::time_point lastArrivalForCall(
        const std::string& callId) const;

private:
    struct FiveTuple {
        std::string srcIp;
        std::string dstIp;
        uint16_t    srcPort{0};
        uint16_t    dstPort{0};

        bool operator<(const FiveTuple& o) const noexcept {
            return std::tie(srcIp, dstIp, srcPort, dstPort) <
                   std::tie(o.srcIp, o.dstIp, o.srcPort, o.dstPort);
        }
    };

    // Map from 5-tuple → (callId, direction)
    std::map<FiveTuple, std::pair<std::string, std::string>> tupleToCall_;

    // Map from SSRC → stream stats
    std::map<uint32_t, RtpStreamStats> streams_;

    // Late-arrival buffer: 5-tuple → buffered packets before association (FR-24)
    struct PendingPacket {
        RtpHeader hdr;
        std::chrono::system_clock::time_point arrivalTime;
    };
    static constexpr std::size_t kPendingCap = 1000;
    std::map<FiveTuple, std::vector<PendingPacket>> pending_;

    void processPacket(RtpStreamStats& stats,
                       const RtpHeader& hdr,
                       std::chrono::system_clock::time_point arrivalTime);
};

} // namespace voipscope
