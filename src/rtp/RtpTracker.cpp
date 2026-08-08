#include "RtpTracker.hpp"

#include <algorithm>
#include <cmath>

namespace voipscope {

// ---------------------------------------------------------------------------
// RtpStreamStats derived metrics
// ---------------------------------------------------------------------------

double RtpStreamStats::meanJitterMs() const {
    if (receivedCount < 2) return 0.0;
    double meanJitterUnits = jitterSum / static_cast<double>(receivedCount - 1);
    return meanJitterUnits / static_cast<double>(clockRateHz) * 1000.0;
}

double RtpStreamStats::lossPercent() const {
    if (rtcpCumulativeLost.has_value()) {
        // RTCP authoritative (FR-31)
        uint32_t expected = static_cast<uint32_t>(
            static_cast<uint16_t>(highestSeq - firstSeq) + 1u);
        if (expected == 0) return 0.0;
        double pct = static_cast<double>(*rtcpCumulativeLost) /
                     static_cast<double>(expected) * 100.0;
        return std::clamp(pct, 0.0, 100.0);
    }
    // Sequence-number-based (FR-30)
    if (!seqInitialized || receivedCount == 0) return 0.0;
    uint32_t expected = static_cast<uint32_t>(
        static_cast<uint16_t>(highestSeq - firstSeq) + 1u);
    if (expected == 0) return 0.0;
    double pct = (static_cast<double>(expected) - static_cast<double>(receivedCount)) /
                  static_cast<double>(expected) * 100.0;
    return std::clamp(pct, 0.0, 100.0);
}

// ---------------------------------------------------------------------------
// RtpTracker
// ---------------------------------------------------------------------------

void RtpTracker::associate(const std::string& callId,
                            const SdpInfo& offerSdp,
                            const SdpInfo& answerSdp) {
    // Caller → Callee: src = offer addr, dst = answer addr
    FiveTuple callerTupleFwd{
        offerSdp.connectionAddress,
        answerSdp.connectionAddress,
        offerSdp.mediaPort,
        answerSdp.mediaPort
    };
    // Callee → Caller: reverse
    FiveTuple calleeTupleFwd{
        answerSdp.connectionAddress,
        offerSdp.connectionAddress,
        answerSdp.mediaPort,
        offerSdp.mediaPort
    };

    tupleToCall_[callerTupleFwd] = {callId, "caller_to_callee"};
    tupleToCall_[calleeTupleFwd] = {callId, "callee_to_caller"};

    // Replay any buffered pending packets for these 5-tuples (FR-24)
    for (const auto& [tuple, callAndDir] : tupleToCall_) {
        if (callAndDir.first != callId) continue;
        auto it = pending_.find(tuple);
        if (it == pending_.end()) continue;

        for (const auto& pp : it->second) {
            // Ensure stats entry exists for this SSRC
            auto& stats = streams_[pp.hdr.ssrc];
            if (stats.ssrc == 0) {
                stats.ssrc      = pp.hdr.ssrc;
                stats.srcIp     = tuple.srcIp;
                stats.srcPort   = tuple.srcPort;
                stats.dstIp     = tuple.dstIp;
                stats.dstPort   = tuple.dstPort;
                stats.callId    = callId;
                stats.direction = callAndDir.second;
                stats.clockRateHz = offerSdp.clockRateHz;
            }
            processPacket(stats, pp.hdr, pp.arrivalTime);
        }
        pending_.erase(it);
    }
}

void RtpTracker::ingest(const UdpPacket& pkt, const RtpHeader& hdr) {
    FiveTuple key{pkt.srcIp, pkt.dstIp, pkt.srcPort, pkt.dstPort};

    auto it = tupleToCall_.find(key);
    if (it == tupleToCall_.end()) {
        // Buffer for late association (FR-24)
        auto& vec = pending_[key];
        if (vec.size() < kPendingCap) {
            vec.push_back({hdr, pkt.timestamp});
        }
        return;
    }

    const std::string& callId    = it->second.first;
    const std::string& direction = it->second.second;

    auto& stats = streams_[hdr.ssrc];
    if (stats.ssrc == 0) {
        stats.ssrc      = hdr.ssrc;
        stats.srcIp     = pkt.srcIp;
        stats.srcPort   = pkt.srcPort;
        stats.dstIp     = pkt.dstIp;
        stats.dstPort   = pkt.dstPort;
        stats.callId    = callId;
        stats.direction = direction;
        // clockRateHz will be set from SDP when available; default 8000
    }

    processPacket(stats, hdr, pkt.timestamp);
}

void RtpTracker::processPacket(RtpStreamStats& stats,
                                const RtpHeader& hdr,
                                std::chrono::system_clock::time_point arrivalTime) {
    // Sequence tracking (16-bit wraparound per RFC 3550 §A.1)
    if (!stats.seqInitialized) {
        stats.firstSeq     = hdr.sequenceNumber;
        stats.highestSeq   = hdr.sequenceNumber;
        stats.seqInitialized = true;
    } else {
        uint16_t diff = hdr.sequenceNumber - stats.highestSeq;
        if (diff > 0 && diff < 0x8000u) {
            stats.highestSeq = hdr.sequenceNumber;
        }
    }
    stats.receivedCount++;
    stats.lastArrival = arrivalTime;

    // Jitter computation: RFC 3550 §A.8
    // transit = arrivalTime_in_clock_units - rtp_timestamp
    auto arrivalNs = std::chrono::duration_cast<std::chrono::nanoseconds>(
                         arrivalTime.time_since_epoch()).count();
    // Convert nanoseconds to RTP clock units
    double arrivalUnits = static_cast<double>(arrivalNs) / 1e9 *
                          static_cast<double>(stats.clockRateHz);
    int64_t transit = static_cast<int64_t>(arrivalUnits) -
                      static_cast<int64_t>(hdr.timestamp);

    if (stats.hasTransit) {
        double d = std::abs(static_cast<double>(transit - stats.prevTransit));
        stats.jitter = stats.jitter + (d - stats.jitter) / 16.0;
        stats.jitterSum += stats.jitter;
    }
    stats.prevTransit = transit;
    stats.hasTransit  = true;
}

void RtpTracker::ingestRtcp(const RtcpReportBlock& block) {
    auto it = streams_.find(block.sourceSsrc);
    if (it == streams_.end()) return;
    it->second.rtcpCumulativeLost = block.cumulativeLost;
}

std::vector<RtpStreamStats> RtpTracker::getStreams(const std::string& callId) const {
    std::vector<RtpStreamStats> result;
    for (const auto& [ssrc, stats] : streams_) {
        if (stats.callId == callId) {
            result.push_back(stats);
        }
    }
    return result;
}

std::chrono::system_clock::time_point RtpTracker::lastArrivalForCall(
    const std::string& callId) const
{
    std::chrono::system_clock::time_point best{};
    for (const auto& [ssrc, stats] : streams_) {
        if (stats.callId == callId && stats.lastArrival > best) {
            best = stats.lastArrival;
        }
    }
    return best;
}

} // namespace voipscope
