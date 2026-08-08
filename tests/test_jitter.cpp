#include <gtest/gtest.h>

#include "rtp/RtpTracker.hpp"
#include "pcap/PcapReader.hpp"

using namespace voipscope;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Build a minimal UdpPacket + RtpHeader pair for testing
static UdpPacket makeUdpPkt(std::chrono::system_clock::time_point ts) {
    UdpPacket pkt;
    pkt.timestamp = ts;
    pkt.srcIp = "10.0.0.1";
    pkt.srcPort = 5004;
    pkt.dstIp = "10.0.0.2";
    pkt.dstPort = 5006;
    return pkt;
}

static RtpHeader makeRtpHdr(uint32_t ssrc, uint16_t seq, uint32_t ts) {
    RtpHeader hdr;
    hdr.version        = 2;
    hdr.ssrc           = ssrc;
    hdr.sequenceNumber = seq;
    hdr.timestamp      = ts;
    hdr.payloadType    = 0;
    return hdr;
}

static std::chrono::system_clock::time_point timeAt(double seconds) {
    auto ns = static_cast<long long>(seconds * 1e9);
    return std::chrono::system_clock::time_point(std::chrono::nanoseconds(ns));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

TEST(Jitter, ZeroJitterConstantInterval) {
    // G.711 at 20 ms ptime: 160 RTP units per packet, 20 ms wall clock interval
    RtpTracker tracker;
    SdpInfo offer, answer;
    offer.connectionAddress = "10.0.0.1"; offer.mediaPort = 5004; offer.clockRateHz = 8000;
    answer.connectionAddress = "10.0.0.2"; answer.mediaPort = 5006; answer.clockRateHz = 8000;
    tracker.associate("call1", offer, answer);

    constexpr int kPackets = 50;
    // Arrival: exactly 20 ms apart
    // RTP timestamp: exactly 160 units apart
    for (int i = 0; i < kPackets; ++i) {
        double arrivalSec = 1700000000.0 + i * 0.020;
        auto pkt = makeUdpPkt(timeAt(arrivalSec));
        pkt.srcIp = "10.0.0.1"; pkt.srcPort = 5004;
        pkt.dstIp = "10.0.0.2"; pkt.dstPort = 5006;
        auto hdr = makeRtpHdr(0xCAFEBABE,
                               static_cast<uint16_t>(i),
                               static_cast<uint32_t>(i * 160));
        tracker.ingest(pkt, hdr);
    }

    auto streams = tracker.getStreams("call1");
    ASSERT_EQ(streams.size(), 1u);
    EXPECT_NEAR(streams[0].meanJitterMs(), 0.0, 0.05); // effectively zero
}

TEST(Jitter, JitterGrowsWithVariableInterval) {
    RtpTracker tracker;
    SdpInfo offer, answer;
    offer.connectionAddress = "10.0.0.1"; offer.mediaPort = 5004; offer.clockRateHz = 8000;
    answer.connectionAddress = "10.0.0.2"; answer.mediaPort = 5006; answer.clockRateHz = 8000;
    tracker.associate("call2", offer, answer);

    // Alternating 10 ms and 30 ms arrival intervals, constant RTP timestamp step
    constexpr int kPackets = 40;
    double arrivalSec = 1700000000.0;
    for (int i = 0; i < kPackets; ++i) {
        arrivalSec += (i % 2 == 0) ? 0.010 : 0.030;
        auto pkt = makeUdpPkt(timeAt(arrivalSec));
        pkt.srcIp = "10.0.0.1"; pkt.srcPort = 5004;
        pkt.dstIp = "10.0.0.2"; pkt.dstPort = 5006;
        auto hdr = makeRtpHdr(0xBEEF0001,
                               static_cast<uint16_t>(i),
                               static_cast<uint32_t>(i * 160)); // constant RTP step
        tracker.ingest(pkt, hdr);
    }

    auto streams = tracker.getStreams("call2");
    ASSERT_EQ(streams.size(), 1u);
    EXPECT_GT(streams[0].meanJitterMs(), 5.0); // should be significant
}

TEST(Jitter, SequenceWrapAround) {
    RtpTracker tracker;
    SdpInfo offer, answer;
    offer.connectionAddress = "10.0.0.1"; offer.mediaPort = 5004; offer.clockRateHz = 8000;
    answer.connectionAddress = "10.0.0.2"; answer.mediaPort = 5006; answer.clockRateHz = 8000;
    tracker.associate("call3", offer, answer);

    // Packets around the 16-bit wraparound: 65533, 65534, 65535, 0, 1, 2
    std::vector<uint16_t> seqs = {65533, 65534, 65535, 0, 1, 2};
    double arrivalSec = 1700000000.0;
    for (std::size_t i = 0; i < seqs.size(); ++i) {
        arrivalSec += 0.020;
        auto pkt = makeUdpPkt(timeAt(arrivalSec));
        pkt.srcIp = "10.0.0.1"; pkt.srcPort = 5004;
        pkt.dstIp = "10.0.0.2"; pkt.dstPort = 5006;
        auto hdr = makeRtpHdr(0xDEADBEEFu,
                               seqs[i],
                               static_cast<uint32_t>(i * 160));
        tracker.ingest(pkt, hdr);
    }

    auto streams = tracker.getStreams("call3");
    ASSERT_EQ(streams.size(), 1u);
    // Expected count = (highestSeq - firstSeq + 1) in 16-bit unsigned = 6
    EXPECT_NEAR(streams[0].lossPercent(), 0.0, 0.01);
}

TEST(Jitter, SinglePacket) {
    RtpTracker tracker;
    SdpInfo offer, answer;
    offer.connectionAddress = "10.0.0.1"; offer.mediaPort = 5004; offer.clockRateHz = 8000;
    answer.connectionAddress = "10.0.0.2"; answer.mediaPort = 5006; answer.clockRateHz = 8000;
    tracker.associate("call4", offer, answer);

    auto pkt = makeUdpPkt(timeAt(1700000000.0));
    pkt.srcIp = "10.0.0.1"; pkt.srcPort = 5004;
    pkt.dstIp = "10.0.0.2"; pkt.dstPort = 5006;
    tracker.ingest(pkt, makeRtpHdr(0x12345678, 0, 0));

    auto streams = tracker.getStreams("call4");
    ASSERT_EQ(streams.size(), 1u);
    EXPECT_NEAR(streams[0].meanJitterMs(), 0.0, 0.001);
    EXPECT_NEAR(streams[0].lossPercent(), 0.0, 0.001);
}
