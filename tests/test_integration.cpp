#include <gtest/gtest.h>

#include "sip/DialogManager.hpp"
#include "sip/SipParser.hpp"
#include "rtp/RtpTracker.hpp"
#include "rtp/RtpParser.hpp"
#include "pcap/PcapReader.hpp"
#include "output/CdrEmitter.hpp"

#include <fstream>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <vector>

using namespace voipscope;

// ---------------------------------------------------------------------------
// Inline pipeline integration test (no PCAP file required)
// ---------------------------------------------------------------------------
// We feed SIP messages and RTP packets directly through the pipeline and
// verify that CDRs are emitted correctly.
// ---------------------------------------------------------------------------

static std::chrono::system_clock::time_point T(double sec) {
    auto ns = static_cast<long long>(sec * 1e9);
    return std::chrono::system_clock::time_point(std::chrono::nanoseconds(ns));
}

static SipMessage buildSip(SipMethod method, int status,
                             const std::string& callId, uint32_t cseq,
                             SipMethod cseqMethod, double timeSec,
                             const std::string& branch,
                             std::optional<SdpInfo> sdp = std::nullopt)
{
    SipMessage msg;
    msg.callId      = callId;
    msg.from        = "<sip:alice@10.0.0.1>;tag=tag_a";
    msg.fromTag     = "tag_a";
    msg.to          = "<sip:bob@10.0.0.2>";
    msg.toTag       = (status == 200) ? "tag_b" : "";
    msg.cseqNumber  = cseq;
    msg.cseqMethod  = cseqMethod;
    msg.viaBranch   = branch;
    msg.captureTime = T(timeSec);
    msg.sdp         = std::move(sdp);
    if (status == 0) {
        msg.method     = method;
        msg.statusCode = 0;
    } else {
        msg.method     = SipMethod::Unknown;
        msg.statusCode = status;
    }
    return msg;
}

static SdpInfo sdpFor(const std::string& ip, uint16_t port,
                       const std::string& codec = "PCMU",
                       uint8_t pt = 0, uint32_t clockRate = 8000)
{
    SdpInfo s;
    s.connectionAddress = ip;
    s.mediaPort         = port;
    s.mediaType         = "audio";
    s.codecName         = codec;
    s.payloadType       = pt;
    s.clockRateHz       = clockRate;
    return s;
}

// Simulate N RTP packets from src→dst with given SSRC and constant timing
static void sendRtp(RtpTracker& tracker,
                    const std::string& srcIp, uint16_t srcPort,
                    const std::string& dstIp, uint16_t dstPort,
                    uint32_t ssrc, int count, double startSec)
{
    for (int i = 0; i < count; ++i) {
        UdpPacket pkt;
        pkt.srcIp   = srcIp;
        pkt.srcPort = srcPort;
        pkt.dstIp   = dstIp;
        pkt.dstPort = dstPort;
        pkt.timestamp = T(startSec + i * 0.020);

        RtpHeader hdr;
        hdr.version        = 2;
        hdr.ssrc           = ssrc;
        hdr.sequenceNumber = static_cast<uint16_t>(i);
        hdr.timestamp      = static_cast<uint32_t>(i * 160);
        hdr.payloadType    = 0;

        tracker.ingest(pkt, hdr);
    }
}

// ---------------------------------------------------------------------------
// Test: full happy-path pipeline (no PCAP, inline)
// ---------------------------------------------------------------------------

TEST(Integration, FullPipelineProducesCdr) {
    DialogManager mgr;
    RtpTracker    tracker;

    const std::string callId = "integration-test@10.0.0.1";

    // INVITE with offer SDP
    mgr.ingest(buildSip(SipMethod::INVITE, 0, callId, 1, SipMethod::INVITE,
                         0.0, "branch1",
                         sdpFor("10.0.0.1", 5004)),
               tracker);

    // 180 Ringing
    mgr.ingest(buildSip(SipMethod::Unknown, 180, callId, 1, SipMethod::INVITE,
                         0.5, "branch1"),
               tracker);

    // 200 OK with answer SDP
    mgr.ingest(buildSip(SipMethod::Unknown, 200, callId, 1, SipMethod::INVITE,
                         1.0, "branch1",
                         sdpFor("10.0.0.2", 5006)),
               tracker);

    // 100 RTP packets (caller → callee), 100 RTP packets (callee → caller)
    sendRtp(tracker, "10.0.0.1", 5004, "10.0.0.2", 5006, 0xAAAAAAAA, 100, 1.1);
    sendRtp(tracker, "10.0.0.2", 5006, "10.0.0.1", 5004, 0xBBBBBBBB, 100, 1.1);

    // BYE
    mgr.ingest(buildSip(SipMethod::BYE, 0, callId, 2, SipMethod::BYE,
                         3.1, "branch2"),
               tracker);

    auto cdrs = mgr.takeCompleted();
    ASSERT_EQ(cdrs.size(), 1u);

    const auto& cdr = cdrs[0];
    EXPECT_EQ(cdr.callId, callId);
    EXPECT_EQ(cdr.status, "complete");
    EXPECT_EQ(cdr.codec,  "PCMU");
    EXPECT_EQ(cdr.payloadType, 0);

    // Two streams should be correlated
    EXPECT_EQ(cdr.streams.size(), 2u);

    // Each stream should have low jitter and zero loss
    for (const auto& s : cdr.streams) {
        EXPECT_NEAR(s.lossPercent, 0.0, 0.1);
        EXPECT_LT(s.meanJitterMs, 1.0);
        EXPECT_GE(s.mos, 3.5);
        EXPECT_LE(s.mos, 4.5);
    }

    // Top-level MOS must be populated
    ASSERT_TRUE(cdr.mos.has_value());
    EXPECT_GE(*cdr.mos, 3.5);

    // CDR must serialise to valid JSON
    std::ostringstream oss;
    emitCdr(cdr, oss);
    auto j = nlohmann::json::parse(oss.str());
    EXPECT_TRUE(j.is_object());
    EXPECT_EQ(j["call_id"].get<std::string>(), callId);
    EXPECT_EQ(j["streams"].size(), 2u);
}

TEST(Integration, NoRtpDialogHasNullMos) {
    DialogManager mgr;
    RtpTracker    tracker;

    const std::string callId = "no-rtp@host";

    mgr.ingest(buildSip(SipMethod::INVITE, 0, callId, 1, SipMethod::INVITE,
                         0.0, "b1", sdpFor("10.0.0.1", 5004)), tracker);
    mgr.ingest(buildSip(SipMethod::Unknown, 200, callId, 1, SipMethod::INVITE,
                         1.0, "b1", sdpFor("10.0.0.2", 5006)), tracker);
    mgr.ingest(buildSip(SipMethod::BYE, 0, callId, 2, SipMethod::BYE,
                         10.0, "b2"), tracker);

    auto cdrs = mgr.takeCompleted();
    ASSERT_EQ(cdrs.size(), 1u);

    // No RTP was sent → mos should be null (CA-07)
    EXPECT_FALSE(cdrs[0].mos.has_value());

    std::ostringstream oss;
    emitCdr(cdrs[0], oss);
    auto j = nlohmann::json::parse(oss.str());
    EXPECT_TRUE(j["mos"].is_null());
}

TEST(Integration, IncompleteDialogAtEof) {
    DialogManager mgr;
    RtpTracker    tracker;

    const std::string callId = "incomplete@host";

    mgr.ingest(buildSip(SipMethod::INVITE, 0, callId, 1, SipMethod::INVITE,
                         0.0, "b1", sdpFor("10.0.0.1", 5004)), tracker);
    mgr.ingest(buildSip(SipMethod::Unknown, 200, callId, 1, SipMethod::INVITE,
                         1.0, "b1", sdpFor("10.0.0.2", 5006)), tracker);

    // EOF without BYE
    auto pending = mgr.takePending(T(60.0), tracker);
    ASSERT_EQ(pending.size(), 1u);
    EXPECT_EQ(pending[0].status, "incomplete");

    std::ostringstream oss;
    emitCdr(pending[0], oss);
    auto j = nlohmann::json::parse(oss.str());
    EXPECT_EQ(j["status"].get<std::string>(), "incomplete");
}

TEST(Integration, NdjsonEachLineValid) {
    DialogManager mgr;
    RtpTracker    tracker;

    // Create two separate calls
    for (int i = 0; i < 2; ++i) {
        std::string callId = "multi-call-" + std::to_string(i) + "@host";
        double base = i * 100.0;

        mgr.ingest(buildSip(SipMethod::INVITE, 0, callId, 1, SipMethod::INVITE,
                             base, "b1_" + std::to_string(i),
                             sdpFor("10.0.0.1", static_cast<uint16_t>(5004 + i*4))),
                   tracker);
        mgr.ingest(buildSip(SipMethod::Unknown, 200, callId, 1, SipMethod::INVITE,
                             base + 1.0, "b1_" + std::to_string(i),
                             sdpFor("10.0.0.2", static_cast<uint16_t>(5006 + i*4))),
                   tracker);
        mgr.ingest(buildSip(SipMethod::BYE, 0, callId, 2, SipMethod::BYE,
                             base + 30.0, "b2_" + std::to_string(i)),
                   tracker);
    }

    auto cdrs = mgr.takeCompleted();
    ASSERT_EQ(cdrs.size(), 2u);

    std::ostringstream oss;
    for (const auto& cdr : cdrs) emitCdr(cdr, oss);

    std::string output = oss.str();
    std::istringstream iss(output);
    std::string line;
    int count = 0;
    while (std::getline(iss, line)) {
        if (line.empty()) continue;
        auto j = nlohmann::json::parse(line); // throws if invalid
        EXPECT_TRUE(j.is_object());
        ++count;
    }
    EXPECT_EQ(count, 2);
}

// ---------------------------------------------------------------------------
// PCAP-file-based integration test using a synthesised PCAP
// ---------------------------------------------------------------------------

namespace {

// Write an integer in little-endian byte order to a vector.
void writeLE32(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(x & 0xFFu);
    v.push_back((x >> 8)  & 0xFFu);
    v.push_back((x >> 16) & 0xFFu);
    v.push_back((x >> 24) & 0xFFu);
}
void writeLE16(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back(x & 0xFFu);
    v.push_back((x >> 8)  & 0xFFu);
}
void writeBE16(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back((x >> 8)  & 0xFFu);
    v.push_back(x & 0xFFu);
}

// Build an Ethernet II / IPv4 / UDP packet around `payload`.
std::vector<uint8_t> makeUdpFrame(
    const std::array<uint8_t,4>& srcIp, uint16_t srcPort,
    const std::array<uint8_t,4>& dstIp, uint16_t dstPort,
    const std::vector<uint8_t>& payload)
{
    std::vector<uint8_t> frame;

    // Ethernet header (14 bytes): dst MAC, src MAC, EtherType 0x0800
    for (int i = 0; i < 6; i++) frame.push_back(0xFF); // dst = broadcast
    const uint8_t srcMac[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    for (auto b : srcMac) frame.push_back(b);
    frame.push_back(0x08); frame.push_back(0x00); // IPv4

    // IPv4 header (20 bytes)
    uint16_t ipTotalLen = static_cast<uint16_t>(20 + 8 + payload.size());
    frame.push_back(0x45);             // version=4, IHL=5
    frame.push_back(0x00);             // DSCP/ECN
    writeBE16(frame, ipTotalLen);      // total length
    writeBE16(frame, 0x0001);          // ID
    writeBE16(frame, 0x4000);          // flags=DF, fragment offset=0
    frame.push_back(64);               // TTL
    frame.push_back(17);               // protocol = UDP
    writeBE16(frame, 0x0000);          // checksum (0 = ignored by pcap_next_ex)
    for (auto b : srcIp) frame.push_back(b);
    for (auto b : dstIp) frame.push_back(b);

    // UDP header (8 bytes)
    uint16_t udpLen = static_cast<uint16_t>(8 + payload.size());
    writeBE16(frame, srcPort);
    writeBE16(frame, dstPort);
    writeBE16(frame, udpLen);
    writeBE16(frame, 0x0000); // checksum (ignored)

    // Payload
    frame.insert(frame.end(), payload.begin(), payload.end());
    return frame;
}

// Build a minimal SIP INVITE payload (SDP offer)
std::vector<uint8_t> makeSipInvite(const std::string& callId) {
    std::string sdp =
        "v=0\r\n"
        "o=alice 1 1 IN IP4 10.0.0.1\r\n"
        "s=Test\r\n"
        "c=IN IP4 10.0.0.1\r\n"
        "t=0 0\r\n"
        "m=audio 5004 RTP/AVP 0\r\n"
        "a=rtpmap:0 PCMU/8000\r\n";
    std::string msg =
        "INVITE sip:bob@10.0.0.2 SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKpcap1\r\n"
        "From: <sip:alice@10.0.0.1>;tag=pcap_a\r\n"
        "To: <sip:bob@10.0.0.2>\r\n"
        "Call-ID: " + callId + "\r\n"
        "CSeq: 1 INVITE\r\n"
        "Contact: <sip:alice@10.0.0.1:5060>\r\n"
        "Content-Type: application/sdp\r\n"
        "Content-Length: " + std::to_string(sdp.size()) + "\r\n"
        "\r\n" + sdp;
    return {msg.begin(), msg.end()};
}

// Build a 200 OK with SDP answer
std::vector<uint8_t> makeSip200Ok(const std::string& callId) {
    std::string sdp =
        "v=0\r\n"
        "o=bob 2 2 IN IP4 10.0.0.2\r\n"
        "s=Test\r\n"
        "c=IN IP4 10.0.0.2\r\n"
        "t=0 0\r\n"
        "m=audio 5006 RTP/AVP 0\r\n"
        "a=rtpmap:0 PCMU/8000\r\n";
    std::string msg =
        "SIP/2.0 200 OK\r\n"
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKpcap1\r\n"
        "From: <sip:alice@10.0.0.1>;tag=pcap_a\r\n"
        "To: <sip:bob@10.0.0.2>;tag=pcap_b\r\n"
        "Call-ID: " + callId + "\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Type: application/sdp\r\n"
        "Content-Length: " + std::to_string(sdp.size()) + "\r\n"
        "\r\n" + sdp;
    return {msg.begin(), msg.end()};
}

// Build a SIP BYE
std::vector<uint8_t> makeSipBye(const std::string& callId) {
    std::string msg =
        "BYE sip:alice@10.0.0.1 SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bKpcap2\r\n"
        "From: <sip:bob@10.0.0.2>;tag=pcap_b\r\n"
        "To: <sip:alice@10.0.0.1>;tag=pcap_a\r\n"
        "Call-ID: " + callId + "\r\n"
        "CSeq: 2 BYE\r\n"
        "Content-Length: 0\r\n"
        "\r\n";
    return {msg.begin(), msg.end()};
}

// Build a minimal RTP packet (12-byte header + 4 bytes G.711 silence)
std::vector<uint8_t> makeRtpPacket(uint32_t ssrc, uint16_t seq, uint32_t ts) {
    std::vector<uint8_t> pkt(16);
    pkt[0]  = 0x80;                    // version=2
    pkt[1]  = 0x00;                    // marker=0, PT=0 (PCMU)
    pkt[2]  = (seq >> 8)  & 0xFF;
    pkt[3]  = seq & 0xFF;
    pkt[4]  = (ts >> 24)  & 0xFF;
    pkt[5]  = (ts >> 16)  & 0xFF;
    pkt[6]  = (ts >> 8)   & 0xFF;
    pkt[7]  = ts & 0xFF;
    pkt[8]  = (ssrc >> 24) & 0xFF;
    pkt[9]  = (ssrc >> 16) & 0xFF;
    pkt[10] = (ssrc >> 8)  & 0xFF;
    pkt[11] = ssrc & 0xFF;
    // 4 bytes of G.711 µ-law silence (0xFF)
    pkt[12] = pkt[13] = pkt[14] = pkt[15] = 0xFF;
    return pkt;
}

// Build a complete synthetic PCAP (global header + packets)
std::vector<uint8_t> buildSyntheticPcap(const std::string& callId) {
    std::vector<uint8_t> pcap;

    // Global PCAP header (24 bytes, little-endian)
    writeLE32(pcap, 0xa1b2c3d4u); // magic (native LE: d4 c3 b2 a1)
    writeLE16(pcap, 2);            // version major
    writeLE16(pcap, 4);            // version minor
    writeLE32(pcap, 0);            // timezone correction
    writeLE32(pcap, 0);            // timestamp accuracy
    writeLE32(pcap, 65535);        // snaplen
    writeLE32(pcap, 1);            // link-layer type: LINKTYPE_ETHERNET

    constexpr std::array<uint8_t,4> alice = {10,0,0,1};
    constexpr std::array<uint8_t,4> bob   = {10,0,0,2};

    // Helper: append a full UDP PCAP record with microsecond-precision timestamp
    auto addPacketUs = [&](uint32_t sec, uint32_t usec,
                           const std::array<uint8_t,4>& srcIp, uint16_t srcPort,
                           const std::array<uint8_t,4>& dstIp, uint16_t dstPort,
                           const std::vector<uint8_t>& payload)
    {
        auto frame = makeUdpFrame(srcIp, srcPort, dstIp, dstPort, payload);
        writeLE32(pcap, sec);
        writeLE32(pcap, usec);
        writeLE32(pcap, static_cast<uint32_t>(frame.size()));
        writeLE32(pcap, static_cast<uint32_t>(frame.size()));
        pcap.insert(pcap.end(), frame.begin(), frame.end());
    };

    // t=0: INVITE from Alice
    addPacketUs(1000, 0, alice, 5060, bob, 5060, makeSipInvite(callId));

    // t=1: 200 OK from Bob with SDP answer
    addPacketUs(1001, 0, bob, 5060, alice, 5060, makeSip200Ok(callId));

    // t=2..2.18s: 10 RTP packets at 20ms intervals (matching 8kHz/160-unit step)
    // Arrival interval = 20ms = 20000 µs; RTP timestamp step = 160 units
    // → constant transit → zero jitter (MOS near maximum for PCMU)
    for (int i = 0; i < 10; i++) {
        uint32_t sec  = 1002 + (i * 20000) / 1000000u;
        uint32_t usec = (i * 20000u) % 1000000u;
        addPacketUs(sec, usec, alice, 5004, bob, 5006,
                    makeRtpPacket(0xAAAA0001u, static_cast<uint16_t>(i),
                                  static_cast<uint32_t>(i * 160)));
    }
    for (int i = 0; i < 10; i++) {
        uint32_t sec  = 1002 + (i * 20000) / 1000000u;
        uint32_t usec = (i * 20000u) % 1000000u;
        addPacketUs(sec, usec, bob, 5006, alice, 5004,
                    makeRtpPacket(0xBBBB0001u, static_cast<uint16_t>(i),
                                  static_cast<uint32_t>(i * 160)));
    }

    // t=5: BYE from Bob
    addPacketUs(1005, 0, bob, 5060, alice, 5060, makeSipBye(callId));

    return pcap;
}

// Write data to a temp file and return its path.
std::string writeTempFile(const std::vector<uint8_t>& data) {
    std::string path = std::string(std::getenv("TMPDIR") ? std::getenv("TMPDIR")
                                                         : "/tmp")
                       + "/voipscope_test_XXXXXX.pcap";
    // Use mkstemp-style logic via a fixed known path
    path = std::string(std::getenv("TMPDIR") ? std::getenv("TMPDIR") : "/tmp")
           + "/voipscope_synthetic_test.pcap";
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return {};
    f.write(reinterpret_cast<const char*>(data.data()),
            static_cast<std::streamsize>(data.size()));
    return path;
}

} // namespace

TEST(Integration, SyntheticPcapProducesCdr) {
    // Build and write a minimal synthetic PCAP to a temp file
    const std::string callId = "synthetic-pcap-001@10.0.0.1";
    auto pcapData = buildSyntheticPcap(callId);
    std::string pcapPath = writeTempFile(pcapData);
    ASSERT_FALSE(pcapPath.empty()) << "Failed to write temp PCAP file";

    // Run the full pipeline through PcapReader (AC-03)
    voipscope::DialogManager mgr;
    voipscope::RtpTracker    tracker;
    std::chrono::system_clock::time_point lastTs;

    {
        voipscope::PcapReader reader(pcapPath);
        while (auto pktOpt = reader.next()) {
            auto& pkt = *pktOpt;
            lastTs = pkt.timestamp;
            std::span<const uint8_t> payload(pkt.payload);

            // SIP heuristic
            if (!payload.empty()) {
                std::string_view sv(
                    reinterpret_cast<const char*>(payload.data()), payload.size());
                if (sv.starts_with("INVITE ") || sv.starts_with("BYE ")  ||
                    sv.starts_with("SIP/2.0")) {
                    auto msgOpt = voipscope::parseSip(sv);
                    if (msgOpt) {
                        msgOpt->srcIp       = pkt.srcIp;
                        msgOpt->srcPort     = pkt.srcPort;
                        msgOpt->dstIp       = pkt.dstIp;
                        msgOpt->dstPort     = pkt.dstPort;
                        msgOpt->captureTime = pkt.timestamp;
                        mgr.ingest(*msgOpt, tracker);
                    }
                }
                // RTP heuristic: version=2 in bits 7:6
                else if (payload.size() >= 12 && (payload[0] >> 6) == 2) {
                    auto hdrOpt = voipscope::parseRtp(payload);
                    if (hdrOpt) tracker.ingest(pkt, *hdrOpt);
                }
            }
        }
    }

    // Flush completed dialogs
    auto cdrs = mgr.takeCompleted();
    // Also flush any pending (incomplete) if needed
    auto pending = mgr.takePending(lastTs, tracker);
    cdrs.insert(cdrs.end(), pending.begin(), pending.end());

    ASSERT_GE(cdrs.size(), 1u) << "Expected at least one CDR";

    // Find the CDR for our call
    const voipscope::Cdr* found = nullptr;
    for (const auto& c : cdrs) {
        if (c.callId == callId) { found = &c; break; }
    }
    ASSERT_NE(found, nullptr) << "CDR for call-id '" << callId << "' not found";

    EXPECT_EQ(found->status, "complete");
    EXPECT_EQ(found->codec,  "PCMU");

    // Two RTP streams should be correlated
    EXPECT_EQ(found->streams.size(), 2u);
    for (const auto& s : found->streams) {
        EXPECT_NEAR(s.lossPercent, 0.0, 0.5);
        EXPECT_GE(s.mos, 3.5);
    }

    // NDJSON output must be valid JSON (AC-03)
    std::ostringstream oss;
    voipscope::emitCdr(*found, oss);
    auto j = nlohmann::json::parse(oss.str());
    EXPECT_TRUE(j.is_object());
    EXPECT_EQ(j["call_id"].get<std::string>(), callId);
    EXPECT_EQ(j["codec"].get<std::string>(),  "PCMU");
}

