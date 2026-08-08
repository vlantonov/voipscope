#include <gtest/gtest.h>

#include "sip/DialogManager.hpp"
#include "sip/SipParser.hpp"
#include "rtp/RtpTracker.hpp"

using namespace voipscope;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static std::chrono::system_clock::time_point makeTime(int offsetSec) {
    return std::chrono::system_clock::time_point(
        std::chrono::seconds(1700000000 + offsetSec));
}

static SipMessage makeMsg(SipMethod method,
                           int statusCode,
                           const std::string& callId,
                           uint32_t cseq,
                           SipMethod cseqMethod,
                           int offsetSec = 0,
                           const std::string& branch = "z9hG4bK1",
                           std::optional<SdpInfo> sdp = std::nullopt)
{
    SipMessage msg;
    msg.callId      = callId;
    msg.from        = "<sip:alice@example.com>;tag=atag";
    msg.fromTag     = "atag";
    msg.to          = "<sip:bob@example.com>";
    msg.toTag       = (statusCode == 200) ? "btag" : "";
    msg.cseqNumber  = cseq;
    msg.cseqMethod  = cseqMethod;
    msg.viaBranch   = branch;
    msg.captureTime = makeTime(offsetSec);
    msg.sdp         = std::move(sdp);

    if (statusCode == 0) {
        msg.method     = method;
        msg.statusCode = 0;
    } else {
        msg.method     = SipMethod::Unknown;
        msg.statusCode = statusCode;
    }
    return msg;
}

static SdpInfo makeSdp(const std::string& ip, uint16_t port) {
    SdpInfo sdp;
    sdp.connectionAddress = ip;
    sdp.mediaPort         = port;
    sdp.mediaType         = "audio";
    sdp.codecName         = "PCMU";
    sdp.payloadType       = 0;
    sdp.clockRateHz       = 8000;
    return sdp;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

TEST(DialogFsm, HappyPath) {
    DialogManager mgr;
    RtpTracker    tracker;

    auto invite = makeMsg(SipMethod::INVITE, 0, "call1", 1, SipMethod::INVITE,
                          0, "branch1", makeSdp("10.0.0.1", 5004));
    mgr.ingest(invite, tracker);
    EXPECT_TRUE(mgr.takeCompleted().empty());

    auto ringing = makeMsg(SipMethod::Unknown, 180, "call1", 1, SipMethod::INVITE, 1);
    mgr.ingest(ringing, tracker);
    EXPECT_TRUE(mgr.takeCompleted().empty());

    auto ok200 = makeMsg(SipMethod::Unknown, 200, "call1", 1, SipMethod::INVITE,
                         2, "branch1", makeSdp("10.0.0.2", 5006));
    mgr.ingest(ok200, tracker);
    EXPECT_TRUE(mgr.takeCompleted().empty()); // BYE not yet

    auto bye = makeMsg(SipMethod::BYE, 0, "call1", 2, SipMethod::BYE, 60);
    mgr.ingest(bye, tracker);

    auto cdrs = mgr.takeCompleted();
    ASSERT_EQ(cdrs.size(), 1u);
    EXPECT_EQ(cdrs[0].callId,  "call1");
    EXPECT_EQ(cdrs[0].status,  "complete");
    EXPECT_EQ(cdrs[0].codec,   "PCMU");
}

TEST(DialogFsm, UnansweredCall486) {
    DialogManager mgr;
    RtpTracker    tracker;

    mgr.ingest(makeMsg(SipMethod::INVITE, 0, "call2", 1, SipMethod::INVITE, 0), tracker);
    mgr.ingest(makeMsg(SipMethod::Unknown, 180, "call2", 1, SipMethod::INVITE, 1), tracker);
    mgr.ingest(makeMsg(SipMethod::Unknown, 486, "call2", 1, SipMethod::INVITE, 2), tracker);

    // Failed/rejected call: no CDR (FR-40)
    EXPECT_TRUE(mgr.takeCompleted().empty());
    EXPECT_TRUE(mgr.takePending(makeTime(5), tracker).empty());
}

TEST(DialogFsm, NoProvisionalDirectEstablished) {
    DialogManager mgr;
    RtpTracker    tracker;

    mgr.ingest(makeMsg(SipMethod::INVITE, 0, "call3", 1, SipMethod::INVITE,
                        0, "b1", makeSdp("10.0.0.1", 5004)), tracker);
    mgr.ingest(makeMsg(SipMethod::Unknown, 200, "call3", 1, SipMethod::INVITE,
                        1, "b1", makeSdp("10.0.0.2", 5006)), tracker);
    mgr.ingest(makeMsg(SipMethod::BYE, 0, "call3", 2, SipMethod::BYE, 30), tracker);

    auto cdrs = mgr.takeCompleted();
    ASSERT_EQ(cdrs.size(), 1u);
    EXPECT_EQ(cdrs[0].status, "complete");
}

TEST(DialogFsm, CallCancel) {
    DialogManager mgr;
    RtpTracker    tracker;

    mgr.ingest(makeMsg(SipMethod::INVITE, 0, "call4", 1, SipMethod::INVITE, 0), tracker);
    mgr.ingest(makeMsg(SipMethod::CANCEL, 0, "call4", 1, SipMethod::CANCEL, 1), tracker);

    // CANCEL before ESTABLISHED → no CDR (FR-40)
    EXPECT_TRUE(mgr.takeCompleted().empty());
}

TEST(DialogFsm, ReInvite) {
    DialogManager mgr;
    RtpTracker    tracker;

    mgr.ingest(makeMsg(SipMethod::INVITE, 0, "call5", 1, SipMethod::INVITE,
                        0, "b1", makeSdp("10.0.0.1", 5004)), tracker);
    mgr.ingest(makeMsg(SipMethod::Unknown, 200, "call5", 1, SipMethod::INVITE,
                        1, "b1", makeSdp("10.0.0.2", 5006)), tracker);

    // Re-INVITE with updated SDP
    mgr.ingest(makeMsg(SipMethod::INVITE, 0, "call5", 2, SipMethod::INVITE,
                        30, "b2", makeSdp("10.0.0.1", 5010)), tracker);
    mgr.ingest(makeMsg(SipMethod::Unknown, 200, "call5", 2, SipMethod::INVITE,
                        31, "b2", makeSdp("10.0.0.2", 5012)), tracker);

    // Still only one dialog (no duplicate)
    EXPECT_TRUE(mgr.takeCompleted().empty()); // no BYE yet

    mgr.ingest(makeMsg(SipMethod::BYE, 0, "call5", 3, SipMethod::BYE, 60), tracker);

    auto cdrs = mgr.takeCompleted();
    ASSERT_EQ(cdrs.size(), 1u); // exactly one CDR (FR-16)
    EXPECT_EQ(cdrs[0].callId, "call5");
}

TEST(DialogFsm, Retransmission) {
    DialogManager mgr;
    RtpTracker    tracker;

    // Same branch + CSeq → retransmission
    auto inv = makeMsg(SipMethod::INVITE, 0, "call6", 1, SipMethod::INVITE, 0, "samebrach");
    mgr.ingest(inv, tracker);
    mgr.ingest(inv, tracker); // duplicate
    mgr.ingest(inv, tracker); // duplicate again

    // Only one dialog should exist; sending BYE should yield exactly one CDR
    mgr.ingest(makeMsg(SipMethod::Unknown, 200, "call6", 1, SipMethod::INVITE,
                        1, "samebrach"), tracker);
    mgr.ingest(makeMsg(SipMethod::BYE, 0, "call6", 2, SipMethod::BYE, 10), tracker);

    auto cdrs = mgr.takeCompleted();
    ASSERT_EQ(cdrs.size(), 1u);
}

TEST(DialogFsm, IncompleteAtEof) {
    DialogManager mgr;
    RtpTracker    tracker;

    mgr.ingest(makeMsg(SipMethod::INVITE, 0, "call7", 1, SipMethod::INVITE,
                        0, "b1", makeSdp("10.0.0.1", 5004)), tracker);
    mgr.ingest(makeMsg(SipMethod::Unknown, 200, "call7", 1, SipMethod::INVITE,
                        1, "b1", makeSdp("10.0.0.2", 5006)), tracker);

    // EOF — no BYE seen
    auto pending = mgr.takePending(makeTime(120), tracker);
    ASSERT_EQ(pending.size(), 1u);
    EXPECT_EQ(pending[0].callId, "call7");
    EXPECT_EQ(pending[0].status, "incomplete");
}

TEST(DialogFsm, TryingAtEof) {
    DialogManager mgr;
    RtpTracker    tracker;

    // INVITE → 180, no 200 OK → EOF → no CDR (FR-40 / §6.4)
    mgr.ingest(makeMsg(SipMethod::INVITE, 0, "call8", 1, SipMethod::INVITE, 0), tracker);
    mgr.ingest(makeMsg(SipMethod::Unknown, 180, "call8", 1, SipMethod::INVITE, 1), tracker);

    auto pending = mgr.takePending(makeTime(30), tracker);
    EXPECT_TRUE(pending.empty());
    EXPECT_TRUE(mgr.takeCompleted().empty());
}
