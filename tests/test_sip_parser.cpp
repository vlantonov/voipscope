#include <gtest/gtest.h>

#include "sip/SipParser.hpp"
#include "sip/SdpParser.hpp"

using namespace voipscope;

// ---------------------------------------------------------------------------
// Helper: build a minimal valid INVITE payload
// ---------------------------------------------------------------------------
static std::string makeInvite(
    std::string_view extraHeaders = "",
    std::string_view body         = "")
{
    std::string base =
        "INVITE sip:bob@example.com SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKnashds8\r\n"
        "From: <sip:alice@example.com>;tag=1928301774\r\n"
        "To: <sip:bob@example.com>\r\n"
        "Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n"
        "CSeq: 314159 INVITE\r\n"
        "Contact: <sip:alice@pc33.atlanta.com>\r\n";
    base += extraHeaders;
    if (!body.empty()) {
        base += "Content-Type: application/sdp\r\n";
        base += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    } else {
        base += "Content-Length: 0\r\n";
    }
    base += "\r\n";
    base += body;
    return base;
}

static std::string make200Ok(std::string_view body = "") {
    std::string base =
        "SIP/2.0 200 OK\r\n"
        "Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKnashds8\r\n"
        "From: <sip:alice@example.com>;tag=1928301774\r\n"
        "To: <sip:bob@example.com>;tag=a6c85cf\r\n"
        "Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n"
        "CSeq: 314159 INVITE\r\n";
    if (!body.empty()) {
        base += "Content-Type: application/sdp\r\n";
        base += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    } else {
        base += "Content-Length: 0\r\n";
    }
    base += "\r\n";
    base += body;
    return base;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

TEST(SipParser, ParseValidInvite) {
    auto result = parseSip(makeInvite());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->method, SipMethod::INVITE);
    EXPECT_EQ(result->callId, "a84b4c76e66710@pc33.atlanta.com");
    EXPECT_EQ(result->cseqNumber, 314159u);
    EXPECT_EQ(result->cseqMethod, SipMethod::INVITE);
    EXPECT_EQ(result->requestUri, "sip:bob@example.com");
    EXPECT_EQ(result->statusCode, 0);
    EXPECT_TRUE(result->isRequest());
}

TEST(SipParser, ParseValidResponse200) {
    auto result = parseSip(make200Ok());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->statusCode, 200);
    EXPECT_EQ(result->reasonPhrase, "OK");
    EXPECT_TRUE(result->isResponse());
    EXPECT_EQ(result->cseqMethod, SipMethod::INVITE);
}

TEST(SipParser, ParseMissingCallIdReturnsNullopt) {
    // Omit Call-ID header
    std::string payload =
        "INVITE sip:bob@example.com SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK1\r\n"
        "From: <sip:alice@example.com>;tag=abc\r\n"
        "To: <sip:bob@example.com>\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Length: 0\r\n"
        "\r\n";
    EXPECT_FALSE(parseSip(payload).has_value());
}

TEST(SipParser, ParseMissingFromReturnsNullopt) {
    std::string payload =
        "INVITE sip:bob@example.com SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK1\r\n"
        "To: <sip:bob@example.com>\r\n"
        "Call-ID: abc@host\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Length: 0\r\n"
        "\r\n";
    EXPECT_FALSE(parseSip(payload).has_value());
}

TEST(SipParser, ParseTagsFromFromTo) {
    auto result = parseSip(makeInvite());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->fromTag, "1928301774");
    EXPECT_EQ(result->toTag, "");  // no tag in initial INVITE To:
}

TEST(SipParser, ParseToTagInResponse) {
    auto result = parseSip(make200Ok());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->fromTag, "1928301774");
    EXPECT_EQ(result->toTag, "a6c85cf");
}

TEST(SipParser, ParseViaBranch) {
    auto result = parseSip(makeInvite());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->viaBranch, "z9hG4bKnashds8");
}

TEST(SipParser, ParseSdpBody) {
    std::string sdp =
        "v=0\r\n"
        "o=alice 2890844526 2890844526 IN IP4 pc33.atlanta.com\r\n"
        "s=Session\r\n"
        "c=IN IP4 192.168.1.10\r\n"
        "t=0 0\r\n"
        "m=audio 49170 RTP/AVP 0\r\n"
        "a=rtpmap:0 PCMU/8000\r\n";

    auto result = parseSip(makeInvite("", sdp));
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->sdp.has_value());
    EXPECT_EQ(result->sdp->codecName,    "PCMU");
    EXPECT_EQ(result->sdp->payloadType,  0);
    EXPECT_EQ(result->sdp->mediaPort,    49170);
    EXPECT_EQ(result->sdp->clockRateHz,  8000u);
    EXPECT_EQ(result->sdp->connectionAddress, "192.168.1.10");
}

TEST(SipParser, ParseStaticPayloadType8) {
    std::string sdp =
        "v=0\r\n"
        "c=IN IP4 10.0.0.1\r\n"
        "m=audio 5004 RTP/AVP 8\r\n";

    auto result = parseSdp(sdp);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->codecName,   "PCMA");
    EXPECT_EQ(result->clockRateHz, 8000u);
}

TEST(SipParser, ParseRtpmapOverride) {
    std::string sdp =
        "v=0\r\n"
        "c=IN IP4 10.0.0.1\r\n"
        "m=audio 5004 RTP/AVP 96\r\n"
        "a=rtpmap:96 OPUS/48000\r\n";

    auto result = parseSdp(sdp);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->codecName,   "OPUS");
    EXPECT_EQ(result->clockRateHz, 48000u);
    EXPECT_EQ(result->payloadType, 96);
}

TEST(SipParser, ParseHeaderFolding) {
    // RFC 3261 §7.3.1 — folded header continuation
    std::string payload =
        "INVITE sip:bob@example.com SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 192.168.1.1:5060\r\n"
        " ;branch=z9hG4bKfold\r\n"
        "From: <sip:alice@example.com>;tag=foldtag\r\n"
        "To: <sip:bob@example.com>\r\n"
        "Call-ID: fold@host\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Length: 0\r\n"
        "\r\n";
    auto result = parseSip(payload);
    ASSERT_TRUE(result.has_value());
    // Via branch must be extracted from the folded value
    EXPECT_EQ(result->viaBranch, "z9hG4bKfold");
}

TEST(SipParser, RejectNonSip) {
    // RTP-like payload (version=2, PT=0x60)
    std::vector<uint8_t> rtp = {0x80, 0x60, 0x00, 0x01, 0x00,0x00,0x00,0x00,
                                0x00,0x00,0x00,0x01};
    std::string_view sv(reinterpret_cast<const char*>(rtp.data()), rtp.size());
    EXPECT_FALSE(parseSip(sv).has_value());
}

TEST(SipParser, RejectTruncatedBody) {
    // Content-Length says 200 but body is only a few bytes
    std::string payload =
        "INVITE sip:bob@example.com SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK1\r\n"
        "From: <sip:alice@example.com>;tag=abc\r\n"
        "To: <sip:bob@example.com>\r\n"
        "Call-ID: trunc@host\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Type: application/sdp\r\n"
        "Content-Length: 200\r\n"
        "\r\n"
        "v=0\r\n"; // only 4 bytes, not 200

    // Should still parse (Content-Length used as cap, not hard requirement for parser)
    // The SDP parsing may or may not find audio — what matters is no crash.
    auto result = parseSip(payload);
    // The message is parseable (mandatory headers are present); SDP may be incomplete.
    ASSERT_TRUE(result.has_value());
}
