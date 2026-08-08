#include <gtest/gtest.h>

#include "output/CdrEmitter.hpp"
#include "output/CdrTypes.hpp"

#include <nlohmann/json.hpp>
#include <sstream>
#include <string>

using namespace voipscope;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static std::chrono::system_clock::time_point makeTimePoint(long long epochSec,
                                                            long long ms = 0) {
    return std::chrono::system_clock::time_point(
        std::chrono::seconds(epochSec) + std::chrono::milliseconds(ms));
}

static Cdr makeSampleCdr(bool twoStreams = false, bool incomplete = false) {
    Cdr cdr;
    cdr.callId      = "abc123@192.168.1.10";
    cdr.caller      = "sip:alice@example.com";
    cdr.callee      = "sip:bob@example.com";
    cdr.startTime   = makeTimePoint(1710492225, 123); // 2024-03-15T10:23:45.123Z
    cdr.endTime     = makeTimePoint(1710492301, 456); // 2024-03-15T10:25:01.456Z
    cdr.codec       = "PCMU";
    cdr.payloadType = 0;
    cdr.status      = incomplete ? "incomplete" : "complete";

    StreamStats s1;
    s1.direction    = "caller_to_callee";
    s1.ssrc         = 305419896;
    s1.mos          = 4.21;
    s1.meanJitterMs = 2.34;
    s1.lossPercent  = 0.12;
    cdr.streams.push_back(s1);
    cdr.mos          = s1.mos;
    cdr.meanJitterMs = s1.meanJitterMs;
    cdr.lossPercent  = s1.lossPercent;
    cdr.ssrc         = s1.ssrc;

    if (twoStreams) {
        StreamStats s2;
        s2.direction    = "callee_to_caller";
        s2.ssrc         = 2882400018;
        s2.mos          = 4.15;
        s2.meanJitterMs = 3.10;
        s2.lossPercent  = 0.00;
        cdr.streams.push_back(s2);
    }

    return cdr;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

TEST(Cdr, SerialiseComplete) {
    Cdr cdr = makeSampleCdr();
    std::ostringstream oss;
    emitCdr(cdr, oss);

    auto j = nlohmann::json::parse(oss.str());
    EXPECT_EQ(j["call_id"].get<std::string>(), "abc123@192.168.1.10");
    EXPECT_EQ(j["caller"].get<std::string>(),  "sip:alice@example.com");
    EXPECT_EQ(j["callee"].get<std::string>(),  "sip:bob@example.com");
    EXPECT_EQ(j["codec"].get<std::string>(),   "PCMU");
    EXPECT_EQ(j["payload_type"].get<int>(),    0);
    EXPECT_EQ(j["status"].get<std::string>(),  "complete");
    EXPECT_TRUE(j.contains("start_time"));
    EXPECT_TRUE(j.contains("end_time"));
    EXPECT_TRUE(j.contains("duration_sec"));
    EXPECT_TRUE(j.contains("streams"));
    EXPECT_TRUE(j.contains("mos"));
}

TEST(Cdr, NullFieldsNoMedia) {
    Cdr cdr;
    cdr.callId      = "no-media@host";
    cdr.caller      = "sip:alice@example.com";
    cdr.callee      = "sip:bob@example.com";
    cdr.startTime   = makeTimePoint(1710492225);
    cdr.endTime     = makeTimePoint(1710492285);
    cdr.codec       = "PCMU";
    cdr.payloadType = 0;
    cdr.status      = "complete";
    // streams is empty, optional fields are nullopt (CA-07)

    std::ostringstream oss;
    emitCdr(cdr, oss);

    auto j = nlohmann::json::parse(oss.str());
    EXPECT_TRUE(j["mos"].is_null());
    EXPECT_TRUE(j["mean_jitter_ms"].is_null());
    EXPECT_TRUE(j["packet_loss_pct"].is_null());
    EXPECT_TRUE(j["ssrc"].is_null());
    EXPECT_EQ(j["streams"].size(), 0u);
}

TEST(Cdr, IncompleteStatus) {
    Cdr cdr = makeSampleCdr(false, true);
    std::ostringstream oss;
    emitCdr(cdr, oss);

    auto j = nlohmann::json::parse(oss.str());
    EXPECT_EQ(j["status"].get<std::string>(), "incomplete");
}

TEST(Cdr, CompleteStatus) {
    Cdr cdr = makeSampleCdr();
    std::ostringstream oss;
    emitCdr(cdr, oss);

    auto j = nlohmann::json::parse(oss.str());
    EXPECT_EQ(j["status"].get<std::string>(), "complete");
}

TEST(Cdr, TwoStreamCdr) {
    Cdr cdr = makeSampleCdr(true);
    std::ostringstream oss;
    emitCdr(cdr, oss);

    auto j = nlohmann::json::parse(oss.str());
    ASSERT_EQ(j["streams"].size(), 2u);
    EXPECT_EQ(j["streams"][0]["direction"].get<std::string>(), "caller_to_callee");
    EXPECT_EQ(j["streams"][1]["direction"].get<std::string>(), "callee_to_caller");
    EXPECT_EQ(j["streams"][0]["ssrc"].get<uint32_t>(), 305419896u);
    EXPECT_EQ(j["streams"][1]["ssrc"].get<uint32_t>(), 2882400018u);
}

TEST(Cdr, NdjsonSingleLine) {
    // Two CDR emissions must produce exactly two '\n'-terminated lines
    std::ostringstream oss;
    emitCdr(makeSampleCdr(), oss);
    emitCdr(makeSampleCdr(), oss);

    std::string output = oss.str();
    int newlines = 0;
    for (char c : output) if (c == '\n') ++newlines;
    EXPECT_EQ(newlines, 2);

    // Each line must be independently parseable
    std::size_t pos1 = output.find('\n');
    ASSERT_NE(pos1, std::string::npos);
    auto j1 = nlohmann::json::parse(output.substr(0, pos1));
    auto j2 = nlohmann::json::parse(output.substr(pos1 + 1));
    EXPECT_TRUE(j1.is_object());
    EXPECT_TRUE(j2.is_object());
}

TEST(Cdr, TimestampFormat) {
    // Verify ISO 8601 format: "YYYY-MM-DDTHH:MM:SS.mmmZ"
    Cdr cdr = makeSampleCdr();
    std::ostringstream oss;
    emitCdr(cdr, oss);

    auto j = nlohmann::json::parse(oss.str());
    std::string ts = j["start_time"].get<std::string>();
    EXPECT_EQ(ts.size(), 24u); // "2024-03-15T10:23:45.123Z"
    EXPECT_EQ(ts.back(), 'Z');
    EXPECT_EQ(ts[10], 'T');
    EXPECT_EQ(ts[19], '.'); // index 19 in "YYYY-MM-DDTHH:MM:SS.mmmZ"
}
