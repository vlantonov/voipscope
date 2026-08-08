#include <gtest/gtest.h>

#include "quality/MosEstimator.hpp"
#include <cmath>

using namespace voipscope;

TEST(Mos, PcmuCleanCall) {
    double mos = computeMos("PCMU", 0.0, 0.0);
    EXPECT_GE(mos, 4.38);
    EXPECT_LE(mos, 4.42);
}

TEST(Mos, PcmaCleanCall) {
    double mos = computeMos("PCMA", 0.0, 0.0);
    EXPECT_GE(mos, 4.38);
    EXPECT_LE(mos, 4.42);
}

TEST(Mos, G729CleanCall) {
    // G.729: R0=82, Ie_codec=11, 0 loss → ie_additional=0, R=82 → MOS≈4.10
    double mos = computeMos("G729", 0.0, 0.0);
    EXPECT_GE(mos, 4.05);
    EXPECT_LE(mos, 4.15);
}

TEST(Mos, HighLoss15Pct) {
    // 15% loss with PCMU should produce poor MOS
    double mos = computeMos("PCMU", 0.0, 15.0);
    EXPECT_LT(mos, 2.5);
}

TEST(Mos, RBelowZeroClamp) {
    // rToMos with negative R should clamp to 1.0
    EXPECT_DOUBLE_EQ(rToMos(-5.0),  1.0);
    EXPECT_DOUBLE_EQ(rToMos(-100.0), 1.0);
}

TEST(Mos, RAbove100Clamp) {
    // rToMos with R > 100 should clamp to 4.5
    EXPECT_DOUBLE_EQ(rToMos(105.0), 4.5);
    EXPECT_DOUBLE_EQ(rToMos(200.0), 4.5);
}

TEST(Mos, UnknownCodecFallback) {
    // Unknown codec baseline R = 80.0
    EXPECT_DOUBLE_EQ(codecBaselineR("OPUS"),  80.0);
    EXPECT_DOUBLE_EQ(codecBaselineR("G726"),  80.0);
    EXPECT_DOUBLE_EQ(codecBaselineR(""),      80.0);
}

TEST(Mos, G711BaselineR) {
    EXPECT_DOUBLE_EQ(codecBaselineR("PCMU"), 93.2);
    EXPECT_DOUBLE_EQ(codecBaselineR("PCMA"), 93.2);
}

TEST(Mos, G722BaselineR) {
    EXPECT_DOUBLE_EQ(codecBaselineR("G722"), 93.0);
}

TEST(Mos, MosTwoDecimalPlaces) {
    // computeMos must return a value rounded to 2 decimal places
    double mos = computeMos("PCMU", 2.5, 0.5);
    // Verify it is round-trippable at 2 d.p.
    double rounded = std::round(mos * 100.0) / 100.0;
    EXPECT_DOUBLE_EQ(mos, rounded);
}

TEST(Mos, ClampHighExtremePcmu) {
    // Perfect conditions → near 4.4 (not exactly 4.5, since R=93.2 < 100)
    double mos = computeMos("PCMU", 0.0, 0.0);
    EXPECT_LE(mos, 4.5);
    EXPECT_GE(mos, 4.0);
}
