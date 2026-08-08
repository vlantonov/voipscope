#include "MosEstimator.hpp"

#include <algorithm>
#include <cmath>
#include <string_view>

namespace voipscope {

namespace {

bool iequal(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) return false;
    }
    return true;
}

} // namespace

double codecBaselineR(std::string_view codec) {
    if (iequal(codec, "PCMU") || iequal(codec, "PCMA")) return 93.2;
    if (iequal(codec, "G722"))                           return 93.0;
    if (iequal(codec, "G729"))                           return 82.0;
    return 80.0;
}

double rToMos(double r) {
    if (r < 0.0)   return 1.0;
    if (r > 100.0) return 4.5;
    return 1.0 + 0.035 * r + r * (r - 60.0) * (100.0 - r) * 7e-6;
}

double computeMos(std::string_view codec, double meanJitterMs, double lossPct) {
    double r0 = codecBaselineR(codec);

    // Per-codec equipment impairment baseline (for Ie_eff calculation)
    double ie_codec = 0.0;
    if (iequal(codec, "G722"))                           ie_codec = 10.0;
    else if (iequal(codec, "G729"))                      ie_codec = 11.0;
    else if (!iequal(codec, "PCMU") && !iequal(codec, "PCMA")) ie_codec = 15.0;

    // Packet-loss impairment via simplified Ie_eff (§9.2 / first PM decisions)
    // Ie_eff = ie_codec + (95 - ie_codec) * loss% / (loss% + 10)
    double ie_eff = ie_codec + (95.0 - ie_codec) * lossPct / (lossPct + 10.0);
    double ie_additional = ie_eff - ie_codec;

    // Jitter-induced delay impairment Id (1 ms floor absorbed by jitter buffer)
    double id = std::max(0.0, (meanJitterMs - 1.0) * 0.1);

    double r = r0 - id - ie_additional;
    double mos = rToMos(r);

    // Clamp to [1.0, 4.5] and round to 2 decimal places (FR-35)
    mos = std::clamp(mos, 1.0, 4.5);
    return std::round(mos * 100.0) / 100.0;
}

} // namespace voipscope
