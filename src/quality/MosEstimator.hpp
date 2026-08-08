#pragma once

#include <string>
#include <string_view>

namespace voipscope {

// Returns per-codec baseline R-value (FR-33).
double codecBaselineR(std::string_view codec);

// Computes MOS from RFC E-model approximation (FR-32 to FR-35).
[[nodiscard]] double computeMos(std::string_view codec,
                                double meanJitterMs,
                                double lossPct);

// Converts R-factor to MOS (FR-34, FR-35). Exposed for unit testing.
[[nodiscard]] double rToMos(double r);

} // namespace voipscope
