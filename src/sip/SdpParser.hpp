#pragma once

#include "SipTypes.hpp"
#include <optional>
#include <string_view>

namespace voipscope {

// Stateless SDP body parser.
// Returns std::nullopt if no valid m=audio line is found.
std::optional<SdpInfo> parseSdp(std::string_view body);

} // namespace voipscope
