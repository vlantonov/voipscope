#pragma once

#include "SipTypes.hpp"
#include <optional>
#include <string_view>

namespace voipscope {

// Stateless RFC 3261 SIP message parser.
// Returns std::nullopt for non-SIP payloads and malformed messages (FR-09).
std::optional<SipMessage> parseSip(std::string_view payload);

} // namespace voipscope
