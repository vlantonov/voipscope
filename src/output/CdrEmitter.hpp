#pragma once

#include "CdrTypes.hpp"
#include <ostream>

namespace voipscope {

// Serialises one CDR as a single NDJSON line (FR-41).
void emitCdr(const Cdr& cdr, std::ostream& out);

} // namespace voipscope
