#pragma once

#include "../output/CdrTypes.hpp"
#include "SipTypes.hpp"
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

namespace voipscope {

// Forward declaration keeps DialogManager.hpp free of RtpTracker.hpp (§12 header rule).
class RtpTracker;

class DialogManager {
public:
    // Drives the SIP FSM for one parsed message (FR-10 to FR-16).
    void ingest(const SipMessage& msg, RtpTracker& tracker);

    // Returns dialogs that reached TERMINATED via BYE and are ready for CDR emission.
    // The returned entries are removed from the registry.
    std::vector<Cdr> takeCompleted();

    // Returns dialogs in ESTABLISHED state at EOF (OQ-07); marks them incomplete.
    // Only ESTABLISHED dialogs are emitted (TRYING/RINGING are silently discarded).
    std::vector<Cdr> takePending(std::chrono::system_clock::time_point eofTime,
                                 RtpTracker& tracker);

private:
    // Registry keyed by call_id alone (design §4.3 note: forking out of scope)
    std::unordered_map<std::string, DialogContext> dialogs_;

    // Completed dialogs buffered until takeCompleted() is called
    std::vector<Cdr> completed_;

    Cdr toCdr(const DialogContext& ctx, RtpTracker& tracker) const;
};

} // namespace voipscope
