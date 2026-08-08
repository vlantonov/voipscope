#include "DialogManager.hpp"
#include "SipParser.hpp"
#include "../rtp/RtpTracker.hpp"
#include "../quality/MosEstimator.hpp"

#include <algorithm>

namespace voipscope {

namespace {

// Build the retransmission guard key (CA-08)
std::string txKey(const SipMessage& msg) {
    return msg.viaBranch + "/" + std::to_string(msg.cseqNumber);
}

} // namespace

void DialogManager::ingest(const SipMessage& msg, RtpTracker& tracker) {
    const std::string& callId = msg.callId;

    // -------------------------------------------------------------------
    // New INVITE: create dialog
    // -------------------------------------------------------------------
    if (msg.isRequest() && msg.method == SipMethod::INVITE) {
        auto it = dialogs_.find(callId);

        if (it == dialogs_.end()) {
            // Brand-new dialog
            DialogContext ctx;
            ctx.callId    = callId;
            ctx.fromTag   = msg.fromTag;
            ctx.toTag     = msg.toTag;
            ctx.callerUri = msg.from;
            ctx.calleeUri = msg.to;
            ctx.state     = DialogState::TRYING;
            ctx.inviteTime = msg.captureTime;
            ctx.inviteCseq = msg.cseqNumber;

            if (msg.sdp.has_value()) ctx.offerSdp = msg.sdp;

            // Record this transaction
            ctx.seenTransactions.insert(txKey(msg));
            dialogs_.emplace(callId, std::move(ctx));
            return;
        }

        // Existing dialog
        auto& ctx = it->second;

        // Retransmission check (CA-08)
        std::string key = txKey(msg);
        if (ctx.seenTransactions.count(key)) return;
        ctx.seenTransactions.insert(key);

        // Re-INVITE (FR-16): only valid in ESTABLISHED state
        if (ctx.state == DialogState::ESTABLISHED &&
            msg.cseqNumber > ctx.inviteCseq) {
            if (msg.sdp.has_value()) ctx.offerSdp = msg.sdp;
            ctx.inviteCseq = msg.cseqNumber;
        }
        return;
    }

    // -------------------------------------------------------------------
    // All other messages: find existing dialog
    // -------------------------------------------------------------------
    auto it = dialogs_.find(callId);
    if (it == dialogs_.end()) return; // no dialog to update

    auto& ctx = it->second;

    // Retransmission dedup for responses/other requests
    if (msg.isRequest() && !msg.viaBranch.empty()) {
        std::string key = txKey(msg);
        if (ctx.seenTransactions.count(key)) return;
        ctx.seenTransactions.insert(key);
    }

    // -------------------------------------------------------------------
    // CANCEL
    // -------------------------------------------------------------------
    if (msg.isRequest() && msg.method == SipMethod::CANCEL) {
        if (ctx.state == DialogState::TRYING || ctx.state == DialogState::RINGING) {
            ctx.state    = DialogState::TERMINATED;
            ctx.endTime  = msg.captureTime;
            ctx.emitCdr  = false;
            completed_.push_back(toCdr(ctx, tracker));
            dialogs_.erase(it);
        }
        return;
    }

    // -------------------------------------------------------------------
    // BYE
    // -------------------------------------------------------------------
    if (msg.isRequest() && msg.method == SipMethod::BYE) {
        if (ctx.state == DialogState::ESTABLISHED) {
            ctx.state   = DialogState::TERMINATED;
            ctx.endTime = msg.captureTime;
            ctx.emitCdr = true;
            completed_.push_back(toCdr(ctx, tracker));
            dialogs_.erase(it);
        }
        return;
    }

    // -------------------------------------------------------------------
    // Responses
    // -------------------------------------------------------------------
    if (!msg.isResponse()) return;

    int code = msg.statusCode;

    // 180 / 183 Provisional
    if ((code == 180 || code == 183) &&
        ctx.state == DialogState::TRYING) {
        ctx.state = DialogState::RINGING;
        if (!msg.toTag.empty() && ctx.toTag.empty()) ctx.toTag = msg.toTag;
        return;
    }

    // 200 OK to INVITE (initial or re-INVITE)
    if (code == 200 && msg.cseqMethod == SipMethod::INVITE) {
        if (!msg.toTag.empty() && ctx.toTag.empty()) ctx.toTag = msg.toTag;

        if (ctx.state == DialogState::TRYING ||
            ctx.state == DialogState::RINGING) {
            // Initial 200 OK: transition to ESTABLISHED
            ctx.state = DialogState::ESTABLISHED;
            ctx.startTime = msg.captureTime;
            if (msg.sdp.has_value()) ctx.answerSdp = msg.sdp;

            // Notify RtpTracker of the media association
            if (ctx.offerSdp.has_value() && ctx.answerSdp.has_value()) {
                tracker.associate(callId, *ctx.offerSdp, *ctx.answerSdp);
            }
        } else if (ctx.state == DialogState::ESTABLISHED &&
                   msg.cseqNumber == ctx.inviteCseq) {
            // 200 OK to re-INVITE: update SDP
            if (msg.sdp.has_value()) {
                ctx.answerSdp = msg.sdp;
                if (ctx.offerSdp.has_value()) {
                    tracker.associate(callId, *ctx.offerSdp, *ctx.answerSdp);
                }
            }
        }
        return;
    }

    // 200 OK to BYE
    if (code == 200 && msg.cseqMethod == SipMethod::BYE) {
        if (ctx.state == DialogState::ESTABLISHED) {
            ctx.state   = DialogState::TERMINATED;
            ctx.endTime = msg.captureTime;
            ctx.emitCdr = true;
            completed_.push_back(toCdr(ctx, tracker));
            dialogs_.erase(it);
        }
        return;
    }

    // 4xx / 5xx / 6xx — failure responses
    if (code >= 400) {
        if (ctx.state == DialogState::TRYING  ||
            ctx.state == DialogState::RINGING ||
            ctx.state == DialogState::ESTABLISHED) {
            ctx.state   = DialogState::TERMINATED;
            ctx.endTime = msg.captureTime;
            ctx.emitCdr = false; // FR-40: unanswered/failed calls do not produce CDR
            // Only push if we want to track failures; design says no CDR.
            dialogs_.erase(it);
        }
        return;
    }
}

std::vector<Cdr> DialogManager::takeCompleted() {
    std::vector<Cdr> out;
    out.swap(completed_);
    return out;
}

std::vector<Cdr> DialogManager::takePending(
    std::chrono::system_clock::time_point eofTime,
    RtpTracker& tracker)
{
    std::vector<Cdr> out;
    for (auto& [callId, ctx] : dialogs_) {
        if (ctx.state != DialogState::ESTABLISHED) continue;
        // EOF handling (OQ-07, §6.4)
        ctx.isIncomplete = true;
        ctx.emitCdr      = true;
        // Use last RTP arrival time if available, otherwise eofTime
        auto lastRtp = tracker.lastArrivalForCall(callId);
        ctx.endTime  = (lastRtp.time_since_epoch().count() != 0) ? lastRtp : eofTime;
        out.push_back(toCdr(ctx, tracker));
    }
    dialogs_.clear();
    return out;
}

Cdr DialogManager::toCdr(const DialogContext& ctx, RtpTracker& tracker) const {
    Cdr cdr;
    cdr.callId  = ctx.callId;
    cdr.caller  = ctx.callerUri;
    cdr.callee  = ctx.calleeUri;
    cdr.startTime = ctx.startTime;
    cdr.endTime   = ctx.endTime;
    cdr.status    = ctx.isIncomplete ? "incomplete" : "complete";

    // Codec from negotiated SDP
    if (ctx.answerSdp.has_value()) {
        cdr.codec       = ctx.answerSdp->codecName;
        cdr.payloadType = ctx.answerSdp->payloadType;
    } else if (ctx.offerSdp.has_value()) {
        cdr.codec       = ctx.offerSdp->codecName;
        cdr.payloadType = ctx.offerSdp->payloadType;
    }

    // Per-stream quality
    auto streams = tracker.getStreams(ctx.callId);
    for (const auto& s : streams) {
        StreamStats ss;
        ss.direction    = s.direction;
        ss.ssrc         = s.ssrc;
        ss.meanJitterMs = s.meanJitterMs();
        ss.lossPercent  = s.lossPercent();
        ss.mos          = computeMos(cdr.codec, ss.meanJitterMs, ss.lossPercent);
        cdr.streams.push_back(ss);
    }

    // Top-level convenience fields (§10.2): populated from streams[0] if present
    if (!cdr.streams.empty()) {
        const auto& s0 = cdr.streams[0];
        cdr.mos          = s0.mos;
        cdr.meanJitterMs = s0.meanJitterMs;
        cdr.lossPercent  = s0.lossPercent;
        cdr.ssrc         = s0.ssrc;
    }
    // else: optional fields remain nullopt → serialised as null (CA-07)

    return cdr;
}

} // namespace voipscope
