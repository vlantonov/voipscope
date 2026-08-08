#include "pcap/PcapReader.hpp"
#include "sip/DialogManager.hpp"
#include "sip/SipParser.hpp"
#include "rtp/RtcpParser.hpp"
#include "rtp/RtpParser.hpp"
#include "rtp/RtpTracker.hpp"
#include "output/CdrEmitter.hpp"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

void printUsage(std::string_view progName) {
    std::cerr << "Usage: " << progName
              << " [OPTIONS] <pcap-file>\n\n"
                 "Options:\n"
                 "  -o, --output <file>   Write CDR NDJSON to <file> (default: stdout)\n"
                 "  -v, --verbose         Print per-packet diagnostics to stderr\n"
                 "  --help                Print this help and exit\n";
}

// Heuristic: return true if the payload looks like a SIP message (§5.1)
bool looksLikeSip(std::span<const uint8_t> payload) {
    if (payload.size() < 7) return false;
    std::string_view sv(reinterpret_cast<const char*>(payload.data()), payload.size());
    if (sv.starts_with("SIP/"))    return true;
    if (sv.starts_with("INVITE ")) return true;
    if (sv.starts_with("ACK "))    return true;
    if (sv.starts_with("BYE "))    return true;
    if (sv.starts_with("CANCEL ")) return true;
    if (sv.starts_with("OPTIONS "))return true;
    if (sv.starts_with("REGISTER ")) return true;
    return false;
}

// Heuristic: RTP/RTCP both have version=2 in bits [7:6] of byte 0.
// Try RTCP first (PT byte 1 in {200,201}), then RTP otherwise.
bool looksLikeRtcp(std::span<const uint8_t> payload) {
    if (payload.size() < 4) return false;
    uint8_t version = (payload[0] >> 6) & 0x03;
    if (version != 2) return false;
    uint8_t pt = payload[1] & 0x7F;
    return (pt == 200 || pt == 201);
}

bool looksLikeRtp(std::span<const uint8_t> payload) {
    if (payload.size() < 12) return false;
    uint8_t version = (payload[0] >> 6) & 0x03;
    return version == 2;
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    std::string pcapFile;
    std::string outputFile;
    bool verbose = false;

    // Manual CLI parsing (no third-party arg parser)
    for (int i = 1; i < argc; ++i) {
        std::string_view arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            printUsage(argv[0]);
            return 0;
        } else if ((arg == "-o" || arg == "--output") && i + 1 < argc) {
            outputFile = argv[++i];
        } else if (arg == "-v" || arg == "--verbose") {
            verbose = true;
        } else if (arg.starts_with("-")) {
            std::cerr << "Unknown option: " << arg << '\n';
            printUsage(argv[0]);
            return 1;
        } else {
            pcapFile = std::string(arg);
        }
    }

    if (pcapFile.empty()) {
        std::cerr << "Error: <pcap-file> argument is required.\n";
        printUsage(argv[0]);
        return 1;
    }

    // Open output stream
    std::ofstream outFile;
    std::ostream* out = &std::cout;
    if (!outputFile.empty()) {
        outFile.open(outputFile);
        if (!outFile) {
            std::cerr << "Error: cannot open output file '" << outputFile << "'\n";
            return 1;
        }
        out = &outFile;
    }

    // Open PCAP — throws std::runtime_error on failure (FR-04)
    voipscope::PcapReader reader{pcapFile};
    voipscope::DialogManager dialogMgr;
    voipscope::RtpTracker rtpTracker;

    std::chrono::system_clock::time_point lastTimestamp;

    // Main packet loop
    while (auto pktOpt = reader.next()) {
        auto& pkt = *pktOpt;
        lastTimestamp = pkt.timestamp;

        std::span<const uint8_t> payload(pkt.payload);

        if (looksLikeSip(payload)) {
            std::string_view sv(
                reinterpret_cast<const char*>(payload.data()), payload.size());
            auto msgOpt = voipscope::parseSip(sv);
            if (msgOpt) {
                auto& msg = *msgOpt;
                msg.srcIp       = pkt.srcIp;
                msg.srcPort     = pkt.srcPort;
                msg.dstIp       = pkt.dstIp;
                msg.dstPort     = pkt.dstPort;
                msg.captureTime = pkt.timestamp;

                if (verbose) {
                    std::cerr << "[SIP] " << pkt.srcIp << ':' << pkt.srcPort
                              << " -> " << pkt.dstIp << ':' << pkt.dstPort
                              << " Call-ID=" << msg.callId << '\n';
                }

                dialogMgr.ingest(msg, rtpTracker);

                // Emit any CDRs that just completed
                for (auto& cdr : dialogMgr.takeCompleted()) {
                    if (verbose) {
                        std::cerr << "[CDR] " << cdr.callId
                                  << " status=" << cdr.status << '\n';
                    }
                    voipscope::emitCdr(cdr, *out);
                }
            }
        } else if (looksLikeRtcp(payload)) {
            auto packets = voipscope::parseRtcp(payload);
            for (const auto& pkt2 : packets) {
                for (const auto& blk : pkt2.reportBlocks) {
                    rtpTracker.ingestRtcp(blk);
                }
            }
        } else if (looksLikeRtp(payload)) {
            auto hdrOpt = voipscope::parseRtp(payload);
            if (hdrOpt) {
                rtpTracker.ingest(pkt, *hdrOpt);
            }
        }
    }

    // EOF: flush pending (incomplete) dialogs (OQ-07)
    for (auto& cdr : dialogMgr.takePending(lastTimestamp, rtpTracker)) {
        if (verbose) {
            std::cerr << "[CDR/incomplete] " << cdr.callId << '\n';
        }
        voipscope::emitCdr(cdr, *out);
    }

    return 0;
}
