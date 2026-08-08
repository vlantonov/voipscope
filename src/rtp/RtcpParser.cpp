#include "RtcpParser.hpp"

#include <arpa/inet.h>
#include <cstring>

namespace voipscope {

namespace {

uint32_t readU32BE(const uint8_t* p) {
    uint32_t v{};
    std::memcpy(&v, p, 4);
    return ntohl(v);
}

} // namespace

std::vector<RtcpPacket> parseRtcp(std::span<const uint8_t> payload) {
    std::vector<RtcpPacket> result;

    const uint8_t* p   = payload.data();
    std::size_t    rem = payload.size();

    while (rem >= 4) {
        uint8_t  byte0 = p[0];
        uint8_t  version = (byte0 >> 6) & 0x03;
        if (version != 2) break; // not RTCP

        uint8_t  rc   = byte0 & 0x1F;  // reception report count / source count
        uint8_t  pt   = p[1];
        uint16_t lenWords{};
        std::memcpy(&lenWords, p + 2, 2);
        lenWords = ntohs(lenWords);

        std::size_t packetBytes = static_cast<std::size_t>(lenWords + 1) * 4;
        if (rem < packetBytes || packetBytes < 4) break;

        if (pt == 200 || pt == 201) {
            // SR or RR — need at least 4 (common) + 4 (senderSsrc) bytes
            if (packetBytes < 8) {
                p   += packetBytes;
                rem -= packetBytes;
                continue;
            }
            RtcpPacket pkt;
            pkt.type       = pt;
            pkt.senderSsrc = readU32BE(p + 4);

            // SR has an additional 20-byte sender info block before report blocks
            std::size_t offset = (pt == 200) ? 28 : 8;
            std::size_t blockSize = 24; // each RR block is 24 bytes

            for (uint8_t i = 0; i < rc; ++i) {
                if (offset + blockSize > packetBytes) break;
                RtcpReportBlock blk;
                blk.sourceSsrc     = readU32BE(p + offset);
                blk.fractionLost   = p[offset + 4];
                // 24-bit cumulative lost (big-endian, 3 bytes)
                blk.cumulativeLost = (static_cast<uint32_t>(p[offset + 5]) << 16) |
                                     (static_cast<uint32_t>(p[offset + 6]) << 8)  |
                                      static_cast<uint32_t>(p[offset + 7]);
                blk.extHighestSeq  = readU32BE(p + offset + 8);
                blk.jitter         = readU32BE(p + offset + 12);
                blk.lsr            = readU32BE(p + offset + 16);
                blk.dlsr           = readU32BE(p + offset + 20);
                pkt.reportBlocks.push_back(blk);
                offset += blockSize;
            }
            result.push_back(std::move(pkt));
        }

        p   += packetBytes;
        rem -= packetBytes;
    }

    return result;
}

} // namespace voipscope
