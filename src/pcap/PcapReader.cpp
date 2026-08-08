#include "PcapReader.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <memory>
#include <optional>
#include <pcap/pcap.h>
#include <stdexcept>

namespace voipscope {

namespace {

// Ethernet II frame offsets
constexpr int kEthHdrLen    = 14;
constexpr int kEthTypeOff   = 12;
constexpr uint16_t kEthIPv4 = 0x0800;

// IPv4 within Ethernet frame
constexpr int kIpVerIhlOff  = kEthHdrLen + 0;
constexpr int kIpProtoOff   = kEthHdrLen + 9;
constexpr int kIpSrcOff     = kEthHdrLen + 12;
constexpr int kIpDstOff     = kEthHdrLen + 16;
constexpr uint8_t kProtoUDP = 0x11;

// UDP header offsets relative to UDP start
constexpr int kUdpSrcOff    = 0;
constexpr int kUdpDstOff    = 2;
constexpr int kUdpLenOff    = 4;
constexpr int kUdpHdrLen    = 8;

// Read 2 bytes big-endian without alignment/aliasing issues
inline uint16_t readU16BE(const uint8_t* p) {
    uint16_t v{};
    std::memcpy(&v, p, 2);
    return ntohs(v);
}

// Convert struct in_addr embedded in raw bytes to dotted-decimal string
inline std::string ipToString(const uint8_t* p) {
    char buf[INET_ADDRSTRLEN]{};
    uint32_t addr{};
    std::memcpy(&addr, p, 4);
    ::inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return buf;
}

} // namespace

struct PcapReader::Impl {
    pcap_t* handle{nullptr};
    char    errbuf[PCAP_ERRBUF_SIZE]{};
};

PcapReader::PcapReader(const std::string& path)
    : impl_(std::make_unique<Impl>())
{
    impl_->handle = ::pcap_open_offline(path.c_str(), impl_->errbuf);
    if (!impl_->handle) {
        throw std::runtime_error(
            std::string("Cannot open PCAP file '") + path + "': " + impl_->errbuf);
    }
    // Only Ethernet link-layer is supported.
    int dlt = ::pcap_datalink(impl_->handle);
    if (dlt != DLT_EN10MB) {
        ::pcap_close(impl_->handle);
        impl_->handle = nullptr;
        throw std::runtime_error(
            std::string("Unsupported link-layer type ") + std::to_string(dlt) +
            " in '" + path + "' (only Ethernet / DLT_EN10MB supported)");
    }
}

PcapReader::~PcapReader() {
    if (impl_ && impl_->handle) {
        ::pcap_close(impl_->handle);
    }
}

std::optional<UdpPacket> PcapReader::next() {
    while (true) {
        struct pcap_pkthdr* header{};
        const uint8_t*      data{};

        int rc = ::pcap_next_ex(impl_->handle, &header, &data);
        if (rc == PCAP_ERROR_BREAK || rc == 0) {
            return std::nullopt; // EOF
        }
        if (rc < 0) {
            return std::nullopt; // error — treat as EOF
        }

        uint32_t caplen = header->caplen;

        // Need at least Ethernet + minimal IPv4 + UDP headers
        if (caplen < static_cast<uint32_t>(kEthHdrLen + 20 + kUdpHdrLen)) {
            continue;
        }

        // EtherType must be IPv4
        uint16_t etherType = readU16BE(data + kEthTypeOff);
        if (etherType != kEthIPv4) {
            continue;
        }

        // IP version and IHL
        uint8_t verIhl   = data[kIpVerIhlOff];
        uint8_t version  = (verIhl >> 4) & 0x0F;
        uint8_t ihl      = (verIhl & 0x0F) * 4;
        if (version != 4 || ihl < 20) {
            continue;
        }

        // Protocol must be UDP
        if (data[kIpProtoOff] != kProtoUDP) {
            continue;
        }

        // Ensure frame is large enough for IP + UDP
        uint32_t udpStart = kEthHdrLen + ihl;
        if (caplen < udpStart + kUdpHdrLen) {
            continue;
        }

        const uint8_t* udp = data + udpStart;
        uint16_t udpLen    = readU16BE(udp + kUdpLenOff);
        if (udpLen < kUdpHdrLen) {
            continue;
        }

        uint32_t payloadLen = udpLen - kUdpHdrLen;
        if (caplen < udpStart + kUdpHdrLen + payloadLen) {
            payloadLen = caplen - udpStart - kUdpHdrLen;
        }

        UdpPacket pkt;
        pkt.srcIp   = ipToString(data + kIpSrcOff);
        pkt.dstIp   = ipToString(data + kIpDstOff);
        pkt.srcPort = readU16BE(udp + kUdpSrcOff);
        pkt.dstPort = readU16BE(udp + kUdpDstOff);

        const uint8_t* payloadPtr = udp + kUdpHdrLen;
        pkt.payload.assign(payloadPtr, payloadPtr + payloadLen);

        // Convert pcap timeval to chrono time_point
        auto secs = std::chrono::seconds(header->ts.tv_sec);
        auto usec = std::chrono::microseconds(header->ts.tv_usec);
        pkt.timestamp = std::chrono::system_clock::time_point(secs + usec);

        return pkt;
    }
}

} // namespace voipscope
