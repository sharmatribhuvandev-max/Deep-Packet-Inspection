#pragma once

#include <cstddef>
#include <cstdint>

#include "dpi/ip.hpp"

namespace dpi {

constexpr uint8_t PROTO_TCP = 6;
constexpr uint8_t PROTO_UDP = 17;

namespace tcpflag {
constexpr uint8_t FIN = 0x01;
constexpr uint8_t SYN = 0x02;
constexpr uint8_t RST = 0x04;
constexpr uint8_t PSH = 0x08;
constexpr uint8_t ACK = 0x10;
}  // namespace tcpflag

// The fields Deep Packet Inspection needs from one packet. Offsets are relative to the
// start of the captured frame.
struct Decoded {
    bool ip = false;          // an IPv4 or IPv6 header was found
    bool vlan = false;        // frame carried one or more 802.1Q tags
    IpAddr src, dst;
    uint8_t proto = 0;        // IP protocol number (6 = TCP, 17 = UDP, ...)
    bool hasPorts = false;    // a TCP/UDP header was decoded
    uint16_t sport = 0, dport = 0;
    uint8_t tcpFlags = 0;
    uint32_t payloadOffset = 0;
    uint32_t payloadLen = 0;
};

bool supportedLinkType(uint32_t linkType);

// Decodes link, network and transport headers. Returns false if the frame is
// not IP (e.g. ARP) or is too damaged to read. Never reads past `len`.
bool decodePacket(const uint8_t* data, size_t len, uint32_t linkType, Decoded& out);

}  // namespace dpi
