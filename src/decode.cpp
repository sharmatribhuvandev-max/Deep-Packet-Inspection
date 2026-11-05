#include "dpi/decode.hpp"

#include <algorithm>

#include "dpi/byte_reader.hpp"
#include "dpi/pcap.hpp"

namespace dpi {
namespace {

constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;
constexpr uint16_t ETHERTYPE_IPV6 = 0x86DD;
constexpr uint16_t ETHERTYPE_VLAN = 0x8100;
constexpr uint16_t ETHERTYPE_QINQ = 0x88A8;

// Decodes TCP or UDP starting at `offset`; `end` is where the IP payload ends.
void decodeTransport(const uint8_t* data, size_t end, size_t offset, Decoded& d) {
    ByteReader r(data, end);
    if (!r.skip(offset)) return;

    if (d.proto == PROTO_TCP) {
        uint16_t sport, dport;
        uint32_t seq, ack;
        uint8_t offsetByte, flags;
        if (!r.u16(sport) || !r.u16(dport) || !r.u32(seq) || !r.u32(ack) ||
            !r.u8(offsetByte) || !r.u8(flags)) {
            return;
        }
        size_t headerLen = size_t(offsetByte >> 4) * 4;
        if (headerLen < 20 || offset + headerLen > end) return;
        d.hasPorts = true;
        d.sport = sport;
        d.dport = dport;
        d.tcpFlags = flags;
        d.payloadOffset = static_cast<uint32_t>(offset + headerLen);
        d.payloadLen = static_cast<uint32_t>(end - (offset + headerLen));
    } else if (d.proto == PROTO_UDP) {
        uint16_t sport, dport, length, checksum;
        if (!r.u16(sport) || !r.u16(dport) || !r.u16(length) || !r.u16(checksum)) return;
        size_t udpEnd = end;
        if (length >= 8) udpEnd = std::min(end, offset + length);
        d.hasPorts = true;
        d.sport = sport;
        d.dport = dport;
        d.payloadOffset = static_cast<uint32_t>(offset + 8);
        d.payloadLen = static_cast<uint32_t>(udpEnd - (offset + 8));
    }
}

bool decodeIPv4(const uint8_t* data, size_t len, size_t start, Decoded& d) {
    ByteReader r(data, len);
    r.skip(start);
    uint8_t versionIhl, tos, ttl, proto;
    uint16_t totalLen, id, fragField, checksum;
    if (!r.u8(versionIhl) || (versionIhl >> 4) != 4) return false;
    size_t ihl = size_t(versionIhl & 0x0F) * 4;
    if (ihl < 20) return false;
    if (!r.u8(tos) || !r.u16(totalLen) || !r.u16(id) || !r.u16(fragField) || !r.u8(ttl) ||
        !r.u8(proto) || !r.u16(checksum) || !r.has(8)) {
        return false;
    }

    d.ip = true;
    d.src = IpAddr::fromV4(r.current());
    d.dst = IpAddr::fromV4(r.current() + 4);
    d.proto = proto;

    // Trust the IP length over the frame length (Ethernet may add padding),
    // unless the capture was truncated.
    size_t end = start + totalLen;
    if (totalLen < ihl || end > len) end = len;

    size_t l4 = start + ihl;
    bool laterFragment = (fragField & 0x1FFF) != 0;  // only the first fragment has ports
    if (l4 <= end && !laterFragment) decodeTransport(data, end, l4, d);
    return true;
}

bool decodeIPv6(const uint8_t* data, size_t len, size_t start, Decoded& d) {
    ByteReader r(data, len);
    r.skip(start);
    uint32_t firstWord;
    uint16_t payloadLen;
    uint8_t nextHeader, hopLimit;
    if (!r.u32(firstWord) || (firstWord >> 28) != 6) return false;
    if (!r.u16(payloadLen) || !r.u8(nextHeader) || !r.u8(hopLimit) || !r.has(32)) return false;

    d.ip = true;
    d.src = IpAddr::fromV6(r.current());
    d.dst = IpAddr::fromV6(r.current() + 16);
    r.skip(32);

    size_t end = std::min(len, start + 40 + payloadLen);
    size_t offset = start + 40;

    // Walk the common extension headers to find the transport protocol.
    for (int i = 0; i < 8; ++i) {
        if (nextHeader == 0 || nextHeader == 43 || nextHeader == 60) {  // hop-by-hop, routing, dest opts
            if (offset + 2 > end) break;
            uint8_t following = data[offset];
            size_t extLen = (size_t(data[offset + 1]) + 1) * 8;
            nextHeader = following;
            offset += extLen;
        } else if (nextHeader == 44) {  // fragment header
            if (offset + 8 > end) break;
            uint8_t following = data[offset];
            uint16_t fragOffset = static_cast<uint16_t>(((data[offset + 2] << 8) | data[offset + 3]) >> 3);
            nextHeader = following;
            offset += 8;
            if (fragOffset != 0) {  // not the first fragment: no transport header here
                d.proto = nextHeader;
                return true;
            }
        } else {
            break;
        }
    }

    d.proto = nextHeader;
    if (offset <= end) decodeTransport(data, end, offset, d);
    return true;
}

}  // namespace

bool supportedLinkType(uint32_t linkType) {
    return linkType == LINKTYPE_ETHERNET || linkType == LINKTYPE_RAW ||
           linkType == LINKTYPE_IPV4 || linkType == LINKTYPE_IPV6;
}

bool decodePacket(const uint8_t* data, size_t len, uint32_t linkType, Decoded& out) {
    out = Decoded{};
    ByteReader r(data, len);
    uint16_t etherType = 0;

    if (linkType == LINKTYPE_ETHERNET) {
        if (!r.skip(12) || !r.u16(etherType)) return false;
        // Up to two VLAN tags (802.1Q / 802.1ad).
        for (int i = 0; i < 2 && (etherType == ETHERTYPE_VLAN || etherType == ETHERTYPE_QINQ); ++i) {
            out.vlan = true;
            if (!r.skip(2) || !r.u16(etherType)) return false;
        }
    } else if (supportedLinkType(linkType)) {
        if (len == 0) return false;
        uint8_t version = data[0] >> 4;
        etherType = version == 4 ? ETHERTYPE_IPV4 : version == 6 ? ETHERTYPE_IPV6 : 0;
    } else {
        return false;
    }

    if (etherType == ETHERTYPE_IPV4) return decodeIPv4(data, len, r.pos(), out);
    if (etherType == ETHERTYPE_IPV6) return decodeIPv6(data, len, r.pos(), out);
    return false;
}

}  // namespace dpi
