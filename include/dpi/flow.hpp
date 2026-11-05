#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "dpi/decode.hpp"
#include "dpi/ip.hpp"

namespace dpi {

// Identifies a connection regardless of direction: A->B and B->A packets
// produce the same key, so requests and replies land in the same flow.
struct FlowKey {
    IpAddr lo, hi;
    uint16_t loPort = 0, hiPort = 0;
    uint8_t proto = 0;

    static FlowKey from(const Decoded& d);

    bool operator==(const FlowKey& o) const {
        return proto == o.proto && loPort == o.loPort && hiPort == o.hiPort && lo == o.lo && hi == o.hi;
    }
};

struct FlowKeyHash {
    size_t operator()(const FlowKey& k) const;
};

// Everything Deep Packet Inspection learns about one connection.
struct Flow {
    FlowKey key;
    uint8_t proto = 0;
    IpAddr client, server;        // client = side that opened the connection
    uint16_t clientPort = 0, serverPort = 0;

    uint64_t packets = 0;
    uint64_t bytes = 0;
    uint64_t droppedPackets = 0;

    std::string domain;           // from TLS SNI, HTTP Host or DNS question
    std::string domainSource;     // "tls-sni", "http-host" or "dns"
    std::string app;              // e.g. "YouTube", or a protocol label like "HTTPS"

    bool blocked = false;
    std::string blockReason;

    // Inspection state
    bool inspectionDone = false;
    bool sawTls = false;
    uint32_t payloadPackets = 0;
    std::string tlsBuffer;        // reassembles a ClientHello split over segments
};

}  // namespace dpi
