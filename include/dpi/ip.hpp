#pragma once

#include <array>
#include <cstdint>
#include <string>

namespace dpi {

// An IPv4 or IPv6 address stored in network byte order.
struct IpAddr {
    uint8_t family = 0;               // 4 or 6 (0 = unset)
    std::array<uint8_t, 16> bytes{};  // IPv4 uses the first 4 bytes

    static IpAddr fromV4(const uint8_t* p);
    static IpAddr fromV6(const uint8_t* p);

    // Parses dotted IPv4 ("10.0.0.1") or IPv6 ("2001:db8::1").
    static bool parse(const std::string& text, IpAddr& out);

    std::string toString() const;

    bool operator==(const IpAddr& o) const { return family == o.family && bytes == o.bytes; }
    bool operator!=(const IpAddr& o) const { return !(*this == o); }
    bool operator<(const IpAddr& o) const {
        if (family != o.family) return family < o.family;
        return bytes < o.bytes;
    }
};

// An address range in CIDR notation, e.g. "10.0.0.0/8". A bare address is a
// range of exactly one host.
struct IpPrefix {
    IpAddr base;
    int bits = 0;

    static bool parse(const std::string& text, IpPrefix& out);
    bool contains(const IpAddr& ip) const;
    std::string toString() const;
};

}  // namespace dpi
