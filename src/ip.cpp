#include "dpi/ip.hpp"

#include <algorithm>
#include <cstdio>
#include <vector>

namespace dpi {
namespace {

int hexValue(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool parseV4(const std::string& s, uint8_t* out) {
    int part = 0;
    int value = -1;
    for (char c : s) {
        if (c >= '0' && c <= '9') {
            value = (value < 0 ? 0 : value) * 10 + (c - '0');
            if (value > 255) return false;
        } else if (c == '.') {
            if (value < 0 || part >= 3) return false;
            out[part++] = static_cast<uint8_t>(value);
            value = -1;
        } else {
            return false;
        }
    }
    if (value < 0 || part != 3) return false;
    out[3] = static_cast<uint8_t>(value);
    return true;
}

// Parses colon-separated hex groups ("2001:db8:1"); empty input gives no groups.
bool parseGroups(const std::string& s, std::vector<uint16_t>& groups) {
    if (s.empty()) return true;
    size_t start = 0;
    while (true) {
        size_t colon = s.find(':', start);
        std::string part = s.substr(start, colon == std::string::npos ? std::string::npos : colon - start);
        if (part.empty() || part.size() > 4) return false;
        unsigned value = 0;
        for (char c : part) {
            int d = hexValue(c);
            if (d < 0) return false;
            value = value * 16 + static_cast<unsigned>(d);
        }
        groups.push_back(static_cast<uint16_t>(value));
        if (colon == std::string::npos) break;
        start = colon + 1;
    }
    return true;
}

bool parseV6(const std::string& s, uint8_t* out) {
    std::vector<uint16_t> head, tail;
    size_t gap = s.find("::");
    if (gap != std::string::npos) {
        if (s.find("::", gap + 1) != std::string::npos) return false;
        if (!parseGroups(s.substr(0, gap), head) || !parseGroups(s.substr(gap + 2), tail)) return false;
        if (head.size() + tail.size() > 7) return false;
    } else {
        if (!parseGroups(s, head) || head.size() != 8) return false;
    }
    uint16_t groups[8] = {0};
    for (size_t i = 0; i < head.size(); ++i) groups[i] = head[i];
    for (size_t i = 0; i < tail.size(); ++i) groups[8 - tail.size() + i] = tail[i];
    for (int i = 0; i < 8; ++i) {
        out[2 * i] = static_cast<uint8_t>(groups[i] >> 8);
        out[2 * i + 1] = static_cast<uint8_t>(groups[i] & 0xFF);
    }
    return true;
}

}  // namespace

IpAddr IpAddr::fromV4(const uint8_t* p) {
    IpAddr a;
    a.family = 4;
    std::copy(p, p + 4, a.bytes.begin());
    return a;
}

IpAddr IpAddr::fromV6(const uint8_t* p) {
    IpAddr a;
    a.family = 6;
    std::copy(p, p + 16, a.bytes.begin());
    return a;
}

bool IpAddr::parse(const std::string& text, IpAddr& out) {
    IpAddr a;
    if (text.find(':') != std::string::npos) {
        if (!parseV6(text, a.bytes.data())) return false;
        a.family = 6;
    } else {
        if (!parseV4(text, a.bytes.data())) return false;
        a.family = 4;
    }
    out = a;
    return true;
}

std::string IpAddr::toString() const {
    char buf[48];
    if (family == 4) {
        std::snprintf(buf, sizeof buf, "%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);
        return buf;
    }
    if (family != 6) return "?";

    uint16_t g[8];
    for (int i = 0; i < 8; ++i) g[i] = static_cast<uint16_t>((bytes[2 * i] << 8) | bytes[2 * i + 1]);

    // Compress the longest run (2+) of zero groups into "::" (RFC 5952).
    int bestStart = -1, bestLen = 0;
    for (int i = 0; i < 8;) {
        if (g[i] != 0) { ++i; continue; }
        int j = i;
        while (j < 8 && g[j] == 0) ++j;
        if (j - i > bestLen) { bestStart = i; bestLen = j - i; }
        i = j;
    }
    if (bestLen < 2) bestStart = -1;

    std::string out;
    for (int i = 0; i < 8; ++i) {
        if (i == bestStart) {
            out += "::";
            i += bestLen - 1;
            continue;
        }
        if (!out.empty() && out.back() != ':') out += ':';
        std::snprintf(buf, sizeof buf, "%x", g[i]);
        out += buf;
    }
    return out;
}

bool IpPrefix::parse(const std::string& text, IpPrefix& out) {
    IpPrefix p;
    size_t slash = text.find('/');
    if (!IpAddr::parse(text.substr(0, slash), p.base)) return false;

    int maxBits = p.base.family == 4 ? 32 : 128;
    p.bits = maxBits;
    if (slash != std::string::npos) {
        std::string b = text.substr(slash + 1);
        if (b.empty() || b.size() > 3) return false;
        for (char c : b) if (c < '0' || c > '9') return false;
        p.bits = std::stoi(b);
        if (p.bits > maxBits) return false;
    }

    // Clear host bits so "10.1.2.3/8" is stored as "10.0.0.0/8".
    for (int i = 0; i < 16; ++i) {
        int bitStart = i * 8;
        if (bitStart >= p.bits) {
            p.base.bytes[i] = 0;
        } else if (bitStart + 8 > p.bits) {
            p.base.bytes[i] &= static_cast<uint8_t>(0xFF << (8 - (p.bits - bitStart)));
        }
    }
    out = p;
    return true;
}

bool IpPrefix::contains(const IpAddr& ip) const {
    if (ip.family != base.family) return false;
    int fullBytes = bits / 8;
    for (int i = 0; i < fullBytes; ++i) {
        if (ip.bytes[i] != base.bytes[i]) return false;
    }
    int rem = bits % 8;
    if (rem == 0) return true;
    uint8_t mask = static_cast<uint8_t>(0xFF << (8 - rem));
    return (ip.bytes[fullBytes] & mask) == base.bytes[fullBytes];
}

std::string IpPrefix::toString() const {
    int maxBits = base.family == 4 ? 32 : 128;
    if (bits == maxBits) return base.toString();
    return base.toString() + "/" + std::to_string(bits);
}

}  // namespace dpi
