#include "dpi/flow.hpp"

namespace dpi {

FlowKey FlowKey::from(const Decoded& d) {
    FlowKey k;
    k.proto = d.proto;
    bool srcFirst = d.src < d.dst || (d.src == d.dst && d.sport <= d.dport);
    if (srcFirst) {
        k.lo = d.src; k.loPort = d.sport;
        k.hi = d.dst; k.hiPort = d.dport;
    } else {
        k.lo = d.dst; k.loPort = d.dport;
        k.hi = d.src; k.hiPort = d.sport;
    }
    return k;
}

// 64-bit FNV-1a over the key fields.
size_t FlowKeyHash::operator()(const FlowKey& k) const {
    uint64_t h = 1469598103934665603ULL;
    auto mix = [&h](uint8_t b) {
        h ^= b;
        h *= 1099511628211ULL;
    };
    mix(k.lo.family);
    for (uint8_t b : k.lo.bytes) mix(b);
    for (uint8_t b : k.hi.bytes) mix(b);
    mix(static_cast<uint8_t>(k.loPort >> 8)); mix(static_cast<uint8_t>(k.loPort));
    mix(static_cast<uint8_t>(k.hiPort >> 8)); mix(static_cast<uint8_t>(k.hiPort));
    mix(k.proto);
    return static_cast<size_t>(h);
}

}  // namespace dpi
