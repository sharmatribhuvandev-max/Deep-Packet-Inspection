#pragma once

#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

namespace dpi {

constexpr uint32_t LINKTYPE_ETHERNET = 1;
constexpr uint32_t LINKTYPE_RAW = 101;   // raw IPv4/IPv6, no link header
constexpr uint32_t LINKTYPE_IPV4 = 228;
constexpr uint32_t LINKTYPE_IPV6 = 229;

struct RawPacket {
    uint64_t seq = 0;       // position in the input file, starting at 0
    uint32_t tsSec = 0;
    uint32_t tsFrac = 0;    // microseconds or nanoseconds, as in the file
    uint32_t origLen = 0;   // length on the wire (may exceed data.size())
    std::vector<uint8_t> data;
};

// Reads classic libpcap files in either byte order, with microsecond or
// nanosecond timestamps. (pcapng is not supported.)
class PcapReader {
public:
    bool open(const std::string& path, std::string& err);
    bool next(RawPacket& pkt);  // false at end of file or on a read error

    uint32_t linkType() const { return link_; }
    uint32_t snapLen() const { return snap_; }
    bool nanosecond() const { return nano_; }
    const std::string& error() const { return err_; }  // set if next() stopped early

private:
    uint32_t fix(uint32_t v) const;

    std::ifstream in_;
    bool swap_ = false;
    bool nano_ = false;
    uint32_t link_ = 0;
    uint32_t snap_ = 0;
    uint64_t seq_ = 0;
    std::string err_;
};

class PcapWriter {
public:
    bool open(const std::string& path, uint32_t linkType, uint32_t snapLen, bool nanosecond,
              std::string& err);
    void write(const RawPacket& pkt);
    void close();

private:
    std::ofstream out_;
};

}  // namespace dpi
