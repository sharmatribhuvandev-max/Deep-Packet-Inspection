#include "dpi/pcap.hpp"

#include <cstring>

namespace dpi {
namespace {

constexpr uint32_t MAGIC_MICRO = 0xa1b2c3d4;
constexpr uint32_t MAGIC_NANO = 0xa1b23c4d;
constexpr uint32_t MAGIC_PCAPNG = 0x0a0d0d0a;
constexpr uint32_t MAX_PACKET_BYTES = 256 * 1024;

uint32_t byteSwap(uint32_t v) {
    return ((v & 0xFF000000u) >> 24) | ((v & 0x00FF0000u) >> 8) |
           ((v & 0x0000FF00u) << 8) | ((v & 0x000000FFu) << 24);
}

template <typename T>
void writeValue(std::ofstream& out, T value) {
    out.write(reinterpret_cast<const char*>(&value), sizeof value);
}

}  // namespace

uint32_t PcapReader::fix(uint32_t v) const { return swap_ ? byteSwap(v) : v; }

bool PcapReader::open(const std::string& path, std::string& err) {
    in_.open(path, std::ios::binary);
    if (!in_) {
        err = "cannot open '" + path + "'";
        return false;
    }

    uint8_t hdr[24];
    if (!in_.read(reinterpret_cast<char*>(hdr), sizeof hdr)) {
        err = "'" + path + "' is too short to be a pcap capture";
        return false;
    }

    uint32_t magic;
    std::memcpy(&magic, hdr, 4);
    if (magic == MAGIC_MICRO) {
    } else if (magic == byteSwap(MAGIC_MICRO)) {
        swap_ = true;
    } else if (magic == MAGIC_NANO) {
        nano_ = true;
    } else if (magic == byteSwap(MAGIC_NANO)) {
        nano_ = swap_ = true;
    } else if (magic == MAGIC_PCAPNG) {
        err = "'" + path + "' is in pcapng format, which is not supported. "
              "Convert it first: editcap -F pcap input.pcapng output.pcap";
        return false;
    } else {
        err = "'" + path + "' is not a pcap capture (unknown file signature)";
        return false;
    }

    uint32_t snap, link;
    std::memcpy(&snap, hdr + 16, 4);
    std::memcpy(&link, hdr + 20, 4);
    snap_ = fix(snap);
    link_ = fix(link) & 0x0FFFFFFF;  // upper bits may carry FCS information
    return true;
}

bool PcapReader::next(RawPacket& pkt) {
    uint8_t h[16];
    if (!in_.read(reinterpret_cast<char*>(h), sizeof h)) {
        if (in_.gcount() != 0) err_ = "capture ends with a truncated packet header";
        return false;
    }

    uint32_t v[4];
    std::memcpy(v, h, sizeof v);
    for (auto& x : v) x = fix(x);
    const uint32_t inclLen = v[2];

    if (inclLen > MAX_PACKET_BYTES) {
        err_ = "packet #" + std::to_string(seq_ + 1) + " claims " + std::to_string(inclLen) +
               " bytes; the capture is probably corrupt";
        return false;
    }

    pkt.data.resize(inclLen);
    if (inclLen != 0 && !in_.read(reinterpret_cast<char*>(pkt.data.data()), inclLen)) {
        err_ = "capture ends with a truncated packet";
        return false;
    }

    pkt.seq = seq_++;
    pkt.tsSec = v[0];
    pkt.tsFrac = v[1];
    pkt.origLen = v[3];
    return true;
}

bool PcapWriter::open(const std::string& path, uint32_t linkType, uint32_t snapLen,
                      bool nanosecond, std::string& err) {
    out_.open(path, std::ios::binary | std::ios::trunc);
    if (!out_) {
        err = "cannot create output file '" + path + "'";
        return false;
    }
    // Written in host byte order; readers detect the order from the magic number.
    writeValue<uint32_t>(out_, nanosecond ? MAGIC_NANO : MAGIC_MICRO);
    writeValue<uint16_t>(out_, 2);  // version 2.4
    writeValue<uint16_t>(out_, 4);
    writeValue<int32_t>(out_, 0);   // timezone offset
    writeValue<uint32_t>(out_, 0);  // timestamp accuracy
    writeValue<uint32_t>(out_, snapLen);
    writeValue<uint32_t>(out_, linkType);
    return true;
}

void PcapWriter::write(const RawPacket& pkt) {
    if (!out_) return;
    writeValue<uint32_t>(out_, pkt.tsSec);
    writeValue<uint32_t>(out_, pkt.tsFrac);
    writeValue<uint32_t>(out_, static_cast<uint32_t>(pkt.data.size()));
    writeValue<uint32_t>(out_, pkt.origLen);
    out_.write(reinterpret_cast<const char*>(pkt.data.data()),
               static_cast<std::streamsize>(pkt.data.size()));
}

void PcapWriter::close() {
    if (out_.is_open()) out_.close();
}

}  // namespace dpi
