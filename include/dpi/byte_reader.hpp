#pragma once

#include <cstddef>
#include <cstdint>

namespace dpi {

// Bounds-checked, big-endian cursor over a byte buffer.
// Every read returns false instead of reading past the end, so parsers built
// on top of it never touch memory outside the packet.
class ByteReader {
public:
    ByteReader() = default;
    ByteReader(const uint8_t* data, size_t size) : data_(data), size_(size) {}

    size_t pos() const { return pos_; }
    size_t size() const { return size_; }
    size_t remaining() const { return size_ - pos_; }
    const uint8_t* current() const { return data_ + pos_; }
    bool has(size_t n) const { return n <= remaining(); }

    bool skip(size_t n) {
        if (!has(n)) return false;
        pos_ += n;
        return true;
    }

    bool u8(uint8_t& v) {
        if (!has(1)) return false;
        v = data_[pos_++];
        return true;
    }

    bool u16(uint16_t& v) {
        if (!has(2)) return false;
        v = static_cast<uint16_t>((data_[pos_] << 8) | data_[pos_ + 1]);
        pos_ += 2;
        return true;
    }

    bool u24(uint32_t& v) {
        if (!has(3)) return false;
        v = (uint32_t(data_[pos_]) << 16) | (uint32_t(data_[pos_ + 1]) << 8) | data_[pos_ + 2];
        pos_ += 3;
        return true;
    }

    bool u32(uint32_t& v) {
        if (!has(4)) return false;
        v = (uint32_t(data_[pos_]) << 24) | (uint32_t(data_[pos_ + 1]) << 16) |
            (uint32_t(data_[pos_ + 2]) << 8) | data_[pos_ + 3];
        pos_ += 4;
        return true;
    }

    // Split off the next n bytes as their own reader and advance past them.
    bool sub(size_t n, ByteReader& out) {
        if (!has(n)) return false;
        out = ByteReader(data_ + pos_, n);
        pos_ += n;
        return true;
    }

private:
    const uint8_t* data_ = nullptr;
    size_t size_ = 0;
    size_t pos_ = 0;
};

}  // namespace dpi
