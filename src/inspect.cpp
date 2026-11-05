#include "dpi/inspect.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <string_view>

#include "dpi/byte_reader.hpp"

namespace dpi {
namespace {

constexpr uint8_t TLS_HANDSHAKE = 0x16;
constexpr uint8_t TLS_CLIENT_HELLO = 0x01;
constexpr uint16_t TLS_EXT_SERVER_NAME = 0x0000;
constexpr size_t TLS_MAX_RECORD = 16384 + 2048;

bool startsWithIgnoreCase(std::string_view text, std::string_view prefix) {
    if (text.size() < prefix.size()) return false;
    for (size_t i = 0; i < prefix.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(text[i])) != prefix[i]) return false;
    }
    return true;
}

std::string_view trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) s.remove_suffix(1);
    return s;
}

}  // namespace

std::string normalizeHost(const std::string& host) {
    std::string h(trim(host));
    std::transform(h.begin(), h.end(), h.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    while (!h.empty() && h.back() == '.') h.pop_back();
    return h;
}

bool isValidHostname(const std::string& host) {
    if (host.empty() || host.size() > 253 || host.front() == '.') return false;
    for (char c : host) {
        bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_';
        if (!ok) return false;
    }
    return true;
}

bool looksLikeTls(const uint8_t* p, size_t n) {
    return n >= 3 && p[0] == TLS_HANDSHAKE && p[1] == 0x03 && p[2] <= 0x04;
}

ParseResult extractTlsSni(const uint8_t* p, size_t n, std::string& host) {
    ByteReader r(p, n);

    // TLS record header: type(1) version(2) length(2)
    uint8_t recordType;
    uint16_t recordVersion, recordLen;
    if (!r.u8(recordType)) return ParseResult::NeedMore;
    if (recordType != TLS_HANDSHAKE) return ParseResult::NotMatched;
    if (!r.u16(recordVersion)) return ParseResult::NeedMore;
    if ((recordVersion >> 8) != 0x03) return ParseResult::NotMatched;
    if (!r.u16(recordLen)) return ParseResult::NeedMore;
    if (recordLen == 0 || recordLen > TLS_MAX_RECORD) return ParseResult::NotMatched;
    if (!r.has(recordLen)) return ParseResult::NeedMore;  // ClientHello continues in a later segment

    ByteReader record;
    r.sub(recordLen, record);

    // Handshake header: type(1) length(3)
    uint8_t hsType;
    uint32_t hsLen;
    if (!record.u8(hsType) || hsType != TLS_CLIENT_HELLO) return ParseResult::NotMatched;
    if (!record.u24(hsLen)) return ParseResult::NotMatched;
    ByteReader hello;
    record.sub(std::min<size_t>(hsLen, record.remaining()), hello);

    // ClientHello body: version(2) random(32) session_id cipher_suites compression extensions
    uint8_t sessionIdLen, compressionLen;
    uint16_t clientVersion, cipherLen, extensionsLen;
    if (!hello.u16(clientVersion) || !hello.skip(32)) return ParseResult::NotMatched;
    if (!hello.u8(sessionIdLen) || !hello.skip(sessionIdLen)) return ParseResult::NotMatched;
    if (!hello.u16(cipherLen) || !hello.skip(cipherLen)) return ParseResult::NotMatched;
    if (!hello.u8(compressionLen) || !hello.skip(compressionLen)) return ParseResult::NotMatched;
    if (!hello.u16(extensionsLen)) return ParseResult::NotMatched;  // no extensions -> no SNI

    ByteReader extensions;
    hello.sub(std::min<size_t>(extensionsLen, hello.remaining()), extensions);

    while (extensions.remaining() >= 4) {
        uint16_t extType = 0, extLen = 0;
        if (!extensions.u16(extType) || !extensions.u16(extLen)) break;
        ByteReader ext;
        if (!extensions.sub(extLen, ext)) break;
        if (extType != TLS_EXT_SERVER_NAME) continue;

        // server_name_list: length(2) then entries of type(1) length(2) name
        uint16_t listLen;
        if (!ext.u16(listLen)) break;
        ByteReader list;
        ext.sub(std::min<size_t>(listLen, ext.remaining()), list);
        while (list.remaining() >= 3) {
            uint8_t nameType = 0;
            uint16_t nameLen = 0;
            if (!list.u8(nameType) || !list.u16(nameLen) || !list.has(nameLen)) break;
            if (nameType == 0) {  // host_name
                std::string name = normalizeHost(
                    std::string(reinterpret_cast<const char*>(list.current()), nameLen));
                if (!isValidHostname(name)) return ParseResult::NotMatched;
                host = name;
                return ParseResult::Found;
            }
            list.skip(nameLen);
        }
        break;
    }
    return ParseResult::NotMatched;
}

bool extractHttpHost(const uint8_t* p, size_t n, std::string& host) {
    static const char* const kMethods[] = {"GET ",    "POST ",    "PUT ",   "HEAD ",
                                           "DELETE ", "OPTIONS ", "PATCH ", "CONNECT "};
    std::string_view text(reinterpret_cast<const char*>(p), n);

    bool isRequest = false;
    for (const char* m : kMethods) {
        if (text.compare(0, std::strlen(m), m) == 0) {
            isRequest = true;
            break;
        }
    }
    if (!isRequest) return false;

    size_t lineEnd = text.find('\n');  // skip the request line
    while (lineEnd != std::string_view::npos) {
        size_t start = lineEnd + 1;
        lineEnd = text.find('\n', start);
        std::string_view line = text.substr(start, lineEnd == std::string_view::npos ? std::string_view::npos
                                                                                   : lineEnd - start);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        if (line.empty()) break;  // blank line = end of headers

        if (startsWithIgnoreCase(line, "host:")) {
            std::string value(trim(line.substr(5)));
            if (!value.empty() && value[0] == '[') {
                return false;  // IPv6 literal, not a domain name
            }
            size_t colon = value.find(':');
            if (colon != std::string::npos) value.resize(colon);  // drop ":8080"
            value = normalizeHost(value);
            if (!isValidHostname(value)) return false;
            host = value;
            return true;
        }
    }
    return false;
}

bool parseDnsQuestion(const uint8_t* p, size_t n, DnsQuestion& q) {
    ByteReader r(p, n);
    uint16_t id, flags, qdCount, anCount, nsCount, arCount;
    if (!r.u16(id) || !r.u16(flags) || !r.u16(qdCount) || !r.u16(anCount) || !r.u16(nsCount) ||
        !r.u16(arCount)) {
        return false;
    }
    uint8_t opcode = (flags >> 11) & 0x0F;
    if (opcode != 0 || qdCount == 0 || qdCount > 16) return false;

    // QNAME: a sequence of length-prefixed labels ending in 0. Compression
    // pointers are followed (with a jump limit) in case a sender uses them.
    std::string name;
    size_t pos = 12;
    size_t afterName = 0;
    bool jumped = false;
    int jumps = 0;
    while (true) {
        if (pos >= n) return false;
        uint8_t len = p[pos];
        if (len == 0) {
            ++pos;
            break;
        }
        if ((len & 0xC0) == 0xC0) {
            if (pos + 1 >= n || ++jumps > 8) return false;
            if (!jumped) afterName = pos + 2;
            jumped = true;
            pos = (size_t(len & 0x3F) << 8) | p[pos + 1];
            continue;
        }
        if ((len & 0xC0) != 0 || pos + 1 + len > n) return false;
        if (!name.empty()) name += '.';
        name.append(reinterpret_cast<const char*>(p + pos + 1), len);
        if (name.size() > 253) return false;
        pos += 1 + size_t(len);
    }

    ByteReader rest(p, n);
    rest.skip(jumped ? afterName : pos);
    uint16_t qtype = 0;
    rest.u16(qtype);

    name = normalizeHost(name);
    if (!isValidHostname(name)) return false;
    q.name = name;
    q.qtype = qtype;
    q.isResponse = (flags & 0x8000) != 0;
    return true;
}

}  // namespace dpi
