#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace dpi {

enum class ParseResult {
    Found,       // hostname extracted
    NeedMore,    // looks right so far, but the data is cut off
    NotMatched,  // not this protocol, or no hostname present
};

// True if the payload starts like a TLS handshake record.
bool looksLikeTls(const uint8_t* p, size_t n);

// Extracts the Server Name Indication from a TLS ClientHello.
ParseResult extractTlsSni(const uint8_t* p, size_t n, std::string& host);

// Extracts the Host header from an HTTP/1.x request.
bool extractHttpHost(const uint8_t* p, size_t n, std::string& host);

struct DnsQuestion {
    std::string name;
    uint16_t qtype = 0;
    bool isResponse = false;
};

// Extracts the first question from a DNS query or response.
bool parseDnsQuestion(const uint8_t* p, size_t n, DnsQuestion& q);

// Lower-cases, trims and drops a trailing dot: "WWW.Example.com." -> "www.example.com".
std::string normalizeHost(const std::string& host);
bool isValidHostname(const std::string& host);

}  // namespace dpi
