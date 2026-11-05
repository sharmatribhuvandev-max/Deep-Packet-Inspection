// Unit tests for Deep Packet Inspection's parsers, classifier and rules.
// Self-contained: no test framework needed. Exit code 0 = all passed.

#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "dpi/byte_reader.hpp"
#include "dpi/classify.hpp"
#include "dpi/decode.hpp"
#include "dpi/flow.hpp"
#include "dpi/inspect.hpp"
#include "dpi/ip.hpp"
#include "dpi/pcap.hpp"
#include "dpi/rules.hpp"

namespace {

int g_checks = 0;
int g_failures = 0;

#define CHECK(cond)                                                                   \
    do {                                                                              \
        ++g_checks;                                                                   \
        if (!(cond)) {                                                                \
            ++g_failures;                                                             \
            std::cerr << __FILE__ << ":" << __LINE__ << ": CHECK failed: " #cond "\n"; \
        }                                                                             \
    } while (0)

using Bytes = std::vector<uint8_t>;

void put16(Bytes& b, uint16_t v) {
    b.push_back(uint8_t(v >> 8));
    b.push_back(uint8_t(v));
}

void put24(Bytes& b, uint32_t v) {
    b.push_back(uint8_t(v >> 16));
    b.push_back(uint8_t(v >> 8));
    b.push_back(uint8_t(v));
}

void append(Bytes& b, const Bytes& more) { b.insert(b.end(), more.begin(), more.end()); }

Bytes buildClientHello(const std::string& host) {
    Bytes sni;
    put16(sni, uint16_t(host.size() + 3));
    sni.push_back(0);
    put16(sni, uint16_t(host.size()));
    sni.insert(sni.end(), host.begin(), host.end());

    Bytes extensions;
    put16(extensions, 0x000a);  // supported_groups first, so the parser must skip it
    put16(extensions, 4);
    put16(extensions, 2);
    put16(extensions, 0x001d);
    put16(extensions, 0x0000);  // server_name
    put16(extensions, uint16_t(sni.size()));
    append(extensions, sni);

    Bytes body;
    put16(body, 0x0303);
    body.insert(body.end(), 32, 0xAB);  // random
    body.push_back(0);                  // session id length
    put16(body, 2);
    put16(body, 0x1301);                // one cipher suite
    body.push_back(1);
    body.push_back(0);                  // compression: null
    put16(body, uint16_t(extensions.size()));
    append(body, extensions);

    Bytes handshake{0x01};
    put24(handshake, uint32_t(body.size()));
    append(handshake, body);

    Bytes record{0x16, 0x03, 0x01};
    put16(record, uint16_t(handshake.size()));
    append(record, handshake);
    return record;
}

Bytes buildDnsQuery(const std::string& host) {
    Bytes b;
    put16(b, 0x1234);
    put16(b, 0x0100);
    put16(b, 1);
    put16(b, 0);
    put16(b, 0);
    put16(b, 0);
    size_t start = 0;
    while (start <= host.size()) {
        size_t dot = host.find('.', start);
        if (dot == std::string::npos) dot = host.size();
        b.push_back(uint8_t(dot - start));
        b.insert(b.end(), host.begin() + long(start), host.begin() + long(dot));
        start = dot + 1;
    }
    b.push_back(0);
    put16(b, 1);
    put16(b, 1);
    return b;
}

std::string tlsHost(const Bytes& b, dpi::ParseResult expected) {
    std::string host;
    dpi::ParseResult r = dpi::extractTlsSni(b.data(), b.size(), host);
    CHECK(r == expected);
    return host;
}

void testByteReader() {
    const uint8_t data[] = {0x12, 0x34, 0x56};
    dpi::ByteReader r(data, sizeof data);
    uint16_t v16 = 0;
    uint32_t v32 = 0;
    CHECK(r.u16(v16) && v16 == 0x1234);
    CHECK(!r.u32(v32));       // only one byte left
    CHECK(r.remaining() == 1);
    CHECK(!r.skip(2));
}

void testIpAddresses() {
    dpi::IpAddr a;
    CHECK(dpi::IpAddr::parse("192.168.1.50", a) && a.family == 4 && a.toString() == "192.168.1.50");
    CHECK(dpi::IpAddr::parse("2001:db8::1", a) && a.family == 6 && a.toString() == "2001:db8::1");
    CHECK(dpi::IpAddr::parse("::1", a) && a.toString() == "::1");
    CHECK(dpi::IpAddr::parse("2001:0db8:0000:0000:0001:0000:0000:0001", a) && a.toString() == "2001:db8::1:0:0:1");
    CHECK(!dpi::IpAddr::parse("256.1.1.1", a));
    CHECK(!dpi::IpAddr::parse("1.2.3", a));
    CHECK(!dpi::IpAddr::parse("1::2::3", a));

    dpi::IpPrefix p;
    dpi::IpAddr inside, outside;
    CHECK(dpi::IpPrefix::parse("10.1.2.3/8", p) && p.toString() == "10.0.0.0/8");
    dpi::IpAddr::parse("10.200.3.4", inside);
    dpi::IpAddr::parse("11.0.0.1", outside);
    CHECK(p.contains(inside));
    CHECK(!p.contains(outside));
    CHECK(dpi::IpPrefix::parse("192.168.1.0/25", p));
    dpi::IpAddr::parse("192.168.1.127", inside);
    dpi::IpAddr::parse("192.168.1.128", outside);
    CHECK(p.contains(inside) && !p.contains(outside));
    CHECK(dpi::IpPrefix::parse("2001:db8::/32", p));
    dpi::IpAddr::parse("2001:db8:1::5", inside);
    CHECK(p.contains(inside));
    CHECK(!dpi::IpPrefix::parse("10.0.0.0/33", p));
}

void testTlsSni() {
    Bytes hello = buildClientHello("www.YouTube.com");
    CHECK(tlsHost(hello, dpi::ParseResult::Found) == "www.youtube.com");

    Bytes partial(hello.begin(), hello.begin() + 40);  // ClientHello cut off mid-way
    tlsHost(partial, dpi::ParseResult::NeedMore);

    Bytes appData = hello;
    appData[0] = 0x17;  // application data, not a handshake
    tlsHost(appData, dpi::ParseResult::NotMatched);

    Bytes broken = hello;
    broken[broken.size() - 5] = 0xFF;  // corrupt the name length inside the extension
    std::string host;
    CHECK(dpi::extractTlsSni(broken.data(), broken.size(), host) != dpi::ParseResult::Found ||
          dpi::isValidHostname(host));
}

void testHttpHost() {
    std::string req = "GET /a HTTP/1.1\r\nUser-Agent: test\r\nHOST:  Example.COM:8080\r\n\r\n";
    std::string host;
    CHECK(dpi::extractHttpHost(reinterpret_cast<const uint8_t*>(req.data()), req.size(), host));
    CHECK(host == "example.com");

    std::string resp = "HTTP/1.1 200 OK\r\nHost: example.com\r\n\r\n";
    CHECK(!dpi::extractHttpHost(reinterpret_cast<const uint8_t*>(resp.data()), resp.size(), host));

    std::string noHost = "GET / HTTP/1.0\r\nAccept: */*\r\n\r\nHost: late.example\r\n";
    CHECK(!dpi::extractHttpHost(reinterpret_cast<const uint8_t*>(noHost.data()), noHost.size(), host));
}

void testDns() {
    Bytes query = buildDnsQuery("www.netflix.com");
    dpi::DnsQuestion q;
    CHECK(dpi::parseDnsQuestion(query.data(), query.size(), q));
    CHECK(q.name == "www.netflix.com" && q.qtype == 1 && !q.isResponse);

    Bytes truncated(query.begin(), query.begin() + 18);
    CHECK(!dpi::parseDnsQuestion(truncated.data(), truncated.size(), q));

    Bytes loop = query;
    loop[12] = 0xC0;  // compression pointer to itself
    loop[13] = 12;
    CHECK(!dpi::parseDnsQuestion(loop.data(), loop.size(), q));
}

void testClassification() {
    CHECK(dpi::appForDomain("www.youtube.com") == "YouTube");
    CHECK(dpi::appForDomain("rr3---sn-a5m.googlevideo.com") == "YouTube");
    CHECK(dpi::appForDomain("www.netflix.com") == "Netflix");      // must not match "x.com"
    CHECK(dpi::appForDomain("www.microsoft.com") == "Microsoft");  // must not match "t.co"
    CHECK(dpi::appForDomain("x.com") == "Twitter/X");
    CHECK(dpi::appForDomain("api.x.com") == "Twitter/X");
    CHECK(dpi::appForDomain("notx.com").empty());
    CHECK(dpi::appForDomain("example.com").empty());
    CHECK(dpi::canonicalAppName("youtube") == "YouTube");
    CHECK(dpi::canonicalAppName("twitter") == "Twitter/X");
    CHECK(dpi::canonicalAppName("myspace").empty());
}

void testRules() {
    dpi::RuleSet rules;
    std::string err;
    CHECK(rules.add("app", "youtube", err));
    CHECK(rules.add("domain", "tiktok", err));
    CHECK(rules.add("domain", "*.example.org", err));
    CHECK(rules.add("ip", "192.168.1.0/24", err));
    CHECK(rules.add("port", "6881", err));
    CHECK(!rules.add("app", "not-an-app", err));
    CHECK(!rules.add("port", "70000", err));
    CHECK(!rules.add("ip", "300.1.1.1", err));

    CHECK(rules.checkContent("YouTube", "www.youtube.com").block);
    CHECK(rules.checkContent("TikTok", "www.tiktok.com").block);
    CHECK(rules.checkContent("HTTPS", "cdn.example.org").block);
    CHECK(rules.checkContent("HTTPS", "example.org").block);
    CHECK(!rules.checkContent("HTTPS", "notexample.org").block);
    CHECK(!rules.checkContent("Netflix", "www.netflix.com").block);

    dpi::IpAddr lan, wan;
    dpi::IpAddr::parse("192.168.1.77", lan);
    dpi::IpAddr::parse("8.8.8.8", wan);
    CHECK(rules.checkEndpoints(wan, 53, lan, 50000, true).block);   // either direction
    dpi::IpAddr other;
    dpi::IpAddr::parse("10.0.0.1", other);
    CHECK(rules.checkEndpoints(other, 6881, wan, 1234, true).block);
    CHECK(!rules.checkEndpoints(other, 6881, wan, 1234, false).block);  // no ports decoded
    CHECK(!rules.checkEndpoints(other, 443, wan, 1234, true).block);
}

void testDecodeAndFlowKey() {
    // Ethernet + VLAN tag + IPv4 + TCP + 5-byte payload
    Bytes frame(12, 0x00);
    put16(frame, 0x8100);
    put16(frame, 100);
    put16(frame, 0x0800);
    Bytes ip = {0x45, 0, 0, 0, 0, 1, 0x40, 0, 64, 6, 0, 0, 192, 168, 1, 10, 93, 184, 215, 14};
    Bytes tcp = {0xC3, 0x50, 0x01, 0xBB, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x18, 0xFF, 0xFF, 0, 0, 0, 0};
    Bytes payload = {'h', 'e', 'l', 'l', 'o'};
    uint16_t total = uint16_t(ip.size() + tcp.size() + payload.size());
    ip[2] = uint8_t(total >> 8);
    ip[3] = uint8_t(total);
    append(frame, ip);
    append(frame, tcp);
    append(frame, payload);
    frame.insert(frame.end(), 6, 0x00);  // Ethernet padding must be ignored

    dpi::Decoded d;
    CHECK(dpi::decodePacket(frame.data(), frame.size(), dpi::LINKTYPE_ETHERNET, d));
    CHECK(d.ip && d.vlan && d.hasPorts);
    CHECK(d.src.toString() == "192.168.1.10" && d.dst.toString() == "93.184.215.14");
    CHECK(d.sport == 50000 && d.dport == 443 && d.proto == dpi::PROTO_TCP);
    CHECK(d.payloadLen == 5 && std::memcmp(frame.data() + d.payloadOffset, "hello", 5) == 0);

    // Truncated frames must be rejected or decoded partially, never over-read.
    for (size_t len = 0; len < frame.size(); ++len) {
        dpi::Decoded partial;
        dpi::decodePacket(frame.data(), len, dpi::LINKTYPE_ETHERNET, partial);
        CHECK(partial.payloadOffset + partial.payloadLen <= len || !partial.hasPorts);
    }

    // The same connection seen in both directions gives the same flow key.
    dpi::Decoded reverse = d;
    std::swap(reverse.src, reverse.dst);
    std::swap(reverse.sport, reverse.dport);
    dpi::FlowKey k1 = dpi::FlowKey::from(d), k2 = dpi::FlowKey::from(reverse);
    CHECK(k1 == k2);
    CHECK(dpi::FlowKeyHash{}(k1) == dpi::FlowKeyHash{}(k2));
}

}  // namespace

int main() {
    testByteReader();
    testIpAddresses();
    testTlsSni();
    testHttpHost();
    testDns();
    testClassification();
    testRules();
    testDecodeAndFlowKey();

    if (g_failures == 0) {
        std::cout << "All " << g_checks << " checks passed.\n";
        return 0;
    }
    std::cout << g_failures << " of " << g_checks << " checks FAILED.\n";
    return 1;
}
