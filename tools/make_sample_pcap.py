#!/usr/bin/env python3
"""Generate a synthetic pcap capture for testing Deep Packet Inspection.

The capture contains HTTPS (TLS ClientHello with SNI), plain HTTP, DNS,
QUIC-like UDP, BitTorrent-like UDP, an IPv6 flow, a VLAN-tagged flow, a
ClientHello split across two TCP segments, and a non-IP (ARP) frame.

Only the Python standard library is used.

Usage:
    python tools/make_sample_pcap.py [output.pcap]
"""

import ipaddress
import random
import struct
import sys

LINKTYPE_ETHERNET = 1
CLIENT_MAC = bytes.fromhex("02000000aa01")
GATEWAY_MAC = bytes.fromhex("02000000bb01")

rng = random.Random(7)  # fixed seed: the same capture every run


def rand_bytes(n):
    return bytes(rng.getrandbits(8) for _ in range(n))


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ip_bytes(addr):
    return ipaddress.ip_address(addr).packed


# --------------------------------------------------------------------------
# Header builders
# --------------------------------------------------------------------------

def ethernet(payload, ethertype, src=CLIENT_MAC, dst=GATEWAY_MAC, vlan=None):
    if vlan is not None:
        return dst + src + struct.pack("!HHH", 0x8100, vlan, ethertype) + payload
    return dst + src + struct.pack("!H", ethertype) + payload


def ipv4(src, dst, proto, payload, ident):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0x4000, 64,
                         proto, 0, ip_bytes(src), ip_bytes(dst))
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def ipv6(src, dst, next_header, payload):
    return struct.pack("!IHBB16s16s", 6 << 28, len(payload), next_header, 64,
                       ip_bytes(src), ip_bytes(dst)) + payload


def pseudo_header(src, dst, proto, length):
    if ":" in src:
        return ip_bytes(src) + ip_bytes(dst) + struct.pack("!I3xB", length, proto)
    return ip_bytes(src) + ip_bytes(dst) + struct.pack("!BBH", 0, proto, length)


def tcp(src, dst, sport, dport, seq, ack, flags, payload=b""):
    header = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 64240, 0, 0)
    csum = checksum(pseudo_header(src, dst, 6, len(header) + len(payload)) + header + payload)
    return header[:16] + struct.pack("!H", csum) + header[18:] + payload


def udp(src, dst, sport, dport, payload):
    header = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    csum = checksum(pseudo_header(src, dst, 17, len(header) + len(payload)) + header + payload) or 0xFFFF
    return header[:6] + struct.pack("!H", csum) + payload


# --------------------------------------------------------------------------
# Application payloads
# --------------------------------------------------------------------------

def tls_client_hello(host):
    name = host.encode()
    server_name = struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
    groups = struct.pack("!HHH", 4, 0x001D, 0x0017)
    alpn_list = b"\x02h2\x08http/1.1"
    alpn = struct.pack("!H", len(alpn_list)) + alpn_list
    versions = b"\x04\x03\x04\x03\x03"

    def ext(ext_type, body):
        return struct.pack("!HH", ext_type, len(body)) + body

    # A non-SNI extension comes first so the parser has to skip over it.
    extensions = (ext(0x000A, groups) + ext(0x0000, server_name) +
                  ext(0x0010, alpn) + ext(0x002B, versions))
    ciphers = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030]

    body = struct.pack("!H", 0x0303) + rand_bytes(32)
    body += b"\x20" + rand_bytes(32)  # session id
    body += struct.pack("!H", len(ciphers) * 2) + b"".join(struct.pack("!H", c) for c in ciphers)
    body += b"\x01\x00"  # compression: null
    body += struct.pack("!H", len(extensions)) + extensions

    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def tls_server_reply(size=600):
    hello = b"\x02" + (size - 4).to_bytes(3, "big") + rand_bytes(size - 4)
    return b"\x16\x03\x03" + struct.pack("!H", len(hello)) + hello


def tls_app_data(size):
    return b"\x17\x03\x03" + struct.pack("!H", size) + rand_bytes(size)


def http_request(host, path="/"):
    return (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: dpi-sample/1.0\r\n"
            f"Accept: */*\r\n\r\n").encode()


def http_response(body_len=400):
    body = b"x" * body_len
    return (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: " +
            str(body_len).encode() + b"\r\n\r\n" + body)


def dns_name(host):
    return b"".join(bytes([len(p)]) + p.encode() for p in host.split(".")) + b"\x00"


def dns_query(host, qid):
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + dns_name(host) + struct.pack("!HH", 1, 1)


def dns_response(host, qid, answer_ip):
    question = dns_name(host) + struct.pack("!HH", 1, 1)
    answer = struct.pack("!HHHIH4s", 0xC00C, 1, 1, 300, 4, ip_bytes(answer_ip))
    return struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0) + question + answer


# --------------------------------------------------------------------------
# Capture builder
# --------------------------------------------------------------------------

class Capture:
    def __init__(self):
        self.frames = []
        self.time = 1_700_000_000.0
        self.ident = 1

    def add(self, frame):
        self.time += rng.uniform(0.0005, 0.02)
        self.frames.append((self.time, frame))

    def ip_frame(self, src, dst, proto, payload, vlan=None, toward_server=True):
        mac_src, mac_dst = (CLIENT_MAC, GATEWAY_MAC) if toward_server else (GATEWAY_MAC, CLIENT_MAC)
        if ":" in src:
            self.add(ethernet(ipv6(src, dst, proto, payload), 0x86DD, mac_src, mac_dst, vlan))
        else:
            self.ident = (self.ident + 1) & 0xFFFF
            self.add(ethernet(ipv4(src, dst, proto, payload, self.ident), 0x0800, mac_src, mac_dst, vlan))

    def tcp_session(self, client, cport, server, sport, client_data, server_data, vlan=None):
        """Handshake, client segments, server segments, then a FIN exchange."""
        c_seq, s_seq = rng.getrandbits(32), rng.getrandbits(32)
        SYN, ACK, PSH, FIN = 0x02, 0x10, 0x08, 0x01

        def c2s(flags, data=b""):
            self.ip_frame(client, server, 6, tcp(client, server, cport, sport, c_seq, s_seq, flags, data), vlan, True)

        def s2c(flags, data=b""):
            self.ip_frame(server, client, 6, tcp(server, client, sport, cport, s_seq, c_seq, flags, data), vlan, False)

        c2s(SYN); c_seq += 1
        s2c(SYN | ACK); s_seq += 1
        c2s(ACK)
        for chunk in client_data:
            c2s(PSH | ACK, chunk); c_seq += len(chunk)
        for chunk in server_data:
            s2c(PSH | ACK, chunk); s_seq += len(chunk)
        c2s(FIN | ACK); c_seq += 1
        s2c(FIN | ACK); s_seq += 1
        c2s(ACK)

    def https(self, client, server, host, split=False, vlan=None, app_bytes=(900, 1200)):
        hello = tls_client_hello(host)
        client_data = [hello[:60], hello[60:]] if split else [hello]
        server_data = [tls_server_reply()] + [tls_app_data(n) for n in app_bytes]
        self.tcp_session(client, rng.randint(49152, 65000), server, 443, client_data, server_data, vlan)

    def http(self, client, server, host, path="/"):
        self.tcp_session(client, rng.randint(49152, 65000), server, 80,
                         [http_request(host, path)], [http_response()])

    def dns(self, client, resolver, host, answer):
        qid = rng.getrandbits(16)
        port = rng.randint(49152, 65000)
        self.ip_frame(client, resolver, 17, udp(client, resolver, port, 53, dns_query(host, qid)))
        self.ip_frame(resolver, client, 17, udp(resolver, client, 53, port, dns_response(host, qid, answer)),
                      toward_server=False)

    def udp_burst(self, client, server, sport, dport, sizes):
        for i, size in enumerate(sizes):
            if i % 2 == 0:
                self.ip_frame(client, server, 17, udp(client, server, sport, dport, rand_bytes(size)))
            else:
                self.ip_frame(server, client, 17, udp(server, client, dport, sport, rand_bytes(size)),
                              toward_server=False)

    def arp(self):
        payload = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, CLIENT_MAC,
                              ip_bytes("192.168.1.10"), b"\x00" * 6, ip_bytes("192.168.1.1"))
        self.add(ethernet(payload, 0x0806, CLIENT_MAC, b"\xff" * 6))

    def save(self, path):
        with open(path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))
            for ts, frame in self.frames:
                sec = int(ts)
                usec = int(round((ts - sec) * 1_000_000)) % 1_000_000
                f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
                f.write(frame)


def build():
    cap = Capture()
    laptop, phone, desktop, guest = "192.168.1.10", "192.168.1.20", "192.168.1.30", "192.168.1.50"
    resolver = "8.8.8.8"

    cap.arp()

    # DNS lookups before the connections they lead to
    cap.dns(laptop, resolver, "www.youtube.com", "142.250.183.110")
    cap.dns(laptop, resolver, "www.netflix.com", "54.155.178.5")
    cap.dns(phone, resolver, "api.github.com", "140.82.112.6")
    cap.dns(phone, resolver, "www.tiktok.com", "23.53.38.41")

    # HTTPS (TLS SNI)
    cap.https(laptop, "142.250.183.110", "www.youtube.com", app_bytes=(1400, 1400, 1400))
    cap.https(laptop, "142.250.183.110", "i.ytimg.com")
    cap.https(laptop, "157.240.16.35", "www.facebook.com")
    cap.https(laptop, "142.250.183.100", "www.google.com")
    cap.https(laptop, "54.155.178.5", "www.netflix.com", app_bytes=(1400, 1400))
    cap.https(laptop, "20.112.250.133", "www.microsoft.com")
    cap.https(phone, "140.82.112.6", "api.github.com")
    cap.https(phone, "23.53.38.41", "www.tiktok.com")
    cap.https(phone, "104.244.42.1", "x.com")
    cap.https(phone, "35.186.224.25", "open.spotify.com")
    cap.https(desktop, "162.159.135.232", "discord.com")
    cap.https(desktop, "170.114.52.2", "us04web.zoom.us")
    cap.https(desktop, "151.101.1.140", "www.reddit.com", split=True)  # ClientHello in 2 segments
    cap.https(desktop, "93.184.215.14", "example.com")                 # domain with no known app

    # HTTPS from a guest device (for IP blocking)
    cap.https(guest, "208.80.154.224", "en.wikipedia.org")

    # IPv6 HTTPS and a VLAN-tagged HTTPS flow
    cap.https("2001:db8:1::10", "2a03:2880:f12f:83:face:b00c::25de", "www.instagram.com")
    cap.https("10.20.0.5", "54.239.28.85", "www.amazon.com", vlan=100)

    # Plain HTTP (Host header)
    cap.http(phone, "93.184.215.14", "example.com", "/index.html")
    cap.http(desktop, "34.223.124.45", "neverssl.com")

    # QUIC-like traffic (UDP 443, no SNI parsing) and BitTorrent-like UDP
    cap.udp_burst(laptop, "142.250.183.110", 51000, 443, [1250, 1200, 900, 1200])
    cap.udp_burst(desktop, "203.0.113.9", 6881, 51413, [300, 300, 1100, 1100, 1100])

    return cap


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "samples/sample.pcap"
    cap = build()
    cap.save(path)
    print(f"Wrote {len(cap.frames)} packets to {path}")


if __name__ == "__main__":
    main()
