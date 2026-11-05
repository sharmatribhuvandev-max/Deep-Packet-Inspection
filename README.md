# Deep Packet Inspection

A multi-threaded deep packet inspection (DPI) engine written in C++17.
It reads a packet capture (`.pcap`) and identifies the application behind each
connection, even for encrypted HTTPS traffic. It can drop traffic that matches
your rules and write the remaining packets to a new capture, in their original order.

```
capture.pcap ──► dpi ──► filtered.pcap   (allowed packets, original order)
                  │
                  ├──► console report       (apps, domains, blocked flows)
                  └──► report.json / flows.csv
```

No external libraries are needed. It builds with g++, clang++ or MSVC on Windows, Linux and macOS.

## Features

- **Identifies applications in encrypted traffic.** It reads the domain name from the
  TLS ClientHello (SNI), the HTTP `Host` header and DNS questions. A ClientHello
  split across several TCP segments is reassembled before parsing.
- **Recognises 20 applications** (YouTube, Netflix, TikTok, GitHub, ...) by
  whole-domain suffix matching. Short domains like `x.com` never match `netflix.com`.
- **Tracks each connection as one bidirectional flow.** Requests and replies share a
  flow, and the engine works out which side is the client.
- **Supports four kinds of blocking rule**, from a rules file or the command line:
  IP addresses and CIDR ranges, applications, domains, and ports. Once a flow is
  blocked, every later packet in it is dropped.
- **Multi-threaded.** Packets are sharded to worker threads by flow hash, so each
  flow is handled by exactly one thread with no locking on flow state. A
  re-ordering writer keeps the output identical whatever the number of threads.
- **Handles real-world packets:** IPv4 and IPv6 (including extension headers),
  802.1Q/QinQ VLAN tags, IP fragments, Ethernet padding, truncated captures,
  microsecond/nanosecond pcap files in either byte order, and raw-IP link types.
- **Safe parsing.** Every header is read through a bounds-checked reader. The test
  suite feeds truncated and corrupted packets to make sure nothing reads out of bounds.
- **Reports** as console tables, JSON (summary, apps, domains, every flow) and CSV
  (one row per flow).

## Build

### Windows (MSYS2 / MinGW-w64)

```powershell
.\build.ps1          # builds build\dpi.exe
.\build.ps1 -Test    # builds and runs the unit tests
```

The executable is statically linked, so it runs on any Windows PC.

### Linux / macOS / any platform with CMake

```bash
cmake -B build
cmake --build build
ctest --test-dir build      # run the unit tests
```

## Usage

```bash
# Create a sample capture (206 packets of mixed traffic)
python tools/make_sample_pcap.py samples/sample.pcap

# Analyse only
dpi samples/sample.pcap

# Block traffic and save the result
dpi samples/sample.pcap -o filtered.pcap --block-app YouTube --block-ip 192.168.1.50

# Use a rules file and export reports
dpi samples/sample.pcap -o filtered.pcap --rules samples/rules.example.txt \
         --json report.json --csv flows.csv
```

| Option | Description |
|---|---|
| `-o, --output <file>` | Write allowed packets to a new pcap |
| `--rules <file>` | Load blocking rules from a file |
| `--block-ip <ip/cidr>` | Block traffic to or from an address or range (`10.0.0.0/8`, `2001:db8::/32`) |
| `--block-app <app>` | Block an application (`YouTube`, `TikTok`, `Netflix`, ...) |
| `--block-domain <d>` | `tiktok.com` blocks that domain and its subdomains; a bare word like `tiktok` blocks any domain containing it |
| `--block-port <n>` | Block TCP/UDP traffic using a port |
| `--json <file>` / `--csv <file>` | Export the report |
| `-w, --workers <n>` | Number of worker threads (default: CPU cores, up to 4) |
| `-q, --quiet` | Don't print report tables |

### Rules file

```text
# samples/rules.example.txt
block-app YouTube
block-app TikTok
block-ip 192.168.1.50
block-port 6881
block-domain facebook.com
```

## Example output

Running the sample capture with the rules file above:

```
┌──────────────────────────────────────────────────────────┐
│                       APPLICATIONS                       │
├─────────────┬───────┬─────────┬───────┬────────┬─────────┤
│ Application │ Flows │ Packets │ Share │ Bytes  │ Status  │
├─────────────┼───────┼─────────┼───────┼────────┼─────────┤
│ YouTube     │     3 │      23 │ 11.2% │ 8.9 KB │ BLOCKED │
│ HTTP        │     2 │      16 │  7.8% │ 1.9 KB │         │
│ GitHub      │     2 │      12 │  5.8% │ 3.5 KB │         │
│ Netflix     │     2 │      12 │  5.8% │ 4.2 KB │         │
│ TikTok      │     2 │      12 │  5.8% │ 3.5 KB │ BLOCKED │
│ Reddit      │     1 │      11 │  5.3% │ 3.4 KB │         │
│ ...         │       │         │       │        │         │
└─────────────┴───────┴─────────┴───────┴────────┴─────────┘

┌──────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                              BLOCKED FLOWS                                               │
├────────────────────┬───────────────────────────────────────┬─────────────┬─────────────────────┬─────────┤
│ Client             │ Server                                │ Application │ Reason              │ Dropped │
├────────────────────┼───────────────────────────────────────┼─────────────┼─────────────────────┼─────────┤
│ 192.168.1.10:60647 │ 142.250.183.110:443 (www.youtube.com) │ YouTube     │ app YouTube         │       8 │
│ 192.168.1.10:59704 │ 157.240.16.35:443 (www.facebook.com)  │ Facebook    │ domain facebook.com │       7 │
│ 192.168.1.50:61532 │ 208.80.154.224:443 (en.wikipedia.org) │ Wikipedia   │ ip 192.168.1.50     │      10 │
│ 192.168.1.30:6881  │ 203.0.113.9:51413                     │ Unknown     │ port 6881           │       5 │
│ 192.168.1.10:55620 │ 8.8.8.8:53 (www.youtube.com)          │ YouTube     │ app YouTube         │       2 │
│ ...                │                                       │             │                     │         │
└────────────────────┴───────────────────────────────────────┴─────────────┴─────────────────────┴─────────┘
```

DNS lookups are attributed to the application they look up, so blocking YouTube
also drops DNS queries for `www.youtube.com`.

## How it works

```
                ┌──────────────┐
 input.pcap ──► │ Reader       │  decode headers, build direction-independent flow key
                └──────┬───────┘
                       │ hash(flow key) % N
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
  ┌──────────┐   ┌──────────┐   ┌──────────┐
  │ Worker 0 │   │ Worker 1 │   │ Worker N │   each owns its flows: inspect payload,
  └────┬─────┘   └────┬─────┘   └────┬─────┘   classify, apply rules, forward/drop
       └──────────────┼──────────────┘
                      ▼
               ┌──────────────┐
               │ Writer       │  re-orders by sequence number, writes allowed packets
               └──────────────┘
```

1. **Reader** (main thread) reads each packet, decodes Ethernet/VLAN → IPv4/IPv6 →
   TCP/UDP, and builds a flow key that is the same in both directions. Non-IP
   frames (ARP, ...) go straight to the writer.
2. **Workers** each own a private flow table. For a new flow, IP and port rules are
   checked at once. Payload packets are inspected until a domain is found: DNS
   question, TLS SNI (buffering up to 16 KB across segments) or HTTP Host. The
   domain is mapped to an app, then app and domain rules are checked. A blocked
   flow drops all its later packets.
3. **Writer** receives verdicts in any order and holds early arrivals until all
   earlier packets are written, so the output capture has the exact order of the input.

All queues are bounded, so memory stays flat on large captures. The rule set is
read-only during processing, so it is shared between threads without locks.

## Project layout

```
include/dpi/   public headers
  byte_reader.hpp   bounds-checked big-endian reader
  ip.hpp            IPv4/IPv6 addresses and CIDR prefixes
  pcap.hpp          pcap reader and writer
  decode.hpp        Ethernet / VLAN / IPv4 / IPv6 / TCP / UDP decoding
  flow.hpp          bidirectional flow key and flow state
  inspect.hpp       TLS SNI, HTTP Host and DNS parsers
  classify.hpp      domain → application signatures
  rules.hpp         blocking rules
  queue.hpp         bounded thread-safe queue
  engine.hpp        multi-threaded pipeline
  report.hpp        console / JSON / CSV reports
  table.hpp         console table rendering
src/                implementations + main.cpp (command line)
tests/              unit tests (no framework needed)
tools/              make_sample_pcap.py: generates test captures
samples/            example rules file
```

## Limitations

- QUIC/HTTP3 is recognised by port only; its SNI is encrypted inside QUIC Initial
  packets and is not decoded yet.
- TLS 1.3 Encrypted Client Hello (ECH) hides the real SNI by design.
- TCP reassembly is limited to finding the ClientHello; retransmitted or
  out-of-order segments during the handshake can prevent classification.
- Packets sent before a flow is classified (e.g. the TCP handshake) are forwarded,
  as in any passive DPI.
- Classic `.pcap` only; convert `.pcapng` with `editcap -F pcap in.pcapng out.pcap`.

## Ideas for future work

- Decrypt QUIC Initial packets to read their SNI
- Live capture from a network interface
- Bandwidth limiting per application instead of blocking
- More application signatures loaded from a file
