#include "dpi/engine.hpp"

#include <algorithm>
#include <chrono>
#include <map>
#include <memory>
#include <thread>
#include <unordered_map>

#include "dpi/classify.hpp"
#include "dpi/decode.hpp"
#include "dpi/inspect.hpp"
#include "dpi/pcap.hpp"
#include "dpi/queue.hpp"

namespace dpi {
namespace {

constexpr size_t kTlsBufferLimit = 16 * 1024;  // max bytes buffered to find a ClientHello
constexpr uint32_t kMaxInspectPackets = 8;      // give up classifying after this many payloads
constexpr size_t kWorkerQueueSize = 4096;
constexpr size_t kOutputQueueSize = 8192;

struct WorkItem {
    RawPacket pkt;
    Decoded decoded;
    FlowKey key;
};

struct Output {
    uint64_t seq = 0;
    bool forward = true;
    RawPacket pkt;
};

std::string portLabel(uint8_t proto, uint16_t port) {
    if (proto == PROTO_TCP) {
        switch (port) {
            case 80: case 8080: return "HTTP";
            case 443: case 8443: return "HTTPS";
            case 53: return "DNS";
            case 22: return "SSH";
            case 25: case 587: return "SMTP";
            case 993: return "IMAPS";
            case 3389: return "RDP";
        }
    } else if (proto == PROTO_UDP) {
        switch (port) {
            case 53: return "DNS";
            case 443: return "QUIC";
            case 123: return "NTP";
            case 67: case 68: return "DHCP";
            case 5353: return "mDNS";
            case 1900: return "SSDP";
        }
    }
    return "";
}

// A protocol-level label for flows that could not be tied to a known app.
std::string fallbackLabel(const Flow& f) {
    if (f.domainSource == "tls-sni") return "HTTPS";
    if (f.domainSource == "http-host") return "HTTP";
    if (f.domainSource == "dns") return "DNS";
    if (f.sawTls) return "TLS";
    std::string label = portLabel(f.proto, f.serverPort);
    if (label.empty()) label = portLabel(f.proto, f.clientPort);
    if (!label.empty()) return label;
    if (f.proto == 1 || f.proto == 58) return "ICMP";
    return "Unknown";
}

class Worker {
public:
    Worker(const RuleSet& rules, BoundedQueue<Output>& output)
        : input(kWorkerQueueSize), rules_(rules), output_(output) {}

    BoundedQueue<WorkItem> input;
    WorkerStats stats;

    void run() {
        WorkItem item;
        while (input.pop(item)) process(item);
    }

    void collectFlows(std::vector<Flow>& out) {
        for (auto& entry : flows_) {
            Flow& f = entry.second;
            if (f.app.empty()) f.app = fallbackLabel(f);
            f.tlsBuffer.clear();
            out.push_back(std::move(f));
        }
        flows_.clear();
    }

private:
    void process(WorkItem& item) {
        const Decoded& d = item.decoded;
        auto [it, isNew] = flows_.try_emplace(item.key);
        Flow& f = it->second;

        if (isNew) {
            startFlow(f, item.key, d);
            ++stats.flows;
            Verdict v = rules_.checkEndpoints(f.client, f.clientPort, f.server, f.serverPort, d.hasPorts);
            if (v.block) block(f, v.reason);
        }

        ++stats.packets;
        ++f.packets;
        f.bytes += item.pkt.origLen;

        if (!f.inspectionDone) {
            if (!d.hasPorts) {
                finishInspection(f);
            } else if (d.payloadLen > 0) {
                inspect(f, d, item.pkt.data.data() + d.payloadOffset);
            }
        }

        bool forward = !f.blocked;
        if (!forward) ++f.droppedPackets;
        output_.push(Output{item.pkt.seq, forward, std::move(item.pkt)});
    }

    static void startFlow(Flow& f, const FlowKey& key, const Decoded& d) {
        f.key = key;
        f.proto = d.proto;

        // Work out which side opened the connection.
        bool srcIsClient = true;
        bool syn = (d.tcpFlags & tcpflag::SYN) != 0;
        bool ack = (d.tcpFlags & tcpflag::ACK) != 0;
        if (d.proto == PROTO_TCP && syn) {
            srcIsClient = !ack;  // SYN = client, SYN-ACK = server
        } else if (d.hasPorts && d.sport < 1024 && d.dport >= 1024) {
            srcIsClient = false;  // well-known source port: the sender is the server
        }
        f.client = srcIsClient ? d.src : d.dst;
        f.clientPort = srcIsClient ? d.sport : d.dport;
        f.server = srcIsClient ? d.dst : d.src;
        f.serverPort = srcIsClient ? d.dport : d.sport;
    }

    void inspect(Flow& f, const Decoded& d, const uint8_t* payload) {
        const size_t n = d.payloadLen;
        ++f.payloadPackets;
        bool fromClient = d.src == f.client && d.sport == f.clientPort;

        if (d.proto == PROTO_UDP && (d.sport == 53 || d.dport == 53 || d.sport == 5353 || d.dport == 5353)) {
            DnsQuestion q;
            if (parseDnsQuestion(payload, n, q)) {
                setDomain(f, q.name, "dns");
                return;
            }
        } else if (d.proto == PROTO_TCP && fromClient) {
            if (!f.tlsBuffer.empty() || looksLikeTls(payload, n)) {
                f.sawTls = true;
                size_t room = kTlsBufferLimit - f.tlsBuffer.size();
                f.tlsBuffer.append(reinterpret_cast<const char*>(payload), std::min(n, room));

                std::string host;
                ParseResult res = extractTlsSni(reinterpret_cast<const uint8_t*>(f.tlsBuffer.data()),
                                                f.tlsBuffer.size(), host);
                if (res == ParseResult::Found) {
                    setDomain(f, host, "tls-sni");
                } else if (res == ParseResult::NotMatched || f.tlsBuffer.size() >= kTlsBufferLimit) {
                    finishInspection(f);
                }
                // NeedMore: the ClientHello continues in the next segment.
                return;
            }
            std::string host;
            if (extractHttpHost(payload, n, host)) {
                setDomain(f, host, "http-host");
                return;
            }
        }

        if (f.payloadPackets >= kMaxInspectPackets) finishInspection(f);
    }

    void setDomain(Flow& f, const std::string& host, const char* source) {
        f.domain = host;
        f.domainSource = source;
        std::string app = appForDomain(host);
        f.app = app.empty() ? fallbackLabel(f) : app;
        endInspection(f);
    }

    void finishInspection(Flow& f) {
        f.app = fallbackLabel(f);
        endInspection(f);
    }

    void endInspection(Flow& f) {
        f.inspectionDone = true;
        std::string().swap(f.tlsBuffer);  // release the buffer's memory
        if (!f.blocked) {
            Verdict v = rules_.checkContent(f.app, f.domain);
            if (v.block) block(f, v.reason);
        }
    }

    static void block(Flow& f, const std::string& reason) {
        if (f.blocked) return;
        f.blocked = true;
        f.blockReason = reason;
    }

    const RuleSet& rules_;
    BoundedQueue<Output>& output_;
    std::unordered_map<FlowKey, Flow, FlowKeyHash> flows_;
};

// Picks the worker for a flow. The hash is re-mixed so the worker choice is
// independent of how each worker's hash table spreads its buckets.
size_t workerFor(const FlowKey& key, size_t workerCount) {
    uint64_t h = static_cast<uint64_t>(FlowKeyHash{}(key));
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    return static_cast<size_t>(h % workerCount);
}

}  // namespace

bool runEngine(const EngineConfig& config, const RuleSet& rules, EngineResult& result, std::string& err) {
    const auto started = std::chrono::steady_clock::now();
    result = EngineResult{};

    PcapReader reader;
    if (!reader.open(config.inputPath, err)) return false;
    if (!supportedLinkType(reader.linkType())) {
        err = "unsupported link type " + std::to_string(reader.linkType()) +
              " (Deep Packet Inspection reads Ethernet and raw-IP captures)";
        return false;
    }

    PcapWriter writer;
    const bool writing = !config.outputPath.empty();
    if (writing && !writer.open(config.outputPath, reader.linkType(), reader.snapLen(), reader.nanosecond(), err)) {
        return false;
    }

    Totals& totals = result.totals;
    BoundedQueue<Output> outputQueue(kOutputQueueSize);

    const unsigned workerCount = std::max(1u, config.workers);
    std::vector<std::unique_ptr<Worker>> workers;
    std::vector<std::thread> workerThreads;
    for (unsigned i = 0; i < workerCount; ++i) workers.push_back(std::make_unique<Worker>(rules, outputQueue));
    for (auto& w : workers) workerThreads.emplace_back([&w] { w->run(); });

    // Workers finish packets in any order; the writer holds early arrivals
    // until every earlier packet has been written, so the output keeps the
    // exact order of the input.
    std::thread writerThread([&] {
        std::map<uint64_t, Output> pending;
        uint64_t nextSeq = 0;
        auto emit = [&](const Output& o) {
            if (o.forward) {
                ++totals.forwarded;
                if (writing) writer.write(o.pkt);
            } else {
                ++totals.dropped;
            }
        };
        Output o;
        while (outputQueue.pop(o)) {
            pending.emplace(o.seq, std::move(o));
            auto it = pending.begin();
            while (it != pending.end() && it->first == nextSeq) {
                emit(it->second);
                it = pending.erase(it);
                ++nextSeq;
            }
        }
        for (const auto& entry : pending) emit(entry.second);
    });

    // Reader: decode just enough to know which worker owns the flow.
    RawPacket pkt;
    while (reader.next(pkt)) {
        ++totals.packets;
        totals.bytes += pkt.origLen;

        Decoded d;
        if (!decodePacket(pkt.data.data(), pkt.data.size(), reader.linkType(), d) || !d.ip) {
            ++totals.nonIp;
            uint64_t seq = pkt.seq;
            outputQueue.push(Output{seq, true, std::move(pkt)});
            pkt = RawPacket{};
            continue;
        }

        if (d.src.family == 4) ++totals.ipv4; else ++totals.ipv6;
        if (d.proto == PROTO_TCP) ++totals.tcp;
        else if (d.proto == PROTO_UDP) ++totals.udp;
        else ++totals.otherIp;

        FlowKey key = FlowKey::from(d);
        size_t idx = workerFor(key, workers.size());
        workers[idx]->input.push(WorkItem{std::move(pkt), d, key});
        pkt = RawPacket{};
    }
    if (!reader.error().empty()) result.warnings.push_back(reader.error());

    for (auto& w : workers) w->input.close();
    for (auto& t : workerThreads) t.join();
    outputQueue.close();
    writerThread.join();
    writer.close();

    for (auto& w : workers) {
        result.workers.push_back(w->stats);
        w->collectFlows(result.flows);
    }

    totals.seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
    return true;
}

}  // namespace dpi
