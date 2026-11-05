#include "dpi/report.hpp"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <map>
#include <set>
#include <sstream>

#include "dpi/decode.hpp"
#include "dpi/table.hpp"

namespace dpi {
namespace {

constexpr size_t kMaxBlockedRows = 25;

struct AppStats {
    uint64_t flows = 0, packets = 0, bytes = 0, blockedFlows = 0;
};

struct DomainStats {
    std::set<std::string> apps;
    std::set<std::string> sources;
    uint64_t flows = 0, packets = 0;
    bool blocked = false;
};

std::map<std::string, AppStats> collectApps(const EngineResult& r) {
    std::map<std::string, AppStats> apps;
    for (const auto& f : r.flows) {
        AppStats& s = apps[f.app];
        ++s.flows;
        s.packets += f.packets;
        s.bytes += f.bytes;
        if (f.blocked) ++s.blockedFlows;
    }
    return apps;
}

std::map<std::string, DomainStats> collectDomains(const EngineResult& r) {
    std::map<std::string, DomainStats> domains;
    for (const auto& f : r.flows) {
        if (f.domain.empty()) continue;
        DomainStats& s = domains[f.domain];
        s.apps.insert(f.app);
        s.sources.insert(f.domainSource);
        ++s.flows;
        s.packets += f.packets;
        s.blocked = s.blocked || f.blocked;
    }
    return domains;
}

// Apps sorted by packet count (largest first), then by name.
std::vector<std::pair<std::string, AppStats>> sortedApps(const EngineResult& r) {
    auto map = collectApps(r);
    std::vector<std::pair<std::string, AppStats>> apps(map.begin(), map.end());
    std::stable_sort(apps.begin(), apps.end(),
                     [](const auto& a, const auto& b) { return a.second.packets > b.second.packets; });
    return apps;
}

std::vector<const Flow*> sortedFlows(const EngineResult& r) {
    std::vector<const Flow*> flows;
    for (const auto& f : r.flows) flows.push_back(&f);
    std::sort(flows.begin(), flows.end(), [](const Flow* a, const Flow* b) {
        if (a->packets != b->packets) return a->packets > b->packets;
        if (a->client != b->client) return a->client < b->client;
        if (a->clientPort != b->clientPort) return a->clientPort < b->clientPort;
        if (a->server != b->server) return a->server < b->server;
        return a->serverPort < b->serverPort;
    });
    return flows;
}

std::string formatBytes(uint64_t bytes) {
    static const char* const kUnits[] = {"B", "KB", "MB", "GB", "TB"};
    double value = static_cast<double>(bytes);
    int unit = 0;
    while (value >= 1024 && unit < 4) {
        value /= 1024;
        ++unit;
    }
    char buf[32];
    if (unit == 0) std::snprintf(buf, sizeof buf, "%llu B", static_cast<unsigned long long>(bytes));
    else std::snprintf(buf, sizeof buf, "%.1f %s", value, kUnits[unit]);
    return buf;
}

std::string percent(uint64_t part, uint64_t whole) {
    char buf[16];
    std::snprintf(buf, sizeof buf, "%.1f%%", whole ? 100.0 * double(part) / double(whole) : 0.0);
    return buf;
}

std::string protocolName(uint8_t proto) {
    switch (proto) {
        case PROTO_TCP: return "TCP";
        case PROTO_UDP: return "UDP";
        case 1: return "ICMP";
        case 58: return "ICMPv6";
        default: return "IP/" + std::to_string(proto);
    }
}

std::string endpoint(const IpAddr& ip, uint16_t port, uint8_t proto) {
    bool hasPort = proto == PROTO_TCP || proto == PROTO_UDP;
    std::string addr = ip.family == 6 && hasPort ? "[" + ip.toString() + "]" : ip.toString();
    return hasPort ? addr + ":" + std::to_string(port) : addr;
}

std::string sourceName(const std::string& source) {
    if (source == "tls-sni") return "TLS SNI";
    if (source == "http-host") return "HTTP Host";
    if (source == "dns") return "DNS";
    return source;
}

std::string n(uint64_t v) { return std::to_string(v); }

std::string join(const std::set<std::string>& items, const std::string& sep,
                 std::string (*fmt)(const std::string&) = nullptr) {
    std::string out;
    for (const auto& item : items) {
        if (!out.empty()) out += sep;
        out += fmt ? fmt(item) : item;
    }
    return out;
}

std::string jsonEscape(const std::string& s) {
    std::string out;
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof buf, "\\u%04x", c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

std::string q(const std::string& s) { return "\"" + jsonEscape(s) + "\""; }

std::string csvField(const std::string& s) {
    if (s.find_first_of(",\"\n\r") == std::string::npos) return s;
    std::string out = "\"";
    for (char c : s) {
        if (c == '"') out += '"';
        out += c;
    }
    return out + "\"";
}

}  // namespace

void printReport(const EngineResult& r, std::ostream& os) {
    const Totals& t = r.totals;

    TextTable summary("SUMMARY");
    summary.addColumn("Metric");
    summary.addColumn("Value", Align::Right);
    summary.addRow({"Packets", n(t.packets)});
    summary.addRow({"Bytes", formatBytes(t.bytes)});
    summary.addRow({"IPv4 / IPv6", n(t.ipv4) + " / " + n(t.ipv6)});
    summary.addRow({"TCP / UDP / other IP", n(t.tcp) + " / " + n(t.udp) + " / " + n(t.otherIp)});
    summary.addRow({"Non-IP frames", n(t.nonIp)});
    summary.addRow({"Flows", n(r.flows.size())});
    summary.addSeparator();
    summary.addRow({"Forwarded", n(t.forwarded) + "  (" + percent(t.forwarded, t.packets) + ")"});
    summary.addRow({"Dropped", n(t.dropped) + "  (" + percent(t.dropped, t.packets) + ")"});
    summary.addSeparator();
    char timing[64];
    std::snprintf(timing, sizeof timing, "%.1f ms", t.seconds * 1000.0);
    summary.addRow({"Processing time", timing});
    if (t.seconds > 0) {
        std::snprintf(timing, sizeof timing, "%.0f pkt/s", double(t.packets) / t.seconds);
        summary.addRow({"Throughput", timing});
    }
    os << '\n';
    summary.print(os);

    TextTable apps("APPLICATIONS");
    apps.addColumn("Application");
    apps.addColumn("Flows", Align::Right);
    apps.addColumn("Packets", Align::Right);
    apps.addColumn("Share", Align::Right);
    apps.addColumn("Bytes", Align::Right);
    apps.addColumn("Status");
    for (const auto& [name, s] : sortedApps(r)) {
        std::string status;
        if (s.blockedFlows == s.flows) status = "BLOCKED";
        else if (s.blockedFlows > 0) status = "BLOCKED " + n(s.blockedFlows) + "/" + n(s.flows);
        apps.addRow({name, n(s.flows), n(s.packets), percent(s.packets, t.packets), formatBytes(s.bytes), status});
    }
    os << '\n';
    apps.print(os);

    auto domains = collectDomains(r);
    if (!domains.empty()) {
        TextTable table("DOMAINS");
        table.addColumn("Domain");
        table.addColumn("Application");
        table.addColumn("Seen in");
        table.addColumn("Flows", Align::Right);
        table.addColumn("Packets", Align::Right);
        table.addColumn("Status");
        for (const auto& [domain, s] : domains) {
            table.addRow({domain, join(s.apps, ", "), join(s.sources, ", ", sourceName), n(s.flows),
                          n(s.packets), s.blocked ? "BLOCKED" : "allowed"});
        }
        os << '\n';
        table.print(os);
    }

    std::vector<const Flow*> blocked;
    for (const Flow* f : sortedFlows(r)) {
        if (f->blocked) blocked.push_back(f);
    }
    if (!blocked.empty()) {
        TextTable table("BLOCKED FLOWS");
        table.addColumn("Client");
        table.addColumn("Server");
        table.addColumn("Application");
        table.addColumn("Reason");
        table.addColumn("Dropped", Align::Right);
        for (size_t i = 0; i < blocked.size() && i < kMaxBlockedRows; ++i) {
            const Flow& f = *blocked[i];
            std::string server = endpoint(f.server, f.serverPort, f.proto);
            if (!f.domain.empty()) server += " (" + f.domain + ")";
            table.addRow({endpoint(f.client, f.clientPort, f.proto), server, f.app, f.blockReason,
                          n(f.droppedPackets)});
        }
        os << '\n';
        table.print(os);
        if (blocked.size() > kMaxBlockedRows) {
            os << "  ... and " << (blocked.size() - kMaxBlockedRows)
               << " more blocked flows (use --json or --csv for the full list)\n";
        }
    }

    TextTable workers("WORKER THREADS");
    workers.addColumn("Worker");
    workers.addColumn("Flows", Align::Right);
    workers.addColumn("Packets", Align::Right);
    workers.addColumn("Share", Align::Right);
    uint64_t ipPackets = 0;
    for (const auto& w : r.workers) ipPackets += w.packets;
    for (size_t i = 0; i < r.workers.size(); ++i) {
        const auto& w = r.workers[i];
        workers.addRow({"#" + n(i), n(w.flows), n(w.packets), percent(w.packets, ipPackets)});
    }
    os << '\n';
    workers.print(os);

    for (const auto& w : r.warnings) os << "\nWarning: " << w << '\n';
}

bool writeJsonReport(const EngineResult& r, const EngineConfig& config, const RuleSet& rules,
                     const std::string& path, std::string& err) {
    std::ofstream out(path, std::ios::trunc);
    if (!out) {
        err = "cannot create JSON report '" + path + "'";
        return false;
    }
    const Totals& t = r.totals;

    out << "{\n";
    out << "  \"tool\": \"Deep Packet Inspection\",\n";
    out << "  \"input\": " << q(config.inputPath) << ",\n";
    out << "  \"output\": " << (config.outputPath.empty() ? "null" : q(config.outputPath)) << ",\n";

    out << "  \"rules\": [";
    auto described = rules.describe();
    for (size_t i = 0; i < described.size(); ++i) out << (i ? ", " : "") << q(described[i]);
    out << "],\n";

    out << "  \"summary\": {\n"
        << "    \"packets\": " << t.packets << ",\n"
        << "    \"bytes\": " << t.bytes << ",\n"
        << "    \"forwarded\": " << t.forwarded << ",\n"
        << "    \"dropped\": " << t.dropped << ",\n"
        << "    \"ipv4\": " << t.ipv4 << ",\n"
        << "    \"ipv6\": " << t.ipv6 << ",\n"
        << "    \"tcp\": " << t.tcp << ",\n"
        << "    \"udp\": " << t.udp << ",\n"
        << "    \"other_ip\": " << t.otherIp << ",\n"
        << "    \"non_ip\": " << t.nonIp << ",\n"
        << "    \"flows\": " << r.flows.size() << ",\n"
        << "    \"seconds\": " << t.seconds << "\n"
        << "  },\n";

    out << "  \"applications\": [\n";
    auto apps = sortedApps(r);
    for (size_t i = 0; i < apps.size(); ++i) {
        const auto& [name, s] = apps[i];
        out << "    {\"name\": " << q(name) << ", \"flows\": " << s.flows << ", \"packets\": " << s.packets
            << ", \"bytes\": " << s.bytes << ", \"blocked_flows\": " << s.blockedFlows << "}"
            << (i + 1 < apps.size() ? "," : "") << "\n";
    }
    out << "  ],\n";

    out << "  \"domains\": [\n";
    auto domains = collectDomains(r);
    size_t di = 0;
    for (const auto& [domain, s] : domains) {
        out << "    {\"domain\": " << q(domain) << ", \"apps\": [";
        size_t ai = 0;
        for (const auto& app : s.apps) out << (ai++ ? ", " : "") << q(app);
        out << "], \"seen_in\": [";
        size_t si = 0;
        for (const auto& src : s.sources) out << (si++ ? ", " : "") << q(src);
        out << "], \"flows\": " << s.flows << ", \"packets\": " << s.packets
            << ", \"blocked\": " << (s.blocked ? "true" : "false") << "}"
            << (++di < domains.size() ? "," : "") << "\n";
    }
    out << "  ],\n";

    out << "  \"flows\": [\n";
    auto flows = sortedFlows(r);
    for (size_t i = 0; i < flows.size(); ++i) {
        const Flow& f = *flows[i];
        out << "    {\"client\": " << q(f.client.toString()) << ", \"client_port\": " << f.clientPort
            << ", \"server\": " << q(f.server.toString()) << ", \"server_port\": " << f.serverPort
            << ", \"protocol\": " << q(protocolName(f.proto)) << ", \"app\": " << q(f.app)
            << ", \"domain\": " << (f.domain.empty() ? "null" : q(f.domain))
            << ", \"domain_source\": " << (f.domainSource.empty() ? "null" : q(f.domainSource))
            << ", \"packets\": " << f.packets << ", \"bytes\": " << f.bytes
            << ", \"dropped_packets\": " << f.droppedPackets
            << ", \"blocked\": " << (f.blocked ? "true" : "false")
            << ", \"block_reason\": " << (f.blocked ? q(f.blockReason) : "null") << "}"
            << (i + 1 < flows.size() ? "," : "") << "\n";
    }
    out << "  ],\n";

    out << "  \"workers\": [\n";
    for (size_t i = 0; i < r.workers.size(); ++i) {
        out << "    {\"id\": " << i << ", \"flows\": " << r.workers[i].flows << ", \"packets\": "
            << r.workers[i].packets << "}" << (i + 1 < r.workers.size() ? "," : "") << "\n";
    }
    out << "  ],\n";

    out << "  \"warnings\": [";
    for (size_t i = 0; i < r.warnings.size(); ++i) out << (i ? ", " : "") << q(r.warnings[i]);
    out << "]\n}\n";

    if (!out) {
        err = "failed while writing JSON report '" + path + "'";
        return false;
    }
    return true;
}

bool writeCsvReport(const EngineResult& r, const std::string& path, std::string& err) {
    std::ofstream out(path, std::ios::trunc);
    if (!out) {
        err = "cannot create CSV report '" + path + "'";
        return false;
    }
    out << "client_ip,client_port,server_ip,server_port,protocol,app,domain,domain_source,"
           "packets,bytes,dropped_packets,blocked,block_reason\n";
    for (const Flow* fp : sortedFlows(r)) {
        const Flow& f = *fp;
        out << f.client.toString() << ',' << f.clientPort << ',' << f.server.toString() << ','
            << f.serverPort << ',' << protocolName(f.proto) << ',' << csvField(f.app) << ','
            << csvField(f.domain) << ',' << f.domainSource << ',' << f.packets << ',' << f.bytes << ','
            << f.droppedPackets << ',' << (f.blocked ? "yes" : "no") << ',' << csvField(f.blockReason)
            << '\n';
    }
    if (!out) {
        err = "failed while writing CSV report '" + path + "'";
        return false;
    }
    return true;
}

}  // namespace dpi
