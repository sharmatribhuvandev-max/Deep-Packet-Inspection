#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "dpi/flow.hpp"
#include "dpi/rules.hpp"

namespace dpi {

struct EngineConfig {
    std::string inputPath;
    std::string outputPath;  // empty = analyse only, write nothing
    unsigned workers = 4;
};

struct Totals {
    uint64_t packets = 0;
    uint64_t bytes = 0;
    uint64_t forwarded = 0;
    uint64_t dropped = 0;
    uint64_t ipv4 = 0;
    uint64_t ipv6 = 0;
    uint64_t tcp = 0;
    uint64_t udp = 0;
    uint64_t otherIp = 0;   // ICMP and other IP protocols
    uint64_t nonIp = 0;     // ARP, LLDP, ... (always forwarded)
    double seconds = 0;
};

struct WorkerStats {
    uint64_t packets = 0;
    uint64_t flows = 0;
};

struct EngineResult {
    Totals totals;
    std::vector<Flow> flows;
    std::vector<WorkerStats> workers;
    std::vector<std::string> warnings;
};

// Reads the input capture, classifies every flow, applies the rules and
// (optionally) writes the allowed packets, in their original order, to the output.
bool runEngine(const EngineConfig& config, const RuleSet& rules, EngineResult& result,
               std::string& err);

}  // namespace dpi
