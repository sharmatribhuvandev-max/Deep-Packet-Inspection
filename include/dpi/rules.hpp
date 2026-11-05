#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "dpi/ip.hpp"

namespace dpi {

struct Verdict {
    bool block = false;
    std::string reason;  // e.g. "app YouTube", "ip 10.0.0.0/8"
};

// The set of blocking rules. It is filled in before processing starts and is
// read-only afterwards, so worker threads can share it without locking.
class RuleSet {
public:
    // kind is one of: "ip", "app", "domain", "port".
    bool add(const std::string& kind, const std::string& value, std::string& err);

    // Loads a rules file. Format, one rule per line ('#' starts a comment):
    //   block-ip 192.168.1.50        block-ip 10.0.0.0/8
    //   block-app YouTube            block-domain tiktok.com
    //   block-port 6881
    bool loadFile(const std::string& path, std::string& err);

    // Rules that can be decided from the first packet of a flow.
    Verdict checkEndpoints(const IpAddr& a, uint16_t aPort, const IpAddr& b, uint16_t bPort,
                           bool hasPorts) const;

    // Rules that need the flow to be classified first.
    Verdict checkContent(const std::string& app, const std::string& domain) const;

    bool empty() const;
    std::vector<std::string> describe() const;

private:
    std::vector<IpPrefix> ips_;
    std::vector<std::string> apps_;     // canonical app names
    std::vector<std::string> domains_;  // lower-case patterns
    std::vector<uint16_t> ports_;
};

}  // namespace dpi
