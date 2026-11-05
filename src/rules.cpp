#include "dpi/rules.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>

#include "dpi/classify.hpp"
#include "dpi/inspect.hpp"

namespace dpi {
namespace {

std::string trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return "";
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

std::string joinApps() {
    std::string out;
    for (const auto& app : knownApps()) {
        if (!out.empty()) out += ", ";
        out += app;
    }
    return out;
}

// "block-ip" / "ip" -> "ip", etc. Returns "" for an unknown keyword.
std::string ruleKind(std::string keyword) {
    std::transform(keyword.begin(), keyword.end(), keyword.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (keyword.rfind("block-", 0) == 0) keyword = keyword.substr(6);
    if (keyword == "ip" || keyword == "app" || keyword == "domain" || keyword == "port") return keyword;
    return "";
}

}  // namespace

bool RuleSet::add(const std::string& kind, const std::string& rawValue, std::string& err) {
    std::string value = trim(rawValue);
    if (value.empty()) {
        err = "missing value for " + kind + " rule";
        return false;
    }

    if (kind == "ip") {
        IpPrefix prefix;
        if (!IpPrefix::parse(value, prefix)) {
            err = "invalid IP address or CIDR range '" + value + "'";
            return false;
        }
        ips_.push_back(prefix);
    } else if (kind == "app") {
        std::string app = canonicalAppName(value);
        if (app.empty()) {
            err = "unknown app '" + value + "'. Known apps: " + joinApps();
            return false;
        }
        if (std::find(apps_.begin(), apps_.end(), app) == apps_.end()) apps_.push_back(app);
    } else if (kind == "domain") {
        std::string pattern = normalizeHost(value);
        if (pattern.rfind("*.", 0) == 0) pattern = pattern.substr(2);
        if (pattern.empty()) {
            err = "invalid domain pattern '" + value + "'";
            return false;
        }
        domains_.push_back(pattern);
    } else if (kind == "port") {
        bool digits = !value.empty() && value.size() <= 5 &&
                      std::all_of(value.begin(), value.end(), [](char c) { return c >= '0' && c <= '9'; });
        int port = digits ? std::stoi(value) : 0;
        if (port < 1 || port > 65535) {
            err = "invalid port '" + value + "' (expected 1-65535)";
            return false;
        }
        ports_.push_back(static_cast<uint16_t>(port));
    } else {
        err = "unknown rule type '" + kind + "'";
        return false;
    }
    return true;
}

bool RuleSet::loadFile(const std::string& path, std::string& err) {
    std::ifstream in(path);
    if (!in) {
        err = "cannot open rules file '" + path + "'";
        return false;
    }
    std::string line;
    int lineNo = 0;
    while (std::getline(in, line)) {
        ++lineNo;
        size_t hash = line.find('#');
        if (hash != std::string::npos) line.resize(hash);
        line = trim(line);
        if (line.empty()) continue;

        size_t space = line.find_first_of(" \t");
        std::string keyword = line.substr(0, space);
        std::string value = space == std::string::npos ? "" : line.substr(space + 1);
        std::string kind = ruleKind(keyword);
        std::string ruleErr;
        if (kind.empty()) {
            ruleErr = "unknown rule '" + keyword + "' (use block-ip, block-app, block-domain or block-port)";
        } else if (add(kind, value, ruleErr)) {
            continue;
        }
        err = path + ":" + std::to_string(lineNo) + ": " + ruleErr;
        return false;
    }
    return true;
}

Verdict RuleSet::checkEndpoints(const IpAddr& a, uint16_t aPort, const IpAddr& b, uint16_t bPort,
                                bool hasPorts) const {
    for (const auto& prefix : ips_) {
        if (prefix.contains(a) || prefix.contains(b)) return {true, "ip " + prefix.toString()};
    }
    if (hasPorts) {
        for (uint16_t port : ports_) {
            if (aPort == port || bPort == port) return {true, "port " + std::to_string(port)};
        }
    }
    return {};
}

Verdict RuleSet::checkContent(const std::string& app, const std::string& domain) const {
    for (const auto& blockedApp : apps_) {
        if (app == blockedApp) return {true, "app " + app};
    }
    if (!domain.empty()) {
        for (const auto& pattern : domains_) {
            // "tiktok.com" blocks that domain and its subdomains;
            // a bare word like "tiktok" blocks any domain containing it.
            bool hit = pattern.find('.') != std::string::npos ? domainMatches(domain, pattern)
                                                              : domain.find(pattern) != std::string::npos;
            if (hit) return {true, "domain " + pattern};
        }
    }
    return {};
}

bool RuleSet::empty() const {
    return ips_.empty() && apps_.empty() && domains_.empty() && ports_.empty();
}

std::vector<std::string> RuleSet::describe() const {
    std::vector<std::string> out;
    for (const auto& p : ips_) out.push_back("block ip     " + p.toString());
    for (const auto& a : apps_) out.push_back("block app    " + a);
    for (const auto& d : domains_) out.push_back("block domain " + d);
    for (uint16_t p : ports_) out.push_back("block port   " + std::to_string(p));
    return out;
}

}  // namespace dpi
