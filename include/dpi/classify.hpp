#pragma once

#include <string>
#include <vector>

namespace dpi {

// True if `host` is `domain` itself or one of its subdomains:
// domainMatches("api.x.com", "x.com") is true, ("netflix.com", "x.com") is false.
bool domainMatches(const std::string& host, const std::string& domain);

// Maps a hostname to an application name ("YouTube"), or "" if unknown.
std::string appForDomain(const std::string& host);

// Every application name Deep Packet Inspection can recognise.
const std::vector<std::string>& knownApps();

// Case-insensitive lookup with aliases ("youtube" -> "YouTube",
// "twitter" / "x" -> "Twitter/X"). Returns "" if not recognised.
std::string canonicalAppName(const std::string& name);

}  // namespace dpi
