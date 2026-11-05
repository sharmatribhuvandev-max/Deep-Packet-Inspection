#pragma once

#include <ostream>
#include <string>

#include "dpi/engine.hpp"
#include "dpi/rules.hpp"

namespace dpi {

// Prints the summary, application, domain, blocked-flow and worker tables.
void printReport(const EngineResult& result, std::ostream& os);

// Writes the full report (summary, apps, domains, every flow) as JSON.
bool writeJsonReport(const EngineResult& result, const EngineConfig& config, const RuleSet& rules,
                     const std::string& path, std::string& err);

// Writes one CSV row per flow.
bool writeCsvReport(const EngineResult& result, const std::string& path, std::string& err);

}  // namespace dpi
