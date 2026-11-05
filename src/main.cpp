// Deep Packet Inspection - command-line entry point (dpi.exe).

#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "dpi/engine.hpp"
#include "dpi/report.hpp"
#include "dpi/rules.hpp"
#include "dpi/table.hpp"

namespace {

constexpr const char* kVersion = "1.0.0";

void printUsage(std::ostream& os) {
    os << "Deep Packet Inspection " << kVersion << " - analyse and filter pcap captures\n"
       << "\n"
       << "Usage:\n"
       << "  dpi <input.pcap> [options]\n"
       << "\n"
       << "Output:\n"
       << "  -o, --output <file>      Write allowed packets to a new pcap file\n"
       << "      --json <file>        Save the full report as JSON\n"
       << "      --csv <file>         Save one row per flow as CSV\n"
       << "  -q, --quiet              Do not print the report tables\n"
       << "\n"
       << "Blocking rules (each can be repeated):\n"
       << "      --rules <file>       Load rules from a file (see samples/rules.example.txt)\n"
       << "      --block-ip <ip|cidr> Block traffic to or from an address or range\n"
       << "      --block-app <app>    Block an application, e.g. YouTube\n"
       << "      --block-domain <d>   Block a domain and its subdomains (tiktok.com),\n"
       << "                           or any domain containing a word (tiktok)\n"
       << "      --block-port <port>  Block traffic using a TCP/UDP port\n"
       << "\n"
       << "Performance:\n"
       << "  -w, --workers <n>        Worker threads (default: CPU cores, max 4)\n"
       << "\n"
       << "Other:\n"
       << "  -h, --help               Show this help\n"
       << "  -v, --version            Show the version\n"
       << "\n"
       << "Example:\n"
       << "  dpi samples/sample.pcap -o clean.pcap --block-app YouTube --block-ip 192.168.1.50\n";
}

struct Options {
    dpi::EngineConfig engine;
    std::string jsonPath;
    std::string csvPath;
    bool quiet = false;
};

// Returns 0 on success, or the exit code to stop with.
int parseArgs(int argc, char** argv, Options& opts, dpi::RuleSet& rules) {
    unsigned cores = std::thread::hardware_concurrency();
    opts.engine.workers = cores == 0 ? 2 : (cores < 4 ? cores : 4);

    auto fail = [](const std::string& msg) {
        std::cerr << "dpi: " << msg << "\n"
                  << "Run 'dpi --help' for usage.\n";
        return 2;
    };

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        auto value = [&](std::string& out) {
            if (i + 1 >= argc) return false;
            out = argv[++i];
            return true;
        };
        std::string v, err;

        if (arg == "-h" || arg == "--help") {
            printUsage(std::cout);
            return -1;
        } else if (arg == "-v" || arg == "--version") {
            std::cout << "Deep Packet Inspection " << kVersion << "\n";
            return -1;
        } else if (arg == "-o" || arg == "--output") {
            if (!value(opts.engine.outputPath)) return fail(arg + " needs a file name");
        } else if (arg == "--json") {
            if (!value(opts.jsonPath)) return fail(arg + " needs a file name");
        } else if (arg == "--csv") {
            if (!value(opts.csvPath)) return fail(arg + " needs a file name");
        } else if (arg == "-q" || arg == "--quiet") {
            opts.quiet = true;
        } else if (arg == "-w" || arg == "--workers") {
            if (!value(v)) return fail(arg + " needs a number");
            int count = 0;
            try { count = std::stoi(v); } catch (...) { count = 0; }
            if (count < 1 || count > 64) return fail("worker count must be between 1 and 64");
            opts.engine.workers = static_cast<unsigned>(count);
        } else if (arg == "--rules") {
            if (!value(v)) return fail(arg + " needs a file name");
            if (!rules.loadFile(v, err)) return fail(err);
        } else if (arg.rfind("--block-", 0) == 0) {
            std::string kind = arg.substr(8);
            if (kind != "ip" && kind != "app" && kind != "domain" && kind != "port") {
                return fail("unknown option '" + arg + "'");
            }
            if (!value(v)) return fail(arg + " needs a value");
            if (!rules.add(kind, v, err)) return fail(err);
        } else if (!arg.empty() && arg[0] == '-') {
            return fail("unknown option '" + arg + "'");
        } else if (opts.engine.inputPath.empty()) {
            opts.engine.inputPath = arg;
        } else {
            return fail("unexpected argument '" + arg + "' (only one input file is allowed)");
        }
    }

    if (opts.engine.inputPath.empty()) {
        printUsage(std::cerr);
        return 2;
    }
    if (!opts.engine.outputPath.empty() && opts.engine.outputPath == opts.engine.inputPath) {
        return fail("output file must be different from the input file");
    }
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    dpi::enableUtf8Console();

    Options opts;
    dpi::RuleSet rules;
    int code = parseArgs(argc, argv, opts, rules);
    if (code == -1) return 0;
    if (code != 0) return code;

    if (!opts.quiet) {
        std::cout << "Deep Packet Inspection " << kVersion << "\n";
        std::cout << "Input:   " << opts.engine.inputPath << "\n";
        if (!opts.engine.outputPath.empty()) std::cout << "Output:  " << opts.engine.outputPath << "\n";
        std::cout << "Workers: " << opts.engine.workers << "\n";
        if (rules.empty()) {
            std::cout << "Rules:   none (analysis only)\n";
        } else {
            std::cout << "Rules:\n";
            for (const auto& line : rules.describe()) std::cout << "  - " << line << "\n";
        }
    }

    dpi::EngineResult result;
    std::string err;
    if (!dpi::runEngine(opts.engine, rules, result, err)) {
        std::cerr << "dpi: " << err << "\n";
        return 1;
    }

    if (!opts.quiet) dpi::printReport(result, std::cout);

    if (!opts.jsonPath.empty()) {
        if (!dpi::writeJsonReport(result, opts.engine, rules, opts.jsonPath, err)) {
            std::cerr << "dpi: " << err << "\n";
            return 1;
        }
        if (!opts.quiet) std::cout << "\nJSON report written to " << opts.jsonPath << "\n";
    }
    if (!opts.csvPath.empty()) {
        if (!dpi::writeCsvReport(result, opts.csvPath, err)) {
            std::cerr << "dpi: " << err << "\n";
            return 1;
        }
        if (!opts.quiet) std::cout << "CSV report written to " << opts.csvPath << "\n";
    }
    if (!opts.quiet && !opts.engine.outputPath.empty()) {
        std::cout << "Filtered capture written to " << opts.engine.outputPath << " ("
                  << result.totals.forwarded << " of " << result.totals.packets << " packets kept)\n";
    }
    return 0;
}
