#include "dpi/classify.hpp"

#include <algorithm>
#include <cctype>
#include <utility>

namespace dpi {
namespace {

struct Signature {
    std::string app;
    std::vector<std::string> domains;
};

// Each app is identified by the domains it serves from. Matching is by whole
// domain suffix, so "x.com" matches "api.x.com" but never "netflix.com".
const std::vector<Signature>& signatures() {
    static const std::vector<Signature> kSignatures = {
        {"YouTube", {"youtube.com", "ytimg.com", "googlevideo.com", "youtu.be", "youtube-nocookie.com"}},
        {"Google", {"google.com", "googleapis.com", "gstatic.com", "gmail.com", "googleusercontent.com", "google.co.in"}},
        {"Facebook", {"facebook.com", "fbcdn.net", "fb.com", "facebook.net", "messenger.com"}},
        {"Instagram", {"instagram.com", "cdninstagram.com"}},
        {"WhatsApp", {"whatsapp.com", "whatsapp.net", "wa.me"}},
        {"Twitter/X", {"twitter.com", "twimg.com", "x.com", "t.co"}},
        {"Netflix", {"netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com", "nflxso.net"}},
        {"Amazon", {"amazon.com", "amazon.in", "amazonaws.com", "cloudfront.net", "media-amazon.com"}},
        {"Microsoft", {"microsoft.com", "live.com", "outlook.com", "office.com", "office365.com", "bing.com",
                       "msn.com", "azure.com", "windows.net", "windowsupdate.com"}},
        {"Apple", {"apple.com", "icloud.com", "mzstatic.com", "itunes.com"}},
        {"Telegram", {"telegram.org", "t.me", "telegram.me"}},
        {"TikTok", {"tiktok.com", "tiktokcdn.com", "tiktokv.com", "byteoversea.com"}},
        {"Spotify", {"spotify.com", "scdn.co", "spotifycdn.com"}},
        {"Zoom", {"zoom.us", "zoom.com"}},
        {"Discord", {"discord.com", "discord.gg", "discordapp.com", "discordapp.net"}},
        {"GitHub", {"github.com", "githubusercontent.com", "github.io", "githubassets.com"}},
        {"LinkedIn", {"linkedin.com", "licdn.com"}},
        {"Reddit", {"reddit.com", "redditmedia.com", "redditstatic.com", "redd.it"}},
        {"Wikipedia", {"wikipedia.org", "wikimedia.org"}},
        {"Cloudflare", {"cloudflare.com", "cloudflare-dns.com"}},
    };
    return kSignatures;
}

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

}  // namespace

bool domainMatches(const std::string& host, const std::string& domain) {
    if (domain.empty() || host.size() < domain.size()) return false;
    if (host.compare(host.size() - domain.size(), domain.size(), domain) != 0) return false;
    return host.size() == domain.size() || host[host.size() - domain.size() - 1] == '.';
}

std::string appForDomain(const std::string& host) {
    for (const auto& sig : signatures()) {
        for (const auto& d : sig.domains) {
            if (domainMatches(host, d)) return sig.app;
        }
    }
    return "";
}

const std::vector<std::string>& knownApps() {
    static const std::vector<std::string> kApps = [] {
        std::vector<std::string> apps;
        for (const auto& sig : signatures()) apps.push_back(sig.app);
        return apps;
    }();
    return kApps;
}

std::string canonicalAppName(const std::string& name) {
    static const std::vector<std::pair<std::string, std::string>> kAliases = {
        {"twitter", "Twitter/X"}, {"x", "Twitter/X"}, {"fb", "Facebook"}, {"insta", "Instagram"},
        {"yt", "YouTube"},        {"msft", "Microsoft"},
    };
    std::string wanted = lower(name);
    for (const auto& app : knownApps()) {
        if (lower(app) == wanted) return app;
    }
    for (const auto& [alias, app] : kAliases) {
        if (alias == wanted) return app;
    }
    return "";
}

}  // namespace dpi
