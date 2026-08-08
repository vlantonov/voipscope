#include "SipParser.hpp"
#include "SdpParser.hpp"

#include <algorithm>
#include <charconv>
#include <string>
#include <string_view>
#include <vector>

namespace voipscope {

namespace {

// Advance past "\r\n" or "\n".
// Returns the line (without trailing \r\n); advances `remaining`.
// Returns empty string_view when no more lines remain.
std::string_view consumeLine(std::string_view& remaining) {
    if (remaining.empty()) return {};
    auto pos = remaining.find('\n');
    std::string_view line;
    if (pos == std::string_view::npos) {
        line      = remaining;
        remaining = {};
    } else {
        line      = remaining.substr(0, pos);
        remaining = remaining.substr(pos + 1);
    }
    if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
    return line;
}

std::string_view trim(std::string_view sv) {
    while (!sv.empty() && (sv.front() == ' ' || sv.front() == '\t')) sv.remove_prefix(1);
    while (!sv.empty() && (sv.back()  == ' ' || sv.back()  == '\t')) sv.remove_suffix(1);
    return sv;
}

// Extract parameter value: search for ";name=" in headerValue.
// Returns empty string if not found.
std::string extractParam(std::string_view headerValue, std::string_view paramName) {
    // Build search string ";paramName=" (case-insensitive would require manual scan)
    std::string search = ";";
    search += paramName;
    search += "=";

    // Case-insensitive search
    std::string lower(headerValue);
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    std::string lowerSearch(search);
    std::transform(lowerSearch.begin(), lowerSearch.end(), lowerSearch.begin(),
                   [](unsigned char c){ return std::tolower(c); });

    auto pos = lower.find(lowerSearch);
    if (pos == std::string::npos) return {};

    std::string_view rest = headerValue.substr(pos + search.size());
    auto end = rest.find(';');
    if (end != std::string_view::npos) rest = rest.substr(0, end);
    return std::string(trim(rest));
}

// Extract Via branch= parameter from the top Via header value
std::string extractViaBranch(std::string_view viaValue) {
    return extractParam(viaValue, "branch");
}

// Parse integer from string_view; returns 0 on failure.
template<typename T>
T parseUint(std::string_view sv) {
    sv = trim(sv);
    T value{};
    auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), value);
    if (ec != std::errc{}) return T{};
    return value;
}

struct Header {
    std::string name;
    std::string value;
};

// Compact form names: c→Content-Type, i→Call-ID, f→From, t→To, v→Via, l→Content-Length
std::string expandCompactName(std::string_view name) {
    if (name.size() == 1) {
        switch (std::tolower(static_cast<unsigned char>(name[0]))) {
            case 'c': return "content-type";
            case 'i': return "call-id";
            case 'f': return "from";
            case 't': return "to";
            case 'v': return "via";
            case 'l': return "content-length";
            case 'm': return "contact";
            default:  break;
        }
    }
    std::string lower(name);
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    return lower;
}

// Find header value by lowercase name; returns empty string_view if not found.
std::string_view findHeader(const std::vector<Header>& headers, std::string_view name) {
    std::string lname(name);
    std::transform(lname.begin(), lname.end(), lname.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    for (const auto& h : headers) {
        if (h.name == lname) return h.value;
    }
    return {};
}

} // namespace

std::optional<SipMessage> parseSip(std::string_view payload) {
    if (payload.empty()) return std::nullopt;

    // Quick heuristic (§5.1): must start with known method or "SIP/"
    constexpr std::string_view kMethods[] = {
        "INVITE ", "ACK ", "BYE ", "CANCEL ", "OPTIONS ", "REGISTER "
    };
    bool looksLikeSip = payload.starts_with("SIP/");
    if (!looksLikeSip) {
        for (auto m : kMethods) {
            if (payload.starts_with(m)) { looksLikeSip = true; break; }
        }
    }
    if (!looksLikeSip) return std::nullopt;

    std::string_view remaining = payload;
    SipMessage msg;

    // -----------------------------------------------------------------------
    // Step 1: First line (request-line or status-line)
    // -----------------------------------------------------------------------
    std::string_view firstLine = consumeLine(remaining);
    if (firstLine.empty()) return std::nullopt;

    if (firstLine.starts_with("SIP/")) {
        // status-line: SIP/2.0 <statusCode> <reasonPhrase>
        auto p1 = firstLine.find(' ');
        if (p1 == std::string_view::npos) return std::nullopt;
        std::string_view rest = firstLine.substr(p1 + 1);
        auto p2 = rest.find(' ');
        if (p2 == std::string_view::npos) return std::nullopt;
        msg.statusCode   = parseUint<int>(rest.substr(0, p2));
        msg.reasonPhrase = std::string(trim(rest.substr(p2 + 1)));
        msg.method       = SipMethod::Unknown;
    } else {
        // request-line: <method> <requestUri> SIP/2.0
        auto p1 = firstLine.find(' ');
        if (p1 == std::string_view::npos) return std::nullopt;
        std::string_view methodSv = firstLine.substr(0, p1);
        std::string_view rest     = firstLine.substr(p1 + 1);
        auto p2 = rest.rfind(' ');
        if (p2 == std::string_view::npos) return std::nullopt;
        msg.method     = sipMethodFromString(methodSv);
        msg.requestUri = std::string(trim(rest.substr(0, p2)));
        // statusCode stays 0 (marks this as a request)
    }

    // -----------------------------------------------------------------------
    // Step 2: Header loop (with folding support per RFC 3261 §7.3.1)
    // -----------------------------------------------------------------------
    std::vector<Header> headers;

    while (!remaining.empty()) {
        std::string_view line = consumeLine(remaining);

        // Blank line → end of headers
        if (line.empty()) break;

        // Folded continuation line
        if ((line[0] == ' ' || line[0] == '\t') && !headers.empty()) {
            headers.back().value += ' ';
            headers.back().value += std::string(trim(line));
            continue;
        }

        // Header field: name ":" *SP value
        auto colon = line.find(':');
        if (colon == std::string_view::npos) continue;

        std::string_view name  = trim(line.substr(0, colon));
        std::string_view value = trim(line.substr(colon + 1));

        headers.push_back({ expandCompactName(name), std::string(value) });
    }

    // -----------------------------------------------------------------------
    // Step 3: Extract mandatory headers (FR-06, FR-07, FR-09)
    // -----------------------------------------------------------------------
    msg.callId = std::string(trim(findHeader(headers, "call-id")));
    msg.from   = std::string(trim(findHeader(headers, "from")));
    msg.to     = std::string(trim(findHeader(headers, "to")));

    std::string_view cseqVal = findHeader(headers, "cseq");

    // Mandatory check (FR-09)
    if (msg.callId.empty() || msg.from.empty() || msg.to.empty() || cseqVal.empty()) {
        return std::nullopt;
    }

    // Extract tags
    msg.fromTag = extractParam(msg.from, "tag");
    msg.toTag   = extractParam(msg.to,   "tag");

    // Parse CSeq: "<number> <method>"
    cseqVal = trim(cseqVal);
    {
        auto sp = cseqVal.find(' ');
        if (sp != std::string_view::npos) {
            msg.cseqNumber = parseUint<uint32_t>(cseqVal.substr(0, sp));
            msg.cseqMethod = sipMethodFromString(trim(cseqVal.substr(sp + 1)));
        }
    }

    // Via branch= from topmost Via
    std::string_view viaVal = findHeader(headers, "via");
    if (!viaVal.empty()) {
        msg.viaBranch = extractViaBranch(viaVal);
    }

    // Optional headers
    msg.contact       = std::string(findHeader(headers, "contact"));
    msg.contentType   = std::string(trim(findHeader(headers, "content-type")));
    msg.contentLength = parseUint<uint32_t>(findHeader(headers, "content-length"));

    // -----------------------------------------------------------------------
    // Step 4: Body extraction and SDP dispatch (FR-08)
    // -----------------------------------------------------------------------
    if (!remaining.empty()) {
        // Trim leading \r\n that may remain after blank line
        if (remaining.starts_with("\r\n")) remaining.remove_prefix(2);
        else if (remaining.starts_with("\n")) remaining.remove_prefix(1);

        std::string_view body = remaining.substr(
            0, std::min<std::size_t>(remaining.size(), msg.contentLength));

        // Detect application/sdp (case-insensitive substring)
        std::string ctLower = msg.contentType;
        std::transform(ctLower.begin(), ctLower.end(), ctLower.begin(),
                       [](unsigned char c){ return std::tolower(c); });
        if (ctLower.find("application/sdp") != std::string::npos) {
            msg.sdp = parseSdp(body);
        }
    }

    return msg;
}

} // namespace voipscope
