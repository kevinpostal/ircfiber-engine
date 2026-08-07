module ircfiber.web.common;

import std.string : strip, split;

import vibe.http.server : HTTPServerRequest;

/// Resolves the real client IP from a request, checking proxy headers
/// in order of trustworthiness before falling back to the raw TCP address.
///
/// Precedence:
///   1. CF-Connecting-IP  — Cloudflare Tunnel (cloudflared)
///   2. X-Forwarded-For   — standard reverse-proxy header (Caddy, nginx, etc.)
///   3. X-Real-IP         — nginx-style single-IP header
///   4. Raw TCP peer      — req.clientAddress
///
/// For multi-value headers (X-Forwarded-For, CF-Connecting-IP) the
/// leftmost (original client) IP is returned.
string getClientIp(scope HTTPServerRequest req) {
    // 1. Cloudflare Tunnel header
    auto cf = req.headers.get("CF-Connecting-IP", "");
    if (cf.length > 0) {
        auto v = cf.split(",")[0].strip();
        if (v.length > 0) return v;
    }

    // 2. Standard reverse-proxy header (comma-separated chain)
    auto xff = req.headers.get("X-Forwarded-For", "");
    if (xff.length > 0) {
        auto v = xff.split(",")[0].strip();
        if (v.length > 0) return v;
    }

    // 3. Single-IP header (nginx, some load balancers)
    auto xri = req.headers.get("X-Real-IP", "");
    if (xri.length > 0) {
        auto v = xri.strip();
        if (v.length > 0) return v;
    }

    // 4. Raw TCP peer address
    try {
        auto addr = req.clientAddress.toAddressString();
        if (addr.length > 0) return addr;
    } catch (Exception) {}
    return "unknown";
}
