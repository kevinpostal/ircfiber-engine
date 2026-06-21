//! # Engine runtime configuration
//!
//! Reads IRCFIBER_* environment variables.

const std = @import("std");
const Allocator = std.mem.Allocator;

const c = @cImport({
    @cInclude("stdlib.h");
});

pub const EngineConfig = struct {
    server_id: []const u8,
    redis_host: []const u8,
    redis_port: u16,
    bind_address: []const u8,
    admin_port: u16,
    log_level: []const u8,
    priority: i32,
    max_connections: i32,
    fallback_only: bool,
    reload_from_pid: ?u32,

    pub fn init(alloc: Allocator) !EngineConfig {
        const server_id = try envOrDefault(alloc, "IRCFIBER_SERVER_ID", "zig1");
        errdefer alloc.free(server_id);

        const redis_url = try envOrDefault(alloc, "IRCFIBER_REDIS_URL", "redis://127.0.0.1:6379/0");
        defer alloc.free(redis_url);
        const redis = try parseRedisUrl(alloc, redis_url);
        errdefer alloc.free(redis.host);

        const bind_address = try envOrDefault(alloc, "IRCFIBER_BIND_ADDRESS", "0.0.0.0");
        errdefer alloc.free(bind_address);

        const admin_port = envOrDefaultU16(alloc, "IRCFIBER_ADMIN_PORT", 8091);
        const log_level = try envOrDefault(alloc, "IRCFIBER_LOG_LEVEL", "info");
        errdefer alloc.free(log_level);
        const priority = envOrDefaultI32(alloc, "IRCFIBER_ENGINE_PRIORITY", 0);
        const max_connections = envOrDefaultI32(alloc, "IRCFIBER_ENGINE_MAX_CONNS", 0);
        const fallback_only = envOrDefaultBool(alloc, "IRCFIBER_ENGINE_FALLBACK");
        const reload_from_pid = envOrDefaultU32(alloc, "IRCFIBER_RELOAD_FROM_PID");

        return .{
            .server_id = server_id,
            .redis_host = redis.host,
            .redis_port = redis.port,
            .bind_address = bind_address,
            .admin_port = admin_port,
            .log_level = log_level,
            .priority = priority,
            .max_connections = max_connections,
            .fallback_only = fallback_only,
            .reload_from_pid = reload_from_pid,
        };
    }

    pub fn deinit(self: *EngineConfig, alloc: Allocator) void {
        alloc.free(self.server_id);
        alloc.free(self.redis_host);
        alloc.free(self.bind_address);
        alloc.free(self.log_level);
    }
};

const RedisEndpoint = struct {
    host: []const u8,
    port: u16,
};

fn parseRedisUrl(alloc: Allocator, url: []const u8) !RedisEndpoint {
    const prefix = "redis://";
    if (!std.mem.startsWith(u8, url, prefix)) {
        return error.InvalidRedisUrl;
    }
    const rest = url[prefix.len..];
    const path_sep = std.mem.lastIndexOfScalar(u8, rest, '/');
    const host_port = if (path_sep) |i| rest[0..i] else rest;

    const port_sep = std.mem.lastIndexOfScalar(u8, host_port, ':');
    if (port_sep) |i| {
        const host = try alloc.dupe(u8, host_port[0..i]);
        const port = std.fmt.parseUnsigned(u16, host_port[i + 1 ..], 10) catch return error.InvalidRedisUrl;
        return .{ .host = host, .port = port };
    } else {
        return .{ .host = try alloc.dupe(u8, host_port), .port = 6379 };
    }
}

fn envOrDefault(alloc: Allocator, key: []const u8, default: []const u8) ![]const u8 {
    const val = c.getenv(key.ptr) orelse return try alloc.dupe(u8, default);
    return try alloc.dupe(u8, std.mem.span(val));
}

fn envOrDefaultU16(_: Allocator, key: []const u8, default: u16) u16 {
    const val = c.getenv(key.ptr) orelse return default;
    const s = std.mem.span(val);
    return std.fmt.parseUnsigned(u16, s, 10) catch default;
}

fn envOrDefaultI32(_: Allocator, key: []const u8, default: i32) i32 {
    const val = c.getenv(key.ptr) orelse return default;
    const s = std.mem.span(val);
    return std.fmt.parseInt(i32, s, 10) catch default;
}

fn envOrDefaultBool(_: Allocator, key: []const u8) bool {
    const val = c.getenv(key.ptr) orelse return false;
    const s = std.mem.span(val);
    return std.mem.eql(u8, s, "true") or std.mem.eql(u8, s, "1") or std.mem.eql(u8, s, "yes");
}

fn envOrDefaultU32(_: Allocator, key: []const u8) ?u32 {
    const val = c.getenv(key.ptr) orelse return null;
    const s = std.mem.span(val);
    return std.fmt.parseUnsigned(u32, s, 10) catch null;
}

// ── Tests ────────────────────────────────────────────────────────

test "parseRedisUrl defaults" {
    const alloc = std.testing.allocator;
    const ep = try parseRedisUrl(alloc, "redis://127.0.0.1:6379/0");
    defer alloc.free(ep.host);
    try std.testing.expectEqualStrings("127.0.0.1", ep.host);
    try std.testing.expectEqual(@as(u16, 6379), ep.port);
}

test "parseRedisUrl custom port" {
    const alloc = std.testing.allocator;
    const ep = try parseRedisUrl(alloc, "redis://redis.example.com:6380/");
    defer alloc.free(ep.host);
    try std.testing.expectEqualStrings("redis.example.com", ep.host);
    try std.testing.expectEqual(@as(u16, 6380), ep.port);
}

test "parseRedisUrl no port" {
    const alloc = std.testing.allocator;
    const ep = try parseRedisUrl(alloc, "redis://localhost");
    defer alloc.free(ep.host);
    try std.testing.expectEqualStrings("localhost", ep.host);
    try std.testing.expectEqual(@as(u16, 6379), ep.port);
}
