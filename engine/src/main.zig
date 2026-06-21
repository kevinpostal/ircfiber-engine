const std = @import("std");
const connection = @import("connection.zig");
const manager = @import("manager.zig");
const ipc_mod = @import("ipc.zig");
const engine_config = @import("config.zig");
const reload = @import("reload.zig");
const posix = std.posix;

var reload_requested: std.atomic.Value(bool) = .init(false);
var drain_requested: std.atomic.Value(bool) = .init(false);

fn reloadHandler(sig: posix.SIG) callconv(.c) void {
    _ = sig;
    reload_requested.store(true, .monotonic);
}

fn drainHandler(sig: posix.SIG) callconv(.c) void {
    _ = sig;
    drain_requested.store(true, .monotonic);
}

pub fn main() !void {
    const alloc = std.heap.c_allocator;

    var cfg = try engine_config.EngineConfig.init(alloc);
    defer cfg.deinit(alloc);

    std.debug.print("IRC Fiber Engine v0.5.0 — Zig\nServer: {s}\nRedis: {s}:{d}\nAdmin: {s}:{d}\n", .{
        cfg.server_id, cfg.redis_host, cfg.redis_port, cfg.bind_address, cfg.admin_port,
    });

    // ── Graceful reload signal handler ───────────────────────
    {
        const mask = posix.sigemptyset();
        const act = std.posix.Sigaction{
            .handler = .{ .handler = reloadHandler },
            .mask = mask,
            .flags = 0,
        };
        std.posix.sigaction(std.posix.SIG.USR1, &act, null);

        // SIGUSR2 → draining mode (rolling restart signal)
        const drain_act = std.posix.Sigaction{
            .handler = .{ .handler = drainHandler },
            .mask = mask,
            .flags = 0,
        };
        std.posix.sigaction(std.posix.SIG.USR2, &drain_act, null);
    }

    // ── Redis ────────────────────────────────────────────────
    var redis = ipc_mod.RedisIPC.init(alloc, .{
        .server_id = cfg.server_id,
        .host = cfg.redis_host,
        .port = cfg.redis_port,
    });
    try redis.connect();

    // ── Connection Manager ───────────────────────────────────
    var mgr = manager.ConnectionManager.init(alloc, cfg.server_id, cfg.redis_host, cfg.redis_port);
    defer mgr.deinit();

    mgr.setEventHandler(struct {
        fn handler(nid: []const u8, ev: connection.Event) void {
            switch (ev) {
                .connected => std.debug.print("  ✓ {s}\n", .{nid}),
                .disconnected => |d| std.debug.print("  ✗ {s}: {s}\n", .{ nid, d.reason }),
                .privmsg => |m| std.debug.print("  <{s}> {s}: {s}\n", .{ m.nick, m.target, m.text }),
                .notice => |n| std.debug.print("  NOTICE {s}: {s}\n", .{ n.nick, n.text }),
                .join => |j| std.debug.print("  JOIN {s} → {s}\n", .{ j.nick, j.channel }),
                .part => |p| std.debug.print("  PART {s} ← {s}\n", .{ p.nick, p.channel }),
                else => {},
            }
        }
    }.handler);

    // ── Network config loading on startup ─────────────────────
    if (cfg.reload_from_pid == null) {
        loadAssignedNetworks(alloc, cfg.server_id, &redis, &mgr);
    }

    // ── Graceful reload receive ──────────────────────────────
    if (cfg.reload_from_pid) |pid| {
        const path = try reload.reloadSocketPath(alloc, @intCast(pid));
        defer alloc.free(path);
        const res: ?reload.ReloadResult = blk: {
            const r = reload.receiveReload(alloc, path) catch |err| {
                std.debug.print("Reload receive failed: {}\n", .{err});
                break :blk null;
            };
            break :blk r;
        };
        if (res) |r| {
            var copy = r;
            defer copy.deinit();
            std.debug.print("Reload: received {d} connections\n", .{copy.networks.len});
            for (copy.networks) |net| {
                const cfg_adopt = connection.Config{
                    .network_id = net.network_id,
                    .network_name = net.network_id,
                    .user_id = if (net.user_id.len > 0) net.user_id else "system",
                    .host = net.host,
                    .port = net.port,
                    .nick = net.nick,
                    .user = net.nick,
                    .real_name = net.nick,
                    .tls = .disabled,
                };
                mgr.adopt(net.network_id, net.network_id, cfg_adopt.user_id, cfg_adopt, net.fd) catch |err| {
                    std.debug.print("Reload: failed to adopt {s}: {}\n", .{ net.host, err });
                    _ = std.c.close(net.fd);
                };
            }
        }
    }

    // ── Register engine in Redis ─────────────────────────────
    try redis.sadd("irc:servers", cfg.server_id);
    const server_key = try std.fmt.allocPrint(alloc, "irc:server:{s}", .{cfg.server_id});
    defer alloc.free(server_key);
    try writeServerRegistration(alloc, cfg.server_id, cfg.bind_address, cfg.admin_port, cfg.priority, cfg.max_connections, cfg.fallback_only, &redis, server_key, &mgr);
    std.debug.print("✓ Redis\n", .{});

    // ── Control consumer (thread) ────────────────────────────
    {
        const ctrl_key = try std.fmt.allocPrint(alloc, "irc:control:{s}", .{cfg.server_id});
        var ctrl_redis = ipc_mod.RedisIPC.init(alloc, .{
            .server_id = cfg.server_id,
            .host = cfg.redis_host,
            .port = cfg.redis_port,
        });
        ctrl_redis.connect() catch {};
        const t = try std.Thread.spawn(.{}, struct {
            fn run(r: *ipc_mod.RedisIPC, key: []const u8, m: *manager.ConnectionManager) void {
                std.debug.print("Control: {s}\n", .{key});
                while (true) {
                    const res = r.blpop(key, 5) catch |err| {
                        if (err == error.Timeout) continue;
                        sleepMs(1000); continue;
                    };
                    const data = res orelse continue;
                    dispatchCtrl(data, m);
                }
            }
        }.run, .{ &ctrl_redis, ctrl_key, &mgr });
        t.detach();
    }

    // ── Health check endpoint (thread) ───────────────────────
    {
        const t = try std.Thread.spawn(.{}, healthCheckThread, .{ alloc, cfg.bind_address, cfg.admin_port });
        t.detach();
    }

    // ── Main loop: heartbeat + state snapshots ──────────────
    var tick: u32 = 0;
    std.debug.print("Engine running.\n", .{});

    while (true) {
        sleepMs(1000);
        tick += 1;

        if (reload_requested.load(.monotonic)) {
            reload_requested.store(false, .monotonic);
            const path = try reload.reloadSocketPath(alloc, @intCast(std.c.getpid()));
            defer alloc.free(path);
            const nets = blk: {
                const n = mgr.reloadNetworks(alloc) catch |err| {
                    std.debug.print("Reload prepare failed: {}\n", .{err});
                    break :blk &[_]reload.ReloadNetwork{};
                };
                break :blk n;
            };
            defer {
                for (nets) |*n| {
                    alloc.free(n.network_id);
                    alloc.free(n.host);
                    alloc.free(n.nick);
                }
                alloc.free(nets);
            }
            reload.serveReload(nets, path) catch |err| {
                std.debug.print("Reload serve failed: {}\n", .{err});
                continue;
            };
            break;
        }

        // SIGUSR2 → draining mode (rolling restart)
        if (drain_requested.load(.monotonic)) {
            drain_requested.store(false, .monotonic);
            std.debug.print("DRAIN: draining=true\n", .{});
            const dr_key = try std.fmt.allocPrint(alloc, "irc:server:{s}", .{cfg.server_id});
            defer alloc.free(dr_key);
            const dr_data = try std.fmt.allocPrint(alloc,
                "{{\"serverId\":\"{s}\",\"draining\":true,\"isHealthy\":true,\"priority\":{d}}}",
                .{ cfg.server_id, cfg.priority },
            );
            defer alloc.free(dr_data);
            redis.hset(dr_key, "data", dr_data) catch {};
        }

        // Heartbeat every 10s
        if (tick % 10 == 0) {
            const server_key_hb = std.fmt.allocPrint(alloc, "irc:server:{s}", .{cfg.server_id}) catch continue;
            defer alloc.free(server_key_hb);
            writeServerRegistration(alloc, cfg.server_id, cfg.bind_address, cfg.admin_port, cfg.priority, cfg.max_connections, cfg.fallback_only, &redis, server_key_hb, &mgr) catch {};
        }

        // State snapshot every 30s
        if (tick % 30 == 0) {
            writeStateSnapshots(alloc, cfg.server_id, &redis, &mgr);
        }

        // Log every 60s
        if (tick % 60 == 0) {
            std.debug.print("♥ #{d} — {d} connections\n", .{ tick / 60, mgr.count() });
        }
    }
}

fn loadAssignedNetworks(alloc: std.mem.Allocator, server_id: []const u8, redis: *ipc_mod.RedisIPC, mgr: *manager.ConnectionManager) void {
    std.debug.print("Network loading: checking assignments for {s}\n", .{server_id});
    const entries = redis.hgetall("irc:assignments") catch {
        std.debug.print("Network loading: could not read irc:assignments\n", .{});
        return;
    };
    defer {
        for (entries) |e| {
            alloc.free(e.field);
            alloc.free(e.value);
        }
        alloc.free(entries);
    }

    for (entries) |e| {
        if (!std.mem.eql(u8, e.value, server_id)) continue;
        const network_id = e.field;
        const state_key = std.fmt.allocPrint(alloc, "irc:state:{s}:{s}", .{ server_id, network_id }) catch continue;
        defer alloc.free(state_key);
        const state_json = redis.hget(state_key, "data") catch continue;
        const json = state_json orelse continue;
        defer alloc.free(json);

        var cfg = configFromStateJson(alloc, json) catch continue;
        defer cfg.deinit(alloc);
        mgr.add(network_id, cfg.network_name, cfg.user_id, cfg) catch |err| {
            std.debug.print("Network loading: failed to add {s}: {}\n", .{ network_id, err });
            continue;
        };
        std.debug.print("Network loading: restored {s}\n", .{network_id});
    }
}

fn jsonStringOr(v: std.json.Value, default: []const u8) []const u8 {
    return if (v == .string) v.string else default;
}

fn configFromStateJson(alloc: std.mem.Allocator, json: []const u8) !connection.Config {
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, json, .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    const cfg_val = root.get("config") orelse return error.MissingConfig;
    if (cfg_val != .object) return error.InvalidConfig;
    const cfg_obj = cfg_val.object;

    const network_id = jsonStringOr(cfg_obj.get("id") orelse .null, "");
    const network_name = jsonStringOr(cfg_obj.get("name") orelse .null, network_id);
    const host = jsonStringOr(cfg_obj.get("host") orelse .null, "irc.libera.chat");
    const port: u16 = @intCast(if (cfg_obj.get("port")) |p| if (p == .integer) p.integer else 6667 else 6667);
    const nick = jsonStringOr(cfg_obj.get("nick") orelse .null, "ircfiber");
    const real_name = jsonStringOr(cfg_obj.get("realName") orelse .null, nick);
    const user_id = jsonStringOr(root.get("ownerId") orelse .null, "system");

    const tls_str = jsonStringOr(cfg_obj.get("tls") orelse .null, "disabled");
    const tls: connection.TLSMode = if (std.mem.eql(u8, tls_str, "enabled")) .enabled else if (std.mem.eql(u8, tls_str, "required")) .required else .disabled;

    const sasl_str = jsonStringOr(cfg_obj.get("sasl") orelse .null, "none");
    const sasl: connection.SASLMechanism = if (std.mem.eql(u8, sasl_str, "plain")) .plain else if (std.mem.eql(u8, sasl_str, "external")) .external else if (std.mem.eql(u8, sasl_str, "scramSha256")) .scramSha256 else .none;

    var cfg = connection.Config{
        .network_id = try alloc.dupe(u8, network_id),
        .network_name = try alloc.dupe(u8, network_name),
        .user_id = try alloc.dupe(u8, user_id),
        .host = try alloc.dupe(u8, host),
        .port = port,
        .nick = try alloc.dupe(u8, nick),
        .user = try alloc.dupe(u8, nick),
        .real_name = try alloc.dupe(u8, real_name),
        .tls = tls,
        .tls_insecure = if (cfg_obj.get("tlsInsecure")) |v| (v == .bool and v.bool) else false,
        .sasl = sasl,
    };
    errdefer cfg.deinit(alloc);

    if (cfg_obj.get("saslUsername")) |u| {
        if (u == .string and u.string.len > 0) cfg.sasl_username = try alloc.dupe(u8, u.string);
    }
    if (cfg_obj.get("saslPassword")) |p| {
        if (p == .string and p.string.len > 0) cfg.sasl_password = try alloc.dupe(u8, p.string);
    }
    cfg.auto_join_channels = try jsonStringArray(alloc, cfg_obj.get("autoJoinChannels"));
    cfg.parted_channels = try jsonStringArray(alloc, cfg_obj.get("partedChannels"));
    return cfg;
}

fn jsonStringArray(alloc: std.mem.Allocator, v: ?std.json.Value) ![]const []const u8 {
    if (v) |val| {
        if (val == .array) {
            const arr = val.array;
            const out = try alloc.alloc([]const u8, arr.items.len);
            errdefer alloc.free(out);
            for (arr.items, 0..) |item, i| {
                if (item == .string) {
                    out[i] = try alloc.dupe(u8, item.string);
                } else {
                    out[i] = try alloc.dupe(u8, "");
                }
            }
            return out;
        }
    }
    return &[_][]const u8{};
}

const SnapshotCtx = struct {
    r: *ipc_mod.RedisIPC,
    server_id: []const u8,
};

fn writeStateSnapshots(_: std.mem.Allocator, server_id: []const u8, redis: *ipc_mod.RedisIPC, mgr: *manager.ConnectionManager) void {
    const ctx = SnapshotCtx{ .r = redis, .server_id = server_id };
    mgr.forEachNetwork(SnapshotCtx, ctx, struct {
        fn cb(sctx: SnapshotCtx, nid: []const u8, mc: *manager.ManagedConnection) void {
            const json = mc.getStateJson(sctx.server_id) catch return;
            defer mc.allocator.free(json);
            const key = std.fmt.allocPrint(mc.allocator, "irc:state:{s}:{s}", .{ sctx.server_id, nid }) catch return;
            defer mc.allocator.free(key);
            sctx.r.hset(key, "data", json) catch {};
        }
    }.cb);
}

const RegCtx = struct {
    r: *ipc_mod.RedisIPC,
    server_key: []const u8,
    server_id: []const u8,
    bind_address: []const u8,
    admin_port: u16,
    ts: i64,
    mgr: *manager.ConnectionManager,
};

const NetBufCtx = struct {
    buf: []u8,
    pos: *usize,
    first: *bool,
};

fn writeServerRegistration(
    alloc: std.mem.Allocator,
    server_id: []const u8,
    bind_address: []const u8,
    admin_port: u16,
    priority: i32,
    max_connections: i32,
    fallback_only: bool,
    redis: *ipc_mod.RedisIPC,
    server_key: []const u8,
    mgr: *manager.ConnectionManager,
) !void {
    const ts = currentTimeMs();

    var networks_buf: [4096]u8 = undefined;
    var npos: usize = 0;
    var first: bool = true;
    try appendFmt(&networks_buf, &npos, "[", .{});
    const ctx = NetBufCtx{ .buf = &networks_buf, .pos = &npos, .first = &first };
    mgr.forEachNetwork(NetBufCtx, ctx, struct {
        fn cb(cx: NetBufCtx, nid: []const u8, _: *manager.ManagedConnection) void {
            if (!cx.first.*) {
                _ = std.fmt.bufPrint(cx.buf[cx.pos.*..], ",", .{}) catch return;
                cx.pos.* += 1;
            } else {
                cx.first.* = false;
            }
            const r = std.fmt.bufPrint(cx.buf[cx.pos.*..], "\"{s}\"", .{nid}) catch return;
            cx.pos.* += r.len;
        }
    }.cb);
    try appendFmt(&networks_buf, &npos, "]", .{});

    const info = try std.fmt.allocPrint(alloc,
        "{{\"serverId\":\"{s}\",\"bindAddress\":\"{s}\",\"port\":{d},\"isHealthy\":true,\"lastHeartbeat\":{d},\"bufferOffset\":1000,\"assignedNetworks\":{s},\"hostConnectionCounts\":{{}},\"priority\":{d},\"maxConnections\":{d},\"fallbackOnly\":{s},\"draining\":false}}",
        .{ server_id, bind_address, admin_port, ts, networks_buf[0..npos], priority, max_connections, if (fallback_only) "true" else "false" },
    );
    defer alloc.free(info);
    const ts_str = try std.fmt.allocPrint(alloc, "{d}", .{ts});
    defer alloc.free(ts_str);
    try redis.hset(server_key, "data", info);
    try redis.hset(server_key, "lastHeartbeat", ts_str);
    try redis.hset(server_key, "isHealthy", "true");
}

fn appendFmt(buf: []u8, pos: *usize, comptime fmt: []const u8, args: anytype) !void {
    const result = try std.fmt.bufPrint(buf[pos.*..], fmt, args);
    pos.* += result.len;
}

fn healthCheckThread(_: std.mem.Allocator, bind_address: []const u8, port: u16) void {
    const fd = std.c.socket(std.c.AF.INET, std.c.SOCK.STREAM, std.c.IPPROTO.TCP);
    if (fd < 0) {
        std.debug.print("Health check: socket failed\n", .{});
        return;
    }
    defer _ = std.c.close(fd);

    const reuse: c_int = 1;
    _ = std.c.setsockopt(fd, std.c.SOL.SOCKET, std.c.SO.REUSEADDR, std.mem.asBytes(&reuse), @sizeOf(c_int));

    const ip = parseIpv4(bind_address) catch {
        std.debug.print("Health check: invalid bind address {s}\n", .{bind_address});
        return;
    };
    const addr = std.c.sockaddr.in{
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, ip),
    };
    if (std.c.bind(fd, @ptrCast(&addr), @sizeOf(std.c.sockaddr.in)) < 0) {
        std.debug.print("Health check: bind failed\n", .{});
        return;
    }
    if (std.c.listen(fd, 5) < 0) {
        std.debug.print("Health check: listen failed\n", .{});
        return;
    }

    std.debug.print("Health check: listening on {s}:{d}\n", .{ bind_address, port });

    var client_buf: [1024]u8 = undefined;
    while (true) {
        const client = std.c.accept(fd, null, null);
        if (client < 0) continue;
        _ = std.c.recv(client, &client_buf, client_buf.len, 0);
        const resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}";
        _ = std.c.send(client, resp, resp.len, 0);
        _ = std.c.close(client);
    }
}

fn parseIpv4(s: []const u8) !u32 {
    var it = std.mem.splitScalar(u8, s, '.');
    var octets: [4]u8 = undefined;
    for (&octets) |*o| {
        const part = it.next() orelse return error.InvalidAddress;
        o.* = std.fmt.parseInt(u8, part, 10) catch return error.InvalidAddress;
    }
    if (it.next() != null) return error.InvalidAddress;
    return (@as(u32, octets[0]) << 24) | (@as(u32, octets[1]) << 16) |
           (@as(u32, octets[2]) << 8) | @as(u32, octets[3]);
}

fn dispatchCtrl(data: []const u8, mgr: *manager.ConnectionManager) void {
    const alloc = std.heap.c_allocator;
    const parsed = std.json.parseFromSlice(std.json.Value, alloc, data, .{}) catch return;
    defer parsed.deinit();
    const obj = parsed.value.object;
    const action_v = obj.get("action") orelse return;
    if (action_v != .string) return;
    const nid_v = obj.get("networkId") orelse return;
    if (nid_v != .string) return;
    const nid = nid_v.string;

    const action = action_v.string;
    if (std.mem.eql(u8, action, "addNetwork") or std.mem.eql(u8, action, "reconnectNetwork") or std.mem.eql(u8, action, "updateConfig")) {
        const cfg_v = obj.get("config") orelse return;
        if (cfg_v != .object) return;
        const co = cfg_v.object;
        const host = jsonString(co.get("host")) orelse return;
        const nick = jsonString(co.get("nick")) orelse return;
        const network_name = jsonString(co.get("name")) orelse nid;
        const port: u16 = @intCast(jsonInt(co.get("port")) orelse 6667);
        const uid = jsonString(obj.get("userId")) orelse "system";

        var net_cfg = connection.Config{
            .network_id = alloc.dupe(u8, nid) catch return,
            .network_name = alloc.dupe(u8, network_name) catch return,
            .user_id = alloc.dupe(u8, uid) catch return,
            .host = alloc.dupe(u8, host) catch return,
            .port = port,
            .nick = alloc.dupe(u8, nick) catch return,
            .user = alloc.dupe(u8, nick) catch return,
            .real_name = alloc.dupe(u8, jsonString(co.get("realName")) orelse nick) catch return,
            .tls = parseTLSMode(jsonString(co.get("tls"))),
            .tls_insecure = if (co.get("tlsInsecure")) |v| (v == .bool and v.bool) else false,
            .sasl = parseSASLMechanism(jsonString(co.get("sasl"))),
            .auto_join_channels = jsonStringArray(alloc, co.get("autoJoinChannels")) catch &.{},
            .parted_channels = jsonStringArray(alloc, co.get("partedChannels")) catch &.{},
        };
        errdefer net_cfg.deinit(alloc);
        if (co.get("saslUsername")) |u| {
            if (u == .string and u.string.len > 0) net_cfg.sasl_username = alloc.dupe(u8, u.string) catch return;
        }
        if (co.get("saslPassword")) |p| {
            if (p == .string and p.string.len > 0) net_cfg.sasl_password = alloc.dupe(u8, p.string) catch return;
        }

        mgr.add(nid, network_name, uid, net_cfg) catch |err| { std.debug.print("  ✗ addNetwork: {}\n", .{err}); };
        std.debug.print("  + {s} ({s}) {s}:{d}\n", .{ nid, network_name, host, port });
    } else if (std.mem.eql(u8, action, "removeNetwork") or std.mem.eql(u8, action, "disconnectNetwork")) {
        mgr.remove(nid);
    }
}

fn jsonString(v: ?std.json.Value) ?[]const u8 {
    if (v) |val| {
        if (val == .string) return val.string;
    }
    return null;
}

fn jsonInt(v: ?std.json.Value) ?i64 {
    if (v) |val| {
        if (val == .integer) return val.integer;
    }
    return null;
}

fn parseTLSMode(s: ?[]const u8) connection.TLSMode {
    const v = s orelse return .disabled;
    if (std.mem.eql(u8, v, "enabled")) return .enabled;
    if (std.mem.eql(u8, v, "required")) return .required;
    return .disabled;
}

fn parseSASLMechanism(s: ?[]const u8) connection.SASLMechanism {
    const v = s orelse return .none;
    if (std.mem.eql(u8, v, "plain")) return .plain;
    if (std.mem.eql(u8, v, "external")) return .external;
    if (std.mem.eql(u8, v, "scramSha256")) return .scramSha256;
    return .none;
}

fn sleepMs(ms: u64) void {
    var ts = std.c.timespec{
        .sec = @intCast(ms / 1000),
        .nsec = @intCast((ms % 1000) * std.time.ns_per_ms),
    };
    _ = std.c.nanosleep(&ts, null);
}
fn currentTimeMs() i64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(std.c.CLOCK.REALTIME, &ts);
    return ts.sec * 1000 + @divTrunc(ts.nsec, 1000000);
}
