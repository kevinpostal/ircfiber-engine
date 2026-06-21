const std = @import("std");
const Allocator = std.mem.Allocator;
const Spinlock = @import("lock.zig").Spinlock;
const connection = @import("connection.zig");
const ipc_mod = @import("ipc.zig");
const reload = @import("reload.zig");
const NetworkConnection = connection.NetworkConnection;
const Config = connection.Config;
const Event = connection.Event;

pub const ManagedConnection = struct {
    allocator: Allocator,
    network_id: []const u8,
    network_name: []const u8,
    user_id: []const u8,
    server_id: []const u8,
    redis_host: []const u8,
    redis_port: u16,
    conn: NetworkConnection,
    thread: ?std.Thread,
    redis: ?ipc_mod.RedisIPC,
    event_handler: ?*const fn (network_id: []const u8, event: Event) void,
    cmd_consumer_running: std.atomic.Value(bool) = .init(false),

    pub fn init(allocator: Allocator, network_id: []const u8, network_name: []const u8, user_id: []const u8, server_id: []const u8, redis_host: []const u8, redis_port: u16, cfg: Config) ManagedConnection {
        return .{
            .allocator = allocator,
            .network_id = allocator.dupe(u8, network_id) catch @panic("OOM"),
            .network_name = allocator.dupe(u8, network_name) catch @panic("OOM"),
            .user_id = allocator.dupe(u8, user_id) catch @panic("OOM"),
            .server_id = allocator.dupe(u8, server_id) catch @panic("OOM"),
            .redis_host = allocator.dupe(u8, redis_host) catch @panic("OOM"),
            .redis_port = redis_port,
            .conn = NetworkConnection.init(allocator, cfg),
            .thread = null,
            .redis = null,
            .event_handler = null,
        };
    }

    pub fn deinit(self: *ManagedConnection) void {
        self.conn.deinit();
        self.allocator.free(self.network_id);
        self.allocator.free(self.network_name);
        self.allocator.free(self.user_id);
        self.allocator.free(self.server_id);
        self.allocator.free(self.redis_host);
    }

    pub fn start(self: *ManagedConnection) void {
        var r = ipc_mod.RedisIPC.init(self.allocator, .{
            .server_id = self.server_id,
            .host = self.redis_host,
            .port = self.redis_port,
        });
        r.connect() catch |err| {
            std.debug.print("MC redis: {}\n", .{err});
        };
        self.redis = r;
        self.conn.setEventCallback(eventBridge, @ptrCast(self));
        self.thread = std.Thread.spawn(.{}, struct {
            fn run(mc_ptr: *ManagedConnection) void { mc_ptr.conn.run(); }
        }.run, .{self}) catch null;
        startCmdConsumer(self);
    }

    pub fn startAdopted(self: *ManagedConnection, fd: c_int) void {
        var r = ipc_mod.RedisIPC.init(self.allocator, .{
            .server_id = self.server_id,
            .host = self.redis_host,
            .port = self.redis_port,
        });
        r.connect() catch |err| {
            std.debug.print("MC redis adopted: {}\n", .{err});
        };
        self.redis = r;
        self.conn.setEventCallback(eventBridge, @ptrCast(self));
        self.thread = std.Thread.spawn(.{}, struct {
            fn run(mc_ptr: *ManagedConnection, raw_fd: c_int) void { mc_ptr.conn.runAdopted(raw_fd); }
        }.run, .{ self, fd }) catch null;
        startCmdConsumer(self);
    }

    pub fn stop(self: *ManagedConnection) void {
        self.cmd_consumer_running.store(false, .monotonic);
        self.conn.stop();
        if (self.thread) |t| { t.join(); self.thread = null; }
        if (self.redis) |*r| { r.close(); self.redis = null; }
    }

    pub fn getStateJson(self: *ManagedConnection, server_id: []const u8) ![]u8 {
        return self.conn.getStateJson(self.allocator, self.user_id, server_id);
    }
};

fn eventBridge(e: Event, conn: *NetworkConnection) void {
    const mc: *ManagedConnection = @ptrCast(@alignCast(conn.event_ctx.?));
    if (mc.redis) |*r| {
        const uid = mc.user_id;
        if (uid.len > 0) publishEvent(r, mc.allocator, mc.network_name, mc.server_id, uid, e) catch |err| {
            std.debug.print("publishEvent error: {}\n", .{err});
        };
    } else {
        std.debug.print("eventBridge: no redis\n", .{});
    }
    if (mc.event_handler) |handler| handler(mc.network_id, e);
}

fn publishEvent(r: *ipc_mod.RedisIPC, alloc: Allocator, network_name: []const u8, server_id: []const u8, uid: []const u8, ev: Event) !void {
    const eid = r.incr("irc:global_eid") catch 0;
    const json = try buildEventJson(alloc, network_name, server_id, ev, eid);
    defer alloc.free(json);

    const stream_key = try std.fmt.allocPrint(alloc, "irc:stream:{s}", .{uid});
    defer alloc.free(stream_key);
    r.lpush(stream_key, json) catch {};
    r.ltrim(stream_key, -1000, -1) catch {};

    const events_key = try std.fmt.allocPrint(alloc, "irc:events:{s}", .{uid});
    defer alloc.free(events_key);
    r.publish(events_key, json) catch {};
}

fn buildEventJson(alloc: Allocator, network_name: []const u8, server_id: []const u8, ev: Event, eid: i64) ![]u8 {
    const ts: i64 = connection.currentTimeMs();
    const id = try randomId(alloc);
    defer alloc.free(id);

    var buf: [8192]u8 = undefined;
    var pos: usize = 0;

    try appendFmt(&buf, &pos, "{{\"y\":\"irc_event\",\"network\":\"{s}\",\"serverId\":\"{s}\",\"i\":\"{s}\",\"m\":\"{s}\"", .{ network_name, server_id, id, id });

    switch (ev) {
        .connected => try appendFmt(&buf, &pos, ",\"n\":\"\",\"x\":\"connected\",\"ch\":\"\",\"c\":\"CONNECTED\"", .{}),
        .disconnected => |d| {
            const reason = try jsonEscape(alloc, d.reason);
            defer alloc.free(reason);
            try appendFmt(&buf, &pos, ",\"n\":\"\",\"x\":\"{s}\",\"ch\":\"\",\"c\":\"DISCONNECTED\"", .{reason});
        },
        .privmsg => |m| {
            const nick = try jsonEscape(alloc, m.nick);
            defer alloc.free(nick);
            const target = try jsonEscape(alloc, m.target);
            defer alloc.free(target);
            const text = try jsonEscape(alloc, m.text);
            defer alloc.free(text);
            try appendFmt(&buf, &pos, ",\"n\":\"{s}\",\"x\":\"{s}\",\"ch\":\"{s}\",\"c\":\"PRIVMSG\"", .{ nick, text, target });
        },
        .notice => |n| {
            const nick = try jsonEscape(alloc, n.nick);
            defer alloc.free(nick);
            const text = try jsonEscape(alloc, n.text);
            defer alloc.free(text);
            try appendFmt(&buf, &pos, ",\"n\":\"{s}\",\"x\":\"{s}\",\"ch\":\"\",\"c\":\"NOTICE\"", .{ nick, text });
        },
        .join => |j| {
            const nick = try jsonEscape(alloc, j.nick);
            defer alloc.free(nick);
            const channel = try jsonEscape(alloc, j.channel);
            defer alloc.free(channel);
            try appendFmt(&buf, &pos, ",\"n\":\"{s}\",\"x\":\"\",\"ch\":\"{s}\",\"c\":\"JOIN\"", .{ nick, channel });
        },
        .part => |p| {
            const nick = try jsonEscape(alloc, p.nick);
            defer alloc.free(nick);
            const channel = try jsonEscape(alloc, p.channel);
            defer alloc.free(channel);
            const reason = try jsonEscape(alloc, p.reason orelse "");
            defer alloc.free(reason);
            try appendFmt(&buf, &pos, ",\"n\":\"{s}\",\"x\":\"{s}\",\"ch\":\"{s}\",\"c\":\"PART\"", .{ nick, reason, channel });
        },
        .quit => |q| {
            const nick = try jsonEscape(alloc, q.nick);
            defer alloc.free(nick);
            const reason = try jsonEscape(alloc, q.reason orelse "");
            defer alloc.free(reason);
            try appendFmt(&buf, &pos, ",\"n\":\"{s}\",\"x\":\"{s}\",\"ch\":\"\",\"c\":\"QUIT\"", .{ nick, reason });
        },
        .nick => |nk| {
            const old = try jsonEscape(alloc, nk.old);
            defer alloc.free(old);
            const new = try jsonEscape(alloc, nk.new);
            defer alloc.free(new);
            try appendFmt(&buf, &pos, ",\"n\":\"{s}\",\"x\":\"{s}\",\"ch\":\"\",\"c\":\"NICK\"", .{ old, new });
        },
        .topic => |t| {
            const nick = try jsonEscape(alloc, t.nick);
            defer alloc.free(nick);
            const channel = try jsonEscape(alloc, t.channel);
            defer alloc.free(channel);
            const topic = try jsonEscape(alloc, t.topic orelse "");
            defer alloc.free(topic);
            try appendFmt(&buf, &pos, ",\"n\":\"{s}\",\"x\":\"{s}\",\"ch\":\"{s}\",\"c\":\"TOPIC\"", .{ nick, topic, channel });
        },
    }

    try appendFmt(&buf, &pos, ",\"t\":{d},\"eid\":{d}}}", .{ ts, eid });
    return try alloc.dupe(u8, buf[0..pos]);
}

fn appendFmt(buf: []u8, pos: *usize, comptime fmt: []const u8, args: anytype) !void {
    const result = try std.fmt.bufPrint(buf[pos.*..], fmt, args);
    pos.* += result.len;
}

fn jsonEscape(alloc: Allocator, s: []const u8) ![]const u8 {
    var buf = try alloc.alloc(u8, s.len * 2 + 1);
    errdefer alloc.free(buf);
    var pos: usize = 0;
    for (s) |ch| {
        switch (ch) {
            '\\' => { buf[pos] = '\\'; buf[pos + 1] = '\\'; pos += 2; },
            '"' => { buf[pos] = '\\'; buf[pos + 1] = '"'; pos += 2; },
            '\n' => { buf[pos] = '\\'; buf[pos + 1] = 'n'; pos += 2; },
            '\r' => { buf[pos] = '\\'; buf[pos + 1] = 'r'; pos += 2; },
            '\t' => { buf[pos] = '\\'; buf[pos + 1] = 't'; pos += 2; },
            else => { buf[pos] = ch; pos += 1; },
        }
    }
    return try alloc.realloc(buf, pos);
}

fn randomId(alloc: Allocator) ![]const u8 {
    var bytes: [16]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(@intCast(connection.currentTimeMs()));
    prng.fill(&bytes);
    // Set version (4) and variant bits for a standard-looking UUID.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    return try std.fmt.allocPrint(alloc, "{x:0>2}{x:0>2}{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}", .{
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11],
        bytes[12], bytes[13], bytes[14], bytes[15],
    });
}

// ── Command Consumer ───────────────────────────────────────────

fn startCmdConsumer(mc: *ManagedConnection) void {
    const cmd_key = std.fmt.allocPrint(mc.allocator, "irc:cmd:{s}:{s}", .{ mc.server_id, mc.network_id }) catch return;
    mc.cmd_consumer_running.store(true, .monotonic);
    const t = std.Thread.spawn(.{}, struct {
        fn run(mc_ptr: *ManagedConnection, key: []const u8) void {
            defer mc_ptr.allocator.free(key);

            var cmd_redis = ipc_mod.RedisIPC.init(mc_ptr.allocator, .{
                .server_id = mc_ptr.server_id,
                .host = mc_ptr.redis_host,
                .port = mc_ptr.redis_port,
            });
            cmd_redis.connect() catch { return; };
            defer cmd_redis.close();

            while (mc_ptr.cmd_consumer_running.load(.monotonic)) {
                const res = cmd_redis.blpop(key, 5) catch continue;
                const data = res orelse continue;
                defer mc_ptr.allocator.free(data);
                dispatchCmd(data, mc_ptr);
            }
        }
    }.run, .{ mc, cmd_key }) catch { mc.cmd_consumer_running.store(false, .monotonic); return; };
    t.detach();
}

fn dispatchCmd(data: []const u8, mc: *ManagedConnection) void {
    const val = std.json.parseFromSliceLeaky(std.json.Value, mc.allocator, data, .{}) catch return;
    if (val != .object) return;
    const obj = val.object;
    const cmd = if (obj.get("cmd")) |cval| if (cval == .string) cval.string else return else return;

    if (std.mem.eql(u8, cmd, "msg")) {
        const target = if (obj.get("target")) |t| if (t == .string) t.string else return else return;
        const text = if (obj.get("text")) |t| if (t == .string) t.string else "" else "";
        mc.conn.cmdFour("PRIVMSG ", target, " :", text);
    } else if (std.mem.eql(u8, cmd, "join")) {
        const channel = if (obj.get("channel")) |ch| if (ch == .string) ch.string else return
            else if (obj.get("target")) |t| if (t == .string) t.string else return else return;
        mc.conn.cmdTwo("JOIN ", channel);
    } else if (std.mem.eql(u8, cmd, "part")) {
        const channel = if (obj.get("channel")) |ch| if (ch == .string) ch.string else return
            else if (obj.get("target")) |t| if (t == .string) t.string else return else return;
        mc.conn.cmdTwo("PART ", channel);
    } else if (std.mem.eql(u8, cmd, "raw")) {
        const text = if (obj.get("text")) |t| if (t == .string) t.string else return else return;
        mc.conn.cmd(text);
    }
}

pub const ConnectionManager = struct {
    allocator: Allocator,
    server_id: []const u8,
    redis_host: []const u8,
    redis_port: u16,
    connections: std.StringHashMap(*ManagedConnection),
    mutex: Spinlock,
    event_handler: ?*const fn (network_id: []const u8, event: Event) void,

    pub fn init(allocator: Allocator, server_id: []const u8, redis_host: []const u8, redis_port: u16) ConnectionManager {
        return .{
            .allocator = allocator,
            .server_id = allocator.dupe(u8, server_id) catch @panic("OOM"),
            .redis_host = allocator.dupe(u8, redis_host) catch @panic("OOM"),
            .redis_port = redis_port,
            .connections = std.StringHashMap(*ManagedConnection).init(allocator),
            .mutex = .{},
            .event_handler = null,
        };
    }

    pub fn deinit(self: *ConnectionManager) void {
        self.shutdown();
        self.connections.deinit();
        self.allocator.free(self.server_id);
        self.allocator.free(self.redis_host);
    }

    pub fn setEventHandler(self: *ConnectionManager, handler: *const fn (network_id: []const u8, event: Event) void) void {
        self.event_handler = handler;
    }

    pub fn add(self: *ConnectionManager, network_id: []const u8, network_name: []const u8, user_id: []const u8, cfg: Config) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.connections.contains(network_id)) return error.AlreadyExists;
        const mc = try self.allocator.create(ManagedConnection);
        mc.* = ManagedConnection.init(self.allocator, network_id, network_name, user_id, self.server_id, self.redis_host, self.redis_port, cfg);
        mc.event_handler = self.event_handler;
        mc.start();
        try self.connections.put(try self.allocator.dupe(u8, network_id), mc);
    }

    pub fn adopt(self: *ConnectionManager, network_id: []const u8, network_name: []const u8, user_id: []const u8, cfg: Config, fd: c_int) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.connections.contains(network_id)) return error.AlreadyExists;
        const mc = try self.allocator.create(ManagedConnection);
        mc.* = ManagedConnection.init(self.allocator, network_id, network_name, user_id, self.server_id, self.redis_host, self.redis_port, cfg);
        mc.event_handler = self.event_handler;
        mc.startAdopted(fd);
        try self.connections.put(try self.allocator.dupe(u8, network_id), mc);
    }

    pub fn remove(self: *ConnectionManager, network_id: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.connections.fetchRemove(network_id)) |kv| {
            kv.value.stop();
            kv.value.deinit();
            self.allocator.destroy(kv.value);
            self.allocator.free(kv.key);
        }
    }

    pub fn sendMessage(self: *ConnectionManager, nid: []const u8, target: []const u8, text: []const u8) void {
        self.mutex.lock(); defer self.mutex.unlock();
        if (self.connections.get(nid)) |m| m.conn.cmdFour("PRIVMSG ", target, " :", text);
    }

    pub fn joinChannel(self: *ConnectionManager, nid: []const u8, channel: []const u8) void {
        self.mutex.lock(); defer self.mutex.unlock();
        if (self.connections.get(nid)) |m| m.conn.cmdTwo("JOIN ", channel);
    }

    pub fn sendRaw(self: *ConnectionManager, nid: []const u8, data: []const u8) void {
        self.mutex.lock(); defer self.mutex.unlock();
        if (self.connections.get(nid)) |m| m.conn.cmd(data);
    }

    pub fn forEachNetwork(self: *ConnectionManager, comptime Ctx: type, ctx: Ctx, cb: *const fn (ctx: Ctx, network_id: []const u8, mc: *ManagedConnection) void) void {
        self.mutex.lock(); defer self.mutex.unlock();
        var it = self.connections.iterator();
        while (it.next()) |entry| cb(ctx, entry.key_ptr.*, entry.value_ptr.*);
    }

    pub fn count(self: *ConnectionManager) usize {
        self.mutex.lock(); defer self.mutex.unlock();
        return self.connections.count();
    }

    pub fn reloadNetworks(self: *ConnectionManager, allocator: Allocator) ![]reload.ReloadNetwork {
        self.mutex.lock(); defer self.mutex.unlock();
        var nets: [256]reload.ReloadNetwork = undefined;
        var ncount: usize = 0;
        errdefer {
            for (nets[0..ncount]) |*n| {
                allocator.free(n.network_id);
                allocator.free(n.host);
                allocator.free(n.nick);
                if (n.user_id.len > 0) allocator.free(n.user_id);
            }
        }
        var it = self.connections.iterator();
        while (it.next()) |entry| {
            const mc = entry.value_ptr.*;
            const fd = mc.conn.transportFd() orelse continue;
            if (ncount >= nets.len) return error.TooManyNetworks;
            nets[ncount] = .{
                .network_id = try allocator.dupe(u8, mc.network_id),
                .host = try allocator.dupe(u8, mc.conn.config.host),
                .nick = try allocator.dupe(u8, mc.conn.current_nick),
                .user_id = try allocator.dupe(u8, mc.user_id),
                .port = mc.conn.config.port,
                .fd = fd,
            };
            ncount += 1;
        }
        const out = try allocator.alloc(reload.ReloadNetwork, ncount);
        for (nets[0..ncount], 0..) |net, i| out[i] = net;
        return out;
    }

    pub fn shutdown(self: *ConnectionManager) void {
        self.mutex.lock(); defer self.mutex.unlock();
        var it = self.connections.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.*.stop();
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
            self.allocator.free(entry.key_ptr.*);
        }
        self.connections.clearRetainingCapacity();
    }
};
