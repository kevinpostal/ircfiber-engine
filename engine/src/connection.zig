//! # NetworkConnection — IRC client
//!
//! Uses transport.zig for TCP, zircon for message types.
//! Handles CAP, SASL, reconnect, and channel state.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const zircon = @import("zircon");
const Transport = @import("transport.zig").Transport;
const Spinlock = @import("lock.zig").Spinlock;

pub const TLSMode = enum { disabled, enabled, required };
pub const SASLMechanism = enum { none, plain, external, scramSha256 };

pub const Config = struct {
    network_id: []const u8 = "",
    network_name: []const u8 = "",
    user_id: []const u8 = "",
    host: []const u8,
    port: u16 = 6667,
    nick: []const u8 = "ircfiber",
    user: []const u8 = "ircfiber",
    real_name: []const u8 = "IRC Fiber",
    tls: TLSMode = .disabled,
    tls_insecure: bool = false,
    sasl: SASLMechanism = .none,
    sasl_username: ?[]const u8 = null,
    sasl_password: ?[]const u8 = null,
    auto_join_channels: []const []const u8 = &.{},
    parted_channels: []const []const u8 = &.{},
    timeout_ms: u64 = 10000,

    pub fn clone(self: Config, allocator: Allocator) !Config {
        const dup = struct {
            fn d(a: Allocator, s: []const u8) ![]const u8 { return try a.dupe(u8, s); }
        }.d;
        const dupMaybe = struct {
            fn d(a: Allocator, s: ?[]const u8) !?[]const u8 { return if (s) |v| try a.dupe(u8, v) else null; }
        }.d;
        const dupArr = struct {
            fn d(a: Allocator, arr: []const []const u8) ![]const []const u8 {
                const out = try a.alloc([]const u8, arr.len);
                errdefer a.free(out);
                for (arr, 0..) |item, i| out[i] = try a.dupe(u8, item);
                return out;
            }
        }.d;
        return .{
            .network_id = try dup(allocator, self.network_id),
            .network_name = try dup(allocator, self.network_name),
            .user_id = try dup(allocator, self.user_id),
            .host = try dup(allocator, self.host),
            .port = self.port,
            .nick = try dup(allocator, self.nick),
            .user = try dup(allocator, self.user),
            .real_name = try dup(allocator, self.real_name),
            .tls = self.tls,
            .tls_insecure = self.tls_insecure,
            .sasl = self.sasl,
            .sasl_username = try dupMaybe(allocator, self.sasl_username),
            .sasl_password = try dupMaybe(allocator, self.sasl_password),
            .auto_join_channels = try dupArr(allocator, self.auto_join_channels),
            .parted_channels = try dupArr(allocator, self.parted_channels),
            .timeout_ms = self.timeout_ms,
        };
    }

    pub fn deinit(self: *Config, allocator: Allocator) void {
        allocator.free(self.network_id);
        allocator.free(self.network_name);
        allocator.free(self.user_id);
        allocator.free(self.host);
        allocator.free(self.nick);
        allocator.free(self.user);
        allocator.free(self.real_name);
        if (self.sasl_username) |s| allocator.free(s);
        if (self.sasl_password) |s| allocator.free(s);
        for (self.auto_join_channels) |ch| allocator.free(ch);
        allocator.free(self.auto_join_channels);
        for (self.parted_channels) |ch| allocator.free(ch);
        allocator.free(self.parted_channels);
        self.* = .{ .host = "" };
    }
};

pub const State = enum { disconnected, connecting, connected, disconnecting };

pub const Event = union(enum) {
    connected: void,
    disconnected: struct { reason: []const u8 },
    notice: struct { nick: []const u8, text: []const u8 },
    join: struct { nick: []const u8, channel: []const u8 },
    part: struct { nick: []const u8, channel: []const u8, reason: ?[]const u8 },
    quit: struct { nick: []const u8, reason: ?[]const u8 },
    nick: struct { old: []const u8, new: []const u8 },
    privmsg: struct { nick: []const u8, target: []const u8, text: []const u8 },
    topic: struct { nick: []const u8, channel: []const u8, topic: ?[]const u8 },
};

pub const NetworkConnection = struct {
    allocator: Allocator,
    config: Config,
    transport: ?Transport,
    read_buf: [8192]u8,
    state: State,
    state_mutex: Spinlock,
    current_nick: []const u8,
    nick_mutex: Spinlock,
    event_callback: ?*const fn (Event, *NetworkConnection) void,
    event_ctx: ?*anyopaque,
    backoff_attempt: u32,
    send_mutex: Spinlock = .{},
    joined_channels: std.StringHashMap(void),
    parted_channels: std.StringHashMap(void),

    pub fn init(allocator: Allocator, config: Config) NetworkConnection {
        var parted = std.StringHashMap(void).init(allocator);
        for (config.parted_channels) |ch| {
            const owned = allocator.dupe(u8, ch) catch continue;
            parted.put(owned, {}) catch allocator.free(owned);
        }
        var cfg = config;
        return .{
            .allocator = allocator,
            .config = cfg.clone(allocator) catch @panic("OOM"),
            .transport = null,
            .read_buf = undefined,
            .state = .disconnected,
            .state_mutex = .{},
            .current_nick = allocator.dupe(u8, config.nick) catch @panic("OOM"),
            .nick_mutex = .{},
            .event_callback = null,
            .event_ctx = null,
            .backoff_attempt = 0,
            .joined_channels = std.StringHashMap(void).init(allocator),
            .parted_channels = parted,
        };
    }

    pub fn deinit(self: *NetworkConnection) void {
        self.close();
        self.config.deinit(self.allocator);
        self.allocator.free(self.current_nick);
        freeChannelMap(self.allocator, &self.joined_channels);
        freeChannelMap(self.allocator, &self.parted_channels);
    }

    fn freeChannelMap(allocator: Allocator, map: *std.StringHashMap(void)) void {
        var it = map.keyIterator();
        while (it.next()) |k| allocator.free(k.*);
        map.deinit();
    }

    fn setState(self: *NetworkConnection, s: State) void {
        self.state_mutex.lock();
        self.state = s;
        self.state_mutex.unlock();
    }

    pub fn getState(self: *NetworkConnection) State {
        self.state_mutex.lock();
        const s = self.state;
        self.state_mutex.unlock();
        return s;
    }

    fn setCurrentNick(self: *NetworkConnection, nick: []const u8) void {
        self.nick_mutex.lock();
        const old = self.current_nick;
        self.current_nick = self.allocator.dupe(u8, nick) catch old;
        if (!std.mem.eql(u8, old, self.current_nick)) self.allocator.free(old);
        self.nick_mutex.unlock();
    }

    pub fn getCurrentNick(self: *NetworkConnection) []const u8 {
        self.nick_mutex.lock();
        const nick = self.allocator.dupe(u8, self.current_nick) catch self.current_nick;
        self.nick_mutex.unlock();
        return nick;
    }

    pub fn getStateJson(self: *NetworkConnection, allocator: Allocator, owner_id: []const u8, server_id: []const u8) ![]u8 {
        const s = self.getState();
        const connected_str = if (s == .connected) "true" else "false";
        const cfg_json = try self.configJson(allocator);
        defer allocator.free(cfg_json);
        const buf_json = try self.buffersJson(allocator);
        defer allocator.free(buf_json);
        const nick = self.getCurrentNick();
        defer allocator.free(nick);

        return try std.fmt.allocPrint(allocator,
            \\{{"config":{s},"connected":{s},"status":"{s}","currentNick":"{s}","buffers":{s},"ownerId":"{s}","serverId":"{s}","updatedAt":{d}}}
        , .{
            cfg_json, connected_str, @tagName(s), nick,
            buf_json, owner_id, server_id, currentTimeMs(),
        });
    }

    fn configJson(self: *NetworkConnection, allocator: Allocator) ![]const u8 {
        var buf: [4096]u8 = undefined;
        var pos: usize = 0;
        try appendFmt(&buf, &pos, "{{\"id\":\"{s}\",\"name\":\"{s}\",\"host\":\"{s}\",\"port\":{d},\"nick\":\"{s}\",\"realName\":\"{s}\",\"tls\":\"{s}\",\"sasl\":\"{s}\"", .{
            self.config.network_id, self.config.network_name, self.config.host, self.config.port,
            self.config.nick, self.config.real_name, @tagName(self.config.tls), @tagName(self.config.sasl),
        });
        try appendFmt(&buf, &pos, ",\"saslUsername\":\"{s}\",\"saslPassword\":\"{s}\"", .{
            self.config.sasl_username orelse "", self.config.sasl_password orelse "",
        });
        try appendFmt(&buf, &pos, ",\"autoJoinChannels\":[", .{});
        for (self.config.auto_join_channels, 0..) |ch, i| {
            if (i > 0) try appendFmt(&buf, &pos, ",", .{});
            try appendFmt(&buf, &pos, "\"{s}\"", .{ch});
        }
        try appendFmt(&buf, &pos, "],\"partedChannels\":[", .{});
        for (self.config.parted_channels, 0..) |ch, i| {
            if (i > 0) try appendFmt(&buf, &pos, ",", .{});
            try appendFmt(&buf, &pos, "\"{s}\"", .{ch});
        }
        try appendFmt(&buf, &pos, "]}}", .{});
        return try allocator.dupe(u8, buf[0..pos]);
    }

    fn buffersJson(self: *NetworkConnection, allocator: Allocator) ![]const u8 {
        var buf: [4096]u8 = undefined;
        var pos: usize = 0;
        try appendFmt(&buf, &pos, "[{{\"name\":\"_server\",\"type\":\"server\",\"isJoined\":true}}", .{});

        // joined channels
        var it = self.joined_channels.keyIterator();
        while (it.next()) |ch| {
            try appendFmt(&buf, &pos, ",{{\"name\":\"{s}\",\"type\":\"channel\",\"isJoined\":true}}", .{ch.*});
        }

        // parted channels not currently joined
        var pit = self.parted_channels.keyIterator();
        while (pit.next()) |ch| {
            if (self.joined_channels.contains(ch.*)) continue;
            try appendFmt(&buf, &pos, ",{{\"name\":\"{s}\",\"type\":\"channel\",\"isJoined\":false}}", .{ch.*});
        }

        try appendFmt(&buf, &pos, "]", .{});
        return try allocator.dupe(u8, buf[0..pos]);
    }

    fn appendFmt(buf: []u8, pos: *usize, comptime fmt: []const u8, args: anytype) !void {
        const result = try std.fmt.bufPrint(buf[pos.*..], fmt, args);
        pos.* += result.len;
    }

    pub fn setEventCallback(self: *NetworkConnection, cb: *const fn (Event, *NetworkConnection) void, ctx: ?*anyopaque) void {
        self.event_callback = cb;
        self.event_ctx = ctx;
    }

    pub fn run(self: *NetworkConnection) void {
        self.setState(.connecting);
        while (true) {
            if (self.getState() == .disconnecting) break;

            self.connectAndRegister() catch |err| {
                std.debug.print("Connect failed ({s}): {}\n", .{ self.config.network_name, err });
                if (self.getState() == .disconnecting) break;
                self.sleepMs(backoffDelay(self.backoff_attempt));
                self.backoff_attempt += 1;
                continue;
            };

            self.setState(.connected);
            self.backoff_attempt = 0;
            self.emit(.{ .connected = {} });

            self.eventLoop() catch |err| {
                std.debug.print("Event loop error ({s}): {}\n", .{ self.config.network_name, err });
                if (self.getState() == .disconnecting) break;
                self.emit(.{ .disconnected = .{ .reason = "connection lost" } });
                self.sleepMs(backoffDelay(self.backoff_attempt));
                self.backoff_attempt += 1;
                continue;
            };
            break;
        }
        self.close();
    }

    /// Adopt an already-connected FD (graceful reload). Skips registration.
    /// TLS path: uses zircon.Client for connect + register + loop.
    /// Thread-local is used because zircon's callback has no context pointer.
    pub fn runTls(self: *NetworkConnection) void {
        var channels: [0][]const u8 = .{};
        var zclient = zircon.Client.init(self.allocator, .{
            .user = self.config.user,
            .nick = self.config.nick,
            .real_name = self.config.real_name,
            .server = self.config.host,
            .port = self.config.port,
            .tls = true,
            .channels = &channels,
        }) catch {
            self.emit(.{ .disconnected = .{ .reason = "TLS init failed" } });
            return;
        };
        defer zclient.deinit();

        std.debug.print("TLS: connecting to {s}:{d}...\n", .{ self.config.host, self.config.port });
        zclient.connect() catch |err| {
            std.debug.print("TLS: connect failed: {}\n", .{err});
            self.emit(.{ .disconnected = .{ .reason = "TLS connect failed" } });
            return;
        };
        std.debug.print("TLS: connected, registering...\n", .{});
        zclient.register() catch |err| {
            std.debug.print("TLS: register failed: {}\n", .{err});
            self.emit(.{ .disconnected = .{ .reason = "TLS register failed" } });
            return;
        };

        std.debug.print("TLS: registered successfully\n", .{});
        self.emit(.{ .connected = {} });
        defer self.emit(.{ .disconnected = .{ .reason = "TLS disconnected" } });

        // Use a thread-local bridge since zircon's callback has no context pointer
        const Bridge = struct {
            var conn: *NetworkConnection = undefined;
        };
        Bridge.conn = self;

        // Use zircon's loop with callbacks that forward to our event system
        zclient.loop(.{
            .msg_callback = struct {
                fn cb(msg: zircon.Message) ?zircon.Message {
                    const nc = Bridge.conn;
                    switch (msg) {
                        .PRIVMSG => |m| nc.emit(.{ .privmsg = .{
                            .nick = extractNick(m.prefix), .target = m.targets, .text = m.text,
                        } }),
                        .JOIN => |m| nc.emit(.{ .join = .{
                            .nick = extractNick(m.prefix), .channel = m.channels,
                        } }),
                        .PART => |m| nc.emit(.{ .part = .{
                            .nick = extractNick(m.prefix), .channel = m.channels, .reason = m.reason,
                        } }),
                        .QUIT => |m| nc.emit(.{ .quit = .{
                            .nick = extractNick(m.prefix), .reason = m.reason,
                        } }),
                        .NOTICE => |m| nc.emit(.{ .notice = .{
                            .nick = extractNick(m.prefix), .text = m.text,
                        } }),
                        .NICK => |m| nc.emit(.{ .nick = .{
                            .old = extractNick(m.prefix), .new = m.nickname,
                        } }),
                        .TOPIC => |m| nc.emit(.{ .topic = .{
                            .nick = extractNick(m.prefix), .channel = m.channel, .topic = m.text,
                        } }),
                        else => {},
                    }
                    return null;
                }
            }.cb,
        }) catch {};
    }

    pub fn runAdopted(self: *NetworkConnection, fd: c_int) void {
        self.transport = Transport.adopt(self.allocator, fd, self.config.host) catch return;
        self.setCurrentNick(self.config.nick);
        self.setState(.connected);
        self.backoff_attempt = 0;
        self.emit(.{ .connected = {} });
        self.eventLoop() catch |err| {
            std.debug.print("Event loop error ({s}): {}\n", .{ self.config.network_name, err });
            self.emit(.{ .disconnected = .{ .reason = "connection lost" } });
        };
        self.close();
    }

    pub fn stop(self: *NetworkConnection) void {
        self.setState(.disconnecting);
        if (self.transport) |*t| {
            t.writeRaw("QUIT :Client closed\r\n") catch {};
            t.close();
            self.transport = null;
        }
    }

    /// Returns the underlying socket fd if this is a plain (non-TLS) connection.
    pub fn transportFd(self: *NetworkConnection) ?c_int {
        if (self.transport) |*t| {
            const fd = t.getFd();
            if (fd >= 0 and t.isPlain()) return fd;
        }
        return null;
    }

    fn close(self: *NetworkConnection) void {
        if (self.transport) |*t| {
            t.close();
            self.transport = null;
        }
    }

    fn emit(self: *NetworkConnection, event: Event) void {
        if (self.event_callback) |cb| cb(event, self);
        _ = self.event_ctx;
    }

    /// Thread-safe: send a raw IRC line. Safe to call from any thread.
    pub fn cmd(self: *NetworkConnection, data: []const u8) void {
        self.send_mutex.lock();
        defer self.send_mutex.unlock();
        if (self.transport) |*t| { t.writeLine(data) catch {}; }
    }

    /// Thread-safe: send two parts (a + b + \r\n). Safe to call from any thread.
    pub fn cmdTwo(self: *NetworkConnection, a: []const u8, b: []const u8) void {
        self.send_mutex.lock();
        defer self.send_mutex.unlock();
        if (self.transport) |*t| { t.writeRaw(a) catch {}; t.writeLine(b) catch {}; }
    }

    /// Thread-safe: send four parts (a + b + c + d + \r\n). For PRIVMSG construction.
    pub fn cmdFour(self: *NetworkConnection, a: []const u8, b: []const u8, c_part: []const u8, d: []const u8) void {
        self.send_mutex.lock();
        defer self.send_mutex.unlock();
        if (self.transport) |*t| { t.writeRaw(a) catch {}; t.writeRaw(b) catch {}; t.writeRaw(c_part) catch {}; t.writeLine(d) catch {}; }
    }

    /// Internal: send line (no mutex — event loop thread only).
    fn sendRaw(self: *NetworkConnection, data: []const u8) !void {
        const t = &(self.transport.?);
        try t.writeRaw(data);
    }

    fn sendLine(self: *NetworkConnection, data: []const u8) !void {
        const t = &(self.transport.?);
        try t.writeLine(data);
    }

    /// Internal: send two parts (no mutex — event loop thread only).
    fn sendTwo(self: *NetworkConnection, a: []const u8, b: []const u8) !void {
        const t = &(self.transport.?);
        try t.writeRaw(a);
        try t.writeLine(b);
    }

    fn readLine(self: *NetworkConnection) !?[]u8 {
        const t = &(self.transport.?);
        const res = try t.readLine(&self.read_buf, 100);
        if (res) |line| {
            return try self.allocator.dupe(u8, line);
        }
        return null;
    }

    // ── Registration ───────────────────────────────────────────

    fn connectAndRegister(self: *NetworkConnection) !void {
        self.setState(.connecting);
        const use_tls = self.config.tls != .disabled;
        self.transport = try Transport.connect(self.allocator, self.config.host, self.config.port, self.config.timeout_ms, use_tls, self.config.tls_insecure);
        errdefer self.close();

        // Send initial registration commands
        try self.sendLine("CAP LS 302");
        try self.sendTwo("NICK ", self.config.nick);
        {   // USER <nick> 0 * :<realname> — build as one line
            const user_line = try std.fmt.allocPrint(self.allocator, "USER {s} 0 * :{s}", .{ self.config.user, self.config.real_name });
            defer self.allocator.free(user_line);
            try self.sendLine(user_line);
        }

        var welcomed = false;
        var cap_req_sent = false;
        var cap_done = false;
        var sasl_done = (self.config.sasl_username == null);

        for (0..400) |_| {
            if (welcomed and cap_done and sasl_done) break;
            const line = try self.readLine() orelse {
                self.sleepMs(10);
                continue;
            };
            defer self.allocator.free(line);
            self.handleRegLine(&welcomed, &cap_req_sent, &cap_done, &sasl_done, line) catch continue;
        }

        for (self.config.auto_join_channels) |ch| {
            self.sendTwo("JOIN ", ch) catch {};
        }
    }

    fn handleRegLine(self: *NetworkConnection, welcomed: *bool, cap_req_sent: *bool, cap_done: *bool, sasl_done: *bool, line: []const u8) !void {
        if (mem.startsWith(u8, line, "PING")) {
            const cookie = if (line.len > 6) blk: {
                // PING :<cookie> or PING <cookie>
                break :blk if (line[5] == ':') line[6..] else line[5..];
            } else "";
            try self.sendRaw("PONG :");
            try self.sendLine(cookie);
            return;
        }
        if (mem.indexOf(u8, line, " 001 ") != null or
            mem.indexOf(u8, line, " 376 ") != null or
            mem.indexOf(u8, line, " 422 ") != null) welcomed.* = true;
        if (mem.indexOf(u8, line, " 433 ") != null or mem.indexOf(u8, line, " 432 ") != null) {
            const new_nick = try std.fmt.allocPrint(self.allocator, "{s}_", .{self.current_nick});
            defer self.allocator.free(new_nick);
            self.setCurrentNick(new_nick);
            const nick_out = self.getCurrentNick();
            defer self.allocator.free(nick_out);
            try self.sendTwo("NICK ", nick_out);
        }
        if (mem.indexOf(u8, line, " CAP ") != null) {
            if (mem.indexOf(u8, line, " LS ") != null) {
                try self.sendLine("CAP REQ :away-notify account-notify extended-join multi-prefix userhost-in-names server-time echo-message labeled-response");
                cap_req_sent.* = true;
            } else if (mem.indexOf(u8, line, " ACK ") != null) {
                if (self.config.sasl_username != null and mem.indexOf(u8, line, "sasl") != null) {
                    try self.sendSaslPlain();
                } else if (!cap_done.*) {
                    try self.sendLine("CAP END");
                    cap_done.* = true;
                }
            } else if (mem.indexOf(u8, line, " NAK ") != null) {
                if (!cap_done.*) { try self.sendLine("CAP END"); cap_done.* = true; }
            } else if (cap_req_sent.* and !cap_done.*) {
                // Non-CAP line after CAP REQ — send CAP END to finish negotiation
                try self.sendLine("CAP END");
                cap_done.* = true;
            }
        } else if (cap_req_sent.* and !cap_done.*) {
            // Line doesn't contain CAP — send CAP END if pending
            try self.sendLine("CAP END");
            cap_done.* = true;
        }
        if (mem.indexOf(u8, line, " 903 ") != null) {
            sasl_done.* = true;
            if (!cap_done.*) { try self.sendLine("CAP END"); cap_done.* = true; }
        }
    }

    fn sendSaslPlain(self: *NetworkConnection) !void {
        const username = self.config.sasl_username orelse return;
        const password = self.config.sasl_password orelse return;
        try self.sendLine("AUTHENTICATE PLAIN");
        const chal = (try self.readLine()) orelse return;
        defer self.allocator.free(chal);
        if (!mem.eql(u8, chal, "+")) return;
        var buf: [1024]u8 = undefined;
        var pos: usize = 0;
        buf[pos] = 0; pos += 1;
        @memcpy(buf[pos..][0..username.len], username); pos += username.len;
        buf[pos] = 0; pos += 1;
        @memcpy(buf[pos..][0..password.len], password); pos += password.len;
        var enc_buf: [2048]u8 = undefined;
        const encoded = std.base64.standard.Encoder.encode(enc_buf[0..], buf[0..pos]);
        try self.sendTwo("AUTHENTICATE ", encoded);
    }

    // ── Event Loop ─────────────────────────────────────────────

    fn eventLoop(self: *NetworkConnection) !void {
        var last_ping: i64 = currentTimeMs();
        while (self.getState() == .connected) {
            const line = try self.readLine() orelse {
                const now = currentTimeMs();
                if (now - last_ping >= 120_000) {
                    self.sendLine("PING :keepalive") catch {};
                    last_ping = now;
                }
                continue;
            };
            defer self.allocator.free(line);

            if (mem.startsWith(u8, line, "PING")) {
                const cookie = if (line.len > 6) blk: {
                    break :blk if (line[5] == ':') line[6..] else line[5..];
                } else "";
                self.sendRaw("PONG :") catch {};
                self.sendLine(cookie) catch {};
                continue;
            }
            if (mem.startsWith(u8, line, "PONG")) continue;

            var proto = zircon.ProtoMessage.parse(line) catch continue;
            if (proto.toMessage()) |msg| {
                self.dispatch(msg);
            }
        }
    }

    fn dispatch(self: *NetworkConnection, msg: zircon.Message) void {
        switch (msg) {
            .PRIVMSG => |m| self.emit(.{ .privmsg = .{
                .nick = extractNick(m.prefix), .target = m.targets, .text = m.text,
            } }),
            .JOIN => |m| {
                if (std.mem.eql(u8, extractNick(m.prefix), self.current_nick)) {
                    const ch = self.allocator.dupe(u8, m.channels) catch m.channels;
                    self.joined_channels.put(ch, {}) catch {};
                    if (self.parted_channels.fetchRemove(m.channels)) |kv| self.allocator.free(kv.key);
                }
                self.emit(.{ .join = .{
                    .nick = extractNick(m.prefix), .channel = m.channels,
                } });
            },
            .PART => |m| {
                if (std.mem.eql(u8, extractNick(m.prefix), self.current_nick)) {
                    if (self.joined_channels.fetchRemove(m.channels)) |kv| self.allocator.free(kv.key);
                    const ch = self.allocator.dupe(u8, m.channels) catch m.channels;
                    self.parted_channels.put(ch, {}) catch {};
                }
                self.emit(.{ .part = .{
                    .nick = extractNick(m.prefix), .channel = m.channels, .reason = m.reason,
                } });
            },
            .QUIT => |m| self.emit(.{ .quit = .{
                .nick = extractNick(m.prefix), .reason = m.reason,
            } }),
            .NOTICE => |m| self.emit(.{ .notice = .{
                .nick = extractNick(m.prefix), .text = m.text,
            } }),
            .NICK => |m| {
                if (std.mem.eql(u8, extractNick(m.prefix), self.current_nick)) {
                    self.setCurrentNick(m.nickname);
                }
                self.emit(.{ .nick = .{
                    .old = extractNick(m.prefix), .new = m.nickname,
                } });
            },
            .TOPIC => |m| self.emit(.{ .topic = .{
                .nick = extractNick(m.prefix), .channel = m.channel, .topic = m.text,
            } }),
            else => {},
        }
    }

    fn sleepMs(self: *NetworkConnection, ms: u64) void {
        _ = self;
        var ts = std.c.timespec{
            .sec = @intCast(ms / 1000),
            .nsec = @intCast((ms % 1000) * 1000000),
        };
        _ = std.c.nanosleep(&ts, null);
    }
};

fn extractNick(prefix: ?zircon.Prefix) []const u8 {
    return if (prefix) |p| p.nick orelse "?" else "?";
}

fn backoffDelay(attempt: u32) u64 {
    const shift: u6 = @intCast(@min(attempt, 10));
    return @min(@as(u64, 15000) * (@as(u64, 1) << shift), 300000);
}

pub fn currentTimeMs() i64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(std.c.CLOCK.REALTIME, &ts);
    return ts.sec * 1000 + @divTrunc(ts.nsec, 1000000);
}
