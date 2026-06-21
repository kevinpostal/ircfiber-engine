//! # Redis IPC — Control queue, event stream, state snapshots
//!
//! Minimal Redis RESP protocol for the engine's control plane.
//! Supports configurable host/port and automatic reconnect on I/O errors.

const std = @import("std");
const mem = std.mem;

const c = @cImport({
    @cInclude("sys/types.h");
    @cInclude("sys/socket.h");
    @cInclude("netdb.h");
    @cInclude("netinet/in.h");
    @cInclude("unistd.h");
    @cInclude("poll.h");
    @cInclude("time.h");
});

pub const Config = struct {
    host: []const u8 = "127.0.0.1",
    port: u16 = 6379,
    server_id: []const u8 = "default",
};

pub const RedisIPC = struct {
    allocator: std.mem.Allocator,
    config: Config,
    fd: c_int,
    read_buf: [16384]u8,
    buf_pos: usize,

    pub fn init(allocator: std.mem.Allocator, config: Config) RedisIPC {
        return .{ .allocator = allocator, .config = config, .fd = -1, .read_buf = undefined, .buf_pos = 0 };
    }

    pub fn connect(self: *RedisIPC) !void {
        try self.doReconnect();
    }

    pub fn close(self: *RedisIPC) void {
        if (self.fd >= 0) _ = c.close(self.fd);
        self.fd = -1;
        self.buf_pos = 0;
    }

    fn doReconnect(self: *RedisIPC) !void {
        self.close();
        self.fd = try tcpConnect(self.config.host, self.config.port);
        self.buf_pos = 0;
    }

    fn ensureConnected(self: *RedisIPC) !void {
        if (self.fd < 0) try self.doReconnect();
    }

    // ── Low-level I/O ──────────────────────────────────────────

    fn send(self: *RedisIPC, data: []const u8) !void {
        try self.ensureConnected();
        var pos: usize = 0;
        while (pos < data.len) {
            const sent = c.write(self.fd, data.ptr + pos, @intCast(data.len - pos));
            if (sent < 0) return error.WriteFailed;
            pos += @intCast(sent);
        }
    }

    fn sendWithRetry(self: *RedisIPC, data: []const u8) !void {
        self.send(data) catch {
            try self.doReconnect();
            try self.send(data);
        };
    }

    fn readLine(self: *RedisIPC) ![]u8 {
        while (self.buf_pos < self.read_buf.len) {
            if (mem.indexOfScalar(u8, self.read_buf[0..self.buf_pos], '\n')) |nl| {
                const line_end = if (nl > 0 and self.read_buf[nl - 1] == '\r') nl - 1 else nl;
                const line = try self.allocator.dupe(u8, self.read_buf[0..line_end]);
                const remaining = self.buf_pos - (nl + 1);
                if (remaining > 0) {
                    @memmove(self.read_buf[0..remaining], self.read_buf[nl + 1 .. self.buf_pos]);
                }
                self.buf_pos = remaining;
                return line;
            }

            var pfd: c.struct_pollfd = .{ .fd = self.fd, .events = c.POLLIN, .revents = 0 };
            if (c.poll(&pfd, 1, 10000) <= 0) return error.Timeout;
            const n = c.read(self.fd, &self.read_buf[self.buf_pos], @intCast(self.read_buf.len - self.buf_pos));
            if (n <= 0) return error.ConnectionClosed;
            self.buf_pos += @intCast(n);
        }
        return error.BufferOverflow;
    }

    fn readBulkString(self: *RedisIPC) ![]u8 {
        const first = try self.readLine();
        if (first.len < 2 or first[0] != '$') return error.UnexpectedReply;
        const len_str = first[1..];
        const len = std.fmt.parseInt(usize, len_str, 10) catch return error.InvalidReply;
        if (len == 0) return self.allocator.dupe(u8, "");
        if (len > self.read_buf.len) return error.BufferOverflow;
        while (self.buf_pos < len + 2) {
            var pfd: c.struct_pollfd = .{ .fd = self.fd, .events = c.POLLIN, .revents = 0 };
            if (c.poll(&pfd, 1, 10000) <= 0) return error.Timeout;
            const n = c.read(self.fd, &self.read_buf[self.buf_pos], @intCast(self.read_buf.len - self.buf_pos));
            if (n <= 0) return error.ConnectionClosed;
            self.buf_pos += @intCast(n);
        }
        const result = try self.allocator.dupe(u8, self.read_buf[0..len]);
        self.buf_pos = 0;
        return result;
    }

    fn drain(self: *RedisIPC) !void {
        _ = try self.readLine();
    }

    fn execCmd(self: *RedisIPC, data: []const u8) !void {
        try self.sendWithRetry(data);
        self.drain() catch {
            try self.doReconnect();
            try self.sendWithRetry(data);
            try self.drain();
        };
    }

    // ── Commands ───────────────────────────────────────────────

    pub fn hset(self: *RedisIPC, key: []const u8, field: []const u8, value: []const u8) !void {
        const data = try std.fmt.allocPrint(self.allocator, "*4\r\n$4\r\nHSET\r\n${d}\r\n{s}\r\n${d}\r\n{s}\r\n${d}\r\n{s}\r\n", .{ key.len, key, field.len, field, value.len, value });
        defer self.allocator.free(data);
        try self.execCmd(data);
    }

    pub fn hget(self: *RedisIPC, key: []const u8, field: []const u8) !?[]u8 {
        const data = try std.fmt.allocPrint(self.allocator, "*3\r\n$4\r\nHGET\r\n${d}\r\n{s}\r\n${d}\r\n{s}\r\n", .{ key.len, key, field.len, field });
        defer self.allocator.free(data);

        var retry: bool = false;
        while (true) {
            self.sendWithRetry(data) catch {
                if (retry) return error.WriteFailed;
                retry = true;
                continue;
            };
            const first = self.readLine() catch {
                if (retry) return error.ConnectionClosed;
                retry = true;
                try self.doReconnect();
                continue;
            };
            defer self.allocator.free(first);
            if (first.len == 1 and first[0] == '$') {
                // nil reply
                return null;
            }
            if (first.len < 2 or first[0] != '$') return error.UnexpectedReply;
            const len = std.fmt.parseInt(usize, first[1..], 10) catch return error.InvalidReply;
            if (len == 0) return try self.allocator.dupe(u8, "");
            const val = self.readLine() catch |err| { if (retry) return err; retry = true; try self.doReconnect(); continue; };
            return val;
        }
    }

    pub const HashEntry = struct { field: []const u8, value: []const u8 };

    pub fn hgetall(self: *RedisIPC, key: []const u8) ![]HashEntry {
        const data = try std.fmt.allocPrint(self.allocator, "*2\r\n$7\r\nHGETALL\r\n${d}\r\n{s}\r\n", .{ key.len, key });
        defer self.allocator.free(data);

        var retry: bool = false;
        while (true) {
            self.sendWithRetry(data) catch {
                if (retry) return error.WriteFailed;
                retry = true;
                continue;
            };
            const first = self.readLine() catch {
                if (retry) return error.ConnectionClosed;
                retry = true;
                try self.doReconnect();
                continue;
            };
            defer self.allocator.free(first);
            if (first.len < 2 or first[0] != '*') return error.UnexpectedReply;
            const count = std.fmt.parseInt(usize, first[1..], 10) catch return error.InvalidReply;
            if (count == 0) return &[_]HashEntry{};
            const entries = try self.allocator.alloc(HashEntry, count / 2);
            errdefer self.allocator.free(entries);
            var i: usize = 0;
            while (i < entries.len) : (i += 1) {
                const fl = self.readLine() catch |err| { if (retry) return err; retry = true; try self.doReconnect(); continue; };
                defer self.allocator.free(fl);
                if (fl.len < 2 or fl[0] != '$') return error.UnexpectedReply;
                const flen = std.fmt.parseInt(usize, fl[1..], 10) catch return error.InvalidReply;
                const fval = self.readLine() catch |err| { if (retry) return err; retry = true; try self.doReconnect(); continue; };
                entries[i].field = fval;

                const vl = self.readLine() catch |err| { if (retry) return err; retry = true; try self.doReconnect(); continue; };
                defer self.allocator.free(vl);
                if (vl.len < 2 or vl[0] != '$') return error.UnexpectedReply;
                const vlen = std.fmt.parseInt(usize, vl[1..], 10) catch return error.InvalidReply;
                const vval = self.readLine() catch |err| { if (retry) return err; retry = true; try self.doReconnect(); continue; };
                entries[i].value = vval;
                _ = flen;
                _ = vlen;
            }
            return entries;
        }
    }

    pub fn lpush(self: *RedisIPC, key: []const u8, value: []const u8) !void {
        const data = try std.fmt.allocPrint(self.allocator, "*3\r\n$5\r\nLPUSH\r\n${d}\r\n{s}\r\n${d}\r\n{s}\r\n", .{ key.len, key, value.len, value });
        defer self.allocator.free(data);
        try self.execCmd(data);
    }

    pub fn blpop(self: *RedisIPC, key: []const u8, timeout_sec: u32) !?[]u8 {
        const data = try std.fmt.allocPrint(self.allocator, "*3\r\n$5\r\nBLPOP\r\n${d}\r\n{s}\r\n${d}\r\n{d}\r\n", .{ key.len, key, 1, timeout_sec });
        defer self.allocator.free(data);

        var retry: bool = false;
        while (true) {
            self.sendWithRetry(data) catch {
                if (retry) return error.WriteFailed;
                retry = true;
                continue;
            };

            const first = self.readLine() catch {
                if (retry) return error.ConnectionClosed;
                retry = true;
                try self.doReconnect();
                continue;
            };
            if (mem.startsWith(u8, first, "*-1")) {
                self.allocator.free(first);
                return null;
            }
            // Skip: $<keylen> and <key>
            _ = self.readLine() catch { self.allocator.free(first); if (retry) return error.ConnectionClosed; retry = true; try self.doReconnect(); continue; };
            _ = self.readLine() catch { self.allocator.free(first); if (retry) return error.ConnectionClosed; retry = true; try self.doReconnect(); continue; };
            self.allocator.free(first);
            // Read: $<vallen>
            _ = self.readLine() catch |err| { if (retry) return err; retry = true; try self.doReconnect(); continue; };
            // Read: <val>
            const val = self.readLine() catch |err| { if (retry) return err; retry = true; try self.doReconnect(); continue; };
            return val;
        }
    }

    pub fn publish(self: *RedisIPC, channel: []const u8, message: []const u8) !void {
        const data = try std.fmt.allocPrint(self.allocator, "*3\r\n$7\r\nPUBLISH\r\n${d}\r\n{s}\r\n${d}\r\n{s}\r\n", .{ channel.len, channel, message.len, message });
        defer self.allocator.free(data);
        try self.execCmd(data);
    }

    pub fn sadd(self: *RedisIPC, key: []const u8, member: []const u8) !void {
        const data = try std.fmt.allocPrint(self.allocator, "*3\r\n$4\r\nSADD\r\n${d}\r\n{s}\r\n${d}\r\n{s}\r\n", .{ key.len, key, member.len, member });
        defer self.allocator.free(data);
        try self.execCmd(data);
    }

    pub fn ltrim(self: *RedisIPC, key: []const u8, start: i64, stop: i64) !void {
        const start_fmt = try std.fmt.allocPrint(self.allocator, "{d}", .{start});
        defer self.allocator.free(start_fmt);
        const stop_fmt = try std.fmt.allocPrint(self.allocator, "{d}", .{stop});
        defer self.allocator.free(stop_fmt);
        const data = try std.fmt.allocPrint(self.allocator, "*4\r\n$5\r\nLTRIM\r\n${d}\r\n{s}\r\n${d}\r\n{s}\r\n${d}\r\n{s}\r\n", .{ key.len, key, start_fmt.len, start_fmt, stop_fmt.len, stop_fmt });
        defer self.allocator.free(data);
        try self.execCmd(data);
    }

    pub fn incr(self: *RedisIPC, key: []const u8) !i64 {
        const data = try std.fmt.allocPrint(self.allocator, "*2\r\n$4\r\nINCR\r\n${d}\r\n{s}\r\n", .{ key.len, key });
        defer self.allocator.free(data);

        var retry: bool = false;
        while (true) {
            self.sendWithRetry(data) catch {
                if (retry) return error.WriteFailed;
                retry = true;
                continue;
            };
            const line = self.readLine() catch {
                if (retry) return error.ConnectionClosed;
                retry = true;
                try self.doReconnect();
                continue;
            };
            defer self.allocator.free(line);
            if (line.len > 0 and line[0] == ':') return std.fmt.parseInt(i64, line[1..], 10) catch 0;
            return 0;
        }
    }
};

// ── TCP Connect ─────────────────────────────────────────────────

const SockAddrStorage = extern union {
    v4: c.struct_sockaddr_in,
    v6: c.struct_sockaddr_in6,
    ll: [28]u8,
};

fn tcpConnect(host_str: []const u8, port: u16) !c_int {
    const host_z = try std.heap.page_allocator.alloc(u8, host_str.len + 1);
    defer std.heap.page_allocator.free(host_z);
    @memcpy(host_z[0..host_str.len], host_str);
    host_z[host_str.len] = 0;

    const port_str = try std.fmt.allocPrint(std.heap.page_allocator, "{d}", .{port});
    defer std.heap.page_allocator.free(port_str);
    const port_z = try std.heap.page_allocator.alloc(u8, port_str.len + 1);
    defer std.heap.page_allocator.free(port_z);
    @memcpy(port_z[0..port_str.len], port_str);
    port_z[port_str.len] = 0;

    var hints: c.struct_addrinfo = undefined;
    @memset(@as([*]u8, @ptrCast(&hints))[0..@sizeOf(@TypeOf(hints))], 0);
    hints.ai_family = c.AF_UNSPEC;
    hints.ai_socktype = c.SOCK_STREAM;
    hints.ai_protocol = c.IPPROTO_TCP;

    var result: ?*c.struct_addrinfo = null;
    const rc = c.getaddrinfo(
        @as(?[*:0]const u8, @ptrCast(host_z.ptr)),
        @as(?[*:0]const u8, @ptrCast(port_z.ptr)),
        &hints,
        &result,
    );
    if (rc != 0) return error.HostNotFound;
    defer c.freeaddrinfo(result);

    var ri = result;
    while (ri) |r| {
        const family = r.ai_family;
        const sock = c.socket(family, c.SOCK_STREAM, c.IPPROTO_TCP);
        if (sock < 0) {
            ri = r.ai_next;
            continue;
        }
        const addr_len: c.socklen_t = @intCast(r.ai_addrlen);
        if (c.connect(sock, r.ai_addr, addr_len) < 0) {
            _ = c.close(sock);
            ri = r.ai_next;
            continue;
        }
        return sock;
    }
    return error.ConnectionFailed;
}
