//! Transport — TCP socket with optional TLS via OpenSSL.
//! Each connection thread does blocking TLS handshake (matching Dlang engine).

const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const Allocator = mem.Allocator;

const c = @cImport({
    @cInclude("sys/types.h");
    @cInclude("sys/socket.h");
    @cInclude("netdb.h");
    @cInclude("fcntl.h");
    @cInclude("unistd.h");
    @cInclude("poll.h");
    @cInclude("netinet/tcp.h");
    @cInclude("time.h");
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/err.h");
});

const SockAddrStorage = extern union {
    v4: c.struct_sockaddr_in,
    v6: c.struct_sockaddr_in6,
    ll: [28]u8,
};

pub const Transport = struct {
    allocator: Allocator,
    fd: c_int,
    hostname: []const u8,
    read_pos: usize = 0,
    ssl: ?*c.SSL = null,   // Non-null if TLS

    pub fn connect(
        allocator: Allocator,
        host: []const u8, port: u16,
        timeout_ms: u64, use_tls: bool, tls_insecure: bool,
    ) !Transport {
        if (use_tls) return connectTls(allocator, host, port, timeout_ms, tls_insecure);
        return connectPlain(allocator, host, port, timeout_ms);
    }

    pub fn adopt(allocator: Allocator, raw_fd: c_int, host: []const u8) !Transport {
        return .{ .allocator = allocator, .fd = raw_fd, .hostname = try allocator.dupe(u8, host) };
    }

    pub fn getFd(self: Transport) c_int { return self.fd; }
    pub fn isPlain(self: Transport) bool { return self.ssl == null; }

    pub fn readLine(self: *Transport, buf: []u8, timeout_ms: u64) !?[]u8 {
        const deadline = currentTimeMs() + @as(i64, @intCast(timeout_ms));
        while (true) {
            if (mem.indexOf(u8, buf[0..self.read_pos], "\r\n")) |idx| {
                const line = buf[0..idx];
                const rem = self.read_pos - (idx + 2);
                if (rem > 0) @memmove(buf[0..rem], buf[idx + 2 .. self.read_pos]);
                self.read_pos = rem;
                return line;
            }
            if (self.read_pos >= buf.len) return error.BufferOverflow;
            if (currentTimeMs() >= deadline) return null;
            if (!waitReadable(self.fd, 50)) continue;

            const n = if (self.ssl) |s| c.SSL_read(s, &buf[self.read_pos], @intCast(buf.len - self.read_pos))
                      else c.read(self.fd, &buf[self.read_pos], @intCast(buf.len - self.read_pos));
            if (n <= 0) return error.ConnectionClosed;
            self.read_pos += @intCast(n);
        }
    }

    pub fn writeRaw(self: *Transport, data: []const u8) !void {
        if (self.ssl) |s| {
            if (c.SSL_write(s, data.ptr, @intCast(data.len)) <= 0) return error.WriteFailed;
        } else {
            if (c.write(self.fd, data.ptr, @intCast(data.len)) < 0) return error.WriteFailed;
        }
    }

    pub fn writeLine(self: *Transport, data: []const u8) !void {
        var sb: [8192]u8 = undefined;
        const max = sb.len - 2;
        const w = if (data.len > max) data[0..max] else data;
        @memcpy(sb[0..w.len], w);
        sb[w.len] = '\r';
        sb[w.len + 1] = '\n';
        if (self.ssl) |s| {
            if (c.SSL_write(s, &sb, @intCast(w.len + 2)) <= 0) return error.WriteFailed;
        } else {
            if (c.write(self.fd, &sb, @intCast(w.len + 2)) < 0) return error.WriteFailed;
        }
    }

    pub fn close(self: *Transport) void {
        if (self.ssl) |s| {
            _ = c.SSL_shutdown(s);
            c.SSL_free(s);
        }
        if (self.fd >= 0) _ = c.close(self.fd);
        self.allocator.free(self.hostname);
    }
};

// ── TLS connect via OpenSSL (blocking, like Dlang's vibe.d) ──────

fn connectTls(allocator: Allocator, host: []const u8, port: u16, _: u64, insecure: bool) !Transport {
    var t = try connectPlain(allocator, host, port, 10000);
    errdefer t.close();

    const ssl_ctx = c.SSL_CTX_new(c.TLS_client_method());
    if (ssl_ctx == null) return error.TlsFailed;
    errdefer c.SSL_CTX_free(ssl_ctx);
    _ = c.SSL_CTX_set_min_proto_version(ssl_ctx, c.TLS1_2_VERSION);

    if (insecure) {
        c.SSL_CTX_set_verify(ssl_ctx, c.SSL_VERIFY_NONE, null);
    }

    const ssl = c.SSL_new(ssl_ctx);
    if (ssl == null) return error.TlsFailed;
    errdefer c.SSL_free(ssl);

    _ = c.SSL_set_fd(ssl, t.fd);
    _ = c.SSL_set_tlsext_host_name(ssl, host.ptr);

    const ret = c.SSL_connect(ssl);
    if (ret != 1) {
        const err = c.SSL_get_error(ssl, ret);
        std.debug.print("TLS error: {d}\n", .{err});
        return error.TlsHandshakeFailed;
    }

    c.SSL_CTX_free(ssl_ctx);
    t.ssl = ssl;
    return t;
}

fn connectPlain(allocator: Allocator, host: []const u8, port: u16, timeout_ms: u64) !Transport {
    const addrs = try resolveHost(allocator, host, port, timeout_ms);
    defer allocator.free(addrs);
    if (addrs.len == 0) return error.HostNotFound;
    for (0..addrs.len) |i| {
        const addr = &addrs[i];
        const sock = c.socket(addr.v4.sin_family, c.SOCK_STREAM, c.IPPROTO_TCP);
        if (sock < 0) continue;
        if (!setNonBlocking(sock)) { _ = c.close(sock); continue; }
        setNoDelay(sock);
        if (!connectSock(sock, addr, @sizeOf(SockAddrStorage), timeout_ms)) { _ = c.close(sock); continue; }
        setBlocking(sock);
        return .{ .allocator = allocator, .fd = sock, .hostname = try allocator.dupe(u8, host) };
    }
    return error.ConnectionFailed;
}

// ── DNS + Connect Helpers ────────────────────────────────────────

fn resolveHost(allocator: Allocator, host: []const u8, port: u16, _: u64) ![]SockAddrStorage {
    const host_z = try allocator.alloc(u8, host.len + 1);
    defer allocator.free(host_z);
    @memcpy(host_z[0..host.len], host); host_z[host.len] = 0;
    const ps = try std.fmt.allocPrint(allocator, "{d}", .{port});
    defer allocator.free(ps);
    const port_z = try allocator.alloc(u8, ps.len + 1);
    defer allocator.free(port_z);
    @memcpy(port_z[0..ps.len], ps); port_z[ps.len] = 0;

    var hints: c.struct_addrinfo = undefined;
    @memset(@as([*]u8, @ptrCast(&hints))[0..@sizeOf(@TypeOf(hints))], 0);
    hints.ai_family = c.AF_UNSPEC;
    hints.ai_socktype = c.SOCK_STREAM;
    hints.ai_protocol = c.IPPROTO_TCP;

    var result: ?*c.struct_addrinfo = null;
    const rc = c.getaddrinfo(@ptrCast(host_z.ptr), @ptrCast(port_z.ptr), &hints, &result);
    if (rc != 0) return error.HostNotFound;
    defer c.freeaddrinfo(result);

    var count: usize = 0;
    var ri = result;
    while (ri) |r| { count += 1; ri = r.ai_next; }
    if (count == 0) return error.HostNotFound;

    const addrs = try allocator.alloc(SockAddrStorage, count);
    var idx: usize = 0; ri = result;
    while (ri) |r| {
        const len = @min(r.ai_addrlen, @sizeOf(SockAddrStorage));
        @memcpy(@as([*]u8, @ptrCast(&addrs[idx]))[0..len], @as([*]u8, @ptrCast(r.ai_addr))[0..len]);
        idx += 1; ri = r.ai_next;
    }
    return addrs;
}

fn setNoDelay(sock: c_int) void {
    const flag: c_int = 1;
    _ = c.setsockopt(sock, c.IPPROTO_TCP, c.TCP_NODELAY, &flag, @sizeOf(c_int));
}
fn setNonBlocking(sock: c_int) bool {
    const flags = c.fcntl(sock, c.F_GETFL, @as(c_int, 0));
    if (flags < 0) return false;
    return c.fcntl(sock, c.F_SETFL, flags | c.O_NONBLOCK) >= 0;
}
fn setBlocking(sock: c_int) void {
    const flags = c.fcntl(sock, c.F_GETFL, @as(c_int, 0));
    if (flags >= 0) { _ = c.fcntl(sock, c.F_SETFL, flags & ~c.O_NONBLOCK); }
}
fn waitReadable(sock: c_int, timeout_ms: u64) bool {
    var pfd: c.struct_pollfd = .{ .fd = sock, .events = c.POLLIN, .revents = 0 };
    return c.poll(&pfd, 1, @intCast(timeout_ms)) > 0;
}
fn waitWritable(sock: c_int, timeout_ms: u64) bool {
    var pfd: c.struct_pollfd = .{ .fd = sock, .events = c.POLLOUT, .revents = 0 };
    return c.poll(&pfd, 1, @intCast(timeout_ms)) > 0;
}
fn connectSock(sock: c_int, addr: *const SockAddrStorage, addr_len: usize, timeout_ms: u64) bool {
    const sa: *align(2) const u8 = @ptrCast(addr);
    const rc = c.connect(sock, @alignCast(@ptrCast(sa)), @intCast(addr_len));
    if (rc == 0) return true;
    if (!waitWritable(sock, timeout_ms)) return false;
    var so_error: c_int = 0;
    var err_len: c.socklen_t = @sizeOf(c_int);
    _ = c.getsockopt(sock, c.SOL_SOCKET, c.SO_ERROR, &so_error, &err_len);
    return so_error == 0;
}
fn currentTimeMs() i64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(std.c.CLOCK.REALTIME, &ts);
    return ts.sec * 1000 + @divTrunc(ts.nsec, 1000000);
}
