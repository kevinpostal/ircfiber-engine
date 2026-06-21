//! # Reload — SCM_RIGHTS file descriptor passing
//!
//! Implements graceful engine reload via Unix socket FD transfer.
//! The old engine sends active IRC connection FDs to the new engine,
//! which adopts them without dropping the connection.
//!
//! ## Protocol
//!
//! 1. New engine connects to `/tmp/ircfiber-reload-<pid>.sock`
//! 2. New engine sends: `"READY\n"` (handshake)
//! 3. Old engine sends: JSON metadata array → `\n`
//! 4. New engine sends: `"ACK\n"`
//! 5. Old engine sends: SCM_RIGHTS message containing all FDs
//! 6. New engine sends: `"DONE\n"`
//! 7. Old engine exits

const std = @import("std");
const posix = std.posix;
const mem = std.mem;
const Allocator = mem.Allocator;

const MAX_FDS_PER_MSG = 64; // Linux limit: (CMSG_SPACE - CMSG_HDR) / sizeof(int)

extern fn ircfiber_cmsg_space(len: usize) usize;
extern fn ircfiber_cmsg_firsthdr(m: *posix.msghdr) ?*std.c.cmsghdr;
extern fn ircfiber_cmsg_nxthdr(m: *posix.msghdr, c: *std.c.cmsghdr) ?*std.c.cmsghdr;
extern fn ircfiber_cmsg_data(c: *std.c.cmsghdr) [*]u8;

// Zig 0.16 removed several `std.posix` wrappers; use libc directly.
fn sysClose(fd: posix.fd_t) void { _ = std.c.close(fd); }
fn sysUnlink(path: []const u8) void {
    var buf: [256]u8 = undefined;
    const len = @min(path.len, buf.len - 1);
    @memcpy(buf[0..len], path[0..len]);
    buf[len] = 0;
    _ = std.c.unlink(buf[0..len :0]);
}
fn sysWrite(fd: posix.fd_t, data: []const u8) !void {
    const n = std.c.write(fd, data.ptr, data.len);
    if (n < 0) return error.WriteFailed;
}
fn sysRead(fd: posix.fd_t, buf: []u8) !usize {
    const n = std.c.read(fd, buf.ptr, buf.len);
    if (n < 0) return error.ReadFailed;
    if (n == 0) return error.ConnectionClosed;
    return @intCast(n);
}
fn sysBind(fd: posix.fd_t, addr: *const posix.sockaddr.un, len: posix.socklen_t) !void {
    if (std.c.bind(fd, @ptrCast(addr), len) != 0) return error.BindFailed;
}
fn sysListen(fd: posix.fd_t, backlog: c_int) !void {
    if (std.c.listen(fd, @intCast(backlog)) != 0) return error.ListenFailed;
}
fn sysAccept(fd: posix.fd_t) !posix.fd_t {
    const client = std.c.accept(fd, null, null);
    if (client < 0) return error.AcceptFailed;
    return client;
}
fn sysConnect(fd: posix.fd_t, addr: *const posix.sockaddr.un, len: posix.socklen_t) !void {
    if (std.c.connect(fd, @ptrCast(addr), len) != 0) return error.ConnectFailed;
}
fn sysSocket(domain: c_int, typ: c_int, protocol: c_int) !posix.fd_t {
    const s = std.c.socket(@intCast(domain), @intCast(typ), @intCast(protocol));
    if (s < 0) return error.SocketFailed;
    return s;
}
fn sysSocketpair(domain: c_int, typ: c_int, protocol: c_int, fds: *[2]posix.fd_t) !void {
    if (std.c.socketpair(@intCast(domain), @intCast(typ), @intCast(protocol), fds) != 0) return error.SocketPairFailed;
}
fn sysSendmsg(fd: posix.fd_t, msg: *posix.msghdr, flags: u32) !void {
    const n = std.c.sendmsg(fd, @ptrCast(msg), flags);
    if (n < 0) return error.SendmsgFailed;
}
fn sysRecvmsg(fd: posix.fd_t, msg: *posix.msghdr, flags: u32) !usize {
    const n = std.c.recvmsg(fd, msg, flags);
    if (n < 0) return error.RecvmsgFailed;
    if (n == 0) return error.ConnectionClosed;
    return @intCast(n);
}

/// Reload metadata for one network connection.
pub const ReloadNetwork = struct {
    /// UUID string of the network
    network_id: []const u8,
    /// IRC hostname (e.g., "irc.libera.chat")
    host: []const u8,
    /// Current IRC nick
    nick: []const u8,
    /// Owning user id
    user_id: []const u8 = "",
    /// IRC port
    port: u16 = 6667,
    /// Raw socket file descriptor
    fd: posix.socket_t,
};

/// Result from a successful reload receive.
pub const ReloadResult = struct {
    networks: []ReloadNetwork,
    allocator: Allocator,

    pub fn deinit(self: *ReloadResult) void {
        for (self.networks) |*n| {
            self.allocator.free(n.network_id);
            self.allocator.free(n.host);
            self.allocator.free(n.nick);
            if (n.user_id.len > 0) self.allocator.free(n.user_id);
        }
        self.allocator.free(self.networks);
    }
};

// ── Reload Server (old engine) ───────────────────────────────────

/// Path to the reload socket. Old engine writes this, new engine reads.
pub fn reloadSocketPath(allocator: Allocator, old_pid: posix.pid_t) ![]u8 {
    return std.fmt.allocPrint(allocator, "/tmp/ircfiber-reload-{d}.sock", .{old_pid});
}

/// Serve a reload — listen on Unix socket, transfer metadata + FDs,
/// then return. The old engine should exit after this.
pub fn serveReload(
    networks: []const ReloadNetwork,
    socket_path: []const u8,
) !void {
    std.log.info("RELOAD: Starting reload server on {s} with {d} connections", .{ socket_path, networks.len });

    // Create Unix socket
    const sock = try createUnixListener(socket_path);
    defer {
        sysClose(sock);
        sysUnlink(socket_path);
    }

    // Accept one client connection
    const client = try acceptTimeout(sock, 30_000); // 30s timeout
    defer sysClose(client);

    // Read handshake: "READY\n"
    var handshake_buf: [16]u8 = undefined;
    const handshake_n = try sysRead(client, &handshake_buf);
    if (!mem.startsWith(u8, handshake_buf[0..handshake_n], "READY")) {
        return error.HandshakeFailed;
    }

    // Send JSON metadata
    try sendJSON(client, networks);
    std.log.info("RELOAD: Sent {d} network configs", .{networks.len});

    // Wait for ACK
    var ack_buf: [8]u8 = undefined;
    const ack_n = try sysRead(client, &ack_buf);
    if (!mem.startsWith(u8, ack_buf[0..ack_n], "ACK")) {
        return error.ProtocolError;
    }

    // Send FDs via SCM_RIGHTS
    var fds: [MAX_FDS_PER_MSG]posix.socket_t = undefined;
    for (networks, 0..) |net, i| {
        fds[i] = net.fd;
    }
    try sendFDs(client, fds[0..networks.len]);
    std.log.info("RELOAD: Sent {d} file descriptors", .{networks.len});

    // Wait for DONE
    const done_n = try sysRead(client, &ack_buf);
    if (!mem.startsWith(u8, ack_buf[0..done_n], "DONE")) {
        return error.ProtocolError;
    }

    std.log.info("RELOAD: Reload complete — {d} connections transferred", .{networks.len});
}

// ── Reload Client (new engine) ───────────────────────────────────

/// Connect to the old engine's reload socket and receive all
/// metadata + file descriptors. Caller owns the returned ReloadResult.
pub fn receiveReload(allocator: Allocator, socket_path: []const u8) !ReloadResult {
    std.log.info("RELOAD: Connecting to reload socket {s}", .{socket_path});

    // Connect to Unix socket
    const sock = try connectUnixSocket(socket_path);
    defer sysClose(sock);

    // Send handshake
    _ = try sysWrite(sock, "READY\n");

    // Receive JSON metadata
    const json_str = try recvJSON(allocator, sock);
    defer allocator.free(json_str);
    std.log.info("RELOAD: Received JSON: {s}", .{json_str});

    // Parse JSON metadata
    const networks = try parseReloadJSON(allocator, json_str);

    // Send ACK
    _ = try sysWrite(sock, "ACK\n");

    // Receive FDs
    const fds = try recvFDs(allocator, sock);
    defer allocator.free(fds);

    std.log.info("RELOAD: Received {d} FDs for {d} networks", .{ fds.len, networks.len });

    if (fds.len != networks.len) {
        return error.ProtocolMismatch;
    }

    // Assign FDs to networks
    for (networks, fds, 0..) |*net, fd, i| {
        _ = i;
        net.fd = fd;
    }

    // Send DONE
    _ = try sysWrite(sock, "DONE\n");

    std.log.info("RELOAD: Successfully received {d} connections", .{networks.len});

    return ReloadResult{
        .networks = networks,
        .allocator = allocator,
    };
}

// ── Unix Socket Helpers ──────────────────────────────────────────

fn createUnixListener(path: []const u8) !posix.socket_t {
    // Remove stale socket file
    sysUnlink(path);

    const s = try sysSocket(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    errdefer sysClose(s);

    var addr: posix.sockaddr.un = undefined;
    addr.family = posix.AF.UNIX;
    @memcpy(addr.path[0..@min(path.len, addr.path.len - 1)], path);
    addr.path[@min(path.len, addr.path.len - 1)] = 0;

    const addr_len: posix.socklen_t = @intCast(@offsetOf(posix.sockaddr.un, "path") + path.len + 1);
    try sysBind(s, &addr, addr_len);
    try sysListen(s, 1);

    return s;
}

fn acceptTimeout(sock: posix.socket_t, timeout_ms: u32) !posix.socket_t {
    var fds: [1]posix.pollfd = .{.{ .fd = sock, .events = posix.POLL.IN, .revents = 0 }};
    const n = try posix.poll(&fds, @intCast(timeout_ms));
    if (n == 0) return error.AcceptTimeout;

    const client = try sysAccept(sock);
    return client;
}

fn connectUnixSocket(path: []const u8) !posix.socket_t {
    const s = try sysSocket(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    errdefer sysClose(s);

    var addr: posix.sockaddr.un = undefined;
    addr.family = posix.AF.UNIX;
    @memcpy(addr.path[0..@min(path.len, addr.path.len - 1)], path);
    addr.path[@min(path.len, addr.path.len - 1)] = 0;

    const addr_len: posix.socklen_t = @intCast(@offsetOf(posix.sockaddr.un, "path") + path.len + 1);
    try sysConnect(s, &addr, addr_len);

    return s;
}

// ── JSON Serialization ───────────────────────────────────────────

fn appendSlice(buf: []u8, pos: *usize, data: []const u8) !void {
    if (pos.* + data.len > buf.len) return error.BufferOverflow;
    @memcpy(buf[pos.*..pos.* + data.len], data);
    pos.* += data.len;
}

fn appendFmt(buf: []u8, pos: *usize, comptime fmt: []const u8, args: anytype) !void {
    const result = try std.fmt.bufPrint(buf[pos.*..], fmt, args);
    pos.* += result.len;
}

fn sendJSON(sock: posix.socket_t, networks: []const ReloadNetwork) !void {
    var buf: [4096]u8 = undefined;
    var pos: usize = 0;

    try appendSlice(&buf, &pos, "[");
    for (networks, 0..) |net, i| {
        if (i > 0) try appendSlice(&buf, &pos, ",");
        try appendFmt(&buf, &pos, "{{\"n\":\"{s}\",\"h\":\"{s}\",\"nk\":\"{s}\",\"u\":\"{s}\",\"p\":{d}}}", .{ net.network_id, net.host, net.nick, net.user_id, net.port });
    }
    try appendSlice(&buf, &pos, "]\n");

    try sysWrite(sock, buf[0..pos]);
}

fn recvJSON(allocator: Allocator, sock: posix.socket_t) ![]u8 {
    var buf: [4096]u8 = undefined;
    var pos: usize = 0;

    while (true) {
        const n = try sysRead(sock, buf[pos..]);
        if (n == 0) return error.ConnectionClosed;
        pos += n;
        if (mem.indexOfScalar(u8, buf[0..pos], '\n')) |nl| {
            return try allocator.dupe(u8, buf[0 .. nl + 1]);
        }
        if (pos >= buf.len) return error.BufferOverflow;
    }
}

fn parseReloadJSON(allocator: Allocator, json: []const u8) ![]ReloadNetwork {
    // Simple JSON parser for our fixed format: [{"n":"...","h":"...","nk":"...","u":"...","p":6697},...]
    var nets: [64]ReloadNetwork = undefined;
    var count: usize = 0;

    var pos: usize = 0;
    // Skip to '['
    while (pos < json.len and json[pos] != '[') pos += 1;
    pos += 1; // skip '['

    while (pos < json.len) {
        // Skip whitespace and commas
        while (pos < json.len and (json[pos] == ' ' or json[pos] == ',' or json[pos] == '\n')) pos += 1;
        if (pos >= json.len or json[pos] == ']') break;

        if (json[pos] != '{') return error.ParseError;
        pos += 1; // skip '{'

        var net: ReloadNetwork = .{
            .network_id = "",
            .host = "",
            .nick = "",
            .user_id = "",
            .port = 6667,
            .fd = -1,
        };
        while (pos < json.len and json[pos] != '}') {
            // Skip whitespace and commas
            while (pos < json.len and (json[pos] == ' ' or json[pos] == ',')) pos += 1;
            if (pos >= json.len or json[pos] == '}') break;

            // Read key: "key"
            if (json[pos] != '"') return error.ParseError;
            pos += 1;
            const key_start = pos;
            while (pos < json.len and json[pos] != '"') pos += 1;
            const key = json[key_start..pos];
            pos += 1; // skip closing '"'

            // Skip ':'
            while (pos < json.len and json[pos] != ':') pos += 1;
            pos += 1; // skip ':'

            if (mem.eql(u8, key, "p")) {
                // numeric value
                const val_start = pos;
                while (pos < json.len and json[pos] != ',' and json[pos] != '}') pos += 1;
                const val = std.mem.trim(u8, json[val_start..pos], " ");
                net.port = std.fmt.parseUnsigned(u16, val, 10) catch 6667;
                continue;
            }

            // Read string value: "value"
            if (json[pos] != '"') return error.ParseError;
            pos += 1;
            const val_start = pos;
            while (pos < json.len and json[pos] != '"') pos += 1;
            const value = json[val_start..pos];
            pos += 1; // skip closing '"'

            if (mem.eql(u8, key, "n")) {
                net.network_id = try allocator.dupe(u8, value);
            } else if (mem.eql(u8, key, "h")) {
                net.host = try allocator.dupe(u8, value);
            } else if (mem.eql(u8, key, "nk")) {
                net.nick = try allocator.dupe(u8, value);
            } else if (mem.eql(u8, key, "u")) {
                net.user_id = try allocator.dupe(u8, value);
            }
        }
        pos += 1; // skip '}'
        net.fd = -1; // will be filled from received FDs
        if (count >= nets.len) return error.TooManyNetworks;
        nets[count] = net;
        count += 1;
    }

    const out = try allocator.alloc(ReloadNetwork, count);
    for (nets[0..count], 0..) |net, i| out[i] = net;
    return out;
}

// ── SCM_RIGHTS FD Transfer ───────────────────────────────────────

fn sendFDs(sock: posix.socket_t, fds: []const posix.socket_t) !void {
    if (fds.len == 0) return;
    // Build the cmsghdr for SCM_RIGHTS
    const fd_bytes = fds.len * @sizeOf(posix.socket_t);
    const hdr_size = @sizeOf(std.c.cmsghdr);
    const total_cmsg = ircfiber_cmsg_space(fd_bytes);
    const aligned_total = total_cmsg;

    var control_buf: [4096]u8 = undefined;
    if (aligned_total > control_buf.len) return error.BufferTooSmall;

    @memset(control_buf[0..aligned_total], 0);

    var hdr: *std.c.cmsghdr = @ptrCast(@alignCast(&control_buf[0]));
    hdr.len = @intCast(hdr_size + fd_bytes);
    hdr.level = posix.SOL.SOCKET;
    hdr.type = posix.SCM.RIGHTS;

    // Copy FDs into cmsg data
    const fd_ptr: [*]posix.socket_t = @ptrCast(@alignCast(ircfiber_cmsg_data(hdr)));
    for (fds, 0..) |fd, i| {
        fd_ptr[i] = fd;
    }

    // Send with dummy byte payload (required for SCM_RIGHTS)
    const dummy: u8 = 0;
    var iov = [1]posix.iovec{.{
        .base = @constCast(@ptrCast(&dummy)),
        .len = 1,
    }};

    var msg = posix.msghdr{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = &control_buf,
        .controllen = @intCast(aligned_total),
        .flags = 0,
    };

    try sysSendmsg(sock, &msg, 0);
}

fn recvFDs(allocator: Allocator, sock: posix.socket_t) ![]posix.socket_t {
    // Buffer for incoming cmsghdr
    var control_buf: [4096]u8 = undefined;

    // Receive dummy byte
    var dummy: u8 = undefined;
    var iov = [1]posix.iovec{.{
        .base = @ptrCast(&dummy),
        .len = 1,
    }};

    var msg = posix.msghdr{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = &control_buf,
        .controllen = control_buf.len,
        .flags = 0,
    };

    const n = try sysRecvmsg(sock, &msg, 0);
    if (n == 0) return error.ConnectionClosed;

    // Walk cmsg chain to find SCM_RIGHTS
    var cmsg = ircfiber_cmsg_firsthdr(&msg);
    while (cmsg) |c| : (cmsg = ircfiber_cmsg_nxthdr(&msg, c)) {
        if (c.level == posix.SOL.SOCKET and c.type == posix.SCM.RIGHTS) {
            const fd_ptr: [*]const posix.socket_t = @ptrCast(@alignCast(ircfiber_cmsg_data(c)));
            const fd_count = (c.len - @sizeOf(std.c.cmsghdr)) / @sizeOf(posix.socket_t);

            var fds = try allocator.alloc(posix.socket_t, fd_count);
            for (0..fd_count) |i| {
                fds[i] = fd_ptr[i];
            }
            return fds;
        }
    }

    return error.NoFdsReceived;
}

// ── Tests ────────────────────────────────────────────────────────

test "Reload: Unix socket create/listen/connect" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

    const pid = posix.getpid();
    const path = try reloadSocketPath(std.testing.allocator, pid);
    defer std.testing.allocator.free(path);

    // Create listener
    const listener = try createUnixListener(path);
    defer {
        sysClose(listener);
        sysUnlink(path);
    }

    // Connect from same process (client-side)
    const client = try connectUnixSocket(path);
    defer sysClose(client);

    // Accept the client
    const server_client = try sysAccept(listener);
    defer sysClose(server_client);

    // Send + receive a message
    const msg = "hello from reload test\n";
    _ = try sysWrite(client, msg);

    var buf: [256]u8 = undefined;
    const n = try sysRead(server_client, &buf);
    try std.testing.expect(mem.startsWith(u8, buf[0..n], "hello"));
}

test "Reload: FD transfer" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

    // Create a connected socket pair
    var fds: [2]posix.socket_t = undefined;
    try sysSocketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &fds);
    defer {
        sysClose(fds[0]);
        sysClose(fds[1]);
    }

    // Create control Unix socket for FD transfer
    const pid = posix.getpid();
    const path = try reloadSocketPath(std.testing.allocator, pid);
    defer std.testing.allocator.free(path);

    const control = try createUnixListener(path);
    defer {
        sysClose(control);
        sysUnlink(path);
    }

    // Receiver: connect, receive FD
    var received_fd: posix.socket_t = -1;
    const recv_thread = try std.Thread.spawn(.{}, recvFDsThread, .{ std.testing.allocator, &received_fd, path });

    // Sender: accept, send FD
    const sender = try acceptTimeout(control, 5000);
    defer sysClose(sender);

    const fd_to_send = [_]posix.socket_t{fds[0]};
    try sendFDs(sender, &fd_to_send);

    recv_thread.join();

    try std.testing.expect(received_fd >= 0);
    // The received FD should be functional
    const test_msg = "test through adopted fd\n";
    _ = try sysWrite(received_fd, test_msg);

    var buf: [256]u8 = undefined;
    const n = try sysRead(fds[1], &buf);
    try std.testing.expect(mem.startsWith(u8, buf[0..n], "test through"));
}

// Helper for test thread
fn recvFDsThread(allocator: Allocator, out_fd: *posix.socket_t, path: []const u8) !void {
    const sock = try connectUnixSocket(path);
    defer sysClose(sock);

    _ = try sysWrite(sock, "READY\n");

    var json_buf: [256]u8 = undefined;
    _ = try sysRead(sock, &json_buf);

    _ = try sysWrite(sock, "ACK\n");

    const fds = try recvFDs(allocator, sock);
    defer allocator.free(fds);

    _ = try sysWrite(sock, "DONE\n");

    if (fds.len > 0) out_fd.* = fds[0];
}

test "Reload: reloadSocketPath format" {
    const path = try reloadSocketPath(std.testing.allocator, 12345);
    defer std.testing.allocator.free(path);
    try std.testing.expect(mem.startsWith(u8, path, "/tmp/ircfiber-reload-"));
    try std.testing.expect(mem.endsWith(u8, path, "12345.sock"));
}
