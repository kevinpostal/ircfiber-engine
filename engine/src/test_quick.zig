// Self-contained Docker IRCd test — imports everything directly
const std = @import("std");
const mem = std.mem;

const c = @cImport({
    @cInclude("sys/types.h");
    @cInclude("sys/socket.h");
    @cInclude("netdb.h");
    @cInclude("fcntl.h");
    @cInclude("unistd.h");
    @cInclude("poll.h");
    @cInclude("netinet/tcp.h");
    @cInclude("time.h");
});

pub fn main() !void {
    std.debug.print("=== Quick Docker IRCd Test ===\n", .{});

    // Connect TCP
    const sock = c.socket(c.AF_INET, c.SOCK_STREAM, 0);
    if (sock < 0) { std.debug.print("socket failed\n", .{}); return; }
    defer _ = c.close(sock);

    var addr: c.struct_sockaddr_in = .{
        .sin_family = c.AF_INET,
        .sin_port = @byteSwap(@as(c_ushort, 6667)),
        .sin_addr = .{ .s_addr = @byteSwap(@as(c_uint, 127 * 256 * 256 * 256 + 1)) },
        .sin_zero = .{0} ** 8,
    };
    _ = addr.sin_zero;

    if (c.connect(sock, @ptrCast(&addr), @sizeOf(@TypeOf(addr))) < 0) {
        std.debug.print("connect failed\n", .{});
        return;
    }
    std.debug.print("✓ TCP connected\n", .{});

    // Send NICK + USER
    const nick = "NICK testbot\r\n";
    _ = c.send(sock, nick, @intCast(nick.len), 0);
    const user = "USER testbot 0 * :Test Bot\r\n";
    _ = c.send(sock, user, @intCast(user.len), 0);
    std.debug.print("✓ NICK/USER sent\n", .{});

    // Read for 3 seconds
    var buf: [4096]u8 = undefined;
    const deadline = currentMs() + 3000;
    while (currentMs() < deadline) {
        var pfd: c.struct_pollfd = .{ .fd = sock, .events = c.POLLIN, .revents = 0 };
        const pr = c.poll(&pfd, 1, 500);
        if (pr > 0) {
            const n = c.recv(sock, &buf, buf.len, 0);
            if (n > 0) {
                const line = buf[0..@intCast(n)];
                std.debug.print("  RECV: {s}\n", .{line});
                // Respond to PING
                if (mem.indexOf(u8, line, "PING") != null) {
                    const pong = "PONG :test\r\n";
                    _ = c.send(sock, pong, @intCast(pong.len), 0);
                    std.debug.print("  → PONG sent\n", .{});
                }
            }
        }
    }

    std.debug.print("✓ Test complete\n", .{});
}

fn currentMs() i64 {
    var ts: c.struct_timespec = undefined;
    _ = c.clock_gettime(0, &ts);
    return ts.tv_sec * 1000 + @divTrunc(ts.tv_nsec, 1000000);
}
