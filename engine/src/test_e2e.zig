const std = @import("std");
const connection = @import("connection.zig");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    std.debug.print("=== IRC Fiber E2E Test ===\n", .{});
    std.debug.print("Connecting to localhost:6667 (Docker IRCd)...\n", .{});

    var conn = connection.NetworkConnection.init(arena.allocator(), .{
        .host = "127.0.0.1",
        .port = 6667,
        .nick = "testbot",
        .user = "testbot",
        .real_name = "IRC Fiber E2E",
        .auto_join_channels = &.{"#test"},
        .timeout_ms = 5000,
    });
    conn.setEventCallback(struct {
        fn cb(e: connection.Event, _: *connection.NetworkConnection) void {
            switch (e) {
                .connected => std.debug.print("✓ CONNECTED\n", .{}),
                .notice => |n| std.debug.print("  NOTICE: {s}\n", .{n.text}),
                .join => |j| std.debug.print("  JOIN: {s} → {s}\n", .{ j.nick, j.channel }),
                .privmsg => |p| std.debug.print("  MSG <{s}> {s}: {s}\n", .{ p.nick, p.target, p.text }),
                .disconnected => |d| std.debug.print("✗ DISCONNECTED: {s}\n", .{d.reason}),
                else => {},
            }
        }
    }.cb);
    conn.run();
    std.debug.print("Connection ended.\n", .{});
}
