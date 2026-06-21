const std = @import("std");
const connection = @import("connection.zig");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    var conn = connection.NetworkConnection.init(arena.allocator(), .{
        .host = "172.22.0.2",
        .port = 6667,
        .nick = "testbot",
        .user = "testbot",
        .real_name = "IRC Fiber Docker Test",
        .auto_join_channels = &.{"#test"},
        .timeout_ms = 5000,
    });
    conn.setEventCallback(struct {
        fn cb(e: connection.Event, _: *connection.NetworkConnection) void {
            switch (e) {
                .connected => std.debug.print("OK: connected\n", .{}),
                .notice => |n| std.debug.print("NOTICE: {s}: {s}\n", .{ n.nick, n.text }),
                .join => |j| std.debug.print("OK: {s} joined {s}\n", .{ j.nick, j.channel }),
                .privmsg => |p| std.debug.print("MSG: <{s}> {s}: {s}\n", .{ p.nick, p.target, p.text }),
                .disconnected => |d| std.debug.print("DISC: {s}\n", .{d.reason}),
                else => {},
            }
        }
    }.cb);
    conn.run();
}
