//! Integration test: Connect to IRC using NetworkConnection
const std = @import("std");
const connection = @import("connection.zig");
const Config = connection.Config;
const Event = connection.Event;
const NetworkConnection = connection.NetworkConnection;

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var conn = NetworkConnection.init(allocator, .{
        .host = "irc.libera.chat",
        .port = 6667,
        .nick = "ircfiber-zig2",
        .user = "ircfiber",
        .real_name = "IRC Fiber Zig Test",
        .timeout_ms = 15000,
    });

    conn.setEventCallback(printEvent, null);
    conn.run();

    std.debug.print("Connection ended.\n", .{});
}

fn printEvent(event: Event, conn: *NetworkConnection) void {
    _ = conn;
    switch (event) {
        .connected => std.debug.print("[CONNECTED]\n", .{}),
        .disconnected => |d| std.debug.print("[DISCONNECTED] {s}\n", .{d.reason}),
        .privmsg => |m| std.debug.print("[PRIVMSG] <{s}> {s}: {s}\n", .{ m.nick, m.target, m.text }),
        .notice => |n| std.debug.print("[NOTICE] {s}: {s}\n", .{ n.nick, n.text }),
        .join => |j| std.debug.print("[JOIN] {s} → {s}\n", .{ j.nick, j.channel }),
        .part => |p| std.debug.print("[PART] {s} ← {s}\n", .{ p.nick, p.channel }),
        .quit => |q| std.debug.print("[QUIT] {s}: {s}\n", .{ q.nick, q.reason orelse "" }),
        .nick => |n| std.debug.print("[NICK] {s} → {s}\n", .{ n.old, n.new }),
        .topic => |t| std.debug.print("[TOPIC] {s}: {s}\n", .{ t.channel, t.topic orelse "" }),
    }
}
