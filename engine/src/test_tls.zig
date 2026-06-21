const std = @import("std");
pub fn main() !void {
    const zircon = @import("zircon");
    std.debug.print("Zircon available, testing TLS...\n", .{});

    var channels: [0][]const u8 = .{};
    var client = try zircon.Client.init(std.heap.c_allocator, .{
        .user = "tlstest",
        .nick = "tlstest",
        .real_name = "TLS Test",
        .server = "meth.cat",
        .port = 6697,
        .tls = true,
        .channels = &channels,
    });
    defer client.deinit();

    std.debug.print("Connecting to meth.cat:6697 (TLS)...\n", .{});
    try client.connect();
    std.debug.print("✓ TCP + TLS connected\n", .{});

    try client.register();
    std.debug.print("✓ Registered\n", .{});

    try client.loop(.{ .msg_callback = null });
}
