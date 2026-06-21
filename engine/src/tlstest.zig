// Quick TLS test — does std.crypto.tls.Client work with raw fds?
const std = @import("std");

pub fn main() !void {
    const host = "meth.cat";
    const port = 6697;

    // Connect TCP using standard library
    const io = std.Io.Threaded.global_single_threaded.io();
    const host_name = try std.Io.net.HostName.init(host);
    var stream = try host_name.connect(io, port, .{ .mode = .stream });
    defer stream.close(io);

    std.debug.print("TCP connected to {s}:{d}\n", .{ host, port });

    // Create reader/writer from stream
    var reader_buf: [16384]u8 = undefined;
    var writer_buf: [16384]u8 = undefined;
    var reader = stream.reader(io, &reader_buf);
    var writer = stream.writer(io, &writer_buf);

    // Use the tls package
    const tls = @import("tls");
    var root_ca: std.crypto.Certificate.Bundle = .empty;
    try root_ca.rescan(std.heap.c_allocator);
    defer root_ca.deinit(std.heap.c_allocator);

    const conn = try tls.client(reader.interface(), writer.interface(), .{
        .host = host,
        .root_ca = root_ca,
    });
    _ = conn;

    std.debug.print("TLS handshake complete!\n", .{});
}
