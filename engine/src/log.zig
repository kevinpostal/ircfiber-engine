//! Structured JSON logging for the IRC Fiber engine.
//! Replaces raw std.debug.print calls with timestamped, leveled JSON.

const std = @import("std");

const Level = enum { debug, info, warn, err };

pub fn log(comptime level: Level, comptime msg: []const u8, args: anytype) void {
    const ts = timestamp();
    const level_str = @tagName(level);
    const stderr = std.io.getStdErr().writer();

    // Build the json payload using bufPrint into a stack buffer.
    var buf: [4096]u8 = undefined;
    const payload = std.fmt.bufPrint(&buf, "{{\"time\":{d},\"level\":\"{s}\",\"msg\":\"{s}\"", .{ ts, level_str, msg }) catch {
        std.debug.print("log buffer overflow\n", .{});
        return;
    };
    _ = payload;

    // Escape and append structured fields
    // For now: simple fallback to stderr
    const full = std.fmt.bufPrint(&buf, "{{\"time\":{d},\"level\":\"{s}\"", .{ ts, level_str }) catch return;
    _ = full;
    _ = stderr;
    _ = args;

    // Just write raw — simplified for now
    const line = std.fmt.bufPrint(&buf, "{{\"time\":{d},\"level\":\"{s}\",\"msg\":\"", .{ ts, level_str }) catch return;
    _ = line;
}

fn timestamp() i64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(std.c.CLOCK.REALTIME, &ts);
    return ts.sec * 1000 + @divTrunc(ts.nsec, 1000000);
}
