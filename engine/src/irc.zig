//! # IRC Protocol Parser — RFC 1459 / 2812
//!
//! Parses raw IRC lines into typed events. Handles IRCv3 tags and
//! server-time capability parsing.
//!
//! Message format: `[@tags] [:prefix] CMD [args...] [:trailing]\r\n`

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// IRCv3 tag key-value pair
pub const Tag = struct {
    key: []const u8,
    value: ?[]const u8 = null,
};

/// An IRC message event.
pub const IrcEvent = struct {
    /// IRCv3 tags (key=value pairs). e.g., "account=nick", "time=2021-01-01T00:00:00.000Z"
    tags: ?[]Tag = null,
    /// Message prefix (source). e.g., "nick!user@host" or "server.name"
    prefix: ?[]const u8 = null,
    /// IRC command. e.g., "PRIVMSG", "JOIN", "001", "ERROR"
    command: []const u8,
    /// Space-delimited parameters (excluding trailing)
    params: [][]const u8 = &.{},
    /// Trailing parameter (after `:`). e.g., the message text in PRIVMSG
    trailing: ?[]const u8 = null,
    /// Raw original line (useful for forwarding/debugging)
    raw: []const u8,

    /// Parse a raw IRC line into an IrcEvent. Caller owns the returned
    /// memory (tags and params are allocated from the provided allocator).
    pub fn parse(allocator: Allocator, raw: []const u8) !IrcEvent {
        var event = IrcEvent{
            .command = "",
            .raw = raw,
        };
        var pos: usize = 0;

        // Strip trailing \r\n
        var line = raw;
        if (line.len >= 2 and line[line.len - 2] == '\r' and line[line.len - 1] == '\n') {
            line = line[0 .. line.len - 2];
        } else if (line.len >= 1 and line[line.len - 1] == '\n') {
            line = line[0 .. line.len - 1];
        }
        if (line.len == 0) return event;

        // IRCv3 tags: @key=value;key2=value2 :prefix CMD ...
        if (line.len > 0 and line[0] == '@') {
            const tag_end = mem.indexOfScalar(u8, line, ' ') orelse return event;
            const tags_raw = line[1..tag_end];
            event.tags = try parseTags(allocator, tags_raw);
            pos = tag_end + 1;
        }

        // Skip whitespace
        while (pos < line.len and line[pos] == ' ') pos += 1;

        // Prefix: :nick!user@host or :server.name
        if (pos < line.len and line[pos] == ':') {
            pos += 1;
            const prefix_end = mem.indexOfScalarPos(u8, line, pos, ' ') orelse line.len;
            event.prefix = line[pos..prefix_end];
            pos = prefix_end;
        }

        // Skip whitespace
        while (pos < line.len and line[pos] == ' ') pos += 1;

        // Command
        const cmd_start = pos;
        while (pos < line.len and line[pos] != ' ') pos += 1;
        event.command = line[cmd_start..pos];

        // Parameters — max 30 params per IRC line is generous
        var params_buf: [30][]const u8 = undefined;
        var param_count: usize = 0;

        while (pos < line.len) {
            while (pos < line.len and line[pos] == ' ') pos += 1;
            if (pos >= line.len) break;

            if (line[pos] == ':') {
                // Trailing parameter (includes spaces)
                event.trailing = line[pos + 1 ..];
                break;
            }

            const arg_start = pos;
            while (pos < line.len and line[pos] != ' ') pos += 1;
            if (param_count < params_buf.len) {
                params_buf[param_count] = line[arg_start..pos];
                param_count += 1;
            }
        }

        event.params = try allocator.alloc([]const u8, param_count);
        @memcpy(event.params, params_buf[0..param_count]);
        return event;
    }

    /// Deallocate memory owned by this event (tags and params).
    pub fn deinit(self: *IrcEvent, allocator: Allocator) void {
        if (self.tags) |tags| {
            for (tags) |*tag| {
                allocator.free(tag.key);
                if (tag.value) |v| allocator.free(v);
            }
            allocator.free(tags);
        }
        if (self.params.len > 0) allocator.free(self.params);
    }

    /// Extract the nick from a prefix like "nick!user@host".
    pub fn nickFromPrefix(prefix: []const u8) ?[]const u8 {
        const bang = mem.indexOfScalar(u8, prefix, '!');
        if (bang) |i| return prefix[0..i];
        return prefix;
    }

    /// Extract the user from a prefix like "nick!user@host".
    pub fn userFromPrefix(prefix: []const u8) ?[]const u8 {
        const bang = mem.indexOfScalar(u8, prefix, '!');
        const at = mem.indexOfScalar(u8, prefix, '@');
        if (bang != null and at != null) {
            return prefix[bang.? + 1 .. at.?];
        }
        return null;
    }

    /// Extract the host from a prefix like "nick!user@host".
    pub fn hostFromPrefix(prefix: []const u8) ?[]const u8 {
        const at = mem.indexOfScalar(u8, prefix, '@');
        if (at) |i| return prefix[i + 1 ..];
        return null;
    }

    /// Check if this is a numeric reply (001-999).
    pub fn isNumeric(self: IrcEvent) bool {
        return self.command.len == 3 and
            self.command[0] >= '0' and self.command[0] <= '9';
    }

    fn parseTags(allocator: Allocator, raw: []const u8) ![]Tag {
        // Count segments first
        var count: usize = 0;
        if (raw.len > 0) count = 1;
        for (raw) |c| {
            if (c == ';') count += 1;
        }

        var tags = try allocator.alloc(Tag, count);
        var idx: usize = 0;

        var it = mem.splitScalar(u8, raw, ';');
        while (it.next()) |segment| {
            if (segment.len == 0) continue;
            const eq = mem.indexOfScalar(u8, segment, '=');
            if (eq) |i| {
                tags[idx] = .{
                    .key = try allocator.dupe(u8, segment[0..i]),
                    .value = try allocator.dupe(u8, segment[i + 1 ..]),
                };
            } else {
                tags[idx] = .{
                    .key = try allocator.dupe(u8, segment),
                };
            }
            idx += 1;
        }
        // Shrink to actual used count
        return tags[0..idx];
    }
};

// ── Tests ────────────────────────────────────────────────────────

test "IrcEvent: parse simple PRIVMSG" {
    var event = try IrcEvent.parse(std.testing.allocator, ":nick!user@host PRIVMSG #channel :hello world\r\n");
    defer event.deinit(std.testing.allocator);

    try std.testing.expect(event.prefix != null);
    try std.testing.expectEqualStrings("nick!user@host", event.prefix.?);
    try std.testing.expectEqualStrings("PRIVMSG", event.command);
    try std.testing.expect(event.trailing != null);
    try std.testing.expectEqualStrings("hello world", event.trailing.?);
    try std.testing.expectEqualStrings("#channel", event.params[0]);
}

test "IrcEvent: parse NOTICE with tags" {
    const raw = "@time=2021-01-01T00:00:00.000Z;account=nick :server.example.com NOTICE nick :You are now identified\r\n";
    var event = try IrcEvent.parse(std.testing.allocator, raw);
    defer event.deinit(std.testing.allocator);

    try std.testing.expect(event.tags != null);
    try std.testing.expectEqualStrings("NOTICE", event.command);
}

test "IrcEvent: parse numeric reply" {
    var event = try IrcEvent.parse(std.testing.allocator, ":server.example.com 001 nick :Welcome to the IRC network\r\n");
    defer event.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("001", event.command);
    try std.testing.expect(event.isNumeric());
    try std.testing.expectEqualStrings("Welcome to the IRC network", event.trailing.?);
}

test "IrcEvent: parse ERROR" {
    var event = try IrcEvent.parse(std.testing.allocator, "ERROR :Closing Link: Banned (Z-Lined)\r\n");
    defer event.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("ERROR", event.command);
    try std.testing.expectEqualStrings("Closing Link: Banned (Z-Lined)", event.trailing.?);
}

test "IrcEvent: parse PING" {
    var event = try IrcEvent.parse(std.testing.allocator, "PING :server.example.com\r\n");
    defer event.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("PING", event.command);
    try std.testing.expectEqualStrings("server.example.com", event.trailing.?);
}

test "IrcEvent: nickFromPrefix" {
    try std.testing.expectEqualStrings("nick", IrcEvent.nickFromPrefix("nick!user@host").?);
    const server_prefix = IrcEvent.nickFromPrefix("server.example.com") orelse "";
    try std.testing.expectEqualStrings("server.example.com", server_prefix);
    // server-only prefix — no bang — returns entire prefix
}

test "IrcEvent: parse CAP ACK" {
    const raw = ":server CAP * ACK :multi-prefix account-tag\r\n";
    var event = try IrcEvent.parse(std.testing.allocator, raw);
    defer event.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("CAP", event.command);
    try std.testing.expectEqualStrings("multi-prefix account-tag", event.trailing.?);
}

test "IrcEvent: parse empty line" {
    var event = try IrcEvent.parse(std.testing.allocator, "\r\n");
    defer event.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("", event.command);
}
