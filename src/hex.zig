//! Hex helpers matching util::to_hex / util::from_hex in the Rust node.
const std = @import("std");

pub const Error = error{ HexError, OutOfMemory };

pub fn encode(gpa: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const out = try gpa.alloc(u8, bytes.len * 2);
    _ = std.fmt.bufPrint(out, "{x}", .{bytes}) catch unreachable;
    return out;
}

/// Decodes hex. Like the Rust version: an optional "0x" prefix is accepted,
/// surrounding whitespace is trimmed, and odd lengths are rejected.
pub fn decode(gpa: std.mem.Allocator, s: []const u8) Error![]u8 {
    if (s.len % 2 == 1) return error.HexError;
    var t = s;
    if (t.len >= 2 and t[0] == '0' and t[1] == 'x') t = t[2..];
    t = std.mem.trim(u8, t, " \t\r\n");
    if (t.len % 2 == 1) return error.HexError;
    const out = try gpa.alloc(u8, t.len / 2);
    errdefer gpa.free(out);
    _ = std.fmt.hexToBytes(out, t) catch return error.HexError;
    return out;
}

test "hex round trip" {
    const gpa = std.testing.allocator;
    const enc = try encode(gpa, &.{ 0x00, 0xab, 0xff });
    defer gpa.free(enc);
    try std.testing.expectEqualStrings("00abff", enc);
    const dec = try decode(gpa, "0x00abff");
    defer gpa.free(dec);
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0xab, 0xff }, dec);
    try std.testing.expectError(error.HexError, decode(gpa, "abc"));
    try std.testing.expectError(error.HexError, decode(gpa, "zz"));
}
