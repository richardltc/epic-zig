//! Primary protocol hash: blake2b-256 over the "hash mode" serialization.
//! Port of `core/src/core/hash.rs`.
const std = @import("std");
const ser = @import("ser.zig");
const hex = @import("hex.zig");

const Blake2b256 = std.crypto.hash.blake2.Blake2b256;

pub const Hash = struct {
    bytes: [32]u8,

    pub const LEN = 32;
    pub const zero: Hash = .{ .bytes = [_]u8{0} ** 32 };

    /// Pads with zeroes if short, truncates if long.
    pub fn fromVec(v: []const u8) Hash {
        var h = zero;
        const n = @min(v.len, LEN);
        @memcpy(h.bytes[0..n], v[0..n]);
        return h;
    }

    pub fn fromHex(gpa: std.mem.Allocator, s: []const u8) ser.Error!Hash {
        const b = try hex.decode(gpa, s);
        defer gpa.free(b);
        return fromVec(b);
    }

    pub fn toHex(self: Hash) [64]u8 {
        var out: [64]u8 = undefined;
        _ = std.fmt.bufPrint(&out, "{x}", .{self.bytes[0..]}) catch unreachable;
        return out;
    }

    /// Most significant 64 bits.
    pub fn toU64(self: Hash) u64 {
        return std.mem.readInt(u64, self.bytes[0..8], .big);
    }

    pub fn eql(a: Hash, b: Hash) bool {
        return std.mem.eql(u8, &a.bytes, &b.bytes);
    }

    /// Lexicographic order, as derived `Ord` on `[u8; 32]`.
    pub fn order(a: Hash, b: Hash) std.math.Order {
        return std.mem.order(u8, &a.bytes, &b.bytes);
    }

    pub fn lessThan(_: void, a: Hash, b: Hash) bool {
        return a.order(b) == .lt;
    }

    pub fn write(self: Hash, w: anytype) ser.Error!void {
        try w.writeFixedBytes(&self.bytes);
    }

    pub fn read(r: *ser.Reader) ser.Error!Hash {
        return .{ .bytes = try r.readArray(32) };
    }

    /// Debug/Display form: first 12 hex chars.
    pub fn format(self: Hash, w: *std.Io.Writer) std.Io.Writer.Error!void {
        const h = self.toHex();
        try w.writeAll(h[0..12]);
    }

    /// `hash + other` in Rust: blake2b(self || other).
    pub fn hashWith(self: Hash, other: anytype) Hash {
        var hw = HashWriter.init();
        ser.write(&hw, self) catch unreachable;
        ser.write(&hw, other) catch unreachable;
        return hw.intoHash();
    }
};

/// Serializer that outputs a hash of the serialized object.
pub const HashWriter = struct {
    state: Blake2b256,
    version: ser.ProtocolVersion = ser.ProtocolVersion.local(),
    mode: ser.Mode = .hash,

    pub fn init() HashWriter {
        return .{ .state = Blake2b256.init(.{}) };
    }

    pub fn writeFixedBytes(self: *HashWriter, bytes: []const u8) ser.Error!void {
        self.state.update(bytes);
    }

    pub fn intoHash(self: *HashWriter) Hash {
        var h: Hash = undefined;
        self.state.final(&h.bytes);
        return h;
    }
};

/// Hash of any serializable value (Rust's `Hashed::hash` via DefaultHashable).
pub fn hashOf(value: anytype) Hash {
    var hw = HashWriter.init();
    ser.write(&hw, value) catch unreachable;
    return hw.intoHash();
}

/// PMMR leaf hash: blake2b(index_u64_be || serialize(item)).
pub fn hashWithIndex(index: u64, item: anytype) Hash {
    var hw = HashWriter.init();
    ser.write(&hw, index) catch unreachable;
    ser.write(&hw, item) catch unreachable;
    return hw.intoHash();
}

test "blake2b-256 of nothing" {
    const h = hashOf(@as([]const u8, &.{}));
    const want = try Hash.fromHex(std.testing.allocator, "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8");
    try std.testing.expect(h.eql(want));
}

test "hash hex, ordering, padding and combine" {
    const gpa = std.testing.allocator;
    const a = Hash.fromVec(&.{ 1, 2 });
    try std.testing.expectEqual(@as(u8, 0), a.bytes[31]);
    try std.testing.expectEqual(@as(u64, 0x0102000000000000), a.toU64());
    const hx = a.toHex();
    try std.testing.expect((try Hash.fromHex(gpa, &hx)).eql(a));
    try std.testing.expect(Hash.zero.order(a) == .lt);

    // hash + hash == blake2b(a || b)
    var manual = Blake2b256.init(.{});
    manual.update(&a.bytes);
    manual.update(&a.bytes);
    var out: [32]u8 = undefined;
    manual.final(&out);
    try std.testing.expectEqualSlices(u8, &out, &a.hashWith(a).bytes);
}

test "hashWithIndex prefixes big-endian index" {
    var manual = Blake2b256.init(.{});
    manual.update(&.{ 0, 0, 0, 0, 0, 0, 0, 7 });
    manual.update(&.{ 0, 0, 0, 0, 0, 0, 0, 9 });
    var out: [32]u8 = undefined;
    manual.final(&out);
    try std.testing.expectEqualSlices(u8, &out, &hashWithIndex(7, @as(u64, 9)).bytes);
}

/// Two hashes hashed together (`(left, right)` in the Rust `hash_with_index`).
pub const HashPair = struct {
    left: Hash,
    right: Hash,

    pub fn write(self: HashPair, w: anytype) ser.Error!void {
        try self.left.write(w);
        try self.right.write(w);
    }
};

/// Parent node hash in a PMMR: blake2b(index || left || right).
pub fn hashPairWithIndex(index: u64, left: Hash, right: Hash) Hash {
    return hashWithIndex(index, HashPair{ .left = left, .right = right });
}
