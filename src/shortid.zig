//! Short ids for compact blocks (`core/src/core/id.rs`): 6 bytes of a keyed
//! SipHash-2-4 of an item's hash, keyed by `hash((block_hash, nonce))`.
const std = @import("std");
const ser = @import("ser.zig");
const hash_mod = @import("hash.zig");

const Hash = hash_mod.Hash;

pub const SIZE = 6;

pub const ShortId = struct {
    bytes: [SIZE]u8,

    pub fn write(self: ShortId, w: anytype) ser.Error!void {
        try w.writeFixedBytes(&self.bytes);
    }
    pub fn read(r: *ser.Reader) ser.Error!ShortId {
        return .{ .bytes = try r.readArray(SIZE) };
    }
    pub fn eql(a: ShortId, b: ShortId) bool {
        return std.mem.eql(u8, &a.bytes, &b.bytes);
    }
    /// Short ids sort by their hash, like every hashable item.
    pub fn hash(self: ShortId) Hash {
        return hash_mod.hashOf(self);
    }
    pub fn fromHex(s: []const u8) ShortId {
        var out: ShortId = .{ .bytes = [_]u8{0} ** SIZE };
        _ = std.fmt.hexToBytes(&out.bytes, s) catch unreachable;
        return out;
    }
};

/// The short id of the item whose hash is `item_hash`, for the block
/// `block_hash` and connection nonce `nonce`.
pub fn shortId(item_hash: Hash, block_hash: Hash, nonce: u64) ShortId {
    const Keyed = struct {
        h: Hash,
        n: u64,
        pub fn write(self: @This(), w: anytype) ser.Error!void {
            try self.h.write(w);
            try ser.writeU64(w, self.n);
        }
    };
    const keyed = hash_mod.hashOf(Keyed{ .h = block_hash, .n = nonce });
    const SipHash = std.crypto.auth.siphash.SipHash64(2, 4);
    var key: [16]u8 = undefined;
    @memcpy(&key, keyed.bytes[0..16]);
    const res = SipHash.toInt(&item_hash.bytes, &key);
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, res, .little);
    return .{ .bytes = buf[0..SIZE].*};
}

/// Sorts short ids into the canonical (hash) order.
pub fn sort(gpa: std.mem.Allocator, ids: []ShortId) std.mem.Allocator.Error!void {
    const tx = @import("transaction.zig");
    try tx.sortByHash(ShortId, gpa, ids);
}

test "short ids match the reference vectors" {
    // id.rs test_short_id: Foo(n) writes n as a u64; its hash is the item hash.
    const Foo = struct {
        n: u64,
        pub fn write(self: @This(), w: anytype) ser.Error!void {
            try ser.writeU64(w, self.n);
        }
    };
    const foo0 = hash_mod.hashOf(Foo{ .n = 0 });
    var expect: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expect, "81e47a19e6b29b0a65b9591762ce5143ed30d0261e5d24a3201752506b20f15c");
    try std.testing.expectEqualSlices(u8, &expect, &foo0.bytes);
    try std.testing.expect(shortId(foo0, Hash.zero, 0).eql(ShortId.fromHex("4cc808b62476")));
    const foo5 = hash_mod.hashOf(Foo{ .n = 5 });
    try std.testing.expect(shortId(foo5, Hash.zero, 5).eql(ShortId.fromHex("02955a094534")));
}
