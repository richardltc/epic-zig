//! SipHash-2-4 as used by Cuckoo cycle (`core/src/pow/siphash.rs`).
const std = @import("std");

const BLOCK_BITS = 6;
const BLOCK_SIZE = 1 << BLOCK_BITS;
const BLOCK_MASK = BLOCK_SIZE - 1;

pub const SipHash24 = struct {
    v: [4]u64,

    pub fn init(keys: [4]u64) SipHash24 {
        return .{ .v = keys };
    }

    pub fn hash(self: *SipHash24, nonce: u64) void {
        self.v[3] ^= nonce;
        self.round();
        self.round();
        self.v[0] ^= nonce;
        self.v[2] ^= 0xff;
        inline for (0..4) |_| self.round();
    }

    pub fn digest(self: SipHash24) u64 {
        return (self.v[0] ^ self.v[1]) ^ (self.v[2] ^ self.v[3]);
    }

    fn round(self: *SipHash24) void {
        const v = &self.v;
        v[0] +%= v[1];
        v[2] +%= v[3];
        v[1] = std.math.rotl(u64, v[1], 13);
        v[3] = std.math.rotl(u64, v[3], 16);
        v[1] ^= v[0];
        v[3] ^= v[2];
        v[0] = std.math.rotl(u64, v[0], 32);
        v[2] +%= v[1];
        v[0] +%= v[3];
        v[1] = std.math.rotl(u64, v[1], 17);
        v[3] = std.math.rotl(u64, v[3], 21);
        v[1] ^= v[2];
        v[3] ^= v[0];
        v[2] = std.math.rotl(u64, v[2], 32);
    }
};

pub fn siphash24(keys: [4]u64, nonce: u64) u64 {
    var s = SipHash24.init(keys);
    s.hash(nonce);
    return s.digest();
}

/// Cuckaroo's block-chained variant.
pub fn siphashBlock(keys: [4]u64, nonce: u64) u64 {
    const nonce0 = nonce & ~@as(u64, BLOCK_MASK);
    var nonce_hash: u64 = 0;
    var s = SipHash24.init(keys);
    var n = nonce0;
    while (n < nonce0 + BLOCK_SIZE) : (n += 1) {
        s.hash(n);
        if (n == nonce) nonce_hash = s.digest();
    }
    if (nonce == nonce0 + BLOCK_MASK) return s.digest();
    return nonce_hash ^ s.digest();
}

test "siphash24 vectors from the reference" {
    try std.testing.expectEqual(@as(u64, 928382149599306901), siphash24(.{ 1, 2, 3, 4 }, 10));
    try std.testing.expectEqual(@as(u64, 10524991083049122233), siphash24(.{ 1, 2, 3, 4 }, 111));
    try std.testing.expectEqual(@as(u64, 1305683875471634734), siphash24(.{ 9, 7, 6, 7 }, 12));
    try std.testing.expectEqual(@as(u64, 11589833042187638814), siphash24(.{ 9, 7, 6, 7 }, 10));
}

test "siphash block vectors from the reference" {
    try std.testing.expectEqual(@as(u64, 1182162244994096396), siphashBlock(.{ 1, 2, 3, 4 }, 10));
    try std.testing.expectEqual(@as(u64, 11303676240481718781), siphashBlock(.{ 1, 2, 3, 4 }, 123));
    try std.testing.expectEqual(@as(u64, 4886136884237259030), siphashBlock(.{ 9, 7, 6, 7 }, 12));
}
