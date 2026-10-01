//! Cuckoo-cycle proof verification (the Cuckatoo verifier from
//! `core/src/pow/cuckatoo.rs`, which the reference uses for all cuckoo proofs).
const std = @import("std");
const siphash = @import("siphash.zig");
const Blake2b256 = std.crypto.hash.blake2.Blake2b256;

pub const VerifyError = error{
    EdgeTooBig,
    EdgesNotAscending,
    EndpointsDontMatch,
    BranchInCycle,
    CycleDeadEnds,
    CycleTooShort,
};

/// SipHash keys from the header bytes: blake2b-256, read as four LE u64.
/// With `nonce`, the last 4 bytes of the header are replaced by the nonce (LE u32).
pub fn siphashKeys(gpa: std.mem.Allocator, header: []const u8, nonce: ?u64) ![4]u64 {
    var out: [32]u8 = undefined;
    if (nonce) |n| {
        const buf = try gpa.dupe(u8, header);
        defer gpa.free(buf);
        std.mem.writeInt(u32, buf[buf.len - 4 ..][0..4], @truncate(n), .little);
        Blake2b256.hash(buf, &out, .{});
    } else {
        Blake2b256.hash(header, &out, .{});
    }
    var keys: [4]u64 = undefined;
    for (0..4) |i| keys[i] = std.mem.readInt(u64, out[i * 8 ..][0..8], .little);
    return keys;
}

fn sipnode(keys: [4]u64, edge_mask: u64, edge: u64, uorv: u64) u64 {
    return siphash.siphash24(keys, 2 *% edge +% uorv) & edge_mask;
}

/// Verifies that `nonces` form a cycle of length `nonces.len` in the graph
/// defined by `keys` with 2^edge_bits edges.
pub fn verify(keys: [4]u64, edge_bits: u8, nonces: []const u64) VerifyError!void {
    const proof_size = nonces.len;
    std.debug.assert(proof_size <= 64 and proof_size % 2 == 0 or proof_size <= 64);
    const edge_mask: u64 = if (edge_bits >= 64) std.math.maxInt(u64) else (@as(u64, 1) << @intCast(edge_bits)) - 1;

    var uvs: [128]u64 = undefined;
    var xor0: u64 = (@as(u64, proof_size) / 2) & 1;
    var xor1: u64 = xor0;

    for (nonces, 0..) |nonce, n| {
        if (nonce > edge_mask) return error.EdgeTooBig;
        if (n > 0 and nonce <= nonces[n - 1]) return error.EdgesNotAscending;
        uvs[2 * n] = sipnode(keys, edge_mask, nonce, 0);
        uvs[2 * n + 1] = sipnode(keys, edge_mask, nonce, 1);
        xor0 ^= uvs[2 * n];
        xor1 ^= uvs[2 * n + 1];
    }
    if (xor0 | xor1 != 0) return error.EndpointsDontMatch;

    var n: usize = 0;
    var i: usize = 0;
    while (true) {
        var j = i;
        var k = j;
        while (true) {
            k = (k + 2) % (2 * proof_size);
            if (k == i) break;
            if (uvs[k] >> 1 == uvs[i] >> 1) {
                if (j != i) return error.BranchInCycle;
                j = k;
            }
        }
        if (j == i or uvs[j] == uvs[i]) return error.CycleDeadEnds;
        i = j ^ 1;
        n += 1;
        if (i == 0) break;
    }
    if (n != proof_size) return error.CycleTooShort;
}

const V1_29 = [42]u64{
    0x48a9e2,   0x9cf043,   0x155ca30,  0x18f4783,  0x248f86c,  0x2629a64,  0x5bad752,  0x72e3569,
    0x93db760,  0x97d3b37,  0x9e05670,  0xa315d5a,  0xa3571a1,  0xa48db46,  0xa7796b6,  0xac43611,
    0xb64912f,  0xbb6c71e,  0xbcc8be1,  0xc38a43a,  0xd4faa99,  0xe018a66,  0xe37e49c,  0xfa975fa,
    0x11786035, 0x1243b60a, 0x12892da0, 0x141b5453, 0x1483c3a0, 0x1505525e, 0x1607352c, 0x16181fe3,
    0x17e3a1da, 0x180b651e, 0x1899d678, 0x1931b0bb, 0x19606448, 0x1b041655, 0x1b2c20ad, 0x1bd7a83c,
    0x1c05d5b0, 0x1c0b9caa,
};

const V1_31 = [42]u64{
    0x1128e07,  0xc181131,  0x110fad36, 0x1135ddee, 0x1669c7d3, 0x1931e6ea, 0x1c0005f3, 0x1dd6ecca,
    0x1e29ce7e, 0x209736fc, 0x2692bf1a, 0x27b85aa9, 0x29bb7693, 0x2dc2a047, 0x2e28650a, 0x2f381195,
    0x350eb3f9, 0x3beed728, 0x3e861cbc, 0x41448cc1, 0x41f08f6d, 0x42fbc48a, 0x4383ab31, 0x4389c61f,
    0x4540a5ce, 0x49a17405, 0x50372ded, 0x512f0db0, 0x588b6288, 0x5a36aa46, 0x5c29e1fe, 0x6118ab16,
    0x634705b5, 0x6633d190, 0x6683782f, 0x6728b6e1, 0x67adfb45, 0x68ae2306, 0x6d60f5e1, 0x78af3c4f,
    0x7dde51ab, 0x7faced21,
};

test "cuckatoo 29 and 31 reference solutions verify" {
    const gpa = std.testing.allocator;
    const header = [_]u8{0} ** 80;
    try verify(try siphashKeys(gpa, &header, 20), 29, &V1_29);
    try verify(try siphashKeys(gpa, &header, 99), 31, &V1_31);
}

test "cuckatoo rejects tampering" {
    const gpa = std.testing.allocator;
    var header = [_]u8{0} ** 80;
    header[0] = 1;
    try std.testing.expectError(error.EndpointsDontMatch, verify(try siphashKeys(gpa, &header, 20), 29, &V1_29));
    header[0] = 0;
    var bad = V1_29;
    bad[0] = 0x48a9e1;
    try std.testing.expect(std.meta.isError(verify(try siphashKeys(gpa, &header, 20), 29, &bad)));
    var unsorted = V1_29;
    std.mem.swap(u64, &unsorted[3], &unsorted[4]);
    try std.testing.expectError(error.EdgesNotAscending, verify(try siphashKeys(gpa, &header, 20), 29, &unsorted));
    var big = V1_29;
    big[41] = (@as(u64, 1) << 29) + 5;
    try std.testing.expectError(error.EdgeTooBig, verify(try siphashKeys(gpa, &header, 20), 29, &big));
}
