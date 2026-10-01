//! Hash checkpoints (`BlockchainCheckpoints` in chain/src/types.rs): the chain
//! must contain exactly these headers. Inside this range PoW verification can
//! be skipped safely, since the header hash-chain is pinned by them.
const std = @import("std");
const Hash = @import("hash.zig").Hash;

pub const Checkpoint = struct { height: u64, hash: Hash };

fn h(comptime hex: []const u8) Hash {
    @setEvalBranchQuota(100_000);
    var out: Hash = undefined;
    _ = std.fmt.hexToBytes(&out.bytes, hex) catch unreachable;
    return out;
}

pub const mainnet = [_]Checkpoint{
    .{ .height = 100000, .hash = h("e835eb9ebc9f2e13b11061691cb268f44b20001f081003169b634497eb730848") },
    .{ .height = 200000, .hash = h("b2365a8c9719a709f11d450bbddfd012011e21c862239bdc8590aba00815e84c") },
    .{ .height = 400000, .hash = h("6578f1cdf5504d29fc757424e75ac60494e0f6d24b7553d124c8bea6ef99b5d8") },
    .{ .height = 600000, .hash = h("de483eafb2141d66bf541a94d8e41858f01ffc517b9fa61d8781483c34c2a6f7") },
    .{ .height = 800000, .hash = h("1465e7c094376e781b1e80ebd6b7a0c6350ec4d6554f9acdd843802162831003") },
    .{ .height = 1000000, .hash = h("00e4a404130ac192face23fd25f2c46a99a38a31d8cf2d3cc79ea7a518830686") },
    .{ .height = 1200000, .hash = h("8d69282df5579d32346ad0f6d3f4e03a43b1e00e741b1f3ba71c2934d81e5e1a") },
    .{ .height = 1400000, .hash = h("e7e34e50e8a5c9bcf3fe7b7ad99e62a848cda37171ce8d37f21bc334035df4d2") },
    .{ .height = 1600000, .hash = h("ba44beaf37776c3e7da3f4a1b906ae238e1178794cbaa90685e3945d2662d7a2") },
    .{ .height = 1800000, .hash = h("4f23aaf2e83e4041cac670226d3024f4468e3b9bb6ffa2548ebc59489bd09b63") },
    .{ .height = 2000000, .hash = h("eaf5d7a4b6f07ccb8bdbe5db2f39e10eea3ee1c28f8333907d91c9ccc21ce99d") },
    .{ .height = 2200000, .hash = h("1243520890d08026daba8207ed3d67186da64d2b71b5c1e2dd26d34092dee6ba") },
};

/// This node's own checkpoints beyond the reference's table, always enforced
/// (PoW is skipped up to the last one by default). Each hash was confirmed
/// against several independent nodes, and against a header chain this node had
/// verified in full (PoW, difficulty, scheduling) (`zig build checkpoints`).
/// 3,500,000: 103.87.68.10, 195.162.57.26 and 188.36.153.167 (2026-10-01).
pub const ours = [_]Checkpoint{
    .{ .height = 2400000, .hash = h("323e4de7b2e77db84fe7655cec5d0598f61897766872ae02dc792ef9be347db2") },
    .{ .height = 2600000, .hash = h("7a360eab8a5345032905d9d3e3f56a6c7cd48484a138ce4f2446664e49ecc261") },
    .{ .height = 2800000, .hash = h("15bcd57f59d96bc8f82069a3b89ffbfcc5de445e6a41f9eeeea112d68bd1ff2d") },
    .{ .height = 3000000, .hash = h("1e4ccbb1eead27c4ebee40cfe79937947ed3f09bd70a960545ffc7a891971473") },
    .{ .height = 3200000, .hash = h("a6cd8175e1669a4a63377a746e611d7164e452918955378e3bb2b74894e15d5a") },
    .{ .height = 3400000, .hash = h("61b695b97ead6c78283d3f1ebf8494c0a46e73d360786120c9bfcf437db99980") },
    .{ .height = 3500000, .hash = h("39b10039147c8982c6f8c15b46ac7fd290306762395a7f4b169275b07b377c34") },
};

/// Further points, only with `extended_checkpoints` (closer to the tip).
pub const extended = [_]Checkpoint{
    .{ .height = 3600000, .hash = h("e7e466efafb6ab13c909d2204a60c7507a3254611b5fdf2641f78736d7addc9d") },
    .{ .height = 3700000, .hash = h("0d6f6213adbd81e050c52792c7956aef12d40b64d2514e4bc5a4a0d4aae5c978") },
};

pub const CheckpointError = error{CheckpointFailure};

/// Height up to which PoW may be skipped: our checkpoints, or also the extended ones.
pub fn trustedUpTo(use_extended: bool) u64 {
    return if (use_extended) extended[extended.len - 1].height else ours[ours.len - 1].height;
}

/// Returns whether `height` is inside the checkpointed range, and errors if a
/// checkpoint exists at exactly this height with a different hash
/// (`check_header_against_checkpoints`). The extended points only count when
/// `use_extended` is on.
pub fn check(height: u64, hash: Hash, use_extended: bool) CheckpointError!bool {
    for (mainnet) |c| {
        if (c.height == height and !c.hash.eql(hash)) return error.CheckpointFailure;
    }
    for (ours) |c| {
        if (c.height == height and !c.hash.eql(hash)) return error.CheckpointFailure;
    }
    if (use_extended) for (extended) |c| {
        if (c.height == height and !c.hash.eql(hash)) return error.CheckpointFailure;
    };
    return height <= trustedUpTo(use_extended);
}

test "checkpoint table" {
    try std.testing.expectEqual(@as(usize, 12), mainnet.len);
    try std.testing.expect(try check(150_000, Hash.zero, false));
    try std.testing.expectError(error.CheckpointFailure, check(200_000, Hash.zero, false));
    try std.testing.expect(try check(200_000, mainnet[1].hash, false));
    // ours are enforced and trusted by default, up to 3.5M
    try std.testing.expectError(error.CheckpointFailure, check(3_000_000, Hash.zero, false));
    try std.testing.expect(try check(3_450_000, Hash.zero, false));
    try std.testing.expect(try check(3_500_000, ours[ours.len - 1].hash, false));
    try std.testing.expect(!(try check(3_500_001, Hash.zero, false)));
    // the extended points only count when enabled
    try std.testing.expect(!(try check(3_600_000, Hash.zero, false)));
    try std.testing.expectError(error.CheckpointFailure, check(3_600_000, Hash.zero, true));
    try std.testing.expect(try check(3_650_000, Hash.zero, true));
    try std.testing.expect(try check(3_700_000, extended[extended.len - 1].hash, true));
    try std.testing.expect(!(try check(3_750_000, Hash.zero, true)));
}
