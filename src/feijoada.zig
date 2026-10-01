//! Feijoada: the deterministic PoW-algorithm scheduler (`core/block/feijoada.rs`).
//! Each block carries a "bottle" of counters of how many of the last 100
//! blocks used each algorithm; the next algorithm is the one furthest below
//! the target proportion of the active policy.
const std = @import("std");
const ser = @import("ser.zig");
const PoWType = @import("pow_types.zig").PoWType;

/// Rust `HashMap<PoWType, u32>`; `null` marks an absent key.
pub const Policy = struct {
    v: [4]?u32,

    pub const default_bottles: Policy = .{ .v = .{ 0, 0, 0, 0 } };

    pub fn init(cuckaroo: u32, cuckatoo: u32, randomx: u32, progpow: u32) Policy {
        return .{ .v = .{ cuckaroo, cuckatoo, randomx, progpow } };
    }

    pub fn get(self: Policy, pow: PoWType) ?u32 {
        return self.v[pow.idx()];
    }

    pub fn eql(a: Policy, b: Policy) bool {
        for (a.v, b.v) |x, y| if (x != y) return false;
        return true;
    }

    pub fn len(self: Policy) u64 {
        var n: u64 = 0;
        for (self.v) |x| n += @intFromBool(x != null);
        return n;
    }

    pub fn write(self: Policy, w: anytype) ser.Error!void {
        try ser.writeU64(w, self.len());
        for (self.v, 0..) |x, i| if (x) |n| {
            try ser.writeU8(w, @intCast(i));
            try ser.writeU32(w, n);
        };
    }

    pub fn read(r: *ser.Reader) ser.Error!Policy {
        const n = try r.readU64();
        var p: Policy = .{ .v = .{ null, null, null, null } };
        var i: u64 = 0;
        while (i < n) : (i += 1) {
            const pow = try PoWType.fromU8(try r.readU8());
            p.v[pow.idx()] = try r.readU32();
        }
        return p;
    }
};

/// Sum of all entries, at least 1.
pub fn countBeans(bottles: Policy) u32 {
    var s: u32 = 0;
    for (bottles.v) |x| s +%= x orelse 0;
    return @max(s, 1);
}

pub fn nextBlockBottles(pow: PoWType, bottles: Policy) Policy {
    var nb = if (countBeans(bottles) == 100) Policy.default_bottles else bottles;
    nb.v[pow.idx()] = (nb.v[pow.idx()] orelse 0) +% 1;
    return nb;
}

/// Picks the algorithm whose share is furthest below its policy proportion.
/// Uses f32 exactly like the reference (bit-for-bit compatible) and, like
/// Rust's `max_by`, prefers the *last* of equally-scored algorithms.
/// Errors where the reference would panic (policy names an algo missing from bottles).
pub fn chooseAlgo(policy: Policy, bottles: Policy) error{MissingBottle}!PoWType {
    const total: f32 = @floatFromInt(countBeans(bottles));
    var best: ?PoWType = null;
    var best_score: f32 = 0;
    for (PoWType.all) |algo| {
        const proportion = policy.get(algo) orelse continue;
        if (proportion == 0) continue;
        const beans = bottles.get(algo) orelse return error.MissingBottle;
        const score: f32 = 100.0 * @as(f32, @floatFromInt(beans)) / total;
        const diff: f32 = @as(f32, @floatFromInt(proportion)) - score;
        if (best == null or diff >= best_score) {
            best = algo;
            best_score = diff;
        }
    }
    return best orelse error.MissingBottle;
}

pub const AllowPolicy = struct { height: u64, value: u64 };

/// Bitmask of policies allowed at `height` (the entry with the greatest
/// height <= `height`; the last entry if none qualifies).
pub fn allowedAt(allowed: []const AllowPolicy, height: u64) ?u64 {
    var best: ?AllowPolicy = null;
    for (allowed) |a| {
        if (a.height <= height and (best == null or a.height >= best.?.height)) best = a;
    }
    if (best) |b| return b.value;
    if (allowed.len == 0) return null;
    return allowed[allowed.len - 1].value;
}

pub fn isAllowedPolicy(allowed: []const AllowPolicy, height: u64, policy: u8) bool {
    const mask = allowedAt(allowed, height) orelse return false;
    if (policy >= 64) return false;
    return (mask & (@as(u64, 1) << @intCast(policy))) != 0;
}

pub const PolicyConfig = struct {
    allowed_policies: []const AllowPolicy,
    policies: []const Policy,

    pub fn policy(self: PolicyConfig, index: u8) ?Policy {
        if (index < self.policies.len) return self.policies[index];
        return null;
    }
};

test "bottles reset at 100 and increment" {
    var b = Policy.default_bottles;
    b.v[2] = 100;
    const n = nextBlockBottles(.randomx, b);
    try std.testing.expectEqual(@as(?u32, 1), n.get(.randomx));
    try std.testing.expectEqual(@as(?u32, 0), n.get(.progpow));
}

test "choose algo follows the deficit" {
    // 60/38/2 mix: with an empty bottle every score is 0, the largest proportion (randomx) wins.
    const pol = Policy.init(0, 2, 60, 38);
    try std.testing.expectEqual(PoWType.randomx, try chooseAlgo(pol, Policy.default_bottles));
    // randomx already has all the beans -> its diff is negative, progpow (38) is furthest below.
    const b = Policy.init(0, 0, 10, 0);
    try std.testing.expectEqual(PoWType.progpow, try chooseAlgo(pol, b));
}

test "policy serialization" {
    const gpa = std.testing.allocator;
    const p = Policy.init(0, 2, 60, 38);
    const bytes = try ser.serVec(gpa, p, ser.ProtocolVersion.local());
    defer gpa.free(bytes);
    try std.testing.expectEqual(@as(usize, 8 + 4 * 5), bytes.len);
    var r = ser.Reader.init(gpa, bytes, ser.ProtocolVersion.local());
    try std.testing.expect((try Policy.read(&r)).eql(p));
}
