//! PoWType and the multi-algorithm Difficulty (from `core/src/pow/types.rs`).
const std = @import("std");
const ser = @import("ser.zig");

pub const PoWType = enum(u8) {
    cuckaroo = 0,
    cuckatoo = 1,
    randomx = 2,
    progpow = 3,

    pub const count = 4;
    pub const all = [_]PoWType{ .cuckaroo, .cuckatoo, .randomx, .progpow };

    pub fn fromU8(v: u8) ser.Error!PoWType {
        return switch (v) {
            0 => .cuckaroo,
            1 => .cuckatoo,
            2 => .randomx,
            3 => .progpow,
            else => error.CorruptedData,
        };
    }

    pub fn idx(self: PoWType) usize {
        return @intFromEnum(self);
    }
};

/// Per-algorithm difficulty. The Rust type is a `HashMap<PoWType, u64>` that
/// is serialized as a count followed by (algo, value) pairs sorted by algo;
/// `null` marks an absent key, which matters for byte-exact re-serialization
/// of data received from peers. Arithmetic wraps like a Rust release build.
pub const Difficulty = struct {
    num: [4]?u64,

    pub fn number(v: u64) Difficulty {
        return .{ .num = .{ v, v, v, v } };
    }
    pub fn zero() Difficulty {
        return number(0);
    }
    pub fn fromNum(n: u64) Difficulty {
        return number(@max(n, 1));
    }

    pub fn toNum(self: Difficulty, pow: PoWType) u64 {
        return self.num[pow.idx()] orelse 0;
    }

    pub fn insert(self: *Difficulty, pow: PoWType, v: u64) void {
        self.num[pow.idx()] = v;
    }

    pub fn len(self: Difficulty) u64 {
        var n: u64 = 0;
        for (self.num) |x| n += @intFromBool(x != null);
        return n;
    }

    fn sum(self: Difficulty) u128 {
        var s: u128 = 0;
        for (self.num) |x| s += x orelse 0;
        return s;
    }

    /// Ordering compares the sum across algorithms.
    pub fn order(a: Difficulty, b: Difficulty) std.math.Order {
        return std.math.order(a.sum(), b.sum());
    }

    pub fn eql(a: Difficulty, b: Difficulty) bool {
        for (a.num, b.num) |x, y| {
            if (x != y) return false;
        }
        return true;
    }

    // The binary ops start from an all-zero map and overwrite keys present
    // in `self`, so the result always has all four entries.
    pub fn add(a: Difficulty, b: Difficulty) Difficulty {
        var d = zero();
        for (a.num, 0..) |x, i| if (x) |v| {
            d.num[i] = v +% (b.num[i] orelse 0);
        };
        return d;
    }
    pub fn sub(a: Difficulty, b: Difficulty) Difficulty {
        var d = zero();
        for (a.num, 0..) |x, i| if (x) |v| {
            d.num[i] = v -% (b.num[i] orelse 0);
        };
        return d;
    }
    pub fn mul(a: Difficulty, b: Difficulty) Difficulty {
        var d = zero();
        for (a.num, 0..) |x, i| if (x) |v| {
            d.num[i] = v *% (b.num[i] orelse 1);
        };
        return d;
    }
    pub fn div(a: Difficulty, b: Difficulty) error{DivisionByZero}!Difficulty {
        var d = zero();
        for (a.num, 0..) |x, i| if (x) |v| {
            const den = b.num[i] orelse 1;
            if (den == 0) return error.DivisionByZero;
            d.num[i] = v / den;
        };
        return d;
    }

    /// 8 + 4 * 9 bytes when all algorithms are present.
    pub const LEN = 8 + PoWType.count * 9;

    pub fn write(self: Difficulty, w: anytype) ser.Error!void {
        try ser.writeU64(w, self.len());
        for (self.num, 0..) |x, i| if (x) |v| {
            try ser.writeU8(w, @intCast(i));
            try ser.writeU64(w, v);
        };
    }

    pub fn read(r: *ser.Reader) ser.Error!Difficulty {
        const n = try r.readU64();
        var d: Difficulty = .{ .num = .{ null, null, null, null } };
        var i: u64 = 0;
        while (i < n) : (i += 1) {
            const pow = try r.readU8();
            const v = try r.readU64();
            const t = try PoWType.fromU8(pow);
            d.num[t.idx()] = v;
        }
        return d;
    }
};

test "difficulty serialization is count + sorted pairs" {
    const gpa = std.testing.allocator;
    var d = Difficulty.number(7);
    d.num[0] = null;
    const bytes = try ser.serVec(gpa, d, ser.ProtocolVersion.local());
    defer gpa.free(bytes);
    try std.testing.expectEqual(@as(usize, 8 + 3 * 9), bytes.len);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 0, 0, 3, 1, 0, 0, 0, 0, 0, 0, 0, 7 }, bytes[0..17]);

    var r = ser.Reader.init(gpa, bytes, ser.ProtocolVersion.local());
    const back = try Difficulty.read(&r);
    try std.testing.expect(back.eql(d));
}

test "difficulty ops fill missing keys and compare by sum" {
    var a = Difficulty.number(10);
    a.num[3] = null;
    const b = Difficulty.number(3);
    const s = a.add(b);
    try std.testing.expectEqual(@as(?u64, 0), s.num[3]);
    try std.testing.expectEqual(@as(?u64, 13), s.num[0]);
    try std.testing.expect(Difficulty.number(2).order(Difficulty.number(3)) == .lt);
    try std.testing.expectError(error.CorruptedData, PoWType.fromU8(9));
}
