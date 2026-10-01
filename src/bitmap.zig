//! 32-bit Roaring bitmap (CRoaring). Serialized in the Portable format, which
//! is what the leaf set and prune list files use.
const std = @import("std");

const r = @cImport({
    // Zig's C translator can't parse arm_neon.h; the header only needs NEON
    // for inline helpers we don't use (the compiled library still uses it).
    @cDefine("DISABLENEON", "1");
    @cInclude("roaring/roaring.h");
});

pub const Bitmap = struct {
    bm: *r.roaring_bitmap_t,

    pub const Error = error{ OutOfMemory, InvalidBitmap };

    pub fn init() Error!Bitmap {
        return .{ .bm = r.roaring_bitmap_create_with_capacity(0) orelse return error.OutOfMemory };
    }

    pub fn deinit(self: *Bitmap) void {
        r.roaring_bitmap_free(self.bm);
        self.* = undefined;
    }

    pub fn clone(self: Bitmap) Error!Bitmap {
        return .{ .bm = r.roaring_bitmap_copy(self.bm) orelse return error.OutOfMemory };
    }

    pub fn add(self: *Bitmap, x: u32) void {
        r.roaring_bitmap_add(self.bm, x);
    }

    pub fn remove(self: *Bitmap, x: u32) void {
        r.roaring_bitmap_remove(self.bm, x);
    }

    pub fn contains(self: Bitmap, x: u32) bool {
        return r.roaring_bitmap_contains(self.bm, x);
    }

    pub fn cardinality(self: Bitmap) u64 {
        return r.roaring_bitmap_get_cardinality(self.bm);
    }

    pub fn isEmpty(self: Bitmap) bool {
        return r.roaring_bitmap_is_empty(self.bm);
    }

    pub fn maximum(self: Bitmap) ?u32 {
        if (self.isEmpty()) return null;
        return r.roaring_bitmap_maximum(self.bm);
    }

    /// Number of elements <= x.
    pub fn rank(self: Bitmap, x: u32) u64 {
        return r.roaring_bitmap_rank(self.bm, x);
    }

    pub fn orInplace(self: *Bitmap, other: Bitmap) void {
        r.roaring_bitmap_or_inplace(self.bm, other.bm);
    }

    pub fn andNew(self: Bitmap, other: Bitmap) Error!Bitmap {
        return .{ .bm = r.roaring_bitmap_and(self.bm, other.bm) orelse return error.OutOfMemory };
    }

    /// Flips [start, end_exclusive), returning a new bitmap.
    pub fn flip(self: Bitmap, start: u64, end_exclusive: u64) Error!Bitmap {
        return .{ .bm = r.roaring_bitmap_flip(self.bm, start, end_exclusive) orelse return error.OutOfMemory };
    }

    /// Removes [min, max] inclusive (no-op when min > max).
    pub fn removeRangeClosed(self: *Bitmap, min: u32, max: u32) void {
        r.roaring_bitmap_remove_range_closed(self.bm, min, max);
    }

    pub fn runOptimize(self: *Bitmap) void {
        _ = r.roaring_bitmap_run_optimize(self.bm);
    }

    pub fn serializedSize(self: Bitmap) usize {
        return r.roaring_bitmap_portable_size_in_bytes(self.bm);
    }

    pub fn serialize(self: Bitmap, gpa: std.mem.Allocator) Error![]u8 {
        const buf = try gpa.alloc(u8, self.serializedSize());
        _ = r.roaring_bitmap_portable_serialize(self.bm, buf.ptr);
        return buf;
    }

    pub fn deserialize(bytes: []const u8) Error!Bitmap {
        const bm = r.roaring_bitmap_portable_deserialize_safe(bytes.ptr, bytes.len) orelse return error.InvalidBitmap;
        return .{ .bm = bm };
    }

    pub const Iterator = struct {
        it: r.roaring_uint32_iterator_t,

        pub fn next(self: *Iterator) ?u32 {
            if (!self.it.has_value) return null;
            const v = self.it.current_value;
            _ = r.roaring_uint32_iterator_advance(&self.it);
            return v;
        }
    };

    pub fn iterator(self: Bitmap) Iterator {
        var it: r.roaring_uint32_iterator_t = undefined;
        r.roaring_iterator_init(self.bm, &it);
        return .{ .it = it };
    }

    pub fn toSlice(self: Bitmap, gpa: std.mem.Allocator) Error![]u32 {
        const out = try gpa.alloc(u32, @intCast(self.cardinality()));
        r.roaring_bitmap_to_uint32_array(self.bm, out.ptr);
        return out;
    }
};

test "bitmap basics, rank, flip and portable round trip" {
    const gpa = std.testing.allocator;
    var b = try Bitmap.init();
    defer b.deinit();
    for ([_]u32{ 1, 5, 6, 100, 70000 }) |x| b.add(x);
    try std.testing.expectEqual(@as(u64, 5), b.cardinality());
    try std.testing.expectEqual(@as(?u32, 70000), b.maximum());
    try std.testing.expectEqual(@as(u64, 3), b.rank(6));
    try std.testing.expectEqual(@as(u64, 3), b.rank(99));
    try std.testing.expect(b.contains(100));
    b.remove(100);
    try std.testing.expect(!b.contains(100));

    var f = try b.flip(1, 8);
    defer f.deinit();
    try std.testing.expect(!f.contains(1));
    try std.testing.expect(f.contains(2));
    try std.testing.expect(f.contains(7));
    try std.testing.expect(!f.contains(5));

    b.runOptimize();
    const bytes = try b.serialize(gpa);
    defer gpa.free(bytes);
    var back = try Bitmap.deserialize(bytes);
    defer back.deinit();
    try std.testing.expectEqual(b.cardinality(), back.cardinality());

    var it = back.iterator();
    var got: [8]u32 = undefined;
    var n: usize = 0;
    while (it.next()) |v| : (n += 1) got[n] = v;
    try std.testing.expectEqualSlices(u32, &.{ 1, 5, 6, 70000 }, got[0..n]);

    try std.testing.expectError(error.InvalidBitmap, Bitmap.deserialize("garbage"));
}
