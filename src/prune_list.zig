//! The prune list: which PMMR subtrees have been fully pruned ("pruned
//! roots"), and the position shifts that pruning causes in the hash and data
//! files. Port of `store/src/prune_list.rs`; file format is the portable
//! serialization of a 32-bit roaring bitmap.
const std = @import("std");
const Io = std.Io;
const pmmr = @import("pmmr.zig");
const fsutil = @import("fsutil.zig");
const Bitmap = @import("bitmap.zig").Bitmap;

pub const PruneList = struct {
    gpa: std.mem.Allocator,
    /// Where to persist on `flush`; null for an in-memory list.
    file: ?struct { dir: Io.Dir, name: []const u8 } = null,
    bitmap: Bitmap,
    pruned_cache: Bitmap,
    shift_cache: std.ArrayList(u64) = .empty,
    leaf_shift_cache: std.ArrayList(u64) = .empty,

    /// Takes ownership of `bitmap`. Position 0 is not valid (1-indexed) and is dropped.
    pub fn init(gpa: std.mem.Allocator, bitmap_in: Bitmap) !PruneList {
        var bm = bitmap_in;
        bm.remove(0);
        return .{ .gpa = gpa, .bitmap = bm, .pruned_cache = try Bitmap.init() };
    }

    pub fn empty(gpa: std.mem.Allocator) !PruneList {
        return init(gpa, try Bitmap.init());
    }

    pub fn deinit(self: *PruneList) void {
        self.bitmap.deinit();
        self.pruned_cache.deinit();
        self.shift_cache.deinit(self.gpa);
        self.leaf_shift_cache.deinit(self.gpa);
    }

    /// Opens (or creates empty) the list persisted as `name` in `dir`.
    pub fn open(gpa: std.mem.Allocator, io: Io, dir: Io.Dir, name: []const u8) !PruneList {
        var bm = if (fsutil.exists(io, dir, name)) blk: {
            const bytes = try fsutil.readAll(gpa, io, dir, name);
            defer gpa.free(bytes);
            break :blk try Bitmap.deserialize(bytes);
        } else try Bitmap.init();
        errdefer bm.deinit();
        var pl = try init(gpa, bm);
        pl.file = .{ .dir = dir, .name = name };
        try pl.initCaches();
        return pl;
    }

    pub fn initCaches(self: *PruneList) !void {
        try self.buildShiftCache();
        try self.buildLeafShiftCache();
        try self.buildPrunedCache();
    }

    pub fn flush(self: *PruneList, io: Io) !void {
        self.bitmap.runOptimize();
        if (self.file) |f| {
            const bytes = try self.bitmap.serialize(self.gpa);
            defer self.gpa.free(bytes);
            try fsutil.saveViaTempFile(self.gpa, io, f.dir, f.name, bytes);
        }
        try self.initCaches();
    }

    fn bmax(self: *const PruneList) u64 {
        return self.bitmap.maximum() orelse 0;
    }

    pub fn getTotalShift(self: *const PruneList) u64 {
        return self.getShift(self.bmax());
    }

    pub fn getTotalLeafShift(self: *const PruneList) u64 {
        return self.getLeafShift(self.bmax());
    }

    fn shiftFrom(self: *const PruneList, cache: []const u64, pos: u64) u64 {
        if (self.bitmap.isEmpty()) return 0;
        const idx = self.bitmap.rank(@truncate(pos));
        if (idx == 0) return 0;
        if (cache.len == 0) return 0;
        if (idx > cache.len) return cache[cache.len - 1];
        return cache[@intCast(idx - 1)];
    }

    pub fn getShift(self: *const PruneList, pos: u64) u64 {
        return self.shiftFrom(self.shift_cache.items, pos);
    }

    pub fn getLeafShift(self: *const PruneList, pos: u64) u64 {
        return self.shiftFrom(self.leaf_shift_cache.items, pos);
    }

    fn buildShiftCache(self: *PruneList) !void {
        if (self.bitmap.isEmpty()) return;
        self.shift_cache.clearRetainingCapacity();
        var it = self.bitmap.iterator();
        while (it.next()) |p32| {
            if (p32 == 0) continue;
            const pos: u64 = p32;
            const prev_shift = self.getShift(pos -| 1);
            const curr_shift: u64 = if (self.isPrunedRoot(pos)) blk: {
                const height = pmmr.bintreePostorderHeight(pos);
                break :blk 2 * ((@as(u64, 1) << @intCast(height)) - 1);
            } else 0;
            try self.shift_cache.append(self.gpa, prev_shift + curr_shift);
        }
    }

    fn buildLeafShiftCache(self: *PruneList) !void {
        if (self.bitmap.isEmpty()) return;
        self.leaf_shift_cache.clearRetainingCapacity();
        var it = self.bitmap.iterator();
        while (it.next()) |p32| {
            if (p32 == 0) continue;
            const pos: u64 = p32;
            const prev_shift = self.getLeafShift(pos -| 1);
            const curr_shift: u64 = if (self.isPrunedRoot(pos)) blk: {
                const height = pmmr.bintreePostorderHeight(pos);
                break :blk if (height == 0) 0 else (@as(u64, 1) << @intCast(height));
            } else 0;
            try self.leaf_shift_cache.append(self.gpa, prev_shift + curr_shift);
        }
    }

    /// Every position in the subtree of a pruned root is pruned. (The reference
    /// walks each position's path to the top; a pruned root at `r` covers
    /// exactly [leftmost(r), r], which is equivalent and much faster.)
    fn buildPrunedCache(self: *PruneList) !void {
        if (self.bitmap.isEmpty()) return;
        var fresh = try Bitmap.init();
        errdefer fresh.deinit();
        var it = self.bitmap.iterator();
        while (it.next()) |r32| {
            if (r32 == 0) continue;
            const r: u64 = r32;
            const left = pmmr.bintreeLeftmost(r);
            var p = left;
            while (p <= r) : (p += 1) fresh.add(@intCast(p));
        }
        fresh.runOptimize();
        self.pruned_cache.deinit();
        self.pruned_cache = fresh;
    }

    /// Marks `pos` pruned, rolling siblings up into their parent where possible.
    pub fn add(self: *PruneList, pos: u64) void {
        std.debug.assert(pos > 0);
        var current = pos;
        while (true) {
            const fam = pmmr.family(current);
            if (self.bitmap.contains(@truncate(fam.sibling)) or self.pruned_cache.contains(@truncate(fam.sibling))) {
                self.pruned_cache.add(@truncate(current));
                self.bitmap.remove(@truncate(fam.sibling));
                current = fam.parent;
            } else {
                self.pruned_cache.add(@truncate(current));
                self.bitmap.add(@truncate(current));
                break;
            }
        }
    }

    pub fn len(self: *const PruneList) u64 {
        return self.bitmap.cardinality();
    }

    pub fn isEmpty(self: *const PruneList) bool {
        return self.bitmap.isEmpty();
    }

    pub fn toVec(self: *const PruneList, gpa: std.mem.Allocator) ![]u64 {
        var out: std.ArrayList(u64) = .empty;
        errdefer out.deinit(gpa);
        var it = self.bitmap.iterator();
        while (it.next()) |x| try out.append(gpa, x);
        return out.toOwnedSlice(gpa);
    }

    pub fn isPruned(self: *const PruneList, pos: u64) bool {
        std.debug.assert(pos > 0);
        return self.pruned_cache.contains(@truncate(pos));
    }

    pub fn isPrunedRoot(self: *const PruneList, pos: u64) bool {
        std.debug.assert(pos > 0);
        return self.bitmap.contains(@truncate(pos));
    }
};

// ------------------------------------------------------------------ tests

const testing = std.testing;

fn expectVec(pl: *const PruneList, want: []const u64) !void {
    const v = try pl.toVec(testing.allocator);
    defer testing.allocator.free(v);
    try testing.expectEqualSlices(u64, want, v);
}

test "zero value is dropped" {
    var bm = try Bitmap.init();
    bm.add(0);
    var pl = try PruneList.init(testing.allocator, bm);
    defer pl.deinit();
    try testing.expect(pl.isEmpty());
}

test "is_pruned" {
    const io = testing.io;
    var pl = try PruneList.empty(testing.allocator);
    defer pl.deinit();
    try testing.expect(!pl.isPruned(1) and !pl.isPruned(2));

    pl.add(2);
    try pl.flush(io);
    try expectVec(&pl, &.{2});
    try testing.expect(!pl.isPruned(1) and pl.isPruned(2) and !pl.isPruned(3));

    pl.add(2);
    pl.add(1);
    try pl.flush(io);
    try expectVec(&pl, &.{3});
    try testing.expect(pl.isPruned(1) and pl.isPruned(2) and pl.isPruned(3) and !pl.isPruned(4));

    pl.add(4);
    try pl.flush(io);
    try expectVec(&pl, &.{ 3, 4 });
    try testing.expect(pl.isPruned(4) and !pl.isPruned(5));
}

test "leaf shift" {
    const io = testing.io;
    var pl = try PruneList.empty(testing.allocator);
    defer pl.deinit();
    for (1..5) |i| try testing.expectEqual(@as(u64, 0), pl.getLeafShift(i));

    pl.add(1);
    try pl.flush(io);
    try expectVec(&pl, &.{1});
    for (1..5) |i| try testing.expectEqual(@as(u64, 0), pl.getLeafShift(i));

    pl.add(1);
    pl.add(2);
    try pl.flush(io);
    try testing.expectEqual(@as(u64, 0), pl.getLeafShift(2));
    try testing.expectEqual(@as(u64, 2), pl.getLeafShift(3));
    try testing.expectEqual(@as(u64, 2), pl.getLeafShift(5));

    pl.add(4);
    try pl.flush(io);
    try expectVec(&pl, &.{ 3, 4 });
    for (3..9) |i| try testing.expectEqual(@as(u64, 2), pl.getLeafShift(i));

    pl.add(4);
    pl.add(5);
    try pl.flush(io);
    try expectVec(&pl, &.{7});
    for (1..7) |i| try testing.expectEqual(@as(u64, 0), pl.getLeafShift(i));
    for (7..10) |i| try testing.expectEqual(@as(u64, 4), pl.getLeafShift(i));

    var p2 = try PruneList.empty(testing.allocator);
    defer p2.deinit();
    p2.add(5);
    p2.add(11);
    p2.add(12);
    p2.add(4);
    try p2.flush(io);
    try expectVec(&p2, &.{ 6, 13 });
    try testing.expectEqual(@as(u64, 0), p2.getLeafShift(2));
    try testing.expectEqual(@as(u64, 0), p2.getLeafShift(4));
    try testing.expectEqual(@as(u64, 2), p2.getLeafShift(8));
    try testing.expectEqual(@as(u64, 2), p2.getLeafShift(9));
    try testing.expectEqual(@as(u64, 4), p2.getLeafShift(13));
    try testing.expectEqual(@as(u64, 4), p2.getLeafShift(14));
}

test "shift" {
    const io = testing.io;
    var pl = try PruneList.empty(testing.allocator);
    defer pl.deinit();
    pl.add(1);
    try pl.flush(io);
    for (1..4) |i| try testing.expectEqual(@as(u64, 0), pl.getShift(i));

    pl.add(1);
    pl.add(2);
    try pl.flush(io);
    try expectVec(&pl, &.{3});
    try testing.expectEqual(@as(u64, 0), pl.getShift(2));
    for (3..7) |i| try testing.expectEqual(@as(u64, 2), pl.getShift(i));

    pl.add(3);
    try pl.flush(io);
    try expectVec(&pl, &.{3});
    pl.add(4);
    try pl.flush(io);
    try expectVec(&pl, &.{ 3, 4 });
    for (3..7) |i| try testing.expectEqual(@as(u64, 2), pl.getShift(i));

    pl.add(4);
    pl.add(5);
    try pl.flush(io);
    try expectVec(&pl, &.{7});
    for (1..7) |i| try testing.expectEqual(@as(u64, 0), pl.getShift(i));
    for (7..10) |i| try testing.expectEqual(@as(u64, 6), pl.getShift(i));

    var x: u64 = 6;
    while (x < 1000) : (x += 1) pl.add(x);
    try pl.flush(io);
    try testing.expectEqual(@as(u64, 996), pl.getShift(1010));

    var p2 = try PruneList.empty(testing.allocator);
    defer p2.deinit();
    p2.add(9);
    p2.add(8);
    p2.add(5);
    p2.add(4);
    try p2.flush(io);
    try expectVec(&p2, &.{ 6, 10 });
    const want = [_]u64{ 0, 0, 0, 0, 0, 2, 2, 2, 2, 4, 4, 4 };
    for (want, 1..) |w, i| try testing.expectEqual(w, p2.getShift(i));
}

/// The reference algorithm for the pruned cache, used to validate the fast one.
fn slowPrunedCache(gpa: std.mem.Allocator, roots: Bitmap) !Bitmap {
    var out = try Bitmap.init();
    const max = roots.maximum() orelse return out;
    var pos: u64 = 1;
    while (pos <= max) : (pos += 1) {
        const p = pmmr.path(pos, max);
        for (p.items()) |x| if (roots.contains(@intCast(x))) {
            out.add(@intCast(pos));
            break;
        };
    }
    _ = gpa;
    return out;
}

test "fast pruned cache equals the reference algorithm" {
    const io = testing.io;
    var pl = try PruneList.empty(testing.allocator);
    defer pl.deinit();
    var prng = std.Random.DefaultPrng.init(42);
    const rand = prng.random();
    for (0..300) |_| pl.add(pmmr.insertionToPmmrIndex(rand.intRangeAtMost(u64, 1, 400)));
    try pl.flush(io);
    var slow = try slowPrunedCache(testing.allocator, pl.bitmap);
    defer slow.deinit();
    try testing.expectEqual(slow.cardinality(), pl.pruned_cache.cardinality());
    const a = try slow.toSlice(testing.allocator);
    defer testing.allocator.free(a);
    const b = try pl.pruned_cache.toSlice(testing.allocator);
    defer testing.allocator.free(b);
    try testing.expectEqualSlices(u32, a, b);
}

test "persists across open" {
    const io = testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var pl = try PruneList.open(testing.allocator, io, tmp.dir, "pmmr_prun.bin");
        defer pl.deinit();
        pl.add(1);
        pl.add(2);
        try pl.flush(io);
    }
    var pl = try PruneList.open(testing.allocator, io, tmp.dir, "pmmr_prun.bin");
    defer pl.deinit();
    try expectVec(&pl, &.{3});
    try testing.expectEqual(@as(u64, 2), pl.getShift(3));
    try testing.expect(pl.isPruned(1));
}
