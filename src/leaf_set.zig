//! The leaf set: which leaves of a prunable PMMR are still unspent. Port of
//! `store/src/leaf_set.rs`; persisted as a portable roaring bitmap.
const std = @import("std");
const Io = std.Io;
const pmmr = @import("pmmr.zig");
const fsutil = @import("fsutil.zig");
const Bitmap = @import("bitmap.zig").Bitmap;
const PruneList = @import("prune_list.zig").PruneList;
const Hash = @import("hash.zig").Hash;

pub const LeafSet = struct {
    gpa: std.mem.Allocator,
    dir: Io.Dir,
    name: []const u8,
    bitmap: Bitmap,
    /// Last flushed state, restored by `discard`.
    bitmap_bak: Bitmap,
    /// Whether `flush` fsyncs the file.
    fsync: bool = true,

    pub fn open(gpa: std.mem.Allocator, io: Io, dir: Io.Dir, name: []const u8) !LeafSet {
        var bm = if (fsutil.exists(io, dir, name)) blk: {
            const bytes = try fsutil.readAll(gpa, io, dir, name);
            defer gpa.free(bytes);
            break :blk try Bitmap.deserialize(bytes);
        } else try Bitmap.init();
        errdefer bm.deinit();
        return .{ .gpa = gpa, .dir = dir, .name = name, .bitmap_bak = try bm.clone(), .bitmap = bm };
    }

    /// `<name>.<first 12 hex chars of the header hash>`: the reference formats
    /// the hash with its Display impl, which truncates, and archives use this name.
    pub fn snapshotName(gpa: std.mem.Allocator, name: []const u8, header_hash: Hash) ![]u8 {
        const hex = header_hash.toHex();
        return std.fmt.allocPrint(gpa, "{s}.{s}", .{ name, hex[0..12] });
    }

    pub fn deinit(self: *LeafSet) void {
        self.bitmap.deinit();
        self.bitmap_bak.deinit();
    }

    /// If a snapshot `<name>.<hash>` exists, make it the current leaf set
    /// (`copy_snapshot`: used when rewinding to a header).
    pub fn copySnapshot(gpa: std.mem.Allocator, io: Io, dir: Io.Dir, name: []const u8, snapshot_name: []const u8) !void {
        if (!fsutil.exists(io, dir, snapshot_name)) return;
        const bytes = try fsutil.readAll(gpa, io, dir, snapshot_name);
        defer gpa.free(bytes);
        var bm = try Bitmap.deserialize(bytes);
        defer bm.deinit();
        try fsutil.saveViaTempFile(gpa, io, dir, name, bytes);
    }

    /// All unpruned leaves up to and including `cutoff_pos`.
    fn unprunedPreCutoff(cutoff_pos: u64, prune_list: *const PruneList) !Bitmap {
        var out = try Bitmap.init();
        errdefer out.deinit();
        var x: u64 = 1;
        while (x <= cutoff_pos) : (x += 1) {
            if (pmmr.isLeaf(x) and !prune_list.isPruned(x)) out.add(@truncate(x));
        }
        return out;
    }

    /// Removes everything above `max` exclusive of `max` itself -- reproducing
    /// the reference, whose `remove_range(cutoff+1..maximum)` is exclusive of
    /// the maximum, so the highest set bit survives a rewind.
    fn removeAbove(bm: *Bitmap, cutoff_pos: u64) void {
        const max: u32 = bm.maximum() orelse 0;
        if (max == 0) return;
        const start: u32 = @truncate(cutoff_pos +% 1);
        const end: u32 = max - 1;
        if (start <= end) bm.removeRangeClosed(start, end);
    }

    /// Leaves that were spent (removed) at or below the cutoff.
    pub fn removedPreCutoff(self: *const LeafSet, cutoff_pos: u64, rewind_rm_pos: *const Bitmap, prune_list: *const PruneList) !Bitmap {
        var bm = try self.bitmap.clone();
        defer bm.deinit();
        removeAbove(&bm, cutoff_pos);
        bm.orInplace(rewind_rm_pos.*);
        var flipped = try bm.flip(1, cutoff_pos + 1);
        defer flipped.deinit();
        var unpruned = try unprunedPreCutoff(cutoff_pos, prune_list);
        defer unpruned.deinit();
        return flipped.andNew(unpruned);
    }

    pub fn rewind(self: *LeafSet, cutoff_pos: u64, rewind_rm_pos: ?*const Bitmap) void {
        removeAbove(&self.bitmap, cutoff_pos);
        if (rewind_rm_pos) |rm| self.bitmap.orInplace(rm.*);
    }

    pub fn add(self: *LeafSet, pos: u64) void {
        self.bitmap.add(@truncate(pos));
    }

    pub fn remove(self: *LeafSet, pos: u64) void {
        self.bitmap.remove(@truncate(pos));
    }

    /// Writes a copy of the current state as `<name>.<header hash hex>`.
    pub fn snapshot(self: *LeafSet, io: Io, header_hash: Hash) !void {
        var cp = try self.bitmap.clone();
        defer cp.deinit();
        cp.runOptimize();
        const bytes = try cp.serialize(self.gpa);
        defer self.gpa.free(bytes);
        const path = try snapshotName(self.gpa, self.name, header_hash);
        defer self.gpa.free(path);
        var f = try self.dir.createFile(io, path, .{});
        defer f.close(io);
        try f.writePositionalAll(io, bytes, 0);
    }

    pub fn flush(self: *LeafSet, io: Io) !void {
        self.bitmap.runOptimize();
        const bytes = try self.bitmap.serialize(self.gpa);
        defer self.gpa.free(bytes);
        try fsutil.saveViaTempFileOpt(self.gpa, io, self.dir, self.name, bytes, self.fsync);
        self.bitmap_bak.deinit();
        self.bitmap_bak = try self.bitmap.clone();
    }

    pub fn discard(self: *LeafSet) !void {
        const fresh = try self.bitmap_bak.clone();
        self.bitmap.deinit();
        self.bitmap = fresh;
    }

    pub fn includes(self: *const LeafSet, pos: u64) bool {
        return self.bitmap.contains(@truncate(pos));
    }

    pub fn len(self: *const LeafSet) u64 {
        return self.bitmap.cardinality();
    }

    pub fn iterator(self: *const LeafSet) Bitmap.Iterator {
        return self.bitmap.iterator();
    }
};

const testing = std.testing;

test "add, remove, flush, discard, reopen" {
    const io = testing.io;
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var ls = try LeafSet.open(gpa, io, tmp.dir, "pmmr_leaf.bin");
        defer ls.deinit();
        for ([_]u64{ 1, 2, 4, 5, 8 }) |p| ls.add(p);
        try ls.flush(io);
        ls.remove(4);
        try testing.expect(!ls.includes(4));
        try ls.discard();
        try testing.expect(ls.includes(4));
        ls.remove(2);
        try ls.flush(io);
        try testing.expectEqual(@as(u64, 4), ls.len());
    }
    var ls = try LeafSet.open(gpa, io, tmp.dir, "pmmr_leaf.bin");
    defer ls.deinit();
    try testing.expect(!ls.includes(2) and ls.includes(8));
}

test "rewind keeps the highest bit, as the reference does" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var ls = try LeafSet.open(gpa, testing.io, tmp.dir, "leaf");
    defer ls.deinit();
    for ([_]u64{ 1, 2, 4, 5, 8, 9, 11 }) |p| ls.add(p);
    ls.rewind(5, null);
    // 8 and 9 are removed but the maximum (11) survives the exclusive range
    try testing.expect(ls.includes(5) and !ls.includes(8) and !ls.includes(9));
    try testing.expect(ls.includes(11));

    // rewinding also re-adds positions spent after the rewind point
    var rm = try Bitmap.init();
    defer rm.deinit();
    rm.add(3);
    ls.rewind(5, &rm);
    try testing.expect(ls.includes(3));
}

test "removed pre cutoff" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var ls = try LeafSet.open(gpa, testing.io, tmp.dir, "leaf");
    defer ls.deinit();
    // leaves 1,2,4,5,8 exist; 2 and 5 were spent (not in the set)
    for ([_]u64{ 1, 4, 8 }) |p| ls.add(p);
    var pl = try PruneList.empty(gpa);
    defer pl.deinit();
    var rm = try Bitmap.init();
    defer rm.deinit();
    var removed = try ls.removedPreCutoff(8, &rm, &pl);
    defer removed.deinit();
    const v = try removed.toSlice(gpa);
    defer gpa.free(v);
    try testing.expectEqualSlices(u32, &.{ 2, 5 }, v);
}

test "snapshot and copy snapshot" {
    const io = testing.io;
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var ls = try LeafSet.open(gpa, io, tmp.dir, "leaf");
    defer ls.deinit();
    ls.add(1);
    ls.add(2);
    const h = Hash.fromVec(&.{ 0xab, 0xcd });
    try ls.snapshot(io, h);
    ls.add(4);
    try ls.flush(io);
    const snap = try LeafSet.snapshotName(gpa, "leaf", h);
    defer gpa.free(snap);
    try LeafSet.copySnapshot(gpa, io, tmp.dir, "leaf", snap);
    var re = try LeafSet.open(gpa, io, tmp.dir, "leaf");
    defer re.deinit();
    try testing.expect(re.includes(2) and !re.includes(4));
}
