//! File-backed PMMR storage: hash file, data file, leaf set and prune list.
//! Port of `store/src/pmmr.rs` (`PMMRBackend`). The on-disk files are the same
//! ones exchanged in txhashset archives, so their formats match the reference:
//!   pmmr_hash.bin  32-byte hashes, in position order (pruned positions removed)
//!   pmmr_data.bin  element data (fixed size, or variable with pmmr_size.bin)
//!   pmmr_leaf.bin  roaring bitmap of unspent leaf positions (prunable only)
//!   pmmr_prun.bin  roaring bitmap of pruned subtree roots
const std = @import("std");
const Io = std.Io;
const ser = @import("ser.zig");
const pmmr = @import("pmmr.zig");
const hash_mod = @import("hash.zig");
const aof = @import("aof.zig");
const Bitmap = @import("bitmap.zig").Bitmap;
const LeafSet = @import("leaf_set.zig").LeafSet;
const PruneList = @import("prune_list.zig").PruneList;
const Hash = hash_mod.Hash;

pub const HASH_FILE = "pmmr_hash.bin";
pub const DATA_FILE = "pmmr_data.bin";
pub const LEAF_FILE = "pmmr_leaf.bin";
pub const PRUN_FILE = "pmmr_prun.bin";
pub const SIZE_FILE = "pmmr_size.bin";

/// The four files that make up a PMMR in a txhashset archive.
pub const PMMR_FILES = [_][]const u8{ HASH_FILE, DATA_FILE, LEAF_FILE, PRUN_FILE };

/// `T`: the element type pushed into the PMMR. `E`: what is stored in the
/// data file (`T::E` in the reference), with `asElmt` converting. `elmt_size`
/// is the fixed size of an encoded `E`, or null for variable-size elements.
pub fn PMMRBackend(comptime T: type, comptime E: type, comptime asElmt: fn (T) E, comptime elmt_size: ?u16) type {
    return struct {
        gpa: std.mem.Allocator,
        io: Io,
        dir: Io.Dir,
        prunable: bool,
        version: ser.ProtocolVersion,
        hash_file: aof.AppendOnlyFile,
        data_file: aof.AppendOnlyFile,
        size_file: ?*aof.AppendOnlyFile,
        leaf_set: LeafSet,
        prune_list: PruneList,

        const Self = @This();
        pub const Elmt = E;

        /// Length of the encoded element at the start of `data` (variable-size files).
        fn sizer(data: []const u8, version: ser.ProtocolVersion) ?usize {
            var r = ser.Reader.init(std.heap.page_allocator, data, version);
            r.limit_fixed = false;
            _ = E.read(&r) catch return null;
            return r.pos;
        }

        pub fn open(gpa: std.mem.Allocator, io: Io, dir: Io.Dir, prunable: bool, version: ser.ProtocolVersion) !*Self {
            return openAt(gpa, io, dir, prunable, version, null);
        }

        /// Like `open`; when `snapshot_hash` is given, first adopts the leaf-set
        /// snapshot `pmmr_leaf.bin.<hash>` (as a txhashset archive provides).
        pub fn openAt(gpa: std.mem.Allocator, io: Io, dir: Io.Dir, prunable: bool, version: ser.ProtocolVersion, snapshot_hash: ?Hash) !*Self {
            if (snapshot_hash) |h| {
                const snap = try LeafSet.snapshotName(gpa, LEAF_FILE, h);
                defer gpa.free(snap);
                try LeafSet.copySnapshot(gpa, io, dir, LEAF_FILE, snap);
            }
            const self = try gpa.create(Self);
            errdefer gpa.destroy(self);
            self.gpa = gpa;
            self.io = io;
            self.dir = dir;
            self.prunable = prunable;
            self.version = version;

            var size_file: ?*aof.AppendOnlyFile = null;
            errdefer if (size_file) |sf| {
                sf.deinit();
                gpa.destroy(sf);
            };
            var size_info: aof.SizeInfo = undefined;
            if (elmt_size) |n| {
                size_info = .{ .fixed = n };
            } else {
                const sf = try gpa.create(aof.AppendOnlyFile);
                errdefer gpa.destroy(sf);
                sf.* = try aof.AppendOnlyFile.open(gpa, io, dir, SIZE_FILE, .{ .fixed = aof.SizeEntry.LEN }, null);
                size_file = sf;
                size_info = .{ .variable = sf };
            }
            self.size_file = size_file;

            self.hash_file = try aof.AppendOnlyFile.open(gpa, io, dir, HASH_FILE, .{ .fixed = Hash.LEN }, null);
            errdefer self.hash_file.deinit();
            self.data_file = try aof.AppendOnlyFile.openVersioned(gpa, io, dir, DATA_FILE, size_info, if (elmt_size == null) &sizer else null, version);
            errdefer self.data_file.deinit();
            self.leaf_set = try LeafSet.open(gpa, io, dir, LEAF_FILE);
            errdefer self.leaf_set.deinit();
            self.prune_list = try PruneList.open(gpa, io, dir, PRUN_FILE);
            // the size file is owned by `self`, not by the (borrowing) data file
            size_file = null;
            return self;
        }

        pub fn close(self: *Self) void {
            self.data_file.deinit();
            self.hash_file.deinit();
            if (self.size_file) |sf| {
                sf.deinit();
                self.gpa.destroy(sf);
            }
            self.leaf_set.deinit();
            self.prune_list.deinit();
            const gpa = self.gpa;
            gpa.destroy(self);
        }

        // ---- Backend interface used by pmmr.PMMR

        pub fn append(self: *Self, elmt: T, hashes: []const Hash) pmmr.Error!void {
            self.appendInner(elmt, hashes) catch return error.BackendFailure;
        }

        fn appendInner(self: *Self, elmt: T, hashes: []const Hash) !void {
            const bytes = try ser.serVec(self.gpa, asElmt(elmt), self.version);
            defer self.gpa.free(bytes);
            try self.data_file.append(bytes);
            const size = self.data_file.sizeUnsyncInElmts();
            for (hashes) |h| try self.hash_file.append(&h.bytes);
            if (self.prunable) {
                const pos = pmmr.insertionToPmmrIndex(size + self.prune_list.getTotalLeafShift());
                self.leaf_set.add(pos);
            }
        }

        fn isPruned(self: *const Self, pos: u64) bool {
            return self.prune_list.isPruned(pos);
        }
        fn isCompacted(self: *const Self, pos: u64) bool {
            return self.prune_list.isPruned(pos) and !self.prune_list.isPrunedRoot(pos);
        }

        pub fn getFromFile(self: *const Self, position: u64) ?Hash {
            if (self.isCompacted(position)) return null;
            const shift = self.prune_list.getShift(position);
            var scratch: [Hash.LEN]u8 = undefined;
            const bytes = (self.hash_file.read(position - shift - 1, &scratch) catch return null) orelse return null;
            return Hash.fromVec(bytes);
        }

        pub fn getDataFromFile(self: *const Self, position: u64) ?E {
            if (!pmmr.isLeaf(position)) return null;
            if (self.isCompacted(position)) return null;
            const flatfile_pos = pmmr.nLeaves(position);
            const shift = self.prune_list.getLeafShift(position);
            var scratch: [4096]u8 = undefined;
            const bytes = (self.data_file.read(flatfile_pos - shift - 1, &scratch) catch return null) orelse return null;
            var r = ser.Reader.init(self.gpa, bytes, self.version);
            r.limit_fixed = false;
            return E.read(&r) catch null;
        }

        pub fn getHash(self: *const Self, pos: u64) ?Hash {
            if (self.prunable and pmmr.isLeaf(pos) and !self.leaf_set.includes(pos)) return null;
            return self.getFromFile(pos);
        }

        pub fn getData(self: *const Self, pos: u64) ?E {
            if (!pmmr.isLeaf(pos)) return null;
            if (self.prunable and !self.leaf_set.includes(pos)) return null;
            return self.getDataFromFile(pos);
        }

        pub fn rewind(self: *Self, position: u64, rewind_rm_pos: ?*const Bitmap) pmmr.Error!void {
            if (self.prunable) self.leaf_set.rewind(position, rewind_rm_pos);
            const shift = self.prune_list.getShift(position);
            self.hash_file.rewind(position - shift);
            const flatfile_pos = pmmr.nLeaves(position);
            const leaf_shift = self.prune_list.getLeafShift(position);
            self.data_file.rewind(flatfile_pos - leaf_shift);
        }

        pub fn remove(self: *Self, pos: u64) pmmr.Error!void {
            std.debug.assert(self.prunable);
            self.leaf_set.remove(pos);
        }

        // ---- leaf iteration (prunable PMMRs)

        /// Positions of unspent leaves, ascending.
        pub fn leafPosIter(self: *const Self) @import("bitmap.zig").Bitmap.Iterator {
            std.debug.assert(self.prunable);
            return self.leaf_set.iterator();
        }

        // ---- sizes

        pub fn unprunedSize(self: *const Self) u64 {
            return self.hashSize() + self.prune_list.getTotalShift();
        }
        pub fn dataSize(self: *const Self) u64 {
            return self.data_file.sizeInElmts();
        }
        pub fn hashSize(self: *const Self) u64 {
            return self.hash_file.sizeInElmts();
        }

        pub fn nUnprunedLeaves(self: *const Self) u64 {
            if (self.prunable) return self.leaf_set.len();
            return pmmr.nLeaves(self.unprunedSize());
        }

        // ---- persistence

        /// Makes everything appended so far durable.
        pub fn sync(self: *Self) !void {
            try self.hash_file.flush();
            try self.data_file.flush();
            if (self.prunable) try self.leaf_set.flush(self.io);
        }

        /// Turns the per-flush fsync on or off (off only while catching up in bulk).
        pub fn setFsync(self: *Self, on: bool) void {
            self.hash_file.setFsync(on);
            self.data_file.setFsync(on);
            self.leaf_set.fsync = on;
        }

        /// Makes everything written so far durable, whatever the fsync setting was.
        pub fn forceSync(self: *Self) !void {
            try self.hash_file.fsync();
            try self.data_file.fsync();
            if (self.prunable) {
                const was = self.leaf_set.fsync;
                self.leaf_set.fsync = true;
                defer self.leaf_set.fsync = was;
                try self.leaf_set.flush(self.io);
            }
        }

        /// Drops all changes since the last `sync`.
        pub fn discard(self: *Self) !void {
            self.hash_file.discard();
            self.data_file.discard();
            if (self.prunable) try self.leaf_set.discard();
        }

        pub fn snapshot(self: *Self, header_hash: Hash) !void {
            try self.leaf_set.snapshot(self.io, header_hash);
        }

        pub fn releaseFiles(self: *Self) void {
            self.data_file.release();
            self.hash_file.release();
        }

        // ---- compaction

        /// Removes fully-spent subtrees below `cutoff_pos` from the files.
        pub fn checkCompact(self: *Self, cutoff_pos: u64, rewind_rm_pos: *const Bitmap) !void {
            std.debug.assert(self.prunable);
            var leaves_removed = try self.leaf_set.removedPreCutoff(cutoff_pos, rewind_rm_pos, &self.prune_list);
            defer leaves_removed.deinit();
            var pos_to_rm = try self.posToRm(&leaves_removed);
            defer pos_to_rm.deinit();

            const all = try pos_to_rm.toSlice(self.gpa);
            defer self.gpa.free(all);

            // hash file indexes (1-based positions minus the current shift, then 0-based)
            {
                const idx = try self.gpa.alloc(u64, all.len);
                defer self.gpa.free(idx);
                for (all, 0..) |p, i| idx[i] = p - self.prune_list.getShift(p) - 1;
                try self.hash_file.savePrune(idx);
            }
            // data file indexes for the leaves among them
            {
                var idx: std.ArrayList(u64) = .empty;
                defer idx.deinit(self.gpa);
                for (all) |p| {
                    if (!pmmr.isLeaf(p)) continue;
                    const flat = pmmr.nLeaves(p);
                    const shift = self.prune_list.getLeafShift(p);
                    try idx.append(self.gpa, flat - shift - 1);
                }
                try self.data_file.savePrune(idx.items);
            }
            var it = leaves_removed.iterator();
            while (it.next()) |p| self.prune_list.add(p);
            try self.prune_list.flush(self.io);
            try self.leaf_set.flush(self.io);
        }

        /// Expands removed leaves upward through fully-removed parents, then drops the roots.
        fn posToRm(self: *Self, leaves_removed: *const Bitmap) !Bitmap {
            var expanded = try Bitmap.init();
            defer expanded.deinit();
            var it = leaves_removed.iterator();
            while (it.next()) |x| {
                expanded.add(x);
                var current: u64 = x;
                while (true) {
                    const fam = pmmr.family(current);
                    const sibling_pruned = self.prune_list.isPrunedRoot(fam.sibling);
                    if (sibling_pruned) expanded.add(@truncate(fam.sibling));
                    if (sibling_pruned or expanded.contains(@truncate(fam.sibling))) {
                        expanded.add(@truncate(fam.parent));
                        current = fam.parent;
                    } else break;
                }
            }
            // removed_excl_roots: keep positions whose parent is also removed
            var out = try Bitmap.init();
            errdefer out.deinit();
            var it2 = expanded.iterator();
            while (it2.next()) |p| {
                const fam = pmmr.family(p);
                if (expanded.contains(@truncate(fam.parent))) out.add(p);
            }
            return out;
        }
    };
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

const TestElem = struct {
    v: [4]u32,
    pub fn write(self: TestElem, w: anytype) ser.Error!void {
        for (self.v) |x| try ser.writeU32(w, x);
    }
    pub fn read(r: *ser.Reader) ser.Error!TestElem {
        var out: TestElem = undefined;
        for (&out.v) |*x| x.* = try r.readU32();
        return out;
    }
    fn same(e: TestElem) TestElem {
        return e;
    }
};

const FileBackend = PMMRBackend(TestElem, TestElem, TestElem.same, 16);
const FilePMMR = pmmr.PMMR(TestElem, FileBackend);
const MemBackend = pmmr.VecBackend(TestElem, TestElem, TestElem.same);
const MemPMMR = pmmr.PMMR(TestElem, MemBackend);

fn te(x: u32) TestElem {
    return .{ .v = .{ 0, 0, 0, x } };
}

test "append, sync and reopen" {
    const io = testing.io;
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var root: Hash = undefined;
    {
        var be = try FileBackend.open(gpa, io, tmp.dir, true, ser.ProtocolVersion.localDb());
        defer be.close();
        var m = FilePMMR.init(be);
        var x: u32 = 1;
        while (x <= 9) : (x += 1) _ = try m.push(te(x));
        root = try m.root();
        try be.sync();
        try testing.expectEqual(@as(u64, 16), be.unprunedSize());
        try testing.expectEqual(@as(u64, 9), be.nUnprunedLeaves());
    }
    var be = try FileBackend.open(gpa, io, tmp.dir, true, ser.ProtocolVersion.localDb());
    defer be.close();
    var m = FilePMMR.at(be, be.unprunedSize());
    try testing.expect(root.eql(try m.root()));
    try testing.expectEqual(@as(u32, 5), m.getData(pmmr.insertionToPmmrIndex(5)).?.v[3]);
    try m.validate();
}

test "unsynced appends are discarded and rewinds are applied on sync" {
    const io = testing.io;
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var be = try FileBackend.open(gpa, io, tmp.dir, true, ser.ProtocolVersion.localDb());
    defer be.close();
    var m = FilePMMR.init(be);
    var x: u32 = 1;
    while (x <= 4) : (x += 1) _ = try m.push(te(x));
    try be.sync();
    const root7 = try m.root();

    _ = try m.push(te(5));
    try be.discard();
    m = FilePMMR.at(be, 7);
    try testing.expect(root7.eql(try m.root()));

    // rewind to 3 leaves (size 4), sync, push a different leaf
    try m.rewind(4, null);
    try be.sync();
    try testing.expectEqual(@as(u64, 4), be.unprunedSize());
    _ = try m.push(te(99));
    try be.sync();
    try testing.expectEqual(@as(u32, 99), m.getData(pmmr.insertionToPmmrIndex(4)).?.v[3]);
}

test "compaction preserves the root and every unspent element" {
    const io = testing.io;
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var be = try FileBackend.open(gpa, io, tmp.dir, true, ser.ProtocolVersion.localDb());
    defer be.close();
    var m = FilePMMR.init(be);

    var mem = MemBackend.init(gpa);
    defer mem.deinit();
    var mm = MemPMMR.init(&mem);

    const n: u32 = 200;
    var x: u32 = 1;
    while (x <= n) : (x += 1) {
        _ = try m.push(te(x));
        _ = try mm.push(te(x));
    }
    try be.sync();
    const orig = try m.root();

    // spend a random-ish subset of leaves, in the same way on both
    var prng = std.Random.DefaultPrng.init(7);
    const rnd = prng.random();
    var spent = std.AutoHashMapUnmanaged(u32, void).empty;
    defer spent.deinit(gpa);
    x = 1;
    while (x <= n) : (x += 1) {
        // spend contiguous runs so whole subtrees become removable
        if (x % 32 < 24 or rnd.boolean()) {
            const pos = pmmr.insertionToPmmrIndex(x);
            _ = try m.prune(pos);
            _ = try mm.prune(pos);
            try spent.put(gpa, x, {});
        }
    }
    try be.sync();
    try testing.expect(orig.eql(try m.root()));

    var rm = try Bitmap.init();
    defer rm.deinit();
    const hash_bytes_before = be.hash_file.size();
    try be.checkCompact(m.last_pos, &rm);
    try testing.expect(be.hash_file.size() < hash_bytes_before);

    // root unchanged; all unspent elements and their hashes intact
    m = FilePMMR.at(be, be.unprunedSize());
    try testing.expect(orig.eql(try m.root()));
    x = 1;
    while (x <= n) : (x += 1) {
        const pos = pmmr.insertionToPmmrIndex(x);
        if (spent.contains(x)) {
            try testing.expect(m.getData(pos) == null);
        } else {
            try testing.expectEqual(x, m.getData(pos).?.v[3]);
            try testing.expect(m.getHash(pos).?.eql(mm.getHash(pos).?));
        }
    }
    try m.validate();

    // it survives a reopen, and can keep growing consistently with the memory copy
    be.close();
    be = try FileBackend.open(gpa, io, tmp.dir, true, ser.ProtocolVersion.localDb());
    m = FilePMMR.at(be, be.unprunedSize());
    try testing.expect(orig.eql(try m.root()));
    x = n + 1;
    while (x <= n + 10) : (x += 1) {
        _ = try m.push(te(x));
        _ = try mm.push(te(x));
    }
    try testing.expect((try m.root()).eql(try mm.root()));
    try m.validate();
}

const KernelLike = struct {
    payload: []const u8,
    fn same(e: KernelLike) KernelLike {
        return e;
    }
    pub fn write(self: KernelLike, w: anytype) ser.Error!void {
        try ser.writeU8(w, @intCast(self.payload.len));
        try w.writeFixedBytes(self.payload);
    }
    var scratch: [255]u8 = undefined;
    pub fn read(r: *ser.Reader) ser.Error!KernelLike {
        const n = try r.readU8();
        const b = try r.readFixedBytes(n);
        @memcpy(scratch[0..n], b);
        return .{ .payload = scratch[0..n] };
    }
};

test "variable-size elements (kernel style) with a size file" {
    const io = testing.io;
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const VB = PMMRBackend(KernelLike, KernelLike, KernelLike.same, null);
    const VP = pmmr.PMMR(KernelLike, VB);
    const words = [_][]const u8{ "a", "bcd", "ef", "ghijk", "l", "mn" };
    {
        var be = try VB.open(gpa, io, tmp.dir, false, ser.ProtocolVersion.local());
        defer be.close();
        var m = VP.init(be);
        for (words) |w| _ = try m.push(.{ .payload = w });
        try be.sync();
    }
    // lose the size file: it is rebuilt from the data on open
    try tmp.dir.deleteFile(io, SIZE_FILE);
    var be = try VB.open(gpa, io, tmp.dir, false, ser.ProtocolVersion.local());
    defer be.close();
    var m = VP.at(be, be.unprunedSize());
    for (words, 1..) |w, i| {
        const got = m.getData(pmmr.insertionToPmmrIndex(i)).?;
        try testing.expectEqualStrings(w, got.payload);
    }
    try testing.expectEqual(@as(u64, 6), be.nUnprunedLeaves());
}
