//! Prunable Merkle Mountain Range: position math, the PMMR itself, an
//! in-memory backend (for tests) and Merkle proofs. Port of
//! `core/src/core/pmmr/*` and `merkle_proof.rs`.
//!
//! Positions are 1-based, in insertion order of the flattened tree, exactly
//! as in the reference.
const std = @import("std");
const ser = @import("ser.zig");
const hash_mod = @import("hash.zig");
const Hash = hash_mod.Hash;

const ALL_ONES: u64 = std.math.maxInt(u64);

pub fn Fixed(comptime T: type, comptime N: usize) type {
    return struct {
        buf: [N]T = undefined,
        len: usize = 0,

        const Self = @This();

        pub fn push(self: *Self, v: T) void {
            self.buf[self.len] = v;
            self.len += 1;
        }
        pub fn items(self: *const Self) []const T {
            return self.buf[0..self.len];
        }
    };
}

pub const Positions = Fixed(u64, 65);
pub const Hashes = Fixed(Hash, 65);

// ------------------------------------------------------------ position math

/// Positions of the peaks of an MMR of `num` nodes; empty if `num` is not a valid size.
pub fn peaks(num: u64) Positions {
    var out: Positions = .{};
    if (num == 0) return out;
    var peak_size: u64 = ALL_ONES >> @intCast(@clz(num));
    var num_left = num;
    var sum_prev: u64 = 0;
    while (peak_size != 0) {
        if (num_left >= peak_size) {
            out.push(sum_prev + peak_size);
            sum_prev += peak_size;
            num_left -= peak_size;
        }
        peak_size >>= 1;
    }
    if (num_left > 0) return .{};
    return out;
}

/// Number of leaves in an MMR of `size` nodes (counting a trailing partial subtree).
pub fn nLeaves(size: u64) u64 {
    const r = peakSizesHeight(size);
    var n: u64 = 0;
    for (r.sizes.items()) |s| n += (s + 1) / 2;
    return if (r.height == 0) n else n + 1;
}

/// PMMR position of the `sz`-th inserted leaf (1-based).
pub fn insertionToPmmrIndex(sz_in: u64) u64 {
    if (sz_in == 0) return 0;
    const sz = sz_in - 1;
    return 2 * sz - @popCount(sz) + 1;
}

pub const PeakSizes = struct { sizes: Positions, height: u64 };

pub fn peakSizesHeight(size: u64) PeakSizes {
    var sizes: Positions = .{};
    if (size == 0) return .{ .sizes = sizes, .height = 0 };
    var peak_size: u64 = ALL_ONES >> @intCast(@clz(size));
    var left = size;
    while (peak_size != 0) {
        if (left >= peak_size) {
            sizes.push(peak_size);
            left -= peak_size;
        }
        peak_size >>= 1;
    }
    return .{ .sizes = sizes, .height = left };
}

pub const PeakMapHeight = struct { peak_map: u64, height: u64 };

pub fn peakMapHeight(pos_in: u64) PeakMapHeight {
    if (pos_in == 0) return .{ .peak_map = 0, .height = 0 };
    var pos = pos_in;
    var peak_size: u64 = ALL_ONES >> @intCast(@clz(pos));
    var bitmap: u64 = 0;
    while (peak_size != 0) {
        bitmap <<= 1;
        if (pos >= peak_size) {
            pos -= peak_size;
            bitmap |= 1;
        }
        peak_size >>= 1;
    }
    return .{ .peak_map = bitmap, .height = pos };
}

/// Height of the node at 1-based `num` (0 for leaves).
pub fn bintreePostorderHeight(num: u64) u64 {
    if (num == 0) return 0;
    return peakMapHeight(num - 1).height;
}

pub fn isLeaf(pos: u64) bool {
    return bintreePostorderHeight(pos) == 0;
}

pub const Family = struct { parent: u64, sibling: u64 };

pub fn family(pos: u64) Family {
    const ph = peakMapHeight(pos - 1);
    const peak = @as(u64, 1) << @intCast(ph.height);
    if (ph.peak_map & peak != 0) return .{ .parent = pos + 1, .sibling = pos + 1 - 2 * peak };
    return .{ .parent = pos + 2 * peak, .sibling = pos + 2 * peak - 1 };
}

pub fn isLeftSibling(pos: u64) bool {
    const ph = peakMapHeight(pos - 1);
    const peak = @as(u64, 1) << @intCast(ph.height);
    return ph.peak_map & peak == 0;
}

/// Path of positions from `pos` up to the peak within an MMR of `last_pos`.
pub fn path(pos: u64, last_pos: u64) Positions {
    const ph = peakMapHeight(pos - 1);
    var peak: u64 = @as(u64, 1) << @intCast(ph.height);
    var out: Positions = .{};
    var current = pos;
    while (current <= last_pos) {
        out.push(current);
        current += if (ph.peak_map & peak != 0) 1 else 2 * peak;
        peak <<= 1;
    }
    return out;
}

pub const BranchEntry = struct { parent: u64, sibling: u64 };
pub const Branch = Fixed(BranchEntry, 65);

/// (parent, sibling) pairs from `pos` up to the local peak.
pub fn familyBranch(pos: u64, last_pos: u64) Branch {
    const ph = peakMapHeight(pos - 1);
    var peak: u64 = @as(u64, 1) << @intCast(ph.height);
    var branch: Branch = .{};
    var current = pos;
    while (current < last_pos) {
        var sibling: u64 = undefined;
        if (ph.peak_map & peak != 0) {
            current += 1;
            sibling = current - 2 * peak;
        } else {
            current += 2 * peak;
            sibling = current - 1;
        }
        if (current > last_pos) break;
        branch.push(.{ .parent = current, .sibling = sibling });
        peak <<= 1;
    }
    return branch;
}

pub fn bintreeRightmost(num: u64) u64 {
    return num - bintreePostorderHeight(num);
}

pub fn bintreeLeftmost(num: u64) u64 {
    const height = bintreePostorderHeight(num);
    return num + 2 - (@as(u64, 2) << @intCast(height));
}

// ----------------------------------------------------------------- PMMR

pub const Error = error{
    OutOfMemory,
    BackendFailure,
    BadMmrSize,
    MissingLeftSibling,
    NotALeaf,
    NoElement,
    NoRoot,
    InvalidMmr,
};

/// The generic PMMR over a backend `B`. `B` must provide (see `VecBackend`):
///   `Elmt`: the element type stored/returned by `getData`;
///   `append(*B, elmt: T, hashes: []const Hash) Error!void`
///   `rewind(*B, position: u64, rewind_rm_pos: ?*const Bitmap) Error!void`
///   `getHash(*const B, pos) ?Hash`, `getFromFile(*const B, pos) ?Hash`
///   `getData(*const B, pos) ?Elmt`
///   `remove(*B, pos) Error!void`
pub fn PMMR(comptime T: type, comptime B: type) type {
    return struct {
        last_pos: u64,
        backend: *B,

        const Self = @This();
        pub const Elmt = B.Elmt;

        pub fn init(backend: *B) Self {
            return .{ .last_pos = 0, .backend = backend };
        }

        pub fn at(backend: *B, last_pos: u64) Self {
            return .{ .last_pos = last_pos, .backend = backend };
        }

        pub fn isEmpty(self: Self) bool {
            return self.last_pos == 0;
        }

        pub fn unprunedSize(self: Self) u64 {
            return self.last_pos;
        }

        fn getFromFile(self: Self, pos: u64) ?Hash {
            if (pos > self.last_pos) return null;
            return self.backend.getFromFile(pos);
        }

        pub fn getHash(self: Self, pos: u64) ?Hash {
            if (pos > self.last_pos) return null;
            if (isLeaf(pos)) return self.backend.getHash(pos);
            return self.backend.getFromFile(pos);
        }

        pub fn getData(self: Self, pos: u64) ?Elmt {
            if (pos > self.last_pos) return null;
            if (isLeaf(pos)) return self.backend.getData(pos);
            return null;
        }

        /// Hashes of the peaks that are available (missing ones are skipped).
        pub fn peakHashes(self: Self) Hashes {
            var out: Hashes = .{};
            for (peaks(self.last_pos).items()) |p| {
                if (self.backend.getFromFile(p)) |h| out.push(h);
            }
            return out;
        }

        /// Peaks bagged from the right, as `bag_the_rhs` in the reference.
        pub fn bagTheRhs(self: Self, peak_pos: u64) ?Hash {
            var rhs: Hashes = .{};
            for (peaks(self.last_pos).items()) |p| {
                if (p > peak_pos) if (self.backend.getFromFile(p)) |h| rhs.push(h);
            }
            var res: ?Hash = null;
            var i = rhs.len;
            while (i > 0) {
                i -= 1;
                const peak = rhs.buf[i];
                res = if (res) |rh| hash_mod.hashPairWithIndex(self.unprunedSize(), peak, rh) else peak;
            }
            return res;
        }

        pub fn root(self: Self) Error!Hash {
            if (self.isEmpty()) return Hash.zero;
            const ph = self.peakHashes();
            var res: ?Hash = null;
            var i = ph.len;
            while (i > 0) {
                i -= 1;
                const peak = ph.buf[i];
                res = if (res) |rh| hash_mod.hashPairWithIndex(self.unprunedSize(), peak, rh) else peak;
            }
            return res orelse error.NoRoot;
        }

        /// Appends `elmt`, returning its position.
        pub fn push(self: *Self, elmt: T) Error!u64 {
            const elmt_pos = self.last_pos + 1;
            var current_hash = hash_mod.hashWithIndex(elmt_pos - 1, elmt);
            var hashes: Hashes = .{};
            hashes.push(current_hash);
            var pos = elmt_pos;

            const ph = peakMapHeight(pos - 1);
            if (ph.height != 0) return error.BadMmrSize;
            var peak: u64 = 1;
            while (ph.peak_map & peak != 0) {
                const left_sibling = pos + 1 - 2 * peak;
                const left_hash = self.backend.getFromFile(left_sibling) orelse return error.MissingLeftSibling;
                peak *= 2;
                pos += 1;
                current_hash = hash_mod.hashPairWithIndex(pos - 1, left_hash, current_hash);
                hashes.push(current_hash);
            }
            try self.backend.append(elmt, hashes.items());
            self.last_pos = pos;
            return elmt_pos;
        }

        pub fn rewind(self: *Self, position: u64, rewind_rm_pos: ?*const @import("bitmap.zig").Bitmap) Error!void {
            var pos = position;
            while (bintreePostorderHeight(pos + 1) > 0) pos += 1;
            try self.backend.rewind(pos, rewind_rm_pos);
            self.last_pos = pos;
        }

        /// Marks a leaf as spent. Returns false if it was already gone.
        pub fn prune(self: *Self, position: u64) Error!bool {
            if (!isLeaf(position)) return error.NotALeaf;
            if (self.backend.getHash(position) == null) return false;
            try self.backend.remove(position);
            return true;
        }

        /// Checks every parent hash matches its children.
        pub fn validate(self: Self) Error!void {
            return self.validateRange(1, self.last_pos);
        }

        /// `validate` for positions `first..=last` (independent per node, so
        /// ranges can be checked in parallel).
        pub fn validateRange(self: Self, first: u64, last: u64) Error!void {
            var n: u64 = first;
            while (n <= last and n <= self.last_pos) : (n += 1) {
                const height = bintreePostorderHeight(n);
                if (height == 0) continue;
                const h = self.getHash(n) orelse continue;
                const left_pos = n - (@as(u64, 1) << @intCast(height));
                const right_pos = n - 1;
                const l = self.getFromFile(left_pos) orelse continue;
                const rr = self.getFromFile(right_pos) orelse continue;
                if (!hash_mod.hashPairWithIndex(n - 1, l, rr).eql(h)) return error.InvalidMmr;
            }
        }

        pub fn elementsFromPmmrIndex(self: Self, gpa: std.mem.Allocator, index_in: u64, max_count: u64, max_pmmr_pos: ?u64) Error!struct { u64, []Elmt } {
            var out: std.ArrayList(Elmt) = .empty;
            errdefer out.deinit(gpa);
            const last = max_pmmr_pos orelse self.last_pos;
            var idx = if (index_in == 0) 1 else index_in;
            while (out.items.len < max_count and idx <= last) : (idx += 1) {
                if (self.getData(idx)) |e| try out.append(gpa, e);
            }
            return .{ idx -| 1, try out.toOwnedSlice(gpa) };
        }

        pub fn merkleProof(self: Self, gpa: std.mem.Allocator, pos: u64) Error!MerkleProof {
            if (!isLeaf(pos)) return error.NotALeaf;
            _ = self.getHash(pos) orelse return error.NoElement;
            const mmr_size = self.unprunedSize();
            const fb = familyBranch(pos, self.last_pos);
            var path_list: std.ArrayList(Hash) = .empty;
            errdefer path_list.deinit(gpa);
            for (fb.items()) |e| {
                if (self.getFromFile(e.sibling)) |h| try path_list.append(gpa, h);
            }
            const peak_pos = if (fb.len > 0) fb.buf[fb.len - 1].parent else pos;

            // peak_path: bagged right-hand side first, then peaks to the left (nearest first)
            var extra: std.ArrayList(Hash) = .empty;
            defer extra.deinit(gpa);
            if (self.bagTheRhs(peak_pos)) |rhs| try extra.append(gpa, rhs);
            var left: Hashes = .{};
            for (peaks(self.last_pos).items()) |p| {
                if (p < peak_pos) if (self.backend.getFromFile(p)) |h| left.push(h);
            }
            // Rust builds [left..., rhs] then reverses: rhs first, then left peaks nearest-first.
            var i = left.len;
            while (i > 0) {
                i -= 1;
                try extra.append(gpa, left.buf[i]);
            }
            try path_list.appendSlice(gpa, extra.items);
            return .{ .mmr_size = mmr_size, .path = try path_list.toOwnedSlice(gpa) };
        }
    };
}

// ------------------------------------------------------------ merkle proof

pub const MerkleProof = struct {
    mmr_size: u64,
    path: []Hash,

    pub const empty: MerkleProof = .{ .mmr_size = 0, .path = &.{} };

    pub fn deinit(self: *MerkleProof, gpa: std.mem.Allocator) void {
        gpa.free(self.path);
        self.* = empty;
    }

    pub fn write(self: MerkleProof, w: anytype) ser.Error!void {
        try ser.writeU64(w, self.mmr_size);
        try ser.writeU64(w, self.path.len);
        for (self.path) |h| try h.write(w);
    }

    pub fn read(r: *ser.Reader) ser.Error!MerkleProof {
        const mmr_size = try r.readU64();
        const path_len = try r.readU64();
        // each hash takes 32 bytes; refuse lengths the input cannot hold
        if (path_len > r.remaining() / 32) return error.UnexpectedEof;
        const p = try r.gpa.alloc(Hash, @intCast(path_len));
        errdefer r.gpa.free(p);
        for (p) |*h| h.* = try Hash.read(r);
        return .{ .mmr_size = mmr_size, .path = p };
    }

    pub const VerifyError = error{RootMismatch};

    /// Verifies that `element` is at `node_pos` in an MMR with this `root`.
    pub fn verify(self: MerkleProof, root_hash: Hash, element: anytype, node_pos: u64) VerifyError!void {
        const peaks_pos = peaks(self.mmr_size);
        var node_hash = hash_mod.hashWithIndex(if (node_pos > self.mmr_size) self.mmr_size else node_pos - 1, element);
        var pos = node_pos;
        var i: usize = 0;
        while (i < self.path.len) : (i += 1) {
            const sibling = self.path[i];
            const fam = family(pos);
            var parent_hash: Hash = undefined;
            const ps = peaks_pos.items();
            const found = std.sort.binarySearch(u64, ps, pos, struct {
                fn order(ctx: u64, item: u64) std.math.Order {
                    return std.math.order(ctx, item);
                }
            }.order);
            const pair_first_sibling: bool = if (found) |x|
                x == ps.len - 1
            else if (fam.parent > self.mmr_size)
                true
            else
                isLeftSibling(fam.sibling);
            const left = if (pair_first_sibling) sibling else node_hash;
            const right = if (pair_first_sibling) node_hash else sibling;
            const parent_pos = fam.parent;
            const parent_idx = if (parent_pos > self.mmr_size) self.mmr_size else parent_pos - 1;
            parent_hash = hash_mod.hashPairWithIndex(parent_idx, left, right);
            node_hash = parent_hash;
            pos = parent_pos;
        }
        if (!node_hash.eql(root_hash)) return error.RootMismatch;
    }
};

// -------------------------------------------------------- in-memory backend

/// Simple backend keeping everything in memory (tests and offline tools).
pub fn VecBackend(comptime T: type, comptime E: type, comptime asElmt: fn (T) E) type {
    return struct {
        gpa: std.mem.Allocator,
        data: std.ArrayList(T) = .empty,
        hashes: std.ArrayList(Hash) = .empty,
        removed: std.AutoHashMapUnmanaged(u64, void) = .empty,

        const Self = @This();
        pub const Elmt = E;

        pub fn init(gpa: std.mem.Allocator) Self {
            return .{ .gpa = gpa };
        }
        pub fn deinit(self: *Self) void {
            self.data.deinit(self.gpa);
            self.hashes.deinit(self.gpa);
            self.removed.deinit(self.gpa);
        }

        pub fn append(self: *Self, elmt: T, hashes: []const Hash) Error!void {
            try self.data.append(self.gpa, elmt);
            try self.hashes.appendSlice(self.gpa, hashes);
        }
        pub fn getFromFile(self: *const Self, pos: u64) ?Hash {
            const idx = pos -| 1;
            if (idx >= self.hashes.items.len) return null;
            return self.hashes.items[@intCast(idx)];
        }
        pub fn getHash(self: *const Self, pos: u64) ?Hash {
            if (self.removed.contains(pos)) return null;
            return self.getFromFile(pos);
        }
        pub fn getData(self: *const Self, pos: u64) ?E {
            if (self.removed.contains(pos)) return null;
            const idx = nLeaves(pos) -| 1;
            if (idx >= self.data.items.len) return null;
            return asElmt(self.data.items[@intCast(idx)]);
        }
        pub fn remove(self: *Self, pos: u64) Error!void {
            try self.removed.put(self.gpa, pos, {});
        }
        pub fn rewind(self: *Self, position: u64, _: ?*const @import("bitmap.zig").Bitmap) Error!void {
            self.data.shrinkRetainingCapacity(@min(self.data.items.len, @as(usize, @intCast(nLeaves(position)))));
            self.hashes.shrinkRetainingCapacity(@min(self.hashes.items.len, @as(usize, @intCast(position))));
        }
    };
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

/// The reference's `TestElem`: four u32s.
const TestElem = struct {
    v: [4]u32,
    pub fn write(self: TestElem, w: anytype) ser.Error!void {
        for (self.v) |x| try ser.writeU32(w, x);
    }
    fn same(e: TestElem) TestElem {
        return e;
    }
};
const TestBackend = VecBackend(TestElem, TestElem, TestElem.same);
const TestPMMR = PMMR(TestElem, TestBackend);

fn eqPos(want: []const u64, got: Positions) !void {
    try testing.expectEqualSlices(u64, want, got.items());
}

test "peak map / sizes / heights" {
    const M = std.math.maxInt(u64);
    inline for (.{
        .{ 0, 0b0, 0 },  .{ 1, 0b1, 0 },  .{ 2, 0b1, 1 },  .{ 3, 0b10, 0 },
        .{ 4, 0b11, 0 }, .{ 5, 0b11, 1 }, .{ 6, 0b11, 2 }, .{ 7, 0b100, 0 },
    }) |t| {
        const r = peakMapHeight(t[0]);
        try testing.expectEqual(@as(u64, t[1]), r.peak_map);
        try testing.expectEqual(@as(u64, t[2]), r.height);
    }
    try testing.expectEqual(PeakMapHeight{ .peak_map = (M >> 1) + 1, .height = 0 }, peakMapHeight(M));
    try testing.expectEqual(PeakMapHeight{ .peak_map = M >> 1, .height = 63 }, peakMapHeight(M - 1));

    var r = peakSizesHeight(6);
    try eqPos(&.{ 3, 1 }, r.sizes);
    try testing.expectEqual(@as(u64, 2), r.height);
    r = peakSizesHeight(7);
    try eqPos(&.{7}, r.sizes);
    r = peakSizesHeight(M);
    try eqPos(&.{M}, r.sizes);

    const expected = "0 0 1 0 0 1 2 0 0 1 0 0 1 2 3 0 0 1 0 0 1 2 0 0 1 0 0 1 2 3 4 " ++
        "0 0 1 0 0 1 2 0 0 1 0 0 1 2 3 0 0 1 0 0 1 2 0 0 1 0 0 1 2 3 4 5 " ++
        "0 0 1 0 0 1 2 0 0 1 0 0 1 2 3 0 0 1 0 0 1 2 0 0 1 0 0 1 2 3 4 0 0 1 0 0";
    var it = std.mem.splitScalar(u8, expected, ' ');
    var count: u64 = 1;
    while (it.next()) |tok| : (count += 1) {
        try testing.expectEqual(try std.fmt.parseInt(u64, tok, 10), bintreePostorderHeight(count));
    }
}

test "leftmost, rightmost, n_leaves, insertion index" {
    const right = [_]u64{ 0, 1, 2, 2, 4, 5, 5, 5 };
    const left = [_]u64{ 0, 1, 2, 1, 4, 5, 4, 1 };
    for (right, 0..) |w, i| try testing.expectEqual(w, bintreeRightmost(i));
    for (left, 0..) |w, i| try testing.expectEqual(w, bintreeLeftmost(i));
    const nl = [_]u64{ 0, 1, 2, 2, 3, 4, 4, 4, 5, 6, 6 };
    for (nl, 0..) |w, i| try testing.expectEqual(w, nLeaves(i));
    const ins = [_]u64{ 0, 1, 2, 4, 5, 8, 9, 11, 12 };
    for (ins, 0..) |w, i| try testing.expectEqual(w, insertionToPmmrIndex(i));
}

test "families, paths, branches, peaks" {
    const f = [_][3]u64{ .{ 1, 3, 2 }, .{ 2, 3, 1 }, .{ 3, 7, 6 }, .{ 4, 6, 5 }, .{ 5, 6, 4 }, .{ 6, 7, 3 }, .{ 7, 15, 14 }, .{ 1000, 1001, 997 } };
    for (f) |t| {
        const r = family(t[0]);
        try testing.expectEqual(t[1], r.parent);
        try testing.expectEqual(t[2], r.sibling);
    }
    try eqPos(&.{1}, path(1, 1));
    try eqPos(&.{ 1, 3 }, path(1, 3));
    try eqPos(&.{ 2, 3 }, path(2, 3));
    try eqPos(&.{ 4, 6, 7, 15 }, path(4, 16));
    try testing.expect(isLeftSibling(1) and !isLeftSibling(2) and isLeftSibling(3));

    var b = familyBranch(1, 3);
    try testing.expectEqual(@as(usize, 1), b.len);
    try testing.expectEqual(BranchEntry{ .parent = 3, .sibling = 2 }, b.buf[0]);
    try testing.expectEqual(@as(usize, 0), familyBranch(3, 3).len);
    b = familyBranch(4, 7);
    try testing.expectEqual(@as(usize, 2), b.len);
    try testing.expectEqual(BranchEntry{ .parent = 6, .sibling = 5 }, b.buf[0]);
    try testing.expectEqual(BranchEntry{ .parent = 7, .sibling = 3 }, b.buf[1]);
    try testing.expectEqual(@as(usize, 0), familyBranch(4, 5).len);
    b = familyBranch(1, 1_049_000);
    try testing.expectEqual(@as(usize, 19), b.len);
    try testing.expectEqual(BranchEntry{ .parent = 1048575, .sibling = 1048574 }, b.buf[18]);

    try eqPos(&.{}, peaks(0));
    try eqPos(&.{1}, peaks(1));
    try eqPos(&.{}, peaks(2));
    try eqPos(&.{ 3, 4 }, peaks(4));
    try eqPos(&.{ 7, 10, 11 }, peaks(11));
    try eqPos(&.{ 31, 38, 41, 42 }, peaks(42));
    try eqPos(&.{
        524287, 786430, 917501, 983036, 1015803, 1032186, 1040377, 1044472, 1046519, 1047542,
        1048053, 1048308, 1048435, 1048498, 1048529, 1048544, 1048551, 1048554, 1048555,
    }, peaks(1048555));
}

fn te(a: u32, b: u32, c: u32, d: u32) TestElem {
    return .{ .v = .{ a, b, c, d } };
}

test "push and root match the reference construction" {
    const gpa = testing.allocator;
    const elems = [_]TestElem{
        te(0, 0, 0, 1), te(0, 0, 0, 2), te(0, 0, 0, 3), te(0, 0, 0, 4), te(0, 0, 0, 5),
        te(0, 0, 0, 6), te(0, 0, 0, 7), te(0, 0, 0, 8), te(1, 0, 0, 0),
    };
    var ba = TestBackend.init(gpa);
    defer ba.deinit();
    var m = TestPMMR.init(&ba);
    const H = hash_mod.hashWithIndex;
    const P = hash_mod.hashPairWithIndex;

    _ = try m.push(elems[0]);
    const pos_0 = H(0, elems[0]);
    try testing.expect((try m.root()).eql(pos_0));
    try testing.expectEqual(@as(u64, 1), m.unprunedSize());

    _ = try m.push(elems[1]);
    const pos_1 = H(1, elems[1]);
    const pos_2 = P(2, pos_0, pos_1);
    try testing.expect((try m.root()).eql(pos_2));

    _ = try m.push(elems[2]);
    const pos_3 = H(3, elems[2]);
    try testing.expect((try m.root()).eql(P(4, pos_2, pos_3)));
    try testing.expectEqual(@as(usize, 2), m.peakHashes().len);

    _ = try m.push(elems[3]);
    const pos_4 = H(4, elems[3]);
    const pos_5 = P(5, pos_3, pos_4);
    const pos_6 = P(6, pos_2, pos_5);
    try testing.expect((try m.root()).eql(pos_6));
    try testing.expectEqual(@as(u64, 7), m.unprunedSize());

    _ = try m.push(elems[4]);
    const pos_7 = H(7, elems[4]);
    try testing.expect((try m.root()).eql(P(8, pos_6, pos_7)));

    _ = try m.push(elems[5]);
    const pos_8 = H(8, elems[5]);
    const pos_9 = P(9, pos_7, pos_8);
    try testing.expect((try m.root()).eql(P(10, pos_6, pos_9)));

    _ = try m.push(elems[6]);
    const pos_10 = H(10, elems[6]);
    // root bags from the right: peak6 + (peak9 + peak10), all with the unpruned size 11
    try testing.expect((try m.root()).eql(P(11, pos_6, P(11, pos_9, pos_10))));

    _ = try m.push(elems[7]);
    const pos_11 = H(11, elems[7]);
    const pos_12 = P(12, pos_10, pos_11);
    const pos_13 = P(13, pos_9, pos_12);
    const pos_14 = P(14, pos_6, pos_13);
    try testing.expect((try m.root()).eql(pos_14));
    try testing.expectEqual(@as(u64, 15), m.unprunedSize());

    _ = try m.push(elems[8]);
    const pos_15 = H(15, elems[8]);
    try testing.expect((try m.root()).eql(P(16, pos_14, pos_15)));
    try m.validate();
}

test "prune leaves the root unchanged and only marks leaves" {
    const gpa = testing.allocator;
    var ba = TestBackend.init(gpa);
    defer ba.deinit();
    var m = TestPMMR.init(&ba);
    var x: u32 = 1;
    while (x <= 9) : (x += 1) _ = try m.push(te(0, 0, 0, x));
    const orig = try m.root();
    const sz = m.unprunedSize();
    try testing.expectEqual(@as(usize, 16), ba.hashes.items.len);

    var p = TestPMMR.at(&ba, sz);
    _ = try p.prune(16);
    try testing.expect(orig.eql(try p.root()));
    _ = try p.prune(2);
    _ = try p.prune(4);
    try testing.expectError(error.NotALeaf, p.prune(3));
    _ = try p.prune(5);
    _ = try p.prune(1);
    try testing.expectEqual(@as(u32, 5), ba.removed.count());
    for (1..16) |n| _ = p.prune(n) catch {};
    try testing.expectEqual(@as(u32, 9), ba.removed.count());
    try testing.expect(orig.eql(try p.root()));
    try testing.expectEqual(@as(usize, 16), ba.hashes.items.len);
}

test "elements from pmmr index" {
    const gpa = testing.allocator;
    var ba = TestBackend.init(gpa);
    defer ba.deinit();
    var m = TestPMMR.init(&ba);
    var x: u32 = 1;
    while (x <= 20) : (x += 1) _ = try m.push(te(0, 0, 0, x));

    var res = try m.elementsFromPmmrIndex(gpa, 1, 1000, null);
    try testing.expectEqual(@as(u64, 38), res[0]);
    try testing.expectEqual(@as(usize, 20), res[1].len);
    try testing.expectEqual(@as(u32, 1), res[1][0].v[3]);
    try testing.expectEqual(@as(u32, 20), res[1][19].v[3]);
    gpa.free(res[1]);

    res = try m.elementsFromPmmrIndex(gpa, 8, 1000, 34);
    try testing.expectEqual(@as(u64, 34), res[0]);
    try testing.expectEqual(@as(usize, 14), res[1].len);
    try testing.expectEqual(@as(u32, 5), res[1][0].v[3]);
    gpa.free(res[1]);

    res = try m.elementsFromPmmrIndex(gpa, 8, 7, 34);
    try testing.expectEqual(@as(u64, 19), res[0]);
    try testing.expectEqual(@as(usize, 7), res[1].len);
    gpa.free(res[1]);

    _ = try m.prune(insertionToPmmrIndex(5));
    _ = try m.prune(insertionToPmmrIndex(20));
    res = try m.elementsFromPmmrIndex(gpa, 8, 7, 34);
    try testing.expectEqual(@as(u64, 20), res[0]);
    try testing.expectEqual(@as(u32, 6), res[1][0].v[3]);
    try testing.expectEqual(@as(u32, 12), res[1][6].v[3]);
    gpa.free(res[1]);
}

test "merkle proofs verify for every leaf and reject wrong data" {
    const gpa = testing.allocator;
    var ba = TestBackend.init(gpa);
    defer ba.deinit();
    var m = TestPMMR.init(&ba);
    const n: u32 = 13;
    var x: u32 = 1;
    while (x <= n) : (x += 1) _ = try m.push(te(0, 0, 0, x));
    const root = try m.root();

    x = 1;
    while (x <= n) : (x += 1) {
        const pos = insertionToPmmrIndex(x);
        var proof = try m.merkleProof(gpa, pos);
        defer proof.deinit(gpa);
        try proof.verify(root, te(0, 0, 0, x), pos);
        try testing.expectError(error.RootMismatch, proof.verify(root, te(9, 9, 9, x), pos));

        // wire round-trip
        const bytes = try ser.serVec(gpa, proof, ser.ProtocolVersion.local());
        defer gpa.free(bytes);
        var r = ser.Reader.init(gpa, bytes, ser.ProtocolVersion.local());
        var back = try MerkleProof.read(&r);
        defer back.deinit(gpa);
        try back.verify(root, te(0, 0, 0, x), pos);
    }
    try testing.expectError(error.NotALeaf, m.merkleProof(gpa, 3));
}
