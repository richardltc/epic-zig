//! Iterators over header history used by consensus (`chain/src/store.rs`:
//! `DifficultyIter`, and the bottle iterator for the feijoada scheduler).
//! Generic over a header store providing `get(hash) ?BlockHeader`.
const std = @import("std");
const consensus = @import("consensus.zig");
const block = @import("block.zig");
const hash_mod = @import("hash.zig");
const feijoada = @import("feijoada.zig");

const Hash = hash_mod.Hash;
const BlockHeader = block.BlockHeader;
const HeaderInfo = consensus.HeaderInfo;
const PoWType = @import("pow_types.zig").PoWType;

/// Walks back from `start` through headers *of the same PoW type as the
/// header at each step*, yielding `HeaderInfo` for difficulty calculation:
/// the block's own difficulty increment, its timespan to its immediate
/// predecessor (of any algorithm), and the secondary scaling in force.
pub fn DifficultyIter(comptime Store: type) type {
    return struct {
        store: *const Store,
        start: Hash,
        started: bool = false,
        prev_header: ?BlockHeader = null,

        const Self = @This();

        pub fn init(store: *const Store, start: Hash) Self {
            return .{ .store = store, .start = start };
        }

        pub fn next(self: *Self) ?HeaderInfo {
            const header = (if (!self.started) self.store.get(self.start) else self.prev_header) orelse return null;
            self.started = true;
            const pow_type = header.pow.proof.powType();

            var head = header;
            var prev_difficulty = header.pow.total_difficulty;
            var first = true;
            var prev_timespan: i64 = 60;
            var next_prev: ?BlockHeader = null;
            var scaling: u32 = undefined;
            while (true) {
                const prev = self.store.get(head.prev_hash);
                if (prev) |p| {
                    if (first) {
                        prev_difficulty = header.pow.total_difficulty.sub(p.pow.total_difficulty);
                        prev_timespan = header.timestamp -| p.timestamp;
                    }
                    first = false;
                    if (pow_type == p.pow.proof.powType()) {
                        next_prev = p;
                        scaling = head.pow.secondary_scaling;
                        break;
                    }
                    head = p;
                } else {
                    next_prev = null;
                    scaling = head.pow.secondary_scaling;
                    break;
                }
            }
            self.prev_header = next_prev;
            return .{
                .block_hash = header.hash(),
                .timestamp = @bitCast(header.timestamp),
                .difficulty = prev_difficulty,
                .secondary_scaling = scaling,
                .is_secondary = header.pow.isSecondary(),
                .prev_timespan = @bitCast(prev_timespan),
            };
        }

        /// Collects up to `n` entries (latest first) into `out`.
        pub fn take(self: *Self, out: []HeaderInfo) []HeaderInfo {
            var i: usize = 0;
            while (i < out.len) : (i += 1) {
                out[i] = self.next() orelse break;
            }
            return out[0..i];
        }
    };
}

/// Per-algorithm history of the chain tip, so the difficulty calculation does
/// not have to walk back through the chain looking for the last 61 headers of an
/// algorithm (for a rare algorithm that walk can cross millions of headers).
///
/// For each algorithm it holds the newest `K` `HeaderInfo` entries exactly as
/// `DifficultyIter` would yield them, newest first, valid for one specific tip.
/// Appending a header extends it in O(1); any other tip is rebuilt with the
/// slow iterator.
pub fn AlgoIndex(comptime Store: type) type {
    return struct {
        pub const K = consensus.MAX_DIFF_DATA;

        /// newest-first ring per algorithm
        infos: [4][K]HeaderInfo = undefined,
        len: [4]usize = .{ 0, 0, 0, 0 },
        /// Secondary scaling of the header right after each algorithm's newest
        /// entry (null while that entry is still the tip).
        succ_scaling: [4]?u32 = .{ null, null, null, null },
        /// The tip this index describes.
        tip: ?Hash = null,
        tip_header: ?BlockHeader = null,

        const Self = @This();

        pub fn invalidate(self: *Self) void {
            self.tip = null;
            self.tip_header = null;
        }

        fn pushFront(self: *Self, a: usize, info: HeaderInfo) void {
            const n = @min(self.len[a] + 1, K);
            var i = n - 1;
            while (i > 0) : (i -= 1) self.infos[a][i] = self.infos[a][i - 1];
            self.infos[a][0] = info;
            self.len[a] = n;
        }

        /// Rebuilds for the chain ending at `tip` using the slow iterator.
        pub fn build(self: *Self, store: *const Store, tip: BlockHeader) void {
            self.invalidate();
            self.len = .{ 0, 0, 0, 0 };
            self.succ_scaling = .{ null, null, null, null };
            for (PoWType.all) |algo| {
                const a = algo.idx();
                // newest header of this algorithm at or before the tip, and its successor
                var cur = tip;
                var after: ?BlockHeader = null;
                while (cur.pow.proof.powType() != algo) {
                    after = cur;
                    cur = store.get(cur.prev_hash) orelse break;
                }
                if (cur.pow.proof.powType() != algo) continue;
                self.succ_scaling[a] = if (after) |h| h.pow.secondary_scaling else null;
                var it = DifficultyIter(Store).init(store, cur.hash());
                var tmp: [K]HeaderInfo = undefined;
                const got = it.take(&tmp);
                // `got` is newest first
                for (got, 0..) |e, j| self.infos[a][j] = e;
                self.len[a] = got.len;
            }
            self.tip = tip.hash();
            self.tip_header = tip;
        }

        pub fn isAt(self: *const Self, tip: Hash) bool {
            return self.tip != null and self.tip.?.eql(tip);
        }

        /// Newest-first entries for the algorithm of the tip header (what
        /// `DifficultyIter(tip)` yields). Valid only when `isAt(tip)`.
        pub fn cursor(self: *const Self, out: []HeaderInfo) []HeaderInfo {
            const a = self.tip_header.?.pow.proof.powType().idx();
            const n = @min(self.len[a], out.len);
            @memcpy(out[0..n], self.infos[a][0..n]);
            return out[0..n];
        }

        /// Extends the index with `y`, which must directly follow the current tip.
        /// If any needed history is missing the index is invalidated instead.
        pub fn push(self: *Self, y: BlockHeader) void {
            const pt = self.tip_header orelse return;
            if (!y.prev_hash.eql(self.tip.?)) return self.invalidate();
            const ap = pt.pow.proof.powType().idx();
            if (self.len[ap] > 0 and self.infos[ap][0].block_hash.eql(pt.hash()) and self.succ_scaling[ap] == null)
                self.succ_scaling[ap] = y.pow.secondary_scaling;

            const a = y.pow.proof.powType().idx();
            if (self.len[a] == 0) return self.invalidate();
            const scaling = self.succ_scaling[a] orelse return self.invalidate();
            self.pushFront(a, .{
                .block_hash = y.hash(),
                .timestamp = @bitCast(y.timestamp),
                .difficulty = y.pow.total_difficulty.sub(pt.pow.total_difficulty),
                .secondary_scaling = scaling,
                .is_secondary = y.pow.isSecondary(),
                .prev_timespan = @bitCast(y.timestamp -| pt.timestamp),
            });
            self.succ_scaling[a] = null;
            self.tip = y.hash();
            self.tip_header = y;
        }
    };
}

/// The bottles (feijoada state) the next block under `policy` continues from
/// (`BottleIter` + `take(1)` in the reference): null means "start from the
/// default bottles".
///
/// This reproduces the reference exactly, including its quirk: to find the
/// previous header with the same policy it searches back at most 200 headers,
/// and if that search runs out the result is null even when `start` itself has
/// the same policy. So at the start of a new emission era (policy change) the
/// first two blocks restart from default bottles.
pub fn bottlesCursor(store: anytype, start: Hash, policy: u8) ?feijoada.Policy {
    const header = store.get(start) orelse return null;
    var head = header;
    var i: usize = 0;
    var prev_header: ?BlockHeader = null;
    while (true) {
        i += 1;
        if (i > 200) return null;
        const p = store.get(head.prev_hash) orelse {
            prev_header = null;
            break;
        };
        if (policy == p.policy) {
            prev_header = p;
            break;
        }
        head = p;
    }
    if (header.policy == policy) return header.bottles;
    if (prev_header) |p| return p.bottles;
    return null;
}

// ------------------------------------------------------------------ tests

const testing = std.testing;
const ser = @import("ser.zig");
const fsutil = @import("fsutil.zig");
const pow_types = @import("pow_types.zig");

/// A header store over a map, filled from real fixtures.
const MapStore = struct {
    map: std.AutoHashMapUnmanaged([32]u8, BlockHeader) = .empty,

    pub fn get(self: *const MapStore, h: Hash) ?BlockHeader {
        return self.map.get(h.bytes);
    }
};

/// Loads every `headers_*.bin` fixture; each is a list of contiguous headers.
fn loadWindows(gpa: std.mem.Allocator, io: std.Io) !std.ArrayList([]BlockHeader) {
    var dir = std.Io.Dir.cwd().openDir(io, "testdata", .{ .iterate = true }) catch return error.SkipZigTest;
    defer dir.close(io);
    var out: std.ArrayList([]BlockHeader) = .empty;
    errdefer out.deinit(gpa);
    var it = dir.iterate();
    while (try it.next(io)) |e| {
        if (!std.mem.startsWith(u8, e.name, "headers_") or !std.mem.endsWith(u8, e.name, ".bin")) continue;
        const bytes = try fsutil.readAll(gpa, io, dir, e.name);
        defer gpa.free(bytes);
        var r = ser.Reader.init(gpa, bytes, ser.ProtocolVersion.local());
        r.params = consensus.ChainType.mainnet.readParams();
        const hs = try @import("p2p_msg.zig").Headers.read(&r);
        try out.append(gpa, hs.headers);
    }
    if (out.items.len == 0) return error.SkipZigTest;
    return out;
}

test "real mainnet windows: difficulty adjustment reproduces every header's difficulty" {
    const gpa = testing.allocator;
    const io = testing.io;
    var windows = try loadWindows(gpa, io);
    defer {
        for (windows.items) |w| gpa.free(w);
        windows.deinit(gpa);
    }
    const chain: consensus.ChainType = .mainnet;

    var checked: usize = 0;
    var mismatched: usize = 0;
    for (windows.items) |w| {
        var store: MapStore = .{};
        defer store.map.deinit(gpa);
        for (w) |h| try store.map.put(gpa, h.hash().bytes, h);

        // headers deep enough in the window that same-algo history is fully inside it
        var i: usize = 130;
        while (i < w.len) : (i += 1) {
            const hdr = w[i];
            const prev = w[i - 1];
            if (hdr.height <= 1) continue;
            const prev_algo = prev.pow.proof.powType();

            var it = DifficultyIter(MapStore).init(&store, prev.hash());
            var buf: [consensus.MAX_DIFF_DATA]HeaderInfo = undefined;
            const cursor = it.take(&buf);
            // need a full window of same-algo history inside the fixture
            if (cursor.len < consensus.MAX_DIFF_DATA) continue;
            // (and that history must not run past the window start)
            var oldest_in_window = false;
            for (w[0..1]) |first| oldest_in_window = oldest_in_window or first.hash().eql(cursor[cursor.len - 1].block_hash);
            if (oldest_in_window) continue;

            const want = hdr.pow.total_difficulty.sub(prev.pow.total_difficulty);
            const info = consensus.nextDifficultyFor(chain, hdr.height, prev_algo, cursor);
            checked += 1;
            if (!info.difficulty.eql(want)) {
                mismatched += 1;
                if (mismatched <= 3) std.debug.print("difficulty mismatch at height {d}: want {any} got {any}\n", .{ hdr.height, want.num, info.difficulty.num });
            }
        }
    }
    std.debug.print("difficulty check: {d} real headers checked, {d} mismatches\n", .{ checked, mismatched });
    try testing.expect(checked > 0);
    try testing.expectEqual(@as(usize, 0), mismatched);
}

fn synth(policy: u8, n: u8, prev: ?BlockHeader) BlockHeader {
    var h = BlockHeader.default(.mainnet);
    h.policy = policy;
    h.pow.proof.cuckoo.nonces[0] = n;
    h.bottles = feijoada.Policy.init(0, 0, n, 0);
    if (prev) |p| h.prev_hash = p.hash();
    return h;
}

test "bottle cursor: steady state continues from the previous header; era start restarts" {
    const gpa = testing.allocator;
    var store: MapStore = .{};
    defer store.map.deinit(gpa);

    // 250 blocks of policy 0, then policy 1 begins
    var prev: ?BlockHeader = null;
    var n: u8 = 0;
    var list: std.ArrayList(BlockHeader) = .empty;
    defer list.deinit(gpa);
    var i: usize = 0;
    while (i < 250) : (i += 1) {
        n +%= 1;
        const h = synth(0, n, prev);
        try store.map.put(gpa, h.hash().bytes, h);
        try list.append(gpa, h);
        prev = h;
    }
    // steady state under policy 0: continues from prev's bottles
    const steady = bottlesCursor(&store, prev.?.hash(), 0).?;
    try testing.expect(steady.eql(prev.?.bottles));

    // first block of policy 1: no earlier policy-1 header within reach -> defaults
    try testing.expect(bottlesCursor(&store, prev.?.hash(), 1) == null);

    // add the first policy-1 block (bottles = fresh); the *second* block still gets defaults
    n +%= 1;
    const first = synth(1, n, prev);
    try store.map.put(gpa, first.hash().bytes, first);
    try testing.expect(bottlesCursor(&store, first.hash(), 1) == null);

    // the third block finds a policy-1 predecessor and continues normally
    n +%= 1;
    const second = synth(1, n, first);
    try store.map.put(gpa, second.hash().bytes, second);
    try testing.expect(bottlesCursor(&store, second.hash(), 1).?.eql(second.bottles));
}

test "real windows: the algorithm index yields exactly what the slow iterator yields" {
    const gpa = testing.allocator;
    const io = testing.io;
    var windows = try loadWindows(gpa, io);
    defer {
        for (windows.items) |w| gpa.free(w);
        windows.deinit(gpa);
    }
    const Index = AlgoIndex(MapStore);
    var checked: usize = 0;
    var mismatches: usize = 0;
    for (windows.items) |w| {
        if (w.len < 260) continue;
        var store: MapStore = .{};
        defer store.map.deinit(gpa);
        for (w) |h| try store.map.put(gpa, h.hash().bytes, h);

        var idx: Index = .{};
        // start at a header deep enough that every algorithm present has history in the window
        var i: usize = 200;
        idx.build(&store, w[i]);
        while (i + 1 < w.len) : (i += 1) {
            // compare with the slow iterator for the current tip
            if (!idx.isAt(w[i].hash())) idx.build(&store, w[i]);
            var slow_it = DifficultyIter(MapStore).init(&store, w[i].hash());
            var a: [Index.K]HeaderInfo = undefined;
            var b: [Index.K]HeaderInfo = undefined;
            const slow = slow_it.take(&a);
            const fast = idx.cursor(&b);
            checked += 1;
            var same = slow.len == fast.len;
            if (same) for (slow, fast) |x, y| {
                if (!x.block_hash.eql(y.block_hash) or x.timestamp != y.timestamp or !x.difficulty.eql(y.difficulty) or
                    x.secondary_scaling != y.secondary_scaling or x.is_secondary != y.is_secondary or x.prev_timespan != y.prev_timespan) same = false;
            };
            if (!same) mismatches += 1;
            idx.push(w[i + 1]); // extend incrementally to the next header
        }
    }
    std.debug.print("  index vs slow iterator: {d} tips compared, {d} mismatches\n", .{ checked, mismatches });
    try testing.expect(checked > 1000);
    try testing.expectEqual(@as(usize, 0), mismatches);
}
