//! ProgPoW (CPU, light-cache mode): a port of `progpow-rust/pp_light`, the
//! implementation the reference node uses to verify ProgPoW proofs.
const std = @import("std");
const builtin = @import("builtin");

comptime {
    // Nodes are hashed as raw bytes; the reference assumes a little-endian host.
    std.debug.assert(builtin.cpu.arch.endian() == .little);
}

const Keccak256 = std.crypto.hash.sha3.Keccak256;
const Keccak512 = std.crypto.hash.sha3.Keccak512;

// ---- ethash constants (shared.rs)
pub const DATASET_BYTES_INIT: u64 = 1 << 30;
pub const DATASET_BYTES_GROWTH: u64 = 1 << 23;
pub const CACHE_BYTES_INIT: u64 = 1 << 24;
pub const CACHE_BYTES_GROWTH: u64 = 1 << 17;
pub const ETHASH_EPOCH_LENGTH: u64 = 30000;
const ETHASH_CACHE_ROUNDS = 3;
const ETHASH_MIX_BYTES = 128;
const ETHASH_ACCESSES = 64;
const ETHASH_DATASET_PARENTS = 256;
const NODE_BYTES = 64;
const NODE_WORDS = 16;

// ---- progpow constants (progpow.rs)
const PROGPOW_CACHE_BYTES = 16 * 1024;
const PROGPOW_CACHE_WORDS = PROGPOW_CACHE_BYTES / 4;
const PROGPOW_CNT_CACHE = 12;
const PROGPOW_CNT_MATH = 20;
const PROGPOW_CNT_DAG = ETHASH_ACCESSES;
const PROGPOW_DAG_LOADS = 4;
const PROGPOW_MIX_BYTES = 2 * ETHASH_MIX_BYTES;
const PROGPOW_PERIOD_LENGTH = 50;
const PROGPOW_LANES = 16;
const PROGPOW_REGS = 32;

const FNV_PRIME: u32 = 0x01000193;
const FNV_HASH: u32 = 0x811c9dc5;

pub const Node = [NODE_WORDS]u32;
pub const CDag = [PROGPOW_CACHE_WORDS]u32;

fn nodeBytes(n: *Node) *[NODE_BYTES]u8 {
    return @ptrCast(n);
}
fn nodeBytesConst(n: *const Node) *const [NODE_BYTES]u8 {
    return @ptrCast(n);
}

pub fn epochOf(block_number: u64) u64 {
    return block_number / ETHASH_EPOCH_LENGTH;
}

fn isPrime(n: u64) bool {
    if (n < 2) return false;
    if (n < 4) return true;
    if (n % 2 == 0 or n % 3 == 0) return false;
    var i: u64 = 5;
    while (i * i <= n) : (i += 6) {
        if (n % i == 0 or n % (i + 2) == 0) return false;
    }
    return true;
}

pub fn getCacheSize(block_number: u64) usize {
    var sz: u64 = CACHE_BYTES_INIT + CACHE_BYTES_GROWTH * (block_number / ETHASH_EPOCH_LENGTH);
    sz -= NODE_BYTES;
    while (!isPrime(sz / NODE_BYTES)) sz -= 2 * NODE_BYTES;
    return @intCast(sz);
}

pub fn getDataSize(block_number: u64) usize {
    var sz: u64 = DATASET_BYTES_INIT + DATASET_BYTES_GROWTH * (block_number / ETHASH_EPOCH_LENGTH);
    sz -= ETHASH_MIX_BYTES;
    while (!isPrime(sz / ETHASH_MIX_BYTES)) sz -= 2 * ETHASH_MIX_BYTES;
    return @intCast(sz);
}

/// Seed hash of an epoch: keccak-256 iterated `epoch` times from zero.
pub fn seedHash(epoch: u64) [32]u8 {
    var h = [_]u8{0} ** 32;
    var i: u64 = 0;
    while (i < epoch) : (i += 1) Keccak256.hash(&h, &h, .{});
    return h;
}

fn keccak512Node(dst: *Node, src: []const u8) void {
    Keccak512.hash(src, nodeBytes(dst), .{});
}

/// Builds the light cache for the epoch containing `block_number`.
pub fn buildCache(gpa: std.mem.Allocator, block_number: u64) ![]Node {
    const cache_size = getCacheSize(block_number);
    const num_nodes = cache_size / NODE_BYTES;
    const nodes = try gpa.alloc(Node, num_nodes);
    errdefer gpa.free(nodes);

    const ident = seedHash(epochOf(block_number));
    keccak512Node(&nodes[0], &ident);
    var i: usize = 1;
    while (i < num_nodes) : (i += 1) {
        const prev = nodes[i - 1];
        keccak512Node(&nodes[i], nodeBytesConst(&prev));
    }

    for (0..ETHASH_CACHE_ROUNDS) |_| {
        for (0..num_nodes) |k| {
            const data_idx = (num_nodes - 1 + k) % num_nodes;
            const idx = nodes[k][0] % num_nodes;
            var data = nodes[data_idx];
            const rhs = nodes[idx];
            for (0..NODE_WORDS) |w| data[w] ^= rhs[w];
            keccak512Node(&nodes[k], nodeBytesConst(&data));
        }
    }
    return nodes;
}

fn fnvHash(x: u32, y: u32) u32 {
    return (x *% FNV_PRIME) ^ y;
}

fn fnv1aHash(h: u32, d: u32) u32 {
    return (h ^ d) *% FNV_PRIME;
}

pub fn calculateDagItem(node_index: u32, cache: []const Node) Node {
    const n = cache.len;
    var ret = cache[node_index % n];
    ret[0] ^= node_index;
    var tmp = ret;
    keccak512Node(&ret, nodeBytesConst(&tmp));

    var i: u32 = 0;
    while (i < ETHASH_DATASET_PARENTS) : (i += 1) {
        const parent_index = fnvHash(node_index ^ i, ret[i % NODE_WORDS]) % @as(u32, @intCast(n));
        const parent = &cache[parent_index];
        for (0..NODE_WORDS) |w| ret[w] = fnvHash(ret[w], parent[w]);
    }
    tmp = ret;
    keccak512Node(&ret, nodeBytesConst(&tmp));
    return ret;
}

pub fn generateCdag(cache: []const Node) CDag {
    var c_dag: CDag = undefined;
    for (0..PROGPOW_CACHE_WORDS / 16) |i| {
        const node = calculateDagItem(@intCast(i), cache);
        @memcpy(c_dag[i * 16 ..][0..16], &node);
    }
    return c_dag;
}

// ---- keccak-f[800]

const KECCAKF_RNDC = [24]u32{
    0x00000001, 0x00008082, 0x0000808a, 0x80008000, 0x0000808b, 0x80000001, 0x80008081, 0x00008009,
    0x0000008a, 0x00000088, 0x80008009, 0x8000000a, 0x8000808b, 0x0000008b, 0x00008089, 0x00008003,
    0x00008002, 0x00000080, 0x0000800a, 0x8000000a, 0x80008081, 0x00008080, 0x80000001, 0x80008008,
};
const KECCAKF_ROTC = [24]u5{ 1, 3, 6, 10, 15, 21, 28, 4, 13, 23, 2, 14, 27, 9, 24, 8, 25, 11, 30, 18, 7, 29, 20, 12 };
const KECCAKF_PILN = [24]usize{ 10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1 };

fn keccakF800Round(st: *[25]u32, r: usize) void {
    var bc: [5]u32 = undefined;
    for (0..5) |i| bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
    for (0..5) |i| {
        const t = bc[(i + 4) % 5] ^ std.math.rotl(u32, bc[(i + 1) % 5], 1);
        var j: usize = 0;
        while (j < 25) : (j += 5) st[j + i] ^= t;
    }
    var t = st[1];
    for (0..24) |i| {
        const j = KECCAKF_PILN[i];
        bc[0] = st[j];
        st[j] = std.math.rotl(u32, t, @as(u32, KECCAKF_ROTC[i]));
        t = bc[0];
    }
    var j: usize = 0;
    while (j < 25) : (j += 5) {
        for (0..5) |i| bc[i] = st[j + i];
        for (0..5) |i| st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
    }
    st[0] ^= KECCAKF_RNDC[r];
}

fn keccakF800(header_hash: [32]u8, nonce: u64, result: [8]u32, st: *[25]u32) void {
    for (0..8) |i| st[i] = std.mem.readInt(u32, header_hash[4 * i ..][0..4], .little);
    st[8] = @truncate(nonce);
    st[9] = @truncate(nonce >> 32);
    for (0..8) |i| st[10 + i] = result[i];
    // (st[18..25] stay zero)
    for (0..22) |r| keccakF800Round(st, r);
}

fn keccakF800Short(header_hash: [32]u8, nonce: u64, result: [8]u32) u64 {
    var st = [_]u32{0} ** 25;
    keccakF800(header_hash, nonce, result, &st);
    return (@as(u64, @byteSwap(st[0])) << 32) | @as(u64, @byteSwap(st[1]));
}

fn keccakF800Long(header_hash: [32]u8, nonce: u64, result: [8]u32) [8]u32 {
    var st = [_]u32{0} ** 25;
    keccakF800(header_hash, nonce, result, &st);
    return st[0..8].*;
}

// ---- kiss99 and mixing

const Kiss99 = struct {
    z: u32,
    w: u32,
    jsr: u32,
    jcong: u32,

    fn next(self: *Kiss99) u32 {
        self.z = 36969 *% (self.z & 65535) +% (self.z >> 16);
        self.w = 18000 *% (self.w & 65535) +% (self.w >> 16);
        const mwc = (self.z << 16) +% self.w;
        self.jsr ^= self.jsr << 17;
        self.jsr ^= self.jsr >> 13;
        self.jsr ^= self.jsr << 5;
        self.jcong = 69069 *% self.jcong +% 1234567;
        return (mwc ^ self.jcong) +% self.jsr;
    }
};

fn fillMix(seed: u64, lane_id: u32) [PROGPOW_REGS]u32 {
    const z = fnv1aHash(FNV_HASH, @truncate(seed));
    const w = fnv1aHash(z, @truncate(seed >> 32));
    const jsr = fnv1aHash(w, lane_id);
    const jcong = fnv1aHash(jsr, lane_id);
    var rnd = Kiss99{ .z = z, .w = w, .jsr = jsr, .jcong = jcong };
    var mix: [PROGPOW_REGS]u32 = undefined;
    for (&mix) |*m| m.* = rnd.next();
    return mix;
}

fn merge(a: u32, b: u32, r: u32) u32 {
    return switch (r % 4) {
        0 => a *% 33 +% b,
        1 => (a ^ b) *% 33,
        2 => std.math.rotl(u32, a, ((r >> 16) % 31) + 1) ^ b,
        else => std.math.rotr(u32, a, ((r >> 16) % 31) + 1) ^ b,
    };
}

fn math(a: u32, b: u32, r: u32) u32 {
    return switch (r % 11) {
        0 => a +% b,
        1 => a *% b,
        2 => @truncate((@as(u64, a) *% @as(u64, b)) >> 32),
        3 => @min(a, b),
        4 => std.math.rotl(u32, a, b & 31),
        5 => std.math.rotr(u32, a, b & 31),
        6 => a & b,
        7 => a | b,
        8 => a ^ b,
        9 => @as(u32, @clz(a)) + @as(u32, @clz(b)),
        else => @as(u32, @popCount(a)) + @as(u32, @popCount(b)),
    };
}

const InitState = struct {
    rnd: Kiss99,
    dst: [PROGPOW_REGS]u32,
    cache: [PROGPOW_REGS]u32,
};

fn progpowInit(seed: u64) InitState {
    const z = fnv1aHash(FNV_HASH, @truncate(seed));
    const w = fnv1aHash(z, @truncate(seed >> 32));
    const jsr = fnv1aHash(w, @truncate(seed));
    const jcong = fnv1aHash(jsr, @truncate(seed >> 32));
    var rnd = Kiss99{ .z = z, .w = w, .jsr = jsr, .jcong = jcong };
    var dst: [PROGPOW_REGS]u32 = undefined;
    var cch: [PROGPOW_REGS]u32 = undefined;
    for (0..PROGPOW_REGS) |i| {
        dst[i] = @intCast(i);
        cch[i] = @intCast(i);
    }
    var i: usize = PROGPOW_REGS - 1;
    while (i >= 1) : (i -= 1) {
        var j = rnd.next() % (i + 1);
        std.mem.swap(u32, &dst[i], &dst[j]);
        j = rnd.next() % (i + 1);
        std.mem.swap(u32, &cch[i], &cch[j]);
    }
    return .{ .rnd = rnd, .dst = dst, .cache = cch };
}

fn progpowLoop(
    seed: u64,
    loop: usize,
    mix: *[PROGPOW_LANES][PROGPOW_REGS]u32,
    cache: []const Node,
    c_dag: *const CDag,
    data_size: usize,
) void {
    const g_offset: usize = mix[loop % PROGPOW_LANES][0] % (64 * data_size / (PROGPOW_LANES * PROGPOW_DAG_LOADS));

    var dag_item: [64]u32 = undefined;
    for (0..PROGPOW_DAG_LOADS) |l| {
        const index = g_offset * PROGPOW_LANES * PROGPOW_DAG_LOADS + l * 16;
        const node = calculateDagItem(@as(u32, @intCast(index)) / 16, cache);
        @memcpy(dag_item[l * 16 ..][0..16], &node);
    }

    const init = progpowInit(seed);

    for (0..PROGPOW_LANES) |l| {
        var rnd = init.rnd;
        var dst_cnt: usize = 0;
        var cache_cnt: usize = 0;

        for (0..@max(PROGPOW_CNT_CACHE, PROGPOW_CNT_MATH)) |i| {
            if (i < PROGPOW_CNT_CACHE) {
                const src = init.cache[cache_cnt % PROGPOW_REGS];
                cache_cnt += 1;
                const offset = mix[l][src] % PROGPOW_CACHE_WORDS;
                const data = c_dag[offset];
                const dst = init.dst[dst_cnt % PROGPOW_REGS];
                dst_cnt += 1;
                mix[l][dst] = merge(mix[l][dst], data, rnd.next());
            }
            if (i < PROGPOW_CNT_MATH) {
                const src_rnd = rnd.next() % (PROGPOW_REGS * (PROGPOW_REGS - 1));
                const src1 = src_rnd % PROGPOW_REGS;
                var src2 = src_rnd / PROGPOW_REGS;
                if (src2 >= src1) src2 += 1;
                const data = math(mix[l][src1], mix[l][src2], rnd.next());
                const dst = init.dst[dst_cnt % PROGPOW_REGS];
                dst_cnt += 1;
                mix[l][dst] = merge(mix[l][dst], data, rnd.next());
            }
        }

        var data_g: [PROGPOW_DAG_LOADS]u32 = undefined;
        const index = ((l ^ loop) % PROGPOW_LANES) * PROGPOW_DAG_LOADS;
        for (0..PROGPOW_DAG_LOADS) |i| data_g[i] = dag_item[index + i];

        mix[l][0] = merge(mix[l][0], data_g[0], rnd.next());
        for (1..PROGPOW_DAG_LOADS) |i| {
            const dst = init.dst[dst_cnt % PROGPOW_REGS];
            dst_cnt += 1;
            mix[l][dst] = merge(mix[l][dst], data_g[i], rnd.next());
        }
    }
}

pub const Result = struct {
    /// The final hash ("value") used for difficulty.
    digest: [8]u32,
    /// The mix digest carried in the header proof.
    mix: [8]u32,

    pub fn digestBytes(self: Result) [32]u8 {
        return std.mem.toBytes(self.digest);
    }
    pub fn mixBytes(self: Result) [32]u8 {
        return std.mem.toBytes(self.mix);
    }
};

pub fn progpow(header_hash: [32]u8, nonce: u64, block_number: u64, cache: []const Node, c_dag: *const CDag) Result {
    var mix: [PROGPOW_LANES][PROGPOW_REGS]u32 = undefined;
    var lane_results: [PROGPOW_LANES]u32 = undefined;
    var result = [_]u32{0} ** 8;

    const data_size = getDataSize(block_number) / PROGPOW_MIX_BYTES;
    std.debug.assert(data_size > 0);

    const seed = keccakF800Short(header_hash, nonce, result);
    for (0..PROGPOW_LANES) |l| mix[l] = fillMix(seed, @intCast(l));

    const period = block_number / PROGPOW_PERIOD_LENGTH;
    for (0..PROGPOW_CNT_DAG) |i| progpowLoop(period, i, &mix, cache, c_dag, data_size);

    for (0..PROGPOW_LANES) |l| {
        lane_results[l] = FNV_HASH;
        for (0..PROGPOW_REGS) |i| lane_results[l] = fnv1aHash(lane_results[l], mix[l][i]);
    }
    result = [_]u32{FNV_HASH} ** 8;
    for (0..PROGPOW_LANES) |l| result[l % 8] = fnv1aHash(result[l % 8], lane_results[l]);

    const digest = keccakF800Long(header_hash, seed, result);
    return .{ .digest = digest, .mix = result };
}

// ------------------------------------------------------- epoch cache

/// One epoch's light cache plus its 16 KiB "cdag".
pub const Light = struct {
    epoch: u64,
    nodes: []Node,
    cdag: CDag,
    refs: std.atomic.Value(u32) = std.atomic.Value(u32).init(1),

    fn build(gpa: std.mem.Allocator, block_number: u64) !*Light {
        const nodes = try buildCache(gpa, block_number);
        errdefer gpa.free(nodes);
        const l = try gpa.create(Light);
        l.* = .{ .epoch = epochOf(block_number), .nodes = nodes, .cdag = generateCdag(nodes) };
        return l;
    }

    pub fn compute(self: *const Light, header_hash: [32]u8, height: u64, nonce: u64) Result {
        return progpow(header_hash, nonce, height, self.nodes, &self.cdag);
    }
};

/// Thread-safe holder of the most recently used epoch caches (two are kept so
/// verification across an epoch boundary doesn't thrash).
pub const Manager = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    mutex: std.Io.Mutex = .init,
    slots: [2]?*Light = .{ null, null },
    next_evict: usize = 0,

    pub fn init(gpa: std.mem.Allocator, io: std.Io) Manager {
        return .{ .gpa = gpa, .io = io };
    }

    pub fn deinit(self: *Manager) void {
        for (&self.slots) |*s| if (s.*) |l| {
            self.gpa.free(l.nodes);
            self.gpa.destroy(l);
            s.* = null;
        };
    }

    /// Computes `progpow` for `height`, building the epoch cache on demand.
    /// The cache stays valid for the call even if another thread evicts it.
    pub fn compute(self: *Manager, header_hash: [32]u8, height: u64, nonce: u64) !Result {
        const light = try self.acquire(height);
        defer self.release(light);
        return light.compute(header_hash, height, nonce);
    }

    fn acquire(self: *Manager, height: u64) !*Light {
        const epoch = epochOf(height);
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.slots) |s| if (s) |l| if (l.epoch == epoch) {
            _ = l.refs.fetchAdd(1, .monotonic);
            return l;
        };
        const fresh = try Light.build(self.gpa, height);
        const idx: usize = if (self.slots[0] == null) 0 else if (self.slots[1] == null) 1 else blk: {
            const i = self.next_evict;
            self.next_evict = (i + 1) % 2;
            break :blk i;
        };
        if (self.slots[idx]) |old| self.release(old);
        self.slots[idx] = fresh;
        _ = fresh.refs.fetchAdd(1, .monotonic); // one for the slot, one for the caller
        return fresh;
    }

    fn release(self: *Manager, l: *Light) void {
        if (l.refs.fetchSub(1, .acq_rel) == 1) {
            self.gpa.free(l.nodes);
            self.gpa.destroy(l);
        }
    }
};

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "cache and data sizes match the reference" {
    try testing.expectEqual(@as(usize, 16776896), getCacheSize(0));
    try testing.expectEqual(@as(usize, 16776896), getCacheSize(ETHASH_EPOCH_LENGTH - 1));
    try testing.expectEqual(@as(usize, 16907456), getCacheSize(ETHASH_EPOCH_LENGTH));
    try testing.expectEqual(@as(usize, 284950208), getCacheSize(2046 * ETHASH_EPOCH_LENGTH));
    try testing.expectEqual(@as(usize, 285081536), getCacheSize(2048 * ETHASH_EPOCH_LENGTH - 1));
    try testing.expectEqual(@as(usize, 1073739904), getDataSize(0));
    try testing.expectEqual(@as(usize, 1082130304), getDataSize(ETHASH_EPOCH_LENGTH));
    try testing.expectEqual(@as(usize, 18236833408), getDataSize(2046 * ETHASH_EPOCH_LENGTH));
}

test "seed hash" {
    try testing.expectEqual([_]u8{0} ** 32, seedHash(0));
    const want = [_]u8{
        241, 175, 44,  134, 39,  121, 245, 239, 228, 236, 43,  160, 195, 152, 46,  7,
        199, 5,   253, 147, 241, 206, 98,  43,  3,   104, 17,  40,  192, 79,  106, 162,
    };
    try testing.expectEqual(want, seedHash(epochOf(486382)));
}

test "merge, math and keccak-f800 primitives" {
    const merges = [_][3]u32{
        .{ 1000000, 101, 33000101 }, .{ 2000000, 102, 66003366 }, .{ 3000000, 103, 6000103 }, .{ 4000000, 104, 2000104 },
        .{ 1000000, 0, 33000000 },   .{ 2000000, 0, 66000000 },   .{ 3000000, 0, 6000000 },   .{ 4000000, 0, 2000000 },
    };
    for (merges, 0..) |t, i| try testing.expectEqual(t[2], merge(t[0], t[1], @intCast(i)));
    const maths = [_][3]u32{
        .{ 20, 22, 42 },   .{ 70000, 80000, 1305032704 }, .{ 70000, 80000, 1 }, .{ 1, 2, 1 },       .{ 3, 10000, 196608 },
        .{ 3, 0, 3 },      .{ 3, 6, 2 },                  .{ 3, 6, 7 },         .{ 3, 6, 5 },        .{ 0, 0xffffffff, 32 },
        .{ 3 << 13, 1 << 5, 3 },
    };
    for (maths, 0..) |t, i| try testing.expectEqual(t[2], math(t[0], t[1], @intCast(i)));

    try testing.expectEqual(@as(u64, 0x5dd431e5fbc604f4), keccakF800Short([_]u8{0} ** 32, 0, [_]u32{0} ** 8));
    const long = keccakF800Long([_]u8{0} ** 32, 0, [_]u32{0} ** 8);
    var hex: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&hex, "{x}", .{std.mem.asBytes(&long)});
    try testing.expectEqualStrings("5dd431e5fbc604f499bfa0232f45f8f142d0ff5178f539e5a7800bf0643697af", &hex);
}

test "cdag and hash for epoch 0" {
    const gpa = testing.allocator;
    const cache = try buildCache(gpa, 0);
    defer gpa.free(cache);
    const cdag = generateCdag(cache);
    const expected = [_]u32{
        690150178,  1181503948, 2248155602, 2118233073, 2193871115, 1791778428, 1067701239, 724807309,  530799275,  3480325829,
        3899029234, 1998124059, 2541974622, 1100859971, 1297211151, 3268320000, 2217813733, 2690422980, 3172863319, 2651064309,
    };
    try testing.expectEqualSlices(u32, &expected, cdag[0..20]);

    const r = progpow([_]u8{0} ** 32, 0, 0, cache, &cdag);
    var hex: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&hex, "{x}", .{&r.digestBytes()});
    try testing.expectEqualStrings("63155f732f2bf556967f906155b510c917e48e99685ead76ea83f4eca03ab12b", &hex);
    _ = try std.fmt.bufPrint(&hex, "{x}", .{&r.mixBytes()});
    try testing.expectEqualStrings("faeb1be51075b03a4ff44b335067951ead07a3b078539ace76fd56fc410557a3", &hex);
}

test "reference test vectors and the node's height-20 mix vector" {
    const gpa = testing.allocator;
    var mgr = Manager.init(gpa, std.testing.io);
    defer mgr.deinit();

    // node crate: header 0, height 20, nonce 10123012301
    const r20 = try mgr.compute([_]u8{0} ** 32, 20, 10123012301);
    try testing.expectEqualSlices(u32, &.{ 1067276040, 109748694, 1270962088, 3616890847, 2528371908, 2524623649, 1191460869, 2529877558 }, &r20.mix);

    const json = @embedFile("data/progpow_testvectors.json");
    const parsed = try std.json.parseFromSlice([]const std.json.Value, gpa, json, .{});
    defer parsed.deinit();
    for (parsed.value) |entry| {
        const a = entry.array.items;
        const height: u64 = @intCast(a[0].integer);
        var header: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&header, a[1].string);
        const nonce = try std.fmt.parseInt(u64, a[2].string, 16);
        var mix: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&mix, a[3].string);
        var fin: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&fin, a[4].string);
        const r = try mgr.compute(header, height, nonce);
        try testing.expectEqualSlices(u8, &fin, &r.digestBytes());
        try testing.expectEqualSlices(u8, &mix, &r.mixBytes());
    }
}
