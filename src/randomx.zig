//! RandomX hashing through the vendored C library, plus the seed-height
//! schedule from `core/src/pow/randomx.rs`.
//!
//! The reference runs in "light" mode (256 MiB cache, no dataset); hashes do
//! not depend on the JIT/AES flags, so we use the fastest flags the CPU offers.
const std = @import("std");

const rx = @cImport(@cInclude("randomx.h"));

pub const SEEDHASH_EPOCH_BLOCKS: u64 = 1000;
pub const SEEDHASH_EPOCH_LAG: u64 = 60;

pub fn epochStart(epoch_height: u64) u64 {
    return if (epoch_height == 0) 0 else epoch_height + SEEDHASH_EPOCH_LAG;
}

pub fn epochEnd(epoch_height: u64) u64 {
    return if (epoch_height == 0)
        SEEDHASH_EPOCH_BLOCKS + SEEDHASH_EPOCH_LAG
    else
        epoch_height + SEEDHASH_EPOCH_LAG + SEEDHASH_EPOCH_BLOCKS;
}

pub fn nextSeedHeight(height: u64) ?u64 {
    const next_height = height - (height % SEEDHASH_EPOCH_BLOCKS);
    if (height <= SEEDHASH_EPOCH_BLOCKS) return null;
    if ((height - 1) % SEEDHASH_EPOCH_BLOCKS <= SEEDHASH_EPOCH_LAG) return next_height;
    return null;
}

/// Height of the block whose hash seeds RandomX for blocks at `height`.
pub fn currentSeedHeight(height: u64) u64 {
    if (height <= SEEDHASH_EPOCH_LAG + SEEDHASH_EPOCH_BLOCKS) return 0;
    if (height % SEEDHASH_EPOCH_BLOCKS <= SEEDHASH_EPOCH_LAG) {
        return height - (height % SEEDHASH_EPOCH_BLOCKS) - SEEDHASH_EPOCH_BLOCKS;
    }
    return height - (height % SEEDHASH_EPOCH_BLOCKS);
}

/// A cache for one seed plus a pool of idle VMs (a VM is single-threaded).
const Entry = struct {
    seed: [32]u8,
    cache: *rx.randomx_cache,
    flags: rx.randomx_flags,
    mutex: std.Io.Mutex = .init,
    idle: std.ArrayList(*rx.randomx_vm) = .empty,
    refs: std.atomic.Value(u32) = std.atomic.Value(u32).init(1),
};

pub const Manager = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    mutex: std.Io.Mutex = .init,
    slots: [2]?*Entry = .{ null, null },
    next_evict: usize = 0,

    pub fn init(gpa: std.mem.Allocator, io: std.Io) Manager {
        return .{ .gpa = gpa, .io = io };
    }

    pub fn deinit(self: *Manager) void {
        for (&self.slots) |*s| if (s.*) |e| {
            self.destroy(e);
            s.* = null;
        };
    }

    fn destroy(self: *Manager, e: *Entry) void {
        for (e.idle.items) |vm| rx.randomx_destroy_vm(vm);
        e.idle.deinit(self.gpa);
        rx.randomx_release_cache(e.cache);
        self.gpa.destroy(e);
    }

    fn release(self: *Manager, e: *Entry) void {
        if (e.refs.fetchSub(1, .acq_rel) == 1) self.destroy(e);
    }

    fn acquire(self: *Manager, seed: [32]u8) !*Entry {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.slots) |s| if (s) |e| if (std.mem.eql(u8, &e.seed, &seed)) {
            _ = e.refs.fetchAdd(1, .monotonic);
            return e;
        };
        const flags = rx.randomx_get_flags();
        const cache = rx.randomx_alloc_cache(flags) orelse
            rx.randomx_alloc_cache(rx.RANDOMX_FLAG_DEFAULT) orelse return error.OutOfMemory;
        rx.randomx_init_cache(cache, &seed, seed.len);
        const e = try self.gpa.create(Entry);
        e.* = .{ .seed = seed, .cache = cache, .flags = flags };
        const idx: usize = if (self.slots[0] == null) 0 else if (self.slots[1] == null) 1 else blk: {
            const i = self.next_evict;
            self.next_evict = (i + 1) % 2;
            break :blk i;
        };
        if (self.slots[idx]) |old| self.release(old);
        self.slots[idx] = e;
        _ = e.refs.fetchAdd(1, .monotonic);
        return e;
    }

    fn takeVm(e: *Entry, io: std.Io) !*rx.randomx_vm {
        e.mutex.lockUncancelable(io);
        const pooled = e.idle.pop();
        e.mutex.unlock(io);
        if (pooled) |vm| return vm;
        return rx.randomx_create_vm(e.flags, e.cache, null) orelse
            rx.randomx_create_vm(rx.RANDOMX_FLAG_DEFAULT, e.cache, null) orelse
            error.OutOfMemory;
    }

    fn returnVm(self: *Manager, e: *Entry, vm: *rx.randomx_vm) void {
        e.mutex.lockUncancelable(self.io);
        defer e.mutex.unlock(self.io);
        e.idle.append(self.gpa, vm) catch rx.randomx_destroy_vm(vm);
    }

    /// RandomX hash of `data` under `seed`.
    pub fn hash(self: *Manager, seed: [32]u8, data: []const u8) ![32]u8 {
        const e = try self.acquire(seed);
        defer self.release(e);
        const vm = try takeVm(e, self.io);
        defer self.returnVm(e, vm);
        var out: [32]u8 = undefined;
        rx.randomx_calculate_hash(vm, data.ptr, data.len, &out);
        return out;
    }
};

test "seed height schedule" {
    try std.testing.expectEqual(@as(u64, 0), currentSeedHeight(0));
    try std.testing.expectEqual(@as(u64, 0), currentSeedHeight(1060));
    try std.testing.expectEqual(@as(u64, 1000), currentSeedHeight(2060)); // still inside the lag window
    try std.testing.expectEqual(@as(u64, 2000), currentSeedHeight(2061));
    try std.testing.expectEqual(@as(u64, 2000), currentSeedHeight(2999));
    try std.testing.expectEqual(@as(u64, 3000), currentSeedHeight(3061));
    try std.testing.expectEqual(@as(?u64, null), nextSeedHeight(1000));
    try std.testing.expectEqual(@as(?u64, 2000), nextSeedHeight(2001));
    try std.testing.expectEqual(@as(u64, 1060 + 0), epochEnd(0));
    try std.testing.expectEqual(@as(u64, 60 + 1000 + 1000), epochEnd(1000));
}

test "zero-input hash matches the Rust wrapper vector, and pool reuse is stable" {
    const gpa = std.testing.allocator;
    var mgr = Manager.init(gpa, std.testing.io);
    defer mgr.deinit();
    const expected = [32]u8{
        58,  219, 87,  205, 58, 5,   219, 157, 210, 19, 148, 114, 219, 191, 100, 122,
        49,  51,  224, 67,  83, 184, 50,  73,  105, 255, 58, 230, 35,  20,  232, 244,
    };
    const input = [_]u8{0} ** 128;
    const seed = [_]u8{0} ** 32;
    try std.testing.expectEqualSlices(u8, &expected, &try mgr.hash(seed, &input));
    try std.testing.expectEqualSlices(u8, &expected, &try mgr.hash(seed, &input));
    // a different seed gives a different hash
    const seed2 = [_]u8{1} ** 32;
    const other = try mgr.hash(seed2, &input);
    try std.testing.expect(!std.mem.eql(u8, &expected, &other));
}
