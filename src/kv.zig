//! Key-value store over RocksDB: the replacement for the reference node's
//! LMDB chain store. Values are serialized with `ser` at the store's protocol
//! version. Batches give read-your-writes, nest (child batches merge into the
//! parent on commit) and commit atomically.
const std = @import("std");
const Io = std.Io;
const ser = @import("ser.zig");

const rdb = @cImport(@cInclude("rocksdb/c.h"));

pub const Error = error{
    DbError,
    SerError,
    NotFound,
    OutOfMemory,
};

pub const Options = struct {
    /// Shared block cache, in MiB.
    block_cache_mb: usize = 256,
    write_buffer_mb: usize = 64,
    /// Bloom filter bits per key (point lookups dominate chain access).
    bloom_bits_per_key: f64 = 10,
    /// fsync the WAL on every commit. Off by default: the WAL still protects
    /// against process crashes; enable for OS-crash durability.
    sync_writes: bool = false,
    background_jobs: c_int = 4,
};

const log = std.log.scoped(.kv);

fn checkErr(err: [*c]u8) Error!void {
    if (err != null) {
        log.err("rocksdb: {s}", .{std.mem.span(err)});
        rdb.rocksdb_free(err);
        return error.DbError;
    }
}

pub const Store = struct {
    gpa: std.mem.Allocator,
    db: *rdb.rocksdb_t,
    opts: *rdb.rocksdb_options_t,
    table_opts: *rdb.rocksdb_block_based_table_options_t,
    cache: *rdb.rocksdb_cache_t,
    ropts: *rdb.rocksdb_readoptions_t,
    wopts: *rdb.rocksdb_writeoptions_t,
    version: ser.ProtocolVersion,

    pub fn open(gpa: std.mem.Allocator, io: Io, path: []const u8, options: Options, version: ser.ProtocolVersion) !*Store {
        try Io.Dir.cwd().createDirPath(io, path);
        const self = try gpa.create(Store);
        errdefer gpa.destroy(self);
        self.gpa = gpa;
        self.version = version;

        self.opts = rdb.rocksdb_options_create().?;
        rdb.rocksdb_options_set_create_if_missing(self.opts, 1);
        rdb.rocksdb_options_increase_parallelism(self.opts, options.background_jobs);
        rdb.rocksdb_options_set_max_background_jobs(self.opts, options.background_jobs);
        rdb.rocksdb_options_set_write_buffer_size(self.opts, options.write_buffer_mb << 20);

        self.table_opts = rdb.rocksdb_block_based_options_create().?;
        self.cache = rdb.rocksdb_cache_create_lru(options.block_cache_mb << 20).?;
        rdb.rocksdb_block_based_options_set_block_cache(self.table_opts, self.cache);
        rdb.rocksdb_block_based_options_set_filter_policy(self.table_opts, rdb.rocksdb_filterpolicy_create_bloom(options.bloom_bits_per_key));
        rdb.rocksdb_options_set_block_based_table_factory(self.opts, self.table_opts);

        self.ropts = rdb.rocksdb_readoptions_create().?;
        self.wopts = rdb.rocksdb_writeoptions_create().?;
        rdb.rocksdb_writeoptions_set_sync(self.wopts, @intFromBool(options.sync_writes));

        const path_z = try gpa.dupeZ(u8, path);
        defer gpa.free(path_z);
        var err: [*c]u8 = null;
        self.db = rdb.rocksdb_open(self.opts, path_z.ptr, &err) orelse {
            checkErr(err) catch {};
            return error.DbError;
        };
        try checkErr(err);
        return self;
    }

    fn setOption(self: *Store, key: [:0]const u8, value: [:0]const u8) Error!void {
        var err: [*c]u8 = null;
        const keys = [_][*c]const u8{key.ptr};
        const values = [_][*c]const u8{value.ptr};
        rdb.rocksdb_set_options(self.db, 1, &keys, &values, &err);
        try checkErr(err);
    }

    /// Bulk-load mode for a long stretch of writes (initial header sync): no
    /// background compaction and no write stalls while level-0 files pile up.
    /// `endBulkLoad` compacts once and restores the defaults.
    pub fn beginBulkLoad(self: *Store) Error!void {
        try self.setOption("level0_slowdown_writes_trigger", "4000");
        try self.setOption("level0_stop_writes_trigger", "8000");
        try self.setOption("disable_auto_compactions", "true");
    }

    pub fn endBulkLoad(self: *Store) Error!void {
        // one pass over everything, then normal operation
        rdb.rocksdb_compact_range(self.db, null, 0, null, 0);
        try self.setOption("disable_auto_compactions", "false");
        try self.setOption("level0_slowdown_writes_trigger", "20");
        try self.setOption("level0_stop_writes_trigger", "36");
    }

    /// Writes and fsyncs the write-ahead log (for a clean shutdown).
    pub fn flushWal(self: *Store) Error!void {
        var err: [*c]u8 = null;
        rdb.rocksdb_flush_wal(self.db, 1, &err);
        try checkErr(err);
    }

    pub fn close(self: *Store) void {
        rdb.rocksdb_close(self.db);
        rdb.rocksdb_readoptions_destroy(self.ropts);
        rdb.rocksdb_writeoptions_destroy(self.wopts);
        rdb.rocksdb_options_destroy(self.opts);
        rdb.rocksdb_block_based_options_destroy(self.table_opts);
        rdb.rocksdb_cache_destroy(self.cache);
        const gpa = self.gpa;
        gpa.destroy(self);
    }

    /// Value for `key` (copied; caller frees with `gpa`).
    pub fn get(self: *const Store, gpa: std.mem.Allocator, key: []const u8) Error!?[]u8 {
        var err: [*c]u8 = null;
        var len: usize = 0;
        const v = rdb.rocksdb_get(self.db, self.ropts, key.ptr, key.len, &len, &err);
        try checkErr(err);
        if (v == null) return null;
        defer rdb.rocksdb_free(v);
        return try gpa.dupe(u8, v[0..len]);
    }

    pub fn getSer(self: *const Store, comptime T: type, gpa: std.mem.Allocator, key: []const u8) Error!?T {
        const bytes = (try self.get(gpa, key)) orelse return null;
        defer gpa.free(bytes);
        return ser.deserialize(T, gpa, bytes, self.version) catch error.SerError;
    }

    pub fn exists(self: *const Store, key: []const u8) Error!bool {
        var err: [*c]u8 = null;
        var len: usize = 0;
        const v = rdb.rocksdb_get(self.db, self.ropts, key.ptr, key.len, &len, &err);
        try checkErr(err);
        if (v == null) return false;
        rdb.rocksdb_free(v);
        return true;
    }

    pub fn put(self: *Store, key: []const u8, value: []const u8) Error!void {
        var err: [*c]u8 = null;
        rdb.rocksdb_put(self.db, self.wopts, key.ptr, key.len, value.ptr, value.len, &err);
        try checkErr(err);
    }

    /// Iterates entries whose key starts with `prefix`, in key order.
    pub fn iterator(self: *const Store, prefix: []const u8) Iterator {
        const it = rdb.rocksdb_create_iterator(self.db, self.ropts).?;
        rdb.rocksdb_iter_seek(it, prefix.ptr, prefix.len);
        return .{ .it = it, .prefix = prefix, .store = self };
    }

    pub const Iterator = struct {
        it: *rdb.rocksdb_iterator_t,
        prefix: []const u8,
        store: *const Store,
        started: bool = false,

        pub const Entry = struct { key: []const u8, value: []const u8 };

        pub fn deinit(self: *Iterator) void {
            rdb.rocksdb_iter_destroy(self.it);
        }

        /// Slices are valid until the next call to `next`.
        pub fn next(self: *Iterator) ?Entry {
            if (self.started) rdb.rocksdb_iter_next(self.it);
            self.started = true;
            if (rdb.rocksdb_iter_valid(self.it) == 0) return null;
            var klen: usize = 0;
            const k = rdb.rocksdb_iter_key(self.it, &klen);
            const key = k[0..klen];
            if (self.prefix.len > 0 and !std.mem.startsWith(u8, key, self.prefix)) return null;
            var vlen: usize = 0;
            const v = rdb.rocksdb_iter_value(self.it, &vlen);
            return .{ .key = key, .value = v[0..vlen] };
        }
    };

    pub fn batch(self: *Store) Batch {
        return Batch.init(self, null);
    }
};

/// Pending writes over a store or a parent batch. Dropping without `commit`
/// aborts. Not thread-safe; use one per task.
pub const Batch = struct {
    store: *Store,
    parent: ?*Batch,
    arena: std.heap.ArenaAllocator,
    /// key -> value, or null for a pending delete
    ops: std.StringHashMapUnmanaged(?[]const u8) = .empty,
    /// Set once committed or dropped; makes `deinit` safe to call again.
    done: bool = false,

    fn init(store: *Store, parent: ?*Batch) Batch {
        return .{ .store = store, .parent = parent, .arena = std.heap.ArenaAllocator.init(store.gpa) };
    }

    pub fn deinit(self: *Batch) void {
        if (self.done) return;
        self.done = true;
        self.ops.deinit(self.store.gpa);
        self.arena.deinit();
    }

    pub fn put(self: *Batch, key: []const u8, value: []const u8) Error!void {
        const a = self.arena.allocator();
        const v = try a.dupe(u8, value);
        const gop = try self.ops.getOrPut(self.store.gpa, key);
        if (!gop.found_existing) gop.key_ptr.* = try a.dupe(u8, key);
        gop.value_ptr.* = v;
    }

    pub fn putSer(self: *Batch, key: []const u8, value: anytype) Error!void {
        return self.putSerWithVersion(key, value, self.store.version);
    }

    pub fn putSerWithVersion(self: *Batch, key: []const u8, value: anytype, version: ser.ProtocolVersion) Error!void {
        const bytes = ser.serVec(self.store.gpa, value, version) catch return error.SerError;
        defer self.store.gpa.free(bytes);
        try self.put(key, bytes);
    }

    pub fn delete(self: *Batch, key: []const u8) Error!void {
        const a = self.arena.allocator();
        const gop = try self.ops.getOrPut(self.store.gpa, key);
        if (!gop.found_existing) gop.key_ptr.* = try a.dupe(u8, key);
        gop.value_ptr.* = null;
    }

    /// Looks through pending writes here, then parents, then the store.
    pub fn get(self: *const Batch, gpa: std.mem.Allocator, key: []const u8) Error!?[]u8 {
        var b: ?*const Batch = self;
        while (b) |cur| : (b = cur.parent) {
            if (cur.ops.get(key)) |pending| {
                return if (pending) |v| try gpa.dupe(u8, v) else null;
            }
        }
        return self.store.get(gpa, key);
    }

    pub fn getSer(self: *const Batch, comptime T: type, gpa: std.mem.Allocator, key: []const u8) Error!?T {
        const bytes = (try self.get(gpa, key)) orelse return null;
        defer gpa.free(bytes);
        return ser.deserialize(T, gpa, bytes, self.store.version) catch error.SerError;
    }

    pub fn exists(self: *const Batch, key: []const u8) Error!bool {
        var b: ?*const Batch = self;
        while (b) |cur| : (b = cur.parent) {
            if (cur.ops.get(key)) |pending| return pending != null;
        }
        return self.store.exists(key);
    }

    /// A child batch: its writes merge into this one on `commit`.
    pub fn child(self: *Batch) Batch {
        return Batch.init(self.store, self);
    }

    /// Applies all pending writes atomically (root batch), or merges them into
    /// the parent (child batch). The batch is consumed either way.
    pub fn commit(self: *Batch) Error!void {
        defer self.deinit();
        if (self.parent) |p| {
            var it = self.ops.iterator();
            while (it.next()) |e| {
                if (e.value_ptr.*) |v| try p.put(e.key_ptr.*, v) else try p.delete(e.key_ptr.*);
            }
            return;
        }
        const wb = rdb.rocksdb_writebatch_create().?;
        defer rdb.rocksdb_writebatch_destroy(wb);
        var it = self.ops.iterator();
        while (it.next()) |e| {
            const k = e.key_ptr.*;
            if (e.value_ptr.*) |v| {
                rdb.rocksdb_writebatch_put(wb, k.ptr, k.len, v.ptr, v.len);
            } else {
                rdb.rocksdb_writebatch_delete(wb, k.ptr, k.len);
            }
        }
        var err: [*c]u8 = null;
        rdb.rocksdb_write(self.store.db, self.store.wopts, wb, &err);
        try checkErr(err);
    }
};

// ---- key helpers (`epic_store::to_key` and friends)

/// [prefix, ':', ...bytes]
pub fn toKey(gpa: std.mem.Allocator, prefix: u8, bytes: []const u8) ![]u8 {
    const out = try gpa.alloc(u8, bytes.len + 2);
    out[0] = prefix;
    out[1] = ':';
    @memcpy(out[2..], bytes);
    return out;
}

/// [prefix, ':', big-endian u64]
pub fn u64ToKey(prefix: u8, val: u64) [10]u8 {
    var out: [10]u8 = undefined;
    out[0] = prefix;
    out[1] = ':';
    std.mem.writeInt(u64, out[2..10], val, .big);
    return out;
}

// ------------------------------------------------------------------ tests

const testing = std.testing;
const Hash = @import("hash.zig").Hash;

fn openTest(gpa: std.mem.Allocator, sub: []const u8) !*Store {
    var buf: [256]u8 = undefined;
    const path = try std.fmt.bufPrint(&buf, ".zig-cache/kvtest/{s}", .{sub});
    Io.Dir.cwd().deleteTree(testing.io, path) catch {};
    return Store.open(gpa, testing.io, path, .{ .block_cache_mb = 8, .write_buffer_mb = 4 }, ser.ProtocolVersion.localDb());
}

test "put, get, exists, delete via batch" {
    const gpa = testing.allocator;
    var s = try openTest(gpa, "basic");
    defer s.close();

    try testing.expect((try s.get(gpa, "a")) == null);
    var b = s.batch();
    try b.put("a", "1");
    try b.put("b", "2");
    // read-your-writes, but not visible outside until commit
    const got = (try b.get(gpa, "a")).?;
    defer gpa.free(got);
    try testing.expectEqualStrings("1", got);
    try testing.expect(!(try s.exists("a")));
    try b.commit();
    try testing.expect(try s.exists("a"));

    var b2 = s.batch();
    try b2.delete("a");
    try testing.expect(!(try b2.exists("a")));
    try testing.expect(try s.exists("a"));
    try b2.commit();
    try testing.expect(!(try s.exists("a")));
    try testing.expect(try s.exists("b"));
}

test "aborted batch leaves no trace; child batches merge or abort" {
    const gpa = testing.allocator;
    var s = try openTest(gpa, "nested");
    defer s.close();
    {
        var b = s.batch();
        defer b.deinit();
        try b.put("x", "1");
    }
    try testing.expect(!(try s.exists("x")));

    var parent = s.batch();
    try parent.put("k1", "p");
    {
        var c = parent.child();
        try c.put("k2", "c");
        try c.delete("k1");
        // the child sees its own writes over the parent's
        try testing.expect(!(try c.exists("k1")));
        try testing.expect(try c.exists("k2"));
        c.deinit(); // abort
    }
    try testing.expect(try parent.exists("k1"));
    try testing.expect(!(try parent.exists("k2")));
    {
        var c = parent.child();
        try c.put("k2", "c");
        try c.delete("k1");
        try c.commit(); // merges into the parent
    }
    try testing.expect(!(try parent.exists("k1")));
    try testing.expect(try parent.exists("k2"));
    try parent.commit();
    try testing.expect(!(try s.exists("k1")));
    try testing.expect(try s.exists("k2"));
}

test "serialized values, prefix iteration and persistence" {
    const gpa = testing.allocator;
    var buf: [128]u8 = undefined;
    const path = try std.fmt.bufPrint(&buf, ".zig-cache/kvtest/persist", .{});
    Io.Dir.cwd().deleteTree(testing.io, path) catch {};
    {
        var s = try Store.open(gpa, testing.io, path, .{ .block_cache_mb = 8, .write_buffer_mb = 4 }, ser.ProtocolVersion.localDb());
        defer s.close();
        var b = s.batch();
        const h = Hash.fromVec(&.{ 1, 2, 3 });
        try b.putSer(&u64ToKey('h', 5), h);
        try b.putSer(&u64ToKey('h', 6), Hash.fromVec(&.{9}));
        try b.putSer(&u64ToKey('x', 1), @as(u64, 77));
        try b.commit();
    }
    var s = try Store.open(gpa, testing.io, path, .{ .block_cache_mb = 8, .write_buffer_mb = 4 }, ser.ProtocolVersion.localDb());
    defer s.close();
    const h = (try s.getSer(Hash, gpa, &u64ToKey('h', 5))).?;
    try testing.expect(h.eql(Hash.fromVec(&.{ 1, 2, 3 })));
    try testing.expectEqual(@as(u64, 77), (try s.getSer(u64, gpa, &u64ToKey('x', 1))).?);
    try testing.expect((try s.getSer(Hash, gpa, &u64ToKey('h', 99))) == null);

    var it = s.iterator("h:");
    defer it.deinit();
    var n: usize = 0;
    while (it.next()) |e| : (n += 1) {
        try testing.expectEqual(@as(usize, 10), e.key.len);
        try testing.expectEqual(@as(usize, 32), e.value.len);
    }
    try testing.expectEqual(@as(usize, 2), n);

    // wrong-size value surfaces as a serialization error
    var b = s.batch();
    try b.put("bad", "xy");
    try b.commit();
    try testing.expectError(error.SerError, s.getSer(Hash, gpa, "bad"));
}
