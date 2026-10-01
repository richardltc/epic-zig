//! Smoke tests proving each vendored native library builds and links.
const std = @import("std");
const roaring = @cImport(@cInclude("roaring/roaring.h"));
const rx = @cImport(@cInclude("randomx.h"));
const rdb = @cImport(@cInclude("rocksdb/c.h"));

test "croaring bitmap" {
    const r = roaring.roaring_bitmap_create();
    defer roaring.roaring_bitmap_free(r);
    roaring.roaring_bitmap_add(r, 42);
    try std.testing.expect(roaring.roaring_bitmap_contains(r, 42));
    try std.testing.expect(!roaring.roaring_bitmap_contains(r, 43));
}

test "randomx zero input matches Rust wrapper vector" {
    const expected = [32]u8{
        58,  219, 87,  205, 58, 5,   219, 157, 210, 19, 148, 114, 219, 191, 100, 122,
        49,  51,  224, 67,  83, 184, 50,  73,  105, 255, 58, 230, 35,  20,  232, 244,
    };
    const flags = rx.randomx_get_flags();
    const cache = rx.randomx_alloc_cache(flags) orelse return error.CacheAlloc;
    defer rx.randomx_release_cache(cache);
    const seed = [_]u8{0} ** 32;
    rx.randomx_init_cache(cache, &seed, seed.len);
    const vm = rx.randomx_create_vm(flags, cache, null) orelse return error.VmCreate;
    defer rx.randomx_destroy_vm(vm);
    const input = [_]u8{0} ** 128;
    var out: [32]u8 = undefined;
    rx.randomx_calculate_hash(vm, &input, input.len, &out);
    try std.testing.expectEqualSlices(u8, &expected, &out);
}

test "rocksdb put/get" {
    const opts = rdb.rocksdb_options_create();
    defer rdb.rocksdb_options_destroy(opts);
    rdb.rocksdb_options_set_create_if_missing(opts, 1);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [256:0]u8 = undefined;
    _ = try std.fmt.bufPrintZ(&path_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    var err: [*c]u8 = null;
    const db = rdb.rocksdb_open(opts, &path_buf, &err) orelse return error.Open;
    defer rdb.rocksdb_close(db);
    try std.testing.expect(err == null);
    const wo = rdb.rocksdb_writeoptions_create();
    defer rdb.rocksdb_writeoptions_destroy(wo);
    rdb.rocksdb_put(db, wo, "k", 1, "value", 5, &err);
    try std.testing.expect(err == null);
    const ro = rdb.rocksdb_readoptions_create();
    defer rdb.rocksdb_readoptions_destroy(ro);
    var len: usize = 0;
    const v = rdb.rocksdb_get(db, ro, "k", 1, &len, &err);
    try std.testing.expect(err == null);
    defer rdb.rocksdb_free(v);
    try std.testing.expectEqualStrings("value", v[0..len]);
}
