//! Small filesystem helpers over `std.Io.Dir` (cross-platform).
const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;

pub fn exists(io: Io, dir: Dir, name: []const u8) bool {
    _ = dir.statFile(io, name, .{}) catch return false;
    return true;
}

/// Reads a whole file. Caller frees.
pub fn readAll(gpa: std.mem.Allocator, io: Io, dir: Dir, name: []const u8) ![]u8 {
    var f = try dir.openFile(io, name, .{ .mode = .read_only });
    defer f.close(io);
    const len: usize = @intCast(try f.length(io));
    const buf = try gpa.alloc(u8, len);
    errdefer gpa.free(buf);
    const n = try f.readPositionalAll(io, buf, 0);
    if (n != len) return error.UnexpectedEndOfFile;
    return buf;
}

/// Writes `bytes` to `name`.tmp, removes any existing `name`, renames into place
/// (`save_via_temp_file` in the reference).
pub fn saveViaTempFile(gpa: std.mem.Allocator, io: Io, dir: Dir, name: []const u8, bytes: []const u8) !void {
    return saveViaTempFileOpt(gpa, io, dir, name, bytes, true);
}

/// `saveViaTempFile`, optionally without the fsync (for bulk catch-up; see `Chain.beginCatchup`).
pub fn saveViaTempFileOpt(gpa: std.mem.Allocator, io: Io, dir: Dir, name: []const u8, bytes: []const u8, do_sync: bool) !void {
    const tmp = try std.fmt.allocPrint(gpa, "{s}.tmp", .{name});
    defer gpa.free(tmp);
    dir.deleteFile(io, tmp) catch |e| switch (e) {
        error.FileNotFound => {},
        else => return e,
    };
    {
        var f = try dir.createFile(io, tmp, .{});
        defer f.close(io);
        try f.writePositionalAll(io, bytes, 0);
        if (do_sync) try f.sync(io);
    }
    dir.deleteFile(io, name) catch |e| switch (e) {
        error.FileNotFound => {},
        else => return e,
    };
    try dir.rename(tmp, dir, name, io);
}

pub fn fileSize(io: Io, dir: Dir, name: []const u8) !u64 {
    const st = try dir.statFile(io, name, .{});
    return st.size;
}

test "save via temp file replaces contents" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try std.testing.expect(!exists(io, tmp.dir, "a.bin"));
    try saveViaTempFile(gpa, io, tmp.dir, "a.bin", "hello");
    try saveViaTempFile(gpa, io, tmp.dir, "a.bin", "world!");
    const got = try readAll(gpa, io, tmp.dir, "a.bin");
    defer gpa.free(got);
    try std.testing.expectEqualStrings("world!", got);
    try std.testing.expect(!exists(io, tmp.dir, "a.bin.tmp"));
    try std.testing.expectEqual(@as(u64, 6), try fileSize(io, tmp.dir, "a.bin"));
}
