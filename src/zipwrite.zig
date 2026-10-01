//! A minimal zip writer (stored entries only, no zip64), enough to build the
//! txhashset archive. The reference writes the same thing with
//! `CompressionMethod::Stored`.
const std = @import("std");
const Io = std.Io;

pub const Entry = struct {
    /// The path inside the zip (forward slashes).
    name: []const u8,
    /// The file to read, relative to the directory passed to `createStored`.
    path: []const u8,
};

const CENTRAL_SIG: u32 = 0x02014b50;
const LOCAL_SIG: u32 = 0x04034b50;
const END_SIG: u32 = 0x06054b50;
/// 1980-01-01 00:00 in DOS time/date.
const DOS_TIME: u16 = 0;
const DOS_DATE: u16 = 0x0021;
const CHUNK = 1 << 20;

const Record = struct { name: []const u8, crc: u32, size: u32, offset: u32 };

fn put16(list: *std.ArrayList(u8), gpa: std.mem.Allocator, v: u16) !void {
    var b: [2]u8 = undefined;
    std.mem.writeInt(u16, &b, v, .little);
    try list.appendSlice(gpa, &b);
}
fn put32(list: *std.ArrayList(u8), gpa: std.mem.Allocator, v: u32) !void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .little);
    try list.appendSlice(gpa, &b);
}

/// Writes `entries` (files under `src_dir`) into `dst` as a zip. Files that
/// don't exist are skipped, like the reference. Returns the zip's length.
pub fn createStored(gpa: std.mem.Allocator, io: Io, dst: Io.File, src_dir: Io.Dir, entries: []const Entry) !u64 {
    const buf = try gpa.alloc(u8, CHUNK);
    defer gpa.free(buf);
    var records: std.ArrayList(Record) = .empty;
    defer records.deinit(gpa);
    var head: std.ArrayList(u8) = .empty;
    defer head.deinit(gpa);

    var pos: u64 = 0;
    for (entries) |e| {
        var f = src_dir.openFile(io, e.path, .{ .mode = .read_only }) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        defer f.close(io);
        const len = try f.length(io);
        if (len >= 0xFFFF_FFFF or pos >= 0xFFFF_FFFF) return error.ZipTooLarge;

        // pass 1: the checksum (the local header needs it up front)
        var crc = std.hash.Crc32.init();
        var off: u64 = 0;
        while (off < len) {
            const n: usize = @intCast(@min(len - off, buf.len));
            if ((try f.readPositionalAll(io, buf[0..n], off)) != n) return error.UnexpectedEndOfFile;
            crc.update(buf[0..n]);
            off += n;
        }

        head.clearRetainingCapacity();
        try put32(&head, gpa, LOCAL_SIG);
        try put16(&head, gpa, 20); // version needed
        try put16(&head, gpa, 0); // flags
        try put16(&head, gpa, 0); // method: stored
        try put16(&head, gpa, DOS_TIME);
        try put16(&head, gpa, DOS_DATE);
        try put32(&head, gpa, crc.final());
        try put32(&head, gpa, @intCast(len));
        try put32(&head, gpa, @intCast(len));
        try put16(&head, gpa, @intCast(e.name.len));
        try put16(&head, gpa, 0); // extra length
        try head.appendSlice(gpa, e.name);
        const local_offset: u32 = @intCast(pos);
        try dst.writePositionalAll(io, head.items, pos);
        pos += head.items.len;

        // pass 2: the data
        off = 0;
        while (off < len) {
            const n: usize = @intCast(@min(len - off, buf.len));
            if ((try f.readPositionalAll(io, buf[0..n], off)) != n) return error.UnexpectedEndOfFile;
            try dst.writePositionalAll(io, buf[0..n], pos);
            pos += n;
            off += n;
        }
        try records.append(gpa, .{ .name = e.name, .crc = crc.final(), .size = @intCast(len), .offset = local_offset });
    }

    // central directory
    const cd_start = pos;
    head.clearRetainingCapacity();
    for (records.items) |r| {
        try put32(&head, gpa, CENTRAL_SIG);
        try put16(&head, gpa, 20); // version made by
        try put16(&head, gpa, 20); // version needed
        try put16(&head, gpa, 0);
        try put16(&head, gpa, 0);
        try put16(&head, gpa, DOS_TIME);
        try put16(&head, gpa, DOS_DATE);
        try put32(&head, gpa, r.crc);
        try put32(&head, gpa, r.size);
        try put32(&head, gpa, r.size);
        try put16(&head, gpa, @intCast(r.name.len));
        try put16(&head, gpa, 0); // extra
        try put16(&head, gpa, 0); // comment
        try put16(&head, gpa, 0); // disk number
        try put16(&head, gpa, 0); // internal attrs
        try put32(&head, gpa, 0o100644 << 16); // external attrs (unix mode)
        try put32(&head, gpa, r.offset);
        try head.appendSlice(gpa, r.name);
    }
    const cd_len = head.items.len;
    try put32(&head, gpa, END_SIG);
    try put16(&head, gpa, 0);
    try put16(&head, gpa, 0);
    try put16(&head, gpa, @intCast(records.items.len));
    try put16(&head, gpa, @intCast(records.items.len));
    try put32(&head, gpa, @intCast(cd_len));
    try put32(&head, gpa, @intCast(cd_start));
    try put16(&head, gpa, 0);
    try dst.writePositionalAll(io, head.items, pos);
    pos += head.items.len;
    try dst.sync(io);
    return pos;
}

test "a stored zip extracts back to the same files" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "a");
    const big = try gpa.alloc(u8, 3 * CHUNK + 17);
    defer gpa.free(big);
    for (big, 0..) |*b, i| b.* = @truncate(i *% 2654435761 >> 7);
    try tmp.dir.writeFile(io, .{ .sub_path = "a/one.bin", .data = big });
    try tmp.dir.writeFile(io, .{ .sub_path = "two.bin", .data = "hello" });

    var zf = try tmp.dir.createFile(io, "out.zip", .{ .read = true });
    defer zf.close(io);
    const n = try createStored(gpa, io, zf, tmp.dir, &.{
        .{ .name = "a/one.bin", .path = "a/one.bin" },
        .{ .name = "missing.bin", .path = "missing.bin" },
        .{ .name = "two.bin", .path = "two.bin" },
    });
    try std.testing.expect(n > big.len);

    try tmp.dir.createDirPath(io, "x");
    var xd = try tmp.dir.openDir(io, "x", .{});
    defer xd.close(io);
    var rbuf: [4096]u8 = undefined;
    var fr = zf.reader(io, &rbuf);
    try std.zip.extract(xd, &fr, .{});
    const got = try tmp.dir.readFileAlloc(io, "x/a/one.bin", gpa, .unlimited);
    defer gpa.free(got);
    try std.testing.expectEqualSlices(u8, big, got);
    const got2 = try tmp.dir.readFileAlloc(io, "x/two.bin", gpa, .unlimited);
    defer gpa.free(got2);
    try std.testing.expectEqualStrings("hello", got2);
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(io, "x/missing.bin", .{}));
}
