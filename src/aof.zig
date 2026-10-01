//! Append-only element files with an in-memory write buffer, as used for the
//! PMMR hash and data files (`store/src/types.rs`). Elements are fixed-size, or
//! variable-size with a companion "size file" of (offset, size) entries.
//!
//! Positions here are 0-based element indexes (the PMMR layer adds 1-based
//! wrappers). Nothing is durable until `flush`; `discard` drops unflushed
//! appends and undoes a `rewind`.
const std = @import("std");
const Io = std.Io;
const ser = @import("ser.zig");
const fsutil = @import("fsutil.zig");

pub const SizeEntry = struct {
    offset: u64,
    size: u16,

    pub const LEN: u16 = 8 + 2;

    pub fn write(self: SizeEntry, w: anytype) ser.Error!void {
        try ser.writeU64(w, self.offset);
        try ser.writeU16(w, self.size);
    }
    pub fn read(r: *ser.Reader) ser.Error!SizeEntry {
        return .{ .offset = try r.readU64(), .size = try r.readU16() };
    }
};

/// Returns the encoded length of the element at the start of `data`, or null
/// if `data` doesn't start with a valid element. Used to rebuild size files.
pub const ElmtSizer = *const fn (data: []const u8, version: ser.ProtocolVersion) ?usize;

pub const SizeInfo = union(enum) {
    fixed: u16,
    /// The size file is a fixed-size (`SizeEntry.LEN`) file owned elsewhere.
    variable: *AppendOnlyFile,
};

pub const AppendOnlyFile = struct {
    gpa: std.mem.Allocator,
    io: Io,
    dir: Io.Dir,
    name: []const u8, // owned
    file: ?Io.File = null,
    size_info: SizeInfo,
    sizer: ?ElmtSizer,
    /// Protocol version the elements are encoded with (for the sizer).
    version: ser.ProtocolVersion = ser.ProtocolVersion.localDb(),
    buffer: std.ArrayList(u8) = .empty,
    /// Index of the first element not yet on disk (or the rewound end).
    buffer_start_pos: u64 = 0,
    /// Value of `buffer_start_pos` before a `rewind`, or 0 if not rewound.
    buffer_start_pos_bak: u64 = 0,
    /// Length of the file on disk.
    file_len: u64 = 0,
    sync_on_flush: bool = true,

    pub fn open(gpa: std.mem.Allocator, io: Io, dir: Io.Dir, name: []const u8, size_info: SizeInfo, sizer: ?ElmtSizer) !AppendOnlyFile {
        return openVersioned(gpa, io, dir, name, size_info, sizer, ser.ProtocolVersion.localDb());
    }

    pub fn openVersioned(gpa: std.mem.Allocator, io: Io, dir: Io.Dir, name: []const u8, size_info: SizeInfo, sizer: ?ElmtSizer, version: ser.ProtocolVersion) !AppendOnlyFile {
        var aof: AppendOnlyFile = .{
            .version = version,
            .gpa = gpa,
            .io = io,
            .dir = dir,
            .name = try gpa.dupe(u8, name),
            .size_info = size_info,
            .sizer = sizer,
        };
        errdefer aof.deinit();
        try aof.init();
        // A variable-size file whose size file doesn't add up is rebuilt from the data.
        if (aof.size_info == .variable) {
            const expected = aof.file_len;
            if (try aof.size_info.variable.sumSizes() != expected) {
                try aof.rebuildSizeFile();
                try aof.init();
            }
        }
        return aof;
    }

    pub fn deinit(self: *AppendOnlyFile) void {
        self.release();
        self.buffer.deinit(self.gpa);
        self.gpa.free(self.name);
    }

    pub fn init(self: *AppendOnlyFile) !void {
        if (self.size_info == .variable) try self.size_info.variable.init();
        if (self.file) |f| f.close(self.io);
        self.file = try self.dir.createFile(self.io, self.name, .{ .read = true, .truncate = false });
        self.file_len = try self.file.?.length(self.io);
        if (self.file_len == 0) {
            self.buffer_start_pos = 0;
        } else {
            self.buffer_start_pos = self.sizeInElmts();
        }
    }

    pub fn release(self: *AppendOnlyFile) void {
        if (self.file) |f| f.close(self.io);
        self.file = null;
        if (self.size_info == .variable) self.size_info.variable.release();
    }

    /// Bytes on disk.
    pub fn size(self: *const AppendOnlyFile) u64 {
        return self.file_len;
    }

    pub fn sizeInElmts(self: *const AppendOnlyFile) u64 {
        return switch (self.size_info) {
            .fixed => |n| self.size() / n,
            .variable => |sf| sf.sizeInElmts(),
        };
    }

    pub fn sizeUnsyncInElmts(self: *const AppendOnlyFile) u64 {
        return switch (self.size_info) {
            .fixed => |n| self.buffer_start_pos + self.buffer.items.len / n,
            .variable => |sf| sf.sizeUnsyncInElmts(),
        };
    }

    /// Appends one element's bytes.
    pub fn append(self: *AppendOnlyFile, bytes: []const u8) !void {
        if (self.size_info == .variable) {
            const sf = self.size_info.variable;
            const next_pos = sf.sizeUnsyncInElmts();
            var offset: u64 = 0;
            if (next_pos != 0) {
                const prev = try sf.readSizeEntry(next_pos - 1);
                offset = prev.offset + prev.size;
            }
            var eb: [SizeEntry.LEN]u8 = undefined;
            std.mem.writeInt(u64, eb[0..8], offset, .big);
            std.mem.writeInt(u16, eb[8..10], @intCast(bytes.len), .big);
            try sf.append(&eb);
        }
        try self.buffer.appendSlice(self.gpa, bytes);
    }

    fn offsetAndSize(self: *const AppendOnlyFile, pos: u64) anyerror!struct { u64, u16 } {
        switch (self.size_info) {
            .fixed => |n| return .{ pos * n, n },
            .variable => |sf| {
                const e = try sf.readSizeEntry(pos);
                return .{ e.offset, e.size };
            },
        }
    }

    fn readSizeEntry(self: *const AppendOnlyFile, pos: u64) anyerror!SizeEntry {
        var scratch: [SizeEntry.LEN]u8 = undefined;
        const bytes = try self.read(pos, &scratch) orelse return error.UnexpectedEndOfFile;
        var r = ser.Reader.init(self.gpa, bytes, ser.ProtocolVersion.localDb());
        return SizeEntry.read(&r);
    }

    /// Reads the element at `pos` into `scratch` (or borrows it from the write
    /// buffer). Returns null if it doesn't exist or is short.
    pub fn read(self: *const AppendOnlyFile, pos: u64, scratch: []u8) anyerror!?[]const u8 {
        if (pos >= self.sizeUnsyncInElmts()) return null;
        const os = try self.offsetAndSize(pos);
        const offset, const length = os;
        if (pos < self.buffer_start_pos) {
            if (scratch.len < length) return error.ScratchTooSmall;
            const f = self.file orelse return null;
            if (offset + length > self.file_len) return null;
            const n = try f.readPositionalAll(self.io, scratch[0..length], offset);
            if (n != length) return null;
            return scratch[0..length];
        }
        const buffer_offset = (try self.offsetAndSize(self.buffer_start_pos))[0];
        const rel = offset -| buffer_offset;
        if (self.buffer.items.len < rel + length) return null;
        return self.buffer.items[@intCast(rel)..][0..length];
    }

    /// End offset (in bytes) of the first `count` elements.
    fn endOffset(self: *const AppendOnlyFile, count: u64) anyerror!u64 {
        if (count == 0) return 0;
        const os = try self.offsetAndSize(count - 1);
        return os[0] + os[1];
    }

    /// Truncates the logical end to `pos` elements. Rewinding into the
    /// unflushed buffer just shortens it; rewinding into flushed data is
    /// applied to the file on `flush` (and undone by `discard`).
    pub fn rewind(self: *AppendOnlyFile, pos: u64) void {
        if (self.size_info == .variable) self.size_info.variable.rewind(pos);
        if (pos >= self.buffer_start_pos) {
            const base = self.endOffset(self.buffer_start_pos) catch 0;
            const target = self.endOffset(pos) catch base;
            const keep: usize = @intCast(@min(@as(u64, self.buffer.items.len), target -| base));
            self.buffer.shrinkRetainingCapacity(keep);
            return;
        }
        if (self.buffer_start_pos_bak == 0) self.buffer_start_pos_bak = self.buffer_start_pos;
        self.buffer_start_pos = pos;
        self.buffer.clearRetainingCapacity();
    }

    /// Whether `flush` fsyncs (off during bulk catch-up).
    pub fn setFsync(self: *AppendOnlyFile, on: bool) void {
        self.sync_on_flush = on;
        if (self.size_info == .variable) self.size_info.variable.sync_on_flush = on;
    }

    /// Fsyncs what is already on disk (after a stretch with `setFsync(false)`).
    pub fn fsync(self: *AppendOnlyFile) !void {
        if (self.size_info == .variable) try self.size_info.variable.fsync();
        if (self.file) |f| try f.sync(self.io);
    }

    pub fn flush(self: *AppendOnlyFile) !void {
        if (self.size_info == .variable) try self.size_info.variable.flush();

        if (self.buffer_start_pos_bak > 0) {
            // A rewind happened: truncate the file to the new logical end.
            if (self.file) |f| f.close(self.io);
            self.file = null;
            var f = try self.dir.createFile(self.io, self.name, .{ .read = true, .truncate = false });
            errdefer f.close(self.io);
            if (self.buffer_start_pos == 0) {
                try f.setLength(self.io, 0);
                self.file_len = 0;
            } else {
                const os = try self.offsetAndSize(self.buffer_start_pos - 1);
                try f.setLength(self.io, os[0] + os[1]);
                self.file_len = os[0] + os[1];
            }
            self.file = f;
            self.buffer_start_pos_bak = 0;
        } else if (self.file == null) {
            self.file = try self.dir.createFile(self.io, self.name, .{ .read = true, .truncate = false });
        }

        const f = self.file.?;
        if (self.buffer.items.len > 0) {
            try f.writePositionalAll(self.io, self.buffer.items, self.file_len);
            self.file_len += self.buffer.items.len;
        }
        if (self.sync_on_flush) try f.sync(self.io);
        self.buffer.clearRetainingCapacity();
        self.buffer_start_pos = self.sizeInElmts();
    }

    pub fn discard(self: *AppendOnlyFile) void {
        if (self.buffer_start_pos_bak > 0) {
            self.buffer_start_pos = self.buffer_start_pos_bak;
            self.buffer_start_pos_bak = 0;
        }
        if (self.size_info == .variable) self.size_info.variable.discard();
        self.buffer.clearRetainingCapacity();
    }

    /// Sum of all size entries (for a size file).
    fn sumSizes(self: *AppendOnlyFile) !u64 {
        var sum: u64 = 0;
        const n = self.buffer_start_pos;
        if (n == 0) return 0;
        const bytes = try self.gpa.alloc(u8, @intCast(n * SizeEntry.LEN));
        defer self.gpa.free(bytes);
        const f = self.file orelse return error.FileNotOpen;
        const got = try f.readPositionalAll(self.io, bytes, 0);
        if (got != bytes.len) return error.UnexpectedEndOfFile;
        var i: usize = 0;
        while (i < n) : (i += 1) sum += std.mem.readInt(u16, bytes[i * SizeEntry.LEN + 8 ..][0..2], .big);
        return sum;
    }

    // ---- prune / rebuild

    /// A buffered sequential reader over the file's persisted bytes.
    const StreamReader = struct {
        aof: *const AppendOnlyFile,
        buf: []u8,
        buf_off: u64 = 0,
        buf_len: usize = 0,

        fn get(self: *StreamReader, offset: u64, len: usize) !?[]const u8 {
            if (offset + len > self.aof.file_len) return null;
            if (offset >= self.buf_off and offset + len <= self.buf_off + self.buf_len) {
                return self.buf[@intCast(offset - self.buf_off)..][0..len];
            }
            const want = @min(self.buf.len, @as(usize, @intCast(self.aof.file_len - offset)));
            if (want < len) return null;
            const n = try self.aof.file.?.readPositionalAll(self.aof.io, self.buf[0..want], offset);
            self.buf_off = offset;
            self.buf_len = n;
            if (n < len) return null;
            return self.buf[0..len];
        }
    };

    const CHUNK = 1 << 20;

    /// Rewrites the file without the elements at the (ascending, 0-based) indexes
    /// in `prune_idx`, then reloads.
    pub fn savePrune(self: *AppendOnlyFile, prune_idx: []const u64) !void {
        const tmp_name = try tmpName(self.gpa, self.name);
        defer self.gpa.free(tmp_name);
        const total = self.sizeInElmts();

        {
            const scratch = try self.gpa.alloc(u8, CHUNK);
            defer self.gpa.free(scratch);
            var sr: StreamReader = .{ .aof = self, .buf = scratch };
            var tmp = try self.dir.createFile(self.io, tmp_name, .{});
            defer tmp.close(self.io);
            var out: std.ArrayList(u8) = .empty;
            defer out.deinit(self.gpa);
            var out_off: u64 = 0;
            var next_prune: usize = 0;
            var idx: u64 = 0;
            var read_off: u64 = 0;
            while (idx < total) : (idx += 1) {
                const os = try self.offsetAndSize(idx);
                _ = os;
                var len: usize = undefined;
                switch (self.size_info) {
                    .fixed => |n| len = n,
                    .variable => |sf| len = (try sf.readSizeEntry(idx)).size,
                }
                if (next_prune < prune_idx.len and prune_idx[next_prune] == idx) {
                    next_prune += 1;
                } else {
                    const elmt = (try sr.get(read_off, len)) orelse return error.UnexpectedEndOfFile;
                    try out.appendSlice(self.gpa, elmt);
                    if (out.items.len >= CHUNK) {
                        try tmp.writePositionalAll(self.io, out.items, out_off);
                        out_off += out.items.len;
                        out.clearRetainingCapacity();
                    }
                }
                read_off += len;
            }
            if (out.items.len > 0) try tmp.writePositionalAll(self.io, out.items, out_off);
            try tmp.sync(self.io);
        }

        try self.replaceWith(tmp_name);
        if (self.size_info == .variable) try self.rebuildSizeFile();
        try self.init();
    }

    fn replaceWith(self: *AppendOnlyFile, tmp_name: []const u8) !void {
        self.release();
        self.dir.deleteFile(self.io, self.name) catch |e| switch (e) {
            error.FileNotFound => {},
            else => return e,
        };
        try self.dir.rename(tmp_name, self.dir, self.name, self.io);
    }

    /// Recomputes the size file by parsing elements out of the data file.
    pub fn rebuildSizeFile(self: *AppendOnlyFile) !void {
        const sf = switch (self.size_info) {
            .variable => |s| s,
            .fixed => return,
        };
        const sizer = self.sizer orelse return error.NoSizer;
        const tmp_name = try tmpName(self.gpa, sf.name);
        defer self.gpa.free(tmp_name);

        // the data file handle may have been released; make sure it's open
        if (self.file == null) {
            self.file = try self.dir.createFile(self.io, self.name, .{ .read = true, .truncate = false });
            self.file_len = try self.file.?.length(self.io);
        }
        {
            const scratch = try self.gpa.alloc(u8, CHUNK);
            defer self.gpa.free(scratch);
            var sr: StreamReader = .{ .aof = self, .buf = scratch };
            var tmp = try self.dir.createFile(self.io, tmp_name, .{});
            defer tmp.close(self.io);
            var out: std.ArrayList(u8) = .empty;
            defer out.deinit(self.gpa);
            var offset: u64 = 0;
            while (offset < self.file_len) {
                // an element is at most u16::MAX bytes; a small window keeps reads sequential
                const avail: usize = @intCast(@min(@as(u64, std.math.maxInt(u16)), self.file_len - offset));
                const window = (try sr.get(offset, avail)) orelse break;
                const len = sizer(window, self.version) orelse break;
                if (len == 0 or len > std.math.maxInt(u16)) break;
                var eb: [SizeEntry.LEN]u8 = undefined;
                std.mem.writeInt(u64, eb[0..8], offset, .big);
                std.mem.writeInt(u16, eb[8..10], @intCast(len), .big);
                try out.appendSlice(self.gpa, &eb);
                offset += len;
            }
            if (out.items.len > 0) try tmp.writePositionalAll(self.io, out.items, 0);
            try tmp.sync(self.io);
        }
        try sf.replaceWith(tmp_name);
    }

    /// Copies the persisted file to `dest_name` in `dest_dir` (for txhashset snapshots).
    pub fn copyTo(self: *AppendOnlyFile, dest_dir: Io.Dir, dest_name: []const u8) !void {
        try self.dir.copyFile(self.name, dest_dir, dest_name, self.io, .{});
    }
};

/// "pmmr_data.bin" -> "pmmr_data.tmp" (Rust `with_extension("tmp")`).
fn tmpName(gpa: std.mem.Allocator, name: []const u8) ![]u8 {
    const stem = if (std.mem.lastIndexOfScalar(u8, name, '.')) |i| name[0..i] else name;
    return std.fmt.allocPrint(gpa, "{s}.tmp", .{stem});
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

fn u32Sizer(data: []const u8, _: ser.ProtocolVersion) ?usize {
    // test elements: 1 length byte + that many payload bytes
    if (data.len == 0) return null;
    const n = data[0];
    if (data.len < 1 + n) return null;
    return 1 + @as(usize, n);
}

test "fixed-size file: append, read through buffer, flush, rewind" {
    const io = testing.io;
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var f = try AppendOnlyFile.open(gpa, io, tmp.dir, "h.bin", .{ .fixed = 4 }, null);
    defer f.deinit();
    try f.append("aaaa");
    try f.append("bbbb");
    var s: [16]u8 = undefined;
    try testing.expectEqualStrings("bbbb", (try f.read(1, &s)).?);
    try testing.expect((try f.read(2, &s)) == null);
    try testing.expectEqual(@as(u64, 2), f.sizeUnsyncInElmts());
    try testing.expectEqual(@as(u64, 0), f.sizeInElmts());
    try f.flush();
    try testing.expectEqual(@as(u64, 2), f.sizeInElmts());
    try f.append("cccc");
    try f.flush();
    try testing.expectEqualStrings("aaaa", (try f.read(0, &s)).?);
    try testing.expectEqualStrings("cccc", (try f.read(2, &s)).?);

    // rewind to 2 elements, then discard: back to 3
    f.rewind(2);
    try testing.expect((try f.read(2, &s)) == null);
    f.discard();
    try testing.expectEqual(@as(u64, 3), f.sizeUnsyncInElmts());
    // rewind and flush truncates the file
    f.rewind(1);
    try f.flush();
    try testing.expectEqual(@as(u64, 4), f.size());
    try f.append("dddd");
    try f.flush();
    try testing.expectEqualStrings("dddd", (try f.read(1, &s)).?);
}

test "rewind inside the unflushed buffer keeps the earlier buffered elements" {
    const io = testing.io;
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var f = try AppendOnlyFile.open(gpa, io, tmp.dir, "h.bin", .{ .fixed = 2 }, null);
    defer f.deinit();
    try f.append("aa");
    try f.flush();
    for ([_][]const u8{ "bb", "cc", "dd" }) |e| try f.append(e);
    f.rewind(2); // keep aa (flushed) and bb (buffered)
    try testing.expectEqual(@as(u64, 2), f.sizeUnsyncInElmts());
    var s: [4]u8 = undefined;
    try testing.expectEqualStrings("bb", (try f.read(1, &s)).?);
    try testing.expect((try f.read(2, &s)) == null);
    try f.append("ee");
    try f.flush();
    try testing.expectEqualStrings("ee", (try f.read(2, &s)).?);
    try testing.expectEqual(@as(u64, 3), f.sizeInElmts());
}

test "fixed-size file: unflushed appends are dropped by discard" {
    const io = testing.io;
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var f = try AppendOnlyFile.open(gpa, io, tmp.dir, "h.bin", .{ .fixed = 2 }, null);
    defer f.deinit();
    try f.append("ab");
    try f.flush();
    try f.append("cd");
    f.discard();
    try testing.expectEqual(@as(u64, 1), f.sizeUnsyncInElmts());
}

test "fixed-size file: save_prune drops the given elements" {
    const io = testing.io;
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var f = try AppendOnlyFile.open(gpa, io, tmp.dir, "h.bin", .{ .fixed = 2 }, null);
    defer f.deinit();
    for ([_][]const u8{ "aa", "bb", "cc", "dd", "ee" }) |e| try f.append(e);
    try f.flush();
    try f.savePrune(&.{ 1, 3 });
    var s: [8]u8 = undefined;
    try testing.expectEqual(@as(u64, 3), f.sizeInElmts());
    try testing.expectEqualStrings("aa", (try f.read(0, &s)).?);
    try testing.expectEqualStrings("cc", (try f.read(1, &s)).?);
    try testing.expectEqualStrings("ee", (try f.read(2, &s)).?);
}

test "variable-size file with size file, prune, and size-file rebuild" {
    const io = testing.io;
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var sf = try gpa.create(AppendOnlyFile);
        defer gpa.destroy(sf);
        sf.* = try AppendOnlyFile.open(gpa, io, tmp.dir, "size.bin", .{ .fixed = SizeEntry.LEN }, null);
        defer sf.deinit();
        var f = try AppendOnlyFile.open(gpa, io, tmp.dir, "data.bin", .{ .variable = sf }, u32Sizer);
        defer f.deinit();
        try f.append("\x02ab");
        try f.append("\x03xyz");
        try f.append("\x01q");
        try f.flush();
        var s: [16]u8 = undefined;
        try testing.expectEqualStrings("\x03xyz", (try f.read(1, &s)).?);
        try f.savePrune(&.{1});
        try testing.expectEqual(@as(u64, 2), f.sizeInElmts());
        try testing.expectEqualStrings("\x01q", (try f.read(1, &s)).?);
    }
    // delete the size file: reopening must rebuild it from the data
    try tmp.dir.deleteFile(io, "size.bin");
    var sf = try gpa.create(AppendOnlyFile);
    defer gpa.destroy(sf);
    sf.* = try AppendOnlyFile.open(gpa, io, tmp.dir, "size.bin", .{ .fixed = SizeEntry.LEN }, null);
    defer sf.deinit();
    var f = try AppendOnlyFile.open(gpa, io, tmp.dir, "data.bin", .{ .variable = sf }, u32Sizer);
    defer f.deinit();
    try testing.expectEqual(@as(u64, 2), f.sizeInElmts());
    var s: [16]u8 = undefined;
    try testing.expectEqualStrings("\x02ab", (try f.read(0, &s)).?);
}
