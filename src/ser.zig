//! Binary serialization layer, wire-compatible with `core/src/ser.rs`.
//!
//! All integers are big-endian. A `Writeable` type has
//! `pub fn write(self: T, w: anytype) ser.Error!void`; a `Readable` type has
//! `pub fn read(r: *ser.Reader) ser.Error!T`. Writers are duck-typed: they
//! provide `mode`, `version` and `writeFixedBytes`.
const std = @import("std");

pub const Error = error{
    /// Ran out of input (the Rust IOErr with kind UnexpectedEof).
    UnexpectedEof,
    UnexpectedData,
    CorruptedData,
    CountError,
    TooLargeRead,
    HexError,
    SortError,
    DuplicateError,
    InvalidBlockVersion,
    OutOfMemory,
};

/// p2p protocol version this node speaks (global::PROTOCOL_VERSION).
pub const PROTOCOL_VERSION: u32 = 2;

pub const ProtocolVersion = struct {
    v: u32,

    pub const MAX: u32 = std.math.maxInt(u32);

    pub fn local() ProtocolVersion {
        return .{ .v = PROTOCOL_VERSION };
    }

    /// Version used for the local database and MMR data files.
    pub fn localDb() ProtocolVersion {
        return .{ .v = 1 };
    }

    pub fn write(self: ProtocolVersion, w: anytype) Error!void {
        try writeU32(w, self.v);
    }

    pub fn read(r: *Reader) Error!ProtocolVersion {
        return .{ .v = try r.readU32() };
    }
};

pub const Mode = enum {
    /// Serialize everything sufficiently to fully reconstruct the object.
    full,
    /// Serialize only the data that defines the object (for hashing).
    hash,
};

// ---------------------------------------------------------------- writing

pub fn writeU8(w: anytype, n: u8) Error!void {
    try w.writeFixedBytes(&.{n});
}
pub fn writeU16(w: anytype, n: u16) Error!void {
    var b: [2]u8 = undefined;
    std.mem.writeInt(u16, &b, n, .big);
    try w.writeFixedBytes(&b);
}
pub fn writeU32(w: anytype, n: u32) Error!void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, n, .big);
    try w.writeFixedBytes(&b);
}
pub fn writeI32(w: anytype, n: i32) Error!void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(i32, &b, n, .big);
    try w.writeFixedBytes(&b);
}
pub fn writeU64(w: anytype, n: u64) Error!void {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, n, .big);
    try w.writeFixedBytes(&b);
}
pub fn writeI64(w: anytype, n: i64) Error!void {
    var b: [8]u8 = undefined;
    std.mem.writeInt(i64, &b, n, .big);
    try w.writeFixedBytes(&b);
}

/// Writes a u64 length prefix followed by the bytes.
pub fn writeBytes(w: anytype, bytes: []const u8) Error!void {
    try writeU64(w, bytes.len);
    try w.writeFixedBytes(bytes);
}

/// Generic write: integers, anything with a `write` method, and slices of
/// those (a slice is written element by element with no length prefix, like
/// Rust's `Vec<T>`).
pub fn write(w: anytype, value: anytype) Error!void {
    const T = @TypeOf(value);
    switch (@typeInfo(T)) {
        .int => |i| switch (i.bits) {
            8 => if (i.signedness == .unsigned) try writeU8(w, value) else @compileError("i8 unsupported"),
            16 => try writeU16(w, value),
            32 => if (i.signedness == .signed) try writeI32(w, value) else try writeU32(w, value),
            64 => if (i.signedness == .signed) try writeI64(w, value) else try writeU64(w, value),
            else => @compileError("unsupported int width"),
        },
        .comptime_int => @compileError("write a typed integer, not a comptime_int"),
        .pointer => |p| switch (p.size) {
            .slice => for (value) |item| try write(w, item),
            .one => try write(w, value.*),
            else => @compileError("unsupported pointer"),
        },
        .@"struct", .@"union", .@"enum" => try value.write(w),
        else => @compileError("type not serializable: " ++ @typeName(T)),
    }
}

/// Writer that accumulates the full serialization in memory.
pub const VecWriter = struct {
    list: std.ArrayList(u8) = .empty,
    gpa: std.mem.Allocator,
    version: ProtocolVersion = ProtocolVersion.local(),
    mode: Mode = .full,

    pub fn init(gpa: std.mem.Allocator, version: ProtocolVersion) VecWriter {
        return .{ .gpa = gpa, .version = version };
    }
    pub fn deinit(self: *VecWriter) void {
        self.list.deinit(self.gpa);
    }
    pub fn writeFixedBytes(self: *VecWriter, bytes: []const u8) Error!void {
        try self.list.appendSlice(self.gpa, bytes);
    }
    pub fn toOwnedSlice(self: *VecWriter) Error![]u8 {
        return self.list.toOwnedSlice(self.gpa);
    }
    pub fn items(self: *const VecWriter) []const u8 {
        return self.list.items;
    }
};

/// Serializes `thing` into a freshly allocated buffer (`ser_vec`).
pub fn serVec(gpa: std.mem.Allocator, thing: anytype, version: ProtocolVersion) Error![]u8 {
    var w = VecWriter.init(gpa, version);
    errdefer w.deinit();
    try write(&w, thing);
    return w.toOwnedSlice();
}

// ---------------------------------------------------------------- reading

/// Chain-dependent values needed while parsing (defaults are mainnet).
pub const ReadParams = struct {
    max_block_weight: usize = 40_000,
    /// Height of the first hard fork, for the header version check.
    first_fork_height: u64 = 9_000_000,
    /// Number of nonces in a Cuckoo proof.
    proof_size: usize = 42,
    min_edge_bits: u8 = 19,
};

/// Reads from an in-memory buffer. Fixed reads return slices borrowed from
/// the buffer (no copying); callers must copy anything that outlives it.
pub const Reader = struct {
    data: []const u8,
    pos: usize = 0,
    version: ProtocolVersion = ProtocolVersion.local(),
    gpa: std.mem.Allocator,
    /// The Rust BinReader refuses fixed reads over 100k bytes; the
    /// StreamingReader used by p2p does not.
    limit_fixed: bool = true,
    /// Chain parameters consulted while deserializing (the Rust node reads
    /// these from process-wide globals).
    params: ReadParams = .{},

    pub const max_fixed_read: usize = 100_000;

    pub fn init(gpa: std.mem.Allocator, data: []const u8, version: ProtocolVersion) Reader {
        return .{ .data = data, .gpa = gpa, .version = version };
    }

    pub fn remaining(self: *const Reader) usize {
        return self.data.len - self.pos;
    }

    pub fn readFixedBytes(self: *Reader, len: usize) Error![]const u8 {
        if (self.limit_fixed and len > max_fixed_read) return error.TooLargeRead;
        if (len > self.remaining()) return error.UnexpectedEof;
        const s = self.data[self.pos..][0..len];
        self.pos += len;
        return s;
    }

    pub fn readArray(self: *Reader, comptime n: usize) Error![n]u8 {
        return (try self.readFixedBytes(n))[0..n].*;
    }

    pub fn readU8(self: *Reader) Error!u8 {
        return (try self.readFixedBytes(1))[0];
    }
    pub fn readU16(self: *Reader) Error!u16 {
        return std.mem.readInt(u16, try self.readArrayPtr(2), .big);
    }
    pub fn readU32(self: *Reader) Error!u32 {
        return std.mem.readInt(u32, try self.readArrayPtr(4), .big);
    }
    pub fn readI32(self: *Reader) Error!i32 {
        return std.mem.readInt(i32, try self.readArrayPtr(4), .big);
    }
    pub fn readU64(self: *Reader) Error!u64 {
        return std.mem.readInt(u64, try self.readArrayPtr(8), .big);
    }
    pub fn readI64(self: *Reader) Error!i64 {
        return std.mem.readInt(i64, try self.readArrayPtr(8), .big);
    }

    fn readArrayPtr(self: *Reader, comptime n: usize) Error!*const [n]u8 {
        return (try self.readFixedBytes(n))[0..n];
    }

    /// u64 length prefix then that many bytes.
    pub fn readBytesLenPrefix(self: *Reader) Error![]const u8 {
        const len = try self.readU64();
        if (len > std.math.maxInt(usize)) return error.TooLargeRead;
        return self.readFixedBytes(@intCast(len));
    }

    pub fn expectU8(self: *Reader, val: u8) Error!u8 {
        const b = try self.readU8();
        if (b != val) return error.UnexpectedData;
        return b;
    }

    /// Generic read for integers and types with a `read` method.
    pub fn read(self: *Reader, comptime T: type) Error!T {
        switch (@typeInfo(T)) {
            .int => |i| return switch (i.bits) {
                8 => self.readU8(),
                16 => self.readU16(),
                32 => if (i.signedness == .signed) self.readI32() else self.readU32(),
                64 => if (i.signedness == .signed) self.readI64() else self.readU64(),
                else => @compileError("unsupported int width"),
            },
            .@"struct", .@"union", .@"enum" => return T.read(self),
            else => @compileError("type not readable: " ++ @typeName(T)),
        }
    }
};

/// Reads elements until the input is exhausted (Rust's `Vec<T>: Readable`).
/// Like the original, a truncated trailing element ends the list silently;
/// any other error is returned.
pub fn readVecUntilEof(comptime T: type, r: *Reader) Error![]T {
    var buf: std.ArrayList(T) = .empty;
    errdefer buf.deinit(r.gpa);
    while (true) {
        const elem = r.read(T) catch |e| switch (e) {
            error.UnexpectedEof => break,
            else => return e,
        };
        try buf.append(r.gpa, elem);
    }
    return buf.toOwnedSlice(r.gpa);
}

/// Reads `count` items (Rust's `read_multi`). Any failure while reading an
/// item surfaces as `CountError`, as in the original.
pub fn readMulti(comptime T: type, r: *Reader, count: u64) Error![]T {
    if (count > 1_000_000) return error.TooLargeRead;
    var buf: std.ArrayList(T) = .empty;
    errdefer buf.deinit(r.gpa);
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        const elem = r.read(T) catch break;
        try buf.append(r.gpa, elem);
    }
    if (buf.items.len != count) return error.CountError;
    return buf.toOwnedSlice(r.gpa);
}

/// Deserializes a `T` from `data`.
pub fn deserialize(comptime T: type, gpa: std.mem.Allocator, data: []const u8, version: ProtocolVersion) Error!T {
    var r = Reader.init(gpa, data, version);
    return r.read(T);
}

// ------------------------------------------------------------------ tests

test "integers are big endian" {
    const gpa = std.testing.allocator;
    var w = VecWriter.init(gpa, ProtocolVersion.local());
    defer w.deinit();
    try write(&w, @as(u8, 1));
    try write(&w, @as(u16, 0x0203));
    try write(&w, @as(u32, 0x04050607));
    try write(&w, @as(i32, -2));
    try write(&w, @as(u64, 0x08090a0b0c0d0e0f));
    try std.testing.expectEqualSlices(u8, &.{
        1,    2,    3,    4,    5,    6,    7,    0xff, 0xff, 0xff, 0xfe,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    }, w.items());

    var r = Reader.init(gpa, w.items(), ProtocolVersion.local());
    try std.testing.expectEqual(@as(u8, 1), try r.read(u8));
    try std.testing.expectEqual(@as(u16, 0x0203), try r.read(u16));
    try std.testing.expectEqual(@as(u32, 0x04050607), try r.read(u32));
    try std.testing.expectEqual(@as(i32, -2), try r.read(i32));
    try std.testing.expectEqual(@as(u64, 0x08090a0b0c0d0e0f), try r.read(u64));
    try std.testing.expectError(error.UnexpectedEof, r.read(u8));
}

test "length-prefixed bytes and read limits" {
    const gpa = std.testing.allocator;
    var w = VecWriter.init(gpa, ProtocolVersion.local());
    defer w.deinit();
    try writeBytes(&w, "abc");
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 0, 0, 3, 'a', 'b', 'c' }, w.items());
    var r = Reader.init(gpa, w.items(), ProtocolVersion.local());
    try std.testing.expectEqualStrings("abc", try r.readBytesLenPrefix());

    var big = Reader.init(gpa, &.{}, ProtocolVersion.local());
    try std.testing.expectError(error.TooLargeRead, big.readFixedBytes(100_001));
}

test "vec read stops silently at truncated tail; readMulti reports CountError" {
    const gpa = std.testing.allocator;
    const data = [_]u8{ 0, 0, 0, 1, 0, 0, 0, 2, 0, 0 };
    var r = Reader.init(gpa, &data, ProtocolVersion.local());
    const v = try readVecUntilEof(u32, &r);
    defer gpa.free(v);
    try std.testing.expectEqualSlices(u32, &.{ 1, 2 }, v);

    var r2 = Reader.init(gpa, &data, ProtocolVersion.local());
    try std.testing.expectError(error.CountError, readMulti(u32, &r2, 3));
    var r3 = Reader.init(gpa, &data, ProtocolVersion.local());
    try std.testing.expectError(error.TooLargeRead, readMulti(u32, &r3, 1_000_001));
}
