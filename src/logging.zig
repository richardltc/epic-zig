//! Console log output in the same style as the reference node's stdout log
//! (log4rs pattern `{d(%Y-%m-%d %H:%M:%S%.3f)} {h({l})} {m}`):
//!
//!   2026-10-01 08:51:53.247 INFO Epic node server started.
//!
//! The level is coloured like log4rs does (ERROR red, WARN yellow, INFO green,
//! DEBUG blue) when the output is a terminal. DEBUG lines are hidden on the
//! console unless `show_debug` is set.
//!
//! Like the reference's `log_to_file`, lines can also go to a log file in the
//! data dir (plain text, its own level, rotated by size into numbered `.gz`
//! files); see `openFile`.
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;

pub const Level = enum {
    err,
    warn,
    info,
    debug,

    /// The reference's level names: Error, Warning, Info, Debug, Trace (any case).
    pub fn parse(s: []const u8) ?Level {
        const eq = std.ascii.eqlIgnoreCase;
        if (eq(s, "error")) return .err;
        if (eq(s, "warning") or eq(s, "warn")) return .warn;
        if (eq(s, "info")) return .info;
        if (eq(s, "debug") or eq(s, "trace")) return .debug;
        return null;
    }
};

/// Show DEBUG lines on the console (`--debug`).
pub var show_debug = false;
/// Console output on/off (the reference's `log_to_stdout`).
pub var to_stdout = true;
/// The console's level (the reference's `stdout_log_level`).
pub var stdout_level: Level = .info;

pub const FileOptions = struct {
    level: Level = .debug,
    append: bool = true,
    /// Rotate once the file passes this many bytes (null: never).
    max_size: ?u64 = 16 << 20,
    /// Rotated files kept, as `<name>.0.gz` (newest) ... `<name>.<n-1>.gz`.
    max_files: u32 = 32,
};

const LogFile = struct {
    mu: Io.Mutex = .init,
    io: Io,
    dir: Io.Dir,
    name_buf: [256]u8 = undefined,
    name_len: usize = 0,
    file: Io.File,
    size: u64,
    opts: FileOptions,

    fn name(self: *const LogFile) []const u8 {
        return self.name_buf[0..self.name_len];
    }
};

var log_file: ?LogFile = null;

/// Starts writing log lines to `path` (relative paths are inside `dir`) too.
pub fn openFile(io: Io, dir: Io.Dir, path: []const u8, opts: FileOptions) !void {
    const base = std.fs.path.basename(path);
    if (base.len == 0 or base.len > 200) return error.BadLogFileName;
    const parent = std.fs.path.dirname(path);
    var d = if (parent) |p| try dir.createDirPathOpen(io, p, .{}) else try dir.openDir(io, ".", .{});
    errdefer d.close(io);
    const f = try d.createFile(io, base, .{ .truncate = !opts.append, .read = true });
    errdefer f.close(io);
    const size = try f.length(io);
    var lf: LogFile = .{ .io = io, .dir = d, .file = f, .size = size, .opts = opts };
    @memcpy(lf.name_buf[0..base.len], base);
    lf.name_len = base.len;
    log_file = lf;
}

/// Rotates the log file: `.N.gz` files shift up one (the oldest is dropped),
/// the current file is compressed into `.0.gz`, and a new file starts.
/// Called with the file's lock held.
fn rotate(lf: *LogFile) void {
    const io = lf.io;
    var a: [300]u8 = undefined;
    var b: [300]u8 = undefined;
    const n = lf.opts.max_files;
    if (n == 0) {
        lf.file.setLength(io, 0) catch {};
        lf.size = 0;
        return;
    }
    if (std.fmt.bufPrint(&a, "{s}.{d}.gz", .{ lf.name(), n - 1 })) |oldest| lf.dir.deleteFile(io, oldest) catch {} else |_| {}
    var i: u32 = n - 1;
    while (i > 0) : (i -= 1) {
        const from = std.fmt.bufPrint(&a, "{s}.{d}.gz", .{ lf.name(), i - 1 }) catch return;
        const to = std.fmt.bufPrint(&b, "{s}.{d}.gz", .{ lf.name(), i }) catch return;
        lf.dir.rename(from, lf.dir, to, io) catch {};
    }
    const rolled = std.fmt.bufPrint(&a, "{s}.rolling", .{lf.name()}) catch return;
    lf.file.close(io);
    lf.dir.rename(lf.name(), lf.dir, rolled, io) catch {};
    lf.file = lf.dir.createFile(io, lf.name(), .{ .truncate = true, .read = true }) catch {
        log_file = null;
        return;
    };
    lf.size = 0;
    const gz = std.fmt.bufPrint(&b, "{s}.0.gz", .{lf.name()}) catch return;
    compressFile(io, lf.dir, rolled, gz) catch {};
    lf.dir.deleteFile(io, rolled) catch {};
}

fn compressFile(io: Io, dir: Io.Dir, from: []const u8, to: []const u8) !void {
    const in = try dir.openFile(io, from, .{});
    defer in.close(io);
    const out = try dir.createFile(io, to, .{ .truncate = true });
    defer out.close(io);
    var rbuf: [64 * 1024]u8 = undefined;
    var r = in.reader(io, &rbuf);
    var wbuf: [64 * 1024]u8 = undefined;
    var w = out.writer(io, &wbuf);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var c = try std.compress.flate.Compress.init(&w.interface, &window, .gzip, .level_1);
    _ = try r.interface.streamRemaining(&c.writer);
    try c.finish();
    try w.interface.flush();
}

fn writeFileLine(line: []const u8) void {
    const lf = &(log_file orelse return);
    lf.mu.lockUncancelable(lf.io);
    defer lf.mu.unlock(lf.io);
    if (log_file == null) return;
    lf.file.writePositionalAll(lf.io, line, lf.size) catch return;
    lf.size += line.len;
    if (lf.opts.max_size) |max| if (lf.size >= max) rotate(lf);
}

/// Writes a crash message straight to the log file (from the panic handler:
/// no locking, the process is going down).
pub fn panicToFile(msg: []const u8, ret_addr: ?usize) void {
    const lf = &(log_file orelse return);
    var b: [32]u8 = undefined;
    var line: [1024]u8 = undefined;
    const text = std.fmt.bufPrint(&line, "{s} ERROR Epic-Zig crashed: {s} (at 0x{x})\n", .{ stamp(&b), msg, ret_addr orelse 0 }) catch return;
    lf.file.writePositionalAll(lf.io, text, lf.size) catch return;
    lf.size += text.len;
}

const Tm = extern struct {
    sec: c_int,
    min: c_int,
    hour: c_int,
    mday: c_int,
    mon: c_int,
    year: c_int,
    wday: c_int,
    yday: c_int,
    isdst: c_int,
    // glibc and the BSDs have more fields after these; room for them
    _rest: [64]u8 = undefined,
};

const Timeval = extern struct { sec: c_long, usec: c_long };

extern "c" fn gettimeofday(tv: *Timeval, tz: ?*anyopaque) c_int;
extern "c" fn localtime_r(t: *const i64, tm: *Tm) ?*Tm;
extern "c" fn _localtime64_s(tm: *Tm, t: *const i64) c_int;
extern "c" fn isatty(fd: c_int) c_int;
extern "c" fn _isatty(fd: c_int) c_int;

/// "YYYY-MM-DD HH:MM:SS.mmm" in local time.
pub fn stamp(buf: *[32]u8) []const u8 {
    var tv: Timeval = .{ .sec = 0, .usec = 0 };
    _ = gettimeofday(&tv, null);
    const secs: i64 = tv.sec;
    var tm: Tm = undefined;
    const ok = if (builtin.os.tag == .windows) _localtime64_s(&tm, &secs) == 0 else localtime_r(&secs, &tm) != null;
    if (!ok) return "????-??-?? ??:??:??.???";
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}", .{
        @as(u32, @intCast(tm.year + 1900)), @as(u32, @intCast(tm.mon + 1)), @as(u32, @intCast(tm.mday)),
        @as(u32, @intCast(tm.hour)),        @as(u32, @intCast(tm.min)),     @as(u32, @intCast(tm.sec)),
        @as(u32, @intCast(@divTrunc(tv.usec, 1000))),
    }) catch "????-??-?? ??:??:??.???";
}

var color_state: std.atomic.Value(u8) = .init(0); // 0 unknown, 1 yes, 2 no

fn useColor() bool {
    switch (color_state.load(.monotonic)) {
        1 => return true,
        2 => return false,
        else => {
            const tty = if (builtin.os.tag == .windows) _isatty(2) != 0 else isatty(2) != 0;
            color_state.store(if (tty) 1 else 2, .monotonic);
            return tty;
        },
    }
}

/// A number with thousands separators for log lines: `{f}` with `num(x)` -> "3,733,983".
pub const Num = struct {
    v: u64,
    pub fn format(self: Num, w: *std.Io.Writer) std.Io.Writer.Error!void {
        var digits: [32]u8 = undefined;
        const s = std.fmt.bufPrint(&digits, "{d}", .{self.v}) catch unreachable;
        for (s, 0..) |c, i| {
            if (i > 0 and (s.len - i) % 3 == 0) try w.writeByte(',');
            try w.writeByte(c);
        }
    }
};

pub fn num(v: anytype) Num {
    return switch (@typeInfo(@TypeOf(v))) {
        .float, .comptime_float => .{ .v = if (v < 0) 0 else @intFromFloat(@round(v)) },
        else => .{ .v = @intCast(v) },
    };
}

fn levelName(level: Level) []const u8 {
    return switch (level) {
        .err => "ERROR",
        .warn => "WARN",
        .info => "INFO",
        .debug => "DEBUG",
    };
}

/// One log line at `level`, to the console and/or the log file.
pub fn log(level: Level, comptime fmt: []const u8, args: anytype) void {
    const console_level: Level = if (show_debug) .debug else stdout_level;
    const to_console = to_stdout and @intFromEnum(level) <= @intFromEnum(console_level);
    const to_file = if (log_file) |lf| @intFromEnum(level) <= @intFromEnum(lf.opts.level) else false;
    if (!to_console and !to_file) return;

    var b: [32]u8 = undefined;
    const ts = stamp(&b);
    const name = levelName(level);
    var buf: [8192]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, fmt, args) catch blk: {
        // too long for the buffer: keep what fits
        const tail = "...";
        @memcpy(buf[buf.len - tail.len ..], tail);
        break :blk buf[0..];
    };
    if (to_console) {
        if (useColor()) {
            const color = switch (level) {
                .err => "\x1b[31m",
                .warn => "\x1b[33m",
                .info => "\x1b[32m",
                .debug => "\x1b[34m",
            };
            std.debug.print("{s} {s}{s}\x1b[0m {s}\n", .{ ts, color, name, msg });
        } else {
            std.debug.print("{s} {s} {s}\n", .{ ts, name, msg });
        }
    }
    if (to_file) {
        var lb: [8192 + 64]u8 = undefined;
        const line = std.fmt.bufPrint(&lb, "{s} {s} {s}\n", .{ ts, name, msg }) catch return;
        writeFileLine(line);
    }
}

pub fn info(comptime fmt: []const u8, args: anytype) void {
    log(.info, fmt, args);
}
pub fn warn(comptime fmt: []const u8, args: anytype) void {
    log(.warn, fmt, args);
}
pub fn err(comptime fmt: []const u8, args: anytype) void {
    log(.err, fmt, args);
}
pub fn debug(comptime fmt: []const u8, args: anytype) void {
    log(.debug, fmt, args);
}

/// INFO line (kept for older call sites).
pub fn print(comptime fmt: []const u8, args: anytype) void {
    log(.info, fmt, args);
}

/// `std.log` output in the same format (installed as `std_options.logFn` by main).
pub fn logFn(comptime level: std.log.Level, comptime scope: @EnumLiteral(), comptime format: []const u8, args: anytype) void {
    _ = scope;
    const l: Level = switch (level) {
        .err => .err,
        .warn => .warn,
        .info => .info,
        .debug => .debug,
    };
    log(l, format, args);
}

test "thousands separators" {
    var b: [64]u8 = undefined;
    try std.testing.expectEqualStrings("0", try std.fmt.bufPrint(&b, "{f}", .{num(0)}));
    try std.testing.expectEqualStrings("999", try std.fmt.bufPrint(&b, "{f}", .{num(999)}));
    try std.testing.expectEqualStrings("1,000", try std.fmt.bufPrint(&b, "{f}", .{num(1000)}));
    try std.testing.expectEqualStrings("3,733,983", try std.fmt.bufPrint(&b, "{f}", .{num(@as(u64, 3733983))}));
    try std.testing.expectEqualStrings("16,278", try std.fmt.bufPrint(&b, "{f}", .{num(16277.6)}));
}

test "the stamp looks like a date and time with milliseconds" {
    var b: [32]u8 = undefined;
    const s = stamp(&b);
    try std.testing.expectEqual(@as(usize, 23), s.len);
    try std.testing.expectEqual(@as(u8, '-'), s[4]);
    try std.testing.expectEqual(@as(u8, ' '), s[10]);
    try std.testing.expectEqual(@as(u8, ':'), s[13]);
    try std.testing.expectEqual(@as(u8, '.'), s[19]);
}

test "log file rotation keeps gzipped copies" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const was_stdout = to_stdout;
    to_stdout = false;
    defer {
        to_stdout = was_stdout;
        if (log_file) |*lf| {
            lf.file.close(io);
            lf.dir.close(io);
        }
        log_file = null;
    }
    try openFile(io, tmp.dir, "test.log", .{ .level = .info, .max_size = 1000, .max_files = 2 });
    for (0..100) |i| info("line {d} of the rotation test", .{i});
    // two rotated copies at most, plus the current file
    _ = try tmp.dir.statFile(io, "test.log.0.gz", .{});
    _ = try tmp.dir.statFile(io, "test.log.1.gz", .{});
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, "test.log.2.gz", .{}));
    // the newest rotated copy decompresses to whole log lines
    const gz = try tmp.dir.readFileAlloc(io, "test.log.0.gz", std.testing.allocator, .limited(1 << 20));
    defer std.testing.allocator.free(gz);
    var input: Io.Reader = .fixed(gz);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var d: std.compress.flate.Decompress = .init(&input, .gzip, &window);
    const text = try d.reader.allocRemaining(std.testing.allocator, .limited(1 << 20));
    defer std.testing.allocator.free(text);
    try std.testing.expect(std.mem.indexOf(u8, text, "INFO line ") != null);
    try std.testing.expect(text.len >= 1000);
}
