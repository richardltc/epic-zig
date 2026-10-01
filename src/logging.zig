//! Console log output in the same style as the reference node's stdout log
//! (log4rs pattern `{d(%Y-%m-%d %H:%M:%S%.3f)} {h({l})} {m}`):
//!
//!   2026-10-01 08:51:53.247 INFO Epic node server started.
//!
//! The level is coloured like log4rs does (ERROR red, WARN yellow, INFO green,
//! DEBUG blue) when the output is a terminal. DEBUG lines are hidden unless
//! `show_debug` is set.
const std = @import("std");
const builtin = @import("builtin");

pub const Level = enum { err, warn, info, debug };

/// Show DEBUG lines (`--debug`).
pub var show_debug = false;

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

/// One log line at `level`.
pub fn log(level: Level, comptime fmt: []const u8, args: anytype) void {
    if (level == .debug and !show_debug) return;
    var b: [32]u8 = undefined;
    const ts = stamp(&b);
    const name = switch (level) {
        .err => "ERROR",
        .warn => "WARN",
        .info => "INFO",
        .debug => "DEBUG",
    };
    if (useColor()) {
        const color = switch (level) {
            .err => "\x1b[31m",
            .warn => "\x1b[33m",
            .info => "\x1b[32m",
            .debug => "\x1b[34m",
        };
        std.debug.print("{s} {s}{s}\x1b[0m " ++ fmt ++ "\n", .{ ts, color, name } ++ args);
    } else {
        std.debug.print("{s} {s} " ++ fmt ++ "\n", .{ ts, name } ++ args);
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
