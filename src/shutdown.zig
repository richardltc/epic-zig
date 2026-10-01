//! Ctrl-C / SIGTERM handling: the signal only raises a flag; a watcher thread
//! (in main) does the actual orderly shutdown. A second Ctrl-C exits at once.
const std = @import("std");
const builtin = @import("builtin");

pub var requested: std.atomic.Value(bool) = .init(false);

fn onSignal(_: std.posix.SIG) callconv(.c) void {
    if (requested.swap(true, .acq_rel)) std.process.exit(130);
}

const windows = struct {
    extern "kernel32" fn SetConsoleCtrlHandler(handler: ?*const fn (u32) callconv(.winapi) i32, add: i32) callconv(.winapi) i32;
    fn onCtrl(_: u32) callconv(.winapi) i32 {
        if (requested.swap(true, .acq_rel)) std.process.exit(130);
        return 1; // handled: don't kill the process yet
    }
};

pub fn install() void {
    if (builtin.os.tag == .windows) {
        _ = windows.SetConsoleCtrlHandler(windows.onCtrl, 1);
        return;
    }
    const act: std.posix.Sigaction = .{
        .handler = .{ .handler = onSignal },
        .mask = std.posix.sigemptyset(),
        .flags = std.posix.SA.RESTART,
    };
    std.posix.sigaction(.INT, &act, null);
    std.posix.sigaction(.TERM, &act, null);
}
