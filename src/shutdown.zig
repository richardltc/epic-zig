//! Ctrl-C / SIGTERM / SIGHUP handling (the same signals as the reference's
//! `ctrlc` "termination" handler): the signal only raises a flag; a watcher
//! thread (in main) does the actual orderly shutdown. A second signal exits at once.
const std = @import("std");
const builtin = @import("builtin");

pub var requested: std.atomic.Value(bool) = .init(false);

fn onSignal(_: std.posix.SIG) callconv(.c) void {
    if (requested.swap(true, .acq_rel)) std.process.exit(130);
}

const windows = struct {
    extern "kernel32" fn SetConsoleCtrlHandler(handler: ?*const fn (u32) callconv(.winapi) i32, add: i32) callconv(.winapi) i32;
    extern "kernel32" fn Sleep(ms: u32) callconv(.winapi) void;
    const CTRL_CLOSE_EVENT = 2;
    const CTRL_LOGOFF_EVENT = 5;
    const CTRL_SHUTDOWN_EVENT = 6;
    fn onCtrl(event: u32) callconv(.winapi) i32 {
        if (requested.swap(true, .acq_rel)) std.process.exit(130);
        // For a closed console window, a logoff or a shutdown, Windows ends the
        // process as soon as this returns: wait here while the watcher shuts
        // down (it exits the process itself; Windows allows a few seconds).
        if (event == CTRL_CLOSE_EVENT or event == CTRL_LOGOFF_EVENT or event == CTRL_SHUTDOWN_EVENT) Sleep(10_000);
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
    // the terminal closing (SSH session dropped, window closed): shut down cleanly too
    std.posix.sigaction(.HUP, &act, null);
}
