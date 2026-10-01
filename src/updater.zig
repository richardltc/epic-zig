//! Automatic updates from the project's GitHub releases.
//!
//! At startup the node asks GitHub for the latest release. If it is newer than
//! this binary, it downloads the package for this platform, checks it against
//! the release's SHA256SUMS, swaps the new binary in for the running one and
//! restarts into it with the same arguments. Anything going wrong (no network,
//! no write access, a bad checksum) just leaves the current version running.
//!
//! Pre-releases and drafts are never installed (GitHub's "latest release"
//! excludes them), and debug builds never update themselves.
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const logging = @import("logging.zig");
const VERSION = @import("version.zig").VERSION;

pub const REPO = "richardltc/epic-zig";
const LATEST_URL = "https://api.github.com/repos/" ++ REPO ++ "/releases/latest";
const USER_AGENT = "epic-zig/" ++ VERSION;
/// Set in the environment of the restarted process, so a mispackaged release
/// can never make the node update in a loop.
pub const RESTARTED_ENV = "EPIC_ZIG_UPDATED";
/// How long startup waits for the check and download before carrying on.
const DEADLINE_SECS = 120;
const MAX_ARCHIVE = 64 << 20;

/// This platform's package name suffix in the release ("linux-x86_64"), or
/// null where no package is published.
fn platform() ?[]const u8 {
    return switch (builtin.os.tag) {
        .linux => switch (builtin.cpu.arch) {
            .x86_64 => "linux-x86_64",
            .aarch64 => "linux-aarch64",
            else => null,
        },
        .macos => switch (builtin.cpu.arch) {
            .x86_64 => "macos-x86_64",
            .aarch64 => "macos-aarch64",
            else => null,
        },
        .windows => if (builtin.cpu.arch == .x86_64) "windows-x86_64" else null,
        else => null,
    };
}

const exe_name = if (builtin.os.tag == .windows) "epic-zig.exe" else "epic-zig";
const archive_ext = if (builtin.os.tag == .windows) ".zip" else ".tar.gz";

/// "1.2.3" (an optional leading "v" and any "-suffix" ignored) as numbers.
fn parseVersion(s: []const u8) ?[3]u32 {
    var v = s;
    if (v.len > 0 and (v[0] == 'v' or v[0] == 'V')) v = v[1..];
    if (std.mem.indexOfAny(u8, v, "-+")) |i| v = v[0..i];
    var out: [3]u32 = .{ 0, 0, 0 };
    var it = std.mem.splitScalar(u8, v, '.');
    var n: usize = 0;
    while (it.next()) |part| : (n += 1) {
        if (n == 3) return null;
        out[n] = std.fmt.parseInt(u32, part, 10) catch return null;
    }
    return if (n == 0) null else out;
}

fn newer(candidate: []const u8, current: []const u8) bool {
    const a = parseVersion(candidate) orelse return false;
    const b = parseVersion(current) orelse return false;
    for (a, b) |x, y| {
        if (x != y) return x > y;
    }
    return false;
}

/// A downloaded, checksum-verified package ready to install.
const Ready = struct {
    version: []const u8,
    archive: []u8,
};

const Check = struct {
    gpa: std.mem.Allocator,
    io: Io,
    done: std.atomic.Value(bool) = .init(false),
    /// Set by the waiting side when it gives up: the worker then frees what it has.
    abandoned: std.atomic.Value(bool) = .init(false),
    result: ?Ready = null,
    err: ?anyerror = null,
};

/// GETs `url` into memory, following redirects itself: GitHub sends release
/// downloads to signed storage URLs, which must be requested exactly as given.
fn get(client: *std.http.Client, gpa: std.mem.Allocator, url: []const u8, accept: []const u8) ![]u8 {
    var cur = try gpa.dupe(u8, url);
    defer gpa.free(cur);
    var hops: u32 = 0;
    while (true) : (hops += 1) {
        if (hops > 5) return error.TooManyRedirects;
        var req = try client.request(.GET, try std.Uri.parse(cur), .{
            .redirect_behavior = .unhandled,
            .keep_alive = false,
            .headers = .{ .user_agent = .{ .override = USER_AGENT }, .accept_encoding = .{ .override = "identity" } },
            .extra_headers = &.{.{ .name = "accept", .value = accept }},
        });
        defer req.deinit();
        try req.sendBodiless();
        var response = try req.receiveHead(&.{});
        const status = response.head.status;
        if (status.class() == .redirect) {
            const loc = response.head.location orelse return error.HttpRedirectLocationMissing;
            const next = try gpa.dupe(u8, loc);
            gpa.free(cur);
            cur = next;
            continue;
        }
        if (status != .ok) {
            logging.debug("Update: {s} returned HTTP {d}", .{ cur, @intFromEnum(status) });
            return error.HttpStatus;
        }
        const r = response.reader(&.{});
        return r.allocRemaining(gpa, .limited(MAX_ARCHIVE)) catch |e| switch (e) {
            error.ReadFailed => return response.bodyErr() orelse error.ReadFailed,
            else => return e,
        };
    }
}

/// The worker: looks up the latest release and, if it is newer, downloads and
/// verifies this platform's package (all in memory; nothing is written).
fn checkWorker(c: *Check) void {
    const r = checkAndDownload(c.gpa, c.io);
    if (r) |maybe| c.result = maybe else |e| c.err = e;
    c.done.store(true, .release);
    if (c.abandoned.load(.acquire)) {
        if (c.result) |res| {
            c.gpa.free(res.archive);
            c.gpa.free(res.version);
        }
        c.gpa.destroy(c);
    }
}

fn checkAndDownload(gpa: std.mem.Allocator, io: Io) !?Ready {
    const plat = platform() orelse return null;
    var client: std.http.Client = .{ .allocator = gpa, .io = io };
    defer client.deinit();

    const meta = try get(&client, gpa, LATEST_URL, "application/vnd.github+json");
    defer gpa.free(meta);
    const Release = struct {
        tag_name: []const u8,
        assets: []const struct { name: []const u8, browser_download_url: []const u8 },
    };
    const parsed = try std.json.parseFromSlice(Release, gpa, meta, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    const rel = parsed.value;

    if (!newer(rel.tag_name, VERSION)) {
        logging.info("Epic-Zig {s} is the latest version", .{VERSION});
        return null;
    }
    const ver = if (rel.tag_name.len > 0 and rel.tag_name[0] == 'v') rel.tag_name[1..] else rel.tag_name;
    logging.info("Epic-Zig {s} is available (running {s})", .{ ver, VERSION });

    var name_buf: [128]u8 = undefined;
    const want = try std.fmt.bufPrint(&name_buf, "epic-zig-{s}-{s}{s}", .{ ver, plat, archive_ext });
    var archive_url: ?[]const u8 = null;
    var sums_url: ?[]const u8 = null;
    for (rel.assets) |a| {
        if (std.mem.eql(u8, a.name, want)) archive_url = a.browser_download_url;
        if (std.mem.eql(u8, a.name, "SHA256SUMS")) sums_url = a.browser_download_url;
    }
    const aurl = archive_url orelse {
        logging.warn("Update: the release has no {s}; staying on {s}", .{ want, VERSION });
        return null;
    };
    const surl = sums_url orelse {
        logging.warn("Update: the release has no SHA256SUMS; staying on {s}", .{VERSION});
        return null;
    };

    const sums = try get(&client, gpa, surl, "application/octet-stream");
    defer gpa.free(sums);
    var expected: ?[32]u8 = null;
    var lines = std.mem.splitScalar(u8, sums, '\n');
    while (lines.next()) |line| {
        var parts = std.mem.tokenizeAny(u8, line, " \t*\r");
        const hex = parts.next() orelse continue;
        const fname = parts.next() orelse continue;
        if (!std.mem.eql(u8, fname, want) or hex.len != 64) continue;
        var d: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&d, hex) catch continue;
        expected = d;
    }
    const want_digest = expected orelse {
        logging.warn("Update: SHA256SUMS doesn't list {s}; staying on {s}", .{ want, VERSION });
        return null;
    };

    logging.info("Downloading {s}...", .{want});
    const archive = try get(&client, gpa, aurl, "application/octet-stream");
    errdefer gpa.free(archive);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(archive, &digest, .{});
    if (!std.mem.eql(u8, &digest, &want_digest)) {
        logging.err("Update: {s} doesn't match its SHA256SUMS checksum; not installing it", .{want});
        gpa.free(archive);
        return null;
    }
    logging.info("Checksum verified", .{});
    return .{ .version = try gpa.dupe(u8, ver), .archive = archive };
}

/// Unpacks the package into `tmp` (a directory next to the executable) and
/// returns the path of the new binary inside it, relative to `exe_dir`.
fn unpack(io: Io, exe_dir: Io.Dir, archive: []const u8, version: []const u8, out: []u8) ![]const u8 {
    const tmp_name = ".epic-zig-update";
    exe_dir.deleteTree(io, tmp_name) catch {};
    var tmp = try exe_dir.createDirPathOpen(io, tmp_name, .{});
    defer tmp.close(io);
    if (builtin.os.tag == .windows) {
        try tmp.writeFile(io, .{ .sub_path = "package.zip", .data = archive });
        var zf = try tmp.openFile(io, "package.zip", .{});
        defer zf.close(io);
        var rbuf: [4096]u8 = undefined;
        var fr = zf.reader(io, &rbuf);
        try std.zip.extract(tmp, &fr, .{});
    } else {
        var input: Io.Reader = .fixed(archive);
        var window: [std.compress.flate.max_window_len]u8 = undefined;
        var gz: std.compress.flate.Decompress = .init(&input, .gzip, &window);
        try std.tar.extract(io, tmp, &gz.reader, .{ .mode_mode = .executable_bit_only });
    }
    const plat = platform().?;
    return std.fmt.bufPrint(out, "{s}/epic-zig-{s}-{s}/{s}", .{ tmp_name, version, plat, exe_name });
}

/// Puts `new_rel` (relative to `exe_dir`) in place of the running executable.
fn install(io: Io, exe_dir: Io.Dir, exe_base: []const u8, new_rel: []const u8) !void {
    exe_dir.setFilePermissions(io, new_rel, .executable_file, .{}) catch {};
    if (builtin.os.tag == .windows) {
        // a running .exe can't be overwritten, but it can be renamed out of the way
        var old_buf: [256]u8 = undefined;
        const old = try std.fmt.bufPrint(&old_buf, "{s}.old", .{exe_base});
        exe_dir.deleteFile(io, old) catch {};
        try exe_dir.rename(exe_base, exe_dir, old, io);
        exe_dir.rename(new_rel, exe_dir, exe_base, io) catch |e| {
            exe_dir.rename(old, exe_dir, exe_base, io) catch {};
            return e;
        };
    } else {
        // atomic: the old binary stays valid for anything still running it
        try exe_dir.rename(new_rel, exe_dir, exe_base, io);
    }
}

/// Removes leftovers of an earlier update (the Windows `.old` binary, the
/// unpack directory).
fn tidy(io: Io, exe_dir: Io.Dir, exe_base: []const u8) void {
    exe_dir.deleteTree(io, ".epic-zig-update") catch {};
    if (builtin.os.tag == .windows) {
        var old_buf: [256]u8 = undefined;
        const old = std.fmt.bufPrint(&old_buf, "{s}.old", .{exe_base}) catch return;
        exe_dir.deleteFile(io, old) catch {};
    }
}

/// Checks for a newer release and, if there is one, installs it and restarts
/// into it (this function then does not return). Returns normally when the
/// node should carry on with the running version.
pub fn run(gpa: std.mem.Allocator, io: Io, args: []const []const u8, environ: *std.process.Environ.Map) void {
    if (builtin.mode == .Debug) return;
    if (environ.get(RESTARTED_ENV) != null) {
        logging.info("Updated to Epic-Zig {s}", .{VERSION});
        return;
    }
    if (platform() == null) return;

    const exe_path = std.process.executablePathAlloc(io, gpa) catch |e| {
        logging.warn("Update check skipped: can't find this executable ({s})", .{@errorName(e)});
        return;
    };
    defer gpa.free(exe_path);
    const exe_base = std.fs.path.basename(exe_path);
    const exe_dir_path = std.fs.path.dirname(exe_path) orelse ".";
    var exe_dir = Io.Dir.cwd().openDir(io, exe_dir_path, .{}) catch |e| {
        logging.warn("Update check skipped: can't open {s} ({s})", .{ exe_dir_path, @errorName(e) });
        return;
    };
    defer exe_dir.close(io);
    tidy(io, exe_dir, exe_base);

    logging.info("Checking for updates...", .{});
    const c = gpa.create(Check) catch return;
    c.* = .{ .gpa = gpa, .io = io };
    const t = std.Thread.spawn(.{}, checkWorker, .{c}) catch {
        gpa.destroy(c);
        return;
    };
    t.detach();
    var waited: u32 = 0;
    while (!c.done.load(.acquire)) : (waited += 1) {
        if (waited >= DEADLINE_SECS * 10) {
            // the worker frees everything itself when it finishes
            c.abandoned.store(true, .release);
            if (c.done.load(.acquire)) break; // finished just now: handle it below
            logging.warn("Update check didn't finish within {d}s; carrying on with {s}", .{ DEADLINE_SECS, VERSION });
            return;
        }
        io.sleep(.fromMilliseconds(100), .awake) catch {};
    }
    defer gpa.destroy(c);
    if (c.err) |e| {
        logging.warn("Update check failed ({s}); carrying on with {s}", .{ @errorName(e), VERSION });
        return;
    }
    const ready = c.result orelse return;
    defer {
        gpa.free(ready.archive);
        gpa.free(ready.version);
    }

    var rel_buf: [256]u8 = undefined;
    const new_rel = unpack(io, exe_dir, ready.archive, ready.version, &rel_buf) catch |e| {
        logging.warn("Update: couldn't unpack the download ({s}); carrying on with {s}", .{ @errorName(e), VERSION });
        tidy(io, exe_dir, exe_base);
        return;
    };
    install(io, exe_dir, exe_base, new_rel) catch |e| {
        logging.warn("Update: couldn't replace {s} ({s}); carrying on with {s}. Is the folder writable by this user?", .{ exe_path, @errorName(e), VERSION });
        tidy(io, exe_dir, exe_base);
        return;
    };
    exe_dir.deleteTree(io, ".epic-zig-update") catch {};
    logging.info("Installed Epic-Zig {s}; restarting", .{ready.version});

    environ.put(RESTARTED_ENV, ready.version) catch {};
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(gpa);
    argv.append(gpa, exe_path) catch return;
    if (args.len > 1) argv.appendSlice(gpa, args[1..]) catch return;
    const e = std.process.replace(io, .{ .argv = argv.items, .environ_map = environ });
    // `replace` only returns on failure (e.g. on Windows): run the new binary as a child instead
    logging.debug("Update: in-place restart unavailable ({s}); starting the new binary", .{@errorName(e)});
    var child = std.process.spawn(io, .{ .argv = argv.items, .environ_map = environ }) catch |se| {
        logging.warn("Update installed but couldn't restart ({s}); please start Epic-Zig again", .{@errorName(se)});
        std.process.exit(0);
    };
    const term = child.wait(io) catch std.process.exit(1);
    std.process.exit(switch (term) {
        .exited => |code| code,
        else => 1,
    });
}

test "version comparison" {
    try std.testing.expect(newer("v0.1.1", "0.1.0"));
    try std.testing.expect(newer("0.2.0", "0.1.9"));
    try std.testing.expect(newer("v1.0.0", "0.9.9"));
    try std.testing.expect(!newer("v0.1.0", "0.1.0"));
    try std.testing.expect(!newer("v0.0.9", "0.1.0"));
    try std.testing.expect(!newer("garbage", "0.1.0"));
    try std.testing.expect(newer("v0.1.1-rc1", "0.1.0"));
}
