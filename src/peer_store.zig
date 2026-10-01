//! Known peers and bans, persisted to `<data-dir>/peers.txt` (one line per
//! peer). Simpler than the reference's RocksDB peer table, same ideas: peers
//! are healthy or defunct, bans are by IP with an expiry, and addresses
//! learned from other peers are filtered before they're trusted.
const std = @import("std");
const Io = std.Io;
const net = Io.net;
const msg = @import("p2p_msg.zig");

pub const State = enum(u8) { healthy = 'H', defunct = 'D' };

/// How long a ban lasts (the reference's `BAN_WINDOW`: 3 hours).
pub const BAN_SECS: i64 = 10800;
const MAX_PEERS: usize = 2000;

/// Hashable form of an address.
pub const Key = struct {
    v6: bool,
    ip: [16]u8,
    port: u16,

    pub fn fromAddr(a: net.IpAddress) Key {
        var k: Key = .{ .v6 = false, .ip = [_]u8{0} ** 16, .port = 0 };
        switch (a) {
            .ip4 => |x| {
                @memcpy(k.ip[0..4], &x.bytes);
                k.port = x.port;
            },
            .ip6 => |x| {
                k.v6 = true;
                k.ip = x.bytes;
                k.port = x.port;
            },
        }
        return k;
    }

    pub fn toAddr(self: Key) net.IpAddress {
        return if (self.v6)
            .{ .ip6 = .{ .bytes = self.ip, .port = self.port } }
        else
            .{ .ip4 = .{ .bytes = self.ip[0..4].*, .port = self.port } };
    }

    /// The same host on port 0 (bans apply to the host, not the port).
    fn host(self: Key) Key {
        var k = self;
        k.port = 0;
        return k;
    }
};

pub const Entry = struct {
    state: State = .healthy,
    last_seen_s: i64 = 0,
    /// When we last tried to connect (0: never).
    last_attempt_s: i64 = 0,
};

/// Don't redial the same address sooner than this, whatever its state.
pub const MIN_REDIAL_SECS: i64 = 30;
/// A defunct peer is worth another try after this long.
pub const RETRY_DEFUNCT_SECS: i64 = 15 * 60;

/// Addresses worth remembering: a real port and a routable host. Private and
/// loopback ranges only count when `allow_local` (tests, LAN setups).
pub fn acceptable(a: net.IpAddress, allow_local: bool) bool {
    switch (a) {
        .ip4 => |x| {
            if (x.port == 0) return false;
            const b = x.bytes;
            if (b[0] == 0 or b[0] >= 224) return false; // unspecified, multicast, reserved
            if (allow_local) return true;
            if (b[0] == 10 or b[0] == 127) return false;
            if (b[0] == 169 and b[1] == 254) return false;
            if (b[0] == 172 and b[1] >= 16 and b[1] <= 31) return false;
            if (b[0] == 192 and b[1] == 168) return false;
            return true;
        },
        .ip6 => |x| {
            if (x.port == 0) return false;
            if (std.mem.allEqual(u8, &x.bytes, 0)) return false;
            if (x.bytes[0] == 0xff) return false; // multicast
            if (allow_local) return true;
            const loopback = std.mem.eql(u8, x.bytes[0..15], &([_]u8{0} ** 15)) and x.bytes[15] == 1;
            if (loopback) return false;
            if ((x.bytes[0] & 0xfe) == 0xfc) return false; // unique local
            if (x.bytes[0] == 0xfe and (x.bytes[1] & 0xc0) == 0x80) return false; // link local
            return true;
        },
    }
}

pub fn fromPeerAddr(pa: msg.PeerAddr) net.IpAddress {
    return switch (pa) {
        .v4 => |a| .{ .ip4 = .{ .bytes = a.ip, .port = a.port } },
        .v6 => |a| blk: {
            var bytes: [16]u8 = undefined;
            for (a.segments, 0..) |s, i| std.mem.writeInt(u16, bytes[i * 2 ..][0..2], s, .big);
            break :blk net.IpAddress.fromIp6(.{ .bytes = bytes, .port = a.port });
        },
    };
}

pub fn toPeerAddr(a: net.IpAddress) msg.PeerAddr {
    return switch (a) {
        .ip4 => |x| .{ .v4 = .{ .ip = x.bytes, .port = x.port } },
        .ip6 => |x| blk: {
            var segs: [8]u16 = undefined;
            for (0..8) |i| segs[i] = std.mem.readInt(u16, x.bytes[i * 2 ..][0..2], .big);
            break :blk .{ .v6 = .{ .segments = segs, .port = x.port } };
        },
    };
}

pub const PeerStore = struct {
    gpa: std.mem.Allocator,
    io: Io,
    mutex: Io.Mutex = .init,
    peers: std.AutoHashMap(Key, Entry),
    /// Host (port 0) -> unix seconds the ban ends.
    bans: std.AutoHashMap(Key, i64),
    dir: ?Io.Dir,
    allow_local: bool,

    pub fn init(gpa: std.mem.Allocator, io: Io, dir: ?Io.Dir, allow_local: bool) PeerStore {
        return .{
            .gpa = gpa,
            .io = io,
            .peers = std.AutoHashMap(Key, Entry).init(gpa),
            .bans = std.AutoHashMap(Key, i64).init(gpa),
            .dir = dir,
            .allow_local = allow_local,
        };
    }

    pub fn deinit(self: *PeerStore) void {
        self.peers.deinit();
        self.bans.deinit();
    }

    fn lock(self: *PeerStore) void {
        self.mutex.lockUncancelable(self.io);
    }
    fn unlock(self: *PeerStore) void {
        self.mutex.unlock(self.io);
    }

    fn nowS(self: *const PeerStore) i64 {
        return @divFloor(Io.Clock.real.now(self.io).toMilliseconds(), 1000);
    }

    // ---- recording

    /// Remembers `a` (e.g. learned from another peer). Unroutable addresses and
    /// banned hosts are ignored. Returns whether it was stored.
    pub fn learn(self: *PeerStore, a: net.IpAddress) bool {
        if (!acceptable(a, self.allow_local)) return false;
        self.lock();
        defer self.unlock();
        const k = Key.fromAddr(a);
        if (self.isBannedLocked(k)) return false;
        if (self.peers.contains(k)) return true;
        if (self.peers.count() >= MAX_PEERS) return false;
        self.peers.put(k, .{ .state = .healthy, .last_seen_s = 0 }) catch return false;
        return true;
    }

    /// Remembers `a` even if it is a private address: for peers the user named
    /// (`--seed`, `--peer`). Banned hosts are still refused.
    pub fn learnForced(self: *PeerStore, a: net.IpAddress) bool {
        self.lock();
        defer self.unlock();
        const k = Key.fromAddr(a);
        if (self.isBannedLocked(k)) return false;
        if (!self.peers.contains(k)) self.peers.put(k, .{ .state = .healthy, .last_seen_s = 0 }) catch return false;
        return true;
    }

    /// A connection to `a` worked.
    pub fn markHealthy(self: *PeerStore, a: net.IpAddress) void {
        self.lock();
        defer self.unlock();
        const k = Key.fromAddr(a);
        if (!acceptable(a, self.allow_local)) return;
        const prev = self.peers.get(k) orelse Entry{};
        self.peers.put(k, .{ .state = .healthy, .last_seen_s = self.nowS(), .last_attempt_s = prev.last_attempt_s }) catch {};
    }

    /// We're about to dial `a`.
    pub fn noteAttempt(self: *PeerStore, a: net.IpAddress) void {
        self.lock();
        defer self.unlock();
        if (self.peers.getPtr(Key.fromAddr(a))) |e| e.last_attempt_s = self.nowS();
    }

    /// A connection to `a` failed or dropped.
    pub fn markDefunct(self: *PeerStore, a: net.IpAddress) void {
        self.lock();
        defer self.unlock();
        const k = Key.fromAddr(a);
        if (self.peers.getPtr(k)) |e| e.state = .defunct;
    }

    pub fn ban(self: *PeerStore, a: net.IpAddress) void {
        self.lock();
        defer self.unlock();
        const k = Key.fromAddr(a);
        self.bans.put(k.host(), self.nowS() + BAN_SECS) catch {};
        // a banned host's addresses are dropped
        var doomed: std.ArrayList(Key) = .empty;
        defer doomed.deinit(self.gpa);
        var it = self.peers.keyIterator();
        while (it.next()) |p| if (std.meta.eql(p.host(), k.host())) doomed.append(self.gpa, p.*) catch {};
        for (doomed.items) |d| _ = self.peers.remove(d);
    }

    fn isBannedLocked(self: *PeerStore, k: Key) bool {
        const until = self.bans.get(k.host()) orelse return false;
        if (until > self.nowS()) return true;
        _ = self.bans.remove(k.host());
        return false;
    }

    /// Lifts a ban on `a`'s host (the reference's `unban_peer`).
    pub fn unban(self: *PeerStore, a: net.IpAddress) void {
        self.lock();
        defer self.unlock();
        _ = self.bans.remove(Key.fromAddr(a).host());
    }

    pub const Row = struct {
        addr: net.IpAddress,
        state: enum { healthy, defunct, banned },
        last_seen_s: i64,
        /// When the ban started (banned rows only).
        banned_at_s: i64 = 0,
    };

    /// Every known address and every banned host (banned hosts get `ban_port`),
    /// for the owner API's `get_peers`. Caller frees the slice.
    pub fn rows(self: *PeerStore, gpa: std.mem.Allocator, ban_port: u16) std.mem.Allocator.Error![]Row {
        self.lock();
        defer self.unlock();
        var out: std.ArrayList(Row) = .empty;
        errdefer out.deinit(gpa);
        var it = self.peers.iterator();
        while (it.next()) |e| try out.append(gpa, .{
            .addr = e.key_ptr.toAddr(),
            .state = if (e.value_ptr.state == .healthy) .healthy else .defunct,
            .last_seen_s = e.value_ptr.last_seen_s,
        });
        const now = self.nowS();
        var bi = self.bans.iterator();
        while (bi.next()) |e| {
            if (e.value_ptr.* <= now) continue;
            var k = e.key_ptr.*;
            k.port = ban_port;
            try out.append(gpa, .{ .addr = k.toAddr(), .state = .banned, .last_seen_s = 0, .banned_at_s = e.value_ptr.* - BAN_SECS });
        }
        return out.toOwnedSlice(gpa);
    }

    pub fn isBanned(self: *PeerStore, a: net.IpAddress) bool {
        self.lock();
        defer self.unlock();
        return self.isBannedLocked(Key.fromAddr(a));
    }

    // ---- queries

    /// Up to `n` addresses worth dialing, best first: peers that connected
    /// before (most recent first), then untried ones, then defunct ones that
    /// are due another try. Skips `exclude`, banned hosts and anything dialed
    /// in the last `MIN_REDIAL_SECS`. Caller frees the slice.
    pub fn candidates(self: *PeerStore, n: usize, exclude: []const net.IpAddress) std.mem.Allocator.Error![]net.IpAddress {
        self.lock();
        defer self.unlock();
        const now = self.nowS();
        const Item = struct { k: Key, rank: u8, seen: i64, jitter: u32 };
        var items: std.ArrayList(Item) = .empty;
        defer items.deinit(self.gpa);
        var it = self.peers.iterator();
        outer: while (it.next()) |e| {
            const v = e.value_ptr.*;
            for (exclude) |x| if (std.meta.eql(Key.fromAddr(x), e.key_ptr.*)) continue :outer;
            if (self.isBannedLocked(e.key_ptr.*)) continue;
            if (v.last_attempt_s != 0 and now - v.last_attempt_s < MIN_REDIAL_SECS) continue;
            const rank: u8 = switch (v.state) {
                .healthy => if (v.last_seen_s != 0) 0 else 1,
                .defunct => blk: {
                    if (v.last_attempt_s != 0 and now - v.last_attempt_s < RETRY_DEFUNCT_SECS) continue :outer;
                    break :blk 2;
                },
            };
            var jb: [4]u8 = undefined;
            self.io.random(&jb);
            try items.append(self.gpa, .{ .k = e.key_ptr.*, .rank = rank, .seen = v.last_seen_s, .jitter = std.mem.readInt(u32, &jb, .little) });
        }
        std.mem.sortUnstable(Item, items.items, {}, struct {
            fn lt(_: void, a: Item, b: Item) bool {
                if (a.rank != b.rank) return a.rank < b.rank;
                if (a.rank == 0 and a.seen != b.seen) return a.seen > b.seen;
                return a.jitter < b.jitter; // random among equals
            }
        }.lt);
        const out = try self.gpa.alloc(net.IpAddress, @min(n, items.items.len));
        for (out, 0..) |*o, i| o.* = items.items[i].k.toAddr();
        return out;
    }

    /// Whether any address is ready to dial right now.
    pub fn hasCandidates(self: *PeerStore) bool {
        const c = self.candidates(1, &.{}) catch return false;
        defer self.gpa.free(c);
        return c.len > 0;
    }

    /// Addresses to hand out for `GetPeerAddrs` (healthy, recently seen). Caller frees.
    pub fn forSharing(self: *PeerStore, max: usize) std.mem.Allocator.Error![]msg.PeerAddr {
        self.lock();
        defer self.unlock();
        var out: std.ArrayList(msg.PeerAddr) = .empty;
        errdefer out.deinit(self.gpa);
        var it = self.peers.iterator();
        while (it.next()) |e| {
            if (out.items.len >= max) break;
            if (e.value_ptr.state != .healthy or e.value_ptr.last_seen_s == 0) continue; // only peers we actually reached
            if (self.isBannedLocked(e.key_ptr.*)) continue;
            try out.append(self.gpa, toPeerAddr(e.key_ptr.toAddr()));
        }
        return out.toOwnedSlice(self.gpa);
    }

    /// Known addresses by state, plus banned hosts (for the peer monitor line).
    pub fn stats(self: *PeerStore) struct { healthy: usize, defunct: usize, banned: usize } {
        self.lock();
        defer self.unlock();
        var h: usize = 0;
        var d: usize = 0;
        var it = self.peers.valueIterator();
        while (it.next()) |e| switch (e.state) {
            .healthy => h += 1,
            .defunct => d += 1,
        };
        var b: usize = 0;
        const now = self.nowS();
        var bi = self.bans.valueIterator();
        while (bi.next()) |until| {
            if (until.* > now) b += 1;
        }
        return .{ .healthy = h, .defunct = d, .banned = b };
    }

    pub fn count(self: *PeerStore) usize {
        self.lock();
        defer self.unlock();
        return self.peers.count();
    }

    // ---- persistence

    const FILE = "peers.txt";

    pub fn save(self: *PeerStore) !void {
        const dir = self.dir orelse return;
        self.lock();
        defer self.unlock();
        var aw: Io.Writer.Allocating = .init(self.gpa);
        defer aw.deinit();
        const w = &aw.writer;
        var it = self.peers.iterator();
        while (it.next()) |e| {
            try w.print("P {s} {x} {d} {c} {d} {d}\n", .{ if (e.key_ptr.v6) "6" else "4", &e.key_ptr.ip, e.key_ptr.port, @intFromEnum(e.value_ptr.state), e.value_ptr.last_seen_s, e.value_ptr.last_attempt_s });
        }
        const now = self.nowS();
        var bi = self.bans.iterator();
        while (bi.next()) |e| {
            if (e.value_ptr.* <= now) continue;
            try w.print("B {s} {x} {d}\n", .{ if (e.key_ptr.v6) "6" else "4", &e.key_ptr.ip, e.value_ptr.* });
        }
        try @import("fsutil.zig").saveViaTempFile(self.gpa, self.io, dir, FILE, aw.written());
    }

    /// Loads `peers.txt` if present; malformed lines are skipped.
    pub fn load(self: *PeerStore) void {
        const dir = self.dir orelse return;
        const bytes = @import("fsutil.zig").readAll(self.gpa, self.io, dir, FILE) catch return;
        defer self.gpa.free(bytes);
        self.lock();
        defer self.unlock();
        var lines = std.mem.splitScalar(u8, bytes, '\n');
        while (lines.next()) |line| self.loadLine(line) catch {};
    }

    fn parseKey(fam: []const u8, ip_hex: []const u8, port: u16) !Key {
        var k: Key = .{ .v6 = std.mem.eql(u8, fam, "6"), .ip = undefined, .port = port };
        if (ip_hex.len != 32) return error.BadLine;
        _ = try std.fmt.hexToBytes(&k.ip, ip_hex);
        return k;
    }

    fn loadLine(self: *PeerStore, line: []const u8) !void {
        var f = std.mem.tokenizeScalar(u8, line, ' ');
        const kind = f.next() orelse return;
        if (std.mem.eql(u8, kind, "P")) {
            const fam = f.next() orelse return error.BadLine;
            const ip = f.next() orelse return error.BadLine;
            const port = try std.fmt.parseInt(u16, f.next() orelse return error.BadLine, 10);
            const st = (f.next() orelse return error.BadLine)[0];
            const seen = try std.fmt.parseInt(i64, f.next() orelse return error.BadLine, 10);
            const attempt: i64 = if (f.next()) |x| (std.fmt.parseInt(i64, x, 10) catch 0) else 0;
            const k = try parseKey(fam, ip, port);
            if (!acceptable(k.toAddr(), self.allow_local)) return;
            try self.peers.put(k, .{ .state = if (st == 'D') .defunct else .healthy, .last_seen_s = seen, .last_attempt_s = attempt });
        } else if (std.mem.eql(u8, kind, "B")) {
            const fam = f.next() orelse return error.BadLine;
            const ip = f.next() orelse return error.BadLine;
            const until = try std.fmt.parseInt(i64, f.next() orelse return error.BadLine, 10);
            try self.bans.put(try parseKey(fam, ip, 0), until);
        }
    }
};

// ------------------------------------------------------------------ tests

const testing = std.testing;

fn a4(a: u8, b: u8, c: u8, d: u8, port: u16) net.IpAddress {
    return .{ .ip4 = .{ .bytes = .{ a, b, c, d }, .port = port } };
}

test "only routable addresses are learned" {
    try testing.expect(acceptable(a4(8, 8, 8, 8, 3414), false));
    try testing.expect(!acceptable(a4(8, 8, 8, 8, 0), false));
    try testing.expect(!acceptable(a4(127, 0, 0, 1, 3414), false));
    try testing.expect(!acceptable(a4(192, 168, 1, 5, 3414), false));
    try testing.expect(!acceptable(a4(10, 0, 0, 1, 3414), false));
    try testing.expect(!acceptable(a4(172, 20, 0, 1, 3414), false));
    try testing.expect(!acceptable(a4(0, 0, 0, 0, 3414), false));
    try testing.expect(!acceptable(a4(239, 1, 1, 1, 3414), false));
    try testing.expect(acceptable(a4(127, 0, 0, 1, 3414), true));
}

test "learn, ban by host, candidates, persistence" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var s = PeerStore.init(gpa, io, tmp.dir, false);
    defer s.deinit();
    try testing.expect(s.learn(a4(8, 8, 8, 8, 3414)));
    try testing.expect(s.learn(a4(8, 8, 4, 4, 3414)));
    try testing.expect(!s.learn(a4(10, 1, 1, 1, 3414)));
    s.markHealthy(a4(8, 8, 4, 4, 3414));
    s.markDefunct(a4(8, 8, 8, 8, 3414));

    // a peer we reached comes first; the defunct one is due a retry
    const c = try s.candidates(10, &.{});
    defer gpa.free(c);
    try testing.expectEqual(@as(usize, 2), c.len);
    try testing.expect(std.meta.eql(Key.fromAddr(c[0]), Key.fromAddr(a4(8, 8, 4, 4, 3414))));
    try testing.expect(std.meta.eql(Key.fromAddr(c[1]), Key.fromAddr(a4(8, 8, 8, 8, 3414))));

    // nothing is redialled straight after an attempt
    s.noteAttempt(a4(8, 8, 4, 4, 3414));
    s.noteAttempt(a4(8, 8, 8, 8, 3414));
    const none = try s.candidates(10, &.{});
    defer gpa.free(none);
    try testing.expectEqual(@as(usize, 0), none.len);

    // bans are per host and drop that host's entries
    s.ban(a4(8, 8, 4, 4, 9999));
    try testing.expect(s.isBanned(a4(8, 8, 4, 4, 3414)));
    try testing.expect(!s.learn(a4(8, 8, 4, 4, 3414)));
    try testing.expect(!s.isBanned(a4(8, 8, 8, 8, 3414)));

    try s.save();
    var s2 = PeerStore.init(gpa, io, tmp.dir, false);
    defer s2.deinit();
    s2.load();
    try testing.expect(s2.isBanned(a4(8, 8, 4, 4, 1)));
    try testing.expectEqual(@as(usize, 1), s2.count());
    const shared = try s2.forSharing(10);
    defer gpa.free(shared);
    try testing.expectEqual(@as(usize, 0), shared.len); // the one left is defunct
}

test "peer address conversions and the wire list round trip" {
    const gpa = testing.allocator;
    const a = a4(8, 8, 4, 4, 3414);
    try testing.expect(std.meta.eql(Key.fromAddr(fromPeerAddr(toPeerAddr(a))), Key.fromAddr(a)));
    const v6: net.IpAddress = .{ .ip6 = .{ .bytes = .{ 0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, .port = 3414 } };
    try testing.expect(std.meta.eql(Key.fromAddr(fromPeerAddr(toPeerAddr(v6))), Key.fromAddr(v6)));

    const list = [_]msg.PeerAddr{ toPeerAddr(a), toPeerAddr(v6) };
    const bytes = try @import("ser.zig").serVec(gpa, msg.PeerAddrs{ .peers = &list }, @import("ser.zig").ProtocolVersion.local());
    defer gpa.free(bytes);
    var r = @import("ser.zig").Reader.init(gpa, bytes, @import("ser.zig").ProtocolVersion.local());
    const back = try msg.PeerAddrs.read(&r);
    defer gpa.free(back.peers);
    try testing.expectEqual(@as(usize, 2), back.peers.len);
    try testing.expect(std.meta.eql(Key.fromAddr(fromPeerAddr(back.peers[1])), Key.fromAddr(v6)));
}
