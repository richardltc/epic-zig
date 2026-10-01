//! Finding peers: learning the network's seed addresses and, for a node started
//! without `--peer`, choosing a peer to sync from.
const std = @import("std");
const Io = std.Io;
const net = Io.net;
const seeds = @import("seeds.zig");
const client = @import("p2p_client.zig");
const consensus = @import("consensus.zig");
const Node = @import("node.zig").Node;
const Chain = @import("chain.zig").Chain;
const Difficulty = @import("pow_types.zig").Difficulty;

const logging = @import("logging.zig");
fn log(comptime fmt: []const u8, args: anytype) void {
    logging.info(fmt, args);
}
fn warn(comptime fmt: []const u8, args: anytype) void {
    logging.warn(fmt, args);
}
fn debug(comptime fmt: []const u8, args: anytype) void {
    logging.debug(fmt, args);
}

/// Adds the network seeds (and any user-named ones) to the peer store; returns
/// how many addresses that added or refreshed.
pub fn learnSeeds(gpa: std.mem.Allocator, io: Io, node: *Node, chain: consensus.ChainType, use_seeds: bool, extra: []const net.IpAddress) usize {
    var n: usize = 0;
    for (extra) |a| if (node.store.learnForced(a)) {
        n += 1;
    };
    if (!use_seeds) return n;
    const addrs = seeds.gather(gpa, io, chain) catch |e| {
        warn("Failed to resolve seed addresses: {s}", .{@errorName(e)});
        return n;
    };
    defer gpa.free(addrs);
    for (addrs) |a| if (node.store.learn(a)) {
        n += 1;
    };
    return n;
}

fn work(d: Difficulty) u128 {
    var t: u128 = 0;
    for (d.num) |x| t += x orelse 0;
    return t;
}

/// One connection attempt, run on its own thread (connects can hang for minutes).
const Attempt = struct {
    gpa: std.mem.Allocator,
    io: Io,
    chain: *Chain,
    addr: net.IpAddress,
    conn: ?*client.Conn = null,
    done: std.atomic.Value(bool) = .init(false),

    fn run(self: *Attempt) void {
        self.conn = client.Conn.connect(self.gpa, self.io, self.addr, self.chain.cfg.chain, self.chain.genesis.hash(), self.chain.genesis.header.pow.total_difficulty) catch null;
        self.done.store(true, .release);
    }
};

/// Picks a peer to sync from when none was named: tries up to `BATCH`
/// candidates at once, takes the connection with the most chain work, and
/// retries (with seeds) until one answers. Returns the connection and the
/// address it reached. Never returns while the network is unreachable.
pub fn findSyncPeer(gpa: std.mem.Allocator, io: Io, node: *Node, use_seeds: bool, extra: []const net.IpAddress) !struct { conn: *client.Conn, addr: net.IpAddress } {
    const BATCH = 6;
    const chain = node.chain;
    var round: u32 = 0;
    while (true) : (round += 1) {
        if (round == 0 or !node.store.hasCandidates()) {
            const n = learnSeeds(gpa, io, node, chain.cfg.chain, use_seeds, extra);
            log("Retrieved seed addresses: {d}; {d} peer(s) known", .{ n, node.store.count() });
        }
        const addrs = try node.store.candidates(BATCH, &.{});
        defer gpa.free(addrs);
        if (addrs.len > 0) {
            var attempts: [BATCH]Attempt = undefined;
            var spawned: usize = 0;
            for (addrs) |a| {
                node.store.noteAttempt(a);
                attempts[spawned] = .{ .gpa = gpa, .io = io, .chain = chain, .addr = a };
                const t = std.Thread.spawn(.{}, Attempt.run, .{&attempts[spawned]}) catch continue;
                t.detach();
                spawned += 1;
            }
            // wait for the first success, then a moment more for better ones; give up after a while
            var first_ok_ms: ?i64 = null;
            const t0 = Io.Clock.awake.now(io).toMilliseconds();
            while (true) {
                io.sleep(.fromMilliseconds(100), .awake) catch {};
                const now = Io.Clock.awake.now(io).toMilliseconds();
                var finished: usize = 0;
                var any_ok = false;
                for (attempts[0..spawned]) |*a| if (a.done.load(.acquire)) {
                    finished += 1;
                    if (a.conn != null) any_ok = true;
                };
                if (any_ok and first_ok_ms == null) first_ok_ms = now;
                if (finished == spawned) break;
                if (first_ok_ms) |f| if (now - f > 4000) break;
                if (now - t0 > 30_000) break;
            }
            // choose the best finished connection, close the rest
            var best: ?usize = null;
            for (attempts[0..spawned], 0..) |*a, i| {
                if (!a.done.load(.acquire)) {
                    node.store.markDefunct(a.addr); // still hanging: its thread will leak a connection at worst
                    continue;
                }
                const c = a.conn orelse {
                    node.store.markDefunct(a.addr);
                    continue;
                };
                if (best == null or work(c.peer.total_difficulty) > work(attempts[best.?].conn.?.peer.total_difficulty)) best = i;
            }
            if (best) |b| {
                for (attempts[0..spawned], 0..) |*a, i| {
                    if (i == b or !a.done.load(.acquire)) continue;
                    if (a.conn) |c| {
                        node.store.markHealthy(a.addr);
                        c.close();
                    }
                }
                const a = attempts[b];
                node.store.markHealthy(a.addr);
                log("Minimum peers requirement met, proceeding with sync. Sync peer: {f} ({s})", .{ a.addr, a.conn.?.peer.userAgent() });
                return .{ .conn = a.conn.?, .addr = a.addr };
            }
        }
        const wait: u64 = @min(5 + round * 5, 60);
        warn("Not enough outbound peers available. Waiting for more peers to connect... (retrying in {d}s)", .{wait});
        io.sleep(.fromSeconds(@intCast(wait)), .awake) catch {};
    }
}
