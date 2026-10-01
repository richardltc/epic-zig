//! The set of live peer connections (inbound and outbound), for broadcasts.
const std = @import("std");
const Io = std.Io;
const client = @import("p2p_client.zig");
const msg = @import("p2p_msg.zig");

const Conn = client.Conn;

/// A quiet connection is pinged after this long and dropped after DROP_MS.
pub const PING_AFTER_MS: i64 = 30_000;
pub const DROP_MS: i64 = 120_000;
/// A peer must finish the handshake within this long.
pub const HANDSHAKE_MS: i64 = 15_000;

pub const Peers = struct {
    gpa: std.mem.Allocator,
    io: Io,
    mutex: Io.Mutex = .init,
    conns: std.ArrayList(*Conn) = .empty,
    /// Inbound streams that haven't finished the handshake, with their deadline.
    pending: std.ArrayList(Pending) = .empty,

    const Pending = struct { stream: std.Io.net.Stream, deadline_ms: i64 };

    pub fn init(gpa: std.mem.Allocator, io: Io) Peers {
        return .{ .gpa = gpa, .io = io };
    }

    pub fn deinit(self: *Peers) void {
        self.conns.deinit(self.gpa);
        self.pending.deinit(self.gpa);
    }

    fn nowMs(self: *const Peers) i64 {
        return Io.Clock.awake.now(self.io).toMilliseconds();
    }

    pub fn addPending(self: *Peers, s: std.Io.net.Stream) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.pending.append(self.gpa, .{ .stream = s, .deadline_ms = self.nowMs() + HANDSHAKE_MS }) catch {};
    }

    pub fn removePending(self: *Peers, s: std.Io.net.Stream) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.pending.items, 0..) |p, i| if (p.stream.socket.handle == s.socket.handle) {
            _ = self.pending.swapRemove(i);
            return;
        };
    }

    /// Liveness sweep (run every few seconds): kills handshakes that took too
    /// long, pings quiet peers and drops peers silent for too long. `ping` is
    /// what to send.
    pub fn reap(self: *Peers, ping: msg.Ping) struct { pinged: usize, dropped: usize } {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const now = self.nowMs();
        var pinged: usize = 0;
        var dropped: usize = 0;
        for (self.pending.items) |p| {
            if (now > p.deadline_ms) {
                p.stream.shutdown(self.io, .both) catch {};
                dropped += 1;
            }
        }
        for (self.conns.items) |c| {
            if (c.exempt) continue;
            const idle = now - c.last_recv_ms.load(.monotonic);
            if (idle > DROP_MS) {
                c.kill();
                dropped += 1;
            } else if (idle > PING_AFTER_MS) {
                if (c.send(.ping, ping)) |_| pinged += 1 else |_| {}
            }
        }
        return .{ .pinged = pinged, .dropped = dropped };
    }

    /// Cuts every connection to the host of `addr` (after a ban).
    pub fn killHost(self: *Peers, addr: std.Io.net.IpAddress) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        var n: usize = 0;
        for (self.conns.items) |c| {
            const r = c.remote orelse continue;
            if (sameHost(r, addr)) {
                c.kill();
                n += 1;
            }
        }
        return n;
    }

    pub fn sameHost(a: std.Io.net.IpAddress, b: std.Io.net.IpAddress) bool {
        return switch (a) {
            .ip4 => |x| b == .ip4 and std.mem.eql(u8, &x.bytes, &b.ip4.bytes),
            .ip6 => |x| b == .ip6 and std.mem.eql(u8, &x.bytes, &b.ip6.bytes),
        };
    }

    /// The first outbound connection's address (the Dandelion relay candidate).
    pub fn firstOutbound(self: *Peers) ?std.Io.net.IpAddress {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.conns.items) |c| if (c.outbound) if (c.remote) |r| return r;
        return null;
    }

    /// Whether a live connection to exactly `addr` exists.
    pub fn isConnectedTo(self: *Peers, addr: std.Io.net.IpAddress) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.conns.items) |c| if (c.remote) |r| {
            if (r.eql(&addr)) return true;
        };
        return false;
    }

    /// Sends `body` as message `t` to the connection to `addr`, if there is one.
    pub fn sendTo(self: *Peers, addr: std.Io.net.IpAddress, t: msg.MsgType, body: anytype) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.conns.items) |c| if (c.remote) |r| {
            if (r.eql(&addr)) return c.send(t, body);
        };
        return error.NotConnected;
    }

    /// Remote addresses of live connections (for not dialing them twice).
    pub fn remotes(self: *Peers, out: []std.Io.net.IpAddress) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        var n: usize = 0;
        for (self.conns.items) |c| {
            if (n >= out.len) break;
            if (c.remote) |r| {
                out[n] = r;
                n += 1;
            }
        }
        return n;
    }

    pub fn add(self: *Peers, c: *Conn) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.conns.append(self.gpa, c) catch {};
    }

    /// Must be called before the connection is closed.
    pub fn remove(self: *Peers, c: *Conn) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.conns.items, 0..) |x, i| if (x == c) {
            _ = self.conns.swapRemove(i);
            return;
        };
    }

    /// Connected peers split by direction.
    pub fn directions(self: *Peers) struct { inbound: usize, outbound: usize } {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        var out: usize = 0;
        for (self.conns.items) |c| {
            if (c.outbound) out += 1;
        }
        return .{ .inbound = self.conns.items.len - out, .outbound = out };
    }

    /// The highest chain any connected peer has told us about (0 if none has).
    pub fn maxHeight(self: *Peers) u64 {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        var best: u64 = 0;
        for (self.conns.items) |c| best = @max(best, c.live().height);
        return best;
    }

    pub fn count(self: *Peers) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.conns.items.len;
    }

    /// Announces a tx: its first kernel's hash to peers that understand that,
    /// the whole tx to the rest (`send_transaction`).
    pub fn broadcastTx(self: *Peers, skip: ?*Conn, tx: @import("transaction.zig").Transaction) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (tx.body.kernels.len == 0) return 0;
        const kh = tx.body.kernels[0].hash();
        var n: usize = 0;
        for (self.conns.items) |c| {
            if (c == skip) continue;
            const sent = if (c.peer.capabilities.has(msg.Capabilities.TX_KERNEL_HASH))
                c.send(.transaction_kernel, msg.HashMsg{ .hash = kh })
            else
                c.send(.transaction, tx);
            if (sent) |_| n += 1 else |_| {}
        }
        return n;
    }

    /// Sends `body` as message `t` to every peer except `skip`. Peers that
    /// fail are left for their own thread to notice and drop.
    pub fn broadcast(self: *Peers, skip: ?*Conn, t: msg.MsgType, body: anytype) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        var n: usize = 0;
        for (self.conns.items) |c| {
            if (c == skip) continue;
            if (c.send(t, body)) |_| n += 1 else |_| {}
        }
        return n;
    }
};
