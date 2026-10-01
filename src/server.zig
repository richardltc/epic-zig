//! The peer-facing side of the node: accepts inbound peers, optionally dials
//! outbound ones, and runs the same message loop for both (headers, blocks,
//! archives, gossip, pings, peer addresses). Not yet done: kernel data, Tor.
//!
//! One thread per connection; the chain is shared through `Chain.lock()`.
const std = @import("std");
const N = @import("logging.zig").num;
const Io = std.Io;
const net = Io.net;
const chain_mod = @import("chain.zig");
const client = @import("p2p_client.zig");
const msg = @import("p2p_msg.zig");

const Chain = chain_mod.Chain;
const Node = @import("node.zig").Node;
const Conn = client.Conn;
const discovery = @import("discovery.zig");

const MAX_INBOUND: u32 = 32;

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

pub const Server = struct {
    gpa: std.mem.Allocator,
    io: Io,
    chain: *Chain,
    node: *Node,
    listener: ?net.Server = null,
    active: std.atomic.Value(u32) = .init(0),
    /// Dial threads currently running (outbound peers besides the sync peer).
    dialing: std.atomic.Value(u32) = .init(0),
    max_outbound: u32 = 0,
    use_seeds: bool = false,
    extra_seeds: []const net.IpAddress = &.{},

    pub fn create(gpa: std.mem.Allocator, io: Io, node: *Node) !*Server {
        const self = try gpa.create(Server);
        self.* = .{ .gpa = gpa, .io = io, .chain = node.chain, .node = node };
        return self;
    }

    /// Starts listening on `addr` and accepting peers on background threads.
    pub fn listen(self: *Server, addr: net.IpAddress) !void {
        self.listener = try addr.listen(self.io, .{});
        const t = try std.Thread.spawn(.{}, acceptLoop, .{self});
        t.detach();
    }

    /// Keeps up to `n` outbound peers: dials addresses from the peer store, asks
    /// connected peers for more every few minutes, and falls back to the network's
    /// seeds (DNS, then a static list) when it has nobody to try.
    pub fn startDiscovery(self: *Server, n: u32, use_seeds: bool, extra_seeds: []const net.IpAddress) !void {
        self.max_outbound = n;
        self.use_seeds = use_seeds;
        self.extra_seeds = extra_seeds;
        const t = try std.Thread.spawn(.{}, discoveryLoop, .{self});
        t.detach();
    }

    const PEERLIST_EVERY_MS: i64 = 5 * 60 * 1000;
    const SEED_EVERY_MS: i64 = 60 * 1000;

    fn discoveryLoop(self: *Server) void {
        var last_peerlist: i64 = 0;
        var last_seed: i64 = -SEED_EVERY_MS;
        while (true) {
            self.io.sleep(.fromSeconds(10), .awake) catch {};
            const now = Io.Clock.awake.now(self.io).toMilliseconds();
            var connected: [64]net.IpAddress = undefined;
            const nc = self.node.peers.remotes(&connected);

            // nobody to try and nobody to talk to: go back to the seeds
            if ((nc == 0 or !self.node.store.hasCandidates()) and now - last_seed >= SEED_EVERY_MS) {
                last_seed = now;
                const n = discovery.learnSeeds(self.gpa, self.io, self.node, self.chain.cfg.chain, self.use_seeds, self.extra_seeds);
                if (n > 0) log("Retrieved seed addresses: {d}; {d} peer(s) known", .{ n, self.node.store.count() });
            }

            // ask everyone we're connected to for their friends
            if (now - last_peerlist >= PEERLIST_EVERY_MS) {
                last_peerlist = now;
                _ = self.node.peers.broadcast(null, .get_peer_addrs, msg.GetPeerAddrs{ .capabilities = .{ .bits = msg.Capabilities.FULL_NODE } });
            }

            const running = self.dialing.load(.monotonic);
            if (running >= self.max_outbound) continue;
            const addrs = self.node.store.candidates(self.max_outbound - running, connected[0..nc]) catch continue;
            defer self.gpa.free(addrs);
            for (addrs) |a| {
                self.node.store.noteAttempt(a);
                _ = self.dialing.fetchAdd(1, .monotonic);
                const t = std.Thread.spawn(.{}, dial, .{ self, a }) catch {
                    _ = self.dialing.fetchSub(1, .monotonic);
                    continue;
                };
                t.detach();
            }
        }
    }

    /// Connects to `addr` and serves the connection until it ends.
    fn dial(self: *Server, addr: net.IpAddress) void {
        defer _ = self.dialing.fetchSub(1, .monotonic);
        const head = self.chain.head() catch return;
        const conn = Conn.connect(self.gpa, self.io, addr, self.chain.cfg.chain, self.chain.genesis.hash(), head.total_difficulty) catch |e| {
            debug("Failed to connect to peer {f}: {s}", .{ addr, @errorName(e) });
            self.node.store.markDefunct(addr);
            return;
        };
        defer conn.close();
        self.node.store.markHealthy(addr);
        self.node.peers.add(conn);
        defer self.node.peers.remove(conn);
        log("Connected to peer {f} ({s})", .{ addr, conn.peer.userAgent() });
        conn.send(.get_peer_addrs, msg.GetPeerAddrs{ .capabilities = .{ .bits = msg.Capabilities.FULL_NODE } }) catch return;
        self.runLoop(conn);
        self.node.store.markDefunct(addr);
    }

    fn acceptLoop(self: *Server) void {
        while (true) {
            const stream = self.listener.?.accept(self.io) catch |e| {
                warn("Failed to accept a connection: {s}", .{@errorName(e)});
                self.io.sleep(.fromSeconds(1), .awake) catch {};
                continue;
            };
            if (self.active.load(.monotonic) >= MAX_INBOUND or self.node.store.isBanned(stream.socket.address)) {
                stream.close(self.io);
                continue;
            }
            _ = self.active.fetchAdd(1, .monotonic);
            const t = std.Thread.spawn(.{}, serveConn, .{ self, stream }) catch {
                stream.close(self.io);
                _ = self.active.fetchSub(1, .monotonic);
                continue;
            };
            t.detach();
        }
    }

    fn serveConn(self: *Server, stream: net.Stream) void {
        defer _ = self.active.fetchSub(1, .monotonic);
        const head = self.chain.head() catch {
            stream.close(self.io);
            return;
        };
        const remote = stream.socket.address;
        self.node.peers.addPending(stream);
        const accepted = Conn.accept(self.gpa, self.io, stream, self.chain.cfg.chain, self.chain.genesis.hash(), head.total_difficulty);
        self.node.peers.removePending(stream);
        const conn = accepted catch |e| {
            debug("Inbound handshake failed: {s}", .{@errorName(e)});
            if (self.node.deservesBan(e)) self.node.banPeer(remote, @errorName(e));
            return;
        };
        defer conn.close();
        self.node.peers.add(conn);
        defer self.node.peers.remove(conn);
        log("Inbound peer connected: {f} ({s})", .{ remote, conn.peer.userAgent() });
        // like the reference: the peer's reachable address is its IP plus the
        // port it says it listens on; remember it so we can share and dial it
        if (conn.peer.listen_port != 0) {
            var a = remote;
            a.setPort(conn.peer.listen_port);
            _ = self.node.store.learn(a);
        }
        self.runLoop(conn);
    }

    /// Serves `conn` until it ends; bans the peer if it misbehaved.
    fn runLoop(self: *Server, conn: *Conn) void {
        while (true) {
            const m = conn.recv() catch |e| {
                debug("Peer disconnected: {s}", .{@errorName(e)});
                if (self.node.deservesBan(e)) if (conn.remote) |a| self.node.banPeer(a, @errorName(e));
                return;
            };
            defer m.deinit(self.gpa);
            self.handle(conn, m) catch |e| {
                warn("Dropping peer after a bad {s} message: {s}", .{ @tagName(m.msg_type), @errorName(e) });
                if (self.node.deservesBan(e)) if (conn.remote) |a| self.node.banPeer(a, @errorName(e));
                return;
            };
        }
    }

    fn handle(self: *Server, conn: *Conn, m: client.Message) !void {
        const chain = self.chain;
        var r = conn.readerFor(m.body);
        switch (m.msg_type) {
            .ping => {
                const p = try msg.Ping.read(&r);
                conn.noteLive(p.total_difficulty, p.height);
                const head = try chain.head();
                try conn.send(.pong, msg.Pong{
                    .total_difficulty = head.total_difficulty,
                    .height = head.height,
                    .local_timestamp = @divTrunc(Io.Clock.real.now(self.io).toMilliseconds(), 1000),
                });
            },
            .pong => {
                const p = try msg.Pong.read(&r);
                conn.noteLive(p.total_difficulty, p.height);
            },
            .get_peer_addrs => {
                _ = try msg.GetPeerAddrs.read(&r);
                const shared = try self.node.store.forSharing(msg.MAX_PEER_ADDRS);
                defer self.gpa.free(shared);
                try conn.send(.peer_addrs, msg.PeerAddrs{ .peers = shared });
            },
            .get_headers => {
                const loc = try msg.Locator.read(&r);
                defer self.gpa.free(loc.hashes);
                try self.sendHeaders(conn, .headers, loc.hashes, 0);
            },
            .get_headers_fast_sync => {
                const loc = try msg.LocatorFastSync.read(&r);
                defer self.gpa.free(loc.hashes);
                try self.sendHeaders(conn, .fast_headers, loc.hashes, loc.offset);
            },
            .get_block => {
                const req = try msg.HashMsg.read(&r);
                var b = (try chain.db.getBlock(chain.db.store, req.hash)) orelse return;
                defer b.deinit(self.gpa);
                try conn.send(.block, b);
            },
            .tx_hash_set_request => try self.sendArchive(conn),
            .transaction, .stem_transaction, .transaction_kernel, .get_transaction, .header, .compact_block, .block, .peer_addrs => try self.node.handleGossip(conn, m),
            .get_compact_block => {
                const req = try msg.HashMsg.read(&r);
                var b = (try chain.db.getBlock(chain.db.store, req.hash)) orelse return;
                defer b.deinit(self.gpa);
                var nonce_bytes: [8]u8 = undefined;
                self.io.random(&nonce_bytes);
                var cb = try @import("compact_block.zig").CompactBlock.fromBlock(self.gpa, b, std.mem.readInt(u64, &nonce_bytes, .little));
                defer cb.deinit(self.gpa);
                try conn.send(.compact_block, cb);
            },
            // Not served (yet): compact blocks, the pool, kernel data. Silence is what
            // the reference does for things it doesn't have.
            else => {},
        }
    }

    fn sendHeaders(self: *Server, conn: *Conn, t: msg.MsgType, locator: []const @import("hash.zig").Hash, offset: u8) !void {
        self.chain.lock();
        const hs = self.chain.locateHeaders(locator, offset, msg.MAX_BLOCK_HEADERS);
        self.chain.unlock();
        const headers = try hs;
        defer self.gpa.free(headers);
        try conn.send(t, msg.Headers{ .headers = headers });
    }

    fn sendArchive(self: *Server, conn: *Conn) !void {
        const chain = self.chain;
        var name_buf: [96]u8 = undefined;
        chain.lock();
        const made = blk: {
            const header = chain.archiveHeader() catch |e| break :blk @as(anyerror!Made, e);
            const z = chain.txhashsetArchive(header, &name_buf) catch |e| break :blk @as(anyerror!Made, e);
            break :blk @as(anyerror!Made, Made{ .hash = header.hash(), .height = header.height, .name = z.name, .bytes = z.bytes });
        };
        chain.unlock();
        const info = made catch |e| {
            warn("Couldn't produce txhashset data right now: {s}", .{@errorName(e)});
            return;
        };

        var f = try chain.root.openFile(self.io, info.name, .{ .mode = .read_only });
        defer f.close(self.io);
        log("Sending txhashset archive at height {f} ({f} MiB)", .{ N(info.height), N(info.bytes >> 20) });
        conn.lockWrite();
        defer conn.unlockWrite();
        try conn.sendLocked(.tx_hash_set_archive, msg.TxHashSetArchive{ .hash = info.hash, .height = info.height, .bytes = info.bytes });
        const buf = try self.gpa.alloc(u8, 1 << 20);
        defer self.gpa.free(buf);
        var off: u64 = 0;
        while (off < info.bytes) {
            const n: usize = @intCast(@min(info.bytes - off, buf.len));
            if ((try f.readPositionalAll(self.io, buf[0..n], off)) != n) return error.UnexpectedEndOfFile;
            try conn.writer.interface.writeAll(buf[0..n]);
            off += n;
        }
        try conn.writer.interface.flush();
        log("Txhashset archive sent", .{});
    }

    const Made = struct { hash: @import("hash.zig").Hash, height: u64, name: []const u8, bytes: u64 };
};
