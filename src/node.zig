//! The node's shared state for the network side: the chain, the transaction
//! pool, and the live peers; plus the gossip handlers (transactions, kernel
//! announcements) used by both the server threads and the sync connection.
const std = @import("std");
const N = @import("logging.zig").num;
const Io = std.Io;
const chain_mod = @import("chain.zig");
const client = @import("p2p_client.zig");
const msg = @import("p2p_msg.zig");
const pool_mod = @import("pool.zig");
const peers_mod = @import("peers.zig");
const block = @import("block.zig");
const tx_mod = @import("transaction.zig");
const hash_mod = @import("hash.zig");
const chain_types = @import("chain_types.zig");
const compact_block = @import("compact_block.zig");
const peer_store = @import("peer_store.zig");
const misbehavior = @import("misbehavior.zig");
const dandelion = @import("dandelion.zig");
const consensus = @import("consensus.zig");

const Chain = chain_mod.Chain;
const Conn = client.Conn;
const Hash = hash_mod.Hash;
const Transaction = tx_mod.Transaction;

/// A node is "syncing" while the bodies are this far behind the headers; it
/// ignores gossiped transactions then (`is_syncing`).
const SYNCING_LAG: u64 = 10;

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

pub const Node = struct {
    gpa: std.mem.Allocator,
    io: Io,
    chain: *Chain,
    pool: pool_mod.TransactionPool,
    peers: peers_mod.Peers,
    /// The connection the tx being added came from; not echoed back to it.
    /// Only read and written while holding the pool lock.
    tx_source: ?*Conn = null,
    /// Blocks we asked a peer for recently (hash -> ms), so several peers
    /// announcing the same block don't make us fetch it repeatedly.
    requested: std.AutoHashMap([32]u8, i64),
    requested_mu: Io.Mutex = .init,
    /// Known peers and bans (persisted in the data dir).
    store: peer_store.PeerStore,
    /// Dandelion: stem or fluff for the current epoch, and the relay peer.
    epoch: dandelion.Epoch = .{ .cfg = .{} },
    epoch_mu: Io.Mutex = .init,
    /// Where we listen for peers, for log lines ("-" when not listening).
    listen_desc: []const u8 = "-",
    /// What the sync is doing, for the API's `get_status` (guarded by `sync_mu`).
    sync_status: SyncStatus = .awaiting_peers,
    sync_mu: Io.Mutex = .init,

    /// The reference's `SyncStatus`, as far as the API reports it.
    pub const SyncStatus = union(enum) {
        awaiting_peers,
        header_sync: struct { current_height: u64, highest_height: u64 },
        txhashset_download: struct { downloaded_size: u64, total_size: u64 },
        /// Validating and installing a downloaded txhashset (the reference's
        /// setup/validation/save stages, which its API reports as "syncing").
        txhashset_processing,
        body_sync: struct { current_height: u64, highest_height: u64 },
        /// Tidying the chain after a sync finishes (as the reference does).
        compacting,
        no_sync,
        shutdown,
    };

    pub fn setSyncStatus(self: *Node, s: SyncStatus) void {
        self.sync_mu.lockUncancelable(self.io);
        defer self.sync_mu.unlock(self.io);
        self.sync_status = s;
    }

    pub fn syncStatus(self: *Node) SyncStatus {
        self.sync_mu.lockUncancelable(self.io);
        defer self.sync_mu.unlock(self.io);
        return self.sync_status;
    }

    pub const Options = struct {
    /// Accept private and loopback addresses as peers (tests, LANs).
    allow_local_peers: bool = false,
};

    pub fn create(gpa: std.mem.Allocator, io: Io, chain: *Chain, cfg: pool_mod.Config, opts: Options) !*Node {
        const self = try gpa.create(Node);
        errdefer gpa.destroy(self);
        self.* = .{
            .gpa = gpa,
            .io = io,
            .chain = chain,
            .pool = undefined,
            .peers = peers_mod.Peers.init(gpa, io),
            .requested = std.AutoHashMap([32]u8, i64).init(gpa),
            .store = peer_store.PeerStore.init(gpa, io, chain.root, opts.allow_local_peers),
        };
        self.store.load();
        self.pool = pool_mod.TransactionPool.init(gpa, io, chain.cfg.chain, cfg, .{
            .ctx = chain,
            .chain_head = viewHead,
            .block_sums = viewBlockSums,
            .validate_tx = viewValidateTx,
            .verify_coinbase_maturity = viewCoinbaseMaturity,
            .verify_tx_lock_height = viewLockHeight,
        }, .{ .ctx = self, .tx_accepted = txAccepted, .stem_tx_accepted = stemTxAccepted });
        client.local_status = .{ .ctx = self, .f = localStatus };
        return self;
    }

    /// Our chain state for pings and pongs.
    fn localStatus(ctx: *anyopaque) ?msg.Ping {
        const self: *Node = @ptrCast(@alignCast(ctx));
        const head = self.chain.head() catch return null;
        return .{ .total_difficulty = head.total_difficulty, .height = head.height, .local_timestamp = @divTrunc(Io.Clock.real.now(self.io).toMilliseconds(), 1000) };
    }

    pub fn destroy(self: *Node) void {
        self.pool.deinit();
        self.peers.deinit();
        self.requested.deinit();
        self.store.save() catch {};
        self.store.deinit();
        self.gpa.destroy(self);
    }

    pub fn isSyncing(self: *Node) bool {
        const head = self.chain.head() catch return true;
        const hh = self.chain.headerHead() catch return true;
        return hh.height > head.height + SYNCING_LAG;
    }

    // ---- the pool's view of the chain (each call takes the chain lock)

    fn chainOf(ctx: *anyopaque) *Chain {
        return @ptrCast(@alignCast(ctx));
    }

    fn viewHead(ctx: *anyopaque) anyerror!block.BlockHeader {
        const c = chainOf(ctx);
        c.lock();
        defer c.unlock();
        const tip = try c.head();
        return (try c.getHeader(tip.last_block_h)) orelse error.NotFound;
    }

    fn viewBlockSums(ctx: *anyopaque, h: Hash) anyerror!chain_types.BlockSums {
        const c = chainOf(ctx);
        return (try c.db.getBlockSums(c.db.store, h)) orelse error.NotFound;
    }

    fn viewValidateTx(ctx: *anyopaque, t: Transaction) anyerror!void {
        const c = chainOf(ctx);
        c.lock();
        defer c.unlock();
        var batch = c.db.batch();
        defer batch.deinit();
        for (t.body.outputs) |o| try c.ths.validateOutput(&c.db, &batch, o);
        for (t.body.inputs) |i| try c.ths.validateInput(&c.db, &batch, i);
    }

    fn viewCoinbaseMaturity(ctx: *anyopaque, t: Transaction) anyerror!void {
        const c = chainOf(ctx);
        c.lock();
        defer c.unlock();
        const tip = try c.head();
        var batch = c.db.batch();
        defer batch.deinit();
        try c.ths.verifyCoinbaseMaturity(&c.db, &batch, &c.header_mmr, t.body.inputs, tip.height + 1);
    }

    fn viewLockHeight(ctx: *anyopaque, t: Transaction) anyerror!void {
        const c = chainOf(ctx);
        const tip = try c.head();
        if (t.lockHeight() > tip.height + 1) return error.TxLockHeight;
    }

    // ---- the pool's outputs

    fn txAccepted(ctx: *anyopaque, entry: *const pool_mod.Entry) void {
        const self: *Node = @ptrCast(@alignCast(ctx));
        const n = self.peers.broadcastTx(self.tx_source, entry.tx);
        log("Transaction {s} accepted to the pool (fee {d}); announced to {d} peer(s)", .{ entry.tx.hash().toHex()[0..12], entry.tx.fee(), n });
    }

    fn nowS(self: *Node) i64 {
        return @divFloor(Io.Clock.real.now(self.io).toMilliseconds(), 1000);
    }

    /// Starts a new Dandelion epoch (caller holds `epoch_mu`).
    fn startEpoch(self: *Node) void {
        var rb: [1]u8 = undefined;
        self.io.random(&rb);
        self.epoch.next(self.nowS(), self.peers.firstOutbound(), rb[0] % 100);
        if (self.epoch.relay) |r| {
            log("DandelionEpoch: next_epoch: is_stem: {} ({d}%), relay: {f}", .{ self.epoch.is_stem, self.epoch.cfg.stem_probability, r });
        } else log("DandelionEpoch: next_epoch: is_stem: {} ({d}%), relay: None", .{ self.epoch.is_stem, self.epoch.cfg.stem_probability });
    }

    /// The pool accepted a stem transaction (`stem_tx_accepted`): in a stem epoch
    /// (or for our own transactions) pass it to the relay peer alone; in a fluff
    /// epoch keep it for the monitor to aggregate and fluff. An error makes the
    /// pool fluff it straight away.
    fn stemTxAccepted(ctx: *anyopaque, entry: *const pool_mod.Entry) anyerror!void {
        const self: *Node = @ptrCast(@alignCast(ctx));
        self.epoch_mu.lockUncancelable(self.io);
        defer self.epoch_mu.unlock(self.io);
        if (self.epoch.isExpired(self.nowS())) self.startEpoch();
        if (!self.epoch.shouldStem(entry.src)) {
            log("Fluff epoch. Aggregating stem tx(s). Will fluff via Dandelion monitor.", .{});
            return;
        }
        // the relay must still be connected; otherwise choose another
        if (self.epoch.relay) |r| {
            if (!self.peers.isConnectedTo(r)) self.epoch.relay = null;
        }
        if (self.epoch.relay == null) self.epoch.relay = self.peers.firstOutbound();
        const relay = self.epoch.relay orelse {
            warn("No relay peer. Fluffing.", .{});
            return error.NoRelay;
        };
        self.peers.sendTo(relay, .stem_transaction, entry.tx) catch |e| {
            warn("Stemming tx failed. Fluffing. ({s})", .{@errorName(e)});
            self.epoch.relay = null;
            return error.NoRelay;
        };
        log("Stemming this epoch, relaying to next peer ({f}).", .{relay});
    }

    /// Starts the Dandelion monitor: every 10 s fluffs aggregated or embargoed stem
    /// transactions and rolls the epoch over.
    pub fn startDandelion(self: *Node) !void {
        const c = self.epoch.cfg;
        log("Starting dandelion monitor: epoch_secs: {d}, embargo_secs: {d}, aggregation_secs: {d}, stem_probability: {d}%, always_stem_our_txs: {}", .{
            c.epoch_secs, c.embargo_secs, c.aggregation_secs, c.stem_probability, c.always_stem_our_txs,
        });
        const t = try std.Thread.spawn(.{}, dandelionMonitor, .{self});
        t.detach();
    }

    fn dandelionMonitor(self: *Node) void {
        while (true) {
            self.io.sleep(.fromSeconds(10), .awake) catch {};
            const now_ms = Io.Clock.real.now(self.io).toMilliseconds();
            self.epoch_mu.lockUncancelable(self.io);
            const expired = self.epoch.isExpired(@divFloor(now_ms, 1000));
            const stem = self.epoch.is_stem;
            const cfg = self.epoch.cfg;
            self.epoch_mu.unlock(self.io);

            {
                self.pool.lock();
                defer self.pool.unlock();
                if (self.pool.stempool.size() > 0) self.dandelionPass(cfg, expired, stem, now_ms);
            }
            // the final fluff of an epoch happens before the next one starts
            if (expired) {
                self.epoch_mu.lockUncancelable(self.io);
                self.startEpoch();
                self.epoch_mu.unlock(self.io);
            }
        }
    }

    fn dandelionPass(self: *Node, cfg: dandelion.Config, expired: bool, stem: bool, now_ms: i64) void {
        const header = viewHead(self.chain) catch return;
        if (!stem) {
            dandelion.processFluffPhase(&self.pool, cfg, expired, now_ms, header) catch |e| warn("dand_mon: Problem processing fluff phase. {s}", .{@errorName(e)});
        }
        var jb: [1]u8 = undefined;
        self.io.random(&jb);
        const n = dandelion.processExpired(&self.pool, cfg, now_ms, jb[0] % 31, header) catch 0;
        if (n > 0) log("dand_mon: embargo expired for {d} tx(s), fluffed successfully.", .{n});
    }

    // ---- entry points

    /// Adds a tx (borrowed) received from `src` (or from the API when null).
    pub fn addTx(self: *Node, src: ?*Conn, tx: Transaction, stem: bool) pool_mod.Error!void {
        self.pool.lock();
        defer self.pool.unlock();
        const header = viewHead(self.chain) catch return error.Other;
        self.tx_source = src;
        defer self.tx_source = null;
        try self.pool.addToPool(.broadcast, tx, stem, header);
    }

    /// Tells the node a block was accepted into the chain (call without the
    /// chain lock): reconciles the pool and, once caught up, announces the
    /// header to every peer but `source`.
    pub fn blockAccepted(self: *Node, b: block.Block, source: ?*Conn) void {
        self.onBlock(b);
        if (self.isSyncing()) return;
        self.maybeCompact();
        const n = self.peers.broadcast(source, .header, b.header);
        log("Block {f} accepted; announced to {d} peer(s)", .{ N(b.header.height), n });
    }

    /// Like the reference: on average once a day of blocks, try compacting (it
    /// only does work a while past the last compaction), on its own thread.
    fn maybeCompact(self: *Node) void {
        var rb: [2]u8 = undefined;
        self.io.random(&rb);
        if (std.mem.readInt(u16, &rb, .little) % @as(u16, @intCast(consensus.COMPACTION_CHECK)) != 0) return;
        const t = std.Thread.spawn(.{}, compactNow, .{self}) catch return;
        t.detach();
    }

    /// Runs a compaction (holding the chain lock while it works).
    pub fn compactNow(self: *Node) void {
        self.chain.lock();
        defer self.chain.unlock();
        const ran = self.chain.compact() catch |e| {
            logging.err("Could not compact chain: {s}", .{@errorName(e)});
            return;
        };
        if (!ran) debug("compact: skipping compaction - threshold is 60 blocks beyond horizon.", .{});
    }

    /// Drops pool txs that a newly accepted block made obsolete. Call without
    /// holding the chain lock.
    pub fn onBlock(self: *Node, b: block.Block) void {
        self.pool.lock();
        defer self.pool.unlock();
        const before = self.pool.txpool.size();
        if (before == 0 and self.pool.stempool.size() == 0) return;
        self.pool.reconcileBlock(b) catch |e| warn("Pool reconciliation failed: {s}", .{@errorName(e)});
        log("Block {f}: pool {d} -> {d} tx(s)", .{ N(b.header.height), before, self.pool.txpool.size() });
    }

    // ---- peers: bans and upkeep

    /// Bans the host of `addr` and cuts its connections.
    pub fn banPeer(self: *Node, addr: std.Io.net.IpAddress, why: []const u8) void {
        self.store.ban(addr);
        const n = self.peers.killHost(addr);
        warn("Banned peer {f} ({s}); dropped {d} connection(s)", .{ addr, why, n });
        self.store.save() catch {};
    }

    /// Whether `e` is bad enough behaviour to ban a peer for.
    pub fn deservesBan(_: *Node, e: anyerror) bool {
        return misbehavior.isBad(e);
    }

    /// Starts the background upkeep thread: pings quiet peers, drops dead ones,
    /// and saves the peer store.
    /// The reference's periodic peer summary.
    pub fn logPeers(self: *Node) void {
        const d = self.peers.directions();
        const s = self.store.stats();
        log("Monitor peers on {s}, [inbound/outbound/all] {d}/{d}/{d} connected. all {d} = {d} healthy + {d} banned + {d} defunct", .{
            self.listen_desc, d.inbound, d.outbound, d.inbound + d.outbound, s.healthy + s.banned + s.defunct, s.healthy, s.banned, s.defunct,
        });
    }

    pub fn startMaintenance(self: *Node) !void {
        const t = try std.Thread.spawn(.{}, maintenance, .{self});
        t.detach();
    }

    fn maintenance(self: *Node) void {
        var tick: u64 = 0;
        while (true) {
            self.io.sleep(.fromSeconds(10), .awake) catch {};
            tick += 1;
            const tip = self.chain.head() catch continue;
            const r = self.peers.reap(.{ .total_difficulty = tip.total_difficulty, .height = tip.height, .local_timestamp = @divFloor(Io.Clock.real.now(self.io).toMilliseconds(), 1000) });
            if (r.dropped > 0) log("Dropped {d} unresponsive peer(s)", .{r.dropped});
            if (tick % 3 == 0) self.logPeers();
            if (tick % 6 == 0) self.store.save() catch {};
        }
    }

    /// Handles a gossip message; errors mean the peer sent garbage.
    pub fn handleGossip(self: *Node, conn: *Conn, m: client.Message) !void {
        var r = conn.readerFor(m.body);
        switch (m.msg_type) {
            .transaction, .stem_transaction => {
                var tx = try Transaction.read(&r);
                defer tx.deinit(self.gpa);
                if (self.isSyncing()) return;
                self.addTx(conn, tx, m.msg_type == .stem_transaction) catch |e| {
                    debug("Transaction {s} rejected: {s}", .{ tx.hash().toHex()[0..12], @errorName(e) });
                };
            },
            .transaction_kernel => {
                const h = (try msg.HashMsg.read(&r)).hash;
                if (self.isSyncing()) return;
                self.pool.lock();
                const have = blk: {
                    defer self.pool.unlock();
                    break :blk try self.pool.retrieveTxByKernelHash(h);
                };
                if (have) |t| {
                    var tt = t;
                    tt.deinit(self.gpa);
                    return;
                }
                try conn.send(.get_transaction, msg.HashMsg{ .hash = h });
            },
            .get_transaction => {
                const h = (try msg.HashMsg.read(&r)).hash;
                self.pool.lock();
                const found = blk: {
                    defer self.pool.unlock();
                    break :blk try self.pool.retrieveTxByKernelHash(h);
                };
                if (found) |t| {
                    var tt = t;
                    defer tt.deinit(self.gpa);
                    try conn.send(.transaction, tt);
                }
            },
            .peer_addrs => {
                const pa = try msg.PeerAddrs.read(&r);
                defer self.gpa.free(pa.peers);
                var kept: usize = 0;
                for (pa.peers) |a| if (self.store.learn(peer_store.fromPeerAddr(a))) {
                    kept += 1;
                };
                debug("Received {d} peer address(es), {d} usable", .{ pa.peers.len, kept });
            },
            .header => {
                const h = try block.BlockHeader.read(&r);
                try self.onHeader(conn, h);
            },
            .compact_block => {
                var cb = try compact_block.CompactBlock.read(&r);
                defer cb.deinit(self.gpa);
                try self.onCompactBlock(conn, cb);
            },
            .block => {
                var b = try block.Block.read(&r);
                defer b.deinit(self.gpa);
                try self.onFullBlock(conn, b);
            },
            else => {},
        }
    }

    // ---- block relay (header first, then compact block)

    fn shouldRequest(self: *Node, h: Hash) bool {
        const now = Io.Clock.awake.now(self.io).toMilliseconds();
        self.requested_mu.lockUncancelable(self.io);
        defer self.requested_mu.unlock(self.io);
        if (self.requested.count() > 1000) self.requested.clearRetainingCapacity();
        if (self.requested.get(h.bytes)) |t| if (now - t < 30_000) return false;
        self.requested.put(h.bytes, now) catch {};
        return true;
    }

    fn haveBlock(self: *Node, h: Hash) bool {
        return self.chain.db.blockExists(self.chain.db.store, h) catch true;
    }

    /// A peer announced a header: if it's a block we lack, ask for it compactly.
    fn onHeader(self: *Node, conn: *Conn, h: block.BlockHeader) !void {
        if (self.isSyncing()) return;
        const hh = h.hash();
        if (self.haveBlock(hh)) return;
        self.chain.lock();
        const accepted = self.chain.acceptHeaders(&.{h}, .{});
        self.chain.unlock();
        accepted catch |e| switch (e) {
            error.Orphan, error.Unfit, error.OldBlock => return, // not ours to follow up
            else => return e,
        };
        if (self.shouldRequest(hh)) try conn.send(.get_compact_block, msg.HashMsg{ .hash = hh });
    }

    /// A full block arrived (because we asked, or pushed): run it through the chain.
    fn onFullBlock(self: *Node, conn: ?*Conn, b: block.Block) !void {
        if (self.isSyncing()) return;
        if (self.haveBlock(b.hash())) return;
        const moved = blk: {
            self.chain.lock();
            defer self.chain.unlock();
            break :blk self.chain.processBlock(b, .{}) catch |e| switch (e) {
                error.Orphan, error.Unfit, error.OldBlock => return,
                else => return e,
            };
        };
        if (moved != null) {
            log("Block {f} received from a peer's announcement", .{N(b.header.height)});
            self.blockAccepted(b, conn);
        }
    }

    /// Rebuilds the block from our pool if we can, otherwise asks for it in full.
    fn onCompactBlock(self: *Node, conn: *Conn, cb: compact_block.CompactBlock) !void {
        if (self.isSyncing()) return;
        const hh = cb.hash();
        if (self.haveBlock(hh)) return;
        const prev = (try self.chain.getHeader(cb.header.prev_hash)) orelse return; // orphan

        var found: ?pool_mod.Pool.Found = null;
        defer if (found) |f| f.deinit(self.gpa);
        if (cb.kern_ids.len > 0) {
            self.pool.lock();
            defer self.pool.unlock();
            found = try self.pool.retrieveTransactions(hh, cb.nonce, cb.kern_ids);
            if (found.?.missing.len > 0) {
                debug("Compact block {f}: {d} tx(s) not in our pool, requesting the full block", .{ N(cb.header.height), found.?.missing.len });
                try conn.send(.get_block, msg.HashMsg{ .hash = hh });
                return;
            }
        }
        const txs: []const Transaction = if (found) |f| f.txs else &.{};
        var b = compact_block.hydrate(self.gpa, cb, txs) catch {
            try conn.send(.get_block, msg.HashMsg{ .hash = hh });
            return;
        };
        defer b.deinit(self.gpa);
        _ = b.validate(self.gpa, self.chain.cfg.chain, &self.chain.foundation, prev.total_kernel_offset) catch {
            try conn.send(.get_block, msg.HashMsg{ .hash = hh });
            return;
        };
        try self.onFullBlock(conn, b);
    }

    /// `Handler` glue for connections we initiated.
    pub fn handler(self: *Node) client.Handler {
        return .{ .ctx = self, .f = onUnsolicited };
    }

    fn onUnsolicited(ctx: *anyopaque, conn: *Conn, m: client.Message) void {
        const self: *Node = @ptrCast(@alignCast(ctx));
        self.handleGossip(conn, m) catch |e| warn("Bad {s} message from a peer: {s}", .{ @tagName(m.msg_type), @errorName(e) });
    }
};
