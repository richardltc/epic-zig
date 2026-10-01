//! A single-peer sync driver: header sync, state (txhashset) sync, body sync,
//! then following the chain. Deliberately simpler than the reference's
//! multi-peer orchestration, but it reaches the same chain state.
const std = @import("std");
const N = @import("logging.zig").num;
const Io = std.Io;
const consensus = @import("consensus.zig");
const chain_mod = @import("chain.zig");
const client = @import("p2p_client.zig");
const msg = @import("p2p_msg.zig");
const hash_mod = @import("hash.zig");
const chain_types = @import("chain_types.zig");
const block_mod = @import("block.zig");
const pow_types = @import("pow_types.zig");
const Node = @import("node.zig").Node;

const Hash = hash_mod.Hash;
const Chain = chain_mod.Chain;

pub const Options = struct {
    /// Stop after header sync.
    headers_only: bool = false,
    /// Stop once the body chain reaches this height (for testing).
    stop_height: ?u64 = null,
    /// Keep polling the peer for new blocks after catching up.
    follow: bool = true,
    /// Blocks requested per round trip during body sync.
    block_window: usize = 64,
    /// Header windows (512 each) kept in flight during header sync.
    header_windows: u32 = 8,
};

fn nowMs(io: Io) i64 {
    return Io.Clock.awake.now(io).toMilliseconds();
}

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

/// Connection-level failures (the peer dropped us, timeouts, resets): worth a reconnect.
/// Anything else (a consensus or storage error) must stop the node.
fn isConnectionError(e: anyerror) bool {
    return switch (e) {
        error.EndOfStream,
        error.ReadFailed,
        error.WriteFailed,
        error.ConnectionResetByPeer,
        error.BrokenPipe,
        error.ConnectionTimedOut,
        error.NetworkDown,
        error.SocketNotConnected,
        error.Unexpected,
        => true,
        else => false,
    };
}

/// Header sync this far behind the peer uses bulk-load mode for the database.
const BULK_HEADERS_GAP: u64 = 50_000;
/// How far behind counts as syncing for the API's status (less is routine following).
const STATUS_LAG: u64 = 5;

/// Replays of at least this many blocks skip the per-block fsync.
const CATCHUP_MIN_BLOCKS: u64 = 100;

pub const Syncer = struct {
    gpa: std.mem.Allocator,
    io: Io,
    chain: *Chain,
    conn: *client.Conn,
    addr: Io.net.IpAddress,
    opts: Options,
    download_dir: Io.Dir,
    node: ?*Node = null,

    /// Makes `c` visible to the node (gossip handling, broadcasts).
    fn adopt(self: *Syncer, c: *client.Conn) void {
        c.exempt = true; // the syncer does its own timing on this connection
        if (self.node) |n| {
            c.handler = n.handler();
            n.peers.add(c);
            n.store.markHealthy(self.addr);
            // ask for the peer's friends; the reply is handled as gossip
            c.send(.get_peer_addrs, msg.GetPeerAddrs{ .capabilities = .{ .bits = msg.Capabilities.FULL_NODE } }) catch {};
        }
    }

    fn release(self: *Syncer, c: *client.Conn) void {
        if (self.node) |n| n.peers.remove(c);
    }

    /// Tries to connect to `addr`; on success the syncer switches to it.
    fn tryConnect(self: *Syncer, addr: Io.net.IpAddress) bool {
        const c = client.Conn.connect(self.gpa, self.io, addr, self.chain.cfg.chain, self.chain.genesis.hash(), self.chain.genesis.header.pow.total_difficulty) catch |e| {
            warn("Failed to connect to sync peer {f}: {s}", .{ addr, @errorName(e) });
            if (self.node) |n| n.store.markDefunct(addr);
            return false;
        };
        self.conn = c;
        self.addr = addr;
        self.adopt(c);
        return true;
    }

    /// Reconnects, to the current peer if it answers, otherwise to any known
    /// healthy peer (from the peer store).
    fn reconnect(self: *Syncer) !void {
        self.release(self.conn);
        self.conn.close();
        var attempt: u32 = 0;
        while (true) : (attempt += 1) {
            self.io.sleep(.fromSeconds(@min(5 + attempt * 5, 60)), .awake) catch {};
            if (self.tryConnect(self.addr)) {
                log("Reconnected to the sync peer", .{});
                return;
            }
            if (self.node) |n| {
                const others = n.store.candidates(5, &.{self.addr}) catch &.{};
                defer if (others.len > 0) self.gpa.free(others);
                for (others) |a| if (self.tryConnect(a)) {
                    log("Switched sync to peer {f}", .{a});
                    return;
                };
            }
            if (attempt > 30) return error.ConnectionTimedOut;
        }
    }

    /// Runs `phase`; on a connection error reconnects and runs it again.
    fn withRetry(self: *Syncer, comptime name: []const u8, comptime phase: fn (*Syncer) anyerror!void) !void {
        while (true) {
            phase(self) catch |e| {
                if (!isConnectionError(e)) return e;
                warn("Peer connection lost during {s} ({s}). Restarting sync.", .{ name, @errorName(e) });
                try self.reconnect();
                continue;
            };
            return;
        }
    }

    fn setStatus(self: *Syncer, s: Node.SyncStatus) void {
        if (self.node) |n| n.setSyncStatus(s);
    }

    fn syncOnce(self: *Syncer) !void {
        try self.withRetry("header sync", syncHeaders);
        if (self.opts.headers_only) return;
        try self.withRetry("state sync", syncState);
        try self.withRetry("body sync", syncBodies);
    }

    pub fn run(gpa: std.mem.Allocator, io: Io, chain: *Chain, conn: *client.Conn, addr: Io.net.IpAddress, opts: Options, node: ?*Node) !void {
        var dl = try chain.root.createDirPathOpen(io, "download", .{});
        defer dl.close(io);
        var self: Syncer = .{ .gpa = gpa, .io = io, .chain = chain, .conn = conn, .addr = addr, .opts = opts, .download_dir = dl, .node = node };
        self.adopt(conn);
        defer {
            self.release(self.conn);
            self.conn.close();
        }

        log("Sync peer: {s}, protocol version {d}", .{ conn.peer.userAgent(), conn.peer.version.v });

        var following_at: ?u64 = null;
        while (true) {
            self.syncOnce() catch |e| {
                // a node that follows the chain keeps going, as the reference's sync loop does
                if (!opts.follow or opts.headers_only) return e;
                logging.err("Sync: unexpected error: {s}; retrying", .{@errorName(e)});
                io.sleep(.fromSeconds(5), .awake) catch {};
                continue;
            };
            if (opts.headers_only) return;
            const head = try chain.head();
            if (opts.stop_height) |h| if (head.height >= h) return;
            if (!opts.follow) return;
            // leaving a sync: compact first, as the reference does on its way to NoSync
            if (self.node) |n| switch (n.syncStatus()) {
                .no_sync, .shutdown => {},
                else => {
                    n.setSyncStatus(.compacting);
                    n.compactNow();
                },
            };
            self.setStatus(.no_sync);
            if (following_at == null) log("Fully synced at height {f}; following the chain", .{N(head.height)});
            following_at = head.height;
            try io.sleep(.fromSeconds(15), .awake);
        }
    }

    // ---------------------------------------------------------- headers

    /// A batch of headers on its way through the pipeline: received, having its
    /// PoW checked on the worker threads, waiting to be applied to the chain.
    const HeaderBatch = struct {
        gpa: std.mem.Allocator,
        chain: *Chain,
        headers: []block_mod.BlockHeader,
        opts: chain_types.Options,
        pre: []?pow_types.Difficulty = &.{},
        thread: ?std.Thread = null,

        fn powWorker(self: *HeaderBatch) void {
            self.chain.verifyPow(self.headers, self.pre);
        }

        /// Starts checking the PoW in the background (a no-op inside checkpoints).
        fn startPow(self: *HeaderBatch) !void {
            if (self.opts.skip_pow) return;
            self.pre = try self.gpa.alloc(?pow_types.Difficulty, self.headers.len);
            self.thread = std.Thread.spawn(.{}, powWorker, .{self}) catch {
                powWorker(self); // no thread available: do it here
                return;
            };
        }

        fn joinPow(self: *HeaderBatch) void {
            if (self.thread) |t| t.join();
            self.thread = null;
        }

        fn destroy(self: *HeaderBatch) void {
            self.joinPow();
            if (self.pre.len > 0) self.gpa.free(self.pre);
            self.gpa.free(self.headers);
            self.gpa.destroy(self);
        }
    };

    /// The peer's chain height, from a ping (null if it doesn't answer sensibly).
    fn peerHeight(self: *Syncer) ?u64 {
        self.conn.send(.ping, client.ourStatus(self.chain.cfg.chain)) catch return null;
        const m = self.conn.recvType(.pong) catch return null;
        defer m.deinit(self.gpa);
        var r = self.conn.readerFor(m.body);
        const p = msg.Pong.read(&r) catch return null;
        self.conn.noteLive(p.total_difficulty, p.height);
        return p.height;
    }

    /// Header sync, pipelined: while one batch is applied to the chain the next
    /// one's PoW is being verified on the other cores and the one after it is
    /// already on the wire. (The PoW check needs no chain state.)
    fn syncHeaders(self: *Syncer) !void {
        const start = nowMs(self.io);
        const start_height = (try self.chain.headerHead()).height;
        var last_report = start;
        var net_ms: i64 = 0;
        var seq_ms: i64 = 0;
        var pow_wait_ms: i64 = 0;
        // the last report, for per-interval figures
        var rep_height = start_height;
        var rep_ms = start;
        var rep_net: i64 = 0;
        var rep_seq: i64 = 0;
        var rep_pow: i64 = 0;

        var prev: ?*HeaderBatch = null;
        defer if (prev) |p| p.destroy();

        // far behind: write in bulk-load mode and compact once at the end
        var bulk = false;
        // the status only says "header sync" when there is real catching up to do,
        // not for the routine check while following the tip
        var target: ?u64 = null;
        if (self.peerHeight()) |ph| {
            if (ph > start_height + STATUS_LAG) {
                target = ph;
                self.setStatus(.{ .header_sync = .{ .current_height = start_height, .highest_height = ph } });
            }
            if (ph > start_height + BULK_HEADERS_GAP) {
                self.chain.beginBulkHeaders();
                bulk = true;
            }
        }
        defer if (bulk) {
            const t0 = nowMs(self.io);
            self.chain.endBulkHeaders();
            log("Header Sync: compacted the header database in {d:.1}s", .{@as(f64, @floatFromInt(nowMs(self.io) - t0)) / 1000.0});
        };

        {
            var loc_buf: [msg.MAX_LOCATORS]Hash = undefined;
            self.chain.lock();
            const loc = self.chain.headerLocator(&loc_buf) catch |e| {
                self.chain.unlock();
                return e;
            };
            self.chain.unlock();
            try self.conn.send(.get_headers, msg.Locator{ .hashes = loc });
        }

        // After the first batch (found with an ordinary locator) the next ones are
        // requested as fast-sync windows, several at a time, so a distant peer's
        // round trips overlap instead of adding up.
        var windowed = false;
        var outstanding: u32 = 0;
        var base_hash: Hash = undefined;
        var base_height: u64 = 0;
        var last_hash: Hash = undefined;
        var last_height: u64 = 0;
        var req_end: u64 = 0; // last height requested so far
        defer {
            // collect replies to requests past the tip so the connection stays in step
            while (outstanding > 0) : (outstanding -= 1) {
                const m = self.conn.recvType(.fast_headers) catch break;
                m.deinit(self.gpa);
            }
        }

        while (true) {
            const t_net = nowMs(self.io);
            const m = try self.conn.recvType(if (windowed) .fast_headers else .headers);
            if (windowed) outstanding -= 1;
            defer m.deinit(self.gpa);
            var r = self.conn.readerFor(m.body);
            var hs = try msg.Headers.read(&r);
            net_ms += nowMs(self.io) - t_net;
            if (hs.headers.len == 0) {
                hs.deinit(self.gpa);
                break;
            }

            const b = try self.gpa.create(HeaderBatch);
            b.* = .{ .gpa = self.gpa, .chain = self.chain, .headers = hs.headers, .opts = undefined };
            var owned = true;
            errdefer if (owned) b.destroy();
            b.opts = try self.chain.optionsForHeaders(b.headers);
            try b.startPow();

            // keep the pipe full: the next windows arrive while we work
            const full = b.headers.len == msg.MAX_BLOCK_HEADERS;
            if (full) {
                const last = b.headers[b.headers.len - 1];
                last_hash = last.hash();
                last_height = last.height;
                if (!windowed) {
                    windowed = true;
                    base_hash = last_hash;
                    base_height = last_height;
                    req_end = last_height;
                }
                while (outstanding < self.opts.header_windows) {
                    // windows are 512-aligned on the base; move the base up before the u8 offset runs out
                    var off = (req_end - base_height) / msg.MAX_BLOCK_HEADERS;
                    if (off > 200 and last_height > base_height) {
                        base_hash = last_hash;
                        base_height = last_height;
                        off = (req_end - base_height) / msg.MAX_BLOCK_HEADERS;
                    }
                    if (off > 255) break;
                    try self.conn.send(.get_headers_fast_sync, msg.LocatorFastSync{ .hashes = &.{base_hash}, .offset = @intCast(off) });
                    req_end += msg.MAX_BLOCK_HEADERS;
                    outstanding += 1;
                }
            }

            if (prev) |p| {
                prev = null;
                defer p.destroy();
                try self.applyBatch(p, &seq_ms, &pow_wait_ms);
                if (target) |t| self.reportHeaders(p, t);
            }
            prev = b;
            owned = false;

            const now = nowMs(self.io);
            if (now - last_report > 3000) {
                const hh = try self.chain.headerHead();
                const span: f64 = @floatFromInt(@max(now - rep_ms, 1));
                const rate = @as(f64, @floatFromInt(hh.height - rep_height)) * 1000.0 / span;
                log("Header Sync: height {f}  ({f}/s; {s}; net {d:.0}% apply {d:.0}% pow-wait {d:.0}%)", .{
                    N(hh.height),                                N(rate),
                    if (b.opts.skip_pow) "PoW skipped in checkpoints" else "PoW verified",
                    100.0 * @as(f64, @floatFromInt(net_ms - rep_net)) / span,
                    100.0 * @as(f64, @floatFromInt(seq_ms - rep_seq)) / span,
                    100.0 * @as(f64, @floatFromInt(pow_wait_ms - rep_pow)) / span,
                });
                last_report = now;
                rep_height = hh.height;
                rep_ms = now;
                rep_net = net_ms;
                rep_seq = seq_ms;
                rep_pow = pow_wait_ms;
            }
            if (!full) break;
        }
        if (prev) |p| {
            prev = null;
            defer p.destroy();
            try self.applyBatch(p, &seq_ms, &pow_wait_ms);
            if (target) |t| self.reportHeaders(p, t);
        }
        const hh = try self.chain.headerHead();
        const secs = @as(f64, @floatFromInt(nowMs(self.io) - start)) / 1000.0;
        // while following the tip this runs every few seconds: quiet unless it found something
        if (hh.height > start_height) {
            log("Header Sync: done at height {f} ({f} new headers, {d:.1}s)", .{ N(hh.height), N(hh.height - start_height), secs });
        } else debug("Header Sync: nothing new at height {f} ({d:.1}s)", .{ N(hh.height), secs });
    }

    /// The API's header-sync figures, from a batch the chain has just accepted.
    fn reportHeaders(self: *Syncer, b: *const HeaderBatch, target: u64) void {
        const h = b.headers[b.headers.len - 1].height;
        // the network keeps growing during a long sync: follow the peers' heights
        const peers_best: u64 = if (self.node) |n| n.peers.maxHeight() else 0;
        self.setStatus(.{ .header_sync = .{ .current_height = h, .highest_height = @max(@max(target, h), peers_best) } });
    }

    fn applyBatch(self: *Syncer, b: *HeaderBatch, seq_ms: *i64, pow_wait_ms: *i64) !void {
        const t0 = nowMs(self.io);
        b.joinPow();
        const t1 = nowMs(self.io);
        pow_wait_ms.* += t1 - t0;
        self.chain.lock();
        defer self.chain.unlock();
        try self.chain.acceptHeadersVerified(b.headers, b.opts, if (b.opts.skip_pow) null else b.pre);
        seq_ms.* += nowMs(self.io) - t1;
    }

    // ------------------------------------------------------ state sync

    fn syncState(self: *Syncer) !void {
        const head = try self.chain.head();
        const hh = try self.chain.headerHead();
        const threshold = self.chain.cfg.chain.stateSyncThreshold();
        if (hh.height <= head.height + threshold) return;
        log("Block synchronization is out of range ({f} blocks behind). Starting txhashset download.", .{N(hh.height - head.height)});

        try self.conn.send(.tx_hash_set_request, msg.TxHashSetRequest{ .hash = Hash.zero, .height = 0 });
        const m = try self.conn.recvType(.tx_hash_set_archive);
        defer m.deinit(self.gpa);
        var r = self.conn.readerFor(m.body);
        const arch = try msg.TxHashSetArchive.read(&r);
        log("State Sync: txhashset archive at height {f}: {f} MiB", .{ N(arch.height), N(arch.bytes >> 20) });
        self.setStatus(.{ .txhashset_download = .{ .downloaded_size = 0, .total_size = arch.bytes } });

        const zip_name = "txhashset.zip";
        {
            var zf = try self.download_dir.createFile(self.io, zip_name, .{});
            defer zf.close(self.io);
            var buf: [1 << 16]u8 = undefined;
            var remaining = arch.bytes;
            var off: u64 = 0;
            var last = nowMs(self.io);
            const t0 = last;
            while (remaining > 0) {
                const n: usize = @intCast(@min(remaining, buf.len));
                try self.conn.reader.interface.readSliceAll(buf[0..n]);
                try zf.writePositionalAll(self.io, buf[0..n], off);
                off += n;
                remaining -= n;
                self.setStatus(.{ .txhashset_download = .{ .downloaded_size = off, .total_size = arch.bytes } });
                const now = nowMs(self.io);
                if (now - last > 3000) {
                    log("State Sync: downloaded {d}/{d} MiB ({d:.1} MiB/s)", .{ off >> 20, arch.bytes >> 20, @as(f64, @floatFromInt(off)) / 1048576.0 / (@as(f64, @floatFromInt(now - t0)) / 1000.0) });
                    last = now;
                }
            }
        }
        self.setStatus(.txhashset_processing);
        {
            self.chain.lock();
            defer self.chain.unlock();
            try self.chain.txhashsetWrite(self.download_dir, zip_name, arch.hash);
        }
        self.download_dir.deleteFile(self.io, zip_name) catch {};
        // validation kept us off the wire for a long time; start on a fresh connection
        try self.reconnect();
    }

    // ------------------------------------------------------- body sync

    fn syncBodies(self: *Syncer) !void {
        const Block = block_mod.Block;
        const start = nowMs(self.io);
        var last_report = start;
        var applied: u64 = 0;
        const target = (try self.chain.headerHead()).height;
        const report_status = target > (try self.chain.head()).height + STATUS_LAG;

        // a long replay runs without per-block fsync (see Chain.beginCatchup)
        {
            const head = try self.chain.head();
            if (target > head.height + CATCHUP_MIN_BLOCKS) {
                self.chain.lock();
                self.chain.beginCatchup();
                self.chain.unlock();
            }
        }
        defer {
            self.chain.lock();
            self.chain.endCatchup();
            self.chain.unlock();
        }

        while (true) {
            const head = try self.chain.head();
            if (report_status) self.setStatus(.{ .body_sync = .{ .current_height = head.height, .highest_height = target } });
            if (head.height >= target) break;
            if (self.opts.stop_height) |h| if (head.height >= h) break;

            var hashes: [128]Hash = undefined;
            const want = @min(@min(self.opts.block_window, hashes.len), target - head.height);
            for (0..want) |i| {
                self.chain.lock();
                const hh = self.chain.header_mmr.hashAtHeight(head.height + 1 + i);
                self.chain.unlock();
                hashes[i] = hh orelse return error.MissingHeader;
                try self.conn.send(.get_block, msg.HashMsg{ .hash = hashes[i] });
            }

            // receive the whole window...
            var blocks: [128]Block = undefined;
            var n_blocks: usize = 0;
            defer for (blocks[0..n_blocks]) |*b| b.deinit(self.gpa);
            for (0..want) |i| {
                const m = try self.conn.recvType(.block);
                defer m.deinit(self.gpa);
                var r = self.conn.readerFor(m.body);
                var b = try Block.read(&r);
                errdefer b.deinit(self.gpa);
                if (!b.hash().eql(hashes[i])) return error.UnexpectedBlock;
                blocks[n_blocks] = b;
                n_blocks += 1;
            }

            // ...check the stateless parts (proofs, signatures) on all cores...
            var ok: [128]bool = undefined;
            const Pre = struct {
                chain: *Chain,
                blocks: []const Block,
                ok: []bool,
                fn work(c: *@This(), i: usize) anyerror!void {
                    c.ok[i] = c.chain.prevalidateBlock(c.blocks[i]);
                }
            };
            var pre: Pre = .{ .chain = self.chain, .blocks = blocks[0..n_blocks], .ok = ok[0..n_blocks] };
            try @import("parallel.zig").forEach(Pre, &pre, n_blocks, Pre.work);

            // ...then apply them in order
            for (blocks[0..n_blocks], 0..) |b, i| {
                const fresh = blk: {
                    self.chain.lock();
                    defer self.chain.unlock();
                    _ = self.chain.processBlock(b, .{ .sync = true, .body_validated = ok[i] }) catch |e| switch (e) {
                        // a peer's announcement got it in first
                        error.Unfit, error.OldBlock => break :blk false,
                        else => return e,
                    };
                    break :blk true;
                };
                if (!fresh) continue;
                if (self.node) |nd| nd.blockAccepted(b, self.conn);
                applied += 1;
            }

            const now = nowMs(self.io);
            if (now - last_report > 2000) {
                const h = try self.chain.head();
                const pr = self.chain.prof;
                const per: f64 = 1e6 * @as(f64, @floatFromInt(@max(applied, 1)));
                const left = target -| h.height;
                const pct: f64 = if (target == 0) 100 else 100.0 * @as(f64, @floatFromInt(h.height)) / @as(f64, @floatFromInt(target));
                log("Block Sync: height {f} / {f}, {f} block(s) remaining, {d:.2}% completed ({d:.1} blocks/s)", .{
                    N(h.height),
                    N(target),
                    N(left),
                    pct,
                    @as(f64, @floatFromInt(applied)) * 1000.0 / @as(f64, @floatFromInt(@max(now - start, 1))),
                });
                debug("Block Sync: per block: checks {d:.1} ms, validate {d:.1} ms, txhashset {d:.1} ms, fsync {d:.1} ms, db {d:.1} ms", .{
                    @as(f64, @floatFromInt(pr[0])) / per,
                    @as(f64, @floatFromInt(pr[1])) / per,
                    @as(f64, @floatFromInt(pr[2])) / per,
                    @as(f64, @floatFromInt(pr[3])) / per,
                    @as(f64, @floatFromInt(pr[4])) / per,
                });
                last_report = now;
            }
        }
        if (applied > 0) log("Block Sync: applied {f} blocks", .{N(applied)});
    }
};
