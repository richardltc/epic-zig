//! The chain: owns the database, txhashset and header MMRs, and runs the
//! header and block processing pipeline. Port of `chain/src/chain.rs` (init,
//! `setup_head`) and `chain/src/pipe.rs`.
//!
//! Not thread-safe by itself: with several tasks (syncer, p2p server) every
//! caller takes `lock()` around calls that touch the header MMR, the
//! txhashset or the caches. Plain database reads are safe without it.
const std = @import("std");
const N = @import("logging.zig").num;
const Io = std.Io;
const ser = @import("ser.zig");
const hash_mod = @import("hash.zig");
const crypto = @import("crypto.zig");
const consensus = @import("consensus.zig");
const block = @import("block.zig");
const tx = @import("transaction.zig");
const pmmr = @import("pmmr.zig");
const kv = @import("kv.zig");
const pow = @import("pow.zig");
const feijoada = @import("feijoada.zig");
const pow_types = @import("pow_types.zig");
const randomx = @import("randomx.zig");
const header_iter = @import("header_iter.zig");
const chain_db = @import("chain_db.zig");
const chain_types = @import("chain_types.zig");
const txhashset_mod = @import("txhashset.zig");
const checkpoints = @import("checkpoints.zig");
const zipwrite = @import("zipwrite.zig");
const fsutil = @import("fsutil.zig");

const Hash = hash_mod.Hash;
const BlockHeader = block.BlockHeader;
const Block = block.Block;
const Tip = chain_types.Tip;
const BlockSums = chain_types.BlockSums;
const ChainType = consensus.ChainType;
const TxHashSet = txhashset_mod.TxHashSet;
const HeaderMmr = txhashset_mod.HeaderMmr;
const PowResult = struct { diff: ?pow_types.Difficulty };
const Options = chain_types.Options;

pub const Error = error{
    Orphan,
    Unfit,
    OldBlock,
    InvalidBlockVersion,
    InvalidBlockTime,
    InvalidPow,
    LowEdgebits,
    InvalidSeed,
    PolicyIsNotAllowed,
    InvalidSortAlgo,
    ThereIsNotPolicy,
    InvalidBlockHeight,
    DifficultyTooLow,
    WrongTotalDifficulty,
    InvalidScaling,
    InvalidBlockProof,
    BadHeader,
    CorruptChain,
    Other,
} || anyerror;

pub const Config = struct {
    chain: ChainType = .mainnet,
    policy: feijoada.PolicyConfig = consensus.default_policy_config,
    kv_options: kv.Options = .{},
    /// Skip PoW verification for headers inside the checkpointed range (all
    /// other header rules still apply and the checkpoint hashes are enforced).
    /// Mainnet only; the same idea as the reference's `skip_pow_validation`.
    skip_pow_in_checkpoints: bool = true,
    /// The reference's `disable_checkpoints`: with `skip_pow_in_checkpoints`,
    /// skip PoW on every header while syncing, not just inside checkpoints.
    disable_checkpoints: bool = false,
    /// Also use the extended checkpoints (3.6M, 3.7M; `checkpoints.extended`).
    /// By default PoW is skipped up to `checkpoints.ours` (3.5M).
    assume_valid: bool = false,
    /// Keep every block: compaction still prunes the txhashset but deletes no blocks.
    archive_mode: bool = false,
};

/// The two hashes the reference refuses outright (`check_bad_header`).
const BAD_HASHES = [_][]const u8{
    "840cdf3ad968bd6895b07e4e3235ee704226f85c3163d2da2e6764c7e2b81ea2",
    "a98bbc899892d2553c52ef17cab6d708f9eaf7d575b3d62ca49bbf9d50ae55a7",
};

/// A direct-mapped in-memory cache of recently used headers. Difficulty and
/// bottle calculations walk back through hundreds (sometimes millions) of
/// headers, so serving repeat reads from memory instead of the database helps a
/// lot during sync. Direct-mapped (a slot per hash prefix, collisions simply
/// overwrite) so every operation is O(1) even when nearly every lookup misses;
/// a hash map with removals degrades badly under that access pattern.
pub const HeaderCache = struct {
    const Slot = struct { valid: bool = false, hash: Hash = Hash.zero, header: BlockHeader = undefined };
    slots: []Slot,

    pub fn init(gpa: std.mem.Allocator, capacity: usize) !HeaderCache {
        const slots = try gpa.alloc(Slot, capacity);
        for (slots) |*s| s.valid = false;
        return .{ .slots = slots };
    }
    pub fn deinit(self: *HeaderCache, gpa: std.mem.Allocator) void {
        gpa.free(self.slots);
    }
    fn slotOf(self: *const HeaderCache, h: Hash) usize {
        return @as(usize, @intCast(h.toU64() % self.slots.len));
    }
    pub fn get(self: *const HeaderCache, h: Hash) ?BlockHeader {
        const s = &self.slots[self.slotOf(h)];
        return if (s.valid and s.hash.eql(h)) s.header else null;
    }
    /// Drops everything (used when a batch fails, since cached headers may not have been committed).
    pub fn clear(self: *HeaderCache) void {
        for (self.slots) |*s| s.valid = false;
    }
    pub fn put(self: *HeaderCache, _: std.mem.Allocator, hash: Hash, header: BlockHeader) void {
        self.slots[self.slotOf(hash)] = .{ .valid = true, .hash = hash, .header = header };
    }
};

/// Adapter so the difficulty iterator can read headers through a batch (and the cache).
const HeaderSource = struct {
    db: *const chain_db.Db,
    batch: *kv.Batch,
    cache: *HeaderCache,
    gpa: std.mem.Allocator,
    pub fn get(self: *const HeaderSource, h: Hash) ?BlockHeader {
        if (self.cache.get(h)) |hit| return hit;
        const found = self.db.getBlockHeader(self.batch, h) catch return null;
        if (found) |hdr| self.cache.put(self.gpa, h, hdr);
        return found;
    }
};

pub fn hasMoreWork(header: BlockHeader, head: Tip) bool {
    return header.pow.total_difficulty.order(head.total_difficulty) == .gt;
}

pub const Chain = struct {
    gpa: std.mem.Allocator,
    io: Io,
    cfg: Config,
    root: Io.Dir,
    header_dir: Io.Dir,
    ths_dir: Io.Dir,
    sync_dir: Io.Dir,
    hdr_dir: Io.Dir,
    db: chain_db.Db,
    ths: TxHashSet,
    header_mmr: HeaderMmr,
    sync_mmr: HeaderMmr,
    genesis: Block,
    verifier: pow.Verifier,
    foundation: block.Foundation,
    /// Set while a block is being processed so nested helpers use its batch.
    currentBatch: ?*kv.Batch = null,
    header_cache: HeaderCache,
    /// Per-algorithm difficulty history of the header tip (see header_iter.AlgoIndex).
    algo_index: header_iter.AlgoIndex(HeaderSource) = .{},
    mutex: Io.Mutex = .init,
    /// Bulk catch-up mode: the txhashset files are not fsynced per block (see `beginCatchup`).
    catchup: bool = false,
    /// A state sync (archive extraction and validation) is running; it works in
    /// a sandbox, so a shutdown may simply abandon it.
    state_sync_active: std.atomic.Value(bool) = .init(false),
    /// Where block processing spends its time (nanoseconds): checks, body validation, txhashset update, fsync, db commit.
    prof: [5]i64 = .{ 0, 0, 0, 0, 0 },

    /// Opens (creating if needed) a chain under `data_dir`.
    pub fn open(gpa: std.mem.Allocator, io: Io, data_dir: []const u8, cfg: Config) !*Chain {
        const self = try gpa.create(Chain);
        errdefer gpa.destroy(self);
        self.gpa = gpa;
        self.io = io;
        self.cfg = cfg;
        self.genesis = block.genesisFor(cfg.chain);
        self.foundation = block.Foundation.embedded(cfg.chain);
        self.currentBatch = null;
        // fields with defaults aren't set by `create`: give them their defaults
        self.algo_index = .{};
        self.mutex = .init;
        self.catchup = false;
        self.state_sync_active = .init(false);
        self.prof = .{ 0, 0, 0, 0, 0 };
        self.header_cache = try HeaderCache.init(gpa, 65536);
        errdefer self.header_cache.deinit(gpa);
        self.verifier = pow.Verifier.init(gpa, io);
        errdefer self.verifier.deinit();

        self.root = try Io.Dir.cwd().createDirPathOpen(io, data_dir, .{});
        errdefer self.root.close(io);
        const db_path = try std.fmt.allocPrint(gpa, "{s}/chain", .{data_dir});
        defer gpa.free(db_path);
        self.db = try chain_db.Db.open(gpa, io, db_path, cfg.chain, cfg.kv_options);
        errdefer self.db.close();

        self.header_dir = try self.root.createDirPathOpen(io, "header", .{});
        errdefer self.header_dir.close(io);
        self.hdr_dir = try self.header_dir.createDirPathOpen(io, "header_head", .{});
        errdefer self.hdr_dir.close(io);
        self.sync_dir = try self.header_dir.createDirPathOpen(io, "sync_head", .{});
        errdefer self.sync_dir.close(io);
        self.header_mmr = try HeaderMmr.open(gpa, io, self.hdr_dir);
        errdefer self.header_mmr.close();
        self.sync_mmr = try HeaderMmr.open(gpa, io, self.sync_dir);
        errdefer self.sync_mmr.close();

        self.recoverTxhashsetSwap();
        self.ths_dir = try self.root.createDirPathOpen(io, "txhashset", .{});
        errdefer self.ths_dir.close(io);
        self.ths = try TxHashSet.open(gpa, io, cfg.chain, self.ths_dir, Tip.fromHeader(self.genesis.header), null);
        errdefer self.ths.close();

        try self.setupHead();
        try self.checkAfterUncleanCatchup();
        return self;
    }

    pub fn close(self: *Chain) void {
        self.header_cache.deinit(self.gpa);
        self.ths.close();
        self.sync_mmr.close();
        self.header_mmr.close();
        self.db.close();
        self.ths_dir.close(self.io);
        self.sync_dir.close(self.io);
        self.hdr_dir.close(self.io);
        self.header_dir.close(self.io);
        self.root.close(self.io);
        self.verifier.deinit();
        const gpa = self.gpa;
        gpa.destroy(self);
    }

    pub fn lock(self: *Chain) void {
        self.mutex.lockUncancelable(self.io);
    }
    pub fn unlock(self: *Chain) void {
        self.mutex.unlock(self.io);
    }

    // ---- read access

    pub fn head(self: *Chain) Error!Tip {
        return (try self.db.head(self.db.store)) orelse error.CorruptChain;
    }
    pub fn headerHead(self: *Chain) Error!Tip {
        return (try self.db.headerHead(self.db.store)) orelse error.CorruptChain;
    }
    pub fn syncHead(self: *Chain) Error!Tip {
        return (try self.db.syncHead(self.db.store)) orelse error.CorruptChain;
    }
    pub fn getHeader(self: *Chain, h: Hash) Error!?BlockHeader {
        return self.db.getBlockHeader(self.db.store, h);
    }

    // ---------------------------------------------------------- setup_head

    fn setupHead(self: *Chain) Error!void {
        var batch = self.db.batch();
        defer batch.deinit();

        if (try self.db.head(&batch)) |h| {
            var cur = h;
            // below the oldest stored block there is nothing to rewind the state with
            const tail = (try self.db.tail(&batch)) orelse Tip.fromHeader(self.genesis.header);
            while (true) {
                const header = (try self.db.getBlockHeader(&batch, cur.last_block_h)) orelse return error.CorruptChain;
                if (self.verifyHeadState(&batch, header)) |_| break else |e| {
                    // stepping back can't help if the files are behind even the oldest
                    // stored block (an empty or lost txhashset), or once we reach it
                    const tail_header = (try self.db.getBlockHeader(&batch, tail.last_block_h)) orelse header;
                    if (header.height <= tail.height or self.ths.sizes.output < tail_header.output_mmr_size) {
                        std.log.warn("The chain state doesn't match the stored blocks at height {f} ({s}) and there are no older blocks to step back to. Resetting the chain state: it will be downloaded again (headers are kept).", .{ N(header.height), @errorName(e) });
                        batch.deinit();
                        batch = self.db.batch();
                        try self.resetBodyState(&batch);
                        break;
                    }
                    // The files may not match the head after a crash: step the head back and retry.
                    std.log.warn("setup_head: {s} at {d} failed ({s}), stepping back", .{ header.hash().toHex()[0..12], header.height, @errorName(e) });
                    const prev = (try self.db.getBlockHeader(&batch, cur.prev_block_h)) orelse return error.CorruptChain;
                    try self.db.deleteBlock(&batch, header.hash());
                    cur = Tip.fromHeader(prev);
                    try self.db.saveBodyHead(&batch, cur);
                }
            }
        } else {
            try self.initGenesis(&batch);
        }

        // The sync head restarts from the header head; if the header head is missing, from the body head.
        const body_head = (try self.db.head(&batch)) orelse return error.CorruptChain;
        var header_head = (try self.db.headerHead(&batch)) orelse body_head;
        if ((try self.db.getBlockHeader(&batch, header_head.last_block_h)) == null) {
            header_head = body_head;
            try self.db.saveHeaderHead(&batch, header_head);
        }
        try self.db.saveSyncHead(&batch, header_head);
        try batch.commit();
    }

    /// Starts the body chain again from genesis: an empty txhashset, no stored
    /// blocks except genesis, body head and tail at genesis. Headers are kept,
    /// so the sync goes straight to a new state (txhashset) download.
    fn resetBodyState(self: *Chain, batch: *kv.Batch) Error!void {
        var doomed: std.ArrayList(Hash) = .empty;
        defer doomed.deinit(self.gpa);
        {
            var it = self.db.store.iterator(&.{ chain_db.BLOCK_PREFIX, ':' });
            defer it.deinit();
            while (it.next()) |e| {
                if (e.key.len != 34) continue;
                const h = Hash{ .bytes = e.key[2..34].* };
                if (!h.eql(self.genesis.hash())) try doomed.append(self.gpa, h);
            }
        }
        for (doomed.items) |h| try self.db.deleteBlock(batch, h);

        self.ths.close();
        self.ths_dir.close(self.io);
        try self.root.deleteTree(self.io, "txhashset");
        self.ths_dir = try self.root.createDirPathOpen(self.io, "txhashset", .{});
        const tip = Tip.fromHeader(self.genesis.header);
        self.ths = try TxHashSet.open(self.gpa, self.io, self.cfg.chain, self.ths_dir, tip, null);
        self.ths.head = tip;
        const spent = try self.ths.applyBlock(&self.db, batch, self.genesis);
        self.gpa.free(spent);
        try self.ths.sync();
        try self.db.saveBodyHead(batch, tip);
        try self.db.saveBodyTail(batch, tip);
    }

    fn initGenesis(self: *Chain, batch: *kv.Batch) Error!void {
        const g = self.genesis;
        const tip = Tip.fromHeader(g.header);
        try self.db.saveBlockHeader(batch, g.header);
        try self.db.saveBlock(batch, g);
        try self.db.saveBodyHead(batch, tip);
        try self.db.saveHeaderHead(batch, tip);
        try self.db.saveSpentIndex(batch, g.hash(), &.{});

        var sums = BlockSums.zero;
        if (g.body.kernels.len > 0) {
            const s = try tx.committedVerifyKernelSums(self.gpa, g.body.inputs, g.body.outputs, g.body.kernels, g.header.overage(self.cfg.chain), g.header.total_kernel_offset);
            sums = .{ .utxo_sum = s.utxo_sum, .kernel_sum = s.kernel_sum };
        }
        try self.header_mmr.applyHeader(g.header);
        try self.header_mmr.sync();
        try self.sync_mmr.applyHeader(g.header);
        try self.sync_mmr.sync();

        self.ths.head = tip;
        const spent = try self.ths.applyBlock(&self.db, batch, g);
        self.gpa.free(spent);
        try self.ths.sync();
        try self.db.saveBlockSums(batch, g.hash(), sums);
    }

    /// Checks the txhashset matches `header`'s roots; builds block sums if missing.
    fn verifyHeadState(self: *Chain, batch: *kv.Batch, header: BlockHeader) Error!void {
        self.ths.head = Tip.fromHeader(header);
        errdefer self.ths.discard() catch {};
        errdefer self.header_mmr.discard() catch {};
        try self.rewindAndApplyFork(batch, header);
        try self.ths.validateRoots(header);
        if (header.height > 0 and (try self.db.getBlockSums(batch, header.hash())) == null) {
            const s = try self.ths.validateKernelSums(self.genesis.header, header);
            try self.db.saveBlockSums(batch, header.hash(), s);
        }
        try self.header_mmr.discard();
        try self.ths.sync();
    }

    // ------------------------------------------------------ header helpers

    fn headerChainHeight(mmr: *const HeaderMmr) ?u64 {
        const n = pmmr.nLeaves(mmr.last_pos);
        return if (n == 0) null else n - 1;
    }

    fn isOnCurrentChain(mmr: *HeaderMmr, header: BlockHeader) bool {
        const h = headerChainHeight(mmr) orelse return false;
        if (header.height > h) return false;
        const at = mmr.hashAtHeight(header.height) orelse return false;
        return at.eql(header.hash());
    }

    fn validateRoot(mmr: *HeaderMmr, header: BlockHeader) Error!void {
        if (header.height == 0) return;
        if (!(try mmr.root()).eql(header.prev_root)) return error.InvalidRoot;
    }

    /// Rewinds `mmr` to the fork point of `header` and re-applies the fork's
    /// headers, validating each header's `prev_root`.
    fn rewindAndApplyHeaderFork(self: *Chain, batch: *kv.Batch, mmr: *HeaderMmr, header: BlockHeader) Error!void {
        var fork: std.ArrayList(Hash) = .empty;
        defer fork.deinit(self.gpa);
        var current = header;
        while (current.height > 0 and !isOnCurrentChain(mmr, current)) {
            try fork.append(self.gpa, current.hash());
            current = (try self.db.getPreviousHeader(batch, current)) orelse return error.Orphan;
        }
        try mmr.rewindToHeight(current.height);
        var i = fork.items.len;
        while (i > 0) {
            i -= 1;
            const h = (try self.db.getBlockHeader(batch, fork.items[i])) orelse return error.CorruptChain;
            try validateRoot(mmr, h);
            try mmr.applyHeader(h);
        }
    }

    /// Rewinds the txhashset to the fork point and replays the blocks of the fork
    /// leading to `header`, leaving the state ready to accept the child of `header`.
    fn rewindAndApplyFork(self: *Chain, batch: *kv.Batch, header: BlockHeader) Error!void {
        try self.rewindAndApplyHeaderFork(batch, &self.header_mmr, header);

        const cur_tip = (try self.db.head(batch)) orelse return error.CorruptChain;
        var current = (try self.db.getBlockHeader(batch, cur_tip.last_block_h)) orelse return error.CorruptChain;
        while (current.height > 0 and !isOnCurrentChain(&self.header_mmr, current)) {
            current = (try self.db.getPreviousHeader(batch, current)) orelse return error.CorruptChain;
        }
        const fork_point = current;
        try self.ths.rewind(&self.db, batch, fork_point);

        var hashes: std.ArrayList(Hash) = .empty;
        defer hashes.deinit(self.gpa);
        current = header;
        while (current.height > fork_point.height) {
            try hashes.append(self.gpa, current.hash());
            current = (try self.db.getPreviousHeader(batch, current)) orelse return error.CorruptChain;
        }
        var i = hashes.items.len;
        while (i > 0) {
            i -= 1;
            var fb = (try self.db.getBlock(batch, hashes.items[i])) orelse return error.CorruptChain;
            defer fb.deinit(self.gpa);
            try self.ths.verifyCoinbaseMaturity(&self.db, batch, &self.header_mmr, fb.body.inputs, fb.header.height);
            try self.ths.validateBlockUtxo(&self.db, batch, fb);
            const prev_sums = (try self.db.getBlockSums(batch, fb.header.prev_hash)) orelse return error.CorruptChain;
            _ = try chain_types.verifyBlockSums(self.gpa, prev_sums, fb, self.cfg.chain);
            const spent = try self.applyBlockToTxhashset(fb);
            self.gpa.free(spent);
        }
    }

    fn applyBlockToTxhashset(self: *Chain, b: Block) Error![]chain_types.CommitPos {
        const spent = try self.ths.applyBlock(&self.db, self.currentBatch.?, b);
        errdefer self.gpa.free(spent);
        try self.ths.validateRoots(b.header);
        try self.ths.validateSizes(b.header);
        return spent;
    }

    // ------------------------------------------------------ header validation

    fn checkBadHeader(header: BlockHeader) Error!void {
        const h = header.hash().toHex();
        for (BAD_HASHES) |bad| if (std.mem.eql(u8, &h, bad)) return error.BadHeader;
    }

    fn algoForPolicy(proof: block.Proof) pow_types.PoWType {
        return switch (proof) {
            .cuckoo => |c| if (c.edge_bits == 29) .cuckaroo else .cuckatoo,
            .randomx => .randomx,
            .progpow => .progpow,
        };
    }

    /// `pipe::validate_header`.
    pub fn validateHeader(self: *Chain, batch: *kv.Batch, header: BlockHeader, opts: Options) Error!void {
        return self.validateHeaderPre(batch, header, opts, null);
    }

    /// `pre`: the result of verifying the header's PoW (from `verifyBatch`), if already done.
    fn validateHeaderPre(self: *Chain, batch: *kv.Batch, header: BlockHeader, opts: Options, pre: ?PowResult) Error!void {
        const chain = self.cfg.chain;
        if (!consensus.validHeaderVersion(chain, header.height, header.version)) return error.InvalidBlockVersion;
        const now = Io.Clock.real.now(self.io).toSeconds();
        if (header.timestamp > now + 12 * @as(i64, consensus.BLOCK_TIME_SEC) and chain != .automated_testing) return error.InvalidBlockTime;
        try checkBadHeader(header);

        var proof_diff: ?pow_types.Difficulty = null;
        if (!opts.skip_pow) {
            if (!header.pow.isPrimary(chain.minEdgeBits()) and !header.pow.isSecondary()) return error.LowEdgebits;
            const res = pre orelse blk: {
                break :blk PowResult{ .diff = self.verifier.verifyWithDifficulty(chain, header) catch null };
            };
            proof_diff = res.diff orelse return error.InvalidPow;
        }

        const prev = (try self.db.getPreviousHeader(batch, header)) orelse return error.Orphan;
        const seed_header = (try self.db.getBlockHeader(batch, Hash.fromVec(&header.pow.seed))) orelse return error.InvalidSeed;
        if (seed_header.height != randomx.currentSeedHeight(header.height)) return error.InvalidSeed;

        if (!feijoada.isAllowedPolicy(self.cfg.policy.allowed_policies, header.height, header.policy)) return error.PolicyIsNotAllowed;
        const cfg_policy = self.cfg.policy.policy(header.policy) orelse return error.ThereIsNotPolicy;
        _ = cfg_policy;
        const hsrc = HeaderSource{ .db = &self.db, .batch = batch, .cache = &self.header_cache, .gpa = self.gpa };
        const bottles = header_iter.bottlesCursor(&hsrc, prev.hash(), header.policy);
        const next = consensus.nextPolicy(self.cfg.policy, header.policy, bottles) catch return error.ThereIsNotPolicy;
        if (next[0] != algoForPolicy(header.pow.proof)) return error.InvalidSortAlgo;

        if (header.height != prev.height + 1) return error.InvalidBlockHeight;
        if (header.timestamp <= prev.timestamp and chain != .automated_testing) return error.InvalidBlockTime;

        if (!opts.skip_pow) {
            const target = header.pow.total_difficulty.sub(prev.pow.total_difficulty);
            const proof_algo = header.pow.proof.powType();
            const target_proof = target.toNum(proof_algo);
            const diff = proof_diff.?;
            if (diff.toNum(proof_algo) < target_proof) return error.DifficultyTooLow;

            const src = HeaderSource{ .db = &self.db, .batch = batch, .cache = &self.header_cache, .gpa = self.gpa };
            if (!self.algo_index.isAt(prev.hash())) self.algo_index.build(&src, prev);
            var buf: [consensus.MAX_DIFF_DATA]consensus.HeaderInfo = undefined;
            const cursor = self.algo_index.cursor(&src, &buf);
            const info = consensus.nextDifficultyFor(chain, header.height, prev.pow.proof.powType(), cursor);
            if (!target.eql(info.difficulty)) return error.WrongTotalDifficulty;
            if (header.pow.proof == .cuckoo and header.pow.secondary_scaling != info.secondary_scaling) return error.InvalidScaling;
        }
    }

    // ------------------------------------------------- header processing

    /// State of an in-flight "extension": a child batch plus the header MMR
    /// that is committed (synced) or discarded when it ends.
    fn finishHeaderExt(mmr: *HeaderMmr, child: *kv.Batch, ok: bool, rollback: bool) Error!void {
        if (ok and !rollback) {
            try child.commit();
            try mmr.sync();
        } else {
            child.deinit();
            try mmr.discard();
        }
    }

    /// After a failed batch the caches may describe uncommitted headers: drop them.
    fn resetCaches(self: *Chain) void {
        self.header_cache.clear();
        self.algo_index.invalidate();
    }

    /// Verifies the PoW of the whole run in parallel, then validates each header
    /// in order (the chain-state checks are sequential) and saves it.
    fn validateAndSaveHeaders(self: *Chain, batch: *kv.Batch, headers: []const BlockHeader, opts: Options, verified: ?[]const ?pow_types.Difficulty) Error!void {
        errdefer self.resetCaches();
        var own: ?[]?pow_types.Difficulty = null;
        defer if (own) |o| self.gpa.free(o);
        var pre: []const ?pow_types.Difficulty = &.{};
        if (!opts.skip_pow) {
            if (verified) |v| {
                std.debug.assert(v.len == headers.len);
                pre = v;
            } else {
                const mine = try self.gpa.alloc(?pow_types.Difficulty, headers.len);
                own = mine;
                self.verifier.verifyBatch(self.cfg.chain, headers, mine);
                pre = mine;
            }
        }
        for (headers, 0..) |h, i| {
            try self.validateHeaderPre(batch, h, opts, if (opts.skip_pow) null else PowResult{ .diff = pre[i] });
            try self.db.saveBlockHeader(batch, h);
            self.header_cache.put(self.gpa, h.hash(), h);
            self.algo_index.push(h);
        }
    }

    /// Options for a batch of headers from a peer: enforces checkpoint hashes
    /// and, when configured, skips PoW inside the checkpointed range.
    pub fn optionsForHeaders(self: *Chain, headers: []const BlockHeader) Error!Options {
        if (self.cfg.chain != .mainnet) return .{ .sync = true };
        var within = false;
        for (headers) |h| within = try checkpoints.check(h.height, h.hash(), self.cfg.assume_valid);
        // `headers_received`: skip only if configured, and only inside the
        // checkpointed range unless checkpoints are disabled
        return .{ .sync = true, .skip_pow = self.cfg.skip_pow_in_checkpoints and (within or self.cfg.disable_checkpoints) };
    }

    /// Validates a batch of headers received during header sync and applies
    /// them to the sync MMR (`pipe::sync_block_headers`).
    pub fn syncBlockHeaders(self: *Chain, headers: []const BlockHeader, opts: Options) Error!void {
        if (headers.len == 0) return;
        errdefer self.resetCaches();
        const last = headers[headers.len - 1];
        var batch = self.db.batch();
        defer batch.deinit();
        const sync_head = (try self.db.syncHead(&batch)) orelse return error.CorruptChain;

        if (try self.db.getBlockHeader(&batch, last.hash())) |existing| {
            if (!hasMoreWork(existing, sync_head)) return;
        }
        try self.validateAndSaveHeaders(&batch, headers, opts, null);

        var child = batch.child();
        const res = self.rewindAndApplyHeaderFork(&child, &self.sync_mmr, last);
        try finishHeaderExt(&self.sync_mmr, &child, if (res) |_| true else |_| false, false);
        try res;

        if (hasMoreWork(last, sync_head)) try self.db.saveSyncHead(&batch, Tip.fromHeader(last));
        try batch.commit();
    }

    /// Processes one header (`pipe::process_block_header`); already-known is success.
    fn processBlockHeaderIn(self: *Chain, batch: *kv.Batch, header: BlockHeader, opts: Options) Error!void {
        const prev = (try self.db.getPreviousHeader(batch, header)) orelse return error.Orphan;
        if (self.checkKnown(batch, header)) |_| {} else |_| return;
        const header_head = (try self.db.headerHead(batch)) orelse return error.CorruptChain;
        if (try self.db.getBlockHeader(batch, header.hash())) |existing| {
            if (!hasMoreWork(existing, header_head)) return;
        }

        var child = batch.child();
        const res = blk: {
            self.rewindAndApplyHeaderFork(&child, &self.header_mmr, prev) catch |e| break :blk e;
            validateRoot(&self.header_mmr, header) catch |e| break :blk e;
            self.header_mmr.applyHeader(header) catch |e| break :blk e;
            break :blk {};
        };
        const ok = if (res) |_| true else |_| false;
        try finishHeaderExt(&self.header_mmr, &child, ok, !hasMoreWork(header, header_head));
        try res;

        try self.validateHeader(batch, header, opts);
        try self.db.saveBlockHeader(batch, header);
        self.algo_index.push(header);
        if (hasMoreWork(header, header_head)) try self.db.saveHeaderHead(batch, Tip.fromHeader(header));
    }

    fn checkKnown(self: *Chain, batch: *kv.Batch, header: BlockHeader) Error!void {
        const tip = (try self.db.head(batch)) orelse return error.CorruptChain;
        const bh = header.hash();
        if (bh.eql(tip.last_block_h) or bh.eql(tip.prev_block_h)) return error.Unfit;
        if (try self.db.blockExists(batch, bh)) {
            if (header.height < tip.height -| 50) return error.OldBlock;
            return error.Unfit;
        }
    }


    // ------------------------------------------------------ header acceptance

    /// Validates a run of headers from a peer and extends the header chain
    /// (main header MMR and header head). `headers` must connect to headers we
    /// already have (the first one's `prev_hash`). Already-known runs are a no-op.
    pub fn acceptHeaders(self: *Chain, headers: []const BlockHeader, opts: Options) Error!void {
        return self.acceptHeadersVerified(headers, opts, null);
    }

    /// Checks the PoW of `headers` on all cores (`out[i]` is header i's proof
    /// difficulty, or null if invalid). Needs no chain state, so callers can
    /// run it ahead of `acceptHeadersVerified`, without the chain lock.
    pub fn verifyPow(self: *Chain, headers: []const BlockHeader, out: []?pow_types.Difficulty) void {
        self.verifier.verifyBatch(self.cfg.chain, headers, out);
    }

    /// `acceptHeaders` with the PoW results already computed by `verifyPow`
    /// (null: compute them here).
    pub fn acceptHeadersVerified(self: *Chain, headers: []const BlockHeader, opts: Options, verified: ?[]const ?pow_types.Difficulty) Error!void {
        if (headers.len == 0) return;
        errdefer self.resetCaches();
        const last = headers[headers.len - 1];
        var batch = self.db.batch();
        defer batch.deinit();
        const header_head = (try self.db.headerHead(&batch)) orelse return error.CorruptChain;
        if (try self.db.getBlockHeader(&batch, last.hash())) |existing| {
            if (!hasMoreWork(existing, header_head)) return;
        }
        try self.validateAndSaveHeaders(&batch, headers, opts, verified);
        var child = batch.child();
        const res = self.rewindAndApplyHeaderFork(&child, &self.header_mmr, last);
        try finishHeaderExt(&self.header_mmr, &child, if (res) |_| true else |_| false, false);
        try res;
        if (hasMoreWork(last, header_head)) {
            const t = Tip.fromHeader(last);
            try self.db.saveHeaderHead(&batch, t);
            try self.db.saveSyncHead(&batch, t);
        }
        try batch.commit();
    }

    /// Hashes to send in a `GetHeaders`: the header head, then heads at
    /// exponentially growing distances back to genesis (max `MAX_LOCATORS`).
    pub fn headerLocator(self: *Chain, out: []Hash) Error![]Hash {
        const hh = try self.headerHead();
        var n: usize = 0;
        var step: u64 = 1;
        var height: u64 = hh.height;
        while (n < out.len) {
            const at = self.header_mmr.hashAtHeight(height) orelse break;
            out[n] = at;
            n += 1;
            if (height == 0) break;
            height = height -| step;
            if (n >= 10) step *= 2;
        }
        if (n < out.len and (n == 0 or !out[n - 1].eql(self.genesis.hash()))) {
            out[n] = self.genesis.hash();
            n += 1;
        }
        return out[0..n];
    }

    // ---------------------------------------------------------- state sync

    /// Every header's kernel root must match the kernel MMR at that header's size.
    /// When `header` is on our header chain the heights are checked in parallel
    /// chunks; otherwise by walking back from it.
    pub fn validateKernelHistory(self: *Chain, ths: *TxHashSet, header: BlockHeader) Error!void {
        const on_main = if (self.header_mmr.hashAtHeight(header.height)) |hh| hh.eql(header.hash()) else false;
        if (!on_main) {
            var batch = self.db.batch();
            defer batch.deinit();
            var current = header;
            while (current.height > 0) {
                const root = try ths.kernelRootAt(current.kernel_mmr_size);
                if (!root.eql(current.kernel_root)) return error.InvalidRoot;
                current = (try self.db.getPreviousHeader(&batch, current)) orelse return error.CorruptChain;
            }
            return;
        }
        const CHUNK: u64 = 20_000;
        const Ctx = struct {
            chain: *Chain,
            ths: *const TxHashSet,
            top: u64,
            fn work(c: *@This(), i: usize) anyerror!void {
                const first = @as(u64, i) * CHUNK + 1;
                const last = @min(first + CHUNK - 1, c.top);
                var cache: TxHashSet.PeakCache = .{};
                var h = first;
                while (h <= last) : (h += 1) {
                    const hash = c.chain.header_mmr.hashAtHeight(h) orelse return error.CorruptChain;
                    const hdr = (try c.chain.db.getBlockHeader(c.chain.db.store, hash)) orelse return error.CorruptChain;
                    const root = try c.ths.kernelRootCached(hdr.kernel_mmr_size, &cache);
                    if (!root.eql(hdr.kernel_root)) return error.InvalidRoot;
                }
            }
        };
        var ctx: Ctx = .{ .chain = self, .ths = ths, .top = header.height };
        @import("parallel.zig").forEach(Ctx, &ctx, @intCast((header.height + CHUNK - 1) / CHUNK), Ctx.work) catch |e| return @errorCast(e);
    }

    /// Rebuilds the commitment -> (position, height) index from the unspent set.
    /// Needs every header up to `head_height` in the database.
    pub fn initOutputPosIndex(self: *Chain, ths: *const TxHashSet, batch: *kv.Batch, head_height: u64) Error!void {
        const Entry = struct { commit: crypto.Commitment, pos: u64 };
        var entries: std.ArrayList(Entry) = .empty;
        defer entries.deinit(self.gpa);
        var it = ths.unspentOutputPositions();
        while (it.next()) |pos| {
            const oid = ths.outputAt(pos) orelse continue;
            try entries.append(self.gpa, .{ .commit = oid.commit, .pos = pos });
        }
        if (entries.items.len == 0) return;

        // the output MMR size after each block, read in parallel; an output's
        // height is the first block whose size covers its position
        const sizes = try self.gpa.alloc(u64, head_height + 1);
        defer self.gpa.free(sizes);
        const CHUNK: u64 = 20_000;
        const Ctx = struct {
            chain: *Chain,
            sizes: []u64,
            fn work(c: *@This(), i: usize) anyerror!void {
                const first = @as(u64, i) * CHUNK + 1;
                const last = @min(first + CHUNK - 1, c.sizes.len - 1);
                var h = first;
                while (h <= last) : (h += 1) {
                    const hash = c.chain.header_mmr.hashAtHeight(h) orelse return error.CorruptChain;
                    const hdr = (try c.chain.db.getBlockHeader(c.chain.db.store, hash)) orelse return error.CorruptChain;
                    c.sizes[h] = hdr.output_mmr_size;
                }
            }
        };
        sizes[0] = 0;
        var ctx: Ctx = .{ .chain = self, .sizes = sizes };
        @import("parallel.zig").forEach(Ctx, &ctx, @intCast((head_height + CHUNK - 1) / CHUNK), Ctx.work) catch |e| return @errorCast(e);

        var height: u64 = 1;
        for (entries.items) |e| {
            while (height <= head_height and sizes[height] < e.pos) height += 1;
            if (height > head_height) break;
            try self.db.saveOutputPosHeight(batch, e.commit, e.pos, height);
        }
    }

    // ------------------------------------------------------ compaction

    /// Compacts when the chain is far enough past the last compaction
    /// (`Chain::compact`): prunes spent outputs below the cut-through horizon
    /// from the txhashset files and deletes the blocks older than it. Returns
    /// whether it ran. Caller holds the lock.
    pub fn compact(self: *Chain) Error!bool {
        return self.compactWithHorizon(self.cfg.chain.cutThroughHorizon());
    }

    /// `compact` with a chosen horizon (tests and tools; the node always uses the consensus one).
    pub fn compactWithHorizon(self: *Chain, horizon: u64) Error!bool {
        if (self.catchup) return false;
        const tip = try self.head();
        const tail = (try self.db.tail(self.db.store)) orelse Tip.fromHeader(self.genesis.header);
        // at most once per 60 blocks past the horizon (restarts don't recompact)
        if (tail.height + horizon + 60 > tip.height) return false;

        const t0 = Io.Clock.awake.now(self.io).toMilliseconds();
        const horizon_height = tip.height - horizon;
        const horizon_hash = self.header_mmr.hashAtHeight(horizon_height) orelse return error.CorruptChain;
        const horizon_header = (try self.db.getBlockHeader(self.db.store, horizon_hash)) orelse return error.CorruptChain;
        const head_header = (try self.db.getBlockHeader(self.db.store, tip.last_block_h)) orelse return error.CorruptChain;

        var batch = self.db.batch();
        defer batch.deinit();

        // positions spent after the horizon must survive (a rewind brings them back)
        var rm = try @import("bitmap.zig").Bitmap.init();
        defer rm.deinit();
        var cur = head_header;
        while (cur.height > horizon_header.height) {
            if (try self.db.getSpentIndex(&batch, cur.hash())) |sl| {
                defer self.gpa.free(sl.items);
                for (sl.items) |cp| rm.add(@truncate(cp.pos));
            }
            cur = (try self.db.getPreviousHeader(&batch, cur)) orelse return error.CorruptChain;
        }

        const before = self.ths.prunableBytes();
        try self.ths.compact(horizon_header, &rm);
        const after = self.ths.prunableBytes();

        // old blocks (fork blocks included), their sums and spent indexes
        var doomed: std.ArrayList(Hash) = .empty;
        defer doomed.deinit(self.gpa);
        {
            var it = self.db.store.iterator(&.{ chain_db.BLOCK_PREFIX, ':' });
            defer it.deinit();
            while (it.next()) |e| {
                if (e.key.len != 34) continue;
                var r = ser.Reader.init(self.gpa, e.value, ser.ProtocolVersion.local());
                r.params = self.cfg.chain.readParams();
                const h = BlockHeader.read(&r) catch continue;
                if (h.height < horizon_header.height) try doomed.append(self.gpa, Hash{ .bytes = e.key[2..34].* });
            }
        }
        if (!self.cfg.archive_mode) {
            for (doomed.items) |h| try self.db.deleteBlock(&batch, h);
            try self.db.saveBodyTail(&batch, Tip.fromHeader(horizon_header));
        } else doomed.clearRetainingCapacity();
        try batch.commit();

        // served archives for older headers are no longer useful
        if (self.archiveHeader()) |ah| {
            var nb: [96]u8 = undefined;
            if (std.fmt.bufPrint(&nb, "txhashset_zip_{s}.zip", .{ah.hash().toHex()[0..12]})) |keep| self.removeOldArchives(keep) else |_| {}
        } else |_| {}

        std.log.info("Compaction complete: horizon {f}, {d} MiB of spent outputs pruned, {f} old blocks removed ({d:.1}s)", .{
            N(horizon_header.height),
            (before -| after) >> 20,
            N(doomed.items.len),
            @as(f64, @floatFromInt(Io.Clock.awake.now(self.io).toMilliseconds() - t0)) / 1000.0,
        });
        return true;
    }

    // ------------------------------------------------------ bulk catch-up

    /// Header sync from far behind writes millions of small records: skip
    /// compaction while it runs, then compact once (`endBulkHeaders`).
    pub fn beginBulkHeaders(self: *Chain) void {
        self.db.store.beginBulkLoad() catch |e| std.log.warn("Bulk-load mode unavailable: {s}", .{@errorName(e)});
    }

    pub fn endBulkHeaders(self: *Chain) void {
        self.db.store.endBulkLoad() catch |e| std.log.warn("Compaction after header sync failed: {s}", .{@errorName(e)});
    }

    const CATCHUP_MARKER = "catchup.lock";

    /// While many blocks are replayed, stop fsyncing the txhashset files after
    /// every block (that is most of the time a block takes). A marker file says
    /// so: if the node dies uncleanly before `endCatchup`, the next start
    /// re-validates the txhashset in full instead of trusting unsynced files.
    /// Caller holds the lock.
    pub fn beginCatchup(self: *Chain) void {
        if (self.catchup) return;
        fsutil.saveViaTempFile(self.gpa, self.io, self.root, CATCHUP_MARKER, "catching up: the txhashset files may not be fsynced\n") catch return;
        self.ths.setFsync(false);
        self.catchup = true;
    }

    /// Fsyncs everything and returns to per-block fsync. Caller holds the lock.
    pub fn endCatchup(self: *Chain) void {
        if (!self.catchup) return;
        self.ths.forceSync() catch |e| {
            std.log.warn("Fsync after catch-up failed ({s}); keeping the catch-up marker", .{@errorName(e)});
            return;
        };
        self.ths.setFsync(true);
        self.root.deleteFile(self.io, CATCHUP_MARKER) catch {};
        self.catchup = false;
    }

    /// At startup: a leftover marker means the last catch-up didn't finish
    /// cleanly, so the txhashset files can't be trusted until validated.
    /// Validates the txhashset against the head (the reference's
    /// `Chain::validate`; `fast` skips range proofs and kernel signatures).
    /// Caller holds the chain lock.
    pub fn validateChain(self: *Chain, fast: bool) Error!void {
        const tip = try self.head();
        const header = (try self.db.getBlockHeader(self.db.store, tip.last_block_h)) orelse return error.CorruptChain;
        _ = try self.ths.validate(self.genesis.header, fast, header);
    }

    fn checkAfterUncleanCatchup(self: *Chain) Error!void {
        if (!fsutil.exists(self.io, self.root, CATCHUP_MARKER)) return;
        const tip = try self.head();
        if (tip.height == 0) {
            self.root.deleteFile(self.io, CATCHUP_MARKER) catch {};
            return;
        }
        const header = (try self.db.getBlockHeader(self.db.store, tip.last_block_h)) orelse return error.CorruptChain;
        std.log.warn("The last catch-up did not finish cleanly: validating the whole txhashset at height {f} (a couple of minutes)...", .{N(header.height)});
        _ = self.ths.validate(self.genesis.header, false, header) catch |e| {
            std.log.err("The txhashset failed validation ({s}). Stop the node, delete '{s}/txhashset' and '{s}/chain' and sync again.", .{ @errorName(e), "<data-dir>", "<data-dir>" });
            return error.CorruptChain;
        };
        try self.ths.forceSync();
        self.root.deleteFile(self.io, CATCHUP_MARKER) catch {};
        std.log.info("Txhashset validated successfully", .{});
    }

    /// The stateless part of block validation (range proofs, signatures,
    /// coinbase, kernel sums). Needs no txhashset, so it may run on several
    /// blocks in parallel, without the chain lock.
    pub fn prevalidateBlock(self: *Chain, b: Block) bool {
        const prev = (self.db.getPreviousHeader(self.db.store, b.header) catch return false) orelse return false;
        _ = b.validate(self.gpa, self.cfg.chain, &self.foundation, prev.total_kernel_offset) catch return false;
        return true;
    }

    /// Adopts a downloaded txhashset archive (a zip in `zip_dir/zip_name`) for
    /// the known header `h`: extracts to a sandbox, validates kernel history and
    /// the whole set (including every range proof and kernel signature), then
    /// replaces the live txhashset and moves the body head to `h`.
    pub fn txhashsetWrite(self: *Chain, zip_dir: Io.Dir, zip_name: []const u8, h: Hash) Error!void {
        const header = (try self.db.getBlockHeader(self.db.store, h)) orelse return error.NotFound;
        const io = self.io;
        self.state_sync_active.store(true, .release);
        defer self.state_sync_active.store(false, .release);
        var t: TxHashSet.StageTimer = .{ .io = io, .last_ms = Io.Clock.awake.now(io).toMilliseconds() };

        self.root.deleteTree(io, "tmp_txhashset") catch {};
        var sandbox = try self.root.createDirPathOpen(io, "tmp_txhashset", .{});
        var sandbox_open = true;
        defer if (sandbox_open) sandbox.close(io);
        var th_dir = try sandbox.createDirPathOpen(io, "txhashset", .{});
        var th_dir_open = true;
        defer if (th_dir_open) th_dir.close(io);
        {
            var zf = try zip_dir.openFile(io, zip_name, .{});
            defer zf.close(io);
            var rbuf: [4096]u8 = undefined;
            var fr = zf.reader(io, &rbuf);
            try std.zip.extract(th_dir, &fr, .{});
        }

        t.lap("extract the archive");
        var sths = try TxHashSet.open(self.gpa, io, self.cfg.chain, th_dir, Tip.fromHeader(header), header.hash());
        var sths_open = true;
        defer if (sths_open) sths.close();
        t.lap("open the txhashset");

        // The kernel history check reads the headers and kernel roots; it can run
        // alongside the whole-set validation (which is CPU-bound).
        try sths.rewindToHeaderSizes(header);
        t.lap("rewind to the archive header");
        std.log.info("Rewinding and validating kernel history and the full txhashset (roots, sums, range proofs, kernel signatures), can take a while...", .{});
        const Hist = struct {
            chain: *Chain,
            ths: *TxHashSet,
            header: BlockHeader,
            result: Error!void = {},
            fn run(self_: *@This()) void {
                self_.result = self_.chain.validateKernelHistory(self_.ths, self_.header);
            }
        };
        var hist: Hist = .{ .chain = self, .ths = &sths, .header = header };
        const hist_thread = std.Thread.spawn(.{}, Hist.run, .{&hist}) catch null;
        if (hist_thread == null) Hist.run(&hist);
        const t_val = Io.Clock.awake.now(io).toMilliseconds();
        const validated = sths.validate(self.genesis.header, false, header);
        if (hist_thread) |th| th.join();
        std.log.info("Finished validating txhashset and kernel history in {d:.1}s. Going to replace...", .{@as(f64, @floatFromInt(Io.Clock.awake.now(io).toMilliseconds() - t_val)) / 1000.0});
        try hist.result;
        const sums = try validated;
        t = .{ .io = io, .last_ms = Io.Clock.awake.now(io).toMilliseconds() };

        var batch = self.db.batch();
        defer batch.deinit();
        try self.db.saveBlockSums(&batch, header.hash(), sums);
        const tip = Tip.fromHeader(header);
        try self.db.saveBodyHead(&batch, tip);
        try self.db.saveBodyTail(&batch, tip);
        std.log.info("Rebuilding the output position index...", .{});
        try self.initOutputPosIndex(&sths, &batch, header.height);
        t.lap("output position index");
        try sths.sync();
        t.lap("sync to disk");
        // nothing may hold the new files or folders open while they move (Windows refuses)
        sths.close();
        sths_open = false;
        th_dir.close(io);
        th_dir_open = false;
        sandbox.close(io);
        sandbox_open = false;
        // from here the files and the database change together: a shutdown must
        // wait for the swap instead of abandoning it half done
        self.state_sync_active.store(false, .release);
        try self.swapInTxhashset(&batch, tip, header.hash());
        std.log.info("Replaced txhashset with the new one; body head is now height {f}", .{N(header.height)});
    }


    /// Replaces the live txhashset with the validated one in `tmp_txhashset/txhashset`
    /// and commits `batch` (the new body head) only once the files are in place.
    /// Any failure puts the old txhashset and head back, so the database and the
    /// files never disagree; a crash part-way is tidied up by `recoverTxhashsetSwap`.
    fn swapInTxhashset(self: *Chain, batch: *kv.Batch, tip: Tip, tip_hash: Hash) Error!void {
        const io = self.io;
        const old_head = try self.head();
        self.ths.close();
        self.ths_dir.close(io);
        self.root.deleteTree(io, "txhashset_old") catch {};

        var moved_old = false;
        var moved_new = false;
        const ok: Error!void = blk: {
            self.root.rename("txhashset", self.root, "txhashset_old", io) catch |e| break :blk fsError(e);
            moved_old = true;
            self.root.rename("tmp_txhashset/txhashset", self.root, "txhashset", io) catch |e| break :blk fsError(e);
            moved_new = true;
            batch.commit() catch |e| break :blk e;
        };
        if (ok) |_| {} else |e| {
            std.log.err("Couldn't swap in the new txhashset ({s}); keeping the old one", .{@errorName(e)});
            if (moved_new) self.root.rename("txhashset", self.root, "tmp_txhashset/txhashset", io) catch {};
            if (moved_old) self.root.rename("txhashset_old", self.root, "txhashset", io) catch {};
            self.ths_dir = try self.root.createDirPathOpen(io, "txhashset", .{});
            self.ths = try TxHashSet.open(self.gpa, io, self.cfg.chain, self.ths_dir, old_head, old_head.last_block_h);
            return e;
        }
        self.ths_dir = try self.root.createDirPathOpen(io, "txhashset", .{});
        self.ths = try TxHashSet.open(self.gpa, io, self.cfg.chain, self.ths_dir, tip, tip_hash);
        self.root.deleteTree(io, "txhashset_old") catch {};
        self.root.deleteTree(io, "tmp_txhashset") catch {};
    }

    fn fsError(e: anyerror) Error {
        std.log.err("File operation failed: {s}", .{@errorName(e)});
        return error.Io;
    }

    /// At startup, before the txhashset is opened: finishes tidying a swap that
    /// was interrupted. If only the old copy exists it goes back into place; if
    /// both exist the swap had completed and the old copy is removed.
    fn recoverTxhashsetSwap(self: *Chain) void {
        const io = self.io;
        if (!fsutil.exists(io, self.root, "txhashset_old")) return;
        if (fsutil.exists(io, self.root, "txhashset")) {
            self.root.deleteTree(io, "txhashset_old") catch {};
        } else {
            std.log.warn("Restoring the txhashset from an interrupted swap", .{});
            self.root.rename("txhashset_old", self.root, "txhashset", io) catch |e|
                std.log.err("Couldn't restore txhashset_old: {s}", .{@errorName(e)});
        }
    }

    // ------------------------------------------------------------ serving

    /// The first header of `locator` that is on our header chain
    /// (`find_common_header`). Caller holds the lock.
    pub fn findCommonHeader(self: *Chain, locator: []const Hash) ?BlockHeader {
        for (locator) |h| {
            const header = (self.db.getBlockHeader(self.db.store, h) catch continue) orelse continue;
            const at = self.header_mmr.hashAtHeight(header.height) orelse continue;
            if (at.eql(h)) return header;
        }
        return null;
    }

    /// Up to `MAX_BLOCK_HEADERS` headers following the common header of
    /// `locator`, starting `offset * MAX_BLOCK_HEADERS` further on
    /// (`locate_headers`). Caller holds the lock and frees the slice.
    pub fn locateHeaders(self: *Chain, locator: []const Hash, offset: u8, max: usize) Error![]BlockHeader {
        const common = self.findCommonHeader(locator) orelse return try self.gpa.alloc(BlockHeader, 0);
        const max_height = (try self.headerHead()).height;
        const skip = @as(u64, offset) * max;
        var out: std.ArrayList(BlockHeader) = .empty;
        errdefer out.deinit(self.gpa);
        var h = common.height + 1;
        while (h <= common.height + max) : (h += 1) {
            if (h + skip > max_height) break;
            const hash = self.header_mmr.hashAtHeight(h + skip) orelse break;
            const header = (try self.db.getBlockHeader(self.db.store, hash)) orelse break;
            try out.append(self.gpa, header);
        }
        return out.toOwnedSlice(self.gpa);
    }

    /// The header of the txhashset archive we offer (`txhashset_archive_header`):
    /// the body head minus the state sync threshold, rounded down to the
    /// archive interval. Caller holds the lock.
    pub fn archiveHeader(self: *Chain) Error!BlockHeader {
        const body_head = try self.head();
        var height = body_head.height -| self.cfg.chain.stateSyncThreshold();
        const interval = self.cfg.chain.txhashsetArchiveInterval();
        height -= height % interval;
        const hash = self.header_mmr.hashAtHeight(height) orelse return error.NotFound;
        return (try self.db.getBlockHeader(self.db.store, hash)) orelse error.NotFound;
    }

    /// Makes (or reuses) the zip of the txhashset as of `header`, under
    /// `<data>/txhashset_zip_<hash>.zip` (`zip_read`). Rewinds the live
    /// txhashset to the header just long enough to snapshot the leaf sets, then
    /// restores it. Caller holds the lock. Returns the zip's name and size.
    pub fn txhashsetArchive(self: *Chain, header: BlockHeader, name_buf: []u8) Error!struct { name: []const u8, bytes: u64 } {
        const io = self.io;
        const hh = header.hash();
        const name = std.fmt.bufPrint(name_buf, "txhashset_zip_{s}.zip", .{hh.toHex()[0..12]}) catch return error.Other;
        if (self.root.statFile(io, name, .{})) |st| return .{ .name = name, .bytes = st.size } else |_| {}

        // drop archives of other headers (they only matter to their own requesters)
        self.removeOldArchives(name);

        {
            var batch = self.db.batch();
            defer batch.deinit();
            errdefer self.ths.discard() catch {};
            try self.ths.rewind(&self.db, &batch, header);
            try self.ths.output.snapshot(hh);
            try self.ths.rproof.snapshot(hh);
            try self.ths.discard();
        }

        var entries: [10]zipwrite.Entry = undefined;
        var names: [2][64]u8 = undefined;
        const fixed = [_][]const u8{
            "kernel/pmmr_data.bin",   "kernel/pmmr_hash.bin",
            "output/pmmr_data.bin",   "output/pmmr_hash.bin",
            "output/pmmr_prun.bin",   "rangeproof/pmmr_data.bin",
            "rangeproof/pmmr_hash.bin", "rangeproof/pmmr_prun.bin",
        };
        for (fixed, 0..) |f, i| entries[i] = .{ .name = f, .path = f };
        const leaf_out = std.fmt.bufPrint(&names[0], "output/pmmr_leaf.bin.{s}", .{hh.toHex()[0..12]}) catch return error.Other;
        const leaf_rp = std.fmt.bufPrint(&names[1], "rangeproof/pmmr_leaf.bin.{s}", .{hh.toHex()[0..12]}) catch return error.Other;
        entries[8] = .{ .name = leaf_out, .path = leaf_out };
        entries[9] = .{ .name = leaf_rp, .path = leaf_rp };

        var tmp_buf: [96]u8 = undefined;
        const tmp = std.fmt.bufPrint(&tmp_buf, "{s}.tmp", .{name}) catch return error.Other;
        self.root.deleteFile(io, tmp) catch {};
        var zf = try self.root.createFile(io, tmp, .{ .read = true });
        const bytes = blk: {
            defer zf.close(io);
            break :blk try zipwrite.createStored(self.gpa, io, zf, self.ths_dir, &entries);
        };
        try self.root.rename(tmp, self.root, name, io);
        return .{ .name = name, .bytes = bytes };
    }

    fn removeOldArchives(self: *Chain, keep: []const u8) void {
        var it = self.root.iterate();
        var victims: std.ArrayList([]u8) = .empty;
        defer {
            for (victims.items) |v| self.gpa.free(v);
            victims.deinit(self.gpa);
        }
        while (it.next(self.io) catch null) |e| {
            if (!std.mem.startsWith(u8, e.name, "txhashset_zip_") or std.mem.eql(u8, e.name, keep)) continue;
            const copy = self.gpa.dupe(u8, e.name) catch continue;
            victims.append(self.gpa, copy) catch self.gpa.free(copy);
        }
        for (victims.items) |v| self.root.deleteFile(self.io, v) catch {};
    }

    // ------------------------------------------------------- block pipeline

    /// Runs the block through validation, applies it, and returns the new head
    /// if the chain head moved (`pipe::process_block`).
    pub fn processBlock(self: *Chain, b: Block, opts: Options) Error!?Tip {
        errdefer self.resetCaches();
        var batch = self.db.batch();
        defer batch.deinit();
        self.currentBatch = &batch;
        defer self.currentBatch = null;

        var tp: i96 = Io.Clock.awake.now(self.io).toNanoseconds();
        try self.checkKnown(&batch, b.header);
        const header_known = (try self.db.getBlockHeader(&batch, b.header.hash())) != null;
        // (a header we already accepted had its PoW checked then)
        if (!opts.skip_pow and !header_known) {
            if (!b.header.pow.isPrimary(self.cfg.chain.minEdgeBits()) and !b.header.pow.isSecondary()) return error.LowEdgebits;
            self.verifier.verifySize(b.header) catch return error.InvalidPow;
        }

        const old_head = (try self.db.head(&batch)) orelse return error.CorruptChain;
        const prev = (try self.db.getPreviousHeader(&batch, b.header)) orelse return error.Orphan;
        const is_next = b.header.prev_hash.eql(old_head.last_block_h);
        if (!is_next and !(try self.db.blockExists(&batch, prev.hash()))) return error.Orphan;

        try self.processBlockHeaderIn(&batch, b.header, opts);
        self.lapProf(0, &tp);

        if (!opts.body_validated) _ = b.validate(self.gpa, self.cfg.chain, &self.foundation, prev.total_kernel_offset) catch return error.InvalidBlockProof;
        self.lapProf(1, &tp);

        // ---- txhashset extension
        self.ths.head = old_head;
        var child = batch.child();
        var new_sums: BlockSums = undefined;
        var spent: []chain_types.CommitPos = &.{};
        var rollback = false;
        const res = blk: {
            self.currentBatch = &child;
            self.rewindAndApplyFork(&child, prev) catch |e| break :blk e;
            self.ths.verifyCoinbaseMaturity(&self.db, &child, &self.header_mmr, b.body.inputs, b.header.height) catch |e| break :blk e;
            self.ths.validateBlockUtxo(&self.db, &child, b) catch |e| break :blk e;
            const prev_sums = (self.db.getBlockSums(&child, b.header.prev_hash) catch |e| break :blk e) orelse break :blk error.CorruptChain;
            new_sums = chain_types.verifyBlockSums(self.gpa, prev_sums, b, self.cfg.chain) catch |e| break :blk e;
            spent = self.applyBlockToTxhashset(b) catch |e| break :blk e;
            const cur_head = (self.db.head(&child) catch |e| break :blk e) orelse break :blk error.CorruptChain;
            rollback = !hasMoreWork(b.header, cur_head);
            break :blk {};
        };
        self.currentBatch = &batch;
        defer if (spent.len > 0) self.gpa.free(spent);
        self.lapProf(2, &tp);

        // the header MMR extension is only scaffolding for the fork: always discard it
        self.header_mmr.discard() catch {};
        if (res) |_| {
            if (rollback) {
                child.deinit();
                try self.ths.discard();
            } else {
                try child.commit();
                self.lapProf(3, &tp);
                try self.ths.sync();
                self.lapProf(3, &tp);
            }
        } else |e| {
            child.deinit();
            self.ths.discard() catch {};
            return e;
        }

        try self.db.saveBlock(&batch, b);
        try self.db.saveBlockSums(&batch, b.hash(), new_sums);
        try self.db.saveSpentIndex(&batch, b.hash(), spent);
        if ((try self.db.tail(&batch)) == null) try self.db.saveBodyTail(&batch, Tip.fromHeader(b.header));

        var result: ?Tip = null;
        if (hasMoreWork(b.header, old_head)) {
            const t = Tip.fromHeader(b.header);
            try self.db.saveBodyHead(&batch, t);
            result = t;
        }
        try batch.commit();
        self.lapProf(4, &tp);
        return result;
    }

    fn lapProf(self: *Chain, slot: usize, t: *i96) void {
        const now = Io.Clock.awake.now(self.io).toNanoseconds();
        self.prof[slot] += @intCast(now - t.*);
        t.* = now;
    }
};

// ------------------------------------------------------------------ tests

const testing = std.testing;

fn tmpDataDir(buf: []u8, name: []const u8) ![]const u8 {
    const p = try std.fmt.bufPrint(buf, ".zig-cache/chaintest/{s}", .{name});
    Io.Dir.cwd().deleteTree(testing.io, p) catch {};
    return p;
}

test "a new chain starts at genesis and reopens at the same head" {
    const gpa = testing.allocator;
    var buf: [128]u8 = undefined;
    const path = try tmpDataDir(&buf, "genesis");
    {
        const c = try Chain.open(gpa, testing.io, path, .{ .kv_options = .{ .block_cache_mb = 8, .write_buffer_mb = 4 } });
        defer c.close();
        const h = try c.head();
        try testing.expectEqual(@as(u64, 0), h.height);
        try testing.expect(h.last_block_h.eql(block.genesisMain().hash()));
        try testing.expectEqual(@as(u64, 1), pmmr.nLeaves(c.header_mmr.last_pos));
    }
    const c = try Chain.open(gpa, testing.io, path, .{ .kv_options = .{ .block_cache_mb = 8, .write_buffer_mb = 4 } });
    defer c.close();
    try testing.expectEqual(@as(u64, 0), (try c.head()).height);
    try testing.expectEqual(@as(u64, 0), (try c.syncHead()).height);
}
