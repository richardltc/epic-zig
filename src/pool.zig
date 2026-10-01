//! The transaction pool: port of `pool/src` (`pool.rs`, `transaction_pool.rs`,
//! `types.rs`). A tx is accepted when the aggregate of the whole pool plus the
//! tx is valid against the chain head. Two layers: the txpool (fluffed txs,
//! what we mine from and relay) and the stempool (Dandelion).
//!
//! Not thread-safe by itself: take `TransactionPool.lock()`. Lock order is
//! pool first, then chain (the chain view functions take the chain lock), and
//! nothing may wait for the pool lock while holding the chain lock.
const std = @import("std");
const Io = std.Io;
const consensus = @import("consensus.zig");
const block = @import("block.zig");
const tx_mod = @import("transaction.zig");
const hash_mod = @import("hash.zig");
const chain_types = @import("chain_types.zig");
const shortid = @import("shortid.zig");

const Hash = hash_mod.Hash;
const Transaction = tx_mod.Transaction;
const TxKernel = tx_mod.TxKernel;
const BlockHeader = block.BlockHeader;
const Block = block.Block;
const BlockSums = chain_types.BlockSums;
const ChainType = consensus.ChainType;
const Weighting = tx_mod.Weighting;
const ShortId = shortid.ShortId;

pub const Error = error{
    ImmatureTransaction,
    ImmatureCoinbase,
    OverCapacity,
    LowFeeTransaction,
    DuplicateCommitment,
    DuplicateTx,
    InvalidTx,
    Other,
} || tx_mod.Error || std.mem.Allocator.Error;

pub const Config = struct {
    /// Base fee per unit of weight a tx must pay to be accepted.
    accept_fee_base: u64 = consensus.MILLI_EPIC,
    max_pool_size: usize = 50_000,
    max_stempool_size: usize = 50_000,
    /// Maximum total weight of the txs selected for a block.
    mineable_max_weight: usize = consensus.MAX_BLOCK_WEIGHT,
};

pub const TxSource = enum { push_api, broadcast, fluff, embargo_expired, deaggregate };

/// A pool entry; owns its transaction.
pub const Entry = struct {
    src: TxSource,
    /// Milliseconds since the epoch when the tx first entered the pool.
    tx_at_ms: i64,
    tx: Transaction,

    pub fn clone(self: Entry, gpa: std.mem.Allocator) std.mem.Allocator.Error!Entry {
        return .{ .src = self.src, .tx_at_ms = self.tx_at_ms, .tx = try self.tx.clone(gpa) };
    }
    pub fn deinit(self: *Entry, gpa: std.mem.Allocator) void {
        self.tx.deinit(gpa);
    }
};

/// What the pool needs from the blockchain (`BlockChain`).
pub const ChainView = struct {
    ctx: *anyopaque,
    chain_head: *const fn (*anyopaque) anyerror!BlockHeader,
    block_sums: *const fn (*anyopaque, Hash) anyerror!BlockSums,
    /// Inputs must be unspent and outputs unique in the chain's UTXO set.
    validate_tx: *const fn (*anyopaque, Transaction) anyerror!void,
    verify_coinbase_maturity: *const fn (*anyopaque, Transaction) anyerror!void,
    verify_tx_lock_height: *const fn (*anyopaque, Transaction) anyerror!void,
};

/// What the pool tells the rest of the node (`PoolAdapter`).
pub const Adapter = struct {
    ctx: *anyopaque,
    tx_accepted: *const fn (*anyopaque, *const Entry) void,
    /// Return an error to make the pool fluff the tx instead.
    stem_tx_accepted: *const fn (*anyopaque, *const Entry) anyerror!void,

    pub const noop: Adapter = .{ .ctx = undefined, .tx_accepted = noopAccepted, .stem_tx_accepted = noopStem };
    fn noopAccepted(_: *anyopaque, _: *const Entry) void {}
    fn noopStem(_: *anyopaque, _: *const Entry) anyerror!void {}
};

fn freeTxs(gpa: std.mem.Allocator, txs: []Transaction) void {
    for (txs) |*t| t.deinit(gpa);
    gpa.free(txs);
}

fn cloneTxs(gpa: std.mem.Allocator, txs: []const Transaction) ![]Transaction {
    const out = try gpa.alloc(Transaction, txs.len);
    var n: usize = 0;
    errdefer {
        for (out[0..n]) |*t| t.deinit(gpa);
        gpa.free(out);
    }
    for (txs) |t| {
        out[n] = try t.clone(gpa);
        n += 1;
    }
    return out;
}

// ----------------------------------------------------------------- Pool

pub const Pool = struct {
    gpa: std.mem.Allocator,
    chain_type: ChainType,
    chain: ChainView,
    name: []const u8,
    entries: std.ArrayList(Entry) = .empty,
    /// Tests can't produce real range proofs; they set this to validate everything else.
    test_skip_range_proofs: bool = false,

    pub fn init(gpa: std.mem.Allocator, chain_type: ChainType, chain: ChainView, name: []const u8) Pool {
        return .{ .gpa = gpa, .chain_type = chain_type, .chain = chain, .name = name };
    }

    pub fn deinit(self: *Pool) void {
        for (self.entries.items) |*e| e.deinit(self.gpa);
        self.entries.deinit(self.gpa);
    }

    pub fn size(self: *const Pool) usize {
        return self.entries.items.len;
    }

    pub fn kernelCount(self: *const Pool) usize {
        var n: usize = 0;
        for (self.entries.items) |e| n += e.tx.body.kernels.len;
        return n;
    }

    pub fn containsTx(self: *const Pool, h: Hash) bool {
        for (self.entries.items) |e| if (e.tx.hash().eql(h)) return true;
        return false;
    }

    /// The tx containing the kernel with this hash (a copy; free with `deinit`).
    pub fn retrieveTxByKernelHash(self: *const Pool, h: Hash) std.mem.Allocator.Error!?Transaction {
        for (self.entries.items) |e| {
            for (e.tx.body.kernels) |k| if (k.hash().eql(h)) return try e.tx.clone(self.gpa);
        }
        return null;
    }

    pub const Found = struct {
        txs: []Transaction,
        missing: []ShortId,
        pub fn deinit(self: Found, gpa: std.mem.Allocator) void {
            freeTxs(gpa, self.txs);
            gpa.free(self.missing);
        }
    };

    /// Finds the pool txs whose kernels have the given short ids for the block
    /// `hash` and `nonce`. Doesn't check the result is complete.
    pub fn retrieveTransactions(self: *const Pool, hash: Hash, nonce: u64, kern_ids: []const ShortId) std.mem.Allocator.Error!Found {
        var txs: std.ArrayList(Transaction) = .empty;
        errdefer {
            for (txs.items) |*t| t.deinit(self.gpa);
            txs.deinit(self.gpa);
        }
        var found = try self.gpa.alloc(bool, kern_ids.len);
        defer self.gpa.free(found);
        @memset(found, false);
        var n_found: usize = 0;
        outer: for (self.entries.items) |e| {
            var used = false;
            for (e.tx.body.kernels) |k| {
                const id = shortid.shortId(k.hash(), hash, nonce);
                for (kern_ids, 0..) |want, i| {
                    if (want.eql(id)) {
                        if (!found[i]) n_found += 1;
                        found[i] = true;
                        used = true;
                    }
                }
                if (n_found == kern_ids.len) {
                    if (used) try txs.append(self.gpa, try e.tx.clone(self.gpa));
                    break :outer;
                }
            }
            if (used) try txs.append(self.gpa, try e.tx.clone(self.gpa));
        }
        var missing: std.ArrayList(ShortId) = .empty;
        errdefer missing.deinit(self.gpa);
        for (kern_ids, 0..) |id, i| if (!found[i]) try missing.append(self.gpa, id);
        return .{ .txs = try txs.toOwnedSlice(self.gpa), .missing = try missing.toOwnedSlice(self.gpa) };
    }

    /// Borrowed view of every tx (valid until the pool changes; free the slice only).
    pub fn allTransactions(self: *const Pool) std.mem.Allocator.Error![]Transaction {
        const out = try self.gpa.alloc(Transaction, self.entries.items.len);
        for (self.entries.items, 0..) |e, i| out[i] = e.tx;
        return out;
    }

    /// One aggregate tx of everything in the pool, or null if empty.
    pub fn allTransactionsAggregate(self: *const Pool) Error!?Transaction {
        if (self.entries.items.len == 0) return null;
        const txs = try self.allTransactions();
        defer self.gpa.free(txs);
        var agg = try tx_mod.aggregate(self.gpa, txs);
        errdefer agg.deinit(self.gpa);
        try self.validateTx(agg, .no_limit);
        return agg;
    }

    /// Adds `entry` (taking ownership, freeing it on failure) if the pool, the
    /// `extra_txs` and the entry aggregate into a tx valid at `header`.
    pub fn addToPool(self: *Pool, entry: Entry, extra_txs: []const Transaction, header: BlockHeader) Error!void {
        var e = entry;
        errdefer e.deinit(self.gpa);
        const eh = e.tx.hash();
        for (self.entries.items) |x| if (x.tx.hash().eql(eh)) return error.DuplicateTx;

        const pool_txs = try self.allTransactions();
        defer self.gpa.free(pool_txs);
        const all = try self.gpa.alloc(Transaction, pool_txs.len + extra_txs.len + 1);
        defer self.gpa.free(all);
        @memcpy(all[0..pool_txs.len], pool_txs);
        @memcpy(all[pool_txs.len..][0..extra_txs.len], extra_txs);
        all[all.len - 1] = e.tx;

        var agg = try tx_mod.aggregate(self.gpa, all);
        defer agg.deinit(self.gpa);
        _ = try self.validateRawTx(agg, header, .no_limit);
        try self.entries.append(self.gpa, e);
    }

    /// Validates `tx` alone, against the chain state, and as applied to the
    /// block sums at `header`; returns the new sums.
    fn validateRawTx(self: *const Pool, t: Transaction, header: BlockHeader, weighting: Weighting) Error!BlockSums {
        try self.validateTx(t, weighting);
        self.chain.validate_tx(self.chain.ctx, t) catch |e| return mapChainError(e);
        return self.applyTxToBlockSums(t, header);
    }

    pub fn validateTx(self: *const Pool, t: Transaction, weighting: Weighting) Error!void {
        if (!self.test_skip_range_proofs) return t.validate(self.gpa, self.chain_type, weighting);
        try t.body.validateRead(self.gpa, self.chain_type, weighting);
        try t.body.verifyFeatures();
        _ = try t.body.verifyKernelSums(self.gpa, t.overage(), t.offset);
        try TxKernel.batchSigVerify(self.gpa, t.body.kernels);
    }

    fn applyTxToBlockSums(self: *const Pool, t: Transaction, header: BlockHeader) Error!BlockSums {
        const gpa = self.gpa;
        const offset = try tx_mod.sumKernelOffsets(gpa, &.{ header.total_kernel_offset, t.offset }, &.{});
        const prev = self.chain.block_sums(self.chain.ctx, header.hash()) catch return error.Other;

        var outs: std.ArrayList(crypto.Commitment) = .empty;
        defer outs.deinit(gpa);
        var ins: std.ArrayList(crypto.Commitment) = .empty;
        defer ins.deinit(gpa);
        var kerns: std.ArrayList(crypto.Commitment) = .empty;
        defer kerns.deinit(gpa);
        try outs.append(gpa, prev.utxo_sum);
        for (t.body.outputs) |o| try outs.append(gpa, o.commit);
        for (t.body.inputs) |i| try ins.append(gpa, i.commit);
        try kerns.append(gpa, prev.kernel_sum);
        for (t.body.kernels) |k| try kerns.append(gpa, k.excess);
        const s = try tx_mod.verifyKernelSumsCommits(gpa, ins.items, outs.items, kerns.items, t.overage(), offset);
        return .{ .utxo_sum = s.utxo_sum, .kernel_sum = s.kernel_sum };
    }

    /// Greedily keeps the txs that stay valid when aggregated with those kept
    /// before them (`validate_raw_txs`). Returns copies.
    pub fn validateRawTxs(self: *const Pool, txs: []const Transaction, extra_tx: ?Transaction, header: BlockHeader, weighting: Weighting) Error![]Transaction {
        var valid: std.ArrayList(Transaction) = .empty;
        errdefer {
            for (valid.items) |*t| t.deinit(self.gpa);
            valid.deinit(self.gpa);
        }
        var candidates: std.ArrayList(Transaction) = .empty;
        defer candidates.deinit(self.gpa);
        for (txs) |t| {
            candidates.clearRetainingCapacity();
            if (extra_tx) |x| try candidates.append(self.gpa, x);
            try candidates.appendSlice(self.gpa, valid.items);
            try candidates.append(self.gpa, t);
            var agg = try tx_mod.aggregate(self.gpa, candidates.items);
            defer agg.deinit(self.gpa);
            if (self.validateRawTx(agg, header, weighting)) |_| {
                try valid.append(self.gpa, try t.clone(self.gpa));
            } else |_| {}
        }
        return valid.toOwnedSlice(self.gpa);
    }

    /// Re-adds every entry against `header` (plus `extra_tx`), dropping those that no longer fit.
    pub fn reconcile(self: *Pool, extra_tx: ?Transaction, header: BlockHeader) Error!void {
        var existing = self.entries;
        self.entries = .empty;
        defer existing.deinit(self.gpa);
        var extra: [1]Transaction = undefined;
        const extras: []const Transaction = if (extra_tx) |x| blk: {
            extra[0] = x;
            break :blk extra[0..1];
        } else &.{};
        for (existing.items) |x| self.addToPool(x, extras, header) catch {};
    }

    /// Evicts txs whose kernels or inputs appear in `b`.
    pub fn reconcileBlock(self: *Pool, b: Block) std.mem.Allocator.Error!void {
        var kernel_hashes = std.AutoHashMap([32]u8, void).init(self.gpa);
        defer kernel_hashes.deinit();
        var input_hashes = std.AutoHashMap([32]u8, void).init(self.gpa);
        defer input_hashes.deinit();
        for (b.body.kernels) |k| try kernel_hashes.put(k.hash().bytes, {});
        for (b.body.inputs) |i| try input_hashes.put(i.hash().bytes, {});
        var keep: usize = 0;
        for (self.entries.items) |*e| {
            var drop = false;
            for (e.tx.body.kernels) |k| if (kernel_hashes.contains(k.hash().bytes)) {
                drop = true;
            };
            for (e.tx.body.inputs) |i| if (input_hashes.contains(i.hash().bytes)) {
                drop = true;
            };
            if (drop) {
                e.deinit(self.gpa);
            } else {
                self.entries.items[keep] = e.*;
                keep += 1;
            }
        }
        self.entries.shrinkRetainingCapacity(keep);
    }

    /// Txs whose kernels are all among `kernels` (to deaggregate a multi-kernel tx). Copies.
    pub fn findMatchingTransactions(self: *const Pool, kernels: []const TxKernel) std.mem.Allocator.Error![]Transaction {
        var found: std.ArrayList(Transaction) = .empty;
        errdefer {
            for (found.items) |*t| t.deinit(self.gpa);
            found.deinit(self.gpa);
        }
        for (self.entries.items) |e| {
            var subset = true;
            for (e.tx.body.kernels) |ek| {
                const h = ek.hash();
                var present = false;
                for (kernels) |k| if (k.hash().eql(h)) {
                    present = true;
                };
                if (!present) subset = false;
            }
            if (subset) try found.append(self.gpa, try e.tx.clone(self.gpa));
        }
        return found.toOwnedSlice(self.gpa);
    }

    // ---- mining selection

    const Bucket = struct {
        raw_txs: std.ArrayList(Transaction) = .empty,
        fee_to_weight: u64,
        age_idx: usize,

        fn deinit(self: *Bucket, gpa: std.mem.Allocator) void {
            for (self.raw_txs.items) |*t| t.deinit(gpa);
            self.raw_txs.deinit(gpa);
        }
    };

    fn newBucket(self: *const Pool, t: Transaction, age_idx: usize) !Bucket {
        var b: Bucket = .{ .fee_to_weight = t.feeToWeight(), .age_idx = age_idx };
        errdefer b.deinit(self.gpa);
        try b.raw_txs.append(self.gpa, try t.clone(self.gpa));
        return b;
    }

    /// A copy of `b` with `t` added, if the aggregate is valid.
    fn bucketWith(self: *const Pool, b: Bucket, t: Transaction, weighting: Weighting) !Bucket {
        var nb: Bucket = .{ .fee_to_weight = 0, .age_idx = b.age_idx };
        errdefer nb.deinit(self.gpa);
        for (b.raw_txs.items) |x| try nb.raw_txs.append(self.gpa, try x.clone(self.gpa));
        try nb.raw_txs.append(self.gpa, try t.clone(self.gpa));
        var agg = try tx_mod.aggregate(self.gpa, nb.raw_txs.items);
        defer agg.deinit(self.gpa);
        try self.validateTx(agg, weighting);
        nb.fee_to_weight = agg.feeToWeight();
        return nb;
    }

    /// Orders pool txs for a block: dependent txs are aggregated into buckets
    /// (unless that lowers the bucket's fee/weight), buckets sorted by fee/weight
    /// then age (`bucket_transactions`). Returns copies.
    pub fn bucketTransactions(self: *const Pool, weighting: Weighting) Error![]Transaction {
        const gpa = self.gpa;
        var buckets: std.ArrayList(Bucket) = .empty;
        defer {
            for (buckets.items) |*b| b.deinit(gpa);
            buckets.deinit(gpa);
        }
        var output_commits = std.AutoHashMap([33]u8, usize).init(gpa);
        defer output_commits.deinit();
        var rejected = std.AutoHashMap([33]u8, void).init(gpa);
        defer rejected.deinit();

        for (self.entries.items) |entry| {
            var insert_pos: ?usize = null;
            var is_rejected = false;
            for (entry.tx.body.inputs) |input| {
                if (rejected.contains(input.commit.bytes)) {
                    is_rejected = true;
                    continue;
                } else if (output_commits.get(input.commit.bytes)) |pos| {
                    if (insert_pos != null) {
                        is_rejected = true;
                        continue;
                    } else insert_pos = pos;
                }
            }
            if (is_rejected) {
                for (entry.tx.body.outputs) |o| try rejected.put(o.commit.bytes, {});
                continue;
            }
            if (insert_pos) |pos| {
                const grown = self.bucketWith(buckets.items[pos], entry.tx, weighting) catch |e| switch (e) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => {
                        // aggregation failed: discard this tx
                        for (entry.tx.body.outputs) |o| try rejected.put(o.commit.bytes, {});
                        continue;
                    },
                };
                if (grown.fee_to_weight >= buckets.items[pos].fee_to_weight) {
                    buckets.items[pos].deinit(gpa);
                    buckets.items[pos] = grown;
                } else {
                    var g = grown;
                    g.deinit(gpa);
                    try buckets.append(gpa, try self.newBucket(entry.tx, buckets.items.len));
                }
            } else {
                insert_pos = buckets.items.len;
                try buckets.append(gpa, try self.newBucket(entry.tx, buckets.items.len));
            }
            for (entry.tx.body.outputs) |o| try output_commits.put(o.commit.bytes, insert_pos.?);
        }

        std.mem.sortUnstable(Bucket, buckets.items, {}, struct {
            fn lt(_: void, a: Bucket, b: Bucket) bool {
                if (a.fee_to_weight != b.fee_to_weight) return a.fee_to_weight > b.fee_to_weight;
                return a.age_idx < b.age_idx;
            }
        }.lt);

        var out: std.ArrayList(Transaction) = .empty;
        errdefer {
            for (out.items) |*t| t.deinit(gpa);
            out.deinit(gpa);
        }
        for (buckets.items) |b| for (b.raw_txs.items) |t| try out.append(gpa, try t.clone(gpa));
        return out.toOwnedSlice(gpa);
    }

    /// The txs to put in the next block (`prepare_mineable_transactions`). Copies.
    pub fn prepareMineableTransactions(self: *const Pool, max_weight: usize) Error![]Transaction {
        const weighting: Weighting = .{ .as_limited_transaction = max_weight };
        const txs = try self.bucketTransactions(weighting);
        defer freeTxs(self.gpa, txs);
        const header = self.chain.chain_head(self.chain.ctx) catch return error.Other;
        return self.validateRawTxs(txs, null, header, weighting);
    }
};

const crypto = @import("crypto.zig");

fn mapChainError(e: anyerror) Error {
    return switch (e) {
        error.DuplicateCommitment => error.DuplicateCommitment,
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidTx,
    };
}

// ------------------------------------------------------- TransactionPool

pub const TransactionPool = struct {
    gpa: std.mem.Allocator,
    io: Io,
    cfg: Config,
    chain_type: ChainType,
    txpool: Pool,
    stempool: Pool,
    /// Recently accepted txs, re-tried after a reorg.
    reorg_cache: std.ArrayList(Entry) = .empty,
    chain: ChainView,
    adapter: Adapter,
    mutex: Io.Mutex = .init,

    pub fn init(gpa: std.mem.Allocator, io: Io, chain_type: ChainType, cfg: Config, chain: ChainView, adapter: Adapter) TransactionPool {
        return .{
            .gpa = gpa,
            .io = io,
            .cfg = cfg,
            .chain_type = chain_type,
            .txpool = Pool.init(gpa, chain_type, chain, "txpool"),
            .stempool = Pool.init(gpa, chain_type, chain, "stempool"),
            .chain = chain,
            .adapter = adapter,
        };
    }

    pub fn deinit(self: *TransactionPool) void {
        self.txpool.deinit();
        self.stempool.deinit();
        for (self.reorg_cache.items) |*e| e.deinit(self.gpa);
        self.reorg_cache.deinit(self.gpa);
    }

    pub fn lock(self: *TransactionPool) void {
        self.mutex.lockUncancelable(self.io);
    }
    pub fn unlock(self: *TransactionPool) void {
        self.mutex.unlock(self.io);
    }

    fn nowMs(self: *const TransactionPool) i64 {
        return Io.Clock.real.now(self.io).toMilliseconds();
    }

    fn addToStempool(self: *TransactionPool, entry: Entry, header: BlockHeader) Error!void {
        const txs = try self.txpool.allTransactions();
        defer self.gpa.free(txs);
        try self.stempool.addToPool(entry, txs, header);
    }

    fn addToReorgCache(self: *TransactionPool, entry: Entry) void {
        self.reorg_cache.append(self.gpa, entry) catch {
            var e = entry;
            e.deinit(self.gpa);
            return;
        };
        if (self.reorg_cache.items.len > self.cfg.max_pool_size) {
            var old = self.reorg_cache.orderedRemove(0);
            old.deinit(self.gpa);
        }
    }

    /// Takes ownership of `entry`.
    fn addToTxpool(self: *TransactionPool, entry: Entry, header: BlockHeader) Error!void {
        var e = entry;
        errdefer e.deinit(self.gpa);
        // first deaggregate a multi-kernel tx against what the pool already has
        if (e.tx.body.kernels.len > 1) {
            const txs = try self.txpool.findMatchingTransactions(e.tx.body.kernels);
            defer freeTxs(self.gpa, txs);
            if (txs.len > 0) {
                var tx = try tx_mod.deaggregate(self.gpa, e.tx, txs);
                errdefer tx.deinit(self.gpa);
                try self.txpool.validateTx(tx, .as_transaction);
                e.tx.deinit(self.gpa);
                e.tx = tx;
                e.src = .deaggregate;
            }
        }
        try self.txpool.addToPool(try e.clone(self.gpa), &.{}, header);
        // the stempool must be reconciled against the new txpool
        var agg = try self.txpool.allTransactionsAggregate();
        defer if (agg) |*a| a.deinit(self.gpa);
        try self.stempool.reconcile(agg, header);
        e.deinit(self.gpa);
    }

    /// Adds `tx` (borrowed) to the stempool or the txpool (`add_to_pool`).
    /// A stem tx that can't be stemmed falls back to fluffing.
    pub fn addToPool(self: *TransactionPool, src: TxSource, tx: Transaction, stem: bool, header: BlockHeader) Error!void {
        if (!stem and self.txpool.containsTx(tx.hash())) return error.DuplicateTx;

        var evict = false;
        if (self.isAcceptable(tx, stem)) |_| {} else |e| {
            if (!stem and e == error.OverCapacity) evict = true else return e;
        }

        try self.txpool.validateTx(tx, .as_transaction);
        self.chain.verify_tx_lock_height(self.chain.ctx, tx) catch return error.ImmatureTransaction;
        self.chain.verify_coinbase_maturity(self.chain.ctx, tx) catch return error.ImmatureCoinbase;

        const entry: Entry = .{ .src = src, .tx_at_ms = self.nowMs(), .tx = tx };
        var stemmed = false;
        if (stem) {
            const copy = try entry.clone(self.gpa);
            if (self.addToStempool(copy, header)) |_| {
                if (self.adapter.stem_tx_accepted(self.adapter.ctx, &entry)) |_| stemmed = true else |_| {}
            } else |_| {}
        }
        if (!stemmed) {
            try self.addToTxpool(try entry.clone(self.gpa), header);
            self.addToReorgCache(try entry.clone(self.gpa));
            self.adapter.tx_accepted(self.adapter.ctx, &entry);
        }
        if (evict) self.evictFromTxpool();
    }

    /// Drops the last tx of the fee-ordered txpool: nothing depends on it and it pays least.
    pub fn evictFromTxpool(self: *TransactionPool) void {
        const txs = self.txpool.bucketTransactions(.no_limit) catch return;
        defer freeTxs(self.gpa, txs);
        if (txs.len == 0) return;
        const victim = txs[txs.len - 1].hash();
        for (self.txpool.entries.items, 0..) |e, i| {
            if (e.tx.hash().eql(victim)) {
                var removed = self.txpool.entries.orderedRemove(i);
                removed.deinit(self.gpa);
                return;
            }
        }
    }

    /// Old txs age out of the reorg cache after 30 minutes.
    pub fn truncateReorgCache(self: *TransactionPool, cutoff_ms: i64) void {
        while (self.reorg_cache.items.len > 0 and self.reorg_cache.items[0].tx_at_ms < cutoff_ms) {
            var old = self.reorg_cache.orderedRemove(0);
            old.deinit(self.gpa);
        }
    }

    pub fn reconcileReorgCache(self: *TransactionPool, header: BlockHeader) Error!void {
        for (self.reorg_cache.items) |e| {
            const copy = try e.clone(self.gpa);
            self.addToTxpool(copy, header) catch {};
        }
    }

    /// Reconciles both pools against a newly accepted block.
    pub fn reconcileBlock(self: *TransactionPool, b: Block) Error!void {
        try self.txpool.reconcileBlock(b);
        try self.txpool.reconcile(null, b.header);
        try self.stempool.reconcileBlock(b);
        var agg = try self.txpool.allTransactionsAggregate();
        defer if (agg) |*a| a.deinit(self.gpa);
        try self.stempool.reconcile(agg, b.header);
    }

    pub fn retrieveTxByKernelHash(self: *const TransactionPool, h: Hash) std.mem.Allocator.Error!?Transaction {
        return self.txpool.retrieveTxByKernelHash(h);
    }

    /// Only the txpool is searched (the stempool is under embargo).
    pub fn retrieveTransactions(self: *const TransactionPool, hash: Hash, nonce: u64, kern_ids: []const ShortId) std.mem.Allocator.Error!Pool.Found {
        return self.txpool.retrieveTransactions(hash, nonce, kern_ids);
    }

    fn isAcceptable(self: *const TransactionPool, tx: Transaction, stem: bool) Error!void {
        if (self.totalSize() > self.cfg.max_pool_size) return error.OverCapacity;
        if (stem and self.stempool.size() > self.cfg.max_stempool_size) return error.OverCapacity;
        if (self.cfg.accept_fee_base > 0) {
            const threshold = @as(u64, tx.txWeight()) * self.cfg.accept_fee_base;
            if (tx.fee() < threshold) return error.LowFeeTransaction;
        }
    }

    pub fn totalSize(self: *const TransactionPool) usize {
        return self.txpool.size();
    }

    pub fn prepareMineableTransactions(self: *const TransactionPool) Error![]Transaction {
        return self.txpool.prepareMineableTransactions(self.cfg.mineable_max_weight);
    }
};

// ------------------------------------------------------------------ tests

const testing = std.testing;

/// A chain stand-in: everything is valid, block sums are whatever the test says.
const FakeChain = struct {
    header: BlockHeader,
    sums: BlockSums,
    reject_commit: ?[33]u8 = null,

    fn view(self: *FakeChain) ChainView {
        return .{
            .ctx = self,
            .chain_head = head,
            .block_sums = sums_fn,
            .validate_tx = validate,
            .verify_coinbase_maturity = ok,
            .verify_tx_lock_height = ok,
        };
    }
    fn head(ctx: *anyopaque) anyerror!BlockHeader {
        const self: *FakeChain = @ptrCast(@alignCast(ctx));
        return self.header;
    }
    fn sums_fn(ctx: *anyopaque, _: Hash) anyerror!BlockSums {
        const self: *FakeChain = @ptrCast(@alignCast(ctx));
        return self.sums;
    }
    fn validate(ctx: *anyopaque, t: Transaction) anyerror!void {
        const self: *FakeChain = @ptrCast(@alignCast(ctx));
        if (self.reject_commit) |rc| for (t.body.outputs) |o| if (std.mem.eql(u8, &o.commit.bytes, &rc)) return error.DuplicateCommitment;
    }
    fn ok(_: *anyopaque, _: Transaction) anyerror!void {}
};

fn testTx(gpa: std.mem.Allocator, in_value: u64, in_blind: u8, out_value: u64, out_blind: u8, fee: u64, seed: u8) !Transaction {
    return tx_mod.testTx(gpa, in_value, in_blind, out_value, out_blind, fee, seed);
}

test "pool: accepts dependent txs, rejects duplicates, buckets, reconciles" {
    const gpa = testing.allocator;
    var fake: FakeChain = .{ .header = block.genesisMain().header, .sums = BlockSums.zero };
    var pool = Pool.init(gpa, .mainnet, fake.view(), "txpool");
    defer pool.deinit();
    pool.test_skip_range_proofs = true;
    const header = fake.header;

    var a = try testTx(gpa, 100, 3, 90, 10, 10, 1);
    defer a.deinit(gpa);
    var b = try testTx(gpa, 90, 10, 70, 20, 20, 2);
    defer b.deinit(gpa);

    try pool.addToPool(.{ .src = .broadcast, .tx_at_ms = 1, .tx = try a.clone(gpa) }, &.{}, header);
    try pool.addToPool(.{ .src = .broadcast, .tx_at_ms = 2, .tx = try b.clone(gpa) }, &.{}, header);
    try testing.expectEqual(@as(usize, 2), pool.size());
    try testing.expectError(error.DuplicateTx, pool.addToPool(.{ .src = .broadcast, .tx_at_ms = 3, .tx = try a.clone(gpa) }, &.{}, header));
    try testing.expect(pool.containsTx(a.hash()));

    // a tx conflicting with the pool (spends A's input again) doesn't fit
    var c = try testTx(gpa, 100, 3, 80, 11, 20, 3);
    try testing.expectError(error.DuplicateError, pool.addToPool(.{ .src = .broadcast, .tx_at_ms = 4, .tx = c }, &.{}, header));
    c = undefined;

    // one bucket: B aggregates into A's (higher fee/weight), so the order is [A, B]
    const ordered = try pool.bucketTransactions(.no_limit);
    defer freeTxs(gpa, ordered);
    try testing.expectEqual(@as(usize, 2), ordered.len);
    try testing.expect(ordered[0].hash().eql(a.hash()));
    try testing.expect(ordered[1].hash().eql(b.hash()));

    // the aggregate of the pool
    var agg = (try pool.allTransactionsAggregate()).?;
    defer agg.deinit(gpa);
    try testing.expectEqual(@as(usize, 2), agg.body.kernels.len);
    try testing.expectEqual(@as(u64, 30), agg.fee());

    // short ids: find B by the id of its kernel, report an unknown id as missing
    const block_hash = Hash.fromVec(&.{9});
    const want = [_]ShortId{
        shortid.shortId(b.body.kernels[0].hash(), block_hash, 77),
        shortid.shortId(Hash.fromVec(&.{1, 2, 3}), block_hash, 77),
    };
    const found = try pool.retrieveTransactions(block_hash, 77, &want);
    defer found.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), found.txs.len);
    try testing.expect(found.txs[0].hash().eql(b.hash()));
    try testing.expectEqual(@as(usize, 1), found.missing.len);
    try testing.expect(found.missing[0].eql(want[1]));

    // a block that contains A's kernel evicts A; B survives on its own
    const blk: Block = .{ .header = header, .body = .{ .inputs = &.{}, .outputs = &.{}, .kernels = a.body.kernels } };
    try pool.reconcileBlock(blk);
    try testing.expectEqual(@as(usize, 1), pool.size());
    try pool.reconcile(null, header);
    try testing.expectEqual(@as(usize, 1), pool.size());
    try testing.expect(pool.containsTx(b.hash()));
}

test "pool: chain rejections and fees" {
    const gpa = testing.allocator;
    var fake: FakeChain = .{ .header = block.genesisMain().header, .sums = BlockSums.zero };
    var tp = TransactionPool.init(gpa, testing.io, .mainnet, .{ .accept_fee_base = 0 }, fake.view(), Adapter.noop);
    defer tp.deinit();
    tp.txpool.test_skip_range_proofs = true;
    tp.stempool.test_skip_range_proofs = true;
    const header = fake.header;

    var a = try testTx(gpa, 100, 3, 90, 10, 10, 1);
    defer a.deinit(gpa);
    // the chain says A's output already exists
    fake.reject_commit = a.body.outputs[0].commit.bytes;
    try testing.expectError(error.DuplicateCommitment, tp.addToPool(.fluff, a, false, header));
    try testing.expectEqual(@as(usize, 0), tp.totalSize());
    fake.reject_commit = null;
    try tp.addToPool(.fluff, a, false, header);
    try testing.expectEqual(@as(usize, 1), tp.totalSize());
    try testing.expectEqual(@as(usize, 1), tp.reorg_cache.items.len);
    try testing.expectError(error.DuplicateTx, tp.addToPool(.fluff, a, false, header));

    // the default fee base demands 4 * 0.001 EPIC for a 1-in/1-out tx; A pays 10 units
    tp.cfg.accept_fee_base = consensus.MILLI_EPIC;
    var b = try testTx(gpa, 90, 10, 70, 20, 20, 2);
    defer b.deinit(gpa);
    try testing.expectError(error.LowFeeTransaction, tp.addToPool(.fluff, b, false, header));

    // a stem tx the adapter accepts stays in the stempool only
    tp.cfg.accept_fee_base = 0;
    try tp.addToPool(.push_api, b, true, header);
    try testing.expectEqual(@as(usize, 1), tp.totalSize());
    try testing.expectEqual(@as(usize, 1), tp.stempool.size());

    // one the adapter refuses to relay is fluffed into the txpool instead
    const Refuse = struct {
        fn stem(_: *anyopaque, _: *const Entry) anyerror!void {
            return error.NoRelay;
        }
        fn accepted(_: *anyopaque, _: *const Entry) void {}
    };
    var dummy: u8 = 0;
    tp.adapter = .{ .ctx = &dummy, .tx_accepted = Refuse.accepted, .stem_tx_accepted = Refuse.stem };
    var c = try testTx(gpa, 70, 20, 50, 30, 20, 4);
    defer c.deinit(gpa);
    try tp.addToPool(.push_api, c, true, header);
    try testing.expectEqual(@as(usize, 2), tp.totalSize());
}

test "dandelion: embargoed and aggregated stem transactions get fluffed" {
    const gpa = testing.allocator;
    const dandelion = @import("dandelion.zig");
    var fake: FakeChain = .{ .header = block.genesisMain().header, .sums = BlockSums.zero };
    var tp = TransactionPool.init(gpa, testing.io, .mainnet, .{ .accept_fee_base = 0 }, fake.view(), Adapter.noop);
    defer tp.deinit();
    tp.txpool.test_skip_range_proofs = true;
    tp.stempool.test_skip_range_proofs = true;
    const header = fake.header;
    const cfg: dandelion.Config = .{};

    var a = try testTx(gpa, 100, 3, 90, 10, 10, 1);
    defer a.deinit(gpa);
    var b = try testTx(gpa, 90, 10, 70, 20, 20, 2);
    defer b.deinit(gpa);

    // the (noop) adapter accepts stem transactions, so they wait in the stempool
    try tp.addToPool(.broadcast, a, true, header);
    try tp.addToPool(.broadcast, b, true, header);
    try testing.expectEqual(@as(usize, 2), tp.stempool.size());
    try testing.expectEqual(@as(usize, 0), tp.txpool.size());
    const t0 = tp.stempool.entries.items[0].tx_at_ms;

    // not old enough: nothing happens
    try testing.expectEqual(@as(usize, 0), try dandelion.processExpired(&tp, cfg, t0 + 1000, 0, header));
    try dandelion.processFluffPhase(&tp, cfg, false, t0 + 1000, header);
    try testing.expectEqual(@as(usize, 2), tp.stempool.size());

    // in a fluff epoch, once a tx is older than the aggregation time, everything is aggregated and fluffed
    try dandelion.processFluffPhase(&tp, cfg, false, t0 + 31_000, header);
    try testing.expectEqual(@as(usize, 0), tp.stempool.size());
    try testing.expectEqual(@as(usize, 1), tp.txpool.size());
    try testing.expectEqual(@as(usize, 2), tp.txpool.entries.items[0].tx.body.kernels.len);

    // embargo: a stem transaction nobody has seen is fluffed on its own after ~3 minutes
    var c = try testTx(gpa, 70, 20, 50, 30, 20, 4);
    defer c.deinit(gpa);
    try tp.addToPool(.broadcast, c, true, header);
    try testing.expectEqual(@as(usize, 1), tp.stempool.size());
    const tc = tp.stempool.entries.items[0].tx_at_ms;
    try testing.expectEqual(@as(usize, 0), try dandelion.processExpired(&tp, cfg, tc + 179_000, 0, header));
    try testing.expectEqual(@as(usize, 1), try dandelion.processExpired(&tp, cfg, tc + 181_000, 0, header));
    try testing.expectEqual(@as(usize, 0), tp.stempool.size());
    try testing.expect(tp.txpool.containsTx(c.hash()) or tp.txpool.size() == 2);
}
