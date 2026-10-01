//! Dandelion++ transaction relay (`DandelionEpoch` and `dandelion_monitor.rs`).
//!
//! A node is either "stem" or "fluff" for a whole epoch. A stem node passes a
//! new transaction to just one outbound peer (the relay) instead of announcing
//! it to everyone, which hides where it came from. A fluff node holds stem
//! transactions a little (to aggregate them) and then announces them to all.
//! Every stem transaction also has an embargo timer: if it isn't seen on the
//! network in time, we fluff it ourselves.
const std = @import("std");
const Io = std.Io;
const net = Io.net;
const pool_mod = @import("pool.zig");
const tx_mod = @import("transaction.zig");
const block = @import("block.zig");

pub const Config = struct {
    /// Length of an epoch.
    epoch_secs: i64 = 600,
    /// Fluff a stem transaction that hasn't been seen after this long (plus up to 30 s of jitter).
    embargo_secs: i64 = 180,
    /// In a fluff epoch, stem transactions older than this are aggregated and fluffed.
    aggregation_secs: i64 = 30,
    /// Percent of epochs that are "stem".
    stem_probability: u8 = 90,
    /// Stem our own (API-pushed) transactions even in a fluff epoch.
    always_stem_our_txs: bool = true,
};

/// The epoch state: stem or fluff, since when, and the relay peer.
pub const Epoch = struct {
    cfg: Config,
    /// Unix seconds the epoch started; 0 means none yet.
    start_s: i64 = 0,
    is_stem: bool = true,
    relay: ?net.IpAddress = null,

    pub fn isExpired(self: *const Epoch, now_s: i64) bool {
        return self.start_s == 0 or now_s - self.start_s > self.cfg.epoch_secs;
    }

    /// Starts the next epoch: stem with `stem_probability`%, relay `relay`.
    /// `roll` is a uniform number in 0..100.
    pub fn next(self: *Epoch, now_s: i64, relay: ?net.IpAddress, roll: u8) void {
        self.start_s = now_s;
        self.relay = relay;
        self.is_stem = roll < self.cfg.stem_probability;
    }

    /// Whether a transaction from `src` should be stemmed right now.
    pub fn shouldStem(self: *const Epoch, src: pool_mod.TxSource) bool {
        return self.is_stem or (src == .push_api and self.cfg.always_stem_our_txs);
    }
};

/// In a fluff epoch (or when the epoch is over): if any stem transaction is
/// older than the aggregation time, aggregate *all* of them with the txpool and
/// fluff the result (`process_fluff_phase`). Needs the pool lock.
pub fn processFluffPhase(pool: *pool_mod.TransactionPool, cfg: Config, epoch_expired: bool, now_ms: i64, header: block.BlockHeader) !void {
    const gpa = pool.gpa;
    if (pool.stempool.size() == 0) return;
    var any_old = false;
    for (pool.stempool.entries.items) |e| if (now_ms - e.tx_at_ms > cfg.aggregation_secs * 1000) {
        any_old = true;
    };
    if (!epoch_expired and !any_old) return;

    const txs = try pool.stempool.allTransactions();
    defer gpa.free(txs);
    var txpool_agg = try pool.txpool.allTransactionsAggregate();
    defer if (txpool_agg) |*a| a.deinit(gpa);
    const fluffable = try pool.stempool.validateRawTxs(txs, txpool_agg, header, .no_limit);
    defer {
        for (fluffable) |*t| t.deinit(gpa);
        gpa.free(fluffable);
    }
    if (fluffable.len == 0) return;
    var agg = try tx_mod.aggregate(gpa, fluffable);
    defer agg.deinit(gpa);
    try pool.txpool.validateTx(agg, .as_transaction);
    try pool.addToPool(.fluff, agg, false, header);
}

/// Fluffs stem transactions whose embargo has run out (`process_expired_entries`).
/// `jitter_s` (0..30) is added to the embargo. Needs the pool lock. Returns how many were fluffed.
pub fn processExpired(pool: *pool_mod.TransactionPool, cfg: Config, now_ms: i64, jitter_s: i64, header: block.BlockHeader) !usize {
    const gpa = pool.gpa;
    const cutoff_ms = (cfg.embargo_secs + jitter_s) * 1000;
    var expired: std.ArrayList(tx_mod.Transaction) = .empty;
    defer {
        for (expired.items) |*t| t.deinit(gpa);
        expired.deinit(gpa);
    }
    for (pool.stempool.entries.items) |e| {
        if (now_ms - e.tx_at_ms > cutoff_ms) try expired.append(gpa, try e.tx.clone(gpa));
    }
    var n: usize = 0;
    for (expired.items) |t| {
        if (pool.addToPool(.embargo_expired, t, false, header)) |_| n += 1 else |_| {}
    }
    return n;
}

test "epochs: expiry, stem probability and always-stem for our own txs" {
    var e: Epoch = .{ .cfg = .{} };
    try std.testing.expect(e.isExpired(1000)); // no epoch yet
    e.next(1000, null, 50);
    try std.testing.expect(e.is_stem);
    try std.testing.expect(!e.isExpired(1000 + 600));
    try std.testing.expect(e.isExpired(1000 + 601));
    e.next(2000, null, 95); // a fluff epoch
    try std.testing.expect(!e.is_stem);
    try std.testing.expect(!e.shouldStem(.broadcast));
    try std.testing.expect(e.shouldStem(.push_api));
    e.cfg.always_stem_our_txs = false;
    try std.testing.expect(!e.shouldStem(.push_api));
}

test "a stem transaction survives the wire (what the relay peer receives)" {
    const gpa = std.testing.allocator;
    const msg = @import("p2p_msg.zig");
    const ser = @import("ser.zig");
    var t = try tx_mod.testTx(gpa, 100, 3, 90, 10, 10, 1);
    defer t.deinit(gpa);
    const framed = try msg.encode(gpa, .mainnet, .stem_transaction, t, ser.ProtocolVersion.local());
    defer gpa.free(framed);
    const head = try msg.MsgHeader.parse(.mainnet, framed[0..msg.MsgHeader.LEN]);
    try std.testing.expectEqual(msg.MsgType.stem_transaction, head.msg_type);
    var r = ser.Reader.init(gpa, framed[msg.MsgHeader.LEN..], ser.ProtocolVersion.local());
    r.params = consensus.ChainType.mainnet.readParams();
    var back = try tx_mod.Transaction.read(&r);
    defer back.deinit(gpa);
    try std.testing.expect(back.hash().eql(t.hash()));
}

const consensus = @import("consensus.zig");
