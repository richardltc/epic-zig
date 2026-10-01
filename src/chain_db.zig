//! Chain database: headers, blocks, heads, output positions, block sums and
//! spent indexes on top of `kv` (the reference's `chain/src/store.rs`, with
//! RocksDB in place of LMDB). Key layout follows the reference.
//!
//! Readers take `src: anytype`, either a `*kv.Store` (committed state) or a
//! `*kv.Batch` (read-your-writes); writers take a `*kv.Batch`.
const std = @import("std");
const kv = @import("kv.zig");
const ser = @import("ser.zig");
const hash_mod = @import("hash.zig");
const crypto = @import("crypto.zig");
const block = @import("block.zig");
const consensus = @import("consensus.zig");
const chain_types = @import("chain_types.zig");

const Hash = hash_mod.Hash;
const Commitment = crypto.Commitment;
const Tip = chain_types.Tip;
const CommitPos = chain_types.CommitPos;
const BlockSums = chain_types.BlockSums;
const BlockHeader = block.BlockHeader;
const Block = block.Block;

pub const BLOCK_HEADER_PREFIX: u8 = 'h';
pub const BLOCK_PREFIX: u8 = 'b';
pub const HEAD_PREFIX: u8 = 'H';
pub const TAIL_PREFIX: u8 = 'T';
pub const SYNC_HEAD_PREFIX: u8 = 's';
pub const HEADER_HEAD_PREFIX: u8 = 'I';
pub const OUTPUT_POS_PREFIX: u8 = 'p';
pub const BLOCK_SUMS_PREFIX: u8 = 'M';
pub const BLOCK_SPENT_PREFIX: u8 = 'S';

pub const Error = kv.Error;

fn hashKey(prefix: u8, h: Hash) [34]u8 {
    var k: [34]u8 = undefined;
    k[0] = prefix;
    k[1] = ':';
    @memcpy(k[2..], &h.bytes);
    return k;
}

fn commitKey(c: Commitment) [35]u8 {
    var k: [35]u8 = undefined;
    k[0] = OUTPUT_POS_PREFIX;
    k[1] = ':';
    @memcpy(k[2..], &c.bytes);
    return k;
}

/// Deserializes with the chain's read parameters so header versions and proof
/// sizes are checked for `chain`.
pub const Db = struct {
    gpa: std.mem.Allocator,
    store: *kv.Store,
    chain: consensus.ChainType,

    pub fn open(gpa: std.mem.Allocator, io: std.Io, path: []const u8, chain: consensus.ChainType, options: kv.Options) !Db {
        const store = try kv.Store.open(gpa, io, path, options, ser.ProtocolVersion.local());
        return .{ .gpa = gpa, .store = store, .chain = chain };
    }

    pub fn close(self: *Db) void {
        self.store.close();
    }

    pub fn batch(self: *Db) kv.Batch {
        return self.store.batch();
    }

    // ---- typed reads (`src`: *kv.Store or *kv.Batch)

    fn getSerParams(self: *const Db, comptime T: type, src: anytype, key: []const u8) Error!?T {
        const bytes = (try src.get(self.gpa, key)) orelse return null;
        defer self.gpa.free(bytes);
        var r = ser.Reader.init(self.gpa, bytes, ser.ProtocolVersion.local());
        r.params = self.chain.readParams();
        return T.read(&r) catch error.SerError;
    }

    pub fn head(self: *const Db, src: anytype) Error!?Tip {
        return self.getSerParams(Tip, src, &.{HEAD_PREFIX});
    }
    pub fn tail(self: *const Db, src: anytype) Error!?Tip {
        return self.getSerParams(Tip, src, &.{TAIL_PREFIX});
    }
    pub fn headerHead(self: *const Db, src: anytype) Error!?Tip {
        return self.getSerParams(Tip, src, &.{HEADER_HEAD_PREFIX});
    }
    pub fn syncHead(self: *const Db, src: anytype) Error!?Tip {
        return self.getSerParams(Tip, src, &.{SYNC_HEAD_PREFIX});
    }

    pub fn getBlockHeader(self: *const Db, src: anytype, h: Hash) Error!?BlockHeader {
        return self.getSerParams(BlockHeader, src, &hashKey(BLOCK_HEADER_PREFIX, h));
    }

    pub fn getPreviousHeader(self: *const Db, src: anytype, header: BlockHeader) Error!?BlockHeader {
        return self.getBlockHeader(src, header.prev_hash);
    }

    /// The returned block owns its body allocations (free with `deinit(gpa)`).
    pub fn getBlock(self: *const Db, src: anytype, h: Hash) Error!?Block {
        return self.getSerParams(Block, src, &hashKey(BLOCK_PREFIX, h));
    }

    pub fn blockExists(_: *const Db, src: anytype, h: Hash) Error!bool {
        return src.exists(&hashKey(BLOCK_PREFIX, h));
    }

    pub fn getBlockSums(self: *const Db, src: anytype, h: Hash) Error!?BlockSums {
        return self.getSerParams(BlockSums, src, &hashKey(BLOCK_SUMS_PREFIX, h));
    }

    /// Spent outputs of a block; free `.items` with the db allocator.
    pub fn getSpentIndex(self: *const Db, src: anytype, h: Hash) Error!?chain_types.SpentList {
        return self.getSerParams(chain_types.SpentList, src, &hashKey(BLOCK_SPENT_PREFIX, h));
    }

    pub fn getOutputPosHeight(self: *const Db, src: anytype, c: Commitment) Error!?CommitPos {
        return self.getSerParams(CommitPos, src, &commitKey(c));
    }

    // ---- writes

    pub fn saveBodyHead(_: *const Db, b: *kv.Batch, t: Tip) Error!void {
        try b.putSer(&.{HEAD_PREFIX}, t);
    }
    pub fn saveBodyTail(_: *const Db, b: *kv.Batch, t: Tip) Error!void {
        try b.putSer(&.{TAIL_PREFIX}, t);
    }
    pub fn saveHeaderHead(_: *const Db, b: *kv.Batch, t: Tip) Error!void {
        try b.putSer(&.{HEADER_HEAD_PREFIX}, t);
    }
    pub fn saveSyncHead(_: *const Db, b: *kv.Batch, t: Tip) Error!void {
        try b.putSer(&.{SYNC_HEAD_PREFIX}, t);
    }

    pub fn saveBlockHeader(_: *const Db, b: *kv.Batch, h: BlockHeader) Error!void {
        try b.putSer(&hashKey(BLOCK_HEADER_PREFIX, h.hash()), h);
    }
    pub fn saveBlock(_: *const Db, b: *kv.Batch, blk: Block) Error!void {
        try b.putSer(&hashKey(BLOCK_PREFIX, blk.hash()), blk);
    }
    pub fn deleteBlock(_: *const Db, b: *kv.Batch, h: Hash) Error!void {
        try b.delete(&hashKey(BLOCK_PREFIX, h));
        try b.delete(&hashKey(BLOCK_SUMS_PREFIX, h));
        try b.delete(&hashKey(BLOCK_SPENT_PREFIX, h));
    }
    pub fn saveBlockSums(_: *const Db, b: *kv.Batch, h: Hash, sums: BlockSums) Error!void {
        try b.putSer(&hashKey(BLOCK_SUMS_PREFIX, h), sums);
    }
    pub fn saveSpentIndex(_: *const Db, b: *kv.Batch, h: Hash, spent: []const CommitPos) Error!void {
        try b.putSer(&hashKey(BLOCK_SPENT_PREFIX, h), chain_types.SpentList{ .items = @constCast(spent) });
    }
    pub fn saveOutputPosHeight(_: *const Db, b: *kv.Batch, c: Commitment, pos: u64, height: u64) Error!void {
        try b.putSer(&commitKey(c), CommitPos{ .pos = pos, .height = height });
    }
    pub fn deleteOutputPosHeight(_: *const Db, b: *kv.Batch, c: Commitment) Error!void {
        try b.delete(&commitKey(c));
    }
};

// ------------------------------------------------------------------ tests

const testing = std.testing;

fn openTest(gpa: std.mem.Allocator, sub: []const u8) !Db {
    var buf: [128]u8 = undefined;
    const path = try std.fmt.bufPrint(&buf, ".zig-cache/chaindbtest/{s}", .{sub});
    std.Io.Dir.cwd().deleteTree(testing.io, path) catch {};
    return Db.open(gpa, testing.io, path, .mainnet, .{ .block_cache_mb = 8, .write_buffer_mb = 4 });
}

test "headers, blocks, heads, sums, spent and output positions" {
    const gpa = testing.allocator;
    var db = try openTest(gpa, "all");
    defer db.close();
    var g = block.genesisMain();
    const gh = g.hash();

    try testing.expect((try db.getBlockHeader(db.store, gh)) == null);
    try testing.expect((try db.head(db.store)) == null);

    var b = db.batch();
    try db.saveBlockHeader(&b, g.header);
    try db.saveBlock(&b, g);
    try db.saveBodyHead(&b, Tip.fromHeader(g.header));
    try db.saveBlockSums(&b, gh, BlockSums.zero);
    const spent = [_]CommitPos{ .{ .pos = 5, .height = 2 }, .{ .pos = 9, .height = 3 } };
    try db.saveSpentIndex(&b, gh, &spent);
    const c: Commitment = .{ .bytes = [_]u8{9} ** 33 };
    try db.saveOutputPosHeight(&b, c, 42, 7);

    // visible inside the batch, not outside, until commit
    try testing.expect((try db.getBlockHeader(&b, gh)) != null);
    try testing.expect((try db.getBlockHeader(db.store, gh)) == null);
    try b.commit();

    const hdr = (try db.getBlockHeader(db.store, gh)).?;
    try testing.expect(hdr.hash().eql(gh));
    var blk = (try db.getBlock(db.store, gh)).?;
    defer blk.deinit(gpa);
    try testing.expect(blk.hash().eql(gh));
    try testing.expect(try db.blockExists(db.store, gh));
    try testing.expectEqual(@as(u64, 0), (try db.head(db.store)).?.height);
    try testing.expect((try db.getBlockSums(db.store, gh)).?.utxo_sum.eql(Commitment.zero));
    const sp = (try db.getSpentIndex(db.store, gh)).?;
    defer gpa.free(sp.items);
    try testing.expectEqual(@as(usize, 2), sp.items.len);
    try testing.expectEqual(@as(u64, 9), sp.items[1].pos);
    const cp = (try db.getOutputPosHeight(db.store, c)).?;
    try testing.expectEqual(@as(u64, 42), cp.pos);
    try testing.expectEqual(@as(u64, 7), cp.height);

    var b2 = db.batch();
    try db.deleteOutputPosHeight(&b2, c);
    try db.deleteBlock(&b2, gh);
    try b2.commit();
    try testing.expect((try db.getOutputPosHeight(db.store, c)) == null);
    try testing.expect(!(try db.blockExists(db.store, gh)));
    _ = &g;
}
