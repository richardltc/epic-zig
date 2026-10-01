//! Types shared across the chain code (`chain/src/types.rs`, `block_sums.rs`).
const std = @import("std");
const ser = @import("ser.zig");
const hash_mod = @import("hash.zig");
const crypto = @import("crypto.zig");
const consensus = @import("consensus.zig");
const block = @import("block.zig");
const tx = @import("transaction.zig");
const Difficulty = @import("pow_types.zig").Difficulty;

const Hash = hash_mod.Hash;
const Commitment = crypto.Commitment;

/// A chain head: height, hashes and accumulated difficulty.
pub const Tip = struct {
    height: u64,
    last_block_h: Hash,
    prev_block_h: Hash,
    total_difficulty: Difficulty,

    pub fn fromHeader(h: block.BlockHeader) Tip {
        return .{
            .height = h.height,
            .last_block_h = h.hash(),
            .prev_block_h = h.prev_hash,
            .total_difficulty = h.pow.total_difficulty,
        };
    }

    pub fn write(self: Tip, w: anytype) ser.Error!void {
        try ser.writeU64(w, self.height);
        try self.last_block_h.write(w);
        try self.prev_block_h.write(w);
        try self.total_difficulty.write(w);
    }

    pub fn read(r: *ser.Reader) ser.Error!Tip {
        return .{
            .height = try r.readU64(),
            .last_block_h = try Hash.read(r),
            .prev_block_h = try Hash.read(r),
            .total_difficulty = try Difficulty.read(r),
        };
    }
};

/// Where an output lives in the output PMMR, and the height it was created at.
pub const CommitPos = struct {
    pos: u64,
    height: u64,

    pub fn write(self: CommitPos, w: anytype) ser.Error!void {
        try ser.writeU64(w, self.pos);
        try ser.writeU64(w, self.height);
    }
    pub fn read(r: *ser.Reader) ser.Error!CommitPos {
        return .{ .pos = try r.readU64(), .height = try r.readU64() };
    }
};

/// Running totals of the UTXO set and of all kernels, as commitments.
pub const BlockSums = struct {
    utxo_sum: Commitment,
    kernel_sum: Commitment,

    pub const zero: BlockSums = .{ .utxo_sum = Commitment.zero, .kernel_sum = Commitment.zero };

    pub fn write(self: BlockSums, w: anytype) ser.Error!void {
        try self.utxo_sum.write(w);
        try self.kernel_sum.write(w);
    }
    pub fn read(r: *ser.Reader) ser.Error!BlockSums {
        return .{ .utxo_sum = try Commitment.read(r), .kernel_sum = try Commitment.read(r) };
    }
};

/// A list of spent outputs (`Vec<CommitPos>`): u64 count then entries.
pub const SpentList = struct {
    items: []CommitPos,

    pub fn write(self: SpentList, w: anytype) ser.Error!void {
        try ser.writeU64(w, self.items.len);
        for (self.items) |c| try c.write(w);
    }
    pub fn read(r: *ser.Reader) ser.Error!SpentList {
        const n = try r.readU64();
        if (n > r.remaining() / 16) return error.CorruptedData;
        const items = try r.gpa.alloc(CommitPos, @intCast(n));
        errdefer r.gpa.free(items);
        for (items) |*c| c.* = try CommitPos.read(r);
        return .{ .items = items };
    }
};

/// Verifies `sums` + the block's contents against the header's overage and offset,
/// returning the new running sums (`pipe::verify_block_sums`).
pub fn verifyBlockSums(gpa: std.mem.Allocator, prev: BlockSums, b: block.Block, chain: consensus.ChainType) tx.Error!BlockSums {
    var outs: std.ArrayList(Commitment) = .empty;
    defer outs.deinit(gpa);
    var ins: std.ArrayList(Commitment) = .empty;
    defer ins.deinit(gpa);
    var kerns: std.ArrayList(Commitment) = .empty;
    defer kerns.deinit(gpa);
    try outs.append(gpa, prev.utxo_sum);
    for (b.body.outputs) |o| try outs.append(gpa, o.commit);
    for (b.body.inputs) |i| try ins.append(gpa, i.commit);
    try kerns.append(gpa, prev.kernel_sum);
    for (b.body.kernels) |k| try kerns.append(gpa, k.excess);
    const s = try tx.verifyKernelSumsCommits(gpa, ins.items, outs.items, kerns.items, b.header.overage(chain), b.header.total_kernel_offset);
    return .{ .utxo_sum = s.utxo_sum, .kernel_sum = s.kernel_sum };
}

/// MMR roots that must match a block header (`TxHashSetRoots`).
pub const TxHashSetRoots = struct {
    output_pmmr_root: Hash,
    bitmap_root: Hash,
    rproof_root: Hash,
    kernel_root: Hash,

    /// Header version >= 7 merges the bitmap accumulator into the output root.
    pub fn outputRoot(self: TxHashSetRoots, header: block.BlockHeader) Hash {
        if (header.version < 7) return self.output_pmmr_root;
        return hash_mod.hashPairWithIndex(header.output_mmr_size, self.output_pmmr_root, self.bitmap_root);
    }

    pub fn validate(self: TxHashSetRoots, header: block.BlockHeader) error{InvalidRoot}!void {
        if (!header.output_root.eql(self.outputRoot(header)) or
            !header.range_proof_root.eql(self.rproof_root) or
            !header.kernel_root.eql(self.kernel_root)) return error.InvalidRoot;
    }
};

/// How much of the chain validation to do (`chain::Options`).
pub const Options = packed struct {
    skip_pow: bool = false,
    sync: bool = false,
    mine: bool = false,
    /// The block's stateless checks (`Chain.prevalidateBlock`) already passed.
    body_validated: bool = false,
};

const testing = std.testing;

test "tip and sums round trip" {
    const gpa = testing.allocator;
    const h = block.genesisMain().header;
    const tip = Tip.fromHeader(h);
    const bytes = try ser.serVec(gpa, tip, ser.ProtocolVersion.local());
    defer gpa.free(bytes);
    var r = ser.Reader.init(gpa, bytes, ser.ProtocolVersion.local());
    const back = try Tip.read(&r);
    try testing.expect(back.last_block_h.eql(tip.last_block_h));
    try testing.expectEqual(@as(u64, 0), back.height);

    const sb = try ser.serVec(gpa, BlockSums.zero, ser.ProtocolVersion.local());
    defer gpa.free(sb);
    try testing.expectEqual(@as(usize, 66), sb.len);
}
