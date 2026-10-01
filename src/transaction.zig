//! Transactions: kernels, inputs, outputs, bodies. Port of
//! `core/src/core/transaction.rs` (+ `committed.rs`).
const std = @import("std");
const ser = @import("ser.zig");
const hash_mod = @import("hash.zig");
const crypto = @import("crypto.zig");
const consensus = @import("consensus.zig");

const Hash = hash_mod.Hash;
const Commitment = crypto.Commitment;
const RangeProof = crypto.RangeProof;
const Signature = crypto.Signature;
const ChainType = consensus.ChainType;

pub const Error = ser.Error || crypto.Error || error{
    KernelSumMismatch,
    TooHeavy,
    LockHeight,
    RangeProof,
    MerkleProof,
    InvalidProofMessage,
    AggregationError,
    CutThrough,
    InvalidOutputFeatures,
    InvalidKernelFeatures,
    IncorrectSignature,
    InvalidValue,
};

// ------------------------------------------------------- kernel features

pub const KernelFeatures = union(enum) {
    plain: struct { fee: u64 },
    coinbase,
    height_locked: struct { fee: u64, lock_height: u64 },

    const PLAIN_U8: u8 = 0;
    const COINBASE_U8: u8 = 1;
    const HEIGHT_LOCKED_U8: u8 = 2;

    pub fn asU8(self: KernelFeatures) u8 {
        return switch (self) {
            .plain => PLAIN_U8,
            .coinbase => COINBASE_U8,
            .height_locked => HEIGHT_LOCKED_U8,
        };
    }

    pub fn eql(a: KernelFeatures, b: KernelFeatures) bool {
        return std.meta.eql(a, b);
    }

    pub fn isCoinbase(self: KernelFeatures) bool {
        return self == .coinbase;
    }
    pub fn isPlain(self: KernelFeatures) bool {
        return self == .plain;
    }
    pub fn isHeightLocked(self: KernelFeatures) bool {
        return self == .height_locked;
    }

    /// The message a kernel signature commits to: blake2b of the features
    /// (type, then fee / lock height as applicable).
    pub fn sigMsg(self: KernelFeatures) [32]u8 {
        var hw = hash_mod.HashWriter.init();
        const x = self.asU8();
        switch (self) {
            .plain => |p| {
                ser.write(&hw, x) catch unreachable;
                ser.write(&hw, p.fee) catch unreachable;
            },
            .coinbase => ser.write(&hw, x) catch unreachable,
            .height_locked => |h| {
                ser.write(&hw, x) catch unreachable;
                ser.write(&hw, h.fee) catch unreachable;
                ser.write(&hw, h.lock_height) catch unreachable;
            },
        }
        return hw.intoHash().bytes;
    }

    fn writeV1(self: KernelFeatures, w: anytype) ser.Error!void {
        var fee: u64 = 0;
        var lock_height: u64 = 0;
        switch (self) {
            .plain => |p| fee = p.fee,
            .coinbase => {},
            .height_locked => |h| {
                fee = h.fee;
                lock_height = h.lock_height;
            },
        }
        try ser.writeU8(w, self.asU8());
        try ser.writeU64(w, fee);
        try ser.writeU64(w, lock_height);
    }

    fn writeV2(self: KernelFeatures, w: anytype) ser.Error!void {
        try ser.writeU8(w, self.asU8());
        switch (self) {
            .plain => |p| try ser.writeU64(w, p.fee),
            .coinbase => {},
            .height_locked => |h| {
                try ser.writeU64(w, h.fee);
                try ser.writeU64(w, h.lock_height);
            },
        }
    }

    /// Hash mode always uses the v1 (fixed 17 byte) layout; on the wire the
    /// layout depends on the protocol version.
    pub fn write(self: KernelFeatures, w: anytype) ser.Error!void {
        if (w.mode == .hash) return self.writeV1(w);
        if (w.version.v <= 1) return self.writeV1(w);
        return self.writeV2(w);
    }

    fn readV1(r: *ser.Reader) ser.Error!KernelFeatures {
        const b = try r.readU8();
        const fee = try r.readU64();
        const lock_height = try r.readU64();
        return switch (b) {
            PLAIN_U8 => if (lock_height != 0) error.CorruptedData else .{ .plain = .{ .fee = fee } },
            COINBASE_U8 => if (fee != 0 or lock_height != 0) error.CorruptedData else .coinbase,
            HEIGHT_LOCKED_U8 => .{ .height_locked = .{ .fee = fee, .lock_height = lock_height } },
            else => error.CorruptedData,
        };
    }

    fn readV2(r: *ser.Reader) ser.Error!KernelFeatures {
        return switch (try r.readU8()) {
            PLAIN_U8 => .{ .plain = .{ .fee = try r.readU64() } },
            COINBASE_U8 => .coinbase,
            HEIGHT_LOCKED_U8 => blk: {
                const fee = try r.readU64();
                const lock_height = try r.readU64();
                break :blk .{ .height_locked = .{ .fee = fee, .lock_height = lock_height } };
            },
            else => error.CorruptedData,
        };
    }

    pub fn read(r: *ser.Reader) ser.Error!KernelFeatures {
        if (r.version.v <= 1) return readV1(r);
        return readV2(r);
    }
};

// ---------------------------------------------------------------- kernel

pub const TxKernel = struct {
    features: KernelFeatures,
    excess: Commitment,
    excess_sig: Signature,

    pub fn withFeatures(features: KernelFeatures) TxKernel {
        return .{ .features = features, .excess = Commitment.zero, .excess_sig = Signature.zero };
    }
    pub fn empty() TxKernel {
        return withFeatures(.{ .plain = .{ .fee = 0 } });
    }

    pub fn write(self: TxKernel, w: anytype) ser.Error!void {
        try self.features.write(w);
        try self.excess.write(w);
        try self.excess_sig.write(w);
    }

    pub fn read(r: *ser.Reader) ser.Error!TxKernel {
        const features = try KernelFeatures.read(r);
        const excess = try Commitment.read(r);
        const sig = try Signature.read(r);
        return .{ .features = features, .excess = excess, .excess_sig = sig };
    }

    pub fn hash(self: TxKernel) Hash {
        return hash_mod.hashOf(self);
    }

    pub fn isCoinbase(self: TxKernel) bool {
        return self.features.isCoinbase();
    }

    pub fn msgToSign(self: TxKernel) [32]u8 {
        return self.features.sigMsg();
    }

    pub fn verify(self: TxKernel) Error!void {
        const pk = self.excess.toPubkey() catch return error.IncorrectSignature;
        const msg = self.msgToSign();
        if (!crypto.aggsigVerifySingleKernel(&self.excess_sig, &msg, &pk)) return error.IncorrectSignature;
    }

    pub fn batchSigVerify(gpa: std.mem.Allocator, kernels: []const TxKernel) Error!void {
        const n = kernels.len;
        const sigs = try gpa.alloc(Signature, n);
        defer gpa.free(sigs);
        const msgs = try gpa.alloc([32]u8, n);
        defer gpa.free(msgs);
        const pks = try gpa.alloc(crypto.PublicKey, n);
        defer gpa.free(pks);
        for (kernels, 0..) |k, i| {
            sigs[i] = k.excess_sig;
            pks[i] = try k.excess.toPubkey();
            msgs[i] = k.msgToSign();
        }
        if (!crypto.schnorrVerifyBatch(gpa, sigs, msgs, pks)) return error.IncorrectSignature;
    }
};

// ------------------------------------------------------ inputs & outputs

pub const OutputFeatures = enum(u8) {
    plain = 0,
    coinbase = 1,

    pub fn isCoinbase(self: OutputFeatures) bool {
        return self == .coinbase;
    }
    pub fn isPlain(self: OutputFeatures) bool {
        return self == .plain;
    }

    pub fn write(self: OutputFeatures, w: anytype) ser.Error!void {
        try ser.writeU8(w, @intFromEnum(self));
    }

    pub fn read(r: *ser.Reader) ser.Error!OutputFeatures {
        return switch (try r.readU8()) {
            0 => .plain,
            1 => .coinbase,
            else => error.CorruptedData,
        };
    }
};

pub const Input = struct {
    features: OutputFeatures,
    commit: Commitment,

    pub fn write(self: Input, w: anytype) ser.Error!void {
        try self.features.write(w);
        try self.commit.write(w);
    }
    pub fn read(r: *ser.Reader) ser.Error!Input {
        const f = try OutputFeatures.read(r);
        return .{ .features = f, .commit = try Commitment.read(r) };
    }
    pub fn hash(self: Input) Hash {
        return hash_mod.hashOf(self);
    }
    pub fn isCoinbase(self: Input) bool {
        return self.features.isCoinbase();
    }
};

pub const Output = struct {
    features: OutputFeatures,
    commit: Commitment,
    proof: RangeProof,

    /// The proof is excluded from the hashed form.
    pub fn write(self: Output, w: anytype) ser.Error!void {
        try self.features.write(w);
        try self.commit.write(w);
        if (w.mode != .hash) try self.proof.write(w);
    }
    pub fn read(r: *ser.Reader) ser.Error!Output {
        const f = try OutputFeatures.read(r);
        const cm = try Commitment.read(r);
        return .{ .features = f, .commit = cm, .proof = try RangeProof.read(r) };
    }
    pub fn hash(self: Output) Hash {
        return hash_mod.hashOf(self);
    }
    pub fn isCoinbase(self: Output) bool {
        return self.features.isCoinbase();
    }
    pub fn identifier(self: Output) OutputIdentifier {
        return .{ .features = self.features, .commit = self.commit };
    }
    pub fn verifyProof(self: Output, gpa: std.mem.Allocator) Error!void {
        try crypto.verifyBulletProof(gpa, self.commit, self.proof);
    }
};

/// What is stored in the output PMMR: features + commitment (34 bytes).
pub const OutputIdentifier = struct {
    features: OutputFeatures,
    commit: Commitment,

    pub const SIZE: u16 = 1 + crypto.PEDERSEN_COMMITMENT_SIZE;

    pub fn fromInput(i: Input) OutputIdentifier {
        return .{ .features = i.features, .commit = i.commit };
    }
    pub fn intoOutput(self: OutputIdentifier, proof: RangeProof) Output {
        return .{ .features = self.features, .commit = self.commit, .proof = proof };
    }
    pub fn write(self: OutputIdentifier, w: anytype) ser.Error!void {
        try self.features.write(w);
        try self.commit.write(w);
    }
    pub fn read(r: *ser.Reader) ser.Error!OutputIdentifier {
        const f = try OutputFeatures.read(r);
        return .{ .features = f, .commit = try Commitment.read(r) };
    }
    pub fn hash(self: OutputIdentifier) Hash {
        return hash_mod.hashOf(self);
    }
};

// -------------------------------------------------------------- weighting

pub const Weighting = union(enum) {
    as_transaction,
    as_limited_transaction: usize,
    as_block,
    no_limit,
};

// --------------------------------------------------------- sorted helpers

/// Verifies that items' hashes are strictly increasing (sorted and unique).
pub fn verifySortedAndUnique(comptime T: type, gpa: std.mem.Allocator, items: []const T) Error!void {
    if (items.len < 2) return;
    var prev = items[0].hash();
    for (items[1..]) |it| {
        const h = it.hash();
        switch (prev.order(h)) {
            .gt => return error.SortError,
            .eq => return error.DuplicateError,
            .lt => {},
        }
        prev = h;
    }
    _ = gpa;
}

fn HashedItem(comptime T: type) type {
    return struct { h: Hash, item: T };
}

/// Sorts by hash, computing each hash once.
pub fn sortByHash(comptime T: type, gpa: std.mem.Allocator, items: []T) std.mem.Allocator.Error!void {
    const Pair = HashedItem(T);
    const tmp = try gpa.alloc(Pair, items.len);
    defer gpa.free(tmp);
    for (items, 0..) |it, i| tmp[i] = .{ .h = it.hash(), .item = it };
    std.mem.sortUnstable(Pair, tmp, {}, struct {
        fn lt(_: void, a: Pair, b: Pair) bool {
            return a.h.order(b.h) == .lt;
        }
    }.lt);
    for (tmp, 0..) |p, i| items[i] = p.item;
}

// ------------------------------------------------------------------ body

pub const TransactionBody = struct {
    inputs: []Input,
    outputs: []Output,
    kernels: []TxKernel,

    pub const empty: TransactionBody = .{ .inputs = &.{}, .outputs = &.{}, .kernels = &.{} };

    pub fn deinit(self: *TransactionBody, gpa: std.mem.Allocator) void {
        gpa.free(self.inputs);
        gpa.free(self.outputs);
        gpa.free(self.kernels);
        self.* = empty;
    }

    pub fn write(self: TransactionBody, w: anytype) ser.Error!void {
        try ser.writeU64(w, self.inputs.len);
        try ser.writeU64(w, self.outputs.len);
        try ser.writeU64(w, self.kernels.len);
        try ser.write(w, self.inputs);
        try ser.write(w, self.outputs);
        try ser.write(w, self.kernels);
    }

    pub fn read(r: *ser.Reader) ser.Error!TransactionBody {
        const input_len = try r.readU64();
        const output_len = try r.readU64();
        const kernel_len = try r.readU64();

        const w = weightAsBlock(clampUsize(input_len), clampUsize(output_len), clampUsize(kernel_len));
        if (w > r.params.max_block_weight) return error.TooLargeRead;

        const inputs = try ser.readMulti(Input, r, input_len);
        errdefer r.gpa.free(inputs);
        const outputs = try ser.readMulti(Output, r, output_len);
        errdefer r.gpa.free(outputs);
        const kernels = try ser.readMulti(TxKernel, r, kernel_len);
        errdefer r.gpa.free(kernels);

        const body: TransactionBody = .{ .inputs = inputs, .outputs = outputs, .kernels = kernels };
        body.verifySorted(r.gpa) catch return error.CorruptedData;
        return body;
    }

    fn clampUsize(v: u64) usize {
        return @intCast(@min(v, std.math.maxInt(usize)));
    }

    /// Builds from parts; sorts unless `verify_sorted`, in which case it checks.
    pub fn init(gpa: std.mem.Allocator, inputs: []Input, outputs: []Output, kernels: []TxKernel, verify_sorted: bool) Error!TransactionBody {
        var body: TransactionBody = .{ .inputs = inputs, .outputs = outputs, .kernels = kernels };
        if (verify_sorted) try body.verifySorted(gpa) else try body.sort(gpa);
        return body;
    }

    pub fn sort(self: *TransactionBody, gpa: std.mem.Allocator) std.mem.Allocator.Error!void {
        try sortByHash(Input, gpa, self.inputs);
        try sortByHash(Output, gpa, self.outputs);
        try sortByHash(TxKernel, gpa, self.kernels);
    }

    pub fn fee(self: TransactionBody) u64 {
        var total: u64 = 0;
        for (self.kernels) |k| {
            const f: u64 = switch (k.features) {
                .coinbase => continue,
                .plain => |p| p.fee,
                .height_locked => |h| h.fee,
            };
            total = total +| f;
        }
        return total;
    }

    fn overage(self: TransactionBody) i64 {
        const f = self.fee();
        return if (f > std.math.maxInt(i64)) std.math.maxInt(i64) else @intCast(f);
    }

    pub fn bodyWeight(self: TransactionBody) usize {
        return weight(self.inputs.len, self.outputs.len, self.kernels.len);
    }
    pub fn bodyWeightAsBlock(self: TransactionBody) usize {
        return weightAsBlock(self.inputs.len, self.outputs.len, self.kernels.len);
    }

    pub fn weight(input_len: usize, output_len: usize, kernel_len: usize) usize {
        const w = (output_len *| 4) +| kernel_len -| input_len;
        return @max(w, 1);
    }

    pub fn weightAsBlock(input_len: usize, output_len: usize, kernel_len: usize) usize {
        return weightAsBlockFn(input_len, output_len, kernel_len);
    }

    pub fn lockHeight(self: TransactionBody) u64 {
        var m: u64 = 0;
        for (self.kernels) |k| switch (k.features) {
            .height_locked => |h| m = @max(m, h.lock_height),
            else => {},
        };
        return m;
    }

    fn verifyWeight(self: TransactionBody, max_block_weight: usize, weighting: Weighting) Error!void {
        const coinbase_weight = consensus.BLOCK_OUTPUT_WEIGHT + consensus.BLOCK_KERNEL_WEIGHT;
        const max_w: usize = switch (weighting) {
            .as_transaction => max_block_weight -| coinbase_weight,
            .as_limited_transaction => |m| @min(max_block_weight, m) -| coinbase_weight,
            .as_block => max_block_weight,
            .no_limit => return,
        };
        if (self.bodyWeightAsBlock() > max_w) return error.TooHeavy;
    }

    pub fn verifySorted(self: TransactionBody, gpa: std.mem.Allocator) Error!void {
        try verifySortedAndUnique(Input, gpa, self.inputs);
        try verifySortedAndUnique(Output, gpa, self.outputs);
        try verifySortedAndUnique(TxKernel, gpa, self.kernels);
    }

    /// No output may be spent by an input of the same body (both sorted by hash).
    fn verifyCutThrough(self: TransactionBody) Error!void {
        var i: usize = 0;
        var o: usize = 0;
        while (i < self.inputs.len and o < self.outputs.len) {
            // Hashes of an Input and the matching Output are equal only when
            // features+commit match (the Output hash excludes the proof).
            switch (self.inputs[i].hash().order(self.outputs[o].hash())) {
                .lt => i += 1,
                .gt => o += 1,
                .eq => return error.CutThrough,
            }
        }
    }

    pub fn verifyFeatures(self: TransactionBody) Error!void {
        for (self.outputs) |o| if (o.isCoinbase()) return error.InvalidOutputFeatures;
        for (self.kernels) |k| if (k.isCoinbase()) return error.InvalidKernelFeatures;
    }

    pub fn validateRead(self: TransactionBody, gpa: std.mem.Allocator, chain: ChainType, weighting: Weighting) Error!void {
        return self.validateReadWeight(gpa, chain.maxBlockWeight(), weighting);
    }

    pub fn validateReadWeight(self: TransactionBody, gpa: std.mem.Allocator, max_block_weight: usize, weighting: Weighting) Error!void {
        try self.verifyWeight(max_block_weight, weighting);
        try self.verifySorted(gpa);
        try self.verifyCutThrough();
    }

    pub fn validate(self: TransactionBody, gpa: std.mem.Allocator, chain: ChainType, weighting: Weighting) Error!void {
        try self.validateRead(gpa, chain, weighting);
        if (self.outputs.len > 0) {
            const commits = try gpa.alloc(Commitment, self.outputs.len);
            defer gpa.free(commits);
            const proofs = try gpa.alloc(RangeProof, self.outputs.len);
            defer gpa.free(proofs);
            for (self.outputs, 0..) |o, i| {
                commits[i] = o.commit;
                proofs[i] = o.proof;
            }
            crypto.verifyBulletProofMulti(gpa, commits, proofs) catch return error.RangeProof;
        }
        try TxKernel.batchSigVerify(gpa, self.kernels);
    }

    // ---- Committed
    pub fn verifyKernelSums(self: TransactionBody, gpa: std.mem.Allocator, overage_: i64, offset: BlindingFactor) Error!KernelSums {
        return committedVerifyKernelSums(gpa, self.inputs, self.outputs, self.kernels, overage_, offset);
    }
};

fn weightAsBlockFn(input_len: usize, output_len: usize, kernel_len: usize) usize {
    return (input_len *| consensus.BLOCK_INPUT_WEIGHT) +|
        (output_len *| consensus.BLOCK_OUTPUT_WEIGHT) +|
        (kernel_len *| consensus.BLOCK_KERNEL_WEIGHT);
}

// ---------------------------------------------------------- BlindingFactor

/// A 32 byte scalar (kernel offset / blinding factor). All zeroes means "zero".
pub const BlindingFactor = struct {
    bytes: [32]u8,

    pub const zero: BlindingFactor = .{ .bytes = [_]u8{0} ** 32 };

    pub fn isZero(self: BlindingFactor) bool {
        return std.mem.allEqual(u8, &self.bytes, 0);
    }
    pub fn eql(a: BlindingFactor, b: BlindingFactor) bool {
        return std.mem.eql(u8, &a.bytes, &b.bytes);
    }

    pub fn write(self: BlindingFactor, w: anytype) ser.Error!void {
        try w.writeFixedBytes(&self.bytes);
    }
    pub fn read(r: *ser.Reader) ser.Error!BlindingFactor {
        return .{ .bytes = try r.readArray(32) };
    }
};

// -------------------------------------------------------------- Committed

pub const KernelSums = struct {
    utxo_sum: Commitment,
    kernel_sum: Commitment,
};

/// Sums commitments, first dropping the all-zero sentinel commitment.
pub fn sumCommits(gpa: std.mem.Allocator, positive: []const Commitment, negative: []const Commitment) Error!Commitment {
    var pos: std.ArrayList(Commitment) = .empty;
    defer pos.deinit(gpa);
    var neg: std.ArrayList(Commitment) = .empty;
    defer neg.deinit(gpa);
    for (positive) |x| if (!x.eql(Commitment.zero)) try pos.append(gpa, x);
    for (negative) |x| if (!x.eql(Commitment.zero)) try neg.append(gpa, x);
    return crypto.commitSum(gpa, pos.items, neg.items);
}

/// Sum of offsets (zero offsets and invalid keys are ignored, as in the reference).
pub fn sumKernelOffsets(gpa: std.mem.Allocator, positive: []const BlindingFactor, negative: []const BlindingFactor) Error!BlindingFactor {
    const pos = try toSecrets(gpa, positive);
    defer gpa.free(pos);
    const neg = try toSecrets(gpa, negative);
    defer gpa.free(neg);
    if (pos.len == 0) return BlindingFactor.zero;
    return .{ .bytes = try crypto.blindSum(gpa, pos, neg) };
}

fn toSecrets(gpa: std.mem.Allocator, bfs: []const BlindingFactor) Error![][32]u8 {
    var out: std.ArrayList([32]u8) = .empty;
    errdefer out.deinit(gpa);
    for (bfs) |b| {
        if (b.isZero()) continue;
        if (!crypto.secretKeyValid(&b.bytes)) continue;
        try out.append(gpa, b.bytes);
    }
    return out.toOwnedSlice(gpa);
}

pub fn committedVerifyKernelSums(
    gpa: std.mem.Allocator,
    inputs: []const Input,
    outputs: []const Output,
    kernels: []const TxKernel,
    overage: i64,
    offset: BlindingFactor,
) Error!KernelSums {
    var in_commits: std.ArrayList(Commitment) = .empty;
    defer in_commits.deinit(gpa);
    var out_commits: std.ArrayList(Commitment) = .empty;
    defer out_commits.deinit(gpa);
    var kern_commits: std.ArrayList(Commitment) = .empty;
    defer kern_commits.deinit(gpa);
    for (inputs) |i| try in_commits.append(gpa, i.commit);
    for (outputs) |o| try out_commits.append(gpa, o.commit);
    for (kernels) |k| try kern_commits.append(gpa, k.excess);
    return verifyKernelSumsCommits(gpa, in_commits.items, out_commits.items, kern_commits.items, overage, offset);
}

/// `Committed::verify_kernel_sums` over raw commitment lists: sum(outputs) +
/// overage - sum(inputs) must equal sum(kernel excesses) + offset*G.
pub fn verifyKernelSumsCommits(
    gpa: std.mem.Allocator,
    inputs: []const Commitment,
    outputs: []const Commitment,
    kernels: []const Commitment,
    overage: i64,
    offset: BlindingFactor,
) Error!KernelSums {
    var in_commits: std.ArrayList(Commitment) = .empty;
    defer in_commits.deinit(gpa);
    var out_commits: std.ArrayList(Commitment) = .empty;
    defer out_commits.deinit(gpa);
    try in_commits.appendSlice(gpa, inputs);
    try out_commits.appendSlice(gpa, outputs);
    if (overage != 0) {
        if (overage == std.math.minInt(i64)) return error.InvalidValue;
        const abs: u64 = @intCast(if (overage < 0) -overage else overage);
        const over_commit = try Commitment.commitValue(abs);
        if (overage < 0) try in_commits.append(gpa, over_commit) else try out_commits.append(gpa, over_commit);
    }
    const utxo_sum = try sumCommits(gpa, out_commits.items, in_commits.items);
    const kernel_sum = try sumCommits(gpa, kernels, &.{});
    var plus_offset: Commitment = undefined;
    if (!offset.isZero()) {
        if (!crypto.secretKeyValid(&offset.bytes)) return error.InvalidSecretKey;
        const offset_commit = try Commitment.commit(0, &offset.bytes);
        plus_offset = try crypto.commitSum(gpa, &.{ kernel_sum, offset_commit }, &.{});
    } else {
        plus_offset = try crypto.commitSum(gpa, &.{kernel_sum}, &.{});
    }
    if (!utxo_sum.eql(plus_offset)) return error.KernelSumMismatch;
    return .{ .utxo_sum = utxo_sum, .kernel_sum = kernel_sum };
}

// ------------------------------------------------------------ Transaction

pub const Transaction = struct {
    offset: BlindingFactor,
    body: TransactionBody,

    pub fn deinit(self: *Transaction, gpa: std.mem.Allocator) void {
        self.body.deinit(gpa);
    }

    pub fn write(self: Transaction, w: anytype) ser.Error!void {
        try self.offset.write(w);
        try self.body.write(w);
    }

    pub fn read(r: *ser.Reader) ser.Error!Transaction {
        const offset = try BlindingFactor.read(r);
        var body = try TransactionBody.read(r);
        errdefer body.deinit(r.gpa);
        const tx: Transaction = .{ .offset = offset, .body = body };
        tx.validateReadWeight(r.gpa, r.params.max_block_weight) catch return error.CorruptedData;
        return tx;
    }

    pub fn hash(self: Transaction) Hash {
        return hash_mod.hashOf(self);
    }

    pub const empty: Transaction = .{ .offset = BlindingFactor.zero, .body = TransactionBody.empty };

    /// A deep copy (the slices are duplicated; the elements are plain values).
    pub fn clone(self: Transaction, gpa: std.mem.Allocator) std.mem.Allocator.Error!Transaction {
        const ins = try gpa.dupe(Input, self.body.inputs);
        errdefer gpa.free(ins);
        const outs = try gpa.dupe(Output, self.body.outputs);
        errdefer gpa.free(outs);
        const kerns = try gpa.dupe(TxKernel, self.body.kernels);
        return .{ .offset = self.offset, .body = .{ .inputs = ins, .outputs = outs, .kernels = kerns } };
    }

    pub fn fee(self: Transaction) u64 {
        return self.body.fee();
    }
    pub fn overage(self: Transaction) i64 {
        return self.body.overage();
    }
    pub fn lockHeight(self: Transaction) u64 {
        return self.body.lockHeight();
    }

    pub fn validateRead(self: Transaction, gpa: std.mem.Allocator, chain: ChainType) Error!void {
        return self.validateReadWeight(gpa, chain.maxBlockWeight());
    }

    pub fn validateReadWeight(self: Transaction, gpa: std.mem.Allocator, max_block_weight: usize) Error!void {
        try self.body.validateReadWeight(gpa, max_block_weight, .as_transaction);
        try self.body.verifyFeatures();
    }

    pub fn validate(self: Transaction, gpa: std.mem.Allocator, chain: ChainType, weighting: Weighting) Error!void {
        try self.body.validate(gpa, chain, weighting);
        try self.body.verifyFeatures();
        _ = try self.body.verifyKernelSums(gpa, self.overage(), self.offset);
    }

    pub fn txWeight(self: Transaction) usize {
        return self.body.bodyWeight();
    }
    pub fn txWeightAsBlock(self: Transaction) usize {
        return self.body.bodyWeightAsBlock();
    }
    pub fn feeToWeight(self: Transaction) u64 {
        return self.fee() * 1000 / self.txWeight();
    }
};


// ------------------------------------------------------------ aggregation

fn hashLess(comptime T: type) fn (void, T, T) bool {
    return struct {
        fn lt(_: void, a: T, b: T) bool {
            return a.hash().order(b.hash()) == .lt;
        }
    }.lt;
}

/// Removes every input that is also an output (they cancel), keeping both lists
/// sorted by hash. Fails if two outputs are identical (`cut_through`).
pub fn cutThrough(gpa: std.mem.Allocator, inputs: *std.ArrayList(Input), outputs: *std.ArrayList(Output)) Error!void {
    try sortByHash(Output, gpa, outputs.items);
    for (1..outputs.items.len) |i| {
        if (outputs.items[i - 1].hash().eql(outputs.items[i].hash())) return error.AggregationError;
    }
    try sortByHash(Input, gpa, inputs.items);
    var i: usize = 0;
    var o: usize = 0;
    var in_w: usize = 0;
    var out_w: usize = 0;
    while (i < inputs.items.len and o < outputs.items.len) {
        switch (inputs.items[i].hash().order(outputs.items[o].hash())) {
            .lt => {
                inputs.items[in_w] = inputs.items[i];
                in_w += 1;
                i += 1;
            },
            .gt => {
                outputs.items[out_w] = outputs.items[o];
                out_w += 1;
                o += 1;
            },
            .eq => {
                i += 1;
                o += 1;
            },
        }
    }
    while (i < inputs.items.len) : (i += 1) {
        inputs.items[in_w] = inputs.items[i];
        in_w += 1;
    }
    while (o < outputs.items.len) : (o += 1) {
        outputs.items[out_w] = outputs.items[o];
        out_w += 1;
    }
    inputs.shrinkRetainingCapacity(in_w);
    outputs.shrinkRetainingCapacity(out_w);
}

/// Aggregates transactions into one multi-kernel transaction with cut-through
/// (`aggregate`). The result is newly allocated; the inputs are untouched.
pub fn aggregate(gpa: std.mem.Allocator, txs: []const Transaction) Error!Transaction {
    if (txs.len == 0) return Transaction.empty;
    if (txs.len == 1) return txs[0].clone(gpa);

    var inputs: std.ArrayList(Input) = .empty;
    errdefer inputs.deinit(gpa);
    var outputs: std.ArrayList(Output) = .empty;
    errdefer outputs.deinit(gpa);
    var kernels: std.ArrayList(TxKernel) = .empty;
    errdefer kernels.deinit(gpa);
    const offsets = try gpa.alloc(BlindingFactor, txs.len);
    defer gpa.free(offsets);
    for (txs, 0..) |t, i| {
        offsets[i] = t.offset;
        try inputs.appendSlice(gpa, t.body.inputs);
        try outputs.appendSlice(gpa, t.body.outputs);
        try kernels.appendSlice(gpa, t.body.kernels);
    }
    try cutThrough(gpa, &inputs, &outputs);
    try sortByHash(TxKernel, gpa, kernels.items);
    const offset = try sumKernelOffsets(gpa, offsets, &.{});

    const ins = try inputs.toOwnedSlice(gpa);
    errdefer gpa.free(ins);
    const outs = try outputs.toOwnedSlice(gpa);
    errdefer gpa.free(outs);
    const kerns = try kernels.toOwnedSlice(gpa);
    return .{ .offset = offset, .body = .{ .inputs = ins, .outputs = outs, .kernels = kerns } };
}

fn containsHash(comptime T: type, items: []const T, x: T) bool {
    const h = x.hash();
    for (items) |i| if (i.hash().eql(h)) return true;
    return false;
}

/// Removes the aggregate of `txs` from the multi-kernel `mk_tx` (`deaggregate`).
pub fn deaggregate(gpa: std.mem.Allocator, mk_tx: Transaction, txs: []const Transaction) Error!Transaction {
    var agg = try aggregate(gpa, txs);
    defer agg.deinit(gpa);

    var inputs: std.ArrayList(Input) = .empty;
    errdefer inputs.deinit(gpa);
    var outputs: std.ArrayList(Output) = .empty;
    errdefer outputs.deinit(gpa);
    var kernels: std.ArrayList(TxKernel) = .empty;
    errdefer kernels.deinit(gpa);
    for (mk_tx.body.inputs) |x| if (!containsHash(Input, agg.body.inputs, x) and !containsHash(Input, inputs.items, x)) try inputs.append(gpa, x);
    for (mk_tx.body.outputs) |x| if (!containsHash(Output, agg.body.outputs, x) and !containsHash(Output, outputs.items, x)) try outputs.append(gpa, x);
    for (mk_tx.body.kernels) |x| if (!containsHash(TxKernel, agg.body.kernels, x) and !containsHash(TxKernel, kernels.items, x)) try kernels.append(gpa, x);

    const offset: BlindingFactor = blk: {
        const pos = try toSecrets(gpa, &.{mk_tx.offset});
        defer gpa.free(pos);
        const neg = try toSecrets(gpa, &.{agg.offset});
        defer gpa.free(neg);
        if (pos.len == 0 and neg.len == 0) break :blk BlindingFactor.zero;
        break :blk .{ .bytes = try crypto.blindSum(gpa, pos, neg) };
    };

    try sortByHash(Input, gpa, inputs.items);
    try sortByHash(Output, gpa, outputs.items);
    try sortByHash(TxKernel, gpa, kernels.items);
    const ins = try inputs.toOwnedSlice(gpa);
    errdefer gpa.free(ins);
    const outs = try outputs.toOwnedSlice(gpa);
    errdefer gpa.free(outs);
    const kerns = try kernels.toOwnedSlice(gpa);
    return .{ .offset = offset, .body = .{ .inputs = ins, .outputs = outs, .kernels = kerns } };
}

// ------------------------------------------------------------------ tests

const testing = std.testing;
const ProtocolVersion = ser.ProtocolVersion;

fn testKernel(fee: u64) TxKernel {
    var k = TxKernel.withFeatures(.{ .plain = .{ .fee = fee } });
    k.excess.bytes[0] = 8;
    return k;
}

test "kernel features serialize per protocol version" {
    const gpa = testing.allocator;
    const plain: KernelFeatures = .{ .plain = .{ .fee = 10 } };
    const v2 = try ser.serVec(gpa, plain, ProtocolVersion{ .v = 2 });
    defer gpa.free(v2);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 0, 0, 0, 10 }, v2);
    const v1 = try ser.serVec(gpa, plain, ProtocolVersion{ .v = 1 });
    defer gpa.free(v1);
    try testing.expectEqual(@as(usize, 17), v1.len);

    var r = ser.Reader.init(gpa, v1, ProtocolVersion{ .v = 1 });
    try testing.expect((try KernelFeatures.read(&r)).eql(plain));
    var r2 = ser.Reader.init(gpa, v2, ProtocolVersion{ .v = 2 });
    try testing.expect((try KernelFeatures.read(&r2)).eql(plain));

    // v1 rejects inconsistent fields
    var bad = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 1 };
    var r3 = ser.Reader.init(gpa, &bad, ProtocolVersion{ .v = 1 });
    try testing.expectError(error.CorruptedData, KernelFeatures.read(&r3));
    // coinbase is one byte in v2
    const cb = try ser.serVec(gpa, KernelFeatures{ .coinbase = {} }, ProtocolVersion{ .v = 2 });
    defer gpa.free(cb);
    try testing.expectEqualSlices(u8, &.{1}, cb);
}

test "kernel hash always uses the v1 layout" {
    var k = testKernel(10);
    k.excess = Commitment.zero;
    // hash-mode encoding: 1 + 8 + 8 + 33 + 64
    var hw = hash_mod.HashWriter.init();
    try ser.write(&hw, k);
    const via_writer = hw.intoHash();
    try testing.expect(via_writer.eql(k.hash()));

    var manual = std.crypto.hash.blake2.Blake2b256.init(.{});
    manual.update(&[_]u8{0});
    manual.update(&[_]u8{ 0, 0, 0, 0, 0, 0, 0, 10 });
    manual.update(&[_]u8{0} ** 8);
    manual.update(&[_]u8{0} ** 33);
    manual.update(&[_]u8{0} ** 64);
    var out: [32]u8 = undefined;
    manual.final(&out);
    try testing.expectEqualSlices(u8, &out, &k.hash().bytes);
}

test "kernel sig message" {
    const plain: KernelFeatures = .{ .plain = .{ .fee = 7 } };
    var manual = std.crypto.hash.blake2.Blake2b256.init(.{});
    manual.update(&[_]u8{0});
    manual.update(&[_]u8{ 0, 0, 0, 0, 0, 0, 0, 7 });
    var out: [32]u8 = undefined;
    manual.final(&out);
    try testing.expectEqualSlices(u8, &out, &plain.sigMsg());
}

test "output hash excludes the proof" {
    var o: Output = .{ .features = .plain, .commit = Commitment.zero, .proof = RangeProof.zero };
    const h1 = o.hash();
    o.proof.proof[5] = 1;
    o.proof.plen = 10;
    try testing.expect(o.hash().eql(h1));
    const gpa = testing.allocator;
    const full = try ser.serVec(gpa, o, ProtocolVersion.local());
    defer gpa.free(full);
    try testing.expectEqual(@as(usize, 1 + 33 + 8 + 10), full.len);
}

test "weights" {
    try testing.expectEqual(@as(usize, 1), TransactionBody.weight(5, 1, 0));
    try testing.expectEqual(@as(usize, 2 * 4 + 1 - 2), TransactionBody.weight(2, 2, 1));
    try testing.expectEqual(@as(usize, 2 + 42 + 3), TransactionBody.weightAsBlock(2, 2, 1));
}

test "fully valid transaction: build, sign, validate, round-trip" {
    const gpa = testing.allocator;
    // in: 100 (blind a); out: 90 (blind b); fee 10; kernel excess = (b - a + offset... ) use offset 0
    // Balance:  out + fee*H - in  == excess  =>  (b - a) * G, so excess key k = b - a.
    var a = [_]u8{0} ** 32;
    a[31] = 3;
    var b = [_]u8{0} ** 32;
    b[31] = 10;
    var k = [_]u8{0} ** 32; // k = b - a = 7
    k[31] = 7;

    const in_commit = try Commitment.commit(100, &a);
    const out_commit = try Commitment.commit(90, &b);
    const excess = try Commitment.commit(0, &k);

    var kernel = TxKernel.withFeatures(.{ .plain = .{ .fee = 10 } });
    kernel.excess = excess;
    const msg = kernel.msgToSign();
    const seed = [_]u8{9} ** 32;
    kernel.excess_sig = crypto.signKernel(&k, &msg, &seed).?;
    try kernel.verify();

    var inputs = [_]Input{.{ .features = .plain, .commit = in_commit }};
    // Range proof generation isn't ported; use a zero proof and skip proof
    // verification by validating the parts individually below.
    var outputs = [_]Output{.{ .features = .plain, .commit = out_commit, .proof = RangeProof.zero }};
    var kernels = [_]TxKernel{kernel};
    var tx: Transaction = .{
        .offset = BlindingFactor.zero,
        .body = try TransactionBody.init(gpa, &inputs, &outputs, &kernels, false),
    };

    try tx.body.validateRead(gpa, .mainnet, .as_transaction);
    try tx.body.verifyFeatures();
    _ = try tx.body.verifyKernelSums(gpa, tx.overage(), tx.offset);
    try TxKernel.batchSigVerify(gpa, tx.body.kernels);

    // wrong fee breaks the sum
    try testing.expectError(error.KernelSumMismatch, tx.body.verifyKernelSums(gpa, 11, tx.offset));

    // a tampered signature is rejected
    var bad = kernel;
    bad.excess_sig.bytes[40] ^= 1;
    try testing.expectError(error.IncorrectSignature, bad.verify());

    // wire round-trip
    const bytes = try ser.serVec(gpa, tx.body, ProtocolVersion.local());
    defer gpa.free(bytes);
    var r = ser.Reader.init(gpa, bytes, ProtocolVersion.local());
    var back = try TransactionBody.read(&r);
    defer back.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), back.inputs.len);
    try testing.expect(back.kernels[0].hash().eql(kernel.hash()));
}

pub fn testSecret(v: u8) [32]u8 {
    var k = [_]u8{0} ** 32;
    k[31] = v;
    return k;
}

pub fn testTx(gpa: std.mem.Allocator, in_value: u64, in_blind: u8, out_value: u64, out_blind: u8, fee: u64, seed: u8) !Transaction {
    const a = testSecret(in_blind);
    const b = testSecret(out_blind);
    const k = testSecret(out_blind - in_blind);
    var kernel = TxKernel.withFeatures(.{ .plain = .{ .fee = fee } });
    kernel.excess = try Commitment.commit(0, &k);
    const msg = kernel.msgToSign();
    kernel.excess_sig = crypto.signKernel(&k, &msg, &([_]u8{seed} ** 32)).?;
    const ins = try gpa.dupe(Input, &.{.{ .features = .plain, .commit = try Commitment.commit(in_value, &a) }});
    const outs = try gpa.dupe(Output, &.{.{ .features = .plain, .commit = try Commitment.commit(out_value, &b), .proof = RangeProof.zero }});
    const kerns = try gpa.dupe(TxKernel, &.{kernel});
    return .{ .offset = BlindingFactor.zero, .body = .{ .inputs = ins, .outputs = outs, .kernels = kerns } };
}

test "aggregate cuts through dependent transactions; deaggregate undoes one" {
    const gpa = testing.allocator;
    // A: 100(a=3) -> 90(b=10), fee 10.  B: 90(b=10) -> 70(c=20), fee 20.
    var a = try testTx(gpa, 100, 3, 90, 10, 10, 1);
    defer a.deinit(gpa);
    var b = try testTx(gpa, 90, 10, 70, 20, 20, 2);
    defer b.deinit(gpa);

    var agg = try aggregate(gpa, &.{ a, b });
    defer agg.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), agg.body.inputs.len);
    try testing.expectEqual(@as(usize, 1), agg.body.outputs.len);
    try testing.expectEqual(@as(usize, 2), agg.body.kernels.len);
    try testing.expectEqual(@as(u64, 30), agg.fee());
    _ = try agg.body.verifyKernelSums(gpa, agg.overage(), agg.offset);
    try agg.body.verifySorted(gpa);

    // order doesn't matter
    var agg2 = try aggregate(gpa, &.{ b, a });
    defer agg2.deinit(gpa);
    try testing.expect(agg.hash().eql(agg2.hash()));

    // a single tx aggregates to itself; none to the empty tx
    var one = try aggregate(gpa, &.{a});
    defer one.deinit(gpa);
    try testing.expect(one.hash().eql(a.hash()));
    try testing.expectEqual(@as(usize, 0), (try aggregate(gpa, &.{})).body.kernels.len);

    // removing A from the aggregate leaves B's kernel and the final output
    var rest = try deaggregate(gpa, agg, &.{a});
    defer rest.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), rest.body.inputs.len);
    try testing.expectEqual(@as(usize, 1), rest.body.outputs.len);
    try testing.expectEqual(@as(usize, 1), rest.body.kernels.len);
    try testing.expect(rest.body.kernels[0].hash().eql(b.body.kernels[0].hash()));

    // duplicate outputs can't be aggregated
    try testing.expectError(error.AggregationError, aggregate(gpa, &.{ a, a }));
}

test "unsorted or duplicate bodies are rejected" {
    const gpa = testing.allocator;
    var ins = [_]Input{
        .{ .features = .plain, .commit = .{ .bytes = [_]u8{1} ** 33 } },
        .{ .features = .plain, .commit = .{ .bytes = [_]u8{1} ** 33 } },
    };
    var body: TransactionBody = .{ .inputs = &ins, .outputs = &.{}, .kernels = &.{} };
    try testing.expectError(error.DuplicateError, body.verifySorted(gpa));
    var ins2 = [_]Input{
        .{ .features = .plain, .commit = .{ .bytes = [_]u8{1} ** 33 } },
        .{ .features = .plain, .commit = .{ .bytes = [_]u8{2} ** 33 } },
    };
    body.inputs = &ins2;
    try sortByHash(Input, gpa, body.inputs);
    try body.verifySorted(gpa);
    std.mem.swap(Input, &body.inputs[0], &body.inputs[1]);
    try testing.expectError(error.SortError, body.verifySorted(gpa));
}
