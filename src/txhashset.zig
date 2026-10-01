//! The txhashset: output, range-proof and kernel PMMRs plus the header MMR.
//! Port of `chain/src/txhashset/*`. All mutating operations are transactional
//! at the file level: they change working state; `sync` makes it durable and
//! `discard` reverts to the last synced state.
const std = @import("std");
const Io = std.Io;
const ser = @import("ser.zig");
const hash_mod = @import("hash.zig");
const crypto = @import("crypto.zig");
const consensus = @import("consensus.zig");
const block = @import("block.zig");
const tx = @import("transaction.zig");
const pmmr = @import("pmmr.zig");
const pmmr_backend = @import("pmmr_backend.zig");
const kv = @import("kv.zig");
const chain_db = @import("chain_db.zig");
const chain_types = @import("chain_types.zig");
const Bitmap = @import("bitmap.zig").Bitmap;

const Hash = hash_mod.Hash;
const Commitment = crypto.Commitment;
const RangeProof = crypto.RangeProof;
const Output = tx.Output;
const OutputIdentifier = tx.OutputIdentifier;
const TxKernel = tx.TxKernel;
const BlockHeader = block.BlockHeader;
const Block = block.Block;
const Tip = chain_types.Tip;
const CommitPos = chain_types.CommitPos;

pub const Error = error{
    TxHashSetErr,
    InvalidRoot,
    InvalidMMRSize,
    AlreadySpent,
    DuplicateCommitment,
    OutputNotFound,
    RangeproofNotFound,
    TxKernelNotFound,
    NotFound,
    OutputMismatch,
    InvalidBitmap,
    ImmatureCoinbase,
} || pmmr.Error || kv.Error || tx.Error || std.mem.Allocator.Error;

// ------------------------------------------------------ bitmap accumulator

/// 1024 bits (128 bytes) of the unspent-output bitmap; hashed as a PMMR leaf.
pub const BitmapChunk = struct {
    bytes: [128]u8 = [_]u8{0} ** 128,

    pub const LEN_BITS = 1024;

    /// Bit 0 is the most significant bit of the first byte (`BitVec::to_bytes`).
    pub fn set(self: *BitmapChunk, idx: u64) void {
        self.bytes[@intCast(idx / 8)] |= @as(u8, 0x80) >> @intCast(idx % 8);
    }
    pub fn any(self: BitmapChunk) bool {
        for (self.bytes) |b| if (b != 0) return true;
        return false;
    }
    pub fn write(self: BitmapChunk, w: anytype) ser.Error!void {
        try w.writeFixedBytes(&self.bytes);
    }
    fn same(c: BitmapChunk) BitmapChunk {
        return c;
    }
};

const ChunkBackend = pmmr.VecBackend(BitmapChunk, BitmapChunk, BitmapChunk.same);
const ChunkPMMR = pmmr.PMMR(BitmapChunk, ChunkBackend);

pub const BitmapAccumulator = struct {
    backend: ChunkBackend,

    pub fn init(gpa: std.mem.Allocator) BitmapAccumulator {
        return .{ .backend = ChunkBackend.init(gpa) };
    }
    pub fn deinit(self: *BitmapAccumulator) void {
        self.backend.deinit();
    }

    fn size(self: *const BitmapAccumulator) u64 {
        return self.backend.hashes.items.len;
    }

    pub fn chunkStartIdx(idx: u64) u64 {
        return idx & ~@as(u64, 0x3ff);
    }

    /// Builds from scratch: `idx` yields ascending indexes of unspent leaves.
    pub fn build(self: *BitmapAccumulator, idx: anytype, total: u64) !void {
        try self.applyFrom(idx, 0, total);
    }

    /// `apply`: `invalidated` is the sorted list of changed leaf indexes, `idx`
    /// yields unspent leaf indexes from the first affected chunk onward.
    pub fn apply(self: *BitmapAccumulator, invalidated: []const u64, idx: anytype, total: u64) !void {
        if (invalidated.len == 0) return;
        const from_idx = invalidated[0];
        try self.rewindPrior(from_idx);
        try self.padLeft(from_idx);
        try self.applyFrom(idx, from_idx, total);
    }

    fn applyFrom(self: *BitmapAccumulator, idx: anytype, from_idx: u64, total: u64) !void {
        var chunk_idx = from_idx / 1024;
        var chunk: BitmapChunk = .{};
        var pending: ?u64 = null;
        while (true) {
            const x = pending orelse (nextBelow(idx, total) orelse break);
            pending = null;
            if (x < chunk_idx * 1024) continue;
            if (x < (chunk_idx + 1) * 1024) {
                chunk.set(x % 1024);
            } else {
                try self.appendChunk(chunk);
                chunk_idx += 1;
                chunk = .{};
                pending = x;
            }
        }
        if (chunk.any()) try self.appendChunk(chunk);
    }

    fn nextBelow(it: anytype, total: u64) ?u64 {
        while (it.nextIdx()) |x| if (x < total) return x;
        return null;
    }

    fn rewindPrior(self: *BitmapAccumulator, from_idx: u64) !void {
        const chunk_idx = from_idx / 1024;
        var m = ChunkPMMR.at(&self.backend, self.size());
        const chunk_pos = pmmr.insertionToPmmrIndex(chunk_idx + 1);
        try m.rewind(chunk_pos -| 1, null);
    }

    fn padLeft(self: *BitmapAccumulator, from_idx: u64) !void {
        const chunk_idx = from_idx / 1024;
        var n = pmmr.nLeaves(self.size());
        while (n < chunk_idx) : (n += 1) try self.appendChunk(.{});
    }

    fn appendChunk(self: *BitmapAccumulator, chunk: BitmapChunk) !void {
        var m = ChunkPMMR.at(&self.backend, self.size());
        _ = try m.push(chunk);
    }

    pub fn root(self: *const BitmapAccumulator) Hash {
        var b = self.backend;
        const m = ChunkPMMR.at(&b, self.size());
        return m.root() catch Hash.zero;
    }
};

// -------------------------------------------------------------- backends

fn outAsElmt(o: Output) OutputIdentifier {
    return o.identifier();
}
fn rpSame(p: RangeProof) RangeProof {
    return p;
}
fn kSame(k: TxKernel) TxKernel {
    return k;
}
fn hdrAsEntry(h: BlockHeader) block.HeaderEntry {
    return h.asEntry();
}

pub const RANGEPROOF_ELMT_SIZE: u16 = 8 + crypto.MAX_PROOF_SIZE;

pub const OutputBackend = pmmr_backend.PMMRBackend(Output, OutputIdentifier, outAsElmt, OutputIdentifier.SIZE);
pub const RangeProofBackend = pmmr_backend.PMMRBackend(RangeProof, RangeProof, rpSame, RANGEPROOF_ELMT_SIZE);
pub const KernelBackend = pmmr_backend.PMMRBackend(TxKernel, TxKernel, kSame, null);
pub const HeaderBackend = pmmr_backend.PMMRBackend(BlockHeader, block.HeaderEntry, hdrAsEntry, block.HeaderEntry.LEN);

pub const OutputPMMR = pmmr.PMMR(Output, OutputBackend);
pub const RangeProofPMMR = pmmr.PMMR(RangeProof, RangeProofBackend);
pub const KernelPMMR = pmmr.PMMR(TxKernel, KernelBackend);
pub const HeaderPMMR = pmmr.PMMR(BlockHeader, HeaderBackend);

// -------------------------------------------------------------- header MMR

/// The MMR of all header hashes on the current chain (one leaf per height).
pub const HeaderMmr = struct {
    backend: *HeaderBackend,
    /// Working size (may run ahead of the synced size until `sync`).
    last_pos: u64,

    pub fn open(gpa: std.mem.Allocator, io: Io, dir: Io.Dir) !HeaderMmr {
        const be = try HeaderBackend.open(gpa, io, dir, false, ser.ProtocolVersion.localDb());
        return .{ .backend = be, .last_pos = be.unprunedSize() };
    }
    pub fn close(self: *HeaderMmr) void {
        self.backend.close();
    }

    fn pmmrView(self: *HeaderMmr) HeaderPMMR {
        return HeaderPMMR.at(self.backend, self.last_pos);
    }

    pub fn applyHeader(self: *HeaderMmr, h: BlockHeader) Error!void {
        var m = self.pmmrView();
        _ = m.push(h) catch return error.TxHashSetErr;
        self.last_pos = m.last_pos;
    }

    /// Rewinds so the last leaf is the header at `height`.
    pub fn rewindToHeight(self: *HeaderMmr, height: u64) Error!void {
        var m = self.pmmrView();
        try m.rewind(pmmr.insertionToPmmrIndex(height + 1), null);
        self.last_pos = m.last_pos;
    }

    pub fn root(self: *HeaderMmr) Error!Hash {
        return self.pmmrView().root() catch error.InvalidRoot;
    }

    /// Hash of the header at `height` on the current chain.
    pub fn hashAtHeight(self: *HeaderMmr, height: u64) ?Hash {
        const entry = self.pmmrView().getData(pmmr.insertionToPmmrIndex(height + 1)) orelse return null;
        return entry.hash;
    }

    pub fn sync(self: *HeaderMmr) !void {
        try self.backend.sync();
    }
    pub fn discard(self: *HeaderMmr) !void {
        try self.backend.discard();
        self.last_pos = self.backend.unprunedSize();
    }
};

// -------------------------------------------------------------- TxHashSet

pub const Sizes = struct { output: u64, rproof: u64, kernel: u64 };

/// How far the signature and range-proof checks have got, for the node's
/// status (the reference's `TxHashsetKernelsValidation` and
/// `TxHashsetRangeProofsValidation`). Only one validation runs at a time.
pub const Progress = struct {
    pub const IDLE: u8 = 0;
    pub const KERNELS: u8 = 1;
    pub const RANGEPROOFS: u8 = 2;
    stage: std.atomic.Value(u8) = .init(IDLE),
    done: std.atomic.Value(u64) = .init(0),
    total: std.atomic.Value(u64) = .init(0),

    fn begin(self: *Progress, stage: u8, total: u64) void {
        self.done.store(0, .monotonic);
        self.total.store(total, .monotonic);
        self.stage.store(stage, .release);
    }
    fn add(self: *Progress, n: u64) void {
        _ = self.done.fetchAdd(n, .monotonic);
    }
    fn end(self: *Progress) void {
        self.stage.store(IDLE, .release);
    }
};
pub var progress: Progress = .{};

pub const TxHashSet = struct {
    gpa: std.mem.Allocator,
    io: Io,
    chain: consensus.ChainType,
    dir: Io.Dir,
    output: *OutputBackend,
    rproof: *RangeProofBackend,
    kernel: *KernelBackend,
    /// Directory handles the backends borrow; closed with the set.
    dirs: [3]Io.Dir,
    /// Working sizes (last positions), ahead of the synced ones inside a transaction.
    sizes: Sizes,
    synced: Sizes,
    head: Tip,
    synced_head: Tip,
    /// Built on demand: only header version >= 7 needs its root.
    accumulator: ?BitmapAccumulator = null,

    /// `dir` is the "txhashset" directory holding output/, rangeproof/, kernel/.
    /// `snapshot`: adopt leaf-set snapshots taken at this header (after a fast-sync download).
    pub fn open(gpa: std.mem.Allocator, io: Io, chain: consensus.ChainType, dir: Io.Dir, head: Tip, snapshot: ?Hash) !TxHashSet {
        var od = try dir.createDirPathOpen(io, "output", .{});
        errdefer od.close(io);
        var rd = try dir.createDirPathOpen(io, "rangeproof", .{});
        errdefer rd.close(io);
        var kd = try dir.createDirPathOpen(io, "kernel", .{});
        errdefer kd.close(io);

        const v1 = ser.ProtocolVersion.localDb();
        const output = try OutputBackend.openAt(gpa, io, od, true, v1, snapshot);
        errdefer output.close();
        const rproof = try RangeProofBackend.openAt(gpa, io, rd, true, v1, snapshot);
        errdefer rproof.close();
        const kernel = try openKernelBackend(gpa, io, kd);
        errdefer kernel.close();

        const sizes: Sizes = .{ .output = output.unprunedSize(), .rproof = rproof.unprunedSize(), .kernel = kernel.unprunedSize() };
        return .{
            .gpa = gpa,
            .io = io,
            .chain = chain,
            .dir = dir,
            .output = output,
            .rproof = rproof,
            .kernel = kernel,
            .dirs = .{ od, rd, kd },
            .sizes = sizes,
            .synced = sizes,
            .head = head,
            .synced_head = head,
        };
    }

    /// The kernel PMMR was written with protocol v2 or v1 depending on who
    /// produced it; try v2 first and keep the version whose first kernel verifies.
    fn openKernelBackend(gpa: std.mem.Allocator, io: Io, kd: Io.Dir) !*KernelBackend {
        const versions = [_]ser.ProtocolVersion{ .{ .v = 2 }, .{ .v = 1 } };
        for (versions) |v| {
            const be = try KernelBackend.open(gpa, io, kd, false, v);
            if (be.unprunedSize() == 0) return be;
            var m = KernelPMMR.at(be, 1);
            if (m.getData(1)) |k| {
                if (k.verify()) |_| return be else |_| {}
            }
            be.close();
            // a wrong-version parse leaves a bogus size file behind: drop it
            kd.deleteFile(io, pmmr_backend.SIZE_FILE) catch {};
        }
        return error.TxHashSetErr;
    }

    pub fn close(self: *TxHashSet) void {
        self.output.close();
        self.rproof.close();
        self.kernel.close();
        for (self.dirs) |d| d.close(self.io);
        if (self.accumulator) |*a| a.deinit();
    }

    fn outPmmr(self: *const TxHashSet) OutputPMMR {
        return OutputPMMR.at(self.output, self.sizes.output);
    }
    fn rpPmmr(self: *const TxHashSet) RangeProofPMMR {
        return RangeProofPMMR.at(self.rproof, self.sizes.rproof);
    }
    fn kernPmmr(self: *const TxHashSet) KernelPMMR {
        return KernelPMMR.at(self.kernel, self.sizes.kernel);
    }

    // ---- read access

    /// Iterator over the positions of unspent outputs (ascending).
    pub fn unspentOutputPositions(self: *const TxHashSet) Bitmap.Iterator {
        return self.output.leafPosIter();
    }

    pub fn outputAt(self: *const TxHashSet, pos: u64) ?OutputIdentifier {
        return self.outPmmr().getData(pos);
    }

    // ---- read access for the node API

    /// The position and height of the unspent output with these features and
    /// commitment, if there is one (`is_unspent`).
    pub fn isUnspent(self: *const TxHashSet, db: *chain_db.Db, batch: *kv.Batch, features: tx.OutputFeatures, commit: crypto.Commitment) Error!?chain_types.CommitPos {
        const cp = (try db.getOutputPosHeight(batch, commit)) orelse return null;
        const h = self.outPmmr().getHash(cp.pos) orelse return null;
        const id: OutputIdentifier = .{ .features = features, .commit = commit };
        return if (h.eql(hash_mod.hashWithIndex(cp.pos - 1, id))) cp else null;
    }

    /// An unspent output with its range proof (`get_unspent_output_at`).
    pub fn unspentOutputAt(self: *const TxHashSet, pos: u64) ?Output {
        const id = self.outPmmr().getData(pos) orelse return null;
        const proof = self.rpPmmr().getData(pos) orelse return null;
        return id.intoOutput(proof);
    }

    pub const OutputListing = struct { last_index: u64, outputs: []Output };

    /// Unspent outputs from PMMR position `start` on, at most `max`, stopping at
    /// `max_index` (`unspent_outputs_by_pmmr_index`). Caller frees `outputs`.
    pub fn outputsFromPmmrIndex(self: *const TxHashSet, gpa: std.mem.Allocator, start: u64, max: u64, max_index: ?u64) std.mem.Allocator.Error!OutputListing {
        var out: std.ArrayList(Output) = .empty;
        errdefer out.deinit(gpa);
        const last = max_index orelse self.sizes.output;
        var p = if (start == 0) 1 else start;
        while (out.items.len < max and p <= last) : (p += 1) {
            if (self.unspentOutputAt(p)) |o| try out.append(gpa, o);
        }
        return .{ .last_index = p -| 1, .outputs = try out.toOwnedSlice(gpa) };
    }

    /// The kernel with this excess, searching backwards from `max_index` to `min_index` (`find_kernel`).
    pub fn findKernel(self: *const TxHashSet, excess: crypto.Commitment, min_index: ?u64, max_index: ?u64) ?struct { kernel: tx.TxKernel, index: u64 } {
        const lo = min_index orelse 1;
        const km = self.kernPmmr();
        var i = (max_index orelse self.sizes.kernel) + 1;
        while (i > lo) {
            i -= 1;
            if (km.getData(i)) |k| if (k.excess.eql(excess)) return .{ .kernel = k, .index = i };
        }
        return null;
    }

    /// Remembers the peak hashes of the last kernel root computed, so walking
    /// through consecutive MMR sizes re-reads only the peaks that changed.
    pub const PeakCache = struct {
        pos: [64]u64 = undefined,
        hash: [64]Hash = undefined,
        len: usize = 0,
    };

    /// `kernelRootAt` with a peak cache (same result).
    pub fn kernelRootCached(self: *const TxHashSet, size: u64, cache: *PeakCache) Error!Hash {
        if (size == 0) return Hash.zero;
        const pk = pmmr.peaks(size);
        var hashes: [64]Hash = undefined;
        var n: usize = 0;
        for (pk.items()) |p| {
            var found: ?Hash = null;
            for (cache.pos[0..cache.len], 0..) |cp, i| if (cp == p) {
                found = cache.hash[i];
                break;
            };
            if (found == null) found = self.kernel.getFromFile(p);
            if (found) |h| {
                hashes[n] = h;
                n += 1;
            }
        }
        // remember these peaks for the next size
        cache.len = 0;
        for (pk.items()) |p| {
            if (cache.len >= cache.pos.len) break;
            cache.pos[cache.len] = p;
            cache.hash[cache.len] = if (cache.len < n) hashes[cache.len] else Hash.zero;
            cache.len += 1;
        }
        var res: ?Hash = null;
        var i = n;
        while (i > 0) {
            i -= 1;
            res = if (res) |rh| hash_mod.hashPairWithIndex(size, hashes[i], rh) else hashes[i];
        }
        return res orelse error.InvalidRoot;
    }

    /// Root of the kernel MMR as it was when it had `size` nodes (kernels are never pruned).
    pub fn kernelRootAt(self: *const TxHashSet, size: u64) Error!Hash {
        return KernelPMMR.at(self.kernel, size).root() catch error.InvalidRoot;
    }

    // ---- roots and sizes

    pub fn roots(self: *TxHashSet, need_bitmap: bool) Error!chain_types.TxHashSetRoots {
        const out_root = self.outPmmr().root() catch return error.InvalidRoot;
        const bitmap_root = if (need_bitmap) try self.accumulatorRoot() else Hash.zero;
        return .{
            .output_pmmr_root = out_root,
            .bitmap_root = bitmap_root,
            .rproof_root = self.rpPmmr().root() catch return error.InvalidRoot,
            .kernel_root = self.kernPmmr().root() catch return error.InvalidRoot,
        };
    }

    pub fn validateRoots(self: *TxHashSet, header: BlockHeader) Error!void {
        if (header.height == 0) return;
        const r = try self.roots(header.version >= 7);
        try r.validate(header);
    }

    pub fn validateSizes(self: *const TxHashSet, header: BlockHeader) Error!void {
        if (header.height == 0) return;
        if (header.output_mmr_size != self.sizes.output or header.output_mmr_size != self.sizes.rproof or header.kernel_mmr_size != self.sizes.kernel)
            return error.InvalidMMRSize;
    }

    // ---- bitmap accumulator (lazy)

    /// Feeds `nextIdx` with the indexes of unspent leaves >= `from_idx`.
    const LeafIdxIter = struct {
        it: Bitmap.Iterator,
        from_pos: u64,

        fn nextIdx(self: *LeafIdxIter) ?u64 {
            while (self.it.next()) |p| {
                if (p < self.from_pos) continue;
                return pmmr.nLeaves(p) -| 1;
            }
            return null;
        }
    };

    fn leafIdxIter(self: *const TxHashSet, from_idx: u64) LeafIdxIter {
        return .{ .it = self.output.leafPosIter(), .from_pos = pmmr.insertionToPmmrIndex(from_idx + 1) };
    }

    fn accumulatorRoot(self: *TxHashSet) Error!Hash {
        if (self.accumulator == null) {
            var acc = BitmapAccumulator.init(self.gpa);
            errdefer acc.deinit();
            var it = self.leafIdxIter(0);
            try acc.build(&it, pmmr.nLeaves(self.sizes.output));
            self.accumulator = acc;
        }
        return self.accumulator.?.root();
    }

    fn updateAccumulator(self: *TxHashSet, affected_pos: []const u64) Error!void {
        var acc = &(self.accumulator orelse return);
        const idx = try self.gpa.alloc(u64, affected_pos.len);
        defer self.gpa.free(idx);
        for (affected_pos, 0..) |p, i| idx[i] = pmmr.nLeaves(p) -| 1;
        std.mem.sort(u64, idx, {}, std.sort.asc(u64));
        const min_idx = if (idx.len > 0) idx[0] else 0;
        var it = self.leafIdxIter(BitmapAccumulator.chunkStartIdx(min_idx));
        try acc.apply(idx, &it, pmmr.nLeaves(self.sizes.output));
    }

    // ---- UTXO checks (`UTXOView`)

    /// An input must reference an unspent output with the same features and commitment.
    pub fn validateInput(self: *const TxHashSet, db: *chain_db.Db, batch: *kv.Batch, input: tx.Input) Error!void {
        if (try db.getOutputPosHeight(batch, input.commit)) |cp| {
            if (self.outPmmr().getHash(cp.pos)) |h| {
                if (h.eql(hash_mod.hashWithIndex(cp.pos - 1, input))) return;
            }
        }
        return error.AlreadySpent;
    }

    /// An output must not duplicate an existing unspent commitment.
    pub fn validateOutput(self: *const TxHashSet, db: *chain_db.Db, batch: *kv.Batch, out: Output) Error!void {
        if (try db.getOutputPosHeight(batch, out.commit)) |cp| {
            if (self.outPmmr().getData(cp.pos)) |existing| {
                if (existing.commit.eql(out.commit)) return error.DuplicateCommitment;
            }
        }
    }

    pub fn validateBlockUtxo(self: *const TxHashSet, db: *chain_db.Db, batch: *kv.Batch, b: Block) Error!void {
        for (b.body.outputs) |o| try self.validateOutput(db, batch, o);
        for (b.body.inputs) |i| try self.validateInput(db, batch, i);
    }

    /// Coinbase outputs spent by `inputs` must be at least `coinbase_maturity`
    /// blocks old at `height` (measured in output MMR positions).
    pub fn verifyCoinbaseMaturity(self: *const TxHashSet, db: *chain_db.Db, batch: *kv.Batch, headers: *HeaderMmr, inputs: []const tx.Input, height: u64) Error!void {
        var pos: u64 = 0;
        for (inputs) |i| {
            if (!i.isCoinbase()) continue;
            if (try db.getOutputPosHeight(batch, i.commit)) |cp| pos = @max(pos, cp.pos);
        }
        if (pos == 0) return;
        const maturity = self.chain.coinbaseMaturity();
        if (height < maturity) return error.ImmatureCoinbase;
        const cutoff_height = height -| maturity;
        const cutoff_hash = headers.hashAtHeight(cutoff_height) orelse return error.NotFound;
        const cutoff_header = (try db.getBlockHeader(batch, cutoff_hash)) orelse return error.NotFound;
        if (pos > cutoff_header.output_mmr_size) return error.ImmatureCoinbase;
    }

    // ---- applying blocks

    /// Applies `b` to the working state, recording output positions in `batch`.
    /// Returns the spent outputs (caller frees with the txhashset allocator).
    pub fn applyBlock(self: *TxHashSet, db: *chain_db.Db, batch: *kv.Batch, b: Block) Error![]CommitPos {
        var affected: std.ArrayList(u64) = .empty;
        defer affected.deinit(self.gpa);
        var spent: std.ArrayList(CommitPos) = .empty;
        errdefer spent.deinit(self.gpa);

        for (b.body.outputs) |out| {
            const pos = try self.applyOutput(db, batch, out);
            try affected.append(self.gpa, pos);
            try db.saveOutputPosHeight(batch, out.commit, pos, b.header.height);
        }
        for (b.body.inputs) |input| {
            const sp = try self.applyInput(db, batch, input);
            try affected.append(self.gpa, sp.pos);
            try db.deleteOutputPosHeight(batch, input.commit);
            try spent.append(self.gpa, sp);
        }
        for (b.body.kernels) |k| {
            var m = self.kernPmmr();
            _ = m.push(k) catch return error.TxHashSetErr;
            self.sizes.kernel = m.last_pos;
        }
        try self.updateAccumulator(affected.items);
        self.head = Tip.fromHeader(b.header);
        return spent.toOwnedSlice(self.gpa);
    }

    fn applyOutput(self: *TxHashSet, db: *chain_db.Db, batch: *kv.Batch, out: Output) Error!u64 {
        if (try db.getOutputPosHeight(batch, out.commit)) |cp| {
            if (self.outPmmr().getData(cp.pos)) |existing| {
                if (existing.commit.eql(out.commit)) return error.DuplicateCommitment;
            }
        }
        var om = self.outPmmr();
        const output_pos = om.push(out) catch return error.TxHashSetErr;
        self.sizes.output = om.last_pos;
        var rm = self.rpPmmr();
        const rproof_pos = rm.push(out.proof) catch return error.TxHashSetErr;
        self.sizes.rproof = rm.last_pos;
        if (self.sizes.output != self.sizes.rproof or output_pos != rproof_pos) return error.TxHashSetErr;
        return output_pos;
    }

    fn applyInput(self: *TxHashSet, db: *chain_db.Db, batch: *kv.Batch, input: tx.Input) Error!CommitPos {
        const cp = (try db.getOutputPosHeight(batch, input.commit)) orelse return error.AlreadySpent;
        var om = self.outPmmr();
        if (om.getHash(cp.pos)) |h| {
            if (!h.eql(hash_mod.hashWithIndex(cp.pos - 1, input))) return error.OutputMismatch;
        }
        const pruned = om.prune(cp.pos) catch return error.TxHashSetErr;
        if (!pruned) return error.AlreadySpent;
        var rm = self.rpPmmr();
        _ = rm.prune(cp.pos) catch return error.TxHashSetErr;
        return cp;
    }

    // ---- rewinding

    fn rewindMmrsToPos(self: *TxHashSet, output_pos: u64, kernel_pos: u64, spent_pos: []const u64) Error!void {
        var bm = try Bitmap.init();
        defer bm.deinit();
        for (spent_pos) |p| bm.add(@truncate(p));
        var om = self.outPmmr();
        try om.rewind(output_pos, &bm);
        self.sizes.output = om.last_pos;
        var rm = self.rpPmmr();
        try rm.rewind(output_pos, &bm);
        self.sizes.rproof = rm.last_pos;
        var km = self.kernPmmr();
        var empty = try Bitmap.init();
        defer empty.deinit();
        try km.rewind(kernel_pos, &empty);
        self.sizes.kernel = km.last_pos;
    }

    /// Truncates the MMRs to the sizes recorded in `header` (no spent-output
    /// bookkeeping): what a node does after loading a downloaded archive whose
    /// files run past the archive header.
    pub fn rewindToHeaderSizes(self: *TxHashSet, header: BlockHeader) Error!void {
        try self.rewindMmrsToPos(header.output_mmr_size, header.kernel_mmr_size, &.{});
        self.accumulatorReset();
        self.head = Tip.fromHeader(header);
    }

    /// Rewinds to the state right after `header` (which must be on the chain
    /// the working state was built on).
    pub fn rewind(self: *TxHashSet, db: *chain_db.Db, batch: *kv.Batch, header: BlockHeader) Error!void {
        const head_header = (try db.getBlockHeader(batch, self.head.last_block_h)) orelse return error.NotFound;
        if (head_header.height <= header.height) {
            try self.rewindMmrsToPos(header.output_mmr_size, header.kernel_mmr_size, &.{});
            self.accumulatorReset();
        } else {
            var current = head_header;
            while (header.height < current.height) {
                try self.rewindSingleBlock(db, batch, current);
                current = (try db.getPreviousHeader(batch, current)) orelse return error.NotFound;
            }
            self.accumulatorReset();
        }
        self.head = Tip.fromHeader(header);
    }

    /// (Rewinding invalidates the incremental accumulator; it is rebuilt on demand.)
    fn accumulatorReset(self: *TxHashSet) void {
        if (self.accumulator) |*a| a.deinit();
        self.accumulator = null;
    }

    fn rewindSingleBlock(self: *TxHashSet, db: *chain_db.Db, batch: *kv.Batch, header: BlockHeader) Error!void {
        const spent_list = try db.getSpentIndex(batch, header.hash());
        defer if (spent_list) |s| self.gpa.free(s.items);
        var spent_pos: std.ArrayList(u64) = .empty;
        defer spent_pos.deinit(self.gpa);
        if (spent_list) |s| for (s.items) |c| try spent_pos.append(self.gpa, c.pos);

        if (header.height == 0) {
            try self.rewindMmrsToPos(0, 0, spent_pos.items);
        } else {
            const prev = (try db.getPreviousHeader(batch, header)) orelse return error.NotFound;
            try self.rewindMmrsToPos(prev.output_mmr_size, prev.kernel_mmr_size, spent_pos.items);
        }

        var blk = (try db.getBlock(batch, header.hash())) orelse return error.NotFound;
        defer blk.deinit(self.gpa);
        for (blk.body.outputs) |out| db.deleteOutputPosHeight(batch, out.commit) catch {};
        if (spent_list) |s| {
            for (blk.body.inputs, s.items) |input, cp| try db.saveOutputPosHeight(batch, input.commit, cp.pos, cp.height);
        }
    }

    // ---- transaction control

    /// Makes the working state durable.
    pub fn sync(self: *TxHashSet) !void {
        try self.output.sync();
        try self.rproof.sync();
        try self.kernel.sync();
        self.synced = self.sizes;
        self.synced_head = self.head;
    }

    /// Removes the spent outputs and range proofs below the horizon from the
    /// files (`compact`). `rewind_rm_pos` holds the positions spent after the
    /// horizon: they stay, so rewinding to the horizon still works. The MMR
    /// roots and sizes don't change.
    pub fn compact(self: *TxHashSet, horizon: BlockHeader, rewind_rm_pos: *const Bitmap) Error!void {
        self.sync() catch |e| {
            std.log.err("Sync before compaction failed: {s}", .{@errorName(e)});
            return error.TxHashSetErr;
        };
        self.output.checkCompact(horizon.output_mmr_size, rewind_rm_pos) catch |e| {
            std.log.err("Compacting the output MMR failed: {s}", .{@errorName(e)});
            return error.TxHashSetErr;
        };
        self.rproof.checkCompact(horizon.output_mmr_size, rewind_rm_pos) catch |e| {
            std.log.err("Compacting the range proof MMR failed: {s}", .{@errorName(e)});
            return error.TxHashSetErr;
        };
    }

    /// Bytes on disk of the output and range proof data and hash files.
    pub fn prunableBytes(self: *const TxHashSet) u64 {
        return self.output.data_file.file_len + self.output.hash_file.file_len + self.rproof.data_file.file_len + self.rproof.hash_file.file_len;
    }

    /// Fsync on every `sync` (the default) or only flush to the OS (bulk catch-up).
    pub fn setFsync(self: *TxHashSet, on: bool) void {
        self.output.setFsync(on);
        self.rproof.setFsync(on);
        self.kernel.setFsync(on);
    }

    /// Fsyncs everything written so far.
    pub fn forceSync(self: *TxHashSet) !void {
        try self.output.forceSync();
        try self.rproof.forceSync();
        try self.kernel.forceSync();
    }

    /// Drops all changes since the last `sync`.
    pub fn discard(self: *TxHashSet) !void {
        try self.output.discard();
        try self.rproof.discard();
        try self.kernel.discard();
        self.sizes = self.synced;
        self.head = self.synced_head;
        self.accumulatorReset();
    }

    // ---- full validation

    const parallel = @import("parallel.zig");

    fn fromWorker(e: anyerror) Error {
        return @errorCast(e);
    }

    /// Checks every parent hash in the three MMRs (in parallel chunks).
    pub fn validateMmrs(self: *TxHashSet) Error!void {
        const CHUNK: u64 = 1 << 20;
        const Ctx = struct {
            ths: *const TxHashSet,
            out_chunks: usize,
            rp_chunks: usize,
            fn work(c: *@This(), i: usize) anyerror!void {
                if (i < c.out_chunks) {
                    const first = @as(u64, i) * CHUNK + 1;
                    return c.ths.outPmmr().validateRange(first, first + CHUNK - 1);
                }
                if (i < c.out_chunks + c.rp_chunks) {
                    const first = @as(u64, i - c.out_chunks) * CHUNK + 1;
                    return c.ths.rpPmmr().validateRange(first, first + CHUNK - 1);
                }
                const first = @as(u64, i - c.out_chunks - c.rp_chunks) * CHUNK + 1;
                return c.ths.kernPmmr().validateRange(first, first + CHUNK - 1);
            }
        };
        var ctx: Ctx = .{
            .ths = self,
            .out_chunks = @intCast((self.sizes.output + CHUNK - 1) / CHUNK),
            .rp_chunks = @intCast((self.sizes.rproof + CHUNK - 1) / CHUNK),
        };
        const kern_chunks: usize = @intCast((self.sizes.kernel + CHUNK - 1) / CHUNK);
        parallel.forEach(Ctx, &ctx, ctx.out_chunks + ctx.rp_chunks + kern_chunks, Ctx.work) catch |e| return fromWorker(e);
    }

    /// Verifies all unspent range proofs, in batches spread over all cores.
    pub fn verifyRangeproofs(self: *TxHashSet) Error!void {
        const BATCH = 1000;
        var positions: std.ArrayList(u64) = .empty;
        defer positions.deinit(self.gpa);
        var it = self.output.leafPosIter();
        // (the leaf-set rewind quirk can leave one stale bit past the end)
        while (it.next()) |pos| if (pos <= self.sizes.output) try positions.append(self.gpa, pos);
        progress.begin(Progress.RANGEPROOFS, positions.items.len);
        defer progress.end();

        const Ctx = struct {
            ths: *const TxHashSet,
            positions: []const u64,
            fn work(c: *@This(), i: usize) anyerror!void {
                const gpa = c.ths.gpa;
                const chunk = c.positions[i * BATCH ..][0..@min(BATCH, c.positions.len - i * BATCH)];
                const commits = try gpa.alloc(Commitment, chunk.len);
                defer gpa.free(commits);
                const proofs = try gpa.alloc(RangeProof, chunk.len);
                defer gpa.free(proofs);
                const om = c.ths.outPmmr();
                const rm = c.ths.rpPmmr();
                for (chunk, 0..) |pos, k| {
                    const out = om.getData(pos) orelse return error.OutputNotFound;
                    commits[k] = out.commit;
                    proofs[k] = rm.getData(pos) orelse return error.RangeproofNotFound;
                }
                try crypto.verifyBulletProofMulti(gpa, commits, proofs);
                progress.add(chunk.len);
            }
        };
        var ctx: Ctx = .{ .ths = self, .positions = positions.items };
        parallel.forEach(Ctx, &ctx, (positions.items.len + BATCH - 1) / BATCH, Ctx.work) catch |e| return fromWorker(e);
    }

    const KERNEL_CHUNK: u64 = 50_000; // MMR positions per work item
    const SIG_BATCH = 5000;

    /// One pass over every kernel, spread over all cores: optionally verifies
    /// the signatures (in batches) and returns the sum of the excesses of each
    /// chunk (point addition is associative, so the partial sums add up to the
    /// whole). Caller frees the result.
    fn kernelPass(self: *TxHashSet, verify_sigs: bool) Error![]Commitment {
        const chunks: usize = @intCast((self.sizes.kernel + KERNEL_CHUNK - 1) / KERNEL_CHUNK);
        const partials = try self.gpa.alloc(Commitment, chunks);
        errdefer self.gpa.free(partials);
        const Ctx = struct {
            ths: *const TxHashSet,
            verify: bool,
            partials: []Commitment,
            fn work(c: *@This(), i: usize) anyerror!void {
                const gpa = c.ths.gpa;
                const first = @as(u64, i) * KERNEL_CHUNK + 1;
                const last = @min(first + KERNEL_CHUNK - 1, c.ths.sizes.kernel);
                var ks: std.ArrayList(TxKernel) = .empty;
                defer ks.deinit(gpa);
                var excesses: std.ArrayList(Commitment) = .empty;
                defer excesses.deinit(gpa);
                const km = c.ths.kernPmmr();
                var n = first;
                while (n <= last) : (n += 1) {
                    if (!pmmr.isLeaf(n)) continue;
                    const k = km.getData(n) orelse return error.TxKernelNotFound;
                    try excesses.append(gpa, k.excess);
                    if (c.verify) {
                        try ks.append(gpa, k);
                        if (ks.items.len >= SIG_BATCH) {
                            try TxKernel.batchSigVerify(gpa, ks.items);
                            progress.add(ks.items.len);
                            ks.clearRetainingCapacity();
                        }
                    }
                }
                if (ks.items.len > 0) {
                    try TxKernel.batchSigVerify(gpa, ks.items);
                    progress.add(ks.items.len);
                }
                c.partials[i] = if (excesses.items.len == 0) Commitment.zero else try tx.sumCommits(gpa, excesses.items, &.{});
            }
        };
        if (verify_sigs) progress.begin(Progress.KERNELS, pmmr.nLeaves(self.sizes.kernel));
        defer if (verify_sigs) progress.end();
        var ctx: Ctx = .{ .ths = self, .verify = verify_sigs, .partials = partials };
        parallel.forEach(Ctx, &ctx, chunks, Ctx.work) catch |e| return fromWorker(e);
        return partials;
    }

    /// Verifies all kernel signatures, in batches spread over all cores.
    pub fn verifyKernelSignatures(self: *TxHashSet) Error!void {
        const partials = try self.kernelPass(true);
        self.gpa.free(partials);
    }

    /// The utxo sum and kernel sum over the whole set, checked against the
    /// header's total overage and kernel offset (`validate_kernel_sums`).
    pub fn validateKernelSums(self: *TxHashSet, genesis: BlockHeader, header: BlockHeader) Error!chain_types.BlockSums {
        const partials = try self.kernelPass(false);
        defer self.gpa.free(partials);
        return self.checkKernelSums(genesis, header, partials);
    }

    fn checkKernelSums(self: *TxHashSet, genesis: BlockHeader, header: BlockHeader, kernel_partials: []const Commitment) Error!chain_types.BlockSums {
        var outs: std.ArrayList(Commitment) = .empty;
        defer outs.deinit(self.gpa);
        const om = self.outPmmr();
        var it = self.output.leafPosIter();
        while (it.next()) |pos| if (om.getData(pos)) |o| try outs.append(self.gpa, o.commit);
        const s = try tx.verifyKernelSumsCommits(self.gpa, &.{}, outs.items, kernel_partials, header.totalOverage(self.chain, genesis.kernel_mmr_size > 0), header.total_kernel_offset);
        return .{ .utxo_sum = s.utxo_sum, .kernel_sum = s.kernel_sum };
    }

    /// `Extension::validate`: MMR hashes, roots, sizes, kernel sums, and (unless
    /// `fast`) every range proof and kernel signature.
    pub fn validate(self: *TxHashSet, genesis: BlockHeader, fast: bool, header: BlockHeader) Error!chain_types.BlockSums {
        var t = self.stageTimer();
        try self.validateMmrs();
        t.lap("MMR hashes");
        try self.validateRoots(header);
        try self.validateSizes(header);
        t.lap("roots and sizes");
        if (self.head.height == 0) return chain_types.BlockSums.zero;
        // kernels are read once: signatures (unless `fast`) and the sums together
        const partials = try self.kernelPass(!fast);
        defer self.gpa.free(partials);
        const sums = try self.checkKernelSums(genesis, header, partials);
        t.lap(if (fast) "kernel sums" else "kernel sums and signatures");
        if (!fast) {
            try self.verifyRangeproofs();
            t.lap("range proofs");
        }
        return sums;
    }

    /// Logs how long each stage of a long operation took.
    pub const StageTimer = struct {
        io: Io,
        last_ms: i64,
        pub fn lap(self: *StageTimer, what: []const u8) void {
            const now = Io.Clock.awake.now(self.io).toMilliseconds();
            std.log.debug("  {s}: {d:.1}s", .{ what, @as(f64, @floatFromInt(now - self.last_ms)) / 1000.0 });
            self.last_ms = now;
        }
    };

    pub fn stageTimer(self: *const TxHashSet) StageTimer {
        return .{ .io = self.io, .last_ms = Io.Clock.awake.now(self.io).toMilliseconds() };
    }
};

// ------------------------------------------------------------------ tests

const testing = std.testing;

/// Every unspent leaf index in [from, total): the naive reference iterator.
const SliceIter = struct {
    items: []const u64,
    i: usize = 0,
    fn nextIdx(self: *SliceIter) ?u64 {
        if (self.i >= self.items.len) return null;
        defer self.i += 1;
        return self.items[self.i];
    }
};

test "bitmap accumulator: incremental updates equal a rebuild from scratch" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultPrng.init(11);
    const rnd = prng.random();

    const total: u64 = 5000;
    var unspent = try gpa.alloc(bool, total);
    defer gpa.free(unspent);
    @memset(unspent, true);

    var acc = BitmapAccumulator.init(gpa);
    defer acc.deinit();
    var all: std.ArrayList(u64) = .empty;
    defer all.deinit(gpa);
    for (0..total) |i| try all.append(gpa, i);
    var it0 = SliceIter{ .items = all.items };
    try acc.build(&it0, total);

    // spend random leaves in several rounds, updating incrementally each time
    for (0..6) |_| {
        var changed: std.ArrayList(u64) = .empty;
        defer changed.deinit(gpa);
        for (0..40) |_| {
            const i = rnd.intRangeLessThan(u64, 0, total);
            if (unspent[@intCast(i)]) {
                unspent[@intCast(i)] = false;
                try changed.append(gpa, i);
            }
        }
        std.mem.sort(u64, changed.items, {}, std.sort.asc(u64));
        if (changed.items.len == 0) continue;
        const start = BitmapAccumulator.chunkStartIdx(changed.items[0]);
        var live: std.ArrayList(u64) = .empty;
        defer live.deinit(gpa);
        for (unspent, 0..) |u, i| if (u and i >= start) try live.append(gpa, i);
        var it = SliceIter{ .items = live.items };
        try acc.apply(changed.items, &it, total);

        // rebuild from scratch and compare roots
        var fresh = BitmapAccumulator.init(gpa);
        defer fresh.deinit();
        var live_all: std.ArrayList(u64) = .empty;
        defer live_all.deinit(gpa);
        for (unspent, 0..) |u, i| if (u) try live_all.append(gpa, i);
        var it2 = SliceIter{ .items = live_all.items };
        try fresh.build(&it2, total);
        try testing.expect(acc.root().eql(fresh.root()));
    }
}

test "bitmap chunk bit order is MSB first" {
    var c: BitmapChunk = .{};
    c.set(0);
    c.set(9);
    try testing.expectEqual(@as(u8, 0x80), c.bytes[0]);
    try testing.expectEqual(@as(u8, 0x40), c.bytes[1]);
    try testing.expect(c.any());
}

fn fakeOutput(n: u8) Output {
    var c: Commitment = .{ .bytes = [_]u8{0} ** 33 };
    c.bytes[0] = 8;
    c.bytes[1] = n;
    var p = RangeProof.zero;
    p.plen = crypto.MAX_PROOF_SIZE;
    p.proof[0] = n;
    return .{ .features = .plain, .commit = c, .proof = p };
}

fn fakeBlock(gpa: std.mem.Allocator, height: u64, prev: ?BlockHeader, outs: []const u8, spends: []const u8) !Block {
    var h = BlockHeader.default(.mainnet);
    h.height = height;
    h.version = 6;
    h.timestamp = 1_600_000_000 + @as(i64, @intCast(height));
    if (prev) |p| h.prev_hash = p.hash();
    h.pow.nonce = height;
    // the header hash covers the proof, not the height: make each proof distinct
    h.pow.proof.cuckoo.nonces[0] = height;
    // sizes so rewinding to a header restores the right MMR positions
    h.output_mmr_size = 0;
    h.kernel_mmr_size = 0;
    const os = try gpa.alloc(Output, outs.len);
    for (outs, 0..) |n, i| os[i] = fakeOutput(n);
    const ins = try gpa.alloc(tx.Input, spends.len);
    for (spends, 0..) |n, i| ins[i] = .{ .features = .plain, .commit = fakeOutput(n).commit };
    const ks = try gpa.alloc(TxKernel, 1);
    // a properly signed kernel (the kernel PMMR's version detection verifies the first one)
    var key = [_]u8{0} ** 32;
    key[31] = @intCast(height + 1);
    ks[0] = TxKernel.withFeatures(.{ .plain = .{ .fee = height } });
    ks[0].excess = try Commitment.commit(0, &key);
    const msg = ks[0].msgToSign();
    ks[0].excess_sig = crypto.signKernel(&key, &msg, &([_]u8{7} ** 32)).?;
    try tx.sortByHash(tx.Input, gpa, ins);
    try tx.sortByHash(Output, gpa, os);
    return .{ .header = h, .body = .{ .inputs = ins, .outputs = os, .kernels = ks } };
}

test "apply, rewind and replay blocks reproduces identical roots and survives reopen" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = blk: {
        var buf: [128]u8 = undefined;
        const path = try std.fmt.bufPrint(&buf, ".zig-cache/txhstest/db", .{});
        std.Io.Dir.cwd().deleteTree(io, path) catch {};
        break :blk try chain_db.Db.open(gpa, io, path, .mainnet, .{ .block_cache_mb = 8, .write_buffer_mb = 4 });
    };
    defer db.close();

    var dir = try tmp.dir.createDirPathOpen(io, "txhashset", .{});
    defer dir.close(io);
    var ths = try TxHashSet.open(gpa, io, .mainnet, dir, Tip.fromHeader(BlockHeader.default(.mainnet)), null);
    defer ths.close();

    // block 1 makes outputs 1..4; block 2 spends 2 and makes 5,6; block 3 spends 1,5 and makes 7
    var b1 = try fakeBlock(gpa, 1, null, &.{ 1, 2, 3, 4 }, &.{});
    defer b1.deinit(gpa);
    var b2 = try fakeBlock(gpa, 2, b1.header, &.{ 5, 6 }, &.{2});
    defer b2.deinit(gpa);
    var b3 = try fakeBlock(gpa, 3, b2.header, &.{7}, &.{ 1, 5 });
    defer b3.deinit(gpa);

    var batch = db.batch();
    defer batch.deinit();
    var roots: [4]chain_types.TxHashSetRoots = undefined;
    var sizes: [4]Sizes = undefined;
    roots[0] = try ths.roots(true);
    sizes[0] = ths.sizes;
    for ([_]*Block{ &b1, &b2, &b3 }, 1..) |b, i| {
        const spent = try ths.applyBlock(&db, &batch, b.*);
        defer gpa.free(spent);
        // like a real header, record the MMR sizes reached by this block
        b.header.output_mmr_size = ths.sizes.output;
        b.header.kernel_mmr_size = ths.sizes.kernel;
        try db.saveBlockHeader(&batch, b.header);
        try db.saveBlock(&batch, b.*);
        try db.saveSpentIndex(&batch, b.hash(), spent);
        roots[i] = try ths.roots(true);
        sizes[i] = ths.sizes;
    }
    try testing.expectEqual(@as(usize, 2), b3.body.inputs.len);
    try testing.expectEqual(@as(u64, 7 + 0), pmmr.nLeaves(ths.sizes.output) + 0);
    // spent outputs are gone from the unspent set but the root is unaffected by pruning alone
    try testing.expect(ths.outPmmr().getData(pmmr.insertionToPmmrIndex(2)) == null);
    try testing.expect(ths.outPmmr().getData(pmmr.insertionToPmmrIndex(3)) != null);

    // double spend and duplicate creation are rejected
    var bad = try fakeBlock(gpa, 4, b3.header, &.{}, &.{2});
    defer bad.deinit(gpa);
    try testing.expectError(error.AlreadySpent, ths.applyBlock(&db, &batch, bad));
    var dup = try fakeBlock(gpa, 4, b3.header, &.{3}, &.{});
    defer dup.deinit(gpa);
    try testing.expectError(error.DuplicateCommitment, ths.applyBlock(&db, &batch, dup));
    try ths.discard();
    try testing.expectEqual(@as(u64, 0), ths.sizes.output); // nothing was synced yet

    // redo (discard dropped the files' work; the db batch still knows the blocks)
    var batch2 = db.batch();
    defer batch2.deinit();
    for ([_]*Block{ &b1, &b2, &b3 }) |b| {
        try db.saveBlockHeader(&batch2, b.header);
        try db.saveBlock(&batch2, b.*);
        const spent = try ths.applyBlock(&db, &batch2, b.*);
        defer gpa.free(spent);
        try db.saveSpentIndex(&batch2, b.hash(), spent);
    }
    try testing.expect((try ths.roots(true)).output_pmmr_root.eql(roots[3].output_pmmr_root));
    try testing.expect((try ths.roots(true)).bitmap_root.eql(roots[3].bitmap_root));

    // rewind to after block 1: identical roots to what we saw then, output_pos restored
    try ths.rewind(&db, &batch2, b1.header);
    const r1 = try ths.roots(true);
    try testing.expect(r1.output_pmmr_root.eql(roots[1].output_pmmr_root));
    try testing.expect(r1.rproof_root.eql(roots[1].rproof_root));
    try testing.expect(r1.kernel_root.eql(roots[1].kernel_root));
    try testing.expect(r1.bitmap_root.eql(roots[1].bitmap_root));
    try testing.expectEqual(sizes[1].output, ths.sizes.output);
    try testing.expect(ths.outPmmr().getData(pmmr.insertionToPmmrIndex(2)) != null);
    try testing.expect((try db.getOutputPosHeight(&batch2, fakeOutput(2).commit)) != null);
    try testing.expect((try db.getOutputPosHeight(&batch2, fakeOutput(5).commit)) == null);

    // replaying blocks 2 and 3 after the rewind gives the same final roots again
    for ([_]*Block{ &b2, &b3 }) |b| {
        const spent = try ths.applyBlock(&db, &batch2, b.*);
        gpa.free(spent);
    }
    const r3 = try ths.roots(true);
    try testing.expect(r3.output_pmmr_root.eql(roots[3].output_pmmr_root));
    try testing.expect(r3.bitmap_root.eql(roots[3].bitmap_root));
    try testing.expect(r3.kernel_root.eql(roots[3].kernel_root));

    // durable across a close/reopen
    try ths.sync();
    ths.close();
    ths = try TxHashSet.open(gpa, io, .mainnet, dir, Tip.fromHeader(b3.header), null);
    try testing.expectEqual(sizes[3].output, ths.sizes.output);
    try testing.expect((try ths.roots(true)).output_pmmr_root.eql(roots[3].output_pmmr_root));
    try ths.validateMmrs();
}

test "compaction prunes spent outputs below the horizon and keeps roots and rewinds working" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = blk: {
        const path = ".zig-cache/txhstest/compactdb";
        std.Io.Dir.cwd().deleteTree(io, path) catch {};
        break :blk try chain_db.Db.open(gpa, io, path, .mainnet, .{ .block_cache_mb = 8, .write_buffer_mb = 4 });
    };
    defer db.close();
    var dir = try tmp.dir.createDirPathOpen(io, "txhashset", .{});
    defer dir.close(io);
    var ths = try TxHashSet.open(gpa, io, .mainnet, dir, Tip.fromHeader(BlockHeader.default(.mainnet)), null);
    defer ths.close();

    // 1: outputs 1..4; 2: spends all four and makes 5,6; 3: spends 5 makes 7; 4: makes 8.
    // (A lone spent leaf keeps its hash and data, as in the reference: only whole spent
    // subtrees leave the files, so block 2 spends a full subtree.)
    var blocks: [4]Block = .{
        try fakeBlock(gpa, 1, null, &.{ 1, 2, 3, 4 }, &.{}),
        undefined, undefined, undefined,
    };
    blocks[1] = try fakeBlock(gpa, 2, blocks[0].header, &.{ 5, 6 }, &.{ 1, 2, 3, 4 });
    blocks[2] = try fakeBlock(gpa, 3, blocks[1].header, &.{7}, &.{5});
    blocks[3] = try fakeBlock(gpa, 4, blocks[2].header, &.{8}, &.{});
    defer for (&blocks) |*b| b.deinit(gpa);

    var batch = db.batch();
    defer batch.deinit();
    var roots: [5]chain_types.TxHashSetRoots = undefined;
    var spent_after: std.ArrayList(u64) = .empty; // positions spent after the horizon (block 2)
    defer spent_after.deinit(gpa);
    for (&blocks, 1..) |*b, i| {
        const spent = try ths.applyBlock(&db, &batch, b.*);
        defer gpa.free(spent);
        b.header.output_mmr_size = ths.sizes.output;
        b.header.kernel_mmr_size = ths.sizes.kernel;
        try db.saveBlockHeader(&batch, b.header);
        try db.saveSpentIndex(&batch, b.hash(), spent);
        try db.saveBlock(&batch, b.*);
        if (i > 2) for (spent) |cp| try spent_after.append(gpa, cp.pos);
        roots[i] = try ths.roots(true);
    }
    try ths.sync();
    const data_before = ths.output.data_file.sizeInElmts();

    var rm = try Bitmap.init();
    defer rm.deinit();
    for (spent_after.items) |p| rm.add(@truncate(p));
    try ths.compact(blocks[1].header, &rm);

    // outputs 1..4 (spent by the horizon) are gone from the data file; roots unchanged
    const hashes_before = ths.output.hash_file.sizeInElmts();
    _ = hashes_before;
    try testing.expectEqual(data_before - 4, ths.output.data_file.sizeInElmts());
    const r = try ths.roots(true);
    try testing.expect(r.output_pmmr_root.eql(roots[4].output_pmmr_root));
    try testing.expect(r.rproof_root.eql(roots[4].rproof_root));
    for ([_]u8{ 6, 7, 8 }) |n| {
        const pos = (try db.getOutputPosHeight(&batch, fakeOutput(n).commit)).?.pos;
        try testing.expect(ths.outPmmr().getData(pos) != null);
    }

    // rewinding to the horizon still works: output 5 (spent after it) comes back
    try ths.rewind(&db, &batch, blocks[1].header);
    const r2 = try ths.roots(true);
    try testing.expect(r2.output_pmmr_root.eql(roots[2].output_pmmr_root));
    try testing.expect(r2.rproof_root.eql(roots[2].rproof_root));
    try testing.expect(r2.bitmap_root.eql(roots[2].bitmap_root));
    try ths.discard();

    // and the compacted files reopen to the same state
    ths.close();
    ths = try TxHashSet.open(gpa, io, .mainnet, dir, Tip.fromHeader(blocks[3].header), null);
    try testing.expect((try ths.roots(true)).output_pmmr_root.eql(roots[4].output_pmmr_root));
}
