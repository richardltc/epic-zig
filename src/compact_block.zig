//! Compact blocks (`core/src/core/compact_block.rs`): a header, a nonce, the
//! coinbase outputs and kernels in full, and short ids for every other
//! kernel. A peer that has the transactions in its pool rebuilds the block.
const std = @import("std");
const ser = @import("ser.zig");
const hash_mod = @import("hash.zig");
const block = @import("block.zig");
const tx_mod = @import("transaction.zig");
const shortid = @import("shortid.zig");

const Hash = hash_mod.Hash;
const Output = tx_mod.Output;
const Input = tx_mod.Input;
const TxKernel = tx_mod.TxKernel;
const Transaction = tx_mod.Transaction;
const ShortId = shortid.ShortId;
const Block = block.Block;

pub const Error = tx_mod.Error;

pub const CompactBlock = struct {
    header: block.BlockHeader,
    nonce: u64,
    /// The coinbase outputs, in full.
    out_full: []Output,
    /// The coinbase kernels, in full.
    kern_full: []TxKernel,
    /// Short ids of all other kernels.
    kern_ids: []ShortId,

    pub fn deinit(self: *CompactBlock, gpa: std.mem.Allocator) void {
        gpa.free(self.out_full);
        gpa.free(self.kern_full);
        gpa.free(self.kern_ids);
    }

    /// The hash of a compact block is its header's (hash mode skips the rest).
    pub fn hash(self: CompactBlock) Hash {
        return self.header.hash();
    }

    pub fn write(self: CompactBlock, w: anytype) ser.Error!void {
        try self.header.write(w);
        if (w.mode != .hash) {
            try ser.writeU64(w, self.nonce);
            try ser.writeU64(w, self.out_full.len);
            try ser.writeU64(w, self.kern_full.len);
            try ser.writeU64(w, self.kern_ids.len);
            for (self.out_full) |o| try o.write(w);
            for (self.kern_full) |k| try k.write(w);
            for (self.kern_ids) |i| try i.write(w);
        }
    }

    /// Reads and checks that each list is sorted and free of duplicates.
    pub fn read(r: *ser.Reader) ser.Error!CompactBlock {
        const header = try block.BlockHeader.read(r);
        const nonce = try r.readU64();
        const n_out = try r.readU64();
        const n_kern = try r.readU64();
        const n_ids = try r.readU64();
        const out_full = try ser.readMulti(Output, r, n_out);
        errdefer r.gpa.free(out_full);
        const kern_full = try ser.readMulti(TxKernel, r, n_kern);
        errdefer r.gpa.free(kern_full);
        const kern_ids = try ser.readMulti(ShortId, r, n_ids);
        errdefer r.gpa.free(kern_ids);
        tx_mod.verifySortedAndUnique(Output, r.gpa, out_full) catch return error.CorruptedData;
        tx_mod.verifySortedAndUnique(TxKernel, r.gpa, kern_full) catch return error.CorruptedData;
        tx_mod.verifySortedAndUnique(ShortId, r.gpa, kern_ids) catch return error.CorruptedData;
        return .{ .header = header, .nonce = nonce, .out_full = out_full, .kern_full = kern_full, .kern_ids = kern_ids };
    }

    /// Builds the compact form of `b` with the given connection nonce.
    pub fn fromBlock(gpa: std.mem.Allocator, b: Block, nonce: u64) std.mem.Allocator.Error!CompactBlock {
        const bh = b.header.hash();
        var outs: std.ArrayList(Output) = .empty;
        errdefer outs.deinit(gpa);
        for (b.body.outputs) |o| if (o.isCoinbase()) try outs.append(gpa, o);
        var kerns: std.ArrayList(TxKernel) = .empty;
        errdefer kerns.deinit(gpa);
        var ids: std.ArrayList(ShortId) = .empty;
        errdefer ids.deinit(gpa);
        for (b.body.kernels) |k| {
            if (k.isCoinbase()) try kerns.append(gpa, k) else try ids.append(gpa, shortid.shortId(k.hash(), bh, nonce));
        }
        try tx_mod.sortByHash(Output, gpa, outs.items);
        try tx_mod.sortByHash(TxKernel, gpa, kerns.items);
        try shortid.sort(gpa, ids.items);
        const o = try outs.toOwnedSlice(gpa);
        errdefer gpa.free(o);
        const k = try kerns.toOwnedSlice(gpa);
        errdefer gpa.free(k);
        return .{ .header = b.header, .nonce = nonce, .out_full = o, .kern_full = k, .kern_ids = try ids.toOwnedSlice(gpa) };
    }
};

fn appendUnique(comptime T: type, gpa: std.mem.Allocator, list: *std.ArrayList(T), seen: *std.AutoHashMap([32]u8, void), item: T) !void {
    const gop = try seen.getOrPut(item.hash().bytes);
    if (!gop.found_existing) try list.append(gpa, item);
}

/// Rebuilds a block from a compact block and the transactions that carry its
/// other kernels (`hydrate_from`). Doesn't validate; the caller must.
pub fn hydrate(gpa: std.mem.Allocator, cb: CompactBlock, txs: []const Transaction) Error!Block {
    var inputs: std.ArrayList(Input) = .empty;
    errdefer inputs.deinit(gpa);
    var outputs: std.ArrayList(Output) = .empty;
    errdefer outputs.deinit(gpa);
    var kernels: std.ArrayList(TxKernel) = .empty;
    errdefer kernels.deinit(gpa);
    var seen_in = std.AutoHashMap([32]u8, void).init(gpa);
    defer seen_in.deinit();
    var seen_out = std.AutoHashMap([32]u8, void).init(gpa);
    defer seen_out.deinit();
    var seen_k = std.AutoHashMap([32]u8, void).init(gpa);
    defer seen_k.deinit();

    for (txs) |t| {
        for (t.body.inputs) |i| try appendUnique(Input, gpa, &inputs, &seen_in, i);
        for (t.body.outputs) |o| try appendUnique(Output, gpa, &outputs, &seen_out, o);
        for (t.body.kernels) |k| try appendUnique(TxKernel, gpa, &kernels, &seen_k, k);
    }
    for (cb.out_full) |o| try appendUnique(Output, gpa, &outputs, &seen_out, o);
    for (cb.kern_full) |k| try appendUnique(TxKernel, gpa, &kernels, &seen_k, k);

    try tx_mod.cutThrough(gpa, &inputs, &outputs);
    try tx_mod.sortByHash(TxKernel, gpa, kernels.items);
    const ins = try inputs.toOwnedSlice(gpa);
    errdefer gpa.free(ins);
    const outs = try outputs.toOwnedSlice(gpa);
    errdefer gpa.free(outs);
    return .{ .header = cb.header, .body = .{ .inputs = ins, .outputs = outs, .kernels = try kernels.toOwnedSlice(gpa) } };
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "compact block round trip and hydration from real blocks" {
    const gpa = testing.allocator;
    const io = testing.io;
    var dir = std.Io.Dir.cwd().openDir(io, "testdata", .{ .iterate = true }) catch return error.SkipZigTest;
    defer dir.close(io);
    var it = dir.iterate();
    var checked: usize = 0;
    while (try it.next(io)) |e| {
        if (!std.mem.startsWith(u8, e.name, "block_")) continue;
        const bytes = @import("fsutil.zig").readAll(gpa, io, dir, e.name) catch continue;
        defer gpa.free(bytes);
        var r = ser.Reader.init(gpa, bytes, ser.ProtocolVersion.local());
        r.params = block_params;
        var b = try Block.read(&r);
        defer b.deinit(gpa);

        var cb = try CompactBlock.fromBlock(gpa, b, 0x1234_5678_9abc);
        defer cb.deinit(gpa);
        try testing.expect(cb.hash().eql(b.hash()));
        try testing.expectEqual(b.body.kernels.len, cb.kern_full.len + cb.kern_ids.len);

        // wire round trip
        const wire = try ser.serVec(gpa, cb, ser.ProtocolVersion.local());
        defer gpa.free(wire);
        var r2 = ser.Reader.init(gpa, wire, ser.ProtocolVersion.local());
        r2.params = block_params;
        var back = try CompactBlock.read(&r2);
        defer back.deinit(gpa);
        try testing.expectEqual(cb.kern_ids.len, back.kern_ids.len);
        try testing.expect(back.hash().eql(cb.hash()));

        // the transaction carrying everything that isn't coinbase
        var ins: std.ArrayList(Input) = .empty;
        defer ins.deinit(gpa);
        var outs: std.ArrayList(Output) = .empty;
        defer outs.deinit(gpa);
        var kerns: std.ArrayList(TxKernel) = .empty;
        defer kerns.deinit(gpa);
        for (b.body.inputs) |x| try ins.append(gpa, x);
        for (b.body.outputs) |x| if (!x.isCoinbase()) try outs.append(gpa, x);
        for (b.body.kernels) |x| if (!x.isCoinbase()) try kerns.append(gpa, x);
        const t: Transaction = .{ .offset = tx_mod.BlindingFactor.zero, .body = .{ .inputs = ins.items, .outputs = outs.items, .kernels = kerns.items } };

        var rebuilt = try hydrate(gpa, cb, &.{t});
        defer rebuilt.deinit(gpa);
        try testing.expect(rebuilt.hash().eql(b.hash()));
        try testing.expectEqual(b.body.inputs.len, rebuilt.body.inputs.len);
        try testing.expectEqual(b.body.outputs.len, rebuilt.body.outputs.len);
        for (b.body.outputs, rebuilt.body.outputs) |x, y| try testing.expect(x.hash().eql(y.hash()));
        for (b.body.kernels, rebuilt.body.kernels) |x, y| try testing.expect(x.hash().eql(y.hash()));
        for (b.body.inputs, rebuilt.body.inputs) |x, y| try testing.expect(x.hash().eql(y.hash()));
        checked += 1;
    }
    if (checked == 0) return error.SkipZigTest;
}

const block_params = @import("consensus.zig").ChainType.readParams(.mainnet);
