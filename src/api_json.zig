//! JSON forms of chain types for the node API (`api/src/types.rs` and the
//! serde derives on the core types), written by hand to match the reference's
//! field names, order and formats exactly.
const std = @import("std");
const Writer = std.Io.Writer;
const block = @import("block.zig");
const tx_mod = @import("transaction.zig");
const crypto = @import("crypto.zig");
const hash_mod = @import("hash.zig");
const pow_types = @import("pow_types.zig");
const chain_types = @import("chain_types.zig");

const Hash = hash_mod.Hash;
const Commitment = crypto.Commitment;

pub fn hex(w: *Writer, bytes: []const u8) Writer.Error!void {
    try w.print("\"{x}\"", .{bytes});
}

pub fn writeHash(w: *Writer, h: Hash) Writer.Error!void {
    try hex(w, &h.bytes);
}

/// chrono's `to_rfc3339()` for a UTC timestamp: `2019-01-15T18:31:00+00:00`.
pub fn rfc3339(w: *Writer, secs: i64) Writer.Error!void {
    const days = @divFloor(secs, 86400);
    const rem: u64 = @intCast(secs - days * 86400);
    // civil from days (Howard Hinnant)
    const z = days + 719468;
    const era = @divFloor(z, 146097);
    const doe: u64 = @intCast(z - era * 146097);
    const yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const y: i64 = @as(i64, @intCast(yoe)) + era * 400;
    const doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const mp = (5 * doy + 2) / 153;
    const d = doy - (153 * mp + 2) / 5 + 1;
    const m: u64 = if (mp < 10) mp + 3 else mp - 9;
    const year: u64 = @intCast(if (m <= 2) y + 1 else y);
    try w.print("\"{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}+00:00\"", .{ year, m, d, rem / 3600, (rem % 3600) / 60, rem % 60 });
}

/// `HashMap<PoWType, u64>` as a JSON object (only the algorithms present).
pub fn difficulty(w: *Writer, d: pow_types.Difficulty) Writer.Error!void {
    try w.writeAll("{");
    var first = true;
    for (pow_types.PoWType.all) |p| {
        if (d.num[p.idx()]) |v| {
            if (!first) try w.writeAll(",");
            first = false;
            try w.print("\"{s}\":{d}", .{ @tagName(p), v });
        }
    }
    try w.writeAll("}");
}

pub fn tip(w: *Writer, t: chain_types.Tip) Writer.Error!void {
    try w.print("{{\"height\":{d},\"last_block_pushed\":", .{t.height});
    try writeHash(w, t.last_block_h);
    try w.writeAll(",\"prev_block_to_last\":");
    try writeHash(w, t.prev_block_h);
    try w.writeAll(",\"total_difficulty\":");
    try difficulty(w, t.total_difficulty);
    try w.writeAll("}");
}

/// Decimal form of a 32-byte big-endian integer (`BigUint` Display).
fn bigDecimal(w: *Writer, be: *const [32]u8) Writer.Error!void {
    var limbs: [8]u32 = undefined;
    for (0..8) |i| limbs[i] = std.mem.readInt(u32, be[i * 4 ..][0..4], .big);
    var chunks: [12]u32 = undefined; // 10^9 digits, least significant first
    var n: usize = 0;
    var nonzero = true;
    while (nonzero) {
        var rem: u64 = 0;
        nonzero = false;
        for (&limbs) |*l| {
            const cur = (rem << 32) | l.*;
            l.* = @intCast(cur / 1_000_000_000);
            rem = cur % 1_000_000_000;
            if (l.* != 0) nonzero = true;
        }
        chunks[n] = @intCast(rem);
        n += 1;
    }
    try w.print("{d}", .{chunks[n - 1]});
    var i = n - 1;
    while (i > 0) {
        i -= 1;
        try w.print("{d:0>9}", .{chunks[i]});
    }
}

pub fn headerPrintable(w: *Writer, h: block.BlockHeader) Writer.Error!void {
    try w.writeAll("{\"hash\":");
    try writeHash(w, h.hash());
    try w.print(",\"version\":{d},\"height\":{d},\"previous\":", .{ h.version, h.height });
    try writeHash(w, h.prev_hash);
    try w.writeAll(",\"prev_root\":");
    try writeHash(w, h.prev_root);
    try w.writeAll(",\"timestamp\":");
    try rfc3339(w, h.timestamp);
    try w.writeAll(",\"output_root\":");
    try writeHash(w, h.output_root);
    try w.writeAll(",\"range_proof_root\":");
    try writeHash(w, h.range_proof_root);
    try w.writeAll(",\"kernel_root\":");
    try writeHash(w, h.kernel_root);
    try w.print(",\"nonce\":{d},\"edge_bits\":{d},\"proof\":", .{ h.pow.nonce, h.pow.edgeBits() });
    switch (h.pow.proof) {
        .cuckoo => |c| {
            try w.writeAll("\"Cuckoo\",\"solution\":{\"Cuckoo\":[");
            for (c.nonces[0..c.n], 0..) |n, i| {
                if (i > 0) try w.writeAll(",");
                try w.print("{d}", .{n});
            }
            try w.writeAll("]}");
        },
        .randomx => |r| {
            try w.writeAll("\"RandomX\",\"solution\":{\"RandomX\":\"");
            try bigDecimal(w, &r.hash);
            try w.writeAll("\"}");
        },
        .progpow => |p| {
            try w.writeAll("\"ProgPow\",\"solution\":{\"ProgPow\":[");
            for (p.mix, 0..) |b, i| {
                if (i > 0) try w.writeAll(",");
                try w.print("{d}", .{b});
            }
            try w.writeAll("]}");
        },
    }
    try w.writeAll(",\"total_difficulty\":");
    try difficulty(w, h.pow.total_difficulty);
    try w.print(",\"secondary_scaling\":{d},\"total_kernel_offset\":", .{h.pow.secondary_scaling});
    try hex(w, &h.total_kernel_offset.bytes);
    try w.writeAll("}");
}

pub fn headerInfo(w: *Writer, h: block.BlockHeader) Writer.Error!void {
    try w.writeAll("{\"hash\":");
    try writeHash(w, h.hash());
    try w.print(",\"height\":{d},\"previous\":", .{h.height});
    try writeHash(w, h.prev_hash);
    try w.writeAll("}");
}

fn featuresName(f: tx_mod.KernelFeatures) []const u8 {
    return switch (f) {
        .plain => "Plain",
        .coinbase => "Coinbase",
        .height_locked => "HeightLocked",
    };
}

/// `TxKernelPrintable` (the block API's kernel form).
pub fn kernelPrintable(w: *Writer, k: tx_mod.TxKernel) Writer.Error!void {
    const fee: u64, const lock: u64 = switch (k.features) {
        .plain => |p| .{ p.fee, 0 },
        .coinbase => .{ 0, 0 },
        .height_locked => |h| .{ h.fee, h.lock_height },
    };
    try w.print("{{\"features\":\"{s}\",\"fee\":{d},\"lock_height\":{d},\"excess\":", .{ featuresName(k.features), fee, lock });
    try hex(w, &k.excess.bytes);
    try w.writeAll(",\"excess_sig\":");
    try hex(w, &k.excess_sig.bytes);
    try w.writeAll("}");
}

pub const OutputInfo = struct {
    spent: bool,
    block_height: ?u64,
    mmr_index: u64,
    include_proof: bool,
};

pub fn outputPrintable(w: *Writer, o: tx_mod.Output, info: OutputInfo) Writer.Error!void {
    try w.print("{{\"output_type\":\"{s}\",\"commit\":", .{if (o.isCoinbase()) "Coinbase" else "Transaction"});
    try hex(w, &o.commit.bytes);
    try w.print(",\"spent\":{},\"proof\":", .{info.spent});
    if (info.include_proof) try hex(w, o.proof.asSlice()) else try w.writeAll("null");
    try w.writeAll(",\"proof_hash\":");
    try writeHash(w, hash_mod.hashOf(o.proof));
    try w.writeAll(",\"block_height\":");
    if (info.block_height) |h| try w.print("{d}", .{h}) else try w.writeAll("null");
    try w.print(",\"merkle_proof\":null,\"mmr_index\":{d}}}", .{info.mmr_index});
}

/// The serde form of a `Transaction` (what wallets push).
pub fn transaction(w: *Writer, t: tx_mod.Transaction) Writer.Error!void {
    try w.writeAll("{\"offset\":");
    try hex(w, &t.offset.bytes);
    try w.writeAll(",\"body\":{\"inputs\":[");
    for (t.body.inputs, 0..) |i, n| {
        if (n > 0) try w.writeAll(",");
        try w.print("{{\"features\":\"{s}\",\"commit\":", .{if (i.features == .coinbase) "Coinbase" else "Plain"});
        try hex(w, &i.commit.bytes);
        try w.writeAll("}");
    }
    try w.writeAll("],\"outputs\":[");
    for (t.body.outputs, 0..) |o, n| {
        if (n > 0) try w.writeAll(",");
        try w.print("{{\"features\":\"{s}\",\"commit\":", .{if (o.isCoinbase()) "Coinbase" else "Plain"});
        try hex(w, &o.commit.bytes);
        try w.writeAll(",\"proof\":");
        try hex(w, o.proof.asSlice());
        try w.writeAll("}");
    }
    try w.writeAll("],\"kernels\":[");
    for (t.body.kernels, 0..) |k, n| {
        if (n > 0) try w.writeAll(",");
        try w.writeAll("{\"features\":");
        switch (k.features) {
            .plain => |p| try w.print("{{\"Plain\":{{\"fee\":{d}}}}}", .{p.fee}),
            .coinbase => try w.writeAll("\"Coinbase\""),
            .height_locked => |h| try w.print("{{\"HeightLocked\":{{\"fee\":{d},\"lock_height\":{d}}}}}", .{ h.fee, h.lock_height }),
        }
        try w.writeAll(",\"excess\":");
        try hex(w, &k.excess.bytes);
        try w.writeAll(",\"excess_sig\":");
        try hex(w, &k.excess_sig.bytes);
        try w.writeAll("}");
    }
    try w.writeAll("]}}");
}

// ------------------------------------------------------------- parsing

pub const ParseError = error{BadJson} || std.mem.Allocator.Error;

fn field(v: std.json.Value, name: []const u8) ParseError!std.json.Value {
    if (v != .object) return error.BadJson;
    return v.object.get(name) orelse error.BadJson;
}

fn hexInto(v: std.json.Value, out: []u8) ParseError!void {
    if (v != .string or v.string.len != out.len * 2) return error.BadJson;
    _ = std.fmt.hexToBytes(out, v.string) catch return error.BadJson;
}

fn commitOf(v: std.json.Value) ParseError!Commitment {
    var c: Commitment = undefined;
    try hexInto(v, &c.bytes);
    return c;
}

fn u64Of(v: std.json.Value) ParseError!u64 {
    return switch (v) {
        .integer => |i| if (i >= 0) @intCast(i) else error.BadJson,
        else => error.BadJson,
    };
}

fn kernelFeatures(v: std.json.Value) ParseError!tx_mod.KernelFeatures {
    switch (v) {
        .string => |s| {
            if (std.mem.eql(u8, s, "Coinbase")) return .{ .coinbase = {} };
            return error.BadJson;
        },
        .object => |o| {
            if (o.get("Plain")) |p| return .{ .plain = .{ .fee = try u64Of(try field(p, "fee")) } };
            if (o.get("HeightLocked")) |h| return .{ .height_locked = .{ .fee = try u64Of(try field(h, "fee")), .lock_height = try u64Of(try field(h, "lock_height")) } };
            return error.BadJson;
        },
        else => return error.BadJson,
    }
}

fn outputFeatures(v: std.json.Value) ParseError!tx_mod.OutputFeatures {
    if (v != .string) return error.BadJson;
    if (std.mem.eql(u8, v.string, "Plain")) return .plain;
    if (std.mem.eql(u8, v.string, "Coinbase")) return .coinbase;
    return error.BadJson;
}

/// Builds a transaction from its serde JSON form. The body slices are newly
/// allocated (free with `Transaction.deinit`); they are sorted as given by the
/// sender, and validation (`validateRead`) rejects unsorted bodies.
pub fn parseTransaction(gpa: std.mem.Allocator, v: std.json.Value) ParseError!tx_mod.Transaction {
    var offset: tx_mod.BlindingFactor = undefined;
    try hexInto(try field(v, "offset"), &offset.bytes);
    const body = try field(v, "body");
    const ins_j = try field(body, "inputs");
    const outs_j = try field(body, "outputs");
    const kerns_j = try field(body, "kernels");
    if (ins_j != .array or outs_j != .array or kerns_j != .array) return error.BadJson;

    const inputs = try gpa.alloc(tx_mod.Input, ins_j.array.items.len);
    errdefer gpa.free(inputs);
    for (ins_j.array.items, 0..) |x, i| inputs[i] = .{ .features = try outputFeatures(try field(x, "features")), .commit = try commitOf(try field(x, "commit")) };

    const outputs = try gpa.alloc(tx_mod.Output, outs_j.array.items.len);
    errdefer gpa.free(outputs);
    for (outs_j.array.items, 0..) |x, i| {
        const pj = try field(x, "proof");
        if (pj != .string or pj.string.len % 2 != 0 or pj.string.len / 2 > crypto.MAX_PROOF_SIZE) return error.BadJson;
        var proof = crypto.RangeProof.zero;
        _ = std.fmt.hexToBytes(proof.proof[0..pj.string.len / 2], pj.string) catch return error.BadJson;
        proof.plen = pj.string.len / 2;
        outputs[i] = .{ .features = try outputFeatures(try field(x, "features")), .commit = try commitOf(try field(x, "commit")), .proof = proof };
    }

    const kernels = try gpa.alloc(tx_mod.TxKernel, kerns_j.array.items.len);
    errdefer gpa.free(kernels);
    for (kerns_j.array.items, 0..) |x, i| {
        var k = tx_mod.TxKernel.withFeatures(try kernelFeatures(try field(x, "features")));
        k.excess = try commitOf(try field(x, "excess"));
        try hexInto(try field(x, "excess_sig"), &k.excess_sig.bytes);
        kernels[i] = k;
    }
    return .{ .offset = offset, .body = .{ .inputs = inputs, .outputs = outputs, .kernels = kernels } };
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "rfc3339 and big decimal" {
    var buf: [128]u8 = undefined;
    var w = Writer.fixed(&buf);
    try rfc3339(&w, 1547577060);
    try testing.expectEqualStrings("\"2019-01-15T18:31:00+00:00\"", w.buffered());
    var w2 = Writer.fixed(&buf);
    var be = [_]u8{0} ** 32;
    be[31] = 0xff;
    be[30] = 0x01; // 511
    try bigDecimal(&w2, &be);
    try testing.expectEqualStrings("511", w2.buffered());
    var w3 = Writer.fixed(&buf);
    be = [_]u8{0xff} ** 32; // 2^256 - 1
    try bigDecimal(&w3, &be);
    try testing.expectEqualStrings("115792089237316195423570985008687907853269984665640564039457584007913129639935", w3.buffered());
}

test "transaction json round trip" {
    const gpa = testing.allocator;
    var t = try tx_mod.testTx(gpa, 100, 3, 90, 10, 10, 1);
    defer t.deinit(gpa);
    var aw: Writer.Allocating = .init(gpa);
    defer aw.deinit();
    try transaction(&aw.writer, t);
    var parsed = try std.json.parseFromSlice(std.json.Value, gpa, aw.written(), .{});
    defer parsed.deinit();
    var back = try parseTransaction(gpa, parsed.value);
    defer back.deinit(gpa);
    try testing.expect(back.hash().eql(t.hash()));
}
