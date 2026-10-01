//! Tests against real mainnet data captured from a node with `zig build fetch`
//! (headers and blocks under testdata/). They skip if the fixtures are absent.
const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const ser = @import("ser.zig");
const fsutil = @import("fsutil.zig");
const consensus = @import("consensus.zig");
const block = @import("block.zig");
const p2p_msg = @import("p2p_msg.zig");
const tx = @import("transaction.zig");
const pmmr = @import("pmmr.zig");
const hash_mod = @import("hash.zig");

const chain: consensus.ChainType = .mainnet;
const Hash = hash_mod.Hash;

fn readerFor(gpa: std.mem.Allocator, bytes: []const u8) ser.Reader {
    var r = ser.Reader.init(gpa, bytes, ser.ProtocolVersion.local());
    r.params = chain.readParams();
    return r;
}

const Fixtures = struct {
    gpa: std.mem.Allocator,
    headers: std.AutoHashMapUnmanaged([32]u8, block.BlockHeader) = .empty,
    windows: std.ArrayList([]block.BlockHeader) = .empty,
    blocks: std.ArrayList(block.Block) = .empty,

    fn load(gpa: std.mem.Allocator, io: Io) !Fixtures {
        var self: Fixtures = .{ .gpa = gpa };
        errdefer self.deinit();
        var dir = Io.Dir.cwd().openDir(io, "testdata", .{ .iterate = true }) catch return error.SkipZigTest;
        defer dir.close(io);
        var it = dir.iterate();
        while (try it.next(io)) |e| {
            const bytes = fsutil.readAll(gpa, io, dir, e.name) catch continue;
            defer gpa.free(bytes);
            var r = readerFor(gpa, bytes);
            if (std.mem.startsWith(u8, e.name, "headers_")) {
                const hs = try p2p_msg.Headers.read(&r);
                try self.windows.append(gpa, hs.headers);
                for (hs.headers) |h| try self.headers.put(gpa, h.hash().bytes, h);
            } else if (std.mem.startsWith(u8, e.name, "block_")) {
                try self.blocks.append(gpa, try block.Block.read(&r));
            }
        }
        if (self.blocks.items.len == 0) return error.SkipZigTest;
        return self;
    }

    fn deinit(self: *Fixtures) void {
        self.headers.deinit(self.gpa);
        for (self.windows.items) |w| self.gpa.free(w);
        self.windows.deinit(self.gpa);
        for (self.blocks.items) |*b| b.deinit(self.gpa);
        self.blocks.deinit(self.gpa);
    }

    fn header(self: *const Fixtures, h: Hash) ?block.BlockHeader {
        return self.headers.get(h.bytes);
    }
};

test "real tip blocks: full validation (range proofs, signatures, coinbase, kernel sums)" {
    const gpa = testing.allocator;
    var fx = try Fixtures.load(gpa, testing.io);
    defer fx.deinit();
    const foundation = block.Foundation.embedded(chain);

    var validated: usize = 0;
    for (fx.blocks.items) |b| {
        const prev = fx.header(b.header.prev_hash) orelse continue;
        // structural checks then the full ones
        try b.validateRead(gpa, chain);
        const kernel_sum = try b.validate(gpa, chain, &foundation, prev.total_kernel_offset);
        _ = kernel_sum;
        // the block's own header and the body agree with what the node sent
        try testing.expect(b.header.hash().eql(b.hash()));
        validated += 1;
        std.debug.print("  block {d} validated: {d} in / {d} out / {d} kernels, {d} epic fees\n", .{
            b.header.height, b.body.inputs.len, b.body.outputs.len, b.body.kernels.len, b.totalFees(),
        });
    }
    try testing.expect(validated > 0);
}

test "real blocks: tampering is detected" {
    const gpa = testing.allocator;
    var fx = try Fixtures.load(gpa, testing.io);
    defer fx.deinit();
    const foundation = block.Foundation.embedded(chain);
    const b = fx.blocks.items[0];
    const prev = fx.header(b.header.prev_hash) orelse return error.SkipZigTest;

    // wrong previous kernel offset breaks the kernel sums
    var bad_offset = prev.total_kernel_offset;
    bad_offset.bytes[31] ^= 1;
    try testing.expect(std.meta.isError(b.validate(gpa, chain, &foundation, bad_offset)));

    // a flipped byte in a kernel signature fails signature verification
    const kernels = try gpa.dupe(tx.TxKernel, b.body.kernels);
    defer gpa.free(kernels);
    kernels[0].excess_sig.bytes[10] ^= 0xff;
    var tampered = b;
    tampered.body.kernels = kernels;
    try testing.expect(std.meta.isError(tampered.validate(gpa, chain, &foundation, prev.total_kernel_offset)));
}

test "real headers: seed header, algorithm scheduling and bottles follow the rules" {
    const gpa = testing.allocator;
    var fx = try Fixtures.load(gpa, testing.io);
    defer fx.deinit();
    const feijoada = @import("feijoada.zig");

    var checked: usize = 0;
    for (fx.windows.items) |w| {
        var i: usize = 1;
        while (i < w.len) : (i += 1) {
            const h = w[i];
            const prev = w[i - 1];
            if (!h.prev_hash.eql(prev.hash())) continue; // window boundary
            // policy in force for that height and the bottles chain forward
            try testing.expectEqual(consensus.emittedPolicy(h.height), h.policy);
            const r = try consensus.nextPolicy(consensus.default_policy_config, h.policy, prev.bottles);
            const algo = h.pow.proof.powType();
            // the reference maps Cuckoo edge_bits 29 to Cuckaroo, everything else to Cuckatoo
            const expected_algo: @import("pow_types.zig").PoWType = switch (h.pow.proof) {
                .cuckoo => |c| if (c.edge_bits == 29) .cuckaroo else .cuckatoo,
                else => algo,
            };
            try testing.expectEqual(r[0], expected_algo);
            try testing.expect(r[1].eql(h.bottles));
            try testing.expect(feijoada.isAllowedPolicy(consensus.default_policy_config.allowed_policies, h.height, h.policy));
            checked += 1;
        }
    }
    std.debug.print("  scheduling/bottles verified on {d} real headers\n", .{checked});
    try testing.expect(checked > 0);
}

test "real headers 1..512 sync through the chain: PoW, era-0 difficulty, seeds, policy and header-MMR roots" {
    const gpa = testing.allocator;
    const io = testing.io;
    var dir = Io.Dir.cwd().openDir(io, "testdata", .{}) catch return error.SkipZigTest;
    defer dir.close(io);
    const bytes = fsutil.readAll(gpa, io, dir, "headers_genesis.bin") catch return error.SkipZigTest;
    defer gpa.free(bytes);
    var r = readerFor(gpa, bytes);
    var hs = try p2p_msg.Headers.read(&r);
    defer hs.deinit(gpa);
    try testing.expect(hs.headers.len > 100);

    const path = ".zig-cache/chaintest/realheaders";
    Io.Dir.cwd().deleteTree(io, path) catch {};
    const c = try @import("chain.zig").Chain.open(gpa, io, path, .{ .kv_options = .{ .block_cache_mb = 16, .write_buffer_mb = 8 } });
    defer c.close();

    try c.syncBlockHeaders(hs.headers, .{});
    const sh = try c.syncHead();
    try testing.expectEqual(hs.headers[hs.headers.len - 1].height, sh.height);
    try testing.expect(sh.last_block_h.eql(hs.headers[hs.headers.len - 1].hash()));
    std.debug.print("  {d} real headers accepted by the full header pipeline\n", .{hs.headers.len});

    // syncing them again is a no-op (already known, no more work)
    try c.syncBlockHeaders(hs.headers, .{});
}

test "measure: algorithm mix near the tip" {
    const gpa = testing.allocator;
    var fx = try Fixtures.load(gpa, testing.io);
    defer fx.deinit();
    var best: ?[]block.BlockHeader = null;
    for (fx.windows.items) |w| {
        if (best == null or w[0].height > best.?[0].height) best = w;
    }
    var counts = [_]usize{0} ** 4;
    for (best.?) |h| counts[h.pow.proof.powType().idx()] += 1;
    std.debug.print("  window at {d}: cuckaroo {d}, cuckatoo {d}, randomx {d}, progpow {d}\n", .{ best.?[0].height, counts[0], counts[1], counts[2], counts[3] });
    for (best.?[0..60]) |h| std.debug.print("{s}", .{@tagName(h.pow.proof.powType())[0..2]});
    std.debug.print("\n", .{});
}
