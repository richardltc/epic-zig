//! Dev tool: connects to a node over P2P and checks our code against real
//! chain data, saving raw headers/blocks as test fixtures.
//!
//!   zig build fetch -- [host:port] [out_dir] [tip_blocks]
//!
//! 1. headers from genesis: every header must link to *our* computed hash of
//!    its predecessor (validates header hashing on real data);
//! 2. hops to the chain tip with fast-sync offsets, saving each 512-header
//!    window and verifying proof-of-work (Cuckoo / RandomX / ProgPoW) on it;
//! 3. requests the newest blocks by our computed hashes (a node answers only
//!    if the hash is right) and fully parses them.
const std = @import("std");
const Io = std.Io;
const epic = @import("epic");

const Hash = epic.hash.Hash;
const BlockHeader = epic.block.BlockHeader;

var stats = struct {
    ok: [4]usize = .{ 0, 0, 0, 0 },
    bad: [4]usize = .{ 0, 0, 0, 0 },
}{};

fn checkPow(v: *epic.pow.Verifier, h: BlockHeader) void {
    const idx = h.pow.proof.powType().idx();
    if (v.verifySize(h)) |_| {
        stats.ok[idx] += 1;
    } else |e| {
        stats.bad[idx] += 1;
        if (stats.bad[idx] <= 3) std.debug.print("    PoW FAIL height {d} ({s}): {s}\n", .{ h.height, @tagName(h.pow.proof.powType()), @errorName(e) });
    }
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    const target = if (args.len > 1) args[1] else "127.0.0.1:3414";
    const out_dir = if (args.len > 2) args[2] else "testdata";
    const tip_blocks: usize = if (args.len > 3) try std.fmt.parseInt(usize, args[3], 10) else 5;

    const colon = std.mem.lastIndexOfScalar(u8, target, ':') orelse return error.BadAddress;
    const addr = try Io.net.IpAddress.parse(target[0..colon], try std.fmt.parseInt(u16, target[colon + 1 ..], 10));

    const chain: epic.consensus.ChainType = .mainnet;
    const genesis = epic.block.genesisMain();
    const genesis_hash = genesis.hash();

    var out = try Io.Dir.cwd().createDirPathOpen(io, out_dir, .{});
    defer out.close(io);

    var verifier = epic.pow.Verifier.init(gpa, io);
    defer verifier.deinit();

    std.debug.print("connecting to {s} ...\n", .{target});
    const conn = try epic.p2p_client.Conn.connect(gpa, io, addr, chain, genesis_hash, genesis.header.pow.total_difficulty);
    defer conn.close();
    std.debug.print("connected: agent \"{s}\", protocol v{d}, caps 0x{x}\n", .{ conn.peer.userAgent(), conn.peer.version.v, conn.peer.capabilities.bits });

    // ---- 1. first window from genesis, with the hash-link check
    var first: []BlockHeader = undefined;
    {
        try conn.send(.get_headers, epic.p2p_msg.Locator{ .hashes = &.{genesis_hash} });
        const m = try conn.recvType(.headers);
        defer m.deinit(gpa);
        var r = conn.readerFor(m.body);
        const hs = try epic.p2p_msg.Headers.read(&r);
        first = hs.headers;
        var prev = genesis_hash;
        for (first) |h| {
            if (!h.prev_hash.eql(prev)) {
                std.debug.print("LINK MISMATCH at height {d}\n", .{h.height});
                return error.HashMismatch;
            }
            prev = h.hash();
        }
        try out.writeFile(io, .{ .sub_path = "headers_genesis.bin", .data = m.body });
        std.debug.print("headers 1..{d}: hash chain verified on real data\n", .{first.len});
        for (first) |h| checkPow(&verifier, h);
    }

    // ---- 2. hop to the tip with fast-sync offsets
    var loc: Hash = first[first.len - 1].hash();
    var loc_height: u64 = first[first.len - 1].height;
    var last_window: []BlockHeader = first;
    var hops: usize = 0;
    while (true) {
        // largest offset that still returns headers
        var off: i32 = 255;
        var window: ?[]BlockHeader = null;
        var body_copy: ?[]u8 = null;
        while (off >= 0) : (off = if (off == 0) -1 else @divTrunc(off, 2)) {
            try conn.send(.get_headers_fast_sync, epic.p2p_msg.LocatorFastSync{ .hashes = &.{loc}, .offset = @intCast(off) });
            const m = try conn.recvType(.fast_headers);
            defer m.deinit(gpa);
            var r = conn.readerFor(m.body);
            const hs = try epic.p2p_msg.Headers.read(&r);
            if (hs.headers.len > 0) {
                window = hs.headers;
                body_copy = try arena.dupe(u8, m.body);
                break;
            }
            gpa.free(hs.headers);
        }
        const w = window orelse break;
        hops += 1;
        var name: [48]u8 = undefined;
        try out.writeFile(io, .{ .sub_path = try std.fmt.bufPrint(&name, "headers_h{d:0>7}.bin", .{w[0].height}), .data = body_copy.? });
        std.debug.print("hop {d}: heights {d}..{d} ({d} headers)\n", .{ hops, w[0].height, w[w.len - 1].height, w.len });
        for (w) |h| checkPow(&verifier, h);
        last_window = w;
        loc = w[w.len - 1].hash();
        loc_height = w[w.len - 1].height;
        if (w.len < 512 and off == 0) break;
    }
    std.debug.print("tip reached at height ~{d}\n", .{loc_height});
    std.debug.print("PoW verified on real headers: cuckaroo {d}/{d}, cuckatoo {d}/{d}, randomx {d}/{d}, progpow {d}/{d} (ok/failed)\n", .{
        stats.ok[0], stats.bad[0], stats.ok[1], stats.bad[1], stats.ok[2], stats.bad[2], stats.ok[3], stats.bad[3],
    });

    // ---- 3. newest blocks by our computed hash
    const n = @min(tip_blocks, last_window.len);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const hdr = last_window[last_window.len - 1 - i];
        const want = hdr.hash();
        try conn.send(.get_block, epic.p2p_msg.HashMsg{ .hash = want });
        const m = try conn.recvType(.block);
        defer m.deinit(gpa);
        var r = conn.readerFor(m.body);
        var blk = try epic.block.Block.read(&r);
        defer blk.deinit(gpa);
        if (!blk.hash().eql(want)) return error.BlockHashMismatch;
        var name: [48]u8 = undefined;
        try out.writeFile(io, .{ .sub_path = try std.fmt.bufPrint(&name, "block_{d:0>7}.bin", .{hdr.height}), .data = m.body });
        std.debug.print("block {d}: {d} in / {d} out / {d} kernels, hash {f} OK\n", .{ hdr.height, blk.body.inputs.len, blk.body.outputs.len, blk.body.kernels.len, want });
    }
}
