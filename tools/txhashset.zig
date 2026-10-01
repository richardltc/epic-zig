//! Dev tool: downloads a real txhashset archive from a node, extracts it, and
//! checks that our MMR roots equal the roots in the real block header.
//!
//!   zig build txhashset -- [host:port] [out_dir]
const std = @import("std");
const Io = std.Io;
const epic = @import("epic");

const BlockHeader = epic.block.BlockHeader;
const Hash = epic.hash.Hash;

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    const target = if (args.len > 1) args[1] else "127.0.0.1:3414";
    const out_path = if (args.len > 2) args[2] else "local";

    const colon = std.mem.lastIndexOfScalar(u8, target, ':') orelse return error.BadAddress;
    const addr = try Io.net.IpAddress.parse(target[0..colon], try std.fmt.parseInt(u16, target[colon + 1 ..], 10));
    const chain: epic.consensus.ChainType = .mainnet;
    const genesis = epic.block.genesisMain();
    const genesis_hash = genesis.hash();

    var out = try Io.Dir.cwd().createDirPathOpen(io, out_path, .{});
    defer out.close(io);

    const conn = try epic.p2p_client.Conn.connect(gpa, io, addr, chain, genesis_hash, genesis.header.pow.total_difficulty);
    defer conn.close();
    std.debug.print("connected to \"{s}\"\n", .{conn.peer.userAgent()});

    // `--reuse <height>`: use the archive already extracted under <out>/txhashset
    const reuse = args.len > 4 and std.mem.eql(u8, args[3], "--reuse");
    var arch: epic.p2p_msg.TxHashSetArchive = undefined;
    if (reuse) {
        arch = .{ .hash = Hash.zero, .height = try std.fmt.parseInt(u64, args[4], 10), .bytes = 0 };
    } else {
        // ---- 1. download the archive
        try conn.send(.tx_hash_set_request, epic.p2p_msg.TxHashSetRequest{ .hash = Hash.zero, .height = 0 });
        const m = try conn.recvType(.tx_hash_set_archive);
        defer m.deinit(gpa);
        var rr = conn.readerFor(m.body);
        arch = try epic.p2p_msg.TxHashSetArchive.read(&rr);
    }
    std.debug.print("archive at height {d}, hash {f}, {d} bytes\n", .{ arch.height, arch.hash, arch.bytes });

    if (!reuse) {
        var zf = try out.createFile(io, "txhashset.zip", .{});
        defer zf.close(io);
        var buf: [1 << 16]u8 = undefined;
        var remaining: u64 = arch.bytes;
        var off: u64 = 0;
        var last_print: u64 = 0;
        while (remaining > 0) {
            const n: usize = @intCast(@min(remaining, buf.len));
            try conn.reader.interface.readSliceAll(buf[0..n]);
            try zf.writePositionalAll(io, buf[0..n], off);
            off += n;
            remaining -= n;
            if (off - last_print > (32 << 20)) {
                std.debug.print("  downloaded {d} MiB\n", .{off >> 20});
                last_print = off;
            }
        }
        std.debug.print("download complete: {d} bytes\n", .{off});
    }

    // ---- 2. extract
    if (!reuse) out.deleteTree(io, "txhashset") catch {};
    var th_dir = try out.createDirPathOpen(io, "txhashset", .{});
    defer th_dir.close(io);
    if (!reuse) {
        var zf = try out.openFile(io, "txhashset.zip", .{});
        defer zf.close(io);
        var rbuf: [4096]u8 = undefined;
        var fr = zf.reader(io, &rbuf);
        try std.zip.extract(th_dir, &fr, .{});
    }
    std.debug.print("extracted\n", .{});

    // ---- 3. find the real header for the archive by hopping headers from genesis
    var loc: Hash = genesis_hash;
    var loc_height: u64 = 0;
    var header: ?BlockHeader = null;
    while (header == null) {
        const remaining_h = arch.height - loc_height;
        const off: u8 = if (remaining_h > 512 * 256) 255 else @intCast((remaining_h - 1) / 512);
        try conn.send(.get_headers_fast_sync, epic.p2p_msg.LocatorFastSync{ .hashes = &.{loc}, .offset = off });
        const hm = try conn.recvType(.fast_headers);
        defer hm.deinit(gpa);
        var r = conn.readerFor(hm.body);
        const hs = try epic.p2p_msg.Headers.read(&r);
        if (hs.headers.len == 0) return error.NoHeaders;
        for (hs.headers) |h| {
            if (h.height == arch.height) header = h;
        }
        const last = hs.headers[hs.headers.len - 1];
        loc = last.hash();
        loc_height = last.height;
    }
    const hdr = header.?;
    std.debug.print("archive header found: height {d}, hash {f}\n", .{ hdr.height, hdr.hash() });

    // ---- 4. open the txhashset and compare roots
    var ths = try epic.txhashset.TxHashSet.open(gpa, io, chain, th_dir, epic.chain_types.Tip.fromHeader(hdr), hdr.hash());
    defer ths.close();
    std.debug.print("sizes: output {d}, rproof {d}, kernel {d}  (header says output {d}, kernel {d})\n", .{
        ths.sizes.output, ths.sizes.rproof, ths.sizes.kernel, hdr.output_mmr_size, hdr.kernel_mmr_size,
    });
    try ths.rewindToHeaderSizes(hdr);
    std.debug.print("rewound to the header's sizes: output {d}, kernel {d}\n", .{ ths.sizes.output, ths.sizes.kernel });
    try ths.validateSizes(hdr);
    std.debug.print("sizes match the header\n", .{});
    const roots = try ths.roots(hdr.version >= 7);
    std.debug.print("output root  ours {f} / header {f}\n", .{ roots.outputRoot(hdr), hdr.output_root });
    std.debug.print("rproof root  ours {f} / header {f}\n", .{ roots.rproof_root, hdr.range_proof_root });
    std.debug.print("kernel root  ours {f} / header {f}\n", .{ roots.kernel_root, hdr.kernel_root });
    try roots.validate(hdr);
    std.debug.print("ROOTS MATCH THE REAL HEADER\n", .{});

    try ths.verifyRangeproofs();
    std.debug.print("RANGEPROOFS OK\n", .{});

    // ---- 5. build the output position index from the real unspent set
    const db_path = try std.fmt.allocPrint(arena, "{s}/db", .{out_path});
    Io.Dir.cwd().deleteTree(io, db_path) catch {};
    var db = try epic.chain_db.Db.open(gpa, io, db_path, chain, .{});
    defer db.close();
    {
        var batch = db.batch();
        var it = ths.unspentOutputPositions();
        var n: u64 = 0;
        while (it.next()) |pos| {
            const oid = ths.outputAt(pos) orelse continue;
            try db.saveOutputPosHeight(&batch, oid.commit, pos, 0);
            n += 1;
            if (n % 200_000 == 0) {
                try batch.commit();
                batch = db.batch();
            }
        }
        try batch.commit();
        std.debug.print("indexed {d} unspent outputs\n", .{n});
    }

    // ---- 6. running sums at the archive header
    std.debug.print("computing utxo/kernel sums over the whole set ...\n", .{});
    var sums = try ths.validateKernelSums(genesis.header, hdr);
    std.debug.print("KERNEL SUMS VERIFY at the archive header (utxo + overage == kernels + offset)\n", .{});

    // ---- 7. replay every real block up to the tip
    var headers: std.ArrayList(BlockHeader) = .empty;
    {
        var loc2 = hdr.hash();
        while (true) {
            try conn.send(.get_headers, epic.p2p_msg.Locator{ .hashes = &.{loc2} });
            const hm = try conn.recvType(.headers);
            defer hm.deinit(gpa);
            var r = conn.readerFor(hm.body);
            const hs = try epic.p2p_msg.Headers.read(&r);
            defer gpa.free(hs.headers);
            if (hs.headers.len == 0) break;
            try headers.appendSlice(arena, hs.headers);
            loc2 = hs.headers[hs.headers.len - 1].hash();
            if (hs.headers.len < 512) break;
        }
    }
    std.debug.print("{d} headers after the archive (up to height {d})\n", .{ headers.items.len, if (headers.items.len > 0) headers.items[headers.items.len - 1].height else hdr.height });

    const foundation = epic.block.Foundation.embedded(chain);
    var prev = hdr;
    var applied: usize = 0;
    var foundation_blocks: usize = 0;
    var batch = db.batch();
    defer batch.deinit();
    for (headers.items) |h| {
        try conn.send(.get_block, epic.p2p_msg.HashMsg{ .hash = h.hash() });
        const bm = try conn.recvType(.block);
        defer bm.deinit(gpa);
        var r = conn.readerFor(bm.body);
        var blk = try epic.block.Block.read(&r);
        defer blk.deinit(gpa);
        if (!blk.hash().eql(h.hash())) return error.BlockHashMismatch;

        // full block validation, then running sums, then apply + roots
        _ = try blk.validate(gpa, chain, &foundation, prev.total_kernel_offset);
        sums = try epic.chain_types.verifyBlockSums(gpa, sums, blk, chain);
        const spent = try ths.applyBlock(&db, &batch, blk);
        gpa.free(spent);
        try ths.validateRoots(blk.header);
        try ths.validateSizes(blk.header);
        if (epic.consensus.isFoundationHeight(chain, h.height)) foundation_blocks += 1;
        prev = blk.header;
        applied += 1;
        if (applied % 500 == 0) std.debug.print("  applied {d} blocks (height {d})\n", .{ applied, h.height });
    }
    std.debug.print("REPLAYED {d} REAL BLOCKS: full validation, kernel sums, and MMR roots/sizes all match ({d} foundation-levy block(s))\n", .{ applied, foundation_blocks });
}
