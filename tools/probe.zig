//! Dev tool: talks to a node like a peer and checks the things a serving node
//! must get right: ping/pong, peer addrs, headers, and compact blocks (parsed
//! from the node and compared against the full block and our own short ids).
//!
//!   zig build probe -- host:port
const std = @import("std");
const Io = std.Io;
const epic = @import("epic");

const Hash = epic.hash.Hash;

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    const target = if (args.len > 1) args[1] else "127.0.0.1:3414";
    const colon = std.mem.lastIndexOfScalar(u8, target, ':') orelse return error.BadAddress;
    const addr = try Io.net.IpAddress.parse(target[0..colon], try std.fmt.parseInt(u16, target[colon + 1 ..], 10));
    const chain: epic.consensus.ChainType = .mainnet;
    const genesis = epic.block.genesisMain();

    const conn = try epic.p2p_client.Conn.connect(gpa, io, addr, chain, genesis.hash(), genesis.header.pow.total_difficulty);
    defer conn.close();
    std.debug.print("connected to \"{s}\" (protocol v{d})\n", .{ conn.peer.userAgent(), conn.peer.version.v });

    // ---- ping
    try conn.send(.ping, epic.p2p_msg.Ping{ .total_difficulty = genesis.header.pow.total_difficulty, .height = 0, .local_timestamp = 0 });
    const pong = try conn.recvType(.pong);
    defer pong.deinit(gpa);
    var pr = conn.readerFor(pong.body);
    const p = try epic.p2p_msg.Pong.read(&pr);
    std.debug.print("pong: height {d}\n", .{p.height});

    // ---- peer addrs
    try conn.send(.get_peer_addrs, epic.p2p_msg.GetPeerAddrs{ .capabilities = .{ .bits = epic.p2p_msg.Capabilities.FULL_NODE } });
    const pa = try conn.recvType(.peer_addrs);
    defer pa.deinit(gpa);
    var par = conn.readerFor(pa.body);
    const addrs = try epic.p2p_msg.PeerAddrs.read(&par);
    defer gpa.free(addrs.peers);
    std.debug.print("peer_addrs: {d} address(es)\n", .{addrs.peers.len});
    for (addrs.peers) |a| switch (a) {
        .v4 => |x| std.debug.print("  {d}.{d}.{d}.{d}:{d}\n", .{ x.ip[0], x.ip[1], x.ip[2], x.ip[3], x.port }),
        .v6 => |x| std.debug.print("  [v6] port {d}\n", .{x.port}),
    };

    // ---- find the header a few blocks below the tip by hopping from genesis
    const want_height = p.height - 3;
    var loc: Hash = genesis.hash();
    var loc_height: u64 = 0;
    var header: ?epic.block.BlockHeader = null;
    var window: []epic.block.BlockHeader = &.{};
    defer gpa.free(window);
    while (header == null) {
        const remaining = want_height - loc_height;
        const off: u8 = if (remaining > 512 * 256) 255 else @intCast((remaining - 1) / 512);
        try conn.send(.get_headers_fast_sync, epic.p2p_msg.LocatorFastSync{ .hashes = &.{loc}, .offset = off });
        const hm = try conn.recvType(.fast_headers);
        defer hm.deinit(gpa);
        var r = conn.readerFor(hm.body);
        var hs = try epic.p2p_msg.Headers.read(&r);
        defer hs.deinit(gpa);
        if (hs.headers.len == 0) return error.NoHeaders;
        for (hs.headers) |h| if (h.height == want_height) {
            header = h;
            window = try gpa.dupe(epic.block.BlockHeader, hs.headers);
        };
        const last = hs.headers[hs.headers.len - 1];
        loc = last.hash();
        loc_height = last.height;
    }
    // prefer a recent block that carries transactions, so the short ids mean something
    var pick: epic.block.BlockHeader = header.?;
    var full: epic.block.Block = undefined;
    var have_full = false;
    var i: usize = window.len;
    var tried: usize = 0;
    while (i > 0 and tried < 300) : (tried += 1) {
        i -= 1;
        const cand = window[i];
        try conn.send(.get_block, epic.p2p_msg.HashMsg{ .hash = cand.hash() });
        const bm = try conn.recvType(.block);
        defer bm.deinit(gpa);
        var br = conn.readerFor(bm.body);
        var b = try epic.block.Block.read(&br);
        if (b.body.kernels.len > 1) {
            pick = cand;
            full = b;
            have_full = true;
            break;
        }
        if (!have_full and cand.height == want_height) {
            full = b;
            pick = cand;
            have_full = true;
            continue;
        }
        b.deinit(gpa);
    }
    defer full.deinit(gpa);
    const hh = pick.hash();
    std.debug.print("using block {d}: {f} ({d} kernels)\n", .{ pick.height, hh, full.body.kernels.len });

    try conn.send(.get_compact_block, epic.p2p_msg.HashMsg{ .hash = hh });
    const cm = try conn.recvType(.compact_block);
    defer cm.deinit(gpa);
    var cr = conn.readerFor(cm.body);
    var cb = try epic.compact_block.CompactBlock.read(&cr);
    defer cb.deinit(gpa);
    std.debug.print("compact block: {d} full outputs, {d} full kernels, {d} kernel ids, nonce {x}\n", .{ cb.out_full.len, cb.kern_full.len, cb.kern_ids.len, cb.nonce });
    if (!cb.hash().eql(hh)) return error.CompactHashMismatch;

    // our short ids for the full block's kernels (same nonce) must be exactly the node's
    var ours: std.ArrayList(epic.shortid.ShortId) = .empty;
    defer ours.deinit(gpa);
    for (full.body.kernels) |k| if (!k.isCoinbase()) try ours.append(gpa, epic.shortid.shortId(k.hash(), hh, cb.nonce));
    try epic.shortid.sort(gpa, ours.items);
    if (ours.items.len != cb.kern_ids.len) return error.KernelIdCountMismatch;
    for (ours.items, cb.kern_ids) |a, b| if (!a.eql(b)) return error.ShortIdMismatch;
    std.debug.print("SHORT IDS MATCH the node's compact block ({d} ids)\n", .{ours.items.len});

    // hydrating from the block's own non-coinbase parts must give back the block
    var ins: std.ArrayList(epic.transaction.Input) = .empty;
    defer ins.deinit(gpa);
    var outs: std.ArrayList(epic.transaction.Output) = .empty;
    defer outs.deinit(gpa);
    var kerns: std.ArrayList(epic.transaction.TxKernel) = .empty;
    defer kerns.deinit(gpa);
    for (full.body.inputs) |x| try ins.append(gpa, x);
    for (full.body.outputs) |x| if (!x.isCoinbase()) try outs.append(gpa, x);
    for (full.body.kernels) |x| if (!x.isCoinbase()) try kerns.append(gpa, x);
    const t: epic.transaction.Transaction = .{ .offset = epic.transaction.BlindingFactor.zero, .body = .{ .inputs = ins.items, .outputs = outs.items, .kernels = kerns.items } };
    var rebuilt = try epic.compact_block.hydrate(gpa, cb, &.{t});
    defer rebuilt.deinit(gpa);
    if (!rebuilt.hash().eql(full.hash())) return error.HydrateMismatch;
    for (full.body.outputs, rebuilt.body.outputs) |a, b| if (!a.hash().eql(b.hash())) return error.HydrateMismatch;
    std.debug.print("HYDRATED BLOCK EQUALS THE FULL BLOCK\n", .{});
}
