//! Dev tool: asks a node for the header hashes at given heights (by hopping
//! with fast-sync header requests) and prints them as checkpoint-table lines.
//!
//!   zig build checkpoints -- host:port height [height ...]
const std = @import("std");
const Io = std.Io;
const epic = @import("epic");

const Hash = epic.hash.Hash;

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 3) return error.Usage;
    const colon = std.mem.lastIndexOfScalar(u8, args[1], ':') orelse return error.BadAddress;
    const addr = try Io.net.IpAddress.parse(args[1][0..colon], try std.fmt.parseInt(u16, args[1][colon + 1 ..], 10));
    const genesis = epic.block.genesisMain();
    const conn = try epic.p2p_client.Conn.connect(gpa, io, addr, .mainnet, genesis.hash(), genesis.header.pow.total_difficulty);
    defer conn.close();

    for (args[2..]) |a| {
        const target = try std.fmt.parseInt(u64, a, 10);
        var loc: Hash = genesis.hash();
        var loc_height: u64 = 0;
        var found: ?epic.block.BlockHeader = null;
        while (found == null) {
            const remaining = target - loc_height;
            const off: u8 = if (remaining > 512 * 256) 255 else @intCast((remaining - 1) / 512);
            try conn.send(.get_headers_fast_sync, epic.p2p_msg.LocatorFastSync{ .hashes = &.{loc}, .offset = off });
            const hm = try conn.recvType(.fast_headers);
            defer hm.deinit(gpa);
            var r = conn.readerFor(hm.body);
            var hs = try epic.p2p_msg.Headers.read(&r);
            defer hs.deinit(gpa);
            if (hs.headers.len == 0) return error.NoHeaders;
            for (hs.headers) |h| if (h.height == target) {
                found = h;
            };
            const last = hs.headers[hs.headers.len - 1];
            loc = last.hash();
            loc_height = last.height;
        }
        std.debug.print("    .{{ .height = {d}, .hash = h(\"{s}\") }},\n", .{ target, &found.?.hash().toHex() });
    }
}
