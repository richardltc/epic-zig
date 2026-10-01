//! Dev tool: compacts a (copy of a) synced data dir with a chosen horizon and
//! checks the result: full txhashset validation, a rewind to the horizon, and a
//! reopen.
//!
//!   zig build compact -Doptimize=ReleaseFast -- <data-dir> <horizon-blocks>
const std = @import("std");
const Io = std.Io;
const epic = @import("epic");

fn dirBytes(io: Io, root: Io.Dir, sub: []const u8) u64 {
    var d = root.openDir(io, sub, .{ .iterate = true }) catch return 0;
    defer d.close(io);
    var total: u64 = 0;
    var it = d.iterate();
    while (it.next(io) catch null) |e| {
        if (e.kind == .file) total += epic.fsutil.fileSize(io, d, e.name) catch 0;
    }
    return total;
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 3) return error.Usage;
    const horizon = try std.fmt.parseInt(u64, args[2], 10);

    {
        const c = try epic.chain.Chain.open(gpa, io, args[1], .{});
        defer c.close();
        const tip = try c.head();
        const tail = (try c.db.tail(c.db.store)).?;
        const head_header = (try c.getHeader(tip.last_block_h)).?;
        const out_before = dirBytes(io, c.ths_dir, "output");
        const rp_before = dirBytes(io, c.ths_dir, "rangeproof");
        std.debug.print("head {d}, tail {d}; output files {d} MiB, rangeproof files {d} MiB\n", .{ tip.height, tail.height, out_before >> 20, rp_before >> 20 });

        c.lock();
        const ran = try c.compactWithHorizon(horizon);
        c.unlock();
        std.debug.print("compaction ran: {}\n", .{ran});
        const new_tail = (try c.db.tail(c.db.store)).?;
        std.debug.print("tail now {d}; output files {d} MiB, rangeproof files {d} MiB\n", .{ new_tail.height, dirBytes(io, c.ths_dir, "output") >> 20, dirBytes(io, c.ths_dir, "rangeproof") >> 20 });

        // the whole state is still valid at the head
        _ = try c.ths.validate(c.genesis.header, false, head_header);
        std.debug.print("FULL VALIDATION AT THE HEAD PASSED\n", .{});

        // and rewinding to the horizon still gives that header's roots
        const hz = (try c.getHeader(c.header_mmr.hashAtHeight(new_tail.height).?)).?;
        var batch = c.db.batch();
        defer batch.deinit();
        try c.ths.rewind(&c.db, &batch, hz);
        try c.ths.validateRoots(hz);
        try c.ths.validateSizes(hz);
        try c.ths.discard();
        c.ths.head = epic.chain_types.Tip.fromHeader(head_header);
        std.debug.print("REWIND TO THE HORIZON ({d}) MATCHES ITS HEADER\n", .{hz.height});

        // old blocks are gone, recent ones remain
        const old = c.header_mmr.hashAtHeight(new_tail.height - 1).?;
        std.debug.print("block below the tail present: {}; block at the tail present: {}\n", .{ try c.db.blockExists(c.db.store, old), try c.db.blockExists(c.db.store, hz.hash()) });
    }
    // reopening re-checks the head state
    const c2 = try epic.chain.Chain.open(gpa, io, args[1], .{});
    defer c2.close();
    std.debug.print("REOPENED at head {d}\n", .{(try c2.head()).height});
}
