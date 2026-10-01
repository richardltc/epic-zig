//! Dev tool: how long does PoW verification take per algorithm, on one thread
//! and on all cores? Uses the real headers in testdata/.
//!
//!   zig build bench -Doptimize=ReleaseFast
const std = @import("std");
const Io = std.Io;
const epic = @import("epic");

fn now(io: Io) i64 {
    return @intCast(Io.Clock.awake.now(io).toNanoseconds());
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    var dir = try Io.Dir.cwd().openDir(io, "testdata", .{ .iterate = true });
    defer dir.close(io);

    var headers: std.ArrayList(epic.block.BlockHeader) = .empty;
    defer headers.deinit(gpa);
    var it = dir.iterate();
    while (try it.next(io)) |e| {
        if (!std.mem.startsWith(u8, e.name, "headers_h")) continue; // the high windows only (real mixed algos)
        const bytes = try epic.fsutil.readAll(gpa, io, dir, e.name);
        defer gpa.free(bytes);
        var r = epic.ser.Reader.init(gpa, bytes, epic.ser.ProtocolVersion.local());
        r.params = epic.consensus.ChainType.mainnet.readParams();
        const hs = try epic.p2p_msg.Headers.read(&r);
        defer gpa.free(hs.headers);
        try headers.appendSlice(gpa, hs.headers);
    }
    std.debug.print("{d} real headers loaded\n", .{headers.items.len});

    var v = epic.pow.Verifier.init(gpa, io);
    defer v.deinit();

    for (epic.pow_types.PoWType.all) |algo| {
        var sel: std.ArrayList(epic.block.BlockHeader) = .empty;
        defer sel.deinit(gpa);
        for (headers.items) |h| if (h.height > 2_300_000 and h.pow.proof.powType() == algo) try sel.append(gpa, h);
        if (sel.items.len < 20) {
            std.debug.print("{s}: only {d} headers, skipped\n", .{ @tagName(algo), sel.items.len });
            continue;
        }
        const n = @min(sel.items.len, 400);
        // warm the per-epoch caches
        for (sel.items[0..@min(n, 8)]) |h| _ = v.verifyWithDifficulty(.mainnet, h) catch {};
        const t0 = now(io);
        var ok: usize = 0;
        for (sel.items[0..n]) |h| {
            if (v.verifyWithDifficulty(.mainnet, h)) |_| ok += 1 else |_| {}
        }
        const t1 = now(io);
        const out = try gpa.alloc(?epic.pow_types.Difficulty, n);
        defer gpa.free(out);
        v.verifyBatch(.mainnet, sel.items[0..n], out);
        const t2 = now(io);
        const single_ms = @as(f64, @floatFromInt(t1 - t0)) / 1e6 / @as(f64, @floatFromInt(n));
        const multi_ms = @as(f64, @floatFromInt(t2 - t1)) / 1e6 / @as(f64, @floatFromInt(n));
        std.debug.print("{s:>9}: {d} headers ok {d}; {d:.2} ms/header on 1 thread, {d:.2} ms/header with all cores ({d:.0}/s)\n", .{ @tagName(algo), n, ok, single_ms, multi_ms, 1000.0 / multi_ms });
    }
}
