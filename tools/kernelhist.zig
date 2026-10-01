//! Dev tool: times kernel-history validation on an existing synced data dir.
//!
//!   zig build kernelhist -Doptimize=ReleaseFast -- <data-dir>
const std = @import("std");
const Io = std.Io;
const epic = @import("epic");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 2) return error.Usage;
    const c = try epic.chain.Chain.open(gpa, io, args[1], .{});
    defer c.close();
    const tip = try c.head();
    const header = (try c.getHeader(tip.last_block_h)).?;
    std.debug.print("head {d}; kernel MMR size {d}\n", .{ header.height, header.kernel_mmr_size });
    var round: usize = 0;
    while (round < 3) : (round += 1) {
        const t0 = Io.Clock.awake.now(io).toMilliseconds();
        try c.validateKernelHistory(&c.ths, header);
        const t1 = Io.Clock.awake.now(io).toMilliseconds();
        std.debug.print("round {d}: kernel history {d:.1}s\n", .{ round, @as(f64, @floatFromInt(t1 - t0)) / 1000.0 });
    }
}
