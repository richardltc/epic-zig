//! A tiny fork-join helper: run `work(ctx, i)` for i in 0..n_items on all
//! cores. The first error stops the remaining work and is returned.
const std = @import("std");

pub fn forEach(comptime Ctx: type, ctx: *Ctx, n_items: usize, comptime work: fn (*Ctx, usize) anyerror!void) anyerror!void {
    const Shared = struct {
        ctx: *Ctx,
        n: usize,
        next: std.atomic.Value(usize) = .init(0),
        failed: std.atomic.Value(bool) = .init(false),
        err: std.atomic.Value(u16) = .init(0),

        fn run(self: *@This()) void {
            while (!self.failed.load(.acquire)) {
                const i = self.next.fetchAdd(1, .monotonic);
                if (i >= self.n) return;
                work(self.ctx, i) catch |e| {
                    // the first error wins
                    if (!self.failed.swap(true, .acq_rel)) self.err.store(@intFromError(e), .release);
                    return;
                };
            }
        }
    };
    var shared: Shared = .{ .ctx = ctx, .n = n_items };
    const cpus = std.Thread.getCpuCount() catch 1;
    const workers = @min(@min(cpus, n_items), 32);
    if (workers <= 1) {
        shared.run();
    } else {
        var threads: [32]std.Thread = undefined;
        var spawned: usize = 0;
        while (spawned < workers - 1) : (spawned += 1) {
            threads[spawned] = std.Thread.spawn(.{}, Shared.run, .{&shared}) catch break;
        }
        shared.run(); // this thread works too
        for (threads[0..spawned]) |t| t.join();
    }
    if (shared.failed.load(.acquire)) return @errorFromInt(shared.err.load(.acquire));
}

test "forEach visits every item once and reports the first error" {
    const Ctx = struct {
        sum: std.atomic.Value(usize) = .init(0),
        fn work(self: *@This(), i: usize) anyerror!void {
            _ = self.sum.fetchAdd(i + 1, .monotonic);
        }
        fn failAt7(self: *@This(), i: usize) anyerror!void {
            _ = self;
            if (i == 7) return error.Seven;
        }
    };
    var c: Ctx = .{};
    try forEach(Ctx, &c, 1000, Ctx.work);
    try std.testing.expectEqual(@as(usize, 1000 * 1001 / 2), c.sum.load(.monotonic));
    var d: Ctx = .{};
    try std.testing.expectError(error.Seven, forEach(Ctx, &d, 100, Ctx.failAt7));
    try forEach(Ctx, &d, 0, Ctx.work);
}
