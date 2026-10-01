//! Dev tool: which of a list of peers complete an Epic handshake right now?
//!
//!   zig build peerscan -- <file with one ip:port per line>
const std = @import("std");
const Io = std.Io;
const epic = @import("epic");

const Job = struct {
    gpa: std.mem.Allocator,
    io: Io,
    addr: Io.net.IpAddress,
    text: []const u8,
    ok: bool = false,
    agent: [64]u8 = undefined,
    agent_len: usize = 0,
    height_known: bool = false,
    done: std.atomic.Value(bool) = .init(false),

    fn run(self: *Job) void {
        defer self.done.store(true, .release);
        const g = epic.block.genesisMain();
        const c = epic.p2p_client.Conn.connect(self.gpa, self.io, self.addr, .mainnet, g.hash(), g.header.pow.total_difficulty) catch return;
        defer c.close();
        self.ok = true;
        const ua = c.peer.userAgent();
        self.agent_len = @min(ua.len, 64);
        @memcpy(self.agent[0..self.agent_len], ua[0..self.agent_len]);
    }
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 2) return error.Usage;
    const text = try Io.Dir.cwd().readFileAlloc(io, args[1], arena, .limited(1 << 20));
    var jobs: std.ArrayList(*Job) = .empty;
    var lines = std.mem.tokenizeAny(u8, text, " \r\n");
    while (lines.next()) |l| {
        const c = std.mem.lastIndexOfScalar(u8, l, ':') orelse continue;
        const port = std.fmt.parseInt(u16, l[c + 1 ..], 10) catch continue;
        const addr = Io.net.IpAddress.parse(l[0..c], port) catch continue;
        const j = try arena.create(Job);
        j.* = .{ .gpa = gpa, .io = io, .addr = addr, .text = l };
        try jobs.append(arena, j);
        const t = try std.Thread.spawn(.{}, Job.run, .{j});
        t.detach();
    }
    // give them 20 s; connections that hang are counted as dead
    const t0 = Io.Clock.awake.now(io).toMilliseconds();
    while (Io.Clock.awake.now(io).toMilliseconds() - t0 < 20_000) {
        var all = true;
        for (jobs.items) |j| if (!j.done.load(.acquire)) {
            all = false;
        };
        if (all) break;
        io.sleep(.fromMilliseconds(200), .awake) catch {};
    }
    var n_ok: usize = 0;
    for (jobs.items) |j| if (j.done.load(.acquire) and j.ok) {
        n_ok += 1;
        std.debug.print("OK {s} {s}\n", .{ j.text, j.agent[0..j.agent_len] });
    };
    std.debug.print("{d} of {d} peers completed a handshake\n", .{ n_ok, jobs.items.len });
    std.process.exit(0);
}
