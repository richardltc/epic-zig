//! Dev tool: misbehaves on purpose to check a node's peer handling.
//!
//!   zig build peertest -- host:port garbage|silent|idle|keepalive [seconds]
const std = @import("std");
const Io = std.Io;
const epic = @import("epic");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 3) return error.Usage;
    const target = args[1];
    const mode = args[2];
    const secs: u64 = if (args.len > 3) try std.fmt.parseInt(u64, args[3], 10) else 60;
    const colon = std.mem.lastIndexOfScalar(u8, target, ':') orelse return error.BadAddress;
    const addr = try Io.net.IpAddress.parse(target[0..colon], try std.fmt.parseInt(u16, target[colon + 1 ..], 10));
    const genesis = epic.block.genesisMain();
    const t0 = Io.Clock.awake.now(io).toMilliseconds();

    if (std.mem.eql(u8, mode, "garbage") or std.mem.eql(u8, mode, "silent")) {
        var stream = addr.connect(io, .{ .mode = .stream }) catch |e| {
            std.debug.print("connect failed: {s}\n", .{@errorName(e)});
            return;
        };
        defer stream.close(io);
        var wbuf: [256]u8 = undefined;
        var rbuf: [256]u8 = undefined;
        var w = stream.writer(io, &wbuf);
        var r = stream.reader(io, &rbuf);
        if (std.mem.eql(u8, mode, "garbage")) {
            try w.interface.writeAll("this is definitely not an epic handshake, just noise............");
            try w.interface.flush();
        }
        // wait for the server to hang up
        var b: [1]u8 = undefined;
        if (r.interface.readSliceAll(&b)) |_| {
            std.debug.print("server sent data?\n", .{});
        } else |e| {
            const dt = Io.Clock.awake.now(io).toMilliseconds() - t0;
            std.debug.print("{s}: server closed the connection after {d} ms ({s})\n", .{ mode, dt, @errorName(e) });
        }
        return;
    }

    const conn = epic.p2p_client.Conn.connect(gpa, io, addr, .mainnet, genesis.hash(), genesis.header.pow.total_difficulty) catch |e| {
        std.debug.print("handshake failed: {s}\n", .{@errorName(e)});
        return;
    };
    defer conn.close();
    std.debug.print("handshake ok with \"{s}\"\n", .{conn.peer.userAgent()});
    if (std.mem.eql(u8, mode, "idle")) {
        // never read, never answer: the node should ping us and then drop us
        var b: [1]u8 = undefined;
        if (conn.reader.interface.readSliceAll(&b)) |_| {
            // the node's first byte is a ping header; keep ignoring it
            while (true) conn.reader.interface.readSliceAll(&b) catch break;
        } else |_| {}
        const dt = Io.Clock.awake.now(io).toMilliseconds() - t0;
        std.debug.print("idle: node closed the connection after {d} s\n", .{@divTrunc(dt, 1000)});
    } else if (std.mem.eql(u8, mode, "keepalive")) {
        // answer pings for `secs` seconds and report whether we were kept
        var pings: u32 = 0;
        while (Io.Clock.awake.now(io).toMilliseconds() - t0 < @as(i64, @intCast(secs * 1000))) {
            const m = conn.recv() catch |e| {
                std.debug.print("keepalive: lost the connection: {s}\n", .{@errorName(e)});
                return;
            };
            defer m.deinit(gpa);
            if (m.msg_type == .ping) {
                pings += 1;
                try conn.send(.pong, epic.p2p_msg.Pong{ .total_difficulty = genesis.header.pow.total_difficulty, .height = 0, .local_timestamp = 0 });
            }
        }
        std.debug.print("keepalive: still connected after {d} s, answered {d} ping(s)\n", .{ secs, pings });
    }
}
