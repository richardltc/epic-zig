//! Where a node with no peers looks for some: the DNS seed of each network
//! and a short static list (the reference's own example config).
const std = @import("std");
const Io = std.Io;
const net = Io.net;
const consensus = @import("consensus.zig");

pub const Seeds = struct {
    dns: []const u8,
    port: u16,
    /// Used when DNS gives nothing.
    fallback: []const [4]u8,
};

/// Fixed fallback peers, tried along with whatever the DNS seed returns (the
/// network is small and the DNS seed answers with a single node). The first
/// group completed a handshake when this list was made (2026-10-01, from a scan
/// of ~200 learned addresses); the last four are the reference's example
/// config. Addresses rot: a node that has run once mostly relies on the peers
/// it has learned (`peers.txt`), like the reference.
const mainnet_fallback = [_][4]u8{
    .{ 103, 87, 68, 10 },
    .{ 101, 128, 75, 197 },
    .{ 99, 251, 118, 240 },
    .{ 43, 163, 1, 22 },
    .{ 195, 162, 57, 26 },
    .{ 73, 97, 43, 138 },
    .{ 45, 16, 228, 98 },
    .{ 95, 217, 197, 180 },
    .{ 5, 161, 127, 56 },
    .{ 5, 75, 242, 4 },
    .{ 5, 78, 71, 29 },
};

pub fn forChain(chain: consensus.ChainType) ?Seeds {
    return switch (chain) {
        .mainnet => .{ .dns = "node.epiccash.com", .port = 3414, .fallback = &mainnet_fallback },
        // the reference's floonet seed host "does not exist yet"
        .floonet => .{ .dns = "floonet.epiccash.com", .port = 13414, .fallback = &.{} },
        else => null,
    };
}

/// All addresses `host` resolves to, on `port`. Caller frees.
pub fn resolve(gpa: std.mem.Allocator, io: Io, host: []const u8, port: u16) ![]net.IpAddress {
    const hn = try net.HostName.init(host);
    var buf: [32]net.HostName.LookupResult = undefined;
    var q: Io.Queue(net.HostName.LookupResult) = .init(&buf);
    try hn.lookup(io, &q, .{ .port = port });
    var out: std.ArrayList(net.IpAddress) = .empty;
    errdefer out.deinit(gpa);
    while (true) {
        const r = q.getOneUncancelable(io) catch break;
        switch (r) {
            .address => |a| try out.append(gpa, a),
            .canonical_name => {},
        }
    }
    return out.toOwnedSlice(gpa);
}

/// The seed addresses for `chain`: what the DNS seed returns plus the static
/// list (a DNS seed that answers can still point only at busy or refusing nodes).
pub fn gather(gpa: std.mem.Allocator, io: Io, chain: consensus.ChainType) ![]net.IpAddress {
    const s = forChain(chain) orelse return try gpa.alloc(net.IpAddress, 0);
    var out: std.ArrayList(net.IpAddress) = .empty;
    errdefer out.deinit(gpa);
    if (resolve(gpa, io, s.dns, s.port)) |addrs| {
        defer gpa.free(addrs);
        try out.appendSlice(gpa, addrs);
    } else |e| std.log.warn("Failed to resolve seed {s}: {s}", .{ s.dns, @errorName(e) });
    outer: for (s.fallback) |b| {
        const a: net.IpAddress = .{ .ip4 = .{ .bytes = b, .port = s.port } };
        for (out.items) |x| if (x.eql(&a)) continue :outer;
        try out.append(gpa, a);
    }
    return out.toOwnedSlice(gpa);
}

test "seed tables" {
    try std.testing.expect(forChain(.mainnet) != null);
    try std.testing.expectEqual(@as(u16, 3414), forChain(.mainnet).?.port);
    try std.testing.expectEqual(@as(u16, 13414), forChain(.floonet).?.port);
    try std.testing.expect(forChain(.automated_testing) == null);
}
