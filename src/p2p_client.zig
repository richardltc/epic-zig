//! A minimal blocking P2P client connection: handshake, framed send/receive.
//! (The full peer manager comes later; this is enough to talk to a node.)
const std = @import("std");
const Io = std.Io;
const net = Io.net;
const ser = @import("ser.zig");
const hash_mod = @import("hash.zig");
const consensus = @import("consensus.zig");
const block = @import("block.zig");
const msg = @import("p2p_msg.zig");
const Difficulty = @import("pow_types.zig").Difficulty;

const Hash = hash_mod.Hash;
const ChainType = consensus.ChainType;

pub const Message = struct {
    msg_type: msg.MsgType,
    /// Owned by the caller (allocated with the connection's allocator).
    body: []u8,

    pub fn deinit(self: Message, gpa: std.mem.Allocator) void {
        gpa.free(self.body);
    }
};

/// The address we listen on, sent in our handshakes so peers can dial us back
/// and pass us on (the reference sends its configured host and port). Set once
/// at startup when the node listens; unset means "not listening" (port 0).
pub var advertised: msg.PeerAddr = .{ .v4 = .{ .ip = .{ 0, 0, 0, 0 }, .port = 0 } };

pub const PeerInfo = struct {
    /// For inbound peers: the port they say they listen on (0 if none).
    listen_port: u16 = 0,
    version: ser.ProtocolVersion,
    capabilities: msg.Capabilities,
    total_difficulty: Difficulty,
    user_agent: [64]u8,
    user_agent_len: usize,
    genesis: Hash,

    pub fn userAgent(self: *const PeerInfo) []const u8 {
        return self.user_agent[0..self.user_agent_len];
    }
};

/// Called for messages a request/response loop isn't waiting for (gossip).
pub const Handler = struct {
    ctx: *anyopaque,
    f: *const fn (ctx: *anyopaque, conn: *Conn, m: Message) void,
};

/// Where a connection gets our own chain state to answer pings with (set by
/// the node at startup). Unset, pings are answered with genesis difficulty.
pub var local_status: ?struct { ctx: *anyopaque, f: *const fn (ctx: *anyopaque) ?msg.Ping } = null;

pub const Conn = struct {
    /// Sends from several threads (replies, broadcasts) are serialized by this.
    write_mu: Io.Mutex = .init,
    handler: ?Handler = null,
    /// Milliseconds (awake clock) of the last message received; the node's
    /// liveness checks read this.
    last_recv_ms: std.atomic.Value(i64) = .init(0),
    /// Connections whose owner does its own I/O timing (the sync connection)
    /// are left alone by the liveness checks.
    exempt: bool = false,
    /// The peer's address, when known.
    remote: ?net.IpAddress = null,
    /// We dialed this peer (as opposed to it dialing us).
    outbound: bool = true,
    /// The peer's chain as of its last ping/pong (the handshake's difficulty
    /// until then). Guarded by `live_mu`.
    live_mu: Io.Mutex = .init,
    live_height: u64 = 0,
    live_difficulty: Difficulty = .{ .num = .{ null, null, null, null } },
    gpa: std.mem.Allocator,
    io: Io,
    chain: ChainType,
    stream: net.Stream,
    reader: net.Stream.Reader,
    writer: net.Stream.Writer,
    rbuf: []u8,
    wbuf: []u8,
    /// Negotiated protocol version (min of both sides).
    version: ser.ProtocolVersion,
    peer: PeerInfo,

    pub const HandshakeError = error{ GenesisMismatch, BadHandshake } || ser.Error || msg.MsgHeader.ParseError;

    /// Connects and performs the handshake as an outbound peer.
    pub fn connect(gpa: std.mem.Allocator, io: Io, addr: net.IpAddress, chain: ChainType, genesis: Hash, our_difficulty: Difficulty) !*Conn {
        const self = try gpa.create(Conn);
        errdefer gpa.destroy(self);
        self.gpa = gpa;
        self.io = io;
        self.chain = chain;
        self.write_mu = .init;
        self.handler = null;
        self.last_recv_ms = .init(Io.Clock.awake.now(io).toMilliseconds());
        self.exempt = false;
        self.outbound = true;
        self.live_mu = .init;
        self.live_height = 0;
        self.remote = addr;
        self.stream = try addr.connect(io, .{ .mode = .stream});
        errdefer self.stream.close(io);
        self.rbuf = try gpa.alloc(u8, 1 << 16);
        errdefer gpa.free(self.rbuf);
        self.wbuf = try gpa.alloc(u8, 1 << 16);
        errdefer gpa.free(self.wbuf);
        self.reader = self.stream.reader(io, self.rbuf);
        self.writer = self.stream.writer(io, self.wbuf);

        const local = ser.ProtocolVersion.local();
        var nonce_bytes: [8]u8 = undefined;
        io.random(&nonce_bytes);
        const hand: msg.Hand = .{
            .version = local,
            .capabilities = .{ .bits = msg.Capabilities.FULL_NODE },
            .nonce = std.mem.readInt(u64, &nonce_bytes, .little),
            .genesis = genesis,
            .total_difficulty = our_difficulty,
            .sender_addr = advertised,
            .receiver_addr = toPeerAddr(addr),
            .user_agent = msg.USER_AGENT,
        };
        const framed = try msg.encode(gpa, chain, .hand, hand, local);
        defer gpa.free(framed);
        try self.writer.interface.writeAll(framed);
        try self.writer.interface.flush();

        const reply = try self.recv();
        defer reply.deinit(gpa);
        if (reply.msg_type != .shake) return error.BadHandshake;
        var r = ser.Reader.init(gpa, reply.body, local);
        r.params = chain.readParams();
        const shake = try msg.Shake.read(&r);
        if (!shake.genesis.eql(genesis)) return error.GenesisMismatch;

        self.version = .{ .v = @min(local.v, shake.version.v) };
        self.peer = .{
            .version = shake.version,
            .capabilities = shake.capabilities,
            .total_difficulty = shake.total_difficulty,
            .user_agent = undefined,
            .user_agent_len = @min(shake.user_agent.len, 64),
            .genesis = shake.genesis,
        };
        @memcpy(self.peer.user_agent[0..self.peer.user_agent_len], shake.user_agent[0..self.peer.user_agent_len]);
        self.live_difficulty = self.peer.total_difficulty;
        return self;
    }

    /// Performs the handshake as the inbound side of `stream` (already accepted).
    /// Closes the stream itself if the handshake fails.
    pub fn accept(gpa: std.mem.Allocator, io: Io, stream: net.Stream, chain: ChainType, genesis: Hash, our_difficulty: Difficulty) !*Conn {
        const self = try gpa.create(Conn);
        errdefer gpa.destroy(self);
        self.gpa = gpa;
        self.io = io;
        self.chain = chain;
        self.write_mu = .init;
        self.handler = null;
        self.last_recv_ms = .init(Io.Clock.awake.now(io).toMilliseconds());
        self.exempt = false;
        self.outbound = false;
        self.live_mu = .init;
        self.live_height = 0;
        self.remote = stream.socket.address;
        self.stream = stream;
        errdefer self.stream.close(io);
        self.rbuf = try gpa.alloc(u8, 1 << 16);
        errdefer gpa.free(self.rbuf);
        self.wbuf = try gpa.alloc(u8, 1 << 16);
        errdefer gpa.free(self.wbuf);
        self.reader = self.stream.reader(io, self.rbuf);
        self.writer = self.stream.writer(io, self.wbuf);

        const local = ser.ProtocolVersion.local();
        const first = try self.recv();
        defer first.deinit(gpa);
        if (first.msg_type != .hand) return error.BadHandshake;
        var r = ser.Reader.init(gpa, first.body, local);
        r.params = chain.readParams();
        const hand = try msg.Hand.read(&r);
        if (!hand.genesis.eql(genesis)) return error.GenesisMismatch;

        self.version = .{ .v = @min(local.v, hand.version.v) };
        self.peer = .{
            .listen_port = hand.sender_addr.port(),
            .version = hand.version,
            .capabilities = hand.capabilities,
            .total_difficulty = hand.total_difficulty,
            .user_agent = undefined,
            .user_agent_len = @min(hand.user_agent.len, 64),
            .genesis = hand.genesis,
        };
        @memcpy(self.peer.user_agent[0..self.peer.user_agent_len], hand.user_agent[0..self.peer.user_agent_len]);
        self.live_difficulty = self.peer.total_difficulty;

        const shake: msg.Shake = .{
            .version = local,
            .capabilities = .{ .bits = msg.Capabilities.FULL_NODE },
            .genesis = genesis,
            .total_difficulty = our_difficulty,
            .user_agent = msg.USER_AGENT,
        };
        const framed = try msg.encode(gpa, chain, .shake, shake, local);
        defer gpa.free(framed);
        try self.writer.interface.writeAll(framed);
        try self.writer.interface.flush();
        return self;
    }

    /// Makes blocked reads and writes on this connection fail (from another thread).
    pub fn kill(self: *Conn) void {
        self.stream.shutdown(self.io, .both) catch {};
    }

    pub fn close(self: *Conn) void {
        self.stream.close(self.io);
        self.gpa.free(self.rbuf);
        self.gpa.free(self.wbuf);
        const gpa = self.gpa;
        gpa.destroy(self);
    }

    pub fn send(self: *Conn, t: msg.MsgType, body: anytype) !void {
        const framed = try msg.encode(self.gpa, self.chain, t, body, self.version);
        defer self.gpa.free(framed);
        self.write_mu.lockUncancelable(self.io);
        defer self.write_mu.unlock(self.io);
        try self.writer.interface.writeAll(framed);
        try self.writer.interface.flush();
    }

    /// For streaming raw bytes after a message (hold it across the message and the bytes).
    pub fn lockWrite(self: *Conn) void {
        self.write_mu.lockUncancelable(self.io);
    }
    pub fn unlockWrite(self: *Conn) void {
        self.write_mu.unlock(self.io);
    }

    /// `send` for a caller that already holds `lockWrite`.
    pub fn sendLocked(self: *Conn, t: msg.MsgType, body: anytype) !void {
        const framed = try msg.encode(self.gpa, self.chain, t, body, self.version);
        defer self.gpa.free(framed);
        try self.writer.interface.writeAll(framed);
        try self.writer.interface.flush();
    }

    /// Receives the next message (unknown types are skipped).
    pub fn recv(self: *Conn) !Message {
        while (true) {
            var hbytes: [msg.MsgHeader.LEN]u8 = undefined;
            try self.reader.interface.readSliceAll(&hbytes);
            const h = try msg.MsgHeader.parse(self.chain, &hbytes);
            const body = try self.gpa.alloc(u8, @intCast(h.msg_len));
            errdefer self.gpa.free(body);
            try self.reader.interface.readSliceAll(body);
            self.last_recv_ms.store(Io.Clock.awake.now(self.io).toMilliseconds(), .monotonic);
            if (msg.MsgType.fromByte(@intFromEnum(h.msg_type)) == null) {
                self.gpa.free(body);
                continue;
            }
            return .{ .msg_type = h.msg_type, .body = body };
        }
    }

    /// Receives until a message of type `want` arrives, answering pings.
    pub fn recvType(self: *Conn, want: msg.MsgType) !Message {
        while (true) {
            const m = try self.recv();
            if (m.msg_type == want) return m;
            defer m.deinit(self.gpa);
            if (self.handler) |h| switch (m.msg_type) {
                .transaction, .stem_transaction, .transaction_kernel, .get_transaction, .header, .compact_block, .block, .peer_addrs => {
                    h.f(h.ctx, self, m);
                    continue;
                },
                else => {},
            };
            switch (m.msg_type) {
                .ping => {
                    var r = self.readerFor(m.body);
                    const p = try msg.Ping.read(&r);
                    self.noteLive(p.total_difficulty, p.height);
                    try self.send(.pong, ourStatus(self.chain));
                },
                .pong => {
                    var r = self.readerFor(m.body);
                    const p = try msg.Pong.read(&r);
                    self.noteLive(p.total_difficulty, p.height);
                },
                .@"error" => return error.PeerSentError,
                else => {},
            }
        }
    }

    /// Records the peer's chain state from a ping or pong.
    pub fn noteLive(self: *Conn, td: Difficulty, height: u64) void {
        self.live_mu.lockUncancelable(self.io);
        defer self.live_mu.unlock(self.io);
        self.live_difficulty = td;
        self.live_height = height;
    }

    /// The peer's last known height and total difficulty.
    pub fn live(self: *Conn) struct { height: u64, difficulty: Difficulty } {
        self.live_mu.lockUncancelable(self.io);
        defer self.live_mu.unlock(self.io);
        return .{ .height = self.live_height, .difficulty = self.live_difficulty };
    }

    pub fn readerFor(self: *const Conn, body: []const u8) ser.Reader {
        var r = ser.Reader.init(self.gpa, body, self.version);
        r.params = self.chain.readParams();
        return r;
    }
};

fn toPeerAddr(a: net.IpAddress) msg.PeerAddr {
    return switch (a) {
        .ip4 => |x| .{ .v4 = .{ .ip = x.bytes, .port = x.port } },
        .ip6 => |x| blk: {
            var segs: [8]u16 = undefined;
            for (0..8) |i| segs[i] = std.mem.readInt(u16, x.bytes[i * 2 ..][0..2], .big);
            break :blk .{ .v6 = .{ .segments = segs, .port = x.port } };
        },
    };
}

/// Our chain state for a ping or pong.
pub fn ourStatus(chain: ChainType) msg.Ping {
    if (local_status) |ls| if (ls.f(ls.ctx)) |p| return p;
    return .{ .total_difficulty = block.genesisFor(chain).header.pow.total_difficulty, .height = 0, .local_timestamp = 0 };
}
