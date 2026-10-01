//! P2P wire messages (`p2p/src/msg.rs`, `types.rs`): framing, handshake,
//! locators, headers, ping/pong and friends.
const std = @import("std");
const ser = @import("ser.zig");
const hash_mod = @import("hash.zig");
const consensus = @import("consensus.zig");
const block = @import("block.zig");
const Difficulty = @import("pow_types.zig").Difficulty;

const Hash = hash_mod.Hash;
const ChainType = consensus.ChainType;

pub const USER_AGENT = "MW/Epic-Zig " ++ @import("version.zig").VERSION;

pub const MAX_BLOCK_HEADERS: u32 = 512;
pub const MAX_PEER_ADDRS: u32 = 256;
pub const MAX_LOCATORS: u32 = 20;

pub fn magic(chain: ChainType) [2]u8 {
    return switch (chain) {
        .floonet => .{ 83, 59 },
        .mainnet => .{ 97, 61 },
        else => .{ 73, 43 },
    };
}

pub const MsgType = enum(u8) {
    @"error" = 0,
    hand = 1,
    shake = 2,
    ping = 3,
    pong = 4,
    get_peer_addrs = 5,
    peer_addrs = 6,
    get_headers = 7,
    header = 8,
    headers = 9,
    get_block = 10,
    block = 11,
    get_compact_block = 12,
    compact_block = 13,
    stem_transaction = 14,
    transaction = 15,
    tx_hash_set_request = 16,
    tx_hash_set_archive = 17,
    ban_reason = 18,
    get_transaction = 19,
    transaction_kernel = 20,
    kernel_data_request = 21,
    kernel_data_response = 22,
    get_headers_fast_sync = 23,
    fast_headers = 24,
    onion_address_request = 25,
    onion_address_response = 26,
    _,

    pub fn fromByte(b: u8) ?MsgType {
        return if (b <= 26) @enumFromInt(b) else null;
    }
};

fn maxBlockSize(chain: ChainType) u64 {
    return chain.maxBlockWeight() / consensus.BLOCK_OUTPUT_WEIGHT * 708;
}

/// The per-type cap in the reference (the header check allows 4x this).
pub fn maxMsgSize(chain: ChainType, t: MsgType) u64 {
    return switch (t) {
        .@"error" => 0,
        .hand => 128,
        .shake => 88,
        .ping, .pong => 16,
        .get_peer_addrs => 4,
        .peer_addrs => 4 + (1 + 16 + 2) * @as(u64, MAX_PEER_ADDRS),
        .get_headers => 1 + 32 * @as(u64, MAX_LOCATORS),
        .get_headers_fast_sync => 1 + 32 * @as(u64, MAX_LOCATORS) + 2,
        .header => 365,
        .headers, .fast_headers => 2 + 365 * @as(u64, MAX_BLOCK_HEADERS),
        .get_block, .get_compact_block, .get_transaction, .transaction_kernel => 32,
        .block, .stem_transaction, .transaction => maxBlockSize(chain),
        .compact_block => maxBlockSize(chain) / 10,
        .tx_hash_set_request => 40,
        .tx_hash_set_archive, .ban_reason => 64,
        .kernel_data_request, .onion_address_request => 0,
        .kernel_data_response => 8,
        .onion_address_response => 256,
        _ => maxBlockSize(chain),
    };
}

pub const MsgHeader = struct {
    msg_type: MsgType,
    msg_len: u64,

    pub const LEN = 2 + 1 + 8;

    pub fn encode(self: MsgHeader, chain: ChainType) [LEN]u8 {
        var out: [LEN]u8 = undefined;
        const m = magic(chain);
        out[0] = m[0];
        out[1] = m[1];
        out[2] = @intFromEnum(self.msg_type);
        std.mem.writeInt(u64, out[3..11], self.msg_len, .big);
        return out;
    }

    pub const ParseError = error{ BadMagic, TooLarge };

    /// Parses and size-checks a header. Unknown types are returned as such
    /// (the caller skips their body).
    pub fn parse(chain: ChainType, bytes: *const [LEN]u8) ParseError!MsgHeader {
        const m = magic(chain);
        if (bytes[0] != m[0] or bytes[1] != m[1]) return error.BadMagic;
        const t: MsgType = @enumFromInt(bytes[2]);
        const len = std.mem.readInt(u64, bytes[3..11], .big);
        const known = MsgType.fromByte(bytes[2]) != null;
        const max = (if (known) maxMsgSize(chain, t) else maxBlockSize(chain)) * 4;
        if (len > max) return error.TooLarge;
        return .{ .msg_type = t, .msg_len = len };
    }
};

/// Frames a message: header followed by the serialized body.
pub fn encode(gpa: std.mem.Allocator, chain: ChainType, t: MsgType, body: anytype, version: ser.ProtocolVersion) ![]u8 {
    const payload = try ser.serVec(gpa, body, version);
    defer gpa.free(payload);
    const out = try gpa.alloc(u8, MsgHeader.LEN + payload.len);
    const h = (MsgHeader{ .msg_type = t, .msg_len = payload.len }).encode(chain);
    @memcpy(out[0..MsgHeader.LEN], &h);
    @memcpy(out[MsgHeader.LEN..], payload);
    return out;
}

// ------------------------------------------------------------ capabilities

pub const Capabilities = struct {
    bits: u32,

    pub const UNKNOWN: u32 = 0;
    pub const HEADER_HIST: u32 = 0b1;
    pub const TXHASHSET_HIST: u32 = 0b10;
    pub const PEER_LIST: u32 = 0b100;
    pub const TX_KERNEL_HASH: u32 = 0b1000;
    pub const HEADER_FASTSYNC: u32 = 0b10000;
    pub const ONIONSTEM: u32 = 0b100000;
    pub const FULL_NODE: u32 = HEADER_HIST | TXHASHSET_HIST | PEER_LIST | TX_KERNEL_HASH | HEADER_FASTSYNC;
    const KNOWN_MASK: u32 = FULL_NODE | ONIONSTEM;

    pub fn has(self: Capabilities, flag: u32) bool {
        return self.bits & flag == flag;
    }
    /// `from_bits_truncate`: unknown bits are dropped.
    pub fn fromBitsTruncate(b: u32) Capabilities {
        return .{ .bits = b & KNOWN_MASK };
    }
};

// -------------------------------------------------------------- peer addr

pub const PeerAddr = union(enum) {
    v4: struct { ip: [4]u8, port: u16 },
    v6: struct { segments: [8]u16, port: u16 },

    pub fn write(self: PeerAddr, w: anytype) ser.Error!void {
        switch (self) {
            .v4 => |a| {
                try ser.writeU8(w, 0);
                try w.writeFixedBytes(&a.ip);
                try ser.writeU16(w, a.port);
            },
            .v6 => |a| {
                try ser.writeU8(w, 1);
                for (a.segments) |s| try ser.writeU16(w, s);
                try ser.writeU16(w, a.port);
            },
        }
    }

    pub fn read(r: *ser.Reader) ser.Error!PeerAddr {
        if ((try r.readU8()) == 0) {
            const ip = try r.readArray(4);
            return .{ .v4 = .{ .ip = ip, .port = try r.readU16() } };
        }
        var segs: [8]u16 = undefined;
        for (&segs) |*s| s.* = try r.readU16();
        return .{ .v6 = .{ .segments = segs, .port = try r.readU16() } };
    }

    pub fn port(self: PeerAddr) u16 {
        return switch (self) {
            inline else => |a| a.port,
        };
    }
};

// -------------------------------------------------------- handshake

pub const Hand = struct {
    version: ser.ProtocolVersion,
    capabilities: Capabilities,
    nonce: u64,
    genesis: Hash,
    total_difficulty: Difficulty,
    sender_addr: PeerAddr,
    receiver_addr: PeerAddr,
    user_agent: []const u8,

    pub fn write(self: Hand, w: anytype) ser.Error!void {
        try self.version.write(w);
        try ser.writeU32(w, self.capabilities.bits);
        try ser.writeU64(w, self.nonce);
        try self.total_difficulty.write(w);
        try self.sender_addr.write(w);
        try self.receiver_addr.write(w);
        try ser.writeBytes(w, self.user_agent);
        try self.genesis.write(w);
    }

    /// `user_agent` borrows from the reader's buffer.
    pub fn read(r: *ser.Reader) ser.Error!Hand {
        const version = try ser.ProtocolVersion.read(r);
        const caps = Capabilities.fromBitsTruncate(try r.readU32());
        const nonce = try r.readU64();
        const td = try Difficulty.read(r);
        const sender = try PeerAddr.read(r);
        const receiver = try PeerAddr.read(r);
        const ua = try r.readBytesLenPrefix();
        if (!std.unicode.utf8ValidateSlice(ua)) return error.CorruptedData;
        const genesis = try Hash.read(r);
        return .{ .version = version, .capabilities = caps, .nonce = nonce, .genesis = genesis, .total_difficulty = td, .sender_addr = sender, .receiver_addr = receiver, .user_agent = ua };
    }
};

pub const Shake = struct {
    version: ser.ProtocolVersion,
    capabilities: Capabilities,
    genesis: Hash,
    total_difficulty: Difficulty,
    user_agent: []const u8,

    pub fn write(self: Shake, w: anytype) ser.Error!void {
        try self.version.write(w);
        try ser.writeU32(w, self.capabilities.bits);
        try self.total_difficulty.write(w);
        try ser.writeBytes(w, self.user_agent);
        try self.genesis.write(w);
    }

    pub fn read(r: *ser.Reader) ser.Error!Shake {
        const version = try ser.ProtocolVersion.read(r);
        const caps = Capabilities.fromBitsTruncate(try r.readU32());
        const td = try Difficulty.read(r);
        const ua = try r.readBytesLenPrefix();
        if (!std.unicode.utf8ValidateSlice(ua)) return error.CorruptedData;
        const genesis = try Hash.read(r);
        return .{ .version = version, .capabilities = caps, .genesis = genesis, .total_difficulty = td, .user_agent = ua };
    }
};

// ------------------------------------------------------- simple messages

pub const Ping = struct {
    total_difficulty: Difficulty,
    height: u64,
    local_timestamp: i64,

    pub fn write(self: Ping, w: anytype) ser.Error!void {
        try self.total_difficulty.write(w);
        try ser.writeU64(w, self.height);
        try ser.writeI64(w, self.local_timestamp);
    }
    pub fn read(r: *ser.Reader) ser.Error!Ping {
        return .{ .total_difficulty = try Difficulty.read(r), .height = try r.readU64(), .local_timestamp = try r.readI64() };
    }
};
/// Pong has the same layout as Ping.
pub const Pong = Ping;

/// A list of block hashes, newest first, to find a common ancestor.
pub const Locator = struct {
    hashes: []const Hash,

    pub fn write(self: Locator, w: anytype) ser.Error!void {
        try ser.writeU8(w, @intCast(self.hashes.len));
        for (self.hashes) |h| try h.write(w);
    }

    /// The hash slice is allocated from the reader's allocator.
    pub fn read(r: *ser.Reader) ser.Error!Locator {
        const len = try r.readU8();
        if (len > MAX_LOCATORS) return error.TooLargeRead;
        const hs = try r.gpa.alloc(Hash, len);
        errdefer r.gpa.free(hs);
        for (hs) |*h| h.* = try Hash.read(r);
        return .{ .hashes = hs };
    }
};

/// Locator plus a window offset (`GetHeadersFastSync`): the reply starts
/// `offset * 512` headers after the located header.
pub const LocatorFastSync = struct {
    hashes: []const Hash,
    offset: u8,

    pub fn write(self: LocatorFastSync, w: anytype) ser.Error!void {
        try ser.writeU8(w, @intCast(self.hashes.len));
        for (self.hashes) |h| try h.write(w);
        try ser.writeU8(w, self.offset);
    }

    /// The hash slice is allocated from the reader's allocator.
    pub fn read(r: *ser.Reader) ser.Error!LocatorFastSync {
        const l = try Locator.read(r);
        errdefer r.gpa.free(l.hashes);
        return .{ .hashes = l.hashes, .offset = try r.readU8() };
    }
};

/// A batch of headers (`Headers` and `FastHeaders` share this layout).
pub const Headers = struct {
    headers: []block.BlockHeader,

    pub fn write(self: Headers, w: anytype) ser.Error!void {
        try ser.writeU16(w, @intCast(self.headers.len));
        for (self.headers) |h| try h.write(w);
    }

    pub fn read(r: *ser.Reader) ser.Error!Headers {
        const len = try r.readU16();
        if (len > MAX_BLOCK_HEADERS) return error.TooLargeRead;
        const hs = try r.gpa.alloc(block.BlockHeader, len);
        errdefer r.gpa.free(hs);
        for (hs) |*h| h.* = try block.BlockHeader.read(r);
        return .{ .headers = hs };
    }

    pub fn deinit(self: *Headers, gpa: std.mem.Allocator) void {
        gpa.free(self.headers);
    }
};

/// Request for a block/compact block by hash.
pub const HashMsg = struct {
    hash: Hash,
    pub fn write(self: HashMsg, w: anytype) ser.Error!void {
        try self.hash.write(w);
    }
    pub fn read(r: *ser.Reader) ser.Error!HashMsg {
        return .{ .hash = try Hash.read(r) };
    }
};

/// Asks a peer for its txhashset archive (the peer picks the header).
pub const TxHashSetRequest = struct {
    hash: Hash,
    height: u64,
    pub fn write(self: TxHashSetRequest, w: anytype) ser.Error!void {
        try self.hash.write(w);
        try ser.writeU64(w, self.height);
    }
};

/// Announces an archive: the header it is at, and how many bytes of zip follow.
pub const TxHashSetArchive = struct {
    hash: Hash,
    height: u64,
    bytes: u64,
    pub fn write(self: TxHashSetArchive, w: anytype) ser.Error!void {
        try self.hash.write(w);
        try ser.writeU64(w, self.height);
        try ser.writeU64(w, self.bytes);
    }
    pub fn read(r: *ser.Reader) ser.Error!TxHashSetArchive {
        return .{ .hash = try Hash.read(r), .height = try r.readU64(), .bytes = try r.readU64() };
    }
};

/// `GetPeerAddrs`: the capabilities the requester wants.
pub const GetPeerAddrs = struct {
    capabilities: Capabilities,
    pub fn read(r: *ser.Reader) ser.Error!GetPeerAddrs {
        return .{ .capabilities = Capabilities.fromBitsTruncate(try r.readU32()) };
    }
    pub fn write(self: GetPeerAddrs, w: anytype) ser.Error!void {
        try ser.writeU32(w, self.capabilities.bits);
    }
};

/// A list of peer addresses.
pub const PeerAddrs = struct {
    peers: []const PeerAddr,

    /// The slice is allocated from the reader's allocator.
    pub fn read(r: *ser.Reader) ser.Error!PeerAddrs {
        const n = try r.readU32();
        if (n > MAX_PEER_ADDRS) return error.TooLargeRead;
        const out = try r.gpa.alloc(PeerAddr, n);
        errdefer r.gpa.free(out);
        for (out) |*a| a.* = try PeerAddr.read(r);
        return .{ .peers = out };
    }

    pub fn write(self: PeerAddrs, w: anytype) ser.Error!void {
        try ser.writeU32(w, @intCast(self.peers.len));
        for (self.peers) |p| try p.write(w);
    }
};

pub const PeerError = struct {
    code: u32,
    message: []const u8,
    pub fn read(r: *ser.Reader) ser.Error!PeerError {
        const code = try r.readU32();
        const m = try r.readBytesLenPrefix();
        return .{ .code = code, .message = m };
    }
};

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "message header framing" {
    const gpa = testing.allocator;
    const framed = try encode(gpa, .mainnet, .get_block, HashMsg{ .hash = Hash.fromVec(&.{7}) }, ser.ProtocolVersion.local());
    defer gpa.free(framed);
    try testing.expectEqual(@as(usize, 11 + 32), framed.len);
    try testing.expectEqual(@as(u8, 97), framed[0]);
    try testing.expectEqual(@as(u8, 61), framed[1]);
    try testing.expectEqual(@as(u8, 10), framed[2]);
    const h = try MsgHeader.parse(.mainnet, framed[0..11]);
    try testing.expectEqual(MsgType.get_block, h.msg_type);
    try testing.expectEqual(@as(u64, 32), h.msg_len);
    try testing.expectError(error.BadMagic, MsgHeader.parse(.floonet, framed[0..11]));
    var big: [11]u8 = framed[0..11].*;
    std.mem.writeInt(u64, big[3..11], 32 * 4 + 1, .big);
    try testing.expectError(error.TooLarge, MsgHeader.parse(.mainnet, &big));
}

test "hand and shake round trip" {
    const gpa = testing.allocator;
    const g = block.genesisMain().hash();
    const hand: Hand = .{
        .version = ser.ProtocolVersion.local(),
        .capabilities = .{ .bits = Capabilities.FULL_NODE },
        .nonce = 0xdeadbeef,
        .genesis = g,
        .total_difficulty = Difficulty.number(5),
        .sender_addr = .{ .v4 = .{ .ip = .{ 127, 0, 0, 1 }, .port = 3414 } },
        .receiver_addr = .{ .v6 = .{ .segments = .{ 0, 0, 0, 0, 0, 0, 0, 1 }, .port = 3414 } },
        .user_agent = USER_AGENT,
    };
    const bytes = try ser.serVec(gpa, hand, ser.ProtocolVersion.local());
    defer gpa.free(bytes);
    var r = ser.Reader.init(gpa, bytes, ser.ProtocolVersion.local());
    const back = try Hand.read(&r);
    try testing.expectEqual(hand.nonce, back.nonce);
    try testing.expect(back.genesis.eql(g));
    try testing.expectEqualStrings(USER_AGENT, back.user_agent);
    try testing.expectEqual(@as(u16, 3414), back.receiver_addr.port());
    try testing.expectEqual(@as(usize, 0), r.remaining());

    const shake: Shake = .{ .version = hand.version, .capabilities = hand.capabilities, .genesis = g, .total_difficulty = hand.total_difficulty, .user_agent = USER_AGENT };
    const sb = try ser.serVec(gpa, shake, ser.ProtocolVersion.local());
    defer gpa.free(sb);
    var r2 = ser.Reader.init(gpa, sb, ser.ProtocolVersion.local());
    try testing.expect((try Shake.read(&r2)).genesis.eql(g));
}

test "locator and headers" {
    const gpa = testing.allocator;
    const hs = [_]Hash{ Hash.fromVec(&.{1}), Hash.fromVec(&.{2}) };
    const bytes = try ser.serVec(gpa, Locator{ .hashes = &hs }, ser.ProtocolVersion.local());
    defer gpa.free(bytes);
    try testing.expectEqual(@as(usize, 1 + 64), bytes.len);
    var r = ser.Reader.init(gpa, bytes, ser.ProtocolVersion.local());
    const l = try Locator.read(&r);
    defer gpa.free(l.hashes);
    try testing.expectEqual(@as(usize, 2), l.hashes.len);

    var hdrs = [_]block.BlockHeader{block.genesisMain().header};
    const hb = try ser.serVec(gpa, Headers{ .headers = &hdrs }, ser.ProtocolVersion.local());
    defer gpa.free(hb);
    var r2 = ser.Reader.init(gpa, hb, ser.ProtocolVersion.local());
    var back = try Headers.read(&r2);
    defer back.deinit(gpa);
    try testing.expect(back.headers[0].hash().eql(hdrs[0].hash()));
}
