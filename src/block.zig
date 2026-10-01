//! Proof-of-work proofs, block headers and blocks. Port of
//! `core/src/core/block.rs`, the `ProofOfWork`/`Proof` parts of
//! `pow/types.rs`, and `genesis.rs`.
const std = @import("std");
const ser = @import("ser.zig");
const hash_mod = @import("hash.zig");
const crypto = @import("crypto.zig");
const consensus = @import("consensus.zig");
const tx = @import("transaction.zig");
const pow_types = @import("pow_types.zig");
const feijoada = @import("feijoada.zig");

const Hash = hash_mod.Hash;
const Commitment = crypto.Commitment;
const ChainType = consensus.ChainType;
const Difficulty = pow_types.Difficulty;
const PoWType = pow_types.PoWType;
const Policy = feijoada.Policy;
const BlindingFactor = tx.BlindingFactor;

pub const MAX_PROOF_NONCES = 42;

pub const Error = tx.Error || error{
    InvalidTotalKernelSum,
    CoinbaseSumMismatch,
    InvalidFoundationOutput,
    WeightExceeded,
    KernelLockHeight,
    FoundationUnavailable,
};

// ------------------------------------------------------------------ proof

/// A proof of work. Cuckoo proofs hold the cycle's nonces (bit-packed on the
/// wire); RandomX carries the hash, ProgPoW the mix digest. (The reference's
/// test-only MD5 proof is not supported and is rejected as corrupted.)
pub const Proof = union(enum) {
    cuckoo: struct { edge_bits: u8, nonces: [MAX_PROOF_NONCES]u64, n: u8 },
    randomx: struct { hash: [32]u8 },
    progpow: struct { mix: [32]u8 },

    pub fn zero(proof_size: usize, min_edge_bits: u8) Proof {
        return .{ .cuckoo = .{ .edge_bits = min_edge_bits, .nonces = [_]u64{0} ** MAX_PROOF_NONCES, .n = @intCast(proof_size) } };
    }

    pub fn cuckooNonces(self: *const Proof) ?[]const u64 {
        return switch (self.*) {
            .cuckoo => |*c| c.nonces[0..c.n],
            else => null,
        };
    }

    pub fn powType(self: Proof) PoWType {
        return switch (self) {
            .cuckoo => |c| if (c.edge_bits == 19 or c.edge_bits == 31) .cuckatoo else .cuckaroo,
            .randomx => .randomx,
            .progpow => .progpow,
        };
    }

    pub fn eql(a: Proof, b: Proof) bool {
        return switch (a) {
            .cuckoo => |x| switch (b) {
                .cuckoo => |y| x.edge_bits == y.edge_bits and x.n == y.n and std.mem.eql(u64, x.nonces[0..x.n], y.nonces[0..y.n]),
                else => false,
            },
            .randomx => |x| switch (b) {
                .randomx => |y| std.mem.eql(u8, &x.hash, &y.hash),
                else => false,
            },
            .progpow => |x| switch (b) {
                .progpow => |y| std.mem.eql(u8, &x.mix, &y.mix),
                else => false,
            },
        };
    }

    pub fn hash(self: Proof) Hash {
        return hash_mod.hashOf(self);
    }

    pub fn write(self: Proof, w: anytype) ser.Error!void {
        switch (self) {
            .cuckoo => |c| {
                try ser.writeU8(w, 0);
                if (w.mode != .hash) try ser.writeU8(w, c.edge_bits);
                const nonce_bits: usize = c.edge_bits;
                var buf = [_]u8{0} ** ((64 * MAX_PROOF_NONCES + 7) / 8);
                const bits_len = nonce_bits * c.n;
                for (c.nonces[0..c.n], 0..) |nonce, n| {
                    var bit: usize = 0;
                    while (bit < nonce_bits) : (bit += 1) {
                        if (nonce & (@as(u64, 1) << @intCast(bit)) != 0) {
                            const pos = n * nonce_bits + bit;
                            buf[pos / 8] |= @as(u8, 1) << @intCast(pos % 8);
                        }
                    }
                }
                try w.writeFixedBytes(buf[0 .. (bits_len + 7) / 8]);
            },
            .randomx => |p| {
                try ser.writeU8(w, 2);
                try w.writeFixedBytes(&p.hash);
            },
            .progpow => |p| {
                try ser.writeU8(w, 3);
                try w.writeFixedBytes(&p.mix);
            },
        }
    }

    pub fn read(r: *ser.Reader) ser.Error!Proof {
        switch (try r.readU8()) {
            0 => {
                const edge_bits = try r.readU8();
                if (edge_bits == 0 or edge_bits > 64) return error.CorruptedData;
                const proof_size = r.params.proof_size;
                if (proof_size > MAX_PROOF_NONCES) return error.CorruptedData;
                const nonce_bits: usize = edge_bits;
                const bits_len = nonce_bits * proof_size;
                const bytes_len = (bits_len + 7) / 8;
                const bits = try r.readFixedBytes(bytes_len);
                var nonces = [_]u64{0} ** MAX_PROOF_NONCES;
                for (0..proof_size) |n| {
                    var nonce: u64 = 0;
                    for (0..nonce_bits) |bit| {
                        const pos = n * nonce_bits + bit;
                        if (bits[pos / 8] & (@as(u8, 1) << @intCast(pos % 8)) != 0) nonce |= @as(u64, 1) << @intCast(bit);
                    }
                    nonces[n] = nonce;
                }
                var pos = bits_len;
                while (pos < bytes_len * 8) : (pos += 1) {
                    if (bits[pos / 8] & (@as(u8, 1) << @intCast(pos % 8)) != 0) return error.CorruptedData;
                }
                return .{ .cuckoo = .{ .edge_bits = edge_bits, .nonces = nonces, .n = @intCast(proof_size) } };
            },
            2 => return .{ .randomx = .{ .hash = try r.readArray(32) } },
            3 => return .{ .progpow = .{ .mix = try r.readArray(32) } },
            else => return error.CorruptedData,
        }
    }
};

// -------------------------------------------------------- proof of work

pub const ProofOfWork = struct {
    total_difficulty: Difficulty,
    secondary_scaling: u32,
    nonce: u64,
    proof: Proof,
    seed: [32]u8,

    pub fn default(chain: ChainType) ProofOfWork {
        return .{
            .total_difficulty = Difficulty.fromNum(1),
            .secondary_scaling = 1,
            .nonce = 0,
            .proof = Proof.zero(chain.proofSize(), chain.minEdgeBits()),
            .seed = [_]u8{0} ** 32,
        };
    }

    pub fn writePrePow(self: ProofOfWork, w: anytype) ser.Error!void {
        try self.total_difficulty.write(w);
        try ser.writeU32(w, self.secondary_scaling);
    }

    /// (The inherent `write` in the reference, which also writes the seed.)
    pub fn write(self: ProofOfWork, w: anytype) ser.Error!void {
        if (w.mode != .hash) {
            try self.writePrePow(w);
            try ser.writeU64(w, self.nonce);
        }
        try self.proof.write(w);
        try w.writeFixedBytes(&self.seed);
    }

    pub fn read(r: *ser.Reader) ser.Error!ProofOfWork {
        const total_difficulty = try Difficulty.read(r);
        const secondary_scaling = try r.readU32();
        const nonce = try r.readU64();
        const proof = try Proof.read(r);
        const seed = try r.readArray(32);
        return .{ .total_difficulty = total_difficulty, .secondary_scaling = secondary_scaling, .nonce = nonce, .proof = proof, .seed = seed };
    }

    pub fn edgeBits(self: ProofOfWork) u8 {
        return switch (self.proof) {
            .cuckoo => |c| c.edge_bits,
            else => 16,
        };
    }

    pub fn isPrimary(self: ProofOfWork, min_edge_bits: u8) bool {
        return switch (self.proof) {
            .cuckoo => |c| c.edge_bits != consensus.SECOND_POW_EDGE_BITS and c.edge_bits >= min_edge_bits,
            else => true,
        };
    }

    pub fn isSecondary(self: ProofOfWork) bool {
        return switch (self.proof) {
            .cuckoo => |c| c.edge_bits == consensus.SECOND_POW_EDGE_BITS,
            else => false,
        };
    }
};

// ------------------------------------------------------------ header

/// chrono NaiveDate min/max bounds, as timestamps, for the sanity check on read.
const MAX_TIMESTAMP: i64 = 8210298412799;
const MIN_TIMESTAMP: i64 = -8334632937600;

/// What is stored in the header MMR: hash plus what difficulty calculation needs.
pub const HeaderEntry = struct {
    hash: Hash,
    timestamp: u64,
    total_difficulty: Difficulty,
    secondary_scaling: u32,
    is_secondary: bool,

    pub const LEN: u16 = Hash.LEN + 8 + Difficulty.LEN + 4 + 1;

    pub fn write(self: HeaderEntry, w: anytype) ser.Error!void {
        try self.hash.write(w);
        try ser.writeU64(w, self.timestamp);
        try self.total_difficulty.write(w);
        try ser.writeU32(w, self.secondary_scaling);
        try ser.writeU8(w, @intFromBool(self.is_secondary));
    }

    pub fn read(r: *ser.Reader) ser.Error!HeaderEntry {
        const h = try Hash.read(r);
        const ts = try r.readU64();
        const td = try Difficulty.read(r);
        const ss = try r.readU32();
        const sec = (try r.readU8()) != 0;
        return .{ .hash = h, .timestamp = ts, .total_difficulty = td, .secondary_scaling = ss, .is_secondary = sec };
    }
};

pub const BlockHeader = struct {
    version: u16,
    height: u64,
    prev_hash: Hash,
    prev_root: Hash,
    /// Unix seconds.
    timestamp: i64,
    output_root: Hash,
    range_proof_root: Hash,
    kernel_root: Hash,
    total_kernel_offset: BlindingFactor,
    output_mmr_size: u64,
    kernel_mmr_size: u64,
    pow: ProofOfWork,
    policy: u8,
    bottles: Policy,

    pub const CURRENT_VERSION: u16 = 6;

    pub fn default(chain: ChainType) BlockHeader {
        return .{
            .version = CURRENT_VERSION,
            .height = 0,
            .prev_hash = Hash.zero,
            .prev_root = Hash.zero,
            .timestamp = 0,
            .output_root = Hash.zero,
            .range_proof_root = Hash.zero,
            .kernel_root = Hash.zero,
            .total_kernel_offset = BlindingFactor.zero,
            .output_mmr_size = 0,
            .kernel_mmr_size = 0,
            .pow = ProofOfWork.default(chain),
            .policy = 0,
            .bottles = Policy.default_bottles,
        };
    }

    pub fn writePrePow(self: BlockHeader, w: anytype) ser.Error!void {
        try ser.writeU64(w, self.height);
        try ser.writeI64(w, self.timestamp);
        try w.writeFixedBytes(&self.prev_hash.bytes);
        try w.writeFixedBytes(&self.prev_root.bytes);
        try w.writeFixedBytes(&self.output_root.bytes);
        try w.writeFixedBytes(&self.range_proof_root.bytes);
        try w.writeFixedBytes(&self.kernel_root.bytes);
        try w.writeFixedBytes(&self.total_kernel_offset.bytes);
        try ser.writeU64(w, self.output_mmr_size);
        try ser.writeU64(w, self.kernel_mmr_size);
    }

    /// In hash mode only version, proof, seed, policy and bottles are written
    /// (the PoW output itself commits to the rest).
    pub fn write(self: BlockHeader, w: anytype) ser.Error!void {
        try ser.writeU16(w, self.version);
        if (w.mode != .hash) try self.writePrePow(w);
        try self.pow.write(w);
        try ser.writeU8(w, self.policy);
        try self.bottles.write(w);
    }

    pub fn read(r: *ser.Reader) ser.Error!BlockHeader {
        const version = try r.readU16();
        const height = try r.readU64();
        const timestamp = try r.readI64();
        const prev_hash = try Hash.read(r);
        const prev_root = try Hash.read(r);
        const output_root = try Hash.read(r);
        const range_proof_root = try Hash.read(r);
        const kernel_root = try Hash.read(r);
        const total_kernel_offset = try BlindingFactor.read(r);
        const output_mmr_size = try r.readU64();
        const kernel_mmr_size = try r.readU64();
        const pow = try ProofOfWork.read(r);
        const policy = try r.readU8();
        const bottles = try Policy.read(r);

        if (timestamp > MAX_TIMESTAMP or timestamp < MIN_TIMESTAMP) return error.CorruptedData;
        const expected: u16 = if (height < r.params.first_fork_height) 6 else 7;
        if (version != expected) return error.InvalidBlockVersion;

        return .{
            .version = version,
            .height = height,
            .prev_hash = prev_hash,
            .prev_root = prev_root,
            .timestamp = timestamp,
            .output_root = output_root,
            .range_proof_root = range_proof_root,
            .kernel_root = kernel_root,
            .total_kernel_offset = total_kernel_offset,
            .output_mmr_size = output_mmr_size,
            .kernel_mmr_size = kernel_mmr_size,
            .pow = pow,
            .policy = policy,
            .bottles = bottles,
        };
    }

    pub fn hash(self: BlockHeader) Hash {
        return hash_mod.hashOf(self);
    }

    pub fn asEntry(self: BlockHeader) HeaderEntry {
        return .{
            .hash = self.hash(),
            .timestamp = @bitCast(self.timestamp),
            .total_difficulty = self.pow.total_difficulty,
            .secondary_scaling = self.pow.secondary_scaling,
            .is_secondary = self.pow.isSecondary(),
        };
    }

    /// Serialized bytes the miner hashes: version, pre-pow fields, pow pre-pow, nonce.
    pub fn prePow(self: BlockHeader, gpa: std.mem.Allocator) ser.Error![]u8 {
        var w = ser.VecWriter.init(gpa, ser.ProtocolVersion.local());
        errdefer w.deinit();
        try ser.writeU16(&w, self.version);
        try self.writePrePow(&w);
        try self.pow.writePrePow(&w);
        try ser.writeU64(&w, self.pow.nonce);
        return w.toOwnedSlice();
    }

    /// keccak-256 of the pre-pow header without the nonce (ProgPoW/RandomX input).
    pub fn prePowHash(self: BlockHeader, gpa: std.mem.Allocator) ser.Error![32]u8 {
        var w = ser.VecWriter.init(gpa, ser.ProtocolVersion.local());
        defer w.deinit();
        try ser.writeU16(&w, self.version);
        try self.writePrePow(&w);
        try self.pow.writePrePow(&w);
        var out: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(w.items(), &out, .{});
        return out;
    }

    /// Negated block reward (+ foundation levy at foundation heights).
    pub fn overage(self: BlockHeader, chain: ChainType) i64 {
        const r = consensus.rewardAtHeight(chain, self.height) +% consensus.addRewardFoundation(chain, self.height);
        return std.math.negate(@as(i64, @bitCast(r))) catch 0;
    }

    pub fn totalOverage(self: BlockHeader, chain: ChainType, genesis_had_reward: bool) i64 {
        return std.math.negate(consensus.totalOverageAtHeight(chain, self.height, genesis_had_reward)) catch 0;
    }
};

// ------------------------------------------------------------- block

pub const Block = struct {
    header: BlockHeader,
    body: tx.TransactionBody,

    pub fn deinit(self: *Block, gpa: std.mem.Allocator) void {
        self.body.deinit(gpa);
    }

    pub fn withHeader(header: BlockHeader) Block {
        return .{ .header = header, .body = tx.TransactionBody.empty };
    }

    pub fn write(self: Block, w: anytype) ser.Error!void {
        try self.header.write(w);
        if (w.mode != .hash) try self.body.write(w);
    }

    pub fn read(r: *ser.Reader) ser.Error!Block {
        const header = try BlockHeader.read(r);
        const body = try tx.TransactionBody.read(r);
        return .{ .header = header, .body = body };
    }

    pub fn hash(self: Block) Hash {
        return self.header.hash();
    }

    pub fn totalFees(self: Block) u64 {
        return self.body.fee();
    }

    /// Structural checks that don't need chain state (`validate_read`).
    pub fn validateRead(self: Block, gpa: std.mem.Allocator, chain: ChainType) Error!void {
        try self.body.validateRead(gpa, chain, .as_block);
        try self.verifyKernelLockHeights();
    }

    fn verifyKernelLockHeights(self: Block) Error!void {
        for (self.body.kernels) |k| switch (k.features) {
            .height_locked => |h| if (h.lock_height > self.header.height) return error.KernelLockHeight,
            else => {},
        };
    }

    fn blockKernelOffset(self: Block, gpa: std.mem.Allocator, prev: BlindingFactor) Error!BlindingFactor {
        if (self.header.total_kernel_offset.eql(prev)) return BlindingFactor.zero;
        return tx.sumKernelOffsets(gpa, &.{self.header.total_kernel_offset}, &.{prev});
    }

    /// Full validation against the previous block's kernel offset. Returns the
    /// kernel sum. `foundation` supplies the expected coinbase commitments.
    pub fn validate(self: Block, gpa: std.mem.Allocator, chain: ChainType, foundation: ?*const Foundation, prev_kernel_offset: BlindingFactor) Error!Commitment {
        try self.body.validate(gpa, chain, .as_block);
        try self.verifyKernelLockHeights();
        try self.verifyCoinbase(gpa, chain, foundation);
        const sums = try self.body.verifyKernelSums(gpa, self.header.overage(chain), try self.blockKernelOffset(gpa, prev_kernel_offset));
        return sums.kernel_sum;
    }

    pub fn verifyCoinbase(self: Block, gpa: std.mem.Allocator, chain: ChainType, foundation: ?*const Foundation) Error!void {
        var cb_outs: std.ArrayList(Commitment) = .empty;
        defer cb_outs.deinit(gpa);
        var cb_kerns: std.ArrayList(Commitment) = .empty;
        defer cb_kerns.deinit(gpa);
        for (self.body.outputs) |o| if (o.isCoinbase()) try cb_outs.append(gpa, o.commit);
        for (self.body.kernels) |k| if (k.isCoinbase()) try cb_kerns.append(gpa, k.excess);

        if (consensus.isFoundationHeight(chain, self.header.height)) {
            const f = foundation orelse return error.FoundationUnavailable;
            const want = f.commitAt(gpa, consensus.foundationIndex(chain, self.header.height)) catch return error.FoundationUnavailable;
            var found = false;
            for (cb_outs.items) |c| found = found or c.eql(want);
            if (!found) return error.InvalidFoundationOutput;
        }

        const over = try Commitment.commitValue(consensus.rewardFoundation(chain, self.totalFees(), self.header.height));
        const out_adjust_sum = try crypto.commitSum(gpa, cb_outs.items, &.{over});
        const kerns_sum = try crypto.commitSum(gpa, cb_kerns.items, &.{});
        if (!kerns_sum.eql(out_adjust_sum)) return error.CoinbaseSumMismatch;
    }
};

// -------------------------------------------------------- foundation data

/// The foundation coinbase list (`foundation.json`): one JSON object per line.
pub const Foundation = struct {
    text: []const u8,

    pub const mainnet_json = @embedFile("data/foundation.json");
    pub const floonet_json = @embedFile("data/foundation_floonet.json");

    pub fn embedded(chain: ChainType) Foundation {
        return .{ .text = if (chain == .mainnet) mainnet_json else floonet_json };
    }

    pub fn fromText(text: []const u8) Foundation {
        return .{ .text = text };
    }

    /// True if this data has the checksum the chain type expects.
    pub fn checksumOk(self: Foundation, chain: ChainType) bool {
        // The reference normalizes CRLF to LF before hashing.
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        var rest = self.text;
        while (std.mem.indexOf(u8, rest, "\r\n")) |i| {
            h.update(rest[0..i]);
            h.update("\n");
            rest = rest[i + 2 ..];
        }
        h.update(rest);
        var digest: [32]u8 = undefined;
        h.final(&digest);
        var hex: [64]u8 = undefined;
        _ = std.fmt.bufPrint(&hex, "{x}", .{digest[0..]}) catch unreachable;
        return std.mem.eql(u8, &hex, chain.foundationJsonSha256());
    }

    fn line(self: Foundation, index: u64) ?[]const u8 {
        var it = std.mem.splitScalar(u8, self.text, '\n');
        var i: u64 = 0;
        while (it.next()) |l| : (i += 1) {
            if (i == index) return l;
        }
        return null;
    }

    /// Commitment of the coinbase output at `index`.
    pub fn commitAt(self: Foundation, gpa: std.mem.Allocator, index: u64) !Commitment {
        const l = self.line(index) orelse return error.FoundationUnavailable;
        const parsed = try std.json.parseFromSlice(struct { output: struct { commit: []const u8 } }, gpa, l, .{ .ignore_unknown_fields = true });
        defer parsed.deinit();
        const hex = parsed.value.output.commit;
        if (hex.len != crypto.PEDERSEN_COMMITMENT_SIZE * 2) return error.FoundationUnavailable;
        var c: Commitment = undefined;
        _ = std.fmt.hexToBytes(&c.bytes, hex) catch return error.FoundationUnavailable;
        return c;
    }
};

// ---------------------------------------------------------------- genesis

fn hex32(comptime s: []const u8) Hash {
    var h: Hash = undefined;
    _ = std.fmt.hexToBytes(&h.bytes, s) catch unreachable;
    return h;
}

fn cuckooProof(edge_bits: u8, comptime nonces_in: []const u64) Proof {
    var nonces = [_]u64{0} ** MAX_PROOF_NONCES;
    for (nonces_in, 0..) |n, i| nonces[i] = n;
    return .{ .cuckoo = .{ .edge_bits = edge_bits, .nonces = nonces, .n = @intCast(nonces_in.len) } };
}

/// 2019-08-09 17:04:38 UTC
const GENESIS_TIMESTAMP: i64 = 1565370278;

pub fn genesisFloo() Block {
    var bottles = Policy.default_bottles;
    bottles.v[PoWType.cuckaroo.idx()] = 1;
    var diff = Difficulty.zero();
    diff.insert(.cuckaroo, 1 << 2);
    diff.insert(.cuckatoo, 1 << 14);
    diff.insert(.randomx, 1 << 13);
    diff.insert(.progpow, 1 << 26);
    var h = BlockHeader.default(.floonet);
    h.version = 6;
    h.height = 0;
    h.timestamp = GENESIS_TIMESTAMP;
    h.prev_root = hex32("00000000000000000017ff4903ef366c8f62e3151ba74e41b8332a126542f538");
    h.output_root = hex32("73b5e0a05ea9e1e4e33b8f1c723bc5c10d17f07042c2af7644f4dbb61f4bc556");
    h.range_proof_root = hex32("667a3ba22f237a875f67c9933037c8564097fa57a3e75be507916de28fc0da26");
    h.kernel_root = hex32("cfdddfe2d938d0026f8b1304442655bbdddde175ff45ddf44cb03bcb0071a72d");
    h.bottles = bottles;
    h.pow = .{
        .total_difficulty = diff,
        .secondary_scaling = 1856,
        .nonce = 23,
        .proof = cuckooProof(29, &.{
            16994232,  22975978,  32664019,  44016212,  50238216,  57272481,  85779161,  124272202, 125203242, 133907662,
            140522149, 145870823, 147481297, 164952795, 177186722, 183382201, 197418356, 211393794, 239282197, 239323031,
            250757611, 281414565, 305112109, 308151499, 357235186, 374041407, 389924708, 390768911, 401322239, 401886855,
            406986280, 416797005, 418935317, 429007407, 439527429, 484809502, 486257104, 495589543, 495892390, 525019296,
            529899691, 531685572,
        }),
        .seed = [_]u8{0} ** 32,
    };
    return Block.withHeader(h);
}

pub fn genesisMain() Block {
    var bottles = Policy.default_bottles;
    bottles.v[PoWType.cuckaroo.idx()] = 1;
    var diff = Difficulty.zero();
    diff.insert(.cuckaroo, 1 << 2);
    diff.insert(.cuckatoo, 1 << 14);
    diff.insert(.randomx, 1 << 22);
    diff.insert(.progpow, 1 << 30);
    var h = BlockHeader.default(.mainnet);
    h.version = 6;
    h.height = 0;
    h.timestamp = GENESIS_TIMESTAMP;
    h.prev_root = hex32("00000000000000000004de683e7aa4d35c51f46ec76c6852b0f3161bd1e2e00e");
    h.output_root = hex32("b10fe806a4373d9b8d8edde98a4ec39d726b542036971c2f14c0738b0605c9cd");
    h.range_proof_root = hex32("e05333e51d9294f08cd6d2d7cea19de2843f92c285a61fd5d61d771c3ac74222");
    h.kernel_root = hex32("4d9ddf437dfbb86f8563ac4e96a0d86842eda609a5125244f43261d4188292e4");
    h.bottles = bottles;
    h.pow = .{
        .total_difficulty = diff,
        .secondary_scaling = 1856,
        .nonce = 41,
        .proof = cuckooProof(29, &.{
            4391451,   36730677,  38198400,  38797304,  60700446,  72910191,  73050441,  110099816, 140885802, 145512513,
            149311222, 149994636, 157557529, 160778700, 162870981, 179649435, 194194460, 227378628, 230933064, 252046196,
            272053956, 277878683, 288331253, 290266880, 293973036, 305315023, 321927758, 353841539, 356489212, 373843111,
            381697287, 389274717, 403108317, 409994705, 411629694, 431823422, 441976653, 521469643, 521868369, 523044572,
            524964447, 530250249,
        }),
        .seed = [_]u8{0} ** 32,
    };
    return Block.withHeader(h);
}

pub fn genesisFor(chain: ChainType) Block {
    return switch (chain) {
        .mainnet => genesisMain(),
        else => genesisFloo(),
    };
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

fn fullHashV1(gpa: std.mem.Allocator, b: Block) !Hash {
    const bytes = try ser.serVec(gpa, b, ser.ProtocolVersion{ .v = 1 });
    defer gpa.free(bytes);
    return hash_mod.hashOf(@as([]const u8, bytes));
}

fn expectHash(h: Hash, hex: []const u8) !void {
    const got = h.toHex();
    try testing.expectEqualStrings(hex, &got);
}

test "floonet genesis hashes match the reference" {
    const gpa = testing.allocator;
    const g = genesisFloo();
    try expectHash(g.hash(), "95d457c669f65ee27b0c90b6b11c53d9b51eb0610b6ea8d5c2a45f96d8200c67");
    try expectHash(try fullHashV1(gpa, g), "daab5e09cbcc90a26d60d718afee61a721fe24cbdabf3bfae591f861437b8218");
}

test "mainnet genesis hashes match the reference" {
    const gpa = testing.allocator;
    const g = genesisMain();
    try expectHash(g.hash(), "454018a56d86e37611bdcabc7de670305c3f3dc9675e314b437f1adc29430851");
    try expectHash(try fullHashV1(gpa, g), "509c7dad7096678942abf510f9c07aecb457041450ff418b531ea4a0f1d67ef4");
}

test "genesis round-trips through the wire format" {
    const gpa = testing.allocator;
    const g = genesisMain();
    const bytes = try ser.serVec(gpa, g, ser.ProtocolVersion.local());
    defer gpa.free(bytes);
    var r = ser.Reader.init(gpa, bytes, ser.ProtocolVersion.local());
    r.params = ChainType.mainnet.readParams();
    var back = try Block.read(&r);
    defer back.deinit(gpa);
    try testing.expect(back.hash().eql(g.hash()));
    try testing.expect(back.header.pow.proof.eql(g.header.pow.proof));
    try testing.expectEqual(@as(usize, 0), r.remaining());
}

test "header rejects wrong version for height" {
    const gpa = testing.allocator;
    var g = genesisMain();
    g.header.version = 7;
    const bytes = try ser.serVec(gpa, g, ser.ProtocolVersion.local());
    defer gpa.free(bytes);
    var r = ser.Reader.init(gpa, bytes, ser.ProtocolVersion.local());
    try testing.expectError(error.InvalidBlockVersion, Block.read(&r));
}

test "foundation data has the expected checksum and indexes commitments" {
    const gpa = testing.allocator;
    try testing.expect(Foundation.embedded(.mainnet).checksumOk(.mainnet));
    try testing.expect(Foundation.embedded(.floonet).checksumOk(.floonet));
    const c = try Foundation.embedded(.mainnet).commitAt(gpa, 0);
    try testing.expectEqual(@as(u8, 0x09), c.bytes[0]);
    try testing.expectEqual(@as(u8, 0xfd), c.bytes[1]);
    try testing.expectError(error.FoundationUnavailable, Foundation.embedded(.mainnet).commitAt(gpa, 999_999));
}

test "cuckoo proof bit packing round trip" {
    const gpa = testing.allocator;
    const p = cuckooProof(29, &[_]u64{1} ** 42);
    const bytes = try ser.serVec(gpa, p, ser.ProtocolVersion.local());
    defer gpa.free(bytes);
    try testing.expectEqual(@as(usize, 1 + 1 + (29 * 42 + 7) / 8), bytes.len);
    var r = ser.Reader.init(gpa, bytes, ser.ProtocolVersion.local());
    try testing.expect((try Proof.read(&r)).eql(p));
}
