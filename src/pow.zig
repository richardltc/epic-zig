//! Header proof-of-work verification and difficulty-from-proof
//! (`core/src/pow.rs` and the `Difficulty::from_proof_*` helpers).
const std = @import("std");
const ser = @import("ser.zig");
const hash_mod = @import("hash.zig");
const consensus = @import("consensus.zig");
const block = @import("block.zig");
const cuckoo = @import("cuckoo.zig");
const progpow = @import("progpow.zig");
const randomx = @import("randomx.zig");
const pow_types = @import("pow_types.zig");

const Difficulty = pow_types.Difficulty;
const ChainType = consensus.ChainType;
const BlockHeader = block.BlockHeader;
const Keccak256 = std.crypto.hash.sha3.Keccak256;

pub const Error = error{
    InvalidPow,
    WrongAlgorithm,
    OutOfMemory,
} || ser.Error;

/// Owns the expensive per-algorithm state (epoch caches, VM pools).
pub const Verifier = struct {
    gpa: std.mem.Allocator,
    progpow: progpow.Manager,
    randomx: randomx.Manager,

    pub fn init(gpa: std.mem.Allocator, io: std.Io) Verifier {
        return .{ .gpa = gpa, .progpow = progpow.Manager.init(gpa, io), .randomx = randomx.Manager.init(gpa, io) };
    }

    pub fn deinit(self: *Verifier) void {
        self.progpow.deinit();
        self.randomx.deinit();
    }

    /// `pow::verify_size`: checks the proof in `header` is valid for its
    /// contents (not that it meets any difficulty target).
    pub fn verifySize(self: *Verifier, header: BlockHeader) Error!void {
        const pre_pow = try header.prePow(self.gpa);
        defer self.gpa.free(pre_pow);
        switch (header.pow.proof) {
            .progpow => |p| {
                const r = try self.progpowOf(pre_pow, header.height, header.pow.nonce);
                if (!std.mem.eql(u8, &r.mixBytes(), &p.mix)) return error.InvalidPow;
            },
            .randomx => |p| {
                const h = self.randomx.hash(header.pow.seed, pre_pow) catch return error.OutOfMemory;
                if (!std.mem.eql(u8, &h, &p.hash)) return error.InvalidPow;
            },
            .cuckoo => |*c| {
                const keys = try cuckoo.siphashKeys(self.gpa, pre_pow, null);
                cuckoo.verify(keys, c.edge_bits, c.nonces[0..c.n]) catch return error.InvalidPow;
            },
        }
    }

    /// `verifySize` and `toDifficulty` in one pass, computing each expensive
    /// hash only once. Returns the difficulty of the proof.
    pub fn verifyWithDifficulty(self: *Verifier, chain: ChainType, header: BlockHeader) Error!Difficulty {
        const pre_pow = try header.prePow(self.gpa);
        defer self.gpa.free(pre_pow);
        switch (header.pow.proof) {
            .progpow => |p| {
                const r = try self.progpowOf(pre_pow, header.height, header.pow.nonce);
                if (!std.mem.eql(u8, &r.mixBytes(), &p.mix)) return error.InvalidPow;
                return fromProofHash(&r.digestBytes());
            },
            .randomx => |p| {
                const h = self.randomx.hash(header.pow.seed, pre_pow) catch return error.OutOfMemory;
                if (!std.mem.eql(u8, &h, &p.hash)) return error.InvalidPow;
                return fromProofHash(&p.hash);
            },
            .cuckoo => |*c| {
                const keys = try cuckoo.siphashKeys(self.gpa, pre_pow, null);
                cuckoo.verify(keys, c.edge_bits, c.nonces[0..c.n]) catch return error.InvalidPow;
                if (c.edge_bits == consensus.SECOND_POW_EDGE_BITS)
                    return fromNum(scaledDifficulty(header.pow.proof, header.pow.secondary_scaling));
                return fromNum(scaledDifficulty(header.pow.proof, consensus.graphWeight(chain, header.height, c.edge_bits)));
            },
        }
    }

    /// Verifies `headers` on all cores. `out[i]` is the difficulty of header i's
    /// proof, or null if the proof is invalid.
    pub fn verifyBatch(self: *Verifier, chain: ChainType, headers: []const BlockHeader, out: []?Difficulty) void {
        std.debug.assert(out.len == headers.len);
        const Ctx = struct {
            v: *Verifier,
            chain: ChainType,
            headers: []const BlockHeader,
            out: []?Difficulty,
            next: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),

            fn worker(ctx: *@This()) void {
                while (true) {
                    const i = ctx.next.fetchAdd(1, .monotonic);
                    if (i >= ctx.headers.len) return;
                    ctx.out[i] = ctx.v.verifyWithDifficulty(ctx.chain, ctx.headers[i]) catch null;
                }
            }
        };
        var ctx: Ctx = .{ .v = self, .chain = chain, .headers = headers, .out = out };
        const cpus = std.Thread.getCpuCount() catch 1;
        const n = @min(@min(cpus, headers.len), 32);
        if (n <= 1) {
            Ctx.worker(&ctx);
            return;
        }
        var threads: [32]std.Thread = undefined;
        var spawned: usize = 0;
        while (spawned < n - 1) : (spawned += 1) {
            threads[spawned] = std.Thread.spawn(.{}, Ctx.worker, .{&ctx}) catch break;
        }
        Ctx.worker(&ctx); // this thread works too
        for (threads[0..spawned]) |t| t.join();
    }

    /// keccak-256 of the pre-pow bytes minus the trailing nonce, then ProgPoW.
    fn progpowOf(self: *Verifier, pre_pow: []const u8, height: u64, nonce: u64) !progpow.Result {
        var h: [32]u8 = undefined;
        Keccak256.hash(pre_pow[0 .. pre_pow.len - 8], &h, .{});
        return self.progpow.compute(h, height, nonce) catch error.OutOfMemory;
    }

    /// `ProofOfWork::to_difficulty`.
    pub fn toDifficulty(self: *Verifier, chain: ChainType, header: BlockHeader) Error!Difficulty {
        switch (header.pow.proof) {
            .cuckoo => |c| {
                if (c.edge_bits == consensus.SECOND_POW_EDGE_BITS) {
                    return fromNum(scaledDifficulty(header.pow.proof, header.pow.secondary_scaling));
                }
                return fromNum(scaledDifficulty(header.pow.proof, consensus.graphWeight(chain, header.height, c.edge_bits)));
            },
            .randomx => |p| return fromProofHash(&p.hash),
            .progpow => {
                const pre_pow = try header.prePow(self.gpa);
                defer self.gpa.free(pre_pow);
                const r = try self.progpowOf(pre_pow, header.height, header.pow.nonce);
                return fromProofHash(&r.digestBytes());
            },
        }
    }
};

fn fromNum(n: u64) Difficulty {
    return Difficulty.fromNum(n);
}

/// `((scale << 64) / max(1, hash.to_u64())).min(u64::MAX)` where the hash is
/// the proof's own protocol hash.
pub fn scaledDifficulty(proof: block.Proof, scale: u64) u64 {
    const h = @max(1, proof.hash().toU64());
    const diff = (@as(u128, scale) << 64) / h;
    return @intCast(@min(diff, std.math.maxInt(u64)));
}

/// `Difficulty::from_proof_hash`: (2^256 - 1) / hash, saturated to u64, for
/// every algorithm. An all-zero hash would divide by zero (a panic in the
/// reference); we treat it as maximum difficulty.
pub fn fromProofHash(hash: *const [32]u8) Difficulty {
    const d = std.mem.readInt(u256, hash, .big);
    if (d == 0) return Difficulty.number(std.math.maxInt(u64));
    const result = std.math.maxInt(u256) / d;
    return Difficulty.number(@intCast(@min(result, std.math.maxInt(u64))));
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

// Note: the reference never verifies genesis PoW (genesis is stored directly and
// the mainnet genesis is a placeholder), so genesis proofs are not valid cycles.
// The cuckoo path is covered by the reference solutions in cuckoo.zig; the
// header -> pre_pow -> siphash key wiring is first exercised by real chain data.

test "randomx proof is checked against the header" {
    var v = Verifier.init(testing.allocator, testing.io);
    defer v.deinit();
    var h = block.BlockHeader.default(.mainnet);
    h.height = 100;
    h.version = 6;
    const pre_pow = try h.prePow(testing.allocator);
    defer testing.allocator.free(pre_pow);
    const good = try v.randomx.hash(h.pow.seed, pre_pow);
    h.pow.proof = .{ .randomx = .{ .hash = good } };
    try v.verifySize(h);
    // the difficulty is (2^256-1)/hash
    const d = try v.toDifficulty(.mainnet, h);
    const want = fromProofHash(&good);
    try testing.expect(d.eql(want));
    h.pow.proof = .{ .randomx = .{ .hash = [_]u8{7} ** 32 } };
    try testing.expectError(error.InvalidPow, v.verifySize(h));
}

test "progpow proof is checked against the header" {
    var v = Verifier.init(testing.allocator, testing.io);
    defer v.deinit();
    var h = block.BlockHeader.default(.mainnet);
    h.height = 20;
    const pre_pow = try h.prePow(testing.allocator);
    defer testing.allocator.free(pre_pow);
    const r = try v.progpowOf(pre_pow, h.height, h.pow.nonce);
    h.pow.proof = .{ .progpow = .{ .mix = r.mixBytes() } };
    try v.verifySize(h);
    const d = try v.toDifficulty(.mainnet, h);
    try testing.expect(d.eql(fromProofHash(&r.digestBytes())));
    h.pow.proof = .{ .progpow = .{ .mix = [_]u8{1} ** 32 } };
    try testing.expectError(error.InvalidPow, v.verifySize(h));
}

test "difficulty from hash saturates and cuckoo difficulty uses the graph weight" {
    // (2^256-1)/1 saturates at u64 max
    var one = [_]u8{0} ** 32;
    one[31] = 1;
    try testing.expectEqual(@as(?u64, std.math.maxInt(u64)), fromProofHash(&one).num[0]);
    // 2^255 -> 1
    var big = [_]u8{0} ** 32;
    big[0] = 0x80;
    try testing.expectEqual(@as(?u64, 1), fromProofHash(&big).num[2]);

    var v = Verifier.init(testing.allocator, testing.io);
    defer v.deinit();
    const g = block.genesisMain().header;
    const d = try v.toDifficulty(.mainnet, g);
    const expected = fromNum(scaledDifficulty(g.pow.proof, consensus.graphWeight(.mainnet, 0, 29)));
    try testing.expect(d.eql(expected));
    try testing.expect((d.num[0] orelse 0) >= 1);
}
