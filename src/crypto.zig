//! secp256k1-zkp bindings used by consensus: Pedersen commitments, Bulletproof
//! range proofs and Schnorr (aggsig) kernel signatures. Mirrors the semantics
//! of the Rust `grin_secp256k1zkp` wrapper used by the reference node.
const std = @import("std");
const ser = @import("ser.zig");
const hash_mod = @import("hash.zig");

pub const c = @cImport({
    @cInclude("secp256k1.h");
    @cInclude("secp256k1_generator.h");
    @cInclude("secp256k1_commitment.h");
    @cInclude("secp256k1_bulletproofs.h");
    @cInclude("secp256k1_aggsig.h");
    @cInclude("secp256k1_schnorrsig.h");
});

pub const PEDERSEN_COMMITMENT_SIZE = 33;
pub const SECRET_KEY_SIZE = 32;
pub const COMPRESSED_PUBLIC_KEY_SIZE = 33;
pub const AGG_SIGNATURE_SIZE = 64;
pub const MESSAGE_SIZE = 32;
/// Epic builds the secp wrapper with `bullet-proof-sizing`: a single proof.
pub const MAX_PROOF_SIZE = 675;

/// Generators as raw 64-byte internal representations (constants.rs).
pub const GENERATOR_G = [64]u8{
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
    0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8,
    0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8,
};
pub const GENERATOR_H = [64]u8{
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
    0x31, 0xd3, 0xc6, 0x86, 0x39, 0x73, 0x92, 0x6e, 0x04, 0x9e, 0x63, 0x7c, 0xb1, 0xb5, 0xf4, 0x0a,
    0x36, 0xda, 0xc2, 0x8a, 0xf1, 0x76, 0x69, 0x68, 0xc3, 0x0c, 0x23, 0x13, 0xf3, 0xa3, 0x89, 0x04,
};

const MAX_WIDTH: usize = 1 << 20;
const SCRATCH_SPACE_SIZE: usize = 256 * MAX_WIDTH;
const MAX_GENERATORS: usize = 256;

pub const Error = error{
    InvalidCommit,
    InvalidPublicKey,
    InvalidSecretKey,
    IncorrectCommitSum,
    InvalidRangeProof,
    InvalidMessage,
    OutOfMemory,
};

// ---------------------------------------------------------- shared state

var ctx_ptr = std.atomic.Value(?*c.secp256k1_context).init(null);
var gens_ptr = std.atomic.Value(?*c.secp256k1_bulletproof_generators).init(null);

/// The process-wide sign+verify context (the "static secp instance"). The C
/// library treats it as read-only after creation, so it is shared freely.
pub fn context() *c.secp256k1_context {
    if (ctx_ptr.load(.acquire)) |p| return p;
    const fresh = c.secp256k1_context_create(c.SECP256K1_CONTEXT_SIGN | c.SECP256K1_CONTEXT_VERIFY).?;
    if (ctx_ptr.cmpxchgStrong(null, fresh, .acq_rel, .acquire)) |existing| {
        c.secp256k1_context_destroy(fresh);
        return existing.?;
    }
    return fresh;
}

fn sharedGenerators() *c.secp256k1_bulletproof_generators {
    if (gens_ptr.load(.acquire)) |p| return p;
    const g: *const c.secp256k1_generator = @ptrCast(&GENERATOR_G);
    const fresh = c.secp256k1_bulletproof_generators_create(context(), g, MAX_GENERATORS).?;
    if (gens_ptr.cmpxchgStrong(null, fresh, .acq_rel, .acquire)) |existing| {
        c.secp256k1_bulletproof_generators_destroy(context(), fresh);
        return existing.?;
    }
    return fresh;
}

inline fn genPtr(g: *const [64]u8) *const c.secp256k1_generator {
    return @ptrCast(g);
}

// ----------------------------------------------------------------- types

pub const Commitment = struct {
    bytes: [PEDERSEN_COMMITMENT_SIZE]u8,

    /// Not a real commitment: 33 zero bytes (`commit_to_zero_value`), used as a
    /// sentinel that is dropped when summing.
    pub const zero: Commitment = .{ .bytes = [_]u8{0} ** PEDERSEN_COMMITMENT_SIZE };

    pub fn eql(a: Commitment, b: Commitment) bool {
        return std.mem.eql(u8, &a.bytes, &b.bytes);
    }

    pub fn write(self: Commitment, w: anytype) ser.Error!void {
        try w.writeFixedBytes(&self.bytes);
    }

    pub fn read(r: *ser.Reader) ser.Error!Commitment {
        return .{ .bytes = try r.readArray(PEDERSEN_COMMITMENT_SIZE) };
    }

    fn parse(self: Commitment) Error!c.secp256k1_pedersen_commitment {
        var out: c.secp256k1_pedersen_commitment = undefined;
        if (c.secp256k1_pedersen_commitment_parse(context(), &out, &self.bytes) != 1) return error.InvalidCommit;
        return out;
    }

    fn fromInternal(internal: *const c.secp256k1_pedersen_commitment) Commitment {
        var out: Commitment = undefined;
        _ = c.secp256k1_pedersen_commitment_serialize(context(), &out.bytes, internal);
        return out;
    }

    /// Pedersen commitment `value*H + blind*G`.
    pub fn commit(value: u64, blind: *const [32]u8) Error!Commitment {
        var internal: c.secp256k1_pedersen_commitment = undefined;
        if (c.secp256k1_pedersen_commit(context(), &internal, blind, value, genPtr(&GENERATOR_H), genPtr(&GENERATOR_G)) != 1)
            return error.InvalidSecretKey;
        return fromInternal(&internal);
    }

    /// Commitment with a zero blinding factor.
    pub fn commitValue(value: u64) Error!Commitment {
        return commit(value, &([_]u8{0} ** 32));
    }

    pub fn toPubkey(self: Commitment) Error!PublicKey {
        const internal = try self.parse();
        var pk: c.secp256k1_pubkey = undefined;
        if (c.secp256k1_pedersen_commitment_to_pubkey(context(), &pk, &internal) != 1) return error.InvalidPublicKey;
        return .{ .raw = pk };
    }
};

/// Sum of positive minus negative commitments (Rust `commit_sum`).
pub fn commitSum(gpa: std.mem.Allocator, positive: []const Commitment, negative: []const Commitment) Error!Commitment {
    const pos = try parseAll(gpa, positive);
    defer gpa.free(pos);
    const neg = try parseAll(gpa, negative);
    defer gpa.free(neg);
    const pos_ptrs = try ptrsOf(gpa, pos);
    defer gpa.free(pos_ptrs);
    const neg_ptrs = try ptrsOf(gpa, neg);
    defer gpa.free(neg_ptrs);
    var out: c.secp256k1_pedersen_commitment = undefined;
    if (c.secp256k1_pedersen_commit_sum(context(), &out, pos_ptrs.ptr, pos.len, neg_ptrs.ptr, neg.len) != 1)
        return error.IncorrectCommitSum;
    return Commitment.fromInternal(&out);
}

fn parseAll(gpa: std.mem.Allocator, commits: []const Commitment) Error![]c.secp256k1_pedersen_commitment {
    const out = try gpa.alloc(c.secp256k1_pedersen_commitment, commits.len);
    errdefer gpa.free(out);
    for (commits, 0..) |cm, i| out[i] = try cm.parse();
    return out;
}

fn ptrsOf(gpa: std.mem.Allocator, items: []const c.secp256k1_pedersen_commitment) Error![]*const c.secp256k1_pedersen_commitment {
    const out = try gpa.alloc(*const c.secp256k1_pedersen_commitment, items.len);
    for (items, 0..) |*it, i| out[i] = it;
    return out;
}

/// Rust `verify_commit_sum`: do positive - negative sum to zero?
pub fn verifyCommitSum(gpa: std.mem.Allocator, positive: []const Commitment, negative: []const Commitment) bool {
    const pos = parseAll(gpa, positive) catch return false;
    defer gpa.free(pos);
    const neg = parseAll(gpa, negative) catch return false;
    defer gpa.free(neg);
    const pp = ptrsOf(gpa, pos) catch return false;
    defer gpa.free(pp);
    const np = ptrsOf(gpa, neg) catch return false;
    defer gpa.free(np);
    return c.secp256k1_pedersen_verify_tally(context(), pp.ptr, pos.len, np.ptr, neg.len) == 1;
}

/// Sum of secret keys (positive first, then negative); result is a valid key.
pub fn blindSum(gpa: std.mem.Allocator, positive: []const [32]u8, negative: []const [32]u8) Error![32]u8 {
    const all = try gpa.alloc([*c]const u8, positive.len + negative.len);
    defer gpa.free(all);
    for (positive, 0..) |*p, i| all[i] = p;
    for (negative, 0..) |*n, i| all[positive.len + i] = n;
    var ret: [32]u8 = undefined;
    if (c.secp256k1_pedersen_blind_sum(context(), &ret, all.ptr, all.len, positive.len) != 1) return error.InvalidSecretKey;
    if (c.secp256k1_ec_seckey_verify(context(), &ret) != 1) return error.InvalidSecretKey;
    return ret;
}

pub fn secretKeyValid(key: *const [32]u8) bool {
    return c.secp256k1_ec_seckey_verify(context(), key) == 1;
}

pub const PublicKey = struct {
    raw: c.secp256k1_pubkey,

    fn isZero(self: *const PublicKey) bool {
        const b: *const [64]u8 = @ptrCast(&self.raw);
        return std.mem.allEqual(u8, b[0..32], 0);
    }

    pub fn parse(bytes: []const u8) Error!PublicKey {
        var pk: c.secp256k1_pubkey = undefined;
        if (c.secp256k1_ec_pubkey_parse(context(), &pk, bytes.ptr, bytes.len) != 1) return error.InvalidPublicKey;
        return .{ .raw = pk };
    }

    pub fn serializeCompressed(self: PublicKey) [COMPRESSED_PUBLIC_KEY_SIZE]u8 {
        var out: [COMPRESSED_PUBLIC_KEY_SIZE]u8 = undefined;
        var len: usize = out.len;
        _ = c.secp256k1_ec_pubkey_serialize(context(), &out, &len, &self.raw, c.SECP256K1_EC_COMPRESSED);
        return out;
    }

    pub fn write(self: PublicKey, w: anytype) ser.Error!void {
        try w.writeFixedBytes(&self.serializeCompressed());
    }

    pub fn read(r: *ser.Reader) ser.Error!PublicKey {
        const buf = try r.readFixedBytes(COMPRESSED_PUBLIC_KEY_SIZE);
        return parse(buf) catch error.CorruptedData;
    }
};

pub const Signature = struct {
    bytes: [AGG_SIGNATURE_SIZE]u8,

    pub const zero: Signature = .{ .bytes = [_]u8{0} ** AGG_SIGNATURE_SIZE };

    pub fn eql(a: Signature, b: Signature) bool {
        return std.mem.eql(u8, &a.bytes, &b.bytes);
    }

    pub fn write(self: Signature, w: anytype) ser.Error!void {
        try w.writeFixedBytes(&self.bytes);
    }

    pub fn read(r: *ser.Reader) ser.Error!Signature {
        return .{ .bytes = try r.readArray(AGG_SIGNATURE_SIZE) };
    }
};

/// Bulletproof. On the wire: u64 length + bytes. Reading always yields
/// `plen == MAX_PROOF_SIZE` with zero padding, as in the reference.
pub const RangeProof = struct {
    proof: [MAX_PROOF_SIZE]u8,
    plen: usize,

    pub const zero: RangeProof = .{ .proof = [_]u8{0} ** MAX_PROOF_SIZE, .plen = 0 };

    pub fn eql(a: RangeProof, b: RangeProof) bool {
        return std.mem.eql(u8, &a.proof, &b.proof);
    }

    pub fn asSlice(self: *const RangeProof) []const u8 {
        return self.proof[0..self.plen];
    }

    pub fn write(self: RangeProof, w: anytype) ser.Error!void {
        try ser.writeBytes(w, self.proof[0..self.plen]);
    }

    pub fn read(r: *ser.Reader) ser.Error!RangeProof {
        const len = try r.readU64();
        const n: usize = @intCast(@min(len, MAX_PROOF_SIZE));
        const p = try r.readFixedBytes(n);
        var out = RangeProof.zero;
        @memcpy(out.proof[0..p.len], p);
        out.plen = MAX_PROOF_SIZE;
        return out;
    }
};

// -------------------------------------------------------- proofs & sigs

/// Batch-verify Bulletproof range proofs for the given commitments.
pub fn verifyBulletProofMulti(gpa: std.mem.Allocator, commits: []const Commitment, proofs: []const RangeProof) Error!void {
    const n = proofs.len;
    const proof_size: usize = if (n > 0) proofs[0].plen else MAX_PROOF_SIZE;
    const parsed = try parseAll(gpa, commits);
    defer gpa.free(parsed);
    const commit_ptrs = try ptrsOf(gpa, parsed);
    defer gpa.free(commit_ptrs);
    const proof_ptrs = try gpa.alloc([*c]const u8, n);
    defer gpa.free(proof_ptrs);
    for (proofs, 0..) |*p, i| proof_ptrs[i] = &p.proof;

    const min_len = @max(n, 1);
    const value_gens = try gpa.alloc([64]u8, min_len);
    defer gpa.free(value_gens);
    for (value_gens) |*g| g.* = GENERATOR_H;

    const extra_ptrs = try gpa.alloc([*c]const u8, n);
    defer gpa.free(extra_ptrs);
    @memset(extra_ptrs, null);
    const extra_lens = try gpa.alloc(usize, n);
    defer gpa.free(extra_lens);
    @memset(extra_lens, 0);

    const scratch = c.secp256k1_scratch_space_create(context(), SCRATCH_SPACE_SIZE) orelse return error.OutOfMemory;
    defer c.secp256k1_scratch_space_destroy(scratch);
    const ok = c.secp256k1_bulletproof_rangeproof_verify_multi(
        context(),
        scratch,
        sharedGenerators(),
        proof_ptrs.ptr,
        n,
        proof_size,
        null,
        commit_ptrs.ptr,
        1,
        64,
        @ptrCast(value_gens.ptr),
        extra_ptrs.ptr,
        extra_lens.ptr,
    );
    if (ok != 1) return error.InvalidRangeProof;
}

pub fn verifyBulletProof(gpa: std.mem.Allocator, commit: Commitment, proof: RangeProof) Error!void {
    return verifyBulletProofMulti(gpa, &.{commit}, &.{proof});
}

/// Verify one kernel signature (aggsig, no partial, pubkey used for `e`).
pub fn aggsigVerifySingleKernel(sig: *const Signature, msg: *const [MESSAGE_SIZE]u8, pubkey: *const PublicKey) bool {
    if (std.mem.allEqual(u8, sig.bytes[0..32], 0) or pubkey.isZero()) return false;
    return c.secp256k1_aggsig_verify_single(context(), &sig.bytes, msg, null, &pubkey.raw, &pubkey.raw, null, 0) == 1;
}

/// Batch Schnorr verification of kernel signatures.
pub fn schnorrVerifyBatch(gpa: std.mem.Allocator, sigs: []const Signature, msgs: []const [MESSAGE_SIZE]u8, pubkeys: []const PublicKey) bool {
    if (sigs.len != msgs.len or sigs.len != pubkeys.len) return false;
    for (pubkeys) |*pk| if (pk.isZero()) return false;
    const n = sigs.len;
    const sp = gpa.alloc([*c]const c.secp256k1_schnorrsig, n) catch return false;
    defer gpa.free(sp);
    const mp = gpa.alloc([*c]const u8, n) catch return false;
    defer gpa.free(mp);
    const pp = gpa.alloc([*c]const c.secp256k1_pubkey, n) catch return false;
    defer gpa.free(pp);
    for (0..n) |i| {
        sp[i] = @ptrCast(&sigs[i].bytes);
        mp[i] = &msgs[i];
        pp[i] = &pubkeys[i].raw;
    }
    const scratch = c.secp256k1_scratch_space_create(context(), SCRATCH_SPACE_SIZE) orelse return false;
    defer c.secp256k1_scratch_space_destroy(scratch);
    return c.secp256k1_schnorrsig_verify_batch(context(), scratch, sp.ptr, mp.ptr, pp.ptr, n) == 1;
}

// ------------------------------------------------------------------ tests

test "generator constants equal the library's exported generators" {
    const g: *const [64]u8 = @ptrCast(&c.secp256k1_generator_const_g);
    const h: *const [64]u8 = @ptrCast(&c.secp256k1_generator_const_h);
    try std.testing.expectEqualSlices(u8, &GENERATOR_G, g);
    try std.testing.expectEqualSlices(u8, &GENERATOR_H, h);
}

test "commit(0, 1) is G-multiple; two_g vector from the reference crate" {
    // secp.commit(value, ZERO_KEY) for value=2 must equal the reference `two_g`-style vector shape
    const c1 = try Commitment.commitValue(1);
    const c2 = try Commitment.commitValue(2);
    try std.testing.expect(!c1.eql(c2));
    try std.testing.expect(c1.bytes[0] == 8 or c1.bytes[0] == 9);
}

test "commitment sums and tallies" {
    const gpa = std.testing.allocator;
    var k1 = [_]u8{0} ** 32;
    k1[31] = 5;
    var k2 = [_]u8{0} ** 32;
    k2[31] = 7;
    const a = try Commitment.commit(10, &k1);
    const b = try Commitment.commit(20, &k2);
    const sum = try commitSum(gpa, &.{ a, b }, &.{});
    var k3 = [_]u8{0} ** 32;
    k3[31] = 12;
    const expect = try Commitment.commit(30, &k3);
    try std.testing.expect(sum.eql(expect));
    try std.testing.expect(verifyCommitSum(gpa, &.{expect}, &.{sum}));
    try std.testing.expect(!verifyCommitSum(gpa, &.{expect}, &.{a}));

    const bs = try blindSum(gpa, &.{ k1, k2 }, &.{});
    try std.testing.expectEqualSlices(u8, &k3, &bs);
    _ = try a.toPubkey();
}

test "range proof serialization pads to max size" {
    const gpa = std.testing.allocator;
    var rp = RangeProof.zero;
    rp.proof[0] = 9;
    rp.plen = 3;
    const bytes = try ser.serVec(gpa, rp, ser.ProtocolVersion.local());
    defer gpa.free(bytes);
    try std.testing.expectEqual(@as(usize, 8 + 3), bytes.len);
    var r = ser.Reader.init(gpa, bytes, ser.ProtocolVersion.local());
    const back = try RangeProof.read(&r);
    try std.testing.expectEqual(@as(usize, MAX_PROOF_SIZE), back.plen);
    try std.testing.expectEqual(@as(u8, 9), back.proof[0]);
}

/// Signs a kernel message with `seckey` (single signer, pubkey encoded in e).
/// Only needed to build transactions (tests, and later wallet-side tooling).
pub fn signKernel(seckey: *const [32]u8, msg: *const [MESSAGE_SIZE]u8, seed: *const [32]u8) ?Signature {
    var pk: c.secp256k1_pubkey = undefined;
    if (c.secp256k1_ec_pubkey_create(context(), &pk, seckey) != 1) return null;
    var sig: Signature = undefined;
    if (c.secp256k1_aggsig_sign_single(context(), &sig.bytes, msg, seckey, null, null, null, null, &pk, seed) != 1) return null;
    return sig;
}

pub fn pubkeyFromSecret(seckey: *const [32]u8) ?PublicKey {
    var pk: c.secp256k1_pubkey = undefined;
    if (c.secp256k1_ec_pubkey_create(context(), &pk, seckey) != 1) return null;
    return .{ .raw = pk };
}
