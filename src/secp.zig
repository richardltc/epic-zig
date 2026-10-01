//! Thin wrapper over the vendored secp256k1-zkp C library.
const std = @import("std");
pub const c = @cImport({
    @cInclude("secp256k1.h");
    @cInclude("secp256k1_generator.h");
    @cInclude("secp256k1_commitment.h");
    @cInclude("secp256k1_bulletproofs.h");
    @cInclude("secp256k1_aggsig.h");
});

test "context creates and a pedersen commitment round-trips" {
    const ctx = c.secp256k1_context_create(c.SECP256K1_CONTEXT_SIGN | c.SECP256K1_CONTEXT_VERIFY);
    defer c.secp256k1_context_destroy(ctx);

    var blind = [_]u8{0} ** 32;
    blind[31] = 1;
    var commit: c.secp256k1_pedersen_commitment = undefined;
    try std.testing.expect(c.secp256k1_pedersen_commit(ctx, &commit, &blind, 5, &c.secp256k1_generator_const_h, &c.secp256k1_generator_const_g) == 1);

    var ser: [33]u8 = undefined;
    try std.testing.expect(c.secp256k1_pedersen_commitment_serialize(ctx, &ser, &commit) == 1);
    try std.testing.expect(ser[0] == 8 or ser[0] == 9);
}
