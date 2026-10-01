//! Which errors mean the peer sent us bad data (and gets banned) as opposed to
//! ones that are our problem or just timing (`is_bad_data` in the reference:
//! everything except unfit/orphan blocks and store, serialization or txhashset
//! failures is a ban).
const std = @import("std");

/// Errors that prove the peer broke the protocol or the consensus rules.
const bad = [_][]const u8{
    // framing and parsing
    "BadMagic",
    "TooLarge",
    "TooLargeRead",
    "CorruptedData",
    "CountError",
    "SortError",
    "DuplicateError",
    "BadHandshake",
    // header and block rules
    "InvalidBlockVersion",
    "InvalidBlockTime",
    "InvalidPow",
    "LowEdgebits",
    "InvalidSeed",
    "PolicyIsNotAllowed",
    "InvalidSortAlgo",
    "ThereIsNotPolicy",
    "InvalidBlockHeight",
    "DifficultyTooLow",
    "WrongTotalDifficulty",
    "InvalidScaling",
    "InvalidBlockProof",
    "BadHeader",
    // transaction and block body rules
    "KernelSumMismatch",
    "TooHeavy",
    "LockHeight",
    "RangeProof",
    "IncorrectSignature",
    "InvalidOutputFeatures",
    "InvalidKernelFeatures",
    "AggregationError",
    "CutThrough",
    "InvalidRoot",
    "InvalidFoundationOutput",
    "KernelLockHeight",
    "AlreadySpent",
    "DuplicateCommitment",
    "ImmatureCoinbase",
};

pub fn isBad(e: anyerror) bool {
    const name = @errorName(e);
    inline for (bad) |b| if (std.mem.eql(u8, name, b)) return true;
    return false;
}

test "protocol and consensus errors are bannable, plumbing errors are not" {
    try std.testing.expect(isBad(error.CorruptedData));
    try std.testing.expect(isBad(error.InvalidPow));
    try std.testing.expect(isBad(error.KernelSumMismatch));
    try std.testing.expect(!isBad(error.Orphan));
    try std.testing.expect(!isBad(error.EndOfStream));
    try std.testing.expect(!isBad(error.OutOfMemory));
    try std.testing.expect(!isBad(error.ReadFailed));
}
