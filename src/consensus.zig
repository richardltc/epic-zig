//! Consensus rules and parameters, ported from `core/src/consensus.rs` and
//! the parameter parts of `core/src/global.rs`. The Rust node keeps the chain
//! type in a process-wide lock; here it is an explicit `ChainType` value.
//! Integer arithmetic wraps where the Rust release build wraps.
const std = @import("std");
const ser = @import("ser.zig");
const Hash = @import("hash.zig").Hash;
const pow_types = @import("pow_types.zig");
const PoWType = pow_types.PoWType;
const Difficulty = pow_types.Difficulty;
const feijoada = @import("feijoada.zig");
const Policy = feijoada.Policy;

pub const ChainType = enum {
    automated_testing,
    user_testing,
    floonet,
    mainnet,

    /// Values the deserializer needs (see `ser.ReadParams`).
    pub fn readParams(self: ChainType) ser.ReadParams {
        return .{
            .max_block_weight = self.maxBlockWeight(),
            .first_fork_height = self.firstForkHeight(),
            .proof_size = self.proofSize(),
            .min_edge_bits = self.minEdgeBits(),
        };
    }

    pub fn shortname(self: ChainType) []const u8 {
        return switch (self) {
            .automated_testing => "auto",
            .user_testing => "user",
            .floonet => "floo",
            .mainnet => "main",
        };
    }

    pub fn isTesting(self: ChainType) bool {
        return self == .automated_testing or self == .user_testing;
    }

    pub fn minEdgeBits(self: ChainType) u8 {
        return switch (self) {
            .automated_testing => 9,
            .user_testing => 15,
            else => DEFAULT_MIN_EDGE_BITS,
        };
    }
    pub fn baseEdgeBits(self: ChainType) u8 {
        return switch (self) {
            .automated_testing => 9,
            .user_testing => 15,
            else => BASE_EDGE_BITS,
        };
    }
    pub fn proofSize(self: ChainType) usize {
        return switch (self) {
            .automated_testing => 4,
            .user_testing => 42,
            else => PROOFSIZE,
        };
    }
    pub fn coinbaseMaturity(self: ChainType) u64 {
        return switch (self) {
            .automated_testing, .user_testing => 3,
            .floonet => 30,
            .mainnet => COINBASE_MATURITY,
        };
    }
    pub fn initialBlockDifficulty(self: ChainType) u64 {
        return if (self.isTesting()) 1 else INITIAL_DIFFICULTY;
    }
    pub fn initialGraphWeight(self: ChainType) u32 {
        return if (self.isTesting()) 1 else @intCast(graphWeight(self, 0, SECOND_POW_EDGE_BITS));
    }
    pub fn maxBlockWeight(self: ChainType) usize {
        return if (self.isTesting()) 150 else MAX_BLOCK_WEIGHT;
    }
    pub fn cutThroughHorizon(self: ChainType) u32 {
        return if (self.isTesting()) 70 else CUT_THROUGH_HORIZON;
    }
    pub fn stateSyncThreshold(self: ChainType) u32 {
        return if (self.isTesting()) 20 else STATE_SYNC_THRESHOLD;
    }
    pub fn txhashsetArchiveInterval(self: ChainType) u64 {
        return if (self.isTesting()) 10 else TXHASHSET_ARCHIVE_INTERVAL;
    }
    pub fn genesisNonce(self: ChainType) u64 {
        return if (self == .user_testing) 27944 else 0;
    }
    pub fn isProduction(self: ChainType) bool {
        return self == .floonet or self == .mainnet;
    }
    pub fn foundationJsonSha256(self: ChainType) []const u8 {
        return switch (self) {
            .mainnet => "5a3a7584127dd31fba18eaeff1c551bfaa74b4e50e537a1e1904fe6730b17f5c",
            else => "503a4d5ccf214df86722d14cc93c1779c54e5b827773c8a2f65888a06f2efbad",
        };
    }
    pub fn foundationHeight(self: ChainType) u64 {
        return switch (self) {
            .automated_testing => 5,
            else => DAY_HEIGHT,
        };
    }
    pub fn firstForkHeight(self: ChainType) u64 {
        return switch (self) {
            .mainnet => MAINNET_FIRST_HARD_FORK,
            .floonet => FLOONET_FIRST_HARD_FORK,
            else => TESTING_FIRST_HARD_FORK,
        };
    }
    /// Height from which the era-1 difficulty algorithm is used.
    pub fn difficultyFixHeight(self: ChainType) u64 {
        return switch (self) {
            .automated_testing, .user_testing => TESTING_DIFFICULTY_ERA,
            .floonet => FLOONET_DIFFICULTY_ERA,
            .mainnet => MAINNET_DIFFICULTY_ERA,
        };
    }
};

pub const PROTOCOL_VERSION = ser.PROTOCOL_VERSION;
pub const STUCK_PEER_KICK_TIME: i64 = 2 * 3600 * 1000;
pub const PEER_EXPIRATION_REMOVE_TIME: i64 = 7 * 2 * 24 * 3600;
pub const TXHASHSET_ARCHIVE_INTERVAL: u64 = 12 * 60;

/// An epic is divisible to 10^8 like bitcoin.
pub const EPIC_BASE: u64 = 100_000_000;
pub const MILLI_EPIC: u64 = EPIC_BASE / 1_000;
pub const MICRO_EPIC: u64 = MILLI_EPIC / 1_000;
pub const FREEMAN: u64 = 1;

pub const BLOCK_TIME_SEC: u64 = 60;
pub const HOUR_HEIGHT: u64 = 3600 / BLOCK_TIME_SEC;
pub const DAY_HEIGHT: u64 = 24 * HOUR_HEIGHT;
pub const WEEK_HEIGHT: u64 = 7 * DAY_HEIGHT;
pub const YEAR_HEIGHT: u64 = 52 * WEEK_HEIGHT;

pub const BLOCK_ERA_1: u64 = DAY_HEIGHT * 334;
pub const BLOCK_ERA_2: u64 = BLOCK_ERA_1 + DAY_HEIGHT * 470;
pub const BLOCK_ERA_3: u64 = BLOCK_ERA_2 + DAY_HEIGHT * 601;
pub const BLOCK_ERA_4: u64 = BLOCK_ERA_3 + DAY_HEIGHT * 800;
pub const BLOCK_ERA_5: u64 = BLOCK_ERA_4 + DAY_HEIGHT * 1019;
/// After era 5 each era lasts ~1460 days.
pub const BLOCK_ERA_6_ONWARDS: u64 = DAY_HEIGHT * 1460;
/// (0.15625 * EPIC_BASE) as u64
pub const BASE_REWARD_ERA_6_ONWARDS: u64 = 15_625_000;

pub fn mainnetBlockTotalRewardAtHeight(height: u64) u64 {
    if (height <= BLOCK_ERA_1) return 16 * EPIC_BASE;
    if (height <= BLOCK_ERA_2) return 8 * EPIC_BASE;
    if (height <= BLOCK_ERA_3) return 4 * EPIC_BASE;
    if (height <= BLOCK_ERA_4) return 2 * EPIC_BASE;
    if (height <= BLOCK_ERA_5) return EPIC_BASE;
    const exp = (height - BLOCK_ERA_5 - 1) / BLOCK_ERA_6_ONWARDS;
    if (exp >= 64) return 0;
    return BASE_REWARD_ERA_6_ONWARDS >> @intCast(exp);
}

pub const FLOONET_BLOCK_ERA_1: u64 = DAY_HEIGHT * 334;

pub fn floonetBlockTotalRewardAtHeight(height: u64) u64 {
    return if (height <= FLOONET_BLOCK_ERA_1) 16 * EPIC_BASE else 8 * EPIC_BASE;
}

pub fn blockTotalRewardAtHeight(chain: ChainType, height: u64) u64 {
    return if (chain == .floonet) floonetBlockTotalRewardAtHeight(height) else mainnetBlockTotalRewardAtHeight(height);
}

/// Total supply of epics at a given height (mainnet schedule).
pub fn fastTotalSupply(height: u64) u64 {
    var supply: u64 = 0;
    const eras = [_]struct { end: u64, reward: u64 }{
        .{ .end = BLOCK_ERA_1, .reward = 16 * EPIC_BASE },
        .{ .end = BLOCK_ERA_2, .reward = 8 * EPIC_BASE },
        .{ .end = BLOCK_ERA_3, .reward = 4 * EPIC_BASE },
        .{ .end = BLOCK_ERA_4, .reward = 2 * EPIC_BASE },
        .{ .end = BLOCK_ERA_5, .reward = EPIC_BASE },
    };
    var start: u64 = 0;
    for (eras) |e| {
        if (height > start) supply +%= (@min(height, e.end) - start) *% e.reward;
        start = e.end;
    }
    if (height > BLOCK_ERA_5) {
        var remaining = height - BLOCK_ERA_5;
        var per_block = BASE_REWARD_ERA_6_ONWARDS;
        while (remaining > 0 and per_block > 0) {
            const blocks = @min(remaining, BLOCK_ERA_6_ONWARDS);
            supply +%= blocks *% per_block;
            remaining -= blocks;
            per_block /= 2;
        }
    }
    return supply;
}

pub fn blocksToNextHalving(height: u64) u64 {
    inline for (.{ BLOCK_ERA_1, BLOCK_ERA_2, BLOCK_ERA_3, BLOCK_ERA_4, BLOCK_ERA_5 }) |end| {
        if (height < end) return end - height;
    }
    const since = height - BLOCK_ERA_5;
    const next = BLOCK_ERA_5 + (since / BLOCK_ERA_6_ONWARDS + 1) * BLOCK_ERA_6_ONWARDS;
    return next - height;
}

// ------------------------------------------------------- foundation levy

pub const FOUNDATION_LEVY_ERA_1: u64 = DAY_HEIGHT * 120;
pub const FOUNDATION_LEVY_ERA_2_ONWARDS: u64 = DAY_HEIGHT * 365;
pub const FOUNDATION_LEVY_RATIO: u64 = 10000;
pub const FOUNDATION_LEVY = [9]u64{ 888, 777, 666, 555, 444, 333, 222, 111, 111 };

pub fn rewardFoundationAtHeight(chain: ChainType, height: u64) u64 {
    if (height == 0) return 0;
    if (height <= FOUNDATION_LEVY_ERA_1) {
        return blockTotalRewardAtHeight(chain, height) * FOUNDATION_LEVY[0] / FOUNDATION_LEVY_RATIO;
    }
    const offset = height - FOUNDATION_LEVY_ERA_1 - 1;
    const index = offset / FOUNDATION_LEVY_ERA_2_ONWARDS + 1;
    if (index < FOUNDATION_LEVY.len) {
        return blockTotalRewardAtHeight(chain, height) * FOUNDATION_LEVY[@intCast(index)] / FOUNDATION_LEVY_RATIO;
    }
    return 0;
}

/// A foundation height is a multiple of the foundation interval that has a
/// non-zero levy.
pub fn isFoundationHeight(chain: ChainType, height: u64) bool {
    return height > 0 and height % chain.foundationHeight() == 0 and rewardFoundationAtHeight(chain, height) != 0;
}

/// Index of this height's coinbase in foundation.json.
pub fn foundationIndex(chain: ChainType, height: u64) u64 {
    std.debug.assert(height > 0);
    return height / chain.foundationHeight() - 1;
}

/// Sum of the levy over the interval ending at `height` (a foundation height).
pub fn cumulativeRewardFoundation(chain: ChainType, height: u64) u64 {
    std.debug.assert(isFoundationHeight(chain, height));
    var sum: u64 = 0;
    const n = (height - chain.foundationHeight()) + 1;
    var h = n;
    while (h <= height) : (h += 1) sum +%= rewardFoundationAtHeight(chain, h);
    return sum;
}

pub fn addRewardFoundation(chain: ChainType, height: u64) u64 {
    return if (isFoundationHeight(chain, height)) cumulativeRewardFoundation(chain, height) else 0;
}

pub fn rewardAtHeight(chain: ChainType, height: u64) u64 {
    return blockTotalRewardAtHeight(chain, height) - rewardFoundationAtHeight(chain, height);
}

/// Mining reward (plus fees).
pub fn reward(chain: ChainType, fee: u64, height: u64) u64 {
    return std.math.add(u64, rewardAtHeight(chain, height), fee) catch std.math.maxInt(u64);
}

/// Mining reward plus the foundation levy at a foundation height.
pub fn rewardFoundation(chain: ChainType, fees: u64, height: u64) u64 {
    return reward(chain, fees, height) +% addRewardFoundation(chain, height);
}

pub fn totalOverageAtHeight(chain: ChainType, height: u64, genesis_had_reward: bool) i64 {
    var sum: i64 = 0;
    if (genesis_had_reward) sum += @intCast(rewardAtHeight(chain, 0));
    var i: u64 = 1;
    while (i <= height) : (i += 1) {
        sum += @intCast(rewardAtHeight(chain, i));
        sum += @intCast(addRewardFoundation(chain, i));
    }
    return sum;
}

// ------------------------------------------------------------ parameters

pub const COINBASE_MATURITY: u64 = DAY_HEIGHT;
pub const PROOFSIZE: usize = 42;
pub const DEFAULT_MIN_EDGE_BITS: u8 = 19;
pub const SECOND_POW_EDGE_BITS: u8 = 31;
pub const BASE_EDGE_BITS: u8 = 24;
pub const CUT_THROUGH_HORIZON: u32 = @intCast(WEEK_HEIGHT);
pub const STATE_SYNC_THRESHOLD: u32 = @intCast(2 * DAY_HEIGHT);
/// On average, try compacting once per this many accepted blocks.
pub const COMPACTION_CHECK: u64 = DAY_HEIGHT;
pub const BLOCK_INPUT_WEIGHT: usize = 1;
pub const BLOCK_OUTPUT_WEIGHT: usize = 21;
pub const BLOCK_KERNEL_WEIGHT: usize = 3;
pub const MAX_BLOCK_WEIGHT: usize = 40_000;

pub const MAINNET_FIRST_HARD_FORK: u64 = 9_000_000;
pub const FLOONET_FIRST_HARD_FORK: u64 = 25_800;
pub const TESTING_FIRST_HARD_FORK: u64 = 6;

pub fn headerVersion(chain: ChainType, height: u64) u16 {
    return if (height < chain.firstForkHeight()) 6 else 7;
}

pub fn validHeaderVersion(chain: ChainType, height: u64, version: u16) bool {
    return version == headerVersion(chain, height);
}

/// Percentage of blocks that should use the secondary PoW.
pub fn secondaryPowRatio(height: u64) u64 {
    return 90 -| (height / (2 * YEAR_HEIGHT / 90));
}

pub const TESTING_DIFFICULTY_ERA: u64 = 50;
pub const FLOONET_DIFFICULTY_ERA: u64 = 200;
pub const MAINNET_DIFFICULTY_ERA: u64 = 501160;

pub const DIFFICULTY_ADJUST_WINDOW: u64 = HOUR_HEIGHT;
pub const BLOCK_TIME_WINDOW: u64 = DIFFICULTY_ADJUST_WINDOW * BLOCK_TIME_SEC;
pub const CLAMP_FACTOR: u64 = 2;
pub const DIFFICULTY_DAMP_FACTOR: u64 = 3;
pub const AR_SCALE_DAMP_FACTOR: u64 = 13;

/// Number of siphash bits defining the graph of a given size.
pub fn graphWeight(chain: ChainType, height: u64, edge_bits: u8) u64 {
    var xpr_edge_bits: u64 = edge_bits;
    var min_edge_bits: u8 = chain.minEdgeBits();
    if (min_edge_bits == 19) min_edge_bits += 12;
    const bits_over_min: u6 = @intCast(@min(edge_bits -| min_edge_bits, 63));

    // (patched in the reference so the weight does not decay to zero)
    const expiry_height: u64 = if (height > 880_000)
        (@as(u64, 1) << bits_over_min) *% (YEAR_HEIGHT * 100)
    else
        (@as(u64, 1) << bits_over_min) *% YEAR_HEIGHT;

    if (height >= expiry_height) {
        xpr_edge_bits = xpr_edge_bits -| (1 + (height - expiry_height) / WEEK_HEIGHT);
    }

    const base = chain.baseEdgeBits();
    const shift: u6 = @intCast((if (edge_bits > base) edge_bits - base else base - edge_bits) & 63);
    return (@as(u64, 2) << shift) *% xpr_edge_bits;
}

pub const MIN_DIFFICULTY: u64 = DIFFICULTY_DAMP_FACTOR;
pub const MIN_DIFFICULTY_RANDOMX: u64 = 4000;
pub const MIN_DIFFICULTY_RANDOMX_TESTING: u64 = 1;
pub const OLD_MIN_DIFFICULTY_RANDOMX: u64 = 5000;
pub const MIN_DIFFICULTY_PROGPOW: u64 = 200_000;
pub const OLD_MIN_DIFFICULTY_PROGPOW: u64 = 100_000;
pub const BLOCK_DIFF_FACTOR_RANDOMX: u64 = 64;
pub const BLOCK_DIFF_FACTOR_PROGPOW: u64 = 64;
pub const MIN_AR_SCALE: u64 = AR_SCALE_DAMP_FACTOR;
pub const RX_CLAMP_FACTOR: u64 = 2;
pub const RX_DIFFICULTY_DAMP_FACTOR: u64 = 3;
pub const PP_CLAMP_FACTOR: u64 = 2;
pub const PP_DIFFICULTY_DAMP_FACTOR: u64 = 3;

pub const UNIT_DIFFICULTY: u64 = (@as(u64, 2) << (SECOND_POW_EDGE_BITS - BASE_EDGE_BITS)) * SECOND_POW_EDGE_BITS;
pub const INITIAL_DIFFICULTY: u64 = 1_000_000 * UNIT_DIFFICULTY;

// ------------------------------------------------------ policy defaults

fn mkPolicy(rx: u32, pp: u32, ckt: u32) Policy {
    return Policy.init(0, ckt, rx, pp);
}

fn mkConfig(comptime mixes: [6]Policy) feijoada.PolicyConfig {
    const eras = [6]u64{ 0, BLOCK_ERA_1 + 1, BLOCK_ERA_2 + 1, BLOCK_ERA_3 + 1, BLOCK_ERA_4 + 1, BLOCK_ERA_5 + 1 };
    const allowed = comptime blk: {
        var a: [6]feijoada.AllowPolicy = undefined;
        for (0..6) |i| a[i] = .{ .height = eras[i], .value = 1 << i };
        break :blk a;
    };
    const pols = mixes;
    return .{ .allowed_policies = &allowed, .policies = &pols };
}

/// Mainnet default schedule (RandomX / ProgPoW / Cuckatoo shares per era).
pub const default_policy_config = mkConfig(.{
    mkPolicy(60, 38, 2), mkPolicy(60, 38, 2), mkPolicy(48, 48, 4),
    mkPolicy(48, 48, 4), mkPolicy(48, 48, 4), mkPolicy(48, 48, 4),
});
pub const no_progpow_policy_config = mkConfig(.{
    mkPolicy(60, 0, 40), mkPolicy(60, 0, 40), mkPolicy(50, 0, 50),
    mkPolicy(45, 0, 55), mkPolicy(25, 0, 75), mkPolicy(15, 0, 85),
});
pub const only_randomx_policy_config = mkConfig(.{
    mkPolicy(100, 0, 0), mkPolicy(100, 0, 0), mkPolicy(100, 0, 0),
    mkPolicy(100, 0, 0), mkPolicy(100, 0, 0), mkPolicy(100, 0, 0),
});

/// Which policy index is emitted at a given height (by emission era).
pub fn emittedPolicy(height: u64) u8 {
    if (height <= BLOCK_ERA_1) return 0;
    if (height <= BLOCK_ERA_2) return 1;
    if (height <= BLOCK_ERA_3) return 2;
    if (height <= BLOCK_ERA_4) return 3;
    if (height <= BLOCK_ERA_5) return 4;
    return 5;
}

/// Returns the algorithm and the bottles of the next block. `prev_bottles`
/// is the previous header's bottles, or null for the first block.
pub fn nextPolicy(cfg: feijoada.PolicyConfig, policy: u8, prev_bottles: ?Policy) error{ MissingBottle, UnknownPolicy }!struct { PoWType, Policy } {
    const bottles = prev_bottles orelse Policy.default_bottles;
    const pol = cfg.policy(policy) orelse return error.UnknownPolicy;
    const pow = try feijoada.chooseAlgo(pol, bottles);
    return .{ pow, feijoada.nextBlockBottles(pow, bottles) };
}

// ------------------------------------------------------------ difficulty

/// Minimal header information needed for difficulty calculation.
pub const HeaderInfo = struct {
    /// Block hash, `Hash.zero` for synthetic entries.
    block_hash: Hash,
    timestamp: u64,
    difficulty: Difficulty,
    secondary_scaling: u32,
    is_secondary: bool,
    /// Time span of the previous block of the same algorithm.
    prev_timespan: u64,

    pub fn fromTsDiff(chain: ChainType, timestamp: u64, difficulty: Difficulty) HeaderInfo {
        return .{
            .block_hash = Hash.zero,
            .timestamp = timestamp,
            .difficulty = difficulty,
            .secondary_scaling = chain.initialGraphWeight(),
            .is_secondary = true,
            .prev_timespan = 0,
        };
    }

    pub fn fromDiffScaling(difficulty: Difficulty, secondary_scaling: u32) HeaderInfo {
        return .{
            .block_hash = Hash.zero,
            .timestamp = 1,
            .difficulty = difficulty,
            .secondary_scaling = secondary_scaling,
            .is_secondary = true,
            .prev_timespan = 0,
        };
    }
};

/// Move value linearly toward a goal.
pub fn damp(actual: u64, goal: u64, damp_factor: u64) u64 {
    return (actual +% (damp_factor - 1) *% goal) / damp_factor;
}

/// Limit value to be within some factor from a goal.
pub fn clamp(actual: u64, goal: u64, clamp_factor: u64) u64 {
    return @max(goal / clamp_factor, @min(actual, goal *% clamp_factor));
}

/// Max entries ever needed: DIFFICULTY_ADJUST_WINDOW + 1.
pub const MAX_DIFF_DATA = DIFFICULTY_ADJUST_WINDOW + 1;

/// Buffer holding the (oldest-first) difficulty window.
pub const DiffData = struct {
    buf: [MAX_DIFF_DATA]HeaderInfo = undefined,
    len: usize = 0,

    pub fn items(self: *const DiffData) []const HeaderInfo {
        return self.buf[0..self.len];
    }
};

/// `cursor` is ordered latest (highest height) to oldest. Result is oldest
/// first, padded with synthetic entries when history is shorter than needed.
pub fn difficultyDataToVector(chain: ChainType, out: *DiffData, cursor: []const HeaderInfo, needed_block_count: u64) []const HeaderInfo {
    const needed: usize = @intCast(needed_block_count + 1);
    const take = @min(cursor.len, needed);
    var last_n = out.buf[0..needed];
    @memcpy(last_n[0..take], cursor[0..take]);
    var i: usize = 1;
    while (i < take) : (i += 1) {
        last_n[i].timestamp = last_n[i - 1].timestamp -| last_n[i - 1].prev_timespan;
    }
    var n = take;
    if (needed > n) {
        const last_ts_delta: u64 = if (n > 1) last_n[0].timestamp -% last_n[1].timestamp else BLOCK_TIME_SEC;
        const last_diff = last_n[0].difficulty;
        var last_ts = last_n[n - 1].timestamp;
        while (n < needed) : (n += 1) {
            last_ts = last_ts -| last_ts_delta;
            last_n[n] = HeaderInfo.fromTsDiff(chain, last_ts, last_diff);
        }
    }
    std.mem.reverse(HeaderInfo, last_n[0..n]);
    out.len = n;
    return last_n[0..n];
}

/// Like `difficultyDataToVector` but keeps latest-first order (used for medians).
pub fn tsDataToVector(chain: ChainType, out: *DiffData, cursor: []const HeaderInfo, needed_block_count: u64) []const HeaderInfo {
    const v = difficultyDataToVector(chain, out, cursor, needed_block_count);
    const m = out.buf[0..v.len];
    std.mem.reverse(HeaderInfo, m);
    return m;
}

/// Count, in units of 1/100, of secondary (AR) blocks in the window.
pub fn arCount(_: u64, diff_data: []const HeaderInfo) u64 {
    var c: u64 = 0;
    for (diff_data) |d| c += @intFromBool(d.is_secondary);
    return 100 * c;
}

pub fn secondaryPowScaling(height: u64, diff_data: []const HeaderInfo) u32 {
    var scale_sum: u64 = 0;
    for (diff_data) |d| scale_sum +%= d.secondary_scaling;
    const target_pct = secondaryPowRatio(height);
    const target_count = DIFFICULTY_ADJUST_WINDOW * target_pct;
    const adj_count = clamp(
        damp(arCount(height, diff_data), target_count, AR_SCALE_DAMP_FACTOR),
        target_count,
        CLAMP_FACTOR,
    );
    const scale = scale_sum *% target_pct / @max(1, adj_count);
    return @truncate(@max(MIN_AR_SCALE, scale));
}

fn diffSum(diff_data: []const HeaderInfo, pow: PoWType) u64 {
    var s: u64 = 0;
    for (diff_data[1..]) |d| s +%= d.difficulty.toNum(pow);
    return s;
}

fn cuckooDifficulty(pow: PoWType, diff_data: []const HeaderInfo) u64 {
    const ts_delta = diff_data[DIFFICULTY_ADJUST_WINDOW].timestamp -% diff_data[0].timestamp;
    const diff_sum = diffSum(diff_data, pow);
    const adj_ts = clamp(damp(ts_delta, BLOCK_TIME_WINDOW, DIFFICULTY_DAMP_FACTOR), BLOCK_TIME_WINDOW, CLAMP_FACTOR);
    return @max(MIN_DIFFICULTY, diff_sum *% BLOCK_TIME_SEC / adj_ts);
}

/// Difficulty for hash-based algos (RandomX, ProgPoW) before the era-1 fix.
pub fn nextHashDifficulty(pow: PoWType, diff_data: []const HeaderInfo) u64 {
    const cutoff: i64 = 60;
    const factor: u64 = switch (pow) {
        .randomx => BLOCK_DIFF_FACTOR_RANDOMX,
        .progpow => BLOCK_DIFF_FACTOR_PROGPOW,
        else => unreachable,
    };
    const min_diff: u64 = if (pow == .randomx) OLD_MIN_DIFFICULTY_RANDOMX else OLD_MIN_DIFFICULTY_PROGPOW;
    const current_diff = diff_data[1].difficulty.toNum(pow);
    const ts_delta: u64 = diff_data[1].timestamp -% diff_data[0].timestamp;
    const offset: i64 = @bitCast(current_diff / factor);
    const sign: i64 = @max(1 -% 2 *% @divTrunc(@as(i64, @bitCast(ts_delta)), cutoff), -99);
    const cur_i: i64 = @bitCast(current_diff);
    const raw: i64 = cur_i +% offset *% sign;
    const clamped: i64 = @max(raw, @as(i64, 1));
    const candidate: u64 = @intCast(clamped);
    return @max(candidate, @min(current_diff, min_diff));
}

/// Next difficulty (pre era-1). `cursor` is latest-first `HeaderInfo`.
pub fn nextDifficulty(chain: ChainType, height: u64, prev_algo: PoWType, cursor: []const HeaderInfo) HeaderInfo {
    if (chain == .floonet or chain == .user_testing) {
        return HeaderInfo.fromDiffScaling(Difficulty.fromNum(1), 1);
    }
    var data: DiffData = .{};
    const window: u64 = switch (prev_algo) {
        .cuckatoo, .cuckaroo => DIFFICULTY_ADJUST_WINDOW,
        .randomx, .progpow => 1,
    };
    const dd = difficultyDataToVector(chain, &data, cursor, window);
    const sec = secondaryPowScaling(height, dd[1..]);
    var diff = dd[dd.len - 1].difficulty;
    diff.insert(prev_algo, switch (prev_algo) {
        .cuckatoo, .cuckaroo => cuckooDifficulty(prev_algo, dd),
        .randomx, .progpow => nextHashDifficulty(prev_algo, dd),
    });
    return HeaderInfo.fromDiffScaling(diff, sec);
}

/// Median timestamp of the last 6 blocks plus this header's timestamp.
/// (Even count picks ts[half], odd averages -- as in the reference.)
pub fn timestampMedian(chain: ChainType, header_ts: u64, cursor: []const HeaderInfo) u64 {
    var data: DiffData = .{};
    const dd = tsDataToVector(chain, &data, cursor, 6);
    var ts: [8]u64 = undefined;
    var n: usize = 0;
    for (dd) |d| {
        ts[n] = d.timestamp;
        n += 1;
    }
    ts[n] = header_ts;
    n += 1;
    std.mem.sort(u64, ts[0..n], {}, std.sort.asc(u64));
    const half = n / 2;
    return if (n % 2 == 0) ts[half] else (ts[half - 1] +% ts[half]) / 2;
}

fn eraDifficulty(chain: ChainType, pow: PoWType, diff_data: []const HeaderInfo) u64 {
    var ts_delta: u64 = 0;
    var i: usize = 1;
    while (i < diff_data.len) : (i += 1) {
        const p = diff_data[i - 1];
        ts_delta +%= p.timestamp -% (p.timestamp -| p.prev_timespan);
    }
    const diff_sum = diffSum(diff_data, pow);
    const clamp_f: u64, const damp_f: u64, const min_diff: u64 = switch (pow) {
        .cuckatoo, .cuckaroo => .{ CLAMP_FACTOR, DIFFICULTY_DAMP_FACTOR, MIN_DIFFICULTY },
        .progpow => .{ PP_CLAMP_FACTOR, PP_DIFFICULTY_DAMP_FACTOR, MIN_DIFFICULTY_PROGPOW },
        .randomx => .{
            RX_CLAMP_FACTOR,
            RX_DIFFICULTY_DAMP_FACTOR,
            if (chain == .user_testing) MIN_DIFFICULTY_RANDOMX_TESTING else MIN_DIFFICULTY_RANDOMX,
        },
    };
    const adj_ts = clamp(damp(ts_delta, BLOCK_TIME_WINDOW, damp_f), BLOCK_TIME_WINDOW, clamp_f);
    return @max(min_diff, diff_sum *% BLOCK_TIME_SEC / adj_ts);
}

/// Next difficulty from the era-1 fix onward (heights >= difficultyFixHeight).
pub fn nextDifficultyEra1(chain: ChainType, height: u64, prev_algo: PoWType, cursor: []const HeaderInfo) HeaderInfo {
    var data: DiffData = .{};
    const dd = difficultyDataToVector(chain, &data, cursor, DIFFICULTY_ADJUST_WINDOW);
    const sec = secondaryPowScaling(height, dd[1..]);
    var diff = dd[dd.len - 1].difficulty;
    diff.insert(prev_algo, eraDifficulty(chain, prev_algo, dd));
    return HeaderInfo.fromDiffScaling(diff, sec);
}

/// Dispatch used by the chain pipeline (chain/src/pipe.rs).
pub fn nextDifficultyFor(chain: ChainType, height: u64, prev_algo: PoWType, cursor: []const HeaderInfo) HeaderInfo {
    return if (height < chain.difficultyFixHeight())
        nextDifficulty(chain, height, prev_algo, cursor)
    else
        nextDifficultyEra1(chain, height, prev_algo, cursor);
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "graph weight matches reference test vectors" {
    const c: ChainType = .mainnet;
    try testing.expectEqual(@as(u64, 256 * 31), graphWeight(c, 1, 31));
    try testing.expectEqual(@as(u64, 512 * 32), graphWeight(c, 1, 32));
    try testing.expectEqual(@as(u64, 1024 * 33), graphWeight(c, 1, 33));
    // one year in (below the 880k patch height) 31 starts decaying, one step per week
    try testing.expectEqual(@as(u64, 256 * 30), graphWeight(c, YEAR_HEIGHT, 31));
    try testing.expectEqual(@as(u64, 256 * 29), graphWeight(c, YEAR_HEIGHT + WEEK_HEIGHT, 31));
    try testing.expectEqual(@as(u64, 512 * 32), graphWeight(c, YEAR_HEIGHT, 32));
    // past the patch height the expiry is pushed out 100x, so no decay
    try testing.expectEqual(@as(u64, 256 * 31), graphWeight(c, 3 * YEAR_HEIGHT, 31));
    try testing.expectEqual(@as(u64, UNIT_DIFFICULTY), graphWeight(c, 0, SECOND_POW_EDGE_BITS));
}

test "emission eras" {
    try testing.expectEqual(@as(u64, 16 * EPIC_BASE), mainnetBlockTotalRewardAtHeight(1));
    try testing.expectEqual(@as(u64, 8 * EPIC_BASE), mainnetBlockTotalRewardAtHeight(BLOCK_ERA_1 + 1));
    try testing.expectEqual(@as(u64, EPIC_BASE), mainnetBlockTotalRewardAtHeight(BLOCK_ERA_5));
    try testing.expectEqual(@as(u64, 15_625_000), mainnetBlockTotalRewardAtHeight(BLOCK_ERA_5 + 1));
    try testing.expectEqual(@as(u64, 15_625_000 / 2), mainnetBlockTotalRewardAtHeight(BLOCK_ERA_5 + BLOCK_ERA_6_ONWARDS + 1));
    try testing.expectEqual(@as(u64, 480_960), BLOCK_ERA_1);
    try testing.expectEqual(@as(u64, 1_157_760), BLOCK_ERA_2);
    try testing.expectEqual(@as(u64, 2_023_200), BLOCK_ERA_3);
    // supply is the sum of per-block rewards
    var sum: u64 = 0;
    var h: u64 = 1;
    while (h <= 3000) : (h += 1) sum += mainnetBlockTotalRewardAtHeight(h);
    try testing.expectEqual(sum, fastTotalSupply(3000));
    try testing.expectEqual(BLOCK_ERA_1 * 16 * EPIC_BASE, fastTotalSupply(BLOCK_ERA_1));
}

test "foundation levy" {
    const c: ChainType = .mainnet;
    try testing.expectEqual(@as(u64, 0), rewardFoundationAtHeight(c, 0));
    try testing.expectEqual(@as(u64, 16 * EPIC_BASE * 888 / 10000), rewardFoundationAtHeight(c, 5));
    try testing.expect(isFoundationHeight(c, DAY_HEIGHT));
    try testing.expect(!isFoundationHeight(c, DAY_HEIGHT + 1));
    try testing.expectEqual(@as(u64, 0), foundationIndex(c, DAY_HEIGHT));
    try testing.expectEqual(@as(u64, DAY_HEIGHT * (16 * EPIC_BASE * 888 / 10000)), cumulativeRewardFoundation(c, DAY_HEIGHT));
    // levy vanishes after the schedule ends
    try testing.expectEqual(@as(u64, 0), rewardFoundationAtHeight(c, FOUNDATION_LEVY_ERA_1 + FOUNDATION_LEVY_ERA_2_ONWARDS * 9 + 1));
}

test "damp and clamp" {
    try testing.expectEqual(@as(u64, 60), damp(60, 60, 3));
    try testing.expectEqual(@as(u64, 100), damp(180, 60, 3));
    try testing.expectEqual(@as(u64, 30), clamp(1, 60, 2));
    try testing.expectEqual(@as(u64, 120), clamp(1000, 60, 2));
}

test "steady-state difficulty stays put" {
    // 62 headers exactly on the 60s target with constant difficulty: the cuckoo
    // retarget should reproduce the same difficulty.
    var hdrs: [70]HeaderInfo = undefined;
    for (&hdrs, 0..) |*h, i| {
        h.* = .{
            .block_hash = Hash.zero,
            .timestamp = 1_000_000 - i * 60,
            .difficulty = Difficulty.number(1000),
            .secondary_scaling = 500,
            .is_secondary = true,
            .prev_timespan = 60,
        };
    }
    const info = nextDifficultyEra1(.mainnet, 600_000, .cuckatoo, &hdrs);
    try testing.expectEqual(@as(u64, 1000), info.difficulty.toNum(.cuckatoo));
}

test "policy default config has six eras" {
    try testing.expectEqual(@as(usize, 6), default_policy_config.policies.len);
    try testing.expect(feijoada.isAllowedPolicy(default_policy_config.allowed_policies, 0, 0));
    try testing.expect(!feijoada.isAllowedPolicy(default_policy_config.allowed_policies, 0, 1));
    try testing.expect(feijoada.isAllowedPolicy(default_policy_config.allowed_policies, BLOCK_ERA_1 + 1, 1));
    try testing.expectEqual(@as(u8, 5), emittedPolicy(BLOCK_ERA_5 + 1));
    const r = try nextPolicy(default_policy_config, 0, null);
    try testing.expectEqual(PoWType.randomx, r[0]);
}
