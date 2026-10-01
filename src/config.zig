//! The node's configuration file, `epic-zig.toml` in the data directory (or
//! `--config PATH`). A small TOML subset: `[section]` headers, `key = value`
//! with strings, integers, booleans and arrays of strings, and `#` comments.
//! Precedence: built-in defaults < the file < command-line flags.
const std = @import("std");
const Io = std.Io;

pub const FILE_NAME = "epic-zig.toml";

pub const Config = struct {
    chain: []const u8 = "mainnet",

    // [p2p]
    peer: []const u8 = "",
    listen: []const u8 = "0.0.0.0:3414",
    max_outbound: u32 = 8,
    seeds: bool = true,
    extra_seeds: []const []const u8 = &.{},
    allow_local_peers: bool = false,

    // [api]
    api_listen: []const u8 = "127.0.0.1:3413",
    api_auth: bool = true,
    /// The reference's `api_secret_path` / `foreign_api_secret_path`; relative
    /// paths are inside the data dir.
    api_secret_path: []const u8 = ".api_secret",
    foreign_api_secret_path: []const u8 = ".foreign_api_secret",

    // [chain]
    /// The reference's settings, same names and defaults.
    skip_pow_validation: bool = true,
    disable_checkpoints: bool = false,
    /// This node's extra checkpoints up to 3.7M (not in the reference).
    extended_checkpoints: bool = false,
    archive_mode: bool = false,

    // [pool]
    accept_fee_base: u64 = 100_000,
    max_pool_size: usize = 50_000,
    max_stempool_size: usize = 50_000,
    mineable_max_weight: usize = 40_000,

    // [dandelion]
    epoch_secs: i64 = 600,
    embargo_secs: i64 = 180,
    aggregation_secs: i64 = 30,
    stem_probability: u8 = 90,
    always_stem_our_txs: bool = true,
};

pub const default_text =
    \\# epic-zig configuration. Command-line flags override these settings.
    \\# Delete this file to get the defaults back.
    \\
    \\chain = "mainnet"                # or "floonet" (default ports then become 13414 and 13413)
    \\
    \\[p2p]
    \\peer = ""                        # sync from this one peer only (host:port); empty: find peers via the seeds
    \\listen = "0.0.0.0:3414"         # accept inbound peers (the Rust node's default); "" to not listen
    \\max_outbound = 8                 # outbound peers to keep when discovering peers
    \\seeds = true                     # use the network's DNS seed when looking for peers
    \\extra_seeds = []                 # more peers to try, e.g. ["203.0.113.5:3414"]
    \\allow_local_peers = false        # accept private/loopback addresses (LANs, tests)
    \\
    \\[api]
    \\listen = "127.0.0.1:3413"       # REST API where wallets expect it (the Rust node's default); "" for no API
    \\auth = true                      # Basic auth (user "epic") on /v1 and /v2/owner, as the Rust node does
    \\api_secret_path = ".api_secret"  # the password (created if missing); relative paths are in the data dir
    \\foreign_api_secret_path = ".foreign_api_secret"  # if this file exists, /v2/foreign needs it too (otherwise open, like the Rust node)
    \\
    \\[chain]
    \\# The first two work exactly like the Rust node's settings of the same name.
    \\skip_pow_validation = true       # skip header PoW inside the checkpointed range (to 3,500,000; the Rust node: 2,200,000); false checks every header
    \\disable_checkpoints = false      # with skip_pow_validation: skip PoW on every header while syncing
    \\extended_checkpoints = false     # also checkpoints at 3,600,000 and 3,700,000 (skip header PoW up to 3,700,000)
    \\archive_mode = false             # keep every block (compaction still prunes the txhashset)
    \\
    \\[pool]
    \\accept_fee_base = 100000         # minimum fee per unit of tx weight
    \\max_pool_size = 50000
    \\max_stempool_size = 50000
    \\mineable_max_weight = 40000
    \\
    \\[dandelion]
    \\epoch_secs = 600
    \\embargo_secs = 180
    \\aggregation_secs = 30
    \\stem_probability = 90            # percent of epochs that relay ("stem") transactions
    \\always_stem_our_txs = true
    \\
;

pub const ParseError = error{ BadConfig, OutOfMemory };

pub const Diag = struct {
    line: usize = 0,
    msg: []const u8 = "",
};

/// Parses `text` over `base`. Strings and arrays are allocated in `arena`.
pub fn parse(arena: std.mem.Allocator, text: []const u8, base: Config, diag: *Diag) ParseError!Config {
    var cfg = base;
    var section: []const u8 = "";
    var lines = std.mem.splitScalar(u8, text, '\n');
    var n: usize = 0;
    while (lines.next()) |raw| {
        n += 1;
        diag.line = n;
        const line = std.mem.trim(u8, stripComment(raw), " \t\r");
        if (line.len == 0) continue;
        if (line[0] == '[') {
            if (line[line.len - 1] != ']') return fail(diag, "bad section header");
            section = std.mem.trim(u8, line[1 .. line.len - 1], " \t");
            continue;
        }
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse return fail(diag, "expected key = value");
        const key = std.mem.trim(u8, line[0..eq], " \t");
        const val = std.mem.trim(u8, line[eq + 1 ..], " \t");
        try set(arena, &cfg, section, key, val, diag);
    }
    return cfg;
}

fn fail(diag: *Diag, msg: []const u8) ParseError {
    diag.msg = msg;
    return error.BadConfig;
}

/// Drops a `#` comment that isn't inside a string.
fn stripComment(line: []const u8) []const u8 {
    var in_str = false;
    for (line, 0..) |c, i| {
        if (c == '"') in_str = !in_str;
        if (c == '#' and !in_str) return line[0..i];
    }
    return line;
}

fn parseString(arena: std.mem.Allocator, v: []const u8, diag: *Diag) ParseError![]const u8 {
    if (v.len < 2 or v[0] != '"' or v[v.len - 1] != '"') return fail(diag, "expected a \"string\"");
    return try arena.dupe(u8, v[1 .. v.len - 1]);
}

fn parseBool(v: []const u8, diag: *Diag) ParseError!bool {
    if (std.mem.eql(u8, v, "true")) return true;
    if (std.mem.eql(u8, v, "false")) return false;
    return fail(diag, "expected true or false");
}

fn parseInt(comptime T: type, v: []const u8, diag: *Diag) ParseError!T {
    var digits: [32]u8 = undefined;
    var n: usize = 0;
    for (v) |c| {
        if (c == '_') continue; // TOML allows 1_000
        if (n >= digits.len) return fail(diag, "number too long");
        digits[n] = c;
        n += 1;
    }
    return std.fmt.parseInt(T, digits[0..n], 10) catch fail(diag, "expected a number");
}

fn parseStringArray(arena: std.mem.Allocator, v: []const u8, diag: *Diag) ParseError![]const []const u8 {
    if (v.len < 2 or v[0] != '[' or v[v.len - 1] != ']') return fail(diag, "expected [\"...\", ...]");
    var out: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, v[1 .. v.len - 1], ',');
    while (it.next()) |item| {
        const t = std.mem.trim(u8, item, " \t");
        if (t.len == 0) continue;
        try out.append(arena, try parseString(arena, t, diag));
    }
    return out.toOwnedSlice(arena);
}

fn set(arena: std.mem.Allocator, cfg: *Config, section: []const u8, key: []const u8, v: []const u8, diag: *Diag) ParseError!void {
    const eq = std.mem.eql;
    if (section.len == 0) {
        if (eq(u8, key, "chain")) {
            cfg.chain = try parseString(arena, v, diag);
            return;
        }
    } else if (eq(u8, section, "p2p")) {
        if (eq(u8, key, "peer")) {
            cfg.peer = try parseString(arena, v, diag);
            return;
        }
        if (eq(u8, key, "listen")) {
            cfg.listen = try parseString(arena, v, diag);
            return;
        }
        if (eq(u8, key, "max_outbound")) {
            cfg.max_outbound = try parseInt(u32, v, diag);
            return;
        }
        if (eq(u8, key, "seeds")) {
            cfg.seeds = try parseBool(v, diag);
            return;
        }
        if (eq(u8, key, "extra_seeds")) {
            cfg.extra_seeds = try parseStringArray(arena, v, diag);
            return;
        }
        if (eq(u8, key, "allow_local_peers")) {
            cfg.allow_local_peers = try parseBool(v, diag);
            return;
        }
    } else if (eq(u8, section, "api")) {
        if (eq(u8, key, "listen")) {
            cfg.api_listen = try parseString(arena, v, diag);
            return;
        }
        if (eq(u8, key, "auth")) {
            cfg.api_auth = try parseBool(v, diag);
            return;
        }
        if (eq(u8, key, "api_secret_path")) {
            cfg.api_secret_path = try parseString(arena, v, diag);
            return;
        }
        if (eq(u8, key, "foreign_api_secret_path")) {
            cfg.foreign_api_secret_path = try parseString(arena, v, diag);
            return;
        }
    } else if (eq(u8, section, "chain")) {
        if (eq(u8, key, "skip_pow_validation")) {
            cfg.skip_pow_validation = try parseBool(v, diag);
            return;
        }
        if (eq(u8, key, "disable_checkpoints")) {
            cfg.disable_checkpoints = try parseBool(v, diag);
            return;
        }
        if (eq(u8, key, "extended_checkpoints")) {
            cfg.extended_checkpoints = try parseBool(v, diag);
            return;
        }
        // older names, from the first config files this node wrote
        if (eq(u8, key, "verify_all_pow")) {
            if (try parseBool(v, diag)) cfg.skip_pow_validation = false;
            return;
        }
        if (eq(u8, key, "assume_valid")) {
            // it used to default to true; ignore it so old files get the reference's default
            _ = try parseBool(v, diag);
            return;
        }
        if (eq(u8, key, "archive_mode")) {
            cfg.archive_mode = try parseBool(v, diag);
            return;
        }
    } else if (eq(u8, section, "pool")) {
        if (eq(u8, key, "accept_fee_base")) {
            cfg.accept_fee_base = try parseInt(u64, v, diag);
            return;
        }
        if (eq(u8, key, "max_pool_size")) {
            cfg.max_pool_size = try parseInt(usize, v, diag);
            return;
        }
        if (eq(u8, key, "max_stempool_size")) {
            cfg.max_stempool_size = try parseInt(usize, v, diag);
            return;
        }
        if (eq(u8, key, "mineable_max_weight")) {
            cfg.mineable_max_weight = try parseInt(usize, v, diag);
            return;
        }
    } else if (eq(u8, section, "dandelion")) {
        if (eq(u8, key, "epoch_secs")) {
            cfg.epoch_secs = try parseInt(i64, v, diag);
            return;
        }
        if (eq(u8, key, "embargo_secs")) {
            cfg.embargo_secs = try parseInt(i64, v, diag);
            return;
        }
        if (eq(u8, key, "aggregation_secs")) {
            cfg.aggregation_secs = try parseInt(i64, v, diag);
            return;
        }
        if (eq(u8, key, "stem_probability")) {
            const p = try parseInt(u8, v, diag);
            if (p > 100) return fail(diag, "stem_probability is a percentage (0-100)");
            cfg.stem_probability = p;
            return;
        }
        if (eq(u8, key, "always_stem_our_txs")) {
            cfg.always_stem_our_txs = try parseBool(v, diag);
            return;
        }
    } else return fail(diag, "unknown section");
    return fail(diag, "unknown key");
}

/// Loads `path` (relative to `dir`), writing the default file first if it
/// doesn't exist and `create` is set.
pub fn load(arena: std.mem.Allocator, io: Io, dir: Io.Dir, path: []const u8, create: bool, diag: *Diag) !Config {
    const text = dir.readFileAlloc(io, path, arena, .limited(1 << 20)) catch |e| switch (e) {
        error.FileNotFound => {
            if (create) try dir.writeFile(io, .{ .sub_path = path, .data = default_text });
            return parse(arena, default_text, .{}, diag);
        },
        else => return e,
    };
    return parse(arena, text, .{}, diag);
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "the default file parses to the defaults" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var diag: Diag = .{};
    const c = try parse(arena_state.allocator(), default_text, .{}, &diag);
    const d: Config = .{};
    try testing.expectEqualStrings(d.chain, c.chain);
    try testing.expectEqual(d.max_outbound, c.max_outbound);
    try testing.expectEqual(d.accept_fee_base, c.accept_fee_base);
    try testing.expectEqual(d.stem_probability, c.stem_probability);
    try testing.expectEqual(@as(usize, 0), c.extra_seeds.len);
}

test "values, comments, arrays and errors" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var diag: Diag = .{};
    const text =
        \\chain = "floonet"   # comment
        \\[p2p]
        \\peer = "127.0.0.1:3414"
        \\max_outbound = 12
        \\extra_seeds = ["1.2.3.4:3414", "5.6.7.8:3414"]
        \\[api]
        \\listen = "127.0.0.1:3423"  # "quoted # inside" comments are fine
        \\auth = false
        \\[pool]
        \\accept_fee_base = 1_000
    ;
    const c = try parse(a, text, .{}, &diag);
    try testing.expectEqualStrings("floonet", c.chain);
    try testing.expectEqualStrings("127.0.0.1:3414", c.peer);
    try testing.expectEqual(@as(u32, 12), c.max_outbound);
    try testing.expectEqual(@as(usize, 2), c.extra_seeds.len);
    try testing.expectEqualStrings("5.6.7.8:3414", c.extra_seeds[1]);
    try testing.expectEqualStrings("127.0.0.1:3423", c.api_listen);
    try testing.expect(!c.api_auth);
    try testing.expectEqual(@as(u64, 1000), c.accept_fee_base);

    try testing.expectError(error.BadConfig, parse(a, "[p2p]\nnope = 1", .{}, &diag));
    try testing.expectEqual(@as(usize, 2), diag.line);
    try testing.expectError(error.BadConfig, parse(a, "[dandelion]\nstem_probability = 150", .{}, &diag));
    try testing.expectError(error.BadConfig, parse(a, "[api]\nauth = maybe", .{}, &diag));
}
