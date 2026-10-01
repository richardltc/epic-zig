//! epic-zig: an Epic Cash node. Isolated by design: it needs an explicit data
//! directory and never touches the default node locations.
//!
//! Settings come from built-in defaults, then `<data-dir>/epic-zig.toml`
//! (written with the defaults on first run; `--config PATH` for another file),
//! then the command-line flags below.
const std = @import("std");
const Io = std.Io;
const builtin = @import("builtin");
const epic = @import("epic");

const N = epic.logging.num;
const VERSION = "0.1.0";

pub const std_options: std.Options = .{ .logFn = epic.logging.logFn };

const usage =
    \\usage: epic-zig --data-dir DIR [options]
    \\
    \\  --data-dir DIR        where chain data lives (required; never ~/.epic)
    \\  --config PATH         settings file (default <data-dir>/epic-zig.toml, created on first run)
    \\  --peer HOST:PORT      sync from this peer. Without it the node finds peers itself: the network's
    \\                        DNS seed, then peers those peers know about (discovery is on by default then)
    \\  --headers-only        stop after header sync
    \\  --stop-height N       stop once the chain reaches height N
    \\  --no-follow           exit after catching up instead of following the tip
    \\  --verify-all-pow      check PoW on every header (the Rust node's skip_pow_validation = false)
    \\  --disable-checkpoints skip PoW on every header while syncing (the Rust node's disable_checkpoints)
    \\  --extended-checkpoints  skip header PoW up to 3,700,000 instead of 3,500,000
    \\  --listen IP:PORT      accept inbound peers here (default 0.0.0.0:3414, floonet 13414)
    \\  --no-listen           don't accept inbound peers
    \\  --api IP:PORT         serve the REST API here (default 127.0.0.1:3413, floonet 13413)
    \\  --no-api              don't serve the API
    \\  --no-api-auth         serve the API without the Basic-auth secret (loopback only!)
    \\  --max-outbound N      keep up to N outbound peers learned from seeds and other peers
    \\  --seeds               with --peer: also discover peers (implied without --peer)
    \\  --seed HOST:PORT      an extra peer to try (repeatable)
    \\  --no-discovery        never look for peers beyond --peer (requires --peer)
    \\  --no-sync             don't sync, just run the peer network (for testing peer handling)
    \\  --allow-local-peers   accept private/loopback addresses as peers (tests, LANs)
    \\  --archive             keep every block (compaction only prunes the txhashset)
    \\  --floonet             use the floonet chain (default is mainnet)
    \\  --debug               also show DEBUG log lines (dial failures, rejected txs, timings)
    \\
    \\Ctrl-C (or SIGTERM) shuts down cleanly; a second Ctrl-C exits at once.
    \\
;

fn dieUsage(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("error: " ++ fmt ++ "\n\n{s}", args ++ .{usage});
    std.process.exit(2);
}

fn die(comptime fmt: []const u8, args: anytype) noreturn {
    epic.logging.err(fmt, args);
    std.process.exit(2);
}

/// Refuses paths that look like a running node's data or a wallet.
fn looksLikeLiveNodeData(path: []const u8) bool {
    const bad = [_][]const u8{ "/.epic", ".epic/", "/.boxwallet", ".boxwallet/", "/.epic-wallet" };
    for (bad) |b| if (std.mem.indexOf(u8, path, b) != null) return true;
    return std.mem.eql(u8, path, ".epic") or std.mem.eql(u8, path, ".boxwallet");
}

fn parseAddr(what: []const u8, s: []const u8) Io.net.IpAddress {
    const c = std.mem.lastIndexOfScalar(u8, s, ':') orelse die("{s} must be IP:PORT, got '{s}'", .{ what, s });
    const port = std.fmt.parseInt(u16, s[c + 1 ..], 10) catch die("bad port in {s} '{s}'", .{ what, s });
    return Io.net.IpAddress.parse(s[0..c], port) catch die("bad address in {s} '{s}'", .{ what, s });
}

fn bindFailed(what: []const u8, addr: []const u8, e: anyerror) noreturn {
    die("can't {s} on {s}: {s}. Is another node (or this one) already running there? " ++
        "Pick another address with --listen/--api or in epic-zig.toml, or turn it off with --no-listen/--no-api.", .{ what, addr, @errorName(e) });
}

/// The mainnet defaults move to the floonet ports on floonet (as in the reference).
fn chainPort(s: []const u8, floonet: bool) []const u8 {
    if (!floonet) return s;
    if (std.mem.eql(u8, s, "0.0.0.0:3414")) return "0.0.0.0:13414";
    if (std.mem.eql(u8, s, "127.0.0.1:3413")) return "127.0.0.1:13413";
    return s;
}

/// Command-line settings; null means "not given, use the config file".
const Cli = struct {
    data_dir: ?[]const u8 = null,
    config: ?[]const u8 = null,
    peer: ?[]const u8 = null,
    listen: ?[]const u8 = null,
    api: ?[]const u8 = null,
    no_api_auth: bool = false,
    no_listen: bool = false,
    no_api: bool = false,
    allow_local: bool = false,
    max_outbound: ?u32 = null,
    seeds: bool = false,
    extra_seeds: std.ArrayList([]const u8) = .empty,
    no_discovery: bool = false,
    no_sync: bool = false,
    archive: bool = false,
    verify_all_pow: bool = false,
    disable_checkpoints: bool = false,
    extended_checkpoints: bool = false,
    floonet: bool = false,
    opts: epic.sync.Options = .{},
};

fn parseCli(arena: std.mem.Allocator, args: []const []const u8) !Cli {
    var cli: Cli = .{};
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        const has_val = i + 1 < args.len;
        const eq = std.mem.eql;
        if (eq(u8, a, "--data-dir") and has_val) {
            i += 1;
            cli.data_dir = args[i];
        } else if (eq(u8, a, "--config") and has_val) {
            i += 1;
            cli.config = args[i];
        } else if (eq(u8, a, "--peer") and has_val) {
            i += 1;
            cli.peer = args[i];
        } else if (eq(u8, a, "--listen") and has_val) {
            i += 1;
            cli.listen = args[i];
        } else if (eq(u8, a, "--api") and has_val) {
            i += 1;
            cli.api = args[i];
        } else if (eq(u8, a, "--max-outbound") and has_val) {
            i += 1;
            cli.max_outbound = std.fmt.parseInt(u32, args[i], 10) catch dieUsage("bad --max-outbound", .{});
        } else if (eq(u8, a, "--seed") and has_val) {
            i += 1;
            try cli.extra_seeds.append(arena, args[i]);
        } else if (eq(u8, a, "--stop-height") and has_val) {
            i += 1;
            cli.opts.stop_height = std.fmt.parseInt(u64, args[i], 10) catch dieUsage("bad --stop-height", .{});
        } else if (eq(u8, a, "--allow-local-peers")) {
            cli.allow_local = true;
        } else if (eq(u8, a, "--seeds")) {
            cli.seeds = true;
        } else if (eq(u8, a, "--no-discovery")) {
            cli.no_discovery = true;
        } else if (eq(u8, a, "--no-sync")) {
            cli.no_sync = true;
        } else if (eq(u8, a, "--no-listen")) {
            cli.no_listen = true;
        } else if (eq(u8, a, "--no-api")) {
            cli.no_api = true;
        } else if (eq(u8, a, "--no-api-auth")) {
            cli.no_api_auth = true;
        } else if (eq(u8, a, "--archive")) {
            cli.archive = true;
        } else if (eq(u8, a, "--headers-only")) {
            cli.opts.headers_only = true;
        } else if (eq(u8, a, "--no-follow")) {
            cli.opts.follow = false;
        } else if (eq(u8, a, "--disable-checkpoints")) {
            cli.disable_checkpoints = true;
        } else if (eq(u8, a, "--extended-checkpoints")) {
            cli.extended_checkpoints = true;
        } else if (eq(u8, a, "--no-assume-valid")) {
            // the old opt-out; that is the default now
        } else if (eq(u8, a, "--verify-all-pow")) {
            cli.verify_all_pow = true;
        } else if (eq(u8, a, "--debug")) {
            epic.logging.show_debug = true;
        } else if (eq(u8, a, "--floonet")) {
            cli.floonet = true;
        } else if (eq(u8, a, "--help") or eq(u8, a, "-h")) {
            std.debug.print("{s}", .{usage});
            std.process.exit(0);
        } else dieUsage("unknown or incomplete argument: {s}", .{a});
    }
    return cli;
}

/// What the shutdown watcher needs.
const Running = struct {
    io: Io,
    chain: *epic.chain.Chain,
    node: *epic.node.Node,
    api: ?*epic.api.Api = null,
};

/// Waits for Ctrl-C/SIGTERM, then stops the node in order: wait for the chain
/// to be idle (a state-sync download/validation is simply abandoned: it works
/// in a sandbox), fsync the txhashset, save the peers, flush the database log.
fn shutdownWatcher(r: *Running) void {
    while (!epic.shutdown.requested.load(.acquire)) r.io.sleep(.fromMilliseconds(200), .awake) catch {};
    epic.logging.warn("Received SIGINT (Ctrl+C) or SIGTERM (kill).", .{});
    r.node.setSyncStatus(.shutdown);
    if (r.api) |a| a.stop();
    epic.logging.warn("Shutting down...", .{});
    if (r.chain.state_sync_active.load(.acquire)) {
        epic.logging.warn("Abandoning the state sync in progress (it restarts next time)", .{});
        epic.logging.warn("Shutdown complete.", .{});
        r.node.store.save() catch {};
        std.process.exit(0);
    }
    var waited: u32 = 0;
    while (!r.chain.mutex.tryLock()) : (waited += 1) {
        if (waited == 10) epic.logging.info("Waiting for the current block/header batch to finish...", .{});
        r.io.sleep(.fromMilliseconds(200), .awake) catch {};
    }
    // the lock is never released: nothing else may touch the chain now
    r.chain.endCatchup();
    r.chain.ths.sync() catch |e| epic.logging.err("Txhashset sync failed: {s}", .{@errorName(e)});
    r.node.store.save() catch {};
    r.chain.db.store.flushWal() catch |e| epic.logging.err("Database log flush failed: {s}", .{@errorName(e)});
    const tip = r.chain.head() catch null;
    const hh = r.chain.headerHead() catch null;
    epic.logging.info("Chain state saved: body head {f}, header head {f}", .{ N(if (tip) |t| t.height else 0), N(if (hh) |h| h.height else 0) });
    epic.logging.warn("Shutdown complete.", .{});
    std.process.exit(0);
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    const cli = try parseCli(arena, args);

    const dd = cli.data_dir orelse dieUsage("--data-dir is required", .{});
    if (looksLikeLiveNodeData(dd)) dieUsage("refusing to use '{s}': it looks like a live node/wallet directory", .{dd});

    // ---- settings: defaults < config file < flags
    var data_dir = try Io.Dir.cwd().createDirPathOpen(io, dd, .{});
    defer data_dir.close(io);
    var diag: epic.config.Diag = .{};
    const file_path = cli.config orelse epic.config.FILE_NAME;
    const file_dir = if (cli.config != null) Io.Dir.cwd() else data_dir;
    const fc = epic.config.load(arena, io, file_dir, file_path, cli.config == null, &diag) catch |e| switch (e) {
        error.BadConfig => die("{s}, line {d}: {s}", .{ file_path, diag.line, diag.msg }),
        else => die("can't read {s}: {s}", .{ file_path, @errorName(e) }),
    };

    var cfg: epic.chain.Config = .{};
    if (cli.floonet or std.mem.eql(u8, fc.chain, "floonet")) {
        cfg.chain = .floonet;
    } else if (!std.mem.eql(u8, fc.chain, "mainnet")) die("unknown chain '{s}' in the config", .{fc.chain});
    cfg.skip_pow_in_checkpoints = fc.skip_pow_validation and !cli.verify_all_pow;
    cfg.disable_checkpoints = fc.disable_checkpoints or cli.disable_checkpoints;
    cfg.assume_valid = fc.extended_checkpoints or cli.extended_checkpoints;
    cfg.archive_mode = cli.archive or fc.archive_mode;

    const peer: ?[]const u8 = cli.peer orelse if (fc.peer.len > 0) fc.peer else null;
    const floonet = cfg.chain == .floonet;
    const listen: ?[]const u8 = if (cli.no_listen) null else cli.listen orelse if (fc.listen.len > 0) chainPort(fc.listen, floonet) else null;
    const api_listen: ?[]const u8 = if (cli.no_api) null else cli.api orelse if (fc.api_listen.len > 0) chainPort(fc.api_listen, floonet) else null;
    const api_auth = fc.api_auth and !cli.no_api_auth;
    const allow_local = cli.allow_local or fc.allow_local_peers;
    if (peer == null and cli.no_discovery) dieUsage("--no-discovery needs --peer", .{});

    const peer_addr: ?Io.net.IpAddress = if (peer) |p| parseAddr("peer", p) else null;
    var extra_seeds: std.ArrayList(Io.net.IpAddress) = .empty;
    for (fc.extra_seeds) |s| try extra_seeds.append(arena, parseAddr("extra_seeds", s));
    for (cli.extra_seeds.items) |s| try extra_seeds.append(arena, parseAddr("--seed", s));

    // discovery: on by default without a peer; with one, only when asked for
    const discover = !cli.no_discovery and (peer == null or cli.max_outbound != null or cli.seeds or extra_seeds.items.len > 0);
    const use_seeds = discover and fc.seeds and (peer == null or cli.seeds or cli.max_outbound != null);
    const outbound: u32 = if (!discover) 0 else (cli.max_outbound orelse fc.max_outbound);

    epic.logging.info("This is Epic-Zig version {s}, built for {s}-{s} by Zig {s}.", .{ VERSION, @tagName(builtin.cpu.arch), @tagName(builtin.os.tag), builtin.zig_version_string });
    epic.logging.info("Using configuration file at {s}{s}", .{ if (cli.config) |p| p else dd, if (cli.config == null) "/" ++ epic.config.FILE_NAME else "" });
    epic.logging.info("Chain: {s}, data dir {s}, peers: {s}", .{ @tagName(cfg.chain), dd, if (peer) |p| p else "from the network's seeds" });
    if (cfg.chain == .mainnet) {
        if (!cfg.skip_pow_in_checkpoints) {
            epic.logging.info("Header PoW: checked on every header (skip_pow_validation = false)", .{});
        } else if (cfg.disable_checkpoints) {
            epic.logging.warn("Header PoW: NOT checked on any header while syncing (disable_checkpoints = true)", .{});
        } else {
            epic.logging.info("Header PoW: skipped up to height {f} ({s}), checked above; --verify-all-pow checks every header", .{
                N(epic.checkpoints.trustedUpTo(cfg.assume_valid)),
                if (cfg.assume_valid) "the Rust node's checkpoints to 2,200,000, then ours and the extended ones" else "the Rust node's checkpoints to 2,200,000, then ours",
            });
        }
    }

    epic.shutdown.install();

    const c = try epic.chain.Chain.open(gpa, io, dd, cfg);
    defer c.close();
    epic.logging.info("Chain opened: body head {f}, header head {f}", .{ N((try c.head()).height), N((try c.headerHead()).height) });

    const node = try epic.node.Node.create(gpa, io, c, .{
        .accept_fee_base = fc.accept_fee_base,
        .max_pool_size = fc.max_pool_size,
        .max_stempool_size = fc.max_stempool_size,
        .mineable_max_weight = fc.mineable_max_weight,
    }, .{ .allow_local_peers = allow_local });
    defer node.destroy();
    node.epoch.cfg = .{
        .epoch_secs = fc.epoch_secs,
        .embargo_secs = fc.embargo_secs,
        .aggregation_secs = fc.aggregation_secs,
        .stem_probability = fc.stem_probability,
        .always_stem_our_txs = fc.always_stem_our_txs,
    };

    var running: Running = .{ .io = io, .chain = c, .node = node };
    const watcher = try std.Thread.spawn(.{}, shutdownWatcher, .{&running});
    watcher.detach();

    const server = try epic.server.Server.create(gpa, io, node);
    try node.startMaintenance();
    try node.startDandelion();
    if (listen) |l| {
        const laddr = parseAddr("listen", l);
        server.listen(laddr) catch |e| bindFailed("listen for peers", l, e);
        // tell the peers we dial where to reach us
        epic.p2p_client.advertised = epic.peer_store.toPeerAddr(laddr);
        node.listen_desc = l;
        epic.logging.info("Starting P2P server, listening on {s}", .{l});
    }
    if (discover) {
        try server.startDiscovery(outbound, use_seeds, extra_seeds.items);
        epic.logging.info("Starting peer discovery: up to {d} outbound peer(s), seeds {s}", .{ outbound, if (use_seeds) "on" else "off" });
    }
    if (api_listen) |l| {
        const laddr = parseAddr("api listen", l);
        var secret: ?[]u8 = null;
        var foreign_secret: ?[]u8 = null;
        if (api_auth) {
            secret = epic.api.loadOrCreateSecret(gpa, io, c.root, fc.api_secret_path) catch |e| die("can't read or create the API secret '{s}': {s}", .{ fc.api_secret_path, @errorName(e) });
            if (fc.foreign_api_secret_path.len > 0)
                foreign_secret = epic.api.loadSecret(gpa, io, c.root, fc.foreign_api_secret_path) catch |e| die("can't read the foreign API secret '{s}': {s}", .{ fc.foreign_api_secret_path, @errorName(e) });
        }
        epic.logging.info("Starting HTTP Node APIs server at {s}.", .{l});
        running.api = epic.api.Api.start(gpa, io, node, laddr, secret, foreign_secret) catch |e| bindFailed("serve the API", l, e);
        if (api_auth) {
            epic.logging.info("HTTP Node APIs server started at {s} (Basic auth: user 'epic', secret from {s}; /v2/foreign {s})", .{ l, fc.api_secret_path, if (foreign_secret != null) "needs the foreign API secret" else "open, as the Rust node's default" });
        } else epic.logging.warn("HTTP Node APIs server started at {s} WITHOUT authentication", .{l});
    }
    epic.logging.info("Epic node server started.", .{});

    if (cli.no_sync) {
        node.setSyncStatus(.no_sync);
        // peer-network-only mode: report now and then until stopped
        while (true) {
            io.sleep(.fromSeconds(20), .awake) catch {};
            node.logPeers();
        }
    }

    var conn: *epic.p2p_client.Conn = undefined;
    var sync_addr: Io.net.IpAddress = undefined;
    if (peer_addr) |addr| {
        // the named peer may be down at startup: keep trying rather than exiting
        var attempt: u32 = 0;
        conn = while (true) : (attempt += 1) {
            if (epic.p2p_client.Conn.connect(gpa, io, addr, cfg.chain, c.genesis.hash(), c.genesis.header.pow.total_difficulty)) |cn| break cn else |e| {
                epic.logging.warn("Can't reach peer {s} ({s}); retrying", .{ peer.?, @errorName(e) });
                io.sleep(.fromSeconds(@min(5 + attempt * 5, 60)), .awake) catch {};
            }
        };
        sync_addr = addr;
    } else {
        const found = try epic.discovery.findSyncPeer(gpa, io, node, use_seeds or !discover, extra_seeds.items);
        conn = found.conn;
        sync_addr = found.addr;
    }
    try epic.sync.Syncer.run(gpa, io, c, conn, sync_addr, cli.opts, node);
    epic.logging.info("Done. body head {f}, header head {f}", .{ N((try c.head()).height), N((try c.headerHead()).height) });
}
