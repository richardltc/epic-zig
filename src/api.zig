//! The node's REST API (`api/src/handlers*.rs`): the v1 endpoints wallets and
//! explorers use. Served over plain HTTP with optional Basic auth (user
//! `epic`, password = the API secret), one thread per connection.
//!
//! Also the JSON-RPC APIs: `/v2/owner` (status, peers, validate/compact) and
//! `/v2/foreign` (chain reads, pool, push). As in the reference, `/v1` and
//! `/v2/owner` need the API secret and `/v2/foreign` only needs the foreign
//! secret when one is configured.
//!
//! Not yet served: merkle proofs in output listings, `/v1/mining/*`, `/v2/tor`.
const std = @import("std");
const Io = std.Io;
const net = Io.net;
const http = std.http;
const Writer = Io.Writer;
const node_mod = @import("node.zig");
const chain_mod = @import("chain.zig");
const json = @import("api_json.zig");
const consensus = @import("consensus.zig");
const block = @import("block.zig");
const tx_mod = @import("transaction.zig");
const crypto = @import("crypto.zig");
const hash_mod = @import("hash.zig");
const ser = @import("ser.zig");
const msg = @import("p2p_msg.zig");
const chain_types = @import("chain_types.zig");
const txhashset_mod = @import("txhashset.zig");

const Node = node_mod.Node;
const Chain = chain_mod.Chain;
const Hash = hash_mod.Hash;
const Commitment = crypto.Commitment;

const MAX_BODY: usize = 4 << 20;
const MAX_CONNECTIONS: u32 = 64;
pub const USERNAME = "epic";
/// The reference node version whose API this one implements. Wallets parse the
/// `node_version` of `get_version` as a semantic version and check it, so it
/// is the reference's crate version (as the reference reports), not our user agent.
pub const NODE_VERSION = "4.0.4";

const logging = @import("logging.zig");
fn log(comptime fmt: []const u8, args: anytype) void {
    logging.info(fmt, args);
}
fn warn(comptime fmt: []const u8, args: anytype) void {
    logging.warn(fmt, args);
}
fn debug(comptime fmt: []const u8, args: anytype) void {
    logging.debug(fmt, args);
}

const Reply = struct {
    status: http.Status = .ok,
    /// Owned by the reply.
    body: []u8,
};

const ApiError = error{ BadRequest, NotFound, Internal } || std.mem.Allocator.Error || Writer.Error;

pub const Api = struct {
    gpa: std.mem.Allocator,
    io: Io,
    node: *Node,
    chain: *Chain,
    listener: net.Server,
    /// `base64("epic:<secret>")` for `/v1` and `/v2/owner`, or null when auth is off.
    auth_token: ?[]const u8,
    /// The same for `/v2/foreign`; null leaves it open (the reference's default).
    foreign_token: ?[]const u8 = null,
    active: std.atomic.Value(u32) = .init(0),
    addr: net.IpAddress,
    stopping: std.atomic.Value(bool) = .init(false),
    stopped: std.atomic.Value(bool) = .init(false),

    fn basicToken(gpa: std.mem.Allocator, secret: ?[]const u8) !?[]const u8 {
        const s = secret orelse return null;
        const plain = try std.fmt.allocPrint(gpa, "{s}:{s}", .{ USERNAME, s });
        defer gpa.free(plain);
        const enc = std.base64.standard.Encoder;
        const out = try gpa.alloc(u8, enc.calcSize(plain.len));
        _ = enc.encode(out, plain);
        return out;
    }

    pub fn start(gpa: std.mem.Allocator, io: Io, node: *Node, addr: net.IpAddress, secret: ?[]const u8, foreign_secret: ?[]const u8) !*Api {
        const self = try gpa.create(Api);
        errdefer gpa.destroy(self);
        const token = try basicToken(gpa, secret);
        const ftoken = try basicToken(gpa, foreign_secret);
        self.* = .{ .gpa = gpa, .io = io, .node = node, .chain = node.chain, .listener = try addr.listen(io, .{}), .auth_token = token, .foreign_token = ftoken, .addr = addr };
        const t = try std.Thread.spawn(.{}, acceptLoop, .{self});
        t.detach();
        return self;
    }

    /// Stops accepting connections (requests in flight finish on their own).
    /// Waits up to a couple of seconds for the accept loop to close.
    pub fn stop(self: *Api) void {
        self.stopping.store(true, .release);
        // wake the blocked accept with a connection of our own
        var a = self.addr;
        switch (a) {
            .ip4 => |*x| if (std.mem.eql(u8, &x.bytes, &.{ 0, 0, 0, 0 })) {
                x.bytes = .{ 127, 0, 0, 1 };
            },
            .ip6 => |*x| if (std.mem.allEqual(u8, &x.bytes, 0)) {
                x.bytes[15] = 1;
            },
        }
        if (a.connect(self.io, .{ .mode = .stream })) |s| s.close(self.io) else |_| {}
        var i: u32 = 0;
        while (!self.stopped.load(.acquire) and i < 20) : (i += 1) self.io.sleep(.fromMilliseconds(100), .awake) catch {};
    }

    fn acceptLoop(self: *Api) void {
        while (true) {
            const stream = self.listener.accept(self.io) catch {
                if (self.stopping.load(.acquire)) break;
                self.io.sleep(.fromSeconds(1), .awake) catch {};
                continue;
            };
            if (self.stopping.load(.acquire)) {
                stream.close(self.io);
                break;
            }
            if (self.active.load(.monotonic) >= MAX_CONNECTIONS) {
                stream.close(self.io);
                continue;
            }
            _ = self.active.fetchAdd(1, .monotonic);
            const t = std.Thread.spawn(.{}, serveConn, .{ self, stream }) catch {
                stream.close(self.io);
                _ = self.active.fetchSub(1, .monotonic);
                continue;
            };
            t.detach();
        }
        self.listener.deinit(self.io);
        log("API server has been stopped", .{});
        self.stopped.store(true, .release);
    }

    fn serveConn(self: *Api, stream: net.Stream) void {
        defer _ = self.active.fetchSub(1, .monotonic);
        defer stream.close(self.io);
        var rbuf: [16 * 1024]u8 = undefined;
        var wbuf: [16 * 1024]u8 = undefined;
        var sr = stream.reader(self.io, &rbuf);
        var sw = stream.writer(self.io, &wbuf);
        var server = http.Server.init(&sr.interface, &sw.interface);
        while (true) {
            var req = server.receiveHead() catch return;
            const keep = req.head.keep_alive;
            self.handleRequest(&req) catch return;
            if (!keep) return;
        }
    }

    fn authorized(req: *http.Server.Request, want: ?[]const u8) bool {
        const token = want orelse return true;
        var it = req.iterateHeaders();
        while (it.next()) |h| {
            if (!std.ascii.eqlIgnoreCase(h.name, "authorization")) continue;
            const prefix = "Basic ";
            if (!std.mem.startsWith(u8, h.value, prefix)) return false;
            return std.mem.eql(u8, std.mem.trim(u8, h.value[prefix.len..], " "), token);
        }
        return false;
    }

    fn handleRequest(self: *Api, req: *http.Server.Request) !void {
        const foreign = std.mem.startsWith(u8, req.head.target, "/v2/foreign");
        if (!authorized(req, if (foreign) self.foreign_token else self.auth_token)) {
            return req.respond("Unauthorized", .{
                .status = .unauthorized,
                .extra_headers = &.{.{ .name = "www-authenticate", .value = if (foreign) "Basic realm=\"EpicForeignAPI\"" else "Basic realm=\"EpicAPI\"" }},
            });
        }
        const method = req.head.method;
        // a POST without Content-Length or chunking has no body (RFC 7230);
        // std.http would otherwise wait for one until the client hangs up
        if (method.requestHasBody() and req.head.content_length == null and req.head.transfer_encoding == .none)
            req.head.content_length = 0;
        // copy the target: reading the body invalidates the head buffers
        const target = try self.gpa.dupe(u8, req.head.target);
        defer self.gpa.free(target);

        var body: []u8 = &.{};
        defer if (body.len > 0) self.gpa.free(body);
        if (method == .POST or method == .PUT) {
            const len = req.head.content_length orelse 0;
            if (len > MAX_BODY) return req.respond("body too large", .{ .status = .payload_too_large });
            if (len > 0) {
                var tmp: [1024]u8 = undefined;
                const reader = req.readerExpectNone(&tmp);
                body = reader.readAlloc(self.gpa, @intCast(len)) catch return req.respond("bad body", .{ .status = .bad_request });
            }
        }

        const reply = self.route(method, target, body) catch |e| {
            const code: http.Status = switch (e) {
                error.BadRequest => .bad_request,
                error.NotFound => .not_found,
                else => .internal_server_error,
            };
            return req.respond(@errorName(e), .{ .status = code });
        };
        defer self.gpa.free(reply.body);
        try req.respond(reply.body, .{
            .status = reply.status,
            .extra_headers = &.{.{ .name = "content-type", .value = "application/json" }},
        });
    }

    // ------------------------------------------------------------ routing

    const Query = struct {
        raw: []const u8,

        fn get(self: Query, name: []const u8) ?[]const u8 {
            var it = std.mem.splitScalar(u8, self.raw, '&');
            while (it.next()) |kv| {
                const eq = std.mem.indexOfScalar(u8, kv, '=') orelse kv.len;
                if (std.mem.eql(u8, kv[0..eq], name)) return if (eq < kv.len) kv[eq + 1 ..] else "";
            }
            return null;
        }
        fn has(self: Query, name: []const u8) bool {
            return self.get(name) != null;
        }
        fn u64Or(self: Query, name: []const u8, default: u64) u64 {
            const v = self.get(name) orelse return default;
            return std.fmt.parseInt(u64, v, 10) catch default;
        }
    };

    fn route(self: *Api, method: http.Method, target: []const u8, body: []const u8) ApiError!Reply {
        const q_at = std.mem.indexOfScalar(u8, target, '?');
        var path = target[0 .. q_at orelse target.len];
        const query: Query = .{ .raw = if (q_at) |i| target[i + 1 ..] else "" };
        while (path.len > 1 and path[path.len - 1] == '/') path = path[0 .. path.len - 1];

        var aw: Writer.Allocating = .init(self.gpa);
        errdefer aw.deinit();
        const w = &aw.writer;

        if (method == .GET) {
            if (std.mem.eql(u8, path, "/v1")) {
                try w.writeAll("[\"get blocks\",\"get headers\",\"get chain\",\"post chain/compact\",\"get chain/validate\",\"get chain/kernels/xxx?min_height=yyy&max_height=zzz\",\"get chain/outputs/byids?id=xxx,yyy,zzz\",\"get chain/outputs/byheight?start_height=101&end_height=200\",\"get status\",\"get txhashset/roots\",\"get txhashset/lastoutputs?n=10\",\"get txhashset/lastrangeproofs\",\"get txhashset/lastkernels\",\"get txhashset/outputs?start_index=1&max=100\",\"get txhashset/heightstopmmr?start_height=1&end_height=1000\",\"get pool\",\"post pool/push_tx\",\"get peers/all\",\"get peers/connected\",\"get version\"]");
            } else if (std.mem.eql(u8, path, "/v1/version")) {
                try w.print("{{\"node_version\":\"{s}\",\"block_header_version\":{d}}}", .{ NODE_VERSION, self.headerVersionNext() });
            } else if (std.mem.eql(u8, path, "/v1/status")) {
                try self.status(w);
            } else if (std.mem.eql(u8, path, "/v1/chain")) {
                const tip = self.chain.head() catch return error.Internal;
                try json.tip(w, tip);
            } else if (std.mem.eql(u8, path, "/v1/pool")) {
                try self.poolInfo(w);
            } else if (std.mem.eql(u8, path, "/v1/peers/connected")) {
                try self.connectedPeers(w);
            } else if (std.mem.eql(u8, path, "/v1/peers/all")) {
                try self.allPeers(w, null);
            } else if (std.mem.eql(u8, path, "/v1/peers/onion_addresses")) {
                try w.writeAll("{\"onion_addresses\":[]}");
            } else if (std.mem.eql(u8, path, "/v1/chain/validate")) {
                try self.validateChain();
                try w.writeAll("{}");
            } else if (std.mem.eql(u8, path, "/v1/chain/outputs/byids")) {
                try self.outputsByIds(w, query);
            } else if (std.mem.eql(u8, path, "/v1/chain/outputs/byheight")) {
                try self.outputsByHeight(w, query);
            } else if (std.mem.startsWith(u8, path, "/v1/chain/kernels/")) {
                try self.kernel(w, path["/v1/chain/kernels/".len..], query);
            } else if (std.mem.startsWith(u8, path, "/v1/txhashset/")) {
                try self.txhashset(w, path["/v1/txhashset/".len..], query);
            } else if (std.mem.startsWith(u8, path, "/v1/blocks/")) {
                try self.blockById(w, path["/v1/blocks/".len..], query, false);
            } else if (std.mem.startsWith(u8, path, "/v1/headers/")) {
                try self.blockById(w, path["/v1/headers/".len..], query, true);
            } else return error.NotFound;
        } else if (method == .POST) {
            if (std.mem.eql(u8, path, "/v1/pool/push_tx")) {
                try self.pushTx(body, query);
            } else if (std.mem.eql(u8, path, "/v1/chain/compact")) {
                self.chain.lock();
                defer self.chain.unlock();
                const ran = self.chain.compact() catch return error.Internal;
                try w.writeAll(if (ran) "{}" else "{\"note\":\"nothing to compact yet: the chain is not far enough past the last compaction\"}");
            } else if (std.mem.eql(u8, path, "/v2/foreign")) {
                try self.rpc(w, body, .foreign);
            } else if (std.mem.eql(u8, path, "/v2/owner")) {
                try self.rpc(w, body, .owner);
            } else return error.NotFound;
        } else return error.NotFound;

        return .{ .body = try aw.toOwnedSlice() };
    }

    fn headerVersionNext(self: *Api) u16 {
        const tip = self.chain.head() catch return block.BlockHeader.CURRENT_VERSION;
        return if (tip.height + 1 < self.chain.cfg.chain.readParams().first_fork_height) 6 else 7;
    }


    // ------------------------------------------------ /v2/foreign JSON-RPC

    fn paramAt(params: std.json.Value, i: usize) ?std.json.Value {
        if (params != .array or i >= params.array.items.len) return null;
        const v = params.array.items[i];
        return if (v == .null) null else v;
    }

    fn paramU64(params: std.json.Value, i: usize) ?u64 {
        const v = paramAt(params, i) orelse return null;
        return switch (v) {
            .integer => |x| if (x >= 0) @intCast(x) else null,
            else => null,
        };
    }

    fn paramBool(params: std.json.Value, i: usize) ?bool {
        const v = paramAt(params, i) orelse return null;
        return if (v == .bool) v.bool else null;
    }

    fn paramStr(params: std.json.Value, i: usize) ?[]const u8 {
        const v = paramAt(params, i) orelse return null;
        return if (v == .string) v.string else null;
    }

    fn rpcEnvelope(w: *Writer, id: std.json.Value) Writer.Error!void {
        try w.writeAll("{\"id\":");
        switch (id) {
            .integer => |n| try w.print("{d}", .{n}),
            .string => |s| try w.print("\"{s}\"", .{s}),
            else => try w.writeAll("null"),
        }
        try w.writeAll(",\"jsonrpc\":\"2.0\",");
    }

    const RpcKind = enum { owner, foreign };

    fn rpc(self: *Api, w: *Writer, body: []const u8, kind: RpcKind) ApiError!void {
        var parsed = std.json.parseFromSlice(std.json.Value, self.gpa, body, .{}) catch {
            try w.writeAll("{\"id\":null,\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32700,\"message\":\"Parse error\"}}");
            return;
        };
        defer parsed.deinit();
        if (parsed.value == .array) {
            try w.writeAll("[");
            for (parsed.value.array.items, 0..) |call, i| {
                if (i > 0) try w.writeAll(",");
                try self.oneCall(w, call, kind);
            }
            try w.writeAll("]");
        } else try self.oneCall(w, parsed.value, kind);
    }

    fn oneCall(self: *Api, w: *Writer, call: std.json.Value, kind: RpcKind) ApiError!void {
        const id: std.json.Value = if (call == .object) (call.object.get("id") orelse .null) else .null;
        const method = if (call == .object) (call.object.get("method") orelse .null) else .null;
        const params: std.json.Value = if (call == .object) (call.object.get("params") orelse .null) else .null;
        try rpcEnvelope(w, id);
        if (method != .string) {
            try w.writeAll("\"error\":{\"code\":-32600,\"message\":\"Invalid Request\"}}");
            return;
        }
        var out: Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        const res = switch (kind) {
            .foreign => self.foreignMethod(&out.writer, method.string, params),
            .owner => self.ownerMethod(&out.writer, method.string, params),
        };
        if (res) |known| {
            if (!known) {
                try w.writeAll("\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}");
                return;
            }
            try w.print("\"result\":{{\"Ok\":{s}}}}}", .{out.written()});
        } else |e| {
            const err_json: []const u8 = switch (e) {
                error.BadRequest => "{\"Argument\":\"bad request\"}",
                error.NotFound => "\"NotFound\"",
                else => "{\"Internal\":\"node error\"}",
            };
            try w.print("\"result\":{{\"Err\":{s}}}}}", .{err_json});
        }
    }

    /// Runs one foreign API method, writing its `Ok` value to `w`. Returns
    /// false if the method is unknown.
    fn foreignMethod(self: *Api, w: *Writer, name: []const u8, params: std.json.Value) ApiError!bool {
        const eq = std.mem.eql;
        if (eq(u8, name, "get_version")) {
            try w.print("{{\"node_version\":\"{s}\",\"block_header_version\":{d}}}", .{ NODE_VERSION, self.headerVersionNext() });
        } else if (eq(u8, name, "get_tip")) {
            try json.tip(w, self.chain.head() catch return error.Internal);
        } else if (eq(u8, name, "get_header") or eq(u8, name, "get_block")) {
            var idbuf: [24]u8 = undefined;
            const id: []const u8 = if (paramU64(params, 0)) |h|
                std.fmt.bufPrint(&idbuf, "{d}", .{h}) catch return error.BadRequest
            else
                (paramStr(params, 1) orelse paramStr(params, 2) orelse return error.BadRequest);
            try self.blockById(w, id, .{ .raw = "" }, eq(u8, name, "get_header"));
        } else if (eq(u8, name, "get_kernel")) {
            const excess = paramStr(params, 0) orelse return error.BadRequest;
            var qb: [80]u8 = undefined;
            const q = std.fmt.bufPrint(&qb, "min_height={d}&max_height={d}", .{ paramU64(params, 1) orelse 0, paramU64(params, 2) orelse std.math.maxInt(u32) }) catch return error.BadRequest;
            try self.kernel(w, excess, .{ .raw = q });
        } else if (eq(u8, name, "get_outputs")) {
            try self.rpcOutputs(w, params);
        } else if (eq(u8, name, "get_unspent_outputs")) {
            const from = paramU64(params, 0) orelse 1;
            const end = paramU64(params, 1);
            const max = @min(paramU64(params, 2) orelse 100, 10_000);
            self.chain.lock();
            defer self.chain.unlock();
            const listing = self.chain.ths.outputsFromPmmrIndex(self.gpa, from, max, end) catch return error.Internal;
            defer self.gpa.free(listing.outputs);
            try w.print("{{\"highest_index\":{d},\"last_retrieved_index\":{d},\"outputs\":[", .{ end orelse self.chain.ths.sizes.output, listing.last_index });
            for (listing.outputs, 0..) |o, i| {
                if (i > 0) try w.writeAll(",");
                try json.outputPrintable(w, o, self.outputInfo(o, paramBool(params, 3) orelse false));
            }
            try w.writeAll("]}");
        } else if (eq(u8, name, "get_pmmr_indices")) {
            var qb: [80]u8 = undefined;
            const q = std.fmt.bufPrint(&qb, "start_height={d}&end_height={d}", .{ paramU64(params, 0) orelse 1, paramU64(params, 1) orelse 0 }) catch return error.BadRequest;
            try self.txhashset(w, "heightstopmmr", .{ .raw = q });
        } else if (eq(u8, name, "get_pool_size")) {
            self.node.pool.lock();
            defer self.node.pool.unlock();
            try w.print("{d}", .{self.node.pool.totalSize()});
        } else if (eq(u8, name, "get_stempool_size")) {
            self.node.pool.lock();
            defer self.node.pool.unlock();
            try w.print("{d}", .{self.node.pool.stempool.size()});
        } else if (eq(u8, name, "get_unconfirmed_transactions")) {
            self.node.pool.lock();
            defer self.node.pool.unlock();
            try w.writeAll("[");
            for (self.node.pool.txpool.entries.items, 0..) |e, i| {
                if (i > 0) try w.writeAll(",");
                const src: []const u8 = switch (e.src) {
                    .push_api => "PushApi",
                    .broadcast => "Broadcast",
                    .fluff => "Fluff",
                    .embargo_expired => "EmbargoExpired",
                    .deaggregate => "Deaggregate",
                };
                try w.print("{{\"src\":\"{s}\",\"tx_at\":", .{src});
                var tb: [40]u8 = undefined;
                var tw = Writer.fixed(&tb);
                try json.rfc3339(&tw, @divFloor(e.tx_at_ms, 1000));
                // chrono's serde form ends in Z
                const t = tw.buffered();
                try w.print("\"{s}Z\"", .{t[1 .. t.len - 7]});
                try w.writeAll(",\"tx\":");
                try json.transaction(w, e.tx);
                try w.writeAll("}");
            }
            try w.writeAll("]");
        } else if (eq(u8, name, "push_transaction")) {
            const txv = paramAt(params, 0) orelse return error.BadRequest;
            var tx = json.parseTransaction(self.gpa, txv) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.BadRequest,
            };
            defer tx.deinit(self.gpa);
            const fluff = paramBool(params, 1) orelse false;
            log("Pushing transaction {s} to pool (inputs: {d}, outputs: {d}, kernels: {d}), fluff: {}", .{ tx.hash().toHex()[0..12], tx.body.inputs.len, tx.body.outputs.len, tx.body.kernels.len, fluff });
            self.node.addTx(null, tx, !fluff) catch |e| {
                warn("Failed to update pool: {s}", .{@errorName(e)});
                return error.BadRequest;
            };
            try w.writeAll("null");
        } else return false;
        return true;
    }

    /// Runs one owner API method (`api/src/owner_rpc.rs`), writing its `Ok`
    /// value to `w`. Returns false if the method is unknown.
    fn ownerMethod(self: *Api, w: *Writer, name: []const u8, params: std.json.Value) ApiError!bool {
        const eq = std.mem.eql;
        if (eq(u8, name, "get_status")) {
            try self.status(w);
        } else if (eq(u8, name, "validate_chain")) {
            try self.validateChain();
            try w.writeAll("null");
        } else if (eq(u8, name, "compact_chain")) {
            self.chain.lock();
            defer self.chain.unlock();
            _ = self.chain.compact() catch return error.Internal;
            try w.writeAll("null");
        } else if (eq(u8, name, "get_peers")) {
            const want: ?net.IpAddress = if (paramStr(params, 0)) |a| (parseSocketAddr(a) orelse return error.BadRequest) else null;
            try self.allPeers(w, want);
        } else if (eq(u8, name, "get_connected_peers")) {
            try self.connectedPeers(w);
        } else if (eq(u8, name, "ban_peer")) {
            const a = parseSocketAddr(paramStr(params, 0) orelse return error.BadRequest) orelse return error.BadRequest;
            self.node.banPeer(a, "ManualBan");
            try w.writeAll("null");
        } else if (eq(u8, name, "unban_peer")) {
            const a = parseSocketAddr(paramStr(params, 0) orelse return error.BadRequest) orelse return error.BadRequest;
            self.node.store.unban(a);
            self.node.store.save() catch {};
            log("Unbanned peer {f}", .{a});
            try w.writeAll("null");
        } else if (eq(u8, name, "get_onion_addresses")) {
            try w.writeAll("[]");
        } else return false;
        return true;
    }

    /// "1.2.3.4:3414" or "[::1]:3414".
    fn parseSocketAddr(s: []const u8) ?net.IpAddress {
        const c = std.mem.lastIndexOfScalar(u8, s, ':') orelse return null;
        const port = std.fmt.parseInt(u16, s[c + 1 ..], 10) catch return null;
        var host = s[0..c];
        if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']') host = host[1 .. host.len - 1];
        return net.IpAddress.parse(host, port) catch null;
    }

    fn validateChain(self: *Api) ApiError!void {
        self.chain.lock();
        defer self.chain.unlock();
        self.chain.validateChain(true) catch |e| {
            warn("Chain validation failed: {s}", .{@errorName(e)});
            return error.Internal;
        };
    }

    /// `get_outputs(commits, start_height, end_height, include_proof, include_merkle_proof)`.
    fn rpcOutputs(self: *Api, w: *Writer, params: std.json.Value) ApiError!void {
        const include_proof = paramBool(params, 3) orelse false;
        self.chain.lock();
        defer self.chain.unlock();
        try w.writeAll("[");
        var first = true;
        if (paramAt(params, 0)) |cs| if (cs == .array) {
            for (cs.array.items) |c| {
                if (c != .string) continue;
                const commit = parseCommit(c.string) catch return error.BadRequest;
                const f = self.findUnspent(commit) orelse continue;
                const o = self.chain.ths.unspentOutputAt(f.pos) orelse continue;
                if (!first) try w.writeAll(",");
                first = false;
                try json.outputPrintable(w, o, .{ .spent = false, .block_height = f.height, .mmr_index = f.pos, .include_proof = include_proof });
            }
        };
        if (paramU64(params, 1)) |from| if (paramU64(params, 2)) |to| {
            if (to < from or to - from > 10_000) return error.BadRequest;
            var h = to + 1;
            while (h > from) {
                h -= 1;
                const header = self.headerAtHeight(h) orelse continue;
                var b = (self.chain.db.getBlock(self.chain.db.store, header.hash()) catch null) orelse continue;
                defer b.deinit(self.gpa);
                for (b.body.outputs) |o| {
                    if (!first) try w.writeAll(",");
                    first = false;
                    try json.outputPrintable(w, o, self.outputInfo(o, include_proof));
                }
            }
        };
        try w.writeAll("]");
    }

    // ------------------------------------------------------ small handlers

    /// The reference's `Status` (`/v1/status`, owner `get_status`).
    fn status(self: *Api, w: *Writer) ApiError!void {
        const tip = self.chain.head() catch return error.Internal;
        try w.print("{{\"protocol_version\":{d},\"user_agent\":\"{s}\",\"connections\":{d},\"tip\":", .{ ser.ProtocolVersion.local().v, msg.USER_AGENT, self.node.peers.count() });
        try json.tip(w, tip);
        const hh = (self.chain.headerHead() catch return error.Internal).height;
        const network_h = @max(hh, self.node.peers.maxHeight());
        switch (self.node.syncStatus()) {
            .awaiting_peers => try w.writeAll(",\"sync_status\":\"awaiting_peers\""),
            .header_sync => |x| try w.print(",\"sync_status\":\"header_sync\",\"sync_info\":{{\"current_height\":{d},\"highest_height\":{d}}}", .{ x.current_height, x.highest_height }),
            // the reference sends no heights in these stages; ours adds the header
            // and network heights (extra fields only) so a UI can keep showing them
            .txhashset_download => |x| try w.print(",\"sync_status\":\"txhashset_download\",\"sync_info\":{{\"downloaded_size\":{d},\"total_size\":{d},\"current_height\":{d},\"highest_height\":{d}}}", .{ x.downloaded_size, x.total_size, hh, network_h }),
            .txhashset_processing => {
                const p = &txhashset_mod.progress;
                switch (p.stage.load(.acquire)) {
                    txhashset_mod.Progress.KERNELS => try w.print(",\"sync_status\":\"txhashset_kernels_validation\",\"sync_info\":{{\"kernels\":{d},\"kernels_total\":{d},\"current_height\":{d},\"highest_height\":{d}}}", .{ p.done.load(.monotonic), p.total.load(.monotonic), hh, network_h }),
                    txhashset_mod.Progress.RANGEPROOFS => try w.print(",\"sync_status\":\"txhashset_rangeproofs_validation\",\"sync_info\":{{\"rproofs\":{d},\"rproofs_total\":{d},\"current_height\":{d},\"highest_height\":{d}}}", .{ p.done.load(.monotonic), p.total.load(.monotonic), hh, network_h }),
                    else => try w.print(",\"sync_status\":\"syncing\",\"sync_info\":{{\"current_height\":{d},\"highest_height\":{d}}}", .{ hh, network_h }),
                }
            },
            .body_sync => |x| try w.print(",\"sync_status\":\"body_sync\",\"sync_info\":{{\"current_height\":{d},\"highest_height\":{d}}}", .{ x.current_height, x.highest_height }),
            .no_sync => try w.writeAll(",\"sync_status\":\"no_sync\""),
            .compacting => try w.writeAll(",\"sync_status\":\"compacting\""),
            .shutdown => try w.writeAll(",\"sync_status\":\"shutdown\""),
        }
        try w.print(",\"supply\":{d},\"max_supply\":21000000,\"blocks_to_next_halving\":{d}}}", .{ consensus.fastTotalSupply(tip.height) / consensus.EPIC_BASE, consensus.blocksToNextHalving(tip.height) });
    }

    fn poolInfo(self: *Api, w: *Writer) ApiError!void {
        self.node.pool.lock();
        defer self.node.pool.unlock();
        const entries = self.node.pool.txpool.entries.items;
        try w.print("{{\"pool_size\":{d},\"txs\":[", .{self.node.pool.totalSize()});
        for (entries, 0..) |e, i| {
            if (i > 0) try w.writeAll(",");
            try json.transaction(w, e.tx);
        }
        try w.writeAll("]}");
    }

    /// Connected peers as the reference's `PeerInfoDisplay`.
    fn connectedPeers(self: *Api, w: *Writer) ApiError!void {
        const p = &self.node.peers;
        p.mutex.lockUncancelable(p.io);
        defer p.mutex.unlock(p.io);
        try w.writeAll("[");
        for (p.conns.items, 0..) |c, i| {
            if (i > 0) try w.writeAll(",");
            const lv = c.live();
            try w.print("{{\"capabilities\":{{\"bits\":{d}}},\"user_agent\":", .{c.peer.capabilities.bits});
            try std.json.Stringify.value(c.peer.userAgent(), .{}, w);
            try w.print(",\"version\":{d},\"addr\":", .{c.peer.version.v});
            if (c.remote) |a| try w.print("\"{f}\"", .{a}) else try w.writeAll("null");
            try w.print(",\"direction\":\"{s}\",\"total_difficulty\":", .{if (c.outbound) "Outbound" else "Inbound"});
            try json.difficulty(w, lv.difficulty);
            try w.print(",\"height\":{d},\"onion_addr\":null}}", .{lv.height});
        }
        try w.writeAll("]");
    }

    /// Known peers as the reference's `PeerData` (all of them, or just `want`).
    fn allPeers(self: *Api, w: *Writer, want: ?net.IpAddress) ApiError!void {
        const port: u16 = if (self.chain.cfg.chain == .floonet) 13414 else 3414;
        const rows = try self.node.store.rows(self.gpa, port);
        defer self.gpa.free(rows);
        try w.writeAll("[");
        var first = true;
        var found = false;
        for (rows) |r| {
            if (want) |a| if (!@import("peers.zig").Peers.sameHost(a, r.addr) or (r.state != .banned and !std.meta.eql(a, r.addr))) continue;
            found = true;
            if (!first) try w.writeAll(",");
            first = false;
            const flags: []const u8 = switch (r.state) {
                .healthy => "Healthy",
                .defunct => "Defunct",
                .banned => "Banned",
            };
            try w.print("{{\"addr\":\"{f}\",\"capabilities\":{{\"bits\":0}},\"user_agent\":\"\",\"flags\":\"{s}\",\"last_banned\":{d},\"ban_reason\":\"{s}\",\"last_connected\":{d},\"local_timestamp\":0}}", .{
                r.addr, flags, r.banned_at_s, if (r.state == .banned) "ManualBan" else "None", r.last_seen_s,
            });
        }
        if (want != null and !found) return error.NotFound;
        try w.writeAll("]");
    }

    fn pushTx(self: *Api, body: []const u8, query: Query) ApiError!void {
        if (body.len == 0) return error.BadRequest;
        var parsed = std.json.parseFromSlice(std.json.Value, self.gpa, body, .{}) catch return error.BadRequest;
        defer parsed.deinit();
        var v = parsed.value;
        // the wallet's JSON-RPC envelope: {"method":"push_transaction","params":[{"body":<tx>}|<tx>, fluff?]}
        if (v == .object) {
            if (v.object.get("params")) |params| if (params == .array and params.array.items.len > 0) {
                v = params.array.items[0];
                if (v == .object) if (v.object.get("body")) |b| if (b == .object and b.object.contains("offset")) {
                    v = b;
                };
            };
        }
        var tx: tx_mod.Transaction = undefined;
        if (v == .object and v.object.contains("tx_hex")) {
            const hexs = v.object.get("tx_hex").?;
            if (hexs != .string or hexs.string.len % 2 != 0) return error.BadRequest;
            const bytes = self.gpa.alloc(u8, hexs.string.len / 2) catch return error.OutOfMemory;
            defer self.gpa.free(bytes);
            _ = std.fmt.hexToBytes(bytes, hexs.string) catch return error.BadRequest;
            var r = ser.Reader.init(self.gpa, bytes, ser.ProtocolVersion.local());
            r.params = self.chain.cfg.chain.readParams();
            tx = tx_mod.Transaction.read(&r) catch return error.BadRequest;
        } else {
            tx = json.parseTransaction(self.gpa, v) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.BadRequest,
            };
        }
        defer tx.deinit(self.gpa);
        log("Pushing transaction {s} to pool (inputs: {d}, outputs: {d}, kernels: {d})", .{ tx.hash().toHex()[0..12], tx.body.inputs.len, tx.body.outputs.len, tx.body.kernels.len });
        self.node.addTx(null, tx, !query.has("fluff")) catch |e| {
            warn("Failed to update pool: {s}", .{@errorName(e)});
            return error.BadRequest;
        };
    }

    // --------------------------------------------------------- chain reads

    const Found = struct { pos: u64, height: u64, features: tx_mod.OutputFeatures };

    /// Looks an output up by commitment, trying both feature types (`get_output`).
    /// Caller holds the chain lock.
    fn findUnspent(self: *Api, commit: Commitment) ?Found {
        var batch = self.chain.db.batch();
        defer batch.deinit();
        for ([_]tx_mod.OutputFeatures{ .plain, .coinbase }) |f| {
            if (self.chain.ths.isUnspent(&self.chain.db, &batch, f, commit) catch null) |cp| return .{ .pos = cp.pos, .height = cp.height, .features = f };
        }
        return null;
    }

    fn parseCommit(s: []const u8) ApiError!Commitment {
        if (s.len != 66) return error.BadRequest;
        var c: Commitment = undefined;
        _ = std.fmt.hexToBytes(&c.bytes, s) catch return error.BadRequest;
        return c;
    }

    fn outputInfo(self: *Api, o: tx_mod.Output, include_proof: bool) json.OutputInfo {
        var batch = self.chain.db.batch();
        defer batch.deinit();
        const unspent = self.chain.ths.isUnspent(&self.chain.db, &batch, o.features, o.commit) catch null;
        const pos = (self.chain.db.getOutputPosHeight(&batch, o.commit) catch null) orelse chain_types.CommitPos{ .pos = 0, .height = 0 };
        return .{
            .spent = unspent == null,
            .block_height = if (unspent) |u| u.height else null,
            .mmr_index = pos.pos,
            .include_proof = include_proof,
        };
    }

    fn outputsByIds(self: *Api, w: *Writer, q: Query) ApiError!void {
        self.chain.lock();
        defer self.chain.unlock();
        try w.writeAll("[");
        var first = true;
        var it = std.mem.splitScalar(u8, q.raw, '&');
        while (it.next()) |kv| {
            if (!std.mem.startsWith(u8, kv, "id=")) continue;
            var ids = std.mem.splitScalar(u8, kv[3..], ',');
            while (ids.next()) |id| {
                const commit = parseCommit(id) catch continue;
                const f = self.findUnspent(commit) orelse continue;
                if (!first) try w.writeAll(",");
                first = false;
                try w.writeAll("{\"commit\":");
                try json.hex(w, &commit.bytes);
                try w.print(",\"height\":{d},\"mmr_index\":{d}}}", .{ f.height, f.pos });
            }
        }
        try w.writeAll("]");
    }

    fn headerAtHeight(self: *Api, height: u64) ?block.BlockHeader {
        const h = self.chain.header_mmr.hashAtHeight(height) orelse return null;
        return (self.chain.db.getBlockHeader(self.chain.db.store, h) catch null);
    }

    fn outputsByHeight(self: *Api, w: *Writer, q: Query) ApiError!void {
        const from = q.u64Or("start_height", 1);
        const end = q.u64Or("end_height", 1);
        if (end < from or end - from > 10_000) return error.BadRequest;
        const include_rp = q.has("include_rp");
        self.chain.lock();
        defer self.chain.unlock();
        try w.writeAll("[");
        var first = true;
        var h = end + 1;
        while (h > from) {
            h -= 1;
            const header = self.headerAtHeight(h) orelse continue;
            var b = (self.chain.db.getBlock(self.chain.db.store, header.hash()) catch null) orelse continue;
            defer b.deinit(self.gpa);
            if (b.body.outputs.len == 0) continue;
            if (!first) try w.writeAll(",");
            first = false;
            try w.writeAll("{\"header\":");
            try json.headerInfo(w, header);
            try w.writeAll(",\"outputs\":[");
            for (b.body.outputs, 0..) |o, i| {
                if (i > 0) try w.writeAll(",");
                try json.outputPrintable(w, o, self.outputInfo(o, include_rp));
            }
            try w.writeAll("]}");
        }
        try w.writeAll("]");
    }

    fn kernel(self: *Api, w: *Writer, excess_hex: []const u8, q: Query) ApiError!void {
        const excess = try parseCommit(excess_hex);
        self.chain.lock();
        defer self.chain.unlock();
        const head = self.chain.head() catch return error.Internal;
        var min_index: ?u64 = null;
        var max_index: ?u64 = null;
        const min_h = q.u64Or("min_height", 0);
        const max_h = q.u64Or("max_height", head.height);
        if (min_h > 0) min_index = (self.headerAtHeight(min_h - 1) orelse return error.NotFound).kernel_mmr_size + 1;
        if (max_h < head.height) max_index = (self.headerAtHeight(max_h) orelse return error.NotFound).kernel_mmr_size;
        const found = self.chain.ths.findKernel(excess, min_index, max_index) orelse return error.NotFound;
        // the height: binary search the headers for the one whose kernel MMR first covers `index`
        var lo: u64 = min_h;
        var hi: u64 = head.height;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            const hd = self.headerAtHeight(mid) orelse return error.Internal;
            if (hd.kernel_mmr_size >= found.index) hi = mid else lo = mid + 1;
        }
        try w.writeAll("{\"tx_kernel\":");
        try kernelSerde(w, found.kernel);
        try w.print(",\"height\":{d},\"mmr_index\":{d}}}", .{ lo, found.index });
    }

    /// A kernel in its serde form (`{"features":{"Plain":{"fee":1}},"excess":..,"excess_sig":..}`).
    fn kernelSerde(w: *Writer, k: tx_mod.TxKernel) Writer.Error!void {
        try w.writeAll("{\"features\":");
        switch (k.features) {
            .plain => |p| try w.print("{{\"Plain\":{{\"fee\":{d}}}}}", .{p.fee}),
            .coinbase => try w.writeAll("\"Coinbase\""),
            .height_locked => |h| try w.print("{{\"HeightLocked\":{{\"fee\":{d},\"lock_height\":{d}}}}}", .{ h.fee, h.lock_height }),
        }
        try w.writeAll(",\"excess\":");
        try json.hex(w, &k.excess.bytes);
        try w.writeAll(",\"excess_sig\":");
        try json.hex(w, &k.excess_sig.bytes);
        try w.writeAll("}");
    }

    fn txhashset(self: *Api, w: *Writer, what: []const u8, q: Query) ApiError!void {
        self.chain.lock();
        defer self.chain.unlock();
        const head = self.chain.head() catch return error.Internal;
        if (std.mem.eql(u8, what, "roots")) {
            const hd = (self.chain.db.getBlockHeader(self.chain.db.store, head.last_block_h) catch null) orelse return error.Internal;
            try w.writeAll("{\"output_root_hash\":");
            try json.writeHash(w, hd.output_root);
            try w.writeAll(",\"range_proof_root_hash\":");
            try json.writeHash(w, hd.range_proof_root);
            try w.writeAll(",\"kernel_root_hash\":");
            try json.writeHash(w, hd.kernel_root);
            try w.writeAll("}");
        } else if (std.mem.eql(u8, what, "outputs")) {
            const from = q.u64Or("start_index", 1);
            const end_raw = q.u64Or("end_index", 0);
            const max = @min(q.u64Or("max", 100), 10_000);
            const listing = self.chain.ths.outputsFromPmmrIndex(self.gpa, from, max, if (end_raw == 0) null else end_raw) catch return error.Internal;
            defer self.gpa.free(listing.outputs);
            try w.print("{{\"highest_index\":{d},\"last_retrieved_index\":{d},\"outputs\":[", .{ if (end_raw == 0) self.chain.ths.sizes.output else end_raw, listing.last_index });
            for (listing.outputs, 0..) |o, i| {
                if (i > 0) try w.writeAll(",");
                try json.outputPrintable(w, o, self.outputInfo(o, true));
            }
            try w.writeAll("]}");
        } else if (std.mem.eql(u8, what, "heightstopmmr")) {
            const start_h = q.u64Or("start_height", 1);
            const end_raw = q.u64Or("end_height", 0);
            const end_h = if (end_raw == 0) head.height else end_raw;
            const prev = self.headerAtHeight(start_h -| 1) orelse return error.NotFound;
            const endh = self.headerAtHeight(end_h) orelse return error.NotFound;
            try w.print("{{\"highest_index\":{d},\"last_retrieved_index\":{d},\"outputs\":[]}}", .{ endh.output_mmr_size, prev.output_mmr_size + 1 });
        } else return error.NotFound;
    }

    /// `/v1/blocks/<height|hash|commit>` and `/v1/headers/<...>`.
    fn blockById(self: *Api, w: *Writer, id: []const u8, q: Query, header_only: bool) ApiError!void {
        self.chain.lock();
        defer self.chain.unlock();
        var header: block.BlockHeader = undefined;
        if (std.fmt.parseInt(u64, id, 10)) |height| {
            header = self.headerAtHeight(height) orelse return error.NotFound;
        } else |_| if (id.len == 64) {
            var h: Hash = undefined;
            _ = std.fmt.hexToBytes(&h.bytes, id) catch return error.BadRequest;
            header = (self.chain.db.getBlockHeader(self.chain.db.store, h) catch null) orelse return error.NotFound;
        } else if (id.len == 66) {
            const f = self.findUnspent(try parseCommit(id)) orelse return error.NotFound;
            header = self.headerAtHeight(f.height) orelse return error.NotFound;
        } else return error.BadRequest;

        if (header_only) return json.headerPrintable(w, header);

        var b = (self.chain.db.getBlock(self.chain.db.store, header.hash()) catch null) orelse return error.NotFound;
        defer b.deinit(self.gpa);
        const include_proof = !q.has("compact") and !q.has("no_proof") and q.has("include_proof");
        if (q.has("compact")) {
            // compact form: the coinbase parts in full, the rest as short ids
            var cb = try @import("compact_block.zig").CompactBlock.fromBlock(self.gpa, b, 0);
            defer cb.deinit(self.gpa);
            try w.writeAll("{\"header\":");
            try json.headerPrintable(w, header);
            try w.writeAll(",\"out_full\":[");
            for (cb.out_full, 0..) |o, i| {
                if (i > 0) try w.writeAll(",");
                try json.outputPrintable(w, o, self.outputInfo(o, false));
            }
            try w.writeAll("],\"kern_full\":[");
            for (cb.kern_full, 0..) |k, i| {
                if (i > 0) try w.writeAll(",");
                try json.kernelPrintable(w, k);
            }
            try w.writeAll("],\"kern_ids\":[");
            for (cb.kern_ids, 0..) |sid, i| {
                if (i > 0) try w.writeAll(",");
                try json.hex(w, &sid.bytes);
            }
            try w.writeAll("]}");
            return;
        }
        try w.writeAll("{\"header\":");
        try json.headerPrintable(w, header);
        try w.writeAll(",\"inputs\":[");
        for (b.body.inputs, 0..) |i, n| {
            if (n > 0) try w.writeAll(",");
            try json.hex(w, &i.commit.bytes);
        }
        try w.writeAll("],\"outputs\":[");
        for (b.body.outputs, 0..) |o, n| {
            if (n > 0) try w.writeAll(",");
            try json.outputPrintable(w, o, self.outputInfo(o, include_proof));
        }
        try w.writeAll("],\"kernels\":[");
        for (b.body.kernels, 0..) |k, n| {
            if (n > 0) try w.writeAll(",");
            try json.kernelPrintable(w, k);
        }
        try w.writeAll("]}");
    }
};

/// Reads a secret file's first line, or null if there is no such file (or it's empty).
/// Relative names are inside `dir`.
pub fn loadSecret(gpa: std.mem.Allocator, io: Io, dir: Io.Dir, name: []const u8) !?[]u8 {
    const f = dir.openFile(io, name, .{ .mode = .read_only }) catch |e| switch (e) {
        error.FileNotFound => return null,
        else => return e,
    };
    defer f.close(io);
    var buf: [512]u8 = undefined;
    const n = try f.readPositionalAll(io, &buf, 0);
    var lines = std.mem.splitAny(u8, buf[0..n], "\r\n");
    const line = std.mem.trim(u8, lines.first(), " \t");
    if (line.len == 0) return null;
    return try gpa.dupe(u8, line);
}

/// Reads the API secret from `name` (relative names are inside `dir`),
/// creating a random one if it doesn't exist.
pub fn loadOrCreateSecret(gpa: std.mem.Allocator, io: Io, dir: Io.Dir, name: []const u8) ![]u8 {
    if (dir.openFile(io, name, .{ .mode = .read_only })) |f| {
        defer f.close(io);
        const len: usize = @intCast(try f.length(io));
        const buf = try gpa.alloc(u8, len);
        defer gpa.free(buf);
        _ = try f.readPositionalAll(io, buf, 0);
        return gpa.dupe(u8, std.mem.trim(u8, buf, " \r\n\t"));
    } else |_| {}
    var raw: [10]u8 = undefined;
    io.random(&raw);
    const secret = try std.fmt.allocPrint(gpa, "{x}", .{&raw});
    errdefer gpa.free(secret);
    try dir.writeFile(io, .{ .sub_path = name, .data = secret });
    return secret;
}
