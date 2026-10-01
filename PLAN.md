# epic-zig: Zig rewrite of the Epic Cash node

Reference implementation: `../epic` (Rust, v4.0.4, Grin-derived MimbleWimble).
Goal: wire- and consensus-compatible node, faster sync, RocksDB storage, cross-platform.
Storage is a fresh RocksDB layout (no LMDB import). Native C deps are vendored in `vendor/` and built by build.zig.

## Milestone 1: headless syncing node
Each stage is verified against reference data (genesis hashes, real mainnet blocks) before the next starts.

1. [x] Toolchain + vendored secp256k1-zkp builds via build.zig (smoke test passes)
2. [x] Vendored RandomX, RocksDB, CRoaring compile via build.zig; all smoke tests pass (RandomX matches Rust vector). ProgPoW needs no C++: the node uses the pure-Rust `pp_light` (vendor/progpow-rust/pp_light), so it is ported to Zig in stage 6.
3. [x] core/ser: binary serialization (byteorder-exact), blake2b hashing, Hash/Hashed
4. [x] core/consensus + global: constants, emission eras, foundation levy, difficulty adjustment (both eras), feijoada policies, chain types (foundation.json loading deferred to stage 5)
5. [x] core/block, transaction, kernel, output, Pedersen/Bulletproof/aggsig verification (crypto.zig), header/block/genesis, foundation.json. Both genesis hashes match the Rust node. Deferred to where they are first needed: merkle proofs + PMMR (stage 7), short ids + compact blocks (stage 9), block_sums (stage 8).
6. [x] core/pow: siphash + Cuckoo verifier (matches the real Cuckatoo 29/31 vectors), RandomX manager (light cache + VM pool, C lib), ProgPoW port (matches all reference vectors), header PoW verification, difficulty-from-proof. NOTE: the reference never verifies genesis PoW, so the header->pre_pow->Cuckoo wiring is first proven on real mainnet headers (stage 8/9). Cuckaroo needs no separate verifier: the reference verifies all cuckoo proofs with the Cuckatoo verifier.
7. [x] store: RocksDB kv layer (kv.zig: read-your-writes + nested atomic batches over an in-memory overlay), PMMR math/PMMR/MerkleProof (pmmr.zig), append-only files (aof.zig), leaf set, prune list, file-backed PMMR backend with compaction (pmmr_backend.zig). File formats match the reference so txhashset archives interoperate; compaction is differentially tested against an in-memory PMMR. Deviations: prune-list pruned cache built via subtree ranges (equivalent, tested against the original algorithm); leaf-set rewind keeps the highest bit exactly like the reference (its remove_range is exclusive). Not yet done: mmap reads, BitmapAccumulator (stage 8).
8. [~] chain (in progress; see 'Real-data verification' below): txhashset, header/block pipeline, fork choice, fast sync (txhashset zip), compaction
9. [ ] p2p: handshake, messages, peer store, sync state machine (no Tor at first)
10. [ ] servers: config (epic-server.toml), CLI, run loop; sync mainnet from genesis
Later milestones: pool, HTTP API (wallet-compatible), stratum, Tor, TUI.

## Real-data verification (live mainnet node, via P2P; `zig build fetch`)
Done ahead of stage 9 by building a minimal P2P client (p2p_msg.zig, p2p_client.zig, tools/fetch.zig). Fixtures are saved in testdata/ and replayed by tests.
- handshake + header/block exchange with a real node (agent MW/Epic 4.0.3, protocol v2)
- header hash: every real header links to our computed hash of its predecessor; the node serves blocks requested by our computed hashes
- PoW verified on ~17.6k real headers, 0 failures: cuckaroo 86, cuckatoo 527, randomx 8997, progpow 7985
- difficulty adjustment (era-1) reproduces 12,488 real headers exactly (0 mismatches)
- feijoada scheduling, policy, bottles verified on 17,560 real headers
- 5 real tip blocks fully validated (bulletproofs, kernel sigs, coinbase, kernel sums with offset)
Also verified on a REAL txhashset archive (994 MB, height 3,730,320, `zig build txhashset`): all three MMR roots match the real header; whole-set kernel sums verify (9.35M outputs / 8.1M kernels); 2,904 real blocks replayed on top with full validation + running sums + per-block roots/sizes (0 mismatches, incl. 2 foundation-levy blocks). Bugs caught by real data: AOF rewind inside unflushed buffer; kernel size-file rebuild version + O(n*1MB) window; leaf snapshot file name uses the 12-char Display of the hash.
Done in stage 8: chain_types, chain_db (RocksDB), txhashset (apply/rewind/UTXO checks/validate, lazy bitmap accumulator), header MMR.
Remaining for stage 8: header/block processing pipeline (validate_header, orphans, fork choice, head updates, rewind_and_apply_fork), chain facade + init from genesis/archive, txhashset zip *writing* (serving archives), compaction wiring. Not yet real-data checked: pre-era-1 difficulty (heights < 501160: need headers from that range), foundation-height block, MMR roots vs real headers.

## Known follow-ups
- Node prunes old block bodies: it answers GetBlock only for recent blocks; fast-sync header offsets (offset*512) let a client hop to the tip.
- Zig 0.16 stdlib lacks connect timeouts on POSIX (panics on TODO); handle timeouts at a higher level.
- Epic has a KernelDataRequest/Response message (kernel data outside the txhashset zip): needed in stage 9.
- The dev tool leaks per-hop header windows (throwaway); tidy if it becomes a real tool.
- PMMR reads use pread; add mmap (std.Io.File.MemoryMap) once profiling shows it matters.
- The AOF fsyncs on every flush like the reference; the store commit path is where sync policy should be tuned.
- kv.Store defaults to WAL without fsync; decide the durability policy alongside PMMR flush ordering in stage 8.
- secp256k1-zkp is pinned to b247e1e (the EpicCash fork's submodule pin).
- C libs are built with UBSan off (`-fno-sanitize=undefined`) to match the Rust build; the C code has benign signed shifts.
- Pinned so far: RandomX f324cf2 (randomx-rust v0.2.1 submodule), CRoaring v4.3.1 (croaring-sys 4.3.1), RocksDB v10.10.1 (latest stable; the Rust node used LMDB, so no pin needed).
- CRoaring is built with AVX-512 disabled (Zig's clang lacks evex512 support for it); revisit for perf.
- RocksDB cold build is ~7 min; cross-targets (windows, macos, aarch64) not yet build-tested.
- RocksDB is built without compression libs; add lz4/zstd if storage size matters.
- No Rust toolchain on this machine: test vectors come from the live chain / API, or install rustup to dump them.

## Full sync on real data (verified)
Fresh data dir -> headers to tip (PoW verified from 2.2M) -> fast-sync archive (947 MiB) -> kernel history,
roots, sums, all range proofs, all kernel signatures -> output index -> body sync (~28 blocks/s) -> follow mode.
Bug found and fixed: the leaf-set rewind quirk leaves one stale bit past the MMR end; range-proof verification skips it.
Untested: follow mode over many new blocks, reconnect after network loss, orphans, version-7 headers (>= 9M).

## Serving (stage 9, first part) — verified
src/server.zig + p2p_client `Conn.accept` + zipwrite.zig: inbound handshake, Ping/Pong, GetHeaders(+FastSync), GetBlock,
GetPeerAddrs (empty list), TxHashSetRequest (stored zip of the txhashset at the archive header, `txhashset_zip_<hash12>.zip`).
`Chain.lock()` serialises the syncer and the server threads. Run with `--listen IP:PORT` (off by default).
Verified by pointing tools/txhashset at our own server: real archive (height 3,730,320, 994 MB) -> roots match the real header,
range proofs OK, kernel sums OK, 3,182 blocks fetched from us and replayed. Live node kept following throughout.
Not done: announcing new blocks (needs compact blocks + tx pool), real peer list, KernelDataRequest, inbound timeouts/bans, Tor.

## Transaction pool + relay (stage 9, second part)
src/pool.zig (Pool, TransactionPool; port of pool/src), transaction.zig (aggregate, deaggregate, cut-through), shortid.zig,
compact_block.zig, peers.zig (live connections, broadcasts), node.zig (pool + peers + gossip handlers).
Verified: unit tests (aggregation, pool add/dup/bucket/reconcile, fee + chain rejection, stem fallback);
short ids match the reference vectors; real compact block from the live node parses, our short ids for a real block
(real nonce) equal the node's, hydrating from the block's own txs reproduces the block (`zig build probe`);
a real mainnet tx gossiped by the live node was validated (range proofs, sigs, kernel sums vs chain state) and accepted into our pool.
Known gaps: no Dandelion (stem txs are fluffed at once; no embargo monitor); outbound sync connection only reads gossip
while the syncer is waiting on it (inbound peers are push-driven); no peer bans; txpool re-validates the whole aggregate
(incl. range proofs) on every add, like the reference; HTTP API (push tx / pool stats) not built.

## HTTP API (stage 10, first part) — `--api IP:PORT`
src/api.zig (std.http server, thread per connection, Basic auth user `epic` + secret in `<data-dir>/.api_secret`, generated on first run,
`--no-api-auth` to disable) and src/api_json.zig (hand-written serde-compatible JSON for tips, headers, blocks, outputs, kernels, transactions).
v1: /version /status /chain /pool /pool/push_tx /peers/{all,connected} /chain/outputs/{byids,byheight} /chain/kernels/<excess>
/txhashset/{roots,outputs,heightstopmmr} /blocks/<height|hash|commit> (+?compact) /headers/<...>.
v2 /v2/foreign JSON-RPC (single + batch): get_version get_tip get_header get_block get_kernel get_outputs get_unspent_outputs
get_pmmr_indices get_pool_size get_stempool_size get_unconfirmed_transactions push_transaction.
Verified against our own node with curl (real mainnet data; output/kernel/block lookups agree with each other and the P2P data).
Not done: merkle proofs in output listings, /txhashset/last*, /chain/{validate,compact}, /v2/owner, /v1/mining/*, get_blocks/get_last_n_kernels,
a push_tx of a real valid tx (needs a wallet; the parse and pool-rejection paths are tested). No live-node API comparison: its secret is off limits.

## Peer hardening (stage 9, third part)
peer_store.zig (known peers + per-host bans, persisted in `<data>/peers.txt`, routable-address filter), misbehavior.zig (which errors ban a peer,
following the reference's `is_bad_data`), peers.zig (liveness sweep: ping after 30 s quiet, drop after 120 s, 15 s handshake deadline),
server.zig (one message loop for inbound and outbound peers; optional outbound dialer), sync.zig (fail over to another known peer).
Flags: `--max-outbound N` (default 0: dial nothing but `--peer`), `--allow-local-peers`. A dead `--peer` at startup is retried, not fatal.
Verified on a scratch node over loopback (`zig build peertest`): silent connection dropped after the handshake deadline, garbage -> BadMagic -> host banned
(persisted, refused afterwards), a silent peer dropped after 126 s while a peer answering pings stayed connected (170 s, 6 pings),
and `--max-outbound 1` dialed a seeded peer (our own listener) and served it. Discovery against real peers was deliberately not run (it would dial internet hosts).
Not done: Dandelion (stem relay + embargo monitor), multi-peer sync (we sync from one peer at a time, with failover), rate limiting, inbound-peer addresses are not learned.

## Sync speed (verified end to end against the live node, fresh data dir)
Before: headers ~2 h (PoW on every header past 2.2M at ~300/s, ~4.5k/s before) + state sync ~15 min (sequential validation) + body sync 2 min (27 blocks/s).
Now: **~8-9 minutes from an empty directory to the tip** (472 s and 509 s in two runs; the header phase varies 270-410 s with machine load):
- headers: 3.7M headers in ~4.5-6 min. Pipelined (next batch on the wire, PoW of the following batch on the other cores, chain checks of the current one);
  PoW skipped up to 3,700,000 via this node's own assume-valid checkpoints (`checkpoints.assumed`, 8 hashes taken from a chain this node verified in full
  and confirmed against the reference node; `--no-assume-valid` = reference checkpoints only (2.2M), `--verify-all-pow` = everything). The last ~33k headers get full PoW.
  RocksDB runs in bulk-load mode (no compaction) during the header sync and is compacted once afterwards (~12-14 s).
- state sync: download 200+ MiB/s; MMR hashes, kernel sums + signatures, range proofs, kernel history and the output position index all run on every core;
  kernel history runs alongside the rest. ~125 s of validation (was ~15 min).
- body sync: 300+ blocks/s (was 27): stateless block checks (proofs/signatures) run in parallel over a 64-block window; the txhashset files are not fsynced per block during a
  long replay (marker file `catchup.lock`; if the node dies before it's cleared, the next start validates the whole txhashset first — tested).
Per-header PoW cost (one thread, this CPU): RandomX light 14.7 ms, ProgPoW light 7.9 ms, cuckoo ~0.02 ms (`zig build bench`).
Ideas left: interleave ProgPoW dag-item computation (memory-latency bound) to cut its 7.9 ms, batch-size tuning for kernel signature verification,
multiple connections for header download, overlapping the last headers with the archive download.

## Peer discovery and Dandelion (stage 9, fourth part)
- Discovery (`seeds.zig`, `discovery.zig`, `server.zig` discovery loop, `peer_store.zig`): `--peer` is now optional. Without it the node resolves the network's DNS seed
  (`node.epiccash.com:3414`; static fallback from the reference's example config), tries several candidates in parallel and syncs from the one with the most chain work,
  keeps up to 8 outbound peers (`--max-outbound`), asks connected peers for their address lists every 5 min, retries defunct peers after 15 min, never redials within 30 s,
  and goes back to the seeds when it has nobody. Flags: `--peer` alone keeps the old behaviour (no discovery); `--seeds`, `--seed HOST:PORT`, `--no-discovery`, `--no-sync`.
  Verified on the real network: the DNS seed resolved; a dial reached a public 4.0.3 peer, which returned 156 addresses (all learned). Most public peers closed the connection
  during the handshake: from this machine they already know our IP (the live node is connected to them), and the reference refuses a second connection from a known address.
- Found while testing: `Node.handleGossip` had no cases for peer-address lists, announced headers, compact blocks or full blocks (a botched edit), so the push path for new
  blocks and all peer-list learning were silently inactive. Fixed; node1 then accepted live blocks straight from the peer's announcements.
- Dandelion (`dandelion.zig`, `node.zig`): epochs of 10 min, 90% stem; a stem epoch (or our own API-pushed txs) sends the tx to one outbound relay peer as `StemTransaction`;
  a fluff epoch holds stem txs, aggregates and fluffs them after 30 s; every stem tx has a 180 s (+0-30 s) embargo after which we fluff it ourselves. No relay peer or a failed send
  falls back to fluffing. Unit-tested (epoch rules, aggregation fluff, embargo fluff, wire round trip); NOT tested on the real network (needs a valid wallet-made tx).

## Compaction
`Chain.compact` (port of `Chain::compact`): once the chain is 60 blocks past horizon (one week, 10,080 blocks) + last tail, prunes the spent
outputs/range proofs below the horizon from the txhashset files (keeping everything spent after it, so a rewind to the horizon still works),
deletes blocks (and their sums and spent indexes) below the horizon including fork blocks, moves the body tail, and drops stale served archives.
Triggered like the reference: a 1-in-1440 chance per accepted block once synced (on its own thread), or `POST /v1/chain/compact`.
Verified: unit test (roots unchanged, whole spent subtrees leave the files, rewind to the horizon, reopen); on a copy of node1 with a 1000- then
500-block horizon: 24 MiB pruned, 2,894 old blocks removed, full txhashset validation passes, rewind to the horizon matches its header, reopen OK.
Also fixed: a POST without Content-Length hung the API (std.http waited for a body).

## Config file and clean shutdown
- `src/config.zig`: `<data-dir>/epic-zig.toml` (written with commented defaults on first run; `--config PATH` for another file); a small TOML subset
  (sections, strings, integers, booleans, string arrays, comments). Covers chain, p2p (peer, listen, max_outbound, seeds, extra_seeds, allow_local_peers),
  api (listen, auth), chain (verify_all_pow, assume_valid, archive_mode), pool limits/fees and Dandelion timings. Flags override the file.
- `src/shutdown.zig` + main's watcher: Ctrl-C/SIGTERM (console handler on Windows) -> wait for the chain lock (the current block or header batch
  finishes), end catch-up mode (fsync), sync the txhashset, save peers, fsync the RocksDB WAL, exit 0. A state sync in progress is abandoned (sandboxed).
  A second Ctrl-C exits at once. Verified: header sync interrupted and resumed; follow mode shut down cleanly; settings taken from the file (peer, API).
- `--archive` / `archive_mode`: compaction keeps every block.

## Cross-platform builds (cross-compiled from Linux x86_64; not run on the targets yet)
`zig build -Dtarget=<t> -Doptimize=ReleaseFast` now builds for x86_64-linux (native), aarch64-linux-gnu, x86_64-windows-gnu, aarch64-macos and x86_64-macos.
Fixes: CRoaring's header is imported with DISABLENEON (Zig's C translator can't parse arm_neon.h; the compiled library still uses NEON);
RandomX's argon2_ssse3/avx2 files are compiled as stubs on non-x86 (the dispatcher references them); RocksDB on Windows links rpcrt4 and shlwapi.
Not verified: running them (no wine/qemu/mac here). Things to watch on first run: RandomX JIT on Apple Silicon (MAP_JIT), Windows console Ctrl-C handler.

## Header sync from remote peers
Measured from scratch against public peers (this machine shares its public IP with the live node, and reference nodes treat all
connections from one IP as one peer: `PeerAddr` equality ignores the port except on loopback, so most public peers refuse us here).
One request in flight gave 250-460 headers/s (round-trip bound); keeping 8 fast-sync windows in flight (`Options.header_windows`)
gave 1,100-1,850/s early and ~9,500/s later from the same peer. DNS seed + the static list are now tried together.
- Handshake now advertises our listening address (`p2p_client.advertised`, set from `--listen`), like the reference's `self_addr`, so Rust peers
  record ip:port and can dial us back and pass us on; and for inbound peers we learn ip + the port from their Hand (the reference's `resolve_peer_addr`).
  Verified with two local nodes: the listener learned the dialer's advertised port.
- Defaults now match the Rust node: P2P listens on 0.0.0.0:3414 and the API on 127.0.0.1:3413 (floonet 13414/13413); `--no-listen`, `--no-api`.
  A port in use stops the node with a clear message. Listeners no longer set SO_REUSEPORT (which could have shared a port with a Rust node).
- Seeds: the DNS seed returns one node, which refused this IP, and the reference's four example seeds were dead (2 refused, 2 timed out),
  so a fresh node with no `--peer` could not start. The fallback list now leads with 7 peers that completed a handshake in a scan of
  ~200 learned addresses (`zig build peerscan -- <file>`); a fresh node then found a peer in seconds and synced headers at ~10k/s.
- Header PoW settings now match the reference: `skip_pow_validation` (default true: skip PoW inside the checkpointed range, to 2.2M),
  `disable_checkpoints` (default false; with skip: no header PoW while syncing), checkpoint hashes enforced as in `check_header_against_checkpoints`.
  This node's own checkpoints to 3.7M are opt-in: `extended_checkpoints = true` / `--extended-checkpoints`. Old config keys
  (`assume_valid`, `verify_all_pow`) are read compatibly; `assume_valid` is ignored so old files get the reference default.

## Rust-style log output
- `logging.zig`: `YYYY-MM-DD HH:MM:SS.mmm LEVEL message`, level coloured like log4rs (ERROR red, WARN yellow, INFO green, DEBUG blue) on a terminal, plain in files. `--debug` shows DEBUG lines.
- Messages reworded to the reference's phrasing per stage (startup banner, "Starting HTTP Node APIs server", "Starting dandelion monitor", "Epic node server started.", "DandelionEpoch: next_epoch", "Monitor peers on …" every 30 s, "Header Sync"/"State Sync"/"Block Sync" progress, txhashset validate/replace, "Pushing transaction … to pool", the SIGINT/"Shutting down..."/"Shutdown complete." sequence). Noisy per-peer dial failures, rejected txs and timings are DEBUG.

## /v2/owner JSON-RPC and Rust-style API auth
- `/v2/owner`: get_status, validate_chain, compact_chain, get_peers, get_connected_peers, ban_peer, unban_peer, get_onion_addresses (empty) — same JSON as `api/src/owner_rpc.rs`.
- `get_status`/`/v1/status` report the real sync state (`Node.SyncStatus`: awaiting_peers, header_sync, txhashset_download, syncing, body_sync, no_sync) with the reference's `sync_info`.
- Connected peers carry live height/difficulty from pings/pongs (`Conn.noteLive`); pings are answered with our real tip (`p2p_client.local_status`).
- Auth like the reference: `/v1` + `/v2/owner` use `api_secret_path` (default `.api_secret`); `/v2/foreign` is open unless `foreign_api_secret_path` exists. Relative paths are in the data dir.
- Fixed: `Chain.open` left defaulted fields (mutex, catchup flag, …) uninitialised; body sync no longer exits on a block a peer's announcement already delivered; a following node logs and retries unexpected sync errors.

## Default PoW-skip height raised to 3,500,000
- `checkpoints.ours` (2.4M…3.5M) are always enforced and PoW is skipped up to 3,500,000 by default; `extended_checkpoints` adds 3.6M/3.7M. The Rust node's table (to 2.2M) is unchanged and still enforced.
- 3,500,000 = 39b10039…7c34, confirmed by 103.87.68.10, 195.162.57.26, 188.36.153.167 and by node1's fully PoW-verified header chain (2026-10-01).
- `get_status` reports the reference's `txhashset_kernels_validation` {kernels, kernels_total} and `txhashset_rangeproofs_validation` {rproofs, rproofs_total} from `txhashset.progress`; in the download/validation stages `sync_info` also carries `current_height`/`highest_height` (extra fields) so UIs keep showing heights.
- All of the reference's API sync statuses are now reported: also `compacting` (the chain is compacted when a sync finishes, as the reference's sync loop does on its way to NoSync) and `shutdown`. Only difference: we start at `awaiting_peers` where the reference briefly reports `syncing` (Initial).

## Release builds
- `zig build --release` = ReleaseSafe (Zig runtime safety checks on; the vendored C/C++ libs are always built ReleaseFast). Release builds are stripped (`-Dstrip=false` keeps debug info): 151 MB -> 16 MB.
- Portable Linux build: `zig build --release -Dtarget=x86_64-linux-gnu.2.28 --prefix local/xbuild/x86_64-linux-glibc2.28` needs glibc >= 2.28 only (Ubuntu 20.04+, Debian 10+, RHEL 8+).
