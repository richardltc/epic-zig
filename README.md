# epic-zig

An Epic Cash full node written in Zig. It is a rewrite of the reference Rust node
([EpicCash/epic](https://github.com/EpicCash/epic), version 4.0.4) and aims to be wire- and
consensus-compatible with it: it talks to Rust nodes over the same P2P protocol, validates the chain by the
same rules, and serves the same APIs to wallets. Chain data is stored in RocksDB.

## Status

Early and under active development. It syncs mainnet from scratch, follows the chain, relays blocks and
transactions, and serves wallets on the same machine. It has been run on Linux x86_64 only; the macOS,
Windows and Linux ARM64 builds compile but have not yet been run on those systems.

Not implemented yet:
- mining (the stratum server and the block-template API calls)
- Tor
- merkle proofs in output listings, and the `get_blocks` / `get_last_n_kernels` foreign API calls

Sending from a wallet through this node has not yet been tested with real funds.

## What it does

- **Sync:** header sync (several requests in flight, proof-of-work checked in parallel), then a txhashset
  (chain state) download that is fully validated before use, then the most recent blocks.
- **Validation:** headers, proof-of-work (Cuckaroo, Cuckatoo, RandomX, ProgPow), difficulty, blocks,
  kernel signatures, range proofs, kernel sums and kernel history, spread over all CPU cores where possible.
- **Network:** peer discovery from DNS seeds and peer lists, inbound connections, ban handling, compact
  blocks, and Dandelion++ for transaction relay.
- **Transaction pool** with the reference node's fee and size rules.
- **APIs** on `127.0.0.1:3413`, in the reference node's JSON formats:
  - `/v1/...` REST endpoints (status, chain, blocks, headers, outputs, kernels, txhashset, pool, peers)
  - `/v2/owner` JSON-RPC: `get_status`, `get_peers`, `get_connected_peers`, `ban_peer`, `unban_peer`,
    `validate_chain`, `compact_chain`, `get_onion_addresses`
  - `/v2/foreign` JSON-RPC: `get_version`, `get_tip`, `get_header`, `get_block`, `get_kernel`, `get_outputs`,
    `get_unspent_outputs`, `get_pmmr_indices`, `get_pool_size`, `get_stempool_size`,
    `get_unconfirmed_transactions`, `push_transaction`
- **Compaction** of old spent data, as the reference node does (`--archive` keeps every block).

## Differences from the Rust node

- Header proof-of-work is skipped up to height 3,500,000 by default, protected by checkpoint hashes
  (the Rust node skips up to 2,200,000). `extended_checkpoints = true` skips up to 3,700,000;
  `verify_all_pow = true` checks every header.
- In the txhashset download and validation stages, `get_status` also reports `current_height` and
  `highest_height` in `sync_info`, as extra fields.
- Its user agent is `MW/Epic-Zig <version>`; `get_version` reports `node_version` 4.0.4, the API version
  it implements, because wallets check that number.

## Building

Requires [Zig 0.16](https://ziglang.org/download/). All C/C++ dependencies (secp256k1-zkp, RandomX, RocksDB,
CRoaring) are vendored in `vendor/` and built by `build.zig`; nothing else needs to be installed.

```
zig build test --summary all     # run the tests
zig build --release              # ReleaseSafe build in zig-out/bin/epic-zig
```

Cross-compiling works from any host, for example:

```
zig build --release -Dtarget=x86_64-linux-gnu.2.28   # Linux, glibc 2.28 or newer
zig build --release -Dtarget=aarch64-macos           # macOS, Apple Silicon
zig build --release -Dtarget=x86_64-windows-gnu      # Windows
```

`scripts/release.sh` builds and packages all supported targets and publishes a GitHub release
(`--build-only` just builds into `dist/`).

## Running

```
epic-zig --data-dir <folder>
```

A data folder is required. On first run the node writes its settings to `<folder>/epic-zig.toml`, with the
same defaults as the Rust node: P2P on `0.0.0.0:3414`, the API on `127.0.0.1:3413`, and Basic auth on the API
(user `epic`, password in `<folder>/.api_secret`; `api_secret_path` can point elsewhere). Settings in the
file can be overridden on the command line; `epic-zig --help` lists the options.

Ctrl-C (or SIGTERM) shuts the node down cleanly.

The node also writes `<folder>/epic-zig.log` (including DEBUG lines, which the console hides). It is
rotated at 16 MB into `epic-zig.log.0.gz`, `.1.gz`, ... with 32 kept; crashes are recorded in it too.
When reporting a problem, please include this file. The `[logging]` settings use the Rust node's names
(`log_to_file`, `file_log_level`, `log_max_size`, ...).

## Updates

Release builds check this repository's GitHub releases at startup. If a newer release exists, the node
downloads the package for its platform, checks it against the release's `SHA256SUMS`, replaces its own
binary and restarts with the same options. If anything fails (no network, no write access to the binary's
folder, a checksum mismatch) it carries on with the current version. Pre-releases are not installed.
Turn this off with `auto_update = false` in the `[update]` section of `epic-zig.toml`, or `--no-update`.

## License

Apache License 2.0, the same as the Rust node; see [LICENSE](LICENSE). The vendored libraries keep their own
licences, which are included in the release packages.
