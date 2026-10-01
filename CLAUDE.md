# epic-zig

A Zig 0.16 rewrite of the Epic Cash node (Rust reference: `../epic`, v4.0.4), using RocksDB. It must stay
wire- and consensus-compatible with the Rust node and behave like it (same settings, defaults, API, log wording),
only faster. `PLAN.md` records what has been built and why.

## Git
- Do not add `Co-Authored-By` lines (or any Claude/AI attribution) to commit messages or PR descriptions.
- Commit only when asked.

## Build and test
- `zig build test --summary all`: all tests must pass before a change is done.
- `zig build`: debug build in `zig-out/bin/epic-zig`.
- `zig build --release`: ReleaseSafe, stripped (the vendored C/C++ libraries are always ReleaseFast).
- Portable Linux release: `zig build --release -Dtarget=x86_64-linux-gnu.2.28 --prefix local/xbuild/x86_64-linux-glibc2.28`.
- Releases: `scripts/release.sh` (tests, builds Linux x86_64/ARM64 glibc 2.28, macOS Intel/Apple Silicon and Windows,
  packages them with SHA256SUMS, tags `v<VERSION>` and publishes a GitHub release). `--build-only` builds into `dist/`
  without tagging or uploading; `--draft` leaves the release as a draft. The version lives in `src/version.zig`.
- Other targets: `-Dtarget=aarch64-linux-gnu`, `x86_64-windows-gnu`, `aarch64-macos`, `x86_64-macos` (built, not yet run on real machines).

## Safety on this machine
- A live Rust node and wallets run here. Never use `~/.epic`, `~/.boxwallet` or `~/.epic-wallet` as a data dir
  (main.zig refuses them), never read their secrets, and connect to the live node only as an ordinary peer.
- Test nodes need an explicit `--data-dir` (under `local/` or the scratchpad) and ports that don't clash with
  3413/3414 (e.g. `--listen 127.0.0.1:33414 --api 127.0.0.1:33413`).
- The user runs their own test node from `~/epic-zig-test`: don't stop it or delete its data.
- When restarting a test node, find its PID in one command and start it in a separate one: `pgrep -f`/`pkill -f`
  in the same shell line as the start command matches the shell itself. Never `pkill -x epic-zig`.

## Conventions
- Match the Rust node: config keys and defaults, `/v1`, `/v2/owner` and `/v2/foreign` JSON shapes, sync statuses,
  and log lines (`YYYY-MM-DD HH:MM:SS.mmm LEVEL message`, coloured like log4rs). Any deliberate difference goes in
  `PLAN.md` and is mentioned to the user.
- Verify against the reference code in `../epic` rather than from memory.
