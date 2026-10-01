#!/usr/bin/env bash
# Builds release binaries for Linux, macOS and Windows and publishes them as a
# GitHub release for the version in src/version.zig.
#
#   scripts/release.sh            build, test, confirm, then tag + publish
#   scripts/release.sh --draft    the same, but leave the GitHub release as a draft
#   scripts/release.sh --build-only   just build and package into dist/ (no tag, no upload)
#   scripts/release.sh --yes      don't ask before tagging and uploading
#
# Needs: zig, git, gh (logged in), tar, zip, sha256sum.
set -euo pipefail

cd "$(dirname "$0")/.."

DRAFT=0
BUILD_ONLY=0
ASSUME_YES=0
for arg in "$@"; do
    case "$arg" in
        --draft) DRAFT=1 ;;
        --build-only) BUILD_ONLY=1 ;;
        --yes | -y) ASSUME_YES=1 ;;
        -h | --help) sed -n '2,10p' "$0"; exit 0 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

die() { echo "error: $*" >&2; exit 1; }
step() { printf '\n==> %s\n' "$*"; }

VERSION=$(sed -n 's/^pub const VERSION = "\(.*\)";/\1/p' src/version.zig)
[ -n "$VERSION" ] || die "couldn't read VERSION from src/version.zig"
TAG="v$VERSION"
DIST="dist/$TAG"

# zig target triple -> name used in the archive
TARGETS=(
    "x86_64-linux-gnu.2.28:linux-x86_64"
    "aarch64-linux-gnu.2.28:linux-aarch64"
    "x86_64-macos:macos-x86_64"
    "aarch64-macos:macos-aarch64"
    "x86_64-windows-gnu:windows-x86_64"
)

# vendored source licence -> name inside the package
THIRD_PARTY=(
    "vendor/rust-secp256k1-zkp/depend/secp256k1-zkp/COPYING:secp256k1-zkp-MIT.txt"
    "vendor/randomx-rust/randomx/LICENSE:RandomX-BSD-3-Clause.txt"
    "vendor/CRoaring/LICENSE:CRoaring-Apache-2.0-or-MIT.txt"
    "vendor/rocksdb/LICENSE.Apache:RocksDB-Apache-2.0.txt"
    "vendor/rocksdb/LICENSE.leveldb:RocksDB-LevelDB-BSD.txt"
)
for pair in "${THIRD_PARTY[@]}"; do
    [ -f "${pair%%:*}" ] || { echo "error: missing ${pair%%:*}" >&2; exit 1; }
done

for tool in zig git tar zip sha256sum; do
    command -v "$tool" >/dev/null || die "$tool is not installed"
done

if [ "$BUILD_ONLY" -eq 0 ]; then
    step "Checking the repository"
    command -v gh >/dev/null || die "gh (GitHub CLI) is not installed"
    gh auth status >/dev/null 2>&1 || die "gh is not logged in: run 'gh auth login'"
    [ -z "$(git status --porcelain)" ] || die "the working tree has uncommitted changes; commit them first"
    git fetch --quiet --tags origin
    [ "$(git rev-parse HEAD)" = "$(git rev-parse '@{u}' 2>/dev/null || echo none)" ] ||
        die "this branch isn't in step with its remote; push or pull first"
    if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
        die "tag $TAG already exists: bump VERSION in src/version.zig"
    fi
    echo "Releasing $TAG from $(git rev-parse --abbrev-ref HEAD) @ $(git rev-parse --short HEAD)"
fi

step "Running the tests"
if ! out=$(zig build test --summary all 2>&1); then
    echo "$out" | tail -20
    die "tests failed"
fi
echo "$out" | grep -E "^Build Summary" || true

step "Building $TAG"
rm -rf "$DIST"
mkdir -p "$DIST/build" "$DIST/stage"
for entry in "${TARGETS[@]}"; do
    target="${entry%%:*}"
    name="${entry##*:}"
    pkg="epic-zig-$VERSION-$name"
    echo "  $target -> $pkg"
    zig build --release -Dtarget="$target" --prefix "$DIST/build/$name" >/dev/null ||
        die "build failed for $target"
    # the package holds just the node (not the dev tools) plus any licence/readme
    mkdir -p "$DIST/stage/$pkg"
    exe="epic-zig"
    [[ "$name" == windows-* ]] && exe="epic-zig.exe"
    cp "$DIST/build/$name/bin/$exe" "$DIST/stage/$pkg/"
    for f in LICENSE LICENSE.md README.md; do
        if [ -f "$f" ]; then cp "$f" "$DIST/stage/$pkg/"; fi
    done
    # the libraries compiled into the binary, whose licences ask to travel with it
    mkdir -p "$DIST/stage/$pkg/third-party-licenses"
    for pair in "${THIRD_PARTY[@]}"; do
        cp "${pair%%:*}" "$DIST/stage/$pkg/third-party-licenses/${pair##*:}"
    done
    if [[ "$name" == windows-* ]]; then
        (cd "$DIST/stage" && zip -qr "../$pkg.zip" "$pkg")
    else
        tar -C "$DIST/stage" -czf "$DIST/$pkg.tar.gz" "$pkg"
    fi
done
rm -rf "$DIST/build" "$DIST/stage"
(cd "$DIST" && sha256sum -- *.tar.gz *.zip >SHA256SUMS)

step "Packages"
ls -lh "$DIST" | tail -n +2
cat "$DIST/SHA256SUMS"

if [ "$BUILD_ONLY" -eq 1 ]; then
    echo
    echo "Built into $DIST (nothing tagged or uploaded)."
    exit 0
fi

if [ "$ASSUME_YES" -eq 0 ]; then
    echo
    read -r -p "Tag $TAG, push the tag and publish these files to GitHub$([ "$DRAFT" -eq 1 ] && echo ' as a draft')? [y/N] " answer
    [[ "$answer" =~ ^[Yy]$ ]] || { echo "Stopped; nothing was tagged or uploaded."; exit 1; }
fi

step "Tagging $TAG"
git tag -a "$TAG" -m "Epic-Zig $TAG"
git push origin "$TAG"

step "Publishing the GitHub release"
NOTES=$(cat <<EOF
Epic-Zig $TAG: an Epic Cash node written in Zig, compatible with the Rust node (4.0.4).

| Download | For |
|---|---|
| \`epic-zig-$VERSION-linux-x86_64.tar.gz\` | Linux x86_64 (glibc 2.28+: Ubuntu 20.04+, Debian 10+, RHEL 8+) |
| \`epic-zig-$VERSION-linux-aarch64.tar.gz\` | Linux ARM64 (glibc 2.28+) |
| \`epic-zig-$VERSION-macos-aarch64.tar.gz\` | macOS, Apple Silicon |
| \`epic-zig-$VERSION-macos-x86_64.tar.gz\` | macOS, Intel |
| \`epic-zig-$VERSION-windows-x86_64.zip\` | Windows x86_64 |

Run: \`epic-zig --data-dir <folder>\` (settings: \`<folder>/epic-zig.toml\`, created on first run).
Check downloads against \`SHA256SUMS\`. The macOS binaries are not code-signed.
EOF
)
draft_flag=()
[ "$DRAFT" -eq 1 ] && draft_flag=(--draft)
gh release create "$TAG" "$DIST"/*.tar.gz "$DIST"/*.zip "$DIST/SHA256SUMS" \
    --title "Epic-Zig $TAG" --notes "$NOTES" --verify-tag "${draft_flag[@]}"

echo
echo "Done: $(gh release view "$TAG" --json url --jq .url)"
