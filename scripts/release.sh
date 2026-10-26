#!/usr/bin/env bash
# Build the Hashstash release binaries reproducibly and record their SHA256s.
#   bash scripts/release.sh [--verify] [--out DIRECTORY]
# Linux only (WSL 2 works). A normal release build: --locked against the
# committed Cargo.lock, never the test-fixtures feature, with the Rust
# toolchain pinned by RUST_TOOLCHAIN (default 1.97.1, as CI). Checkout,
# Cargo home and target paths are remapped, so the same source, toolchain
# and C compiler give byte-identical binaries in any directory. --verify
# rebuilds from scratch in a second target directory and fails unless every
# binary is identical. HASHSTASH_RELEASE_TARGET selects the target directory
# (default target/release-build); keep it on a Linux filesystem under WSL.
# Writes hashstash, hashstash-cold, hashstash-faucet, SHA256SUMS and
# BUILDINFO to DIRECTORY (default target/dist/hashstash-VERSION-linux-ARCH).
set -euo pipefail
export LC_ALL=C TZ=UTC
umask 022
fail() { printf 'release: %s\n' "$*" >&2; exit 1; }

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
verify=false
out=
while (( $# )); do
    case "$1" in
        --verify) verify=true ;;
        --out)
            (( $# >= 2 )) || fail 'missing value for --out'
            out=$2
            shift
            ;;
        -h|--help) sed -n '2,13p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) fail "unknown argument: $1" ;;
    esac
    shift
done
[[ $(uname -s) == Linux ]] || fail 'build on Linux (WSL 2 works); the release runs on Linux hosts'
for tool in sha256sum cc; do
    command -v "$tool" >/dev/null || fail "$tool is required"
done
if ! command -v cargo >/dev/null && [[ -f "$HOME/.cargo/env" ]]; then
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
fi
command -v cargo >/dev/null || fail 'cargo is required'

# The pinned toolchain: the default one when it matches, else rustup's copy.
toolchain=${RUST_TOOLCHAIN:-1.97.1}
run=()
if [[ $(rustc --version 2>/dev/null) != "rustc $toolchain "* ]]; then
    if command -v rustup >/dev/null && grep -q "^$toolchain-" <<< "$(rustup toolchain list)"; then
        run=(rustup run "$toolchain")
    else
        fail "rustc $toolchain is required (found: $(rustc --version 2>/dev/null || echo none)); install it with: rustup toolchain install $toolchain --profile minimal"
    fi
fi
with_toolchain() { ${run[@]+"${run[@]}"} "$@"; }

version=$(sed -n 's/^version = "\([0-9.]*\)"$/\1/p' "$root/Cargo.toml" | head -n 1)
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'cannot read the package version from Cargo.toml'
grep -qx "version=$version" "$root/deploy/linux/install.sh" ||
    fail "deploy/linux/install.sh does not pin version $version"
[[ -f "$root/Cargo.lock" ]] || fail 'Cargo.lock is missing'

# Source identity. A release comes from a committed tree; git may be unable
# to read a checkout that another system's git created.
commit=unavailable
dirty=unknown
epoch=0
git_in_root() { git -c safe.directory="$root" -c core.fileMode=false -C "$root" "$@"; }
if command -v git >/dev/null && git_in_root rev-parse --verify -q HEAD >/dev/null 2>&1; then
    commit=$(git_in_root rev-parse HEAD)
    epoch=$(git_in_root log -1 --format=%ct HEAD)
    if [[ -n $(git_in_root status --porcelain --untracked-files=no) ]]; then
        dirty=true
    else
        dirty=false
    fi
fi
if [[ $dirty == true && ${ALLOW_DIRTY:-false} != true ]]; then
    fail 'the checkout has uncommitted changes; commit them, or set ALLOW_DIRTY=true for a build that is not a release'
fi
[[ $commit != unavailable ]] ||
    printf 'release: warning: git cannot read this checkout; BUILDINFO will not name the source commit\n' >&2

cargo_home=${CARGO_HOME:-$HOME/.cargo}
target=${HASHSTASH_RELEASE_TARGET:-$root/target/release-build}
mkdir -p "$target"
target=$(cd -- "$target" && pwd -P)
for path in "$root" "$cargo_home" "$target"; do
    [[ $path != *[[:space:]]* ]] || fail "paths with whitespace cannot be remapped: $path"
done
binaries=(hashstash hashstash-cold hashstash-faucet)

# One build into the given target directory. Later remappings take
# precedence, so a target directory inside the checkout maps to /target.
build() {
    local dir=$1
    local rustflags
    rustflags=$(printf '%s\x1f' \
        "--remap-path-prefix=$root=/hashstash" \
        "--remap-path-prefix=$cargo_home=/cargo" \
        "--remap-path-prefix=$dir=/target")
    env -u RUSTFLAGS -u CARGO_BUILD_RUSTFLAGS -u RUSTC_WRAPPER -u CARGO_BUILD_RUSTC_WRAPPER \
        -u CARGO_PROFILE_RELEASE_DEBUG -u CARGO_PROFILE_RELEASE_STRIP -u CARGO_BUILD_TARGET \
        CARGO_TARGET_DIR="$dir" \
        CARGO_ENCODED_RUSTFLAGS="${rustflags%$'\x1f'}" \
        CFLAGS="-ffile-prefix-map=$root=/hashstash -ffile-prefix-map=$cargo_home=/cargo -ffile-prefix-map=$dir=/target" \
        SOURCE_DATE_EPOCH="$epoch" \
        ${run[@]+"${run[@]}"} cargo build --locked --release --bins --manifest-path "$root/Cargo.toml"
    for binary in "${binaries[@]}"; do
        [[ -x "$dir/release/$binary" ]] || fail "the build produced no $binary"
    done
}

printf 'release: building Hashstash %s with %s\n' "$version" "$(with_toolchain rustc --version)" >&2
build "$target"
reported=$("$target/release/hashstash" --version)
[[ $reported == "hashstash $version" ]] || fail "the built node reports '$reported', not hashstash $version"

if [[ $verify == true ]]; then
    second="$target-verify"
    rm -rf -- "$second"
    mkdir -p "$second"
    second=$(cd -- "$second" && pwd -P)
    printf 'release: rebuilding from scratch in %s to compare\n' "$second" >&2
    build "$second"
    differ=()
    for binary in "${binaries[@]}"; do
        cmp -s "$target/release/$binary" "$second/release/$binary" || differ+=("$binary")
    done
    (( ${#differ[@]} == 0 )) || fail "the second build differs: ${differ[*]}"
    rm -rf -- "$second"
    printf 'release: both builds are byte-identical\n' >&2
fi

dist=${out:-$root/target/dist/hashstash-$version-linux-$(uname -m)}
mkdir -p "$dist"
dist=$(cd -- "$dist" && pwd -P)
for binary in "${binaries[@]}"; do
    install -m 0755 "$target/release/$binary" "$dist/$binary"
done
(cd -- "$dist" && sha256sum "${binaries[@]}" > SHA256SUMS && sha256sum -c --quiet SHA256SUMS)
{
    printf 'version: %s\n' "$version"
    printf 'source_commit: %s\n' "$commit"
    printf 'source_dirty: %s\n' "$dirty"
    printf 'source_date_epoch: %s\n' "$epoch"
    printf 'cargo_lock_sha256: %s\n' "$(sha256sum "$root/Cargo.lock" | cut -d' ' -f1)"
    printf 'command: cargo build --locked --release --bins (no test-fixtures)\n'
    printf 'path_remapping: checkout=/hashstash cargo_home=/cargo target=/target\n'
    printf 'verified_rebuild: %s\n' "$verify"
    printf 'host: %s\n' "$(uname -srm)"
    printf 'libc: %s\n' "$(ldd --version 2>&1 | head -n 1)"
    printf 'c_compiler: %s\n' "$(cc --version | head -n 1)"
    printf 'cargo: %s\n' "$(with_toolchain cargo --version)"
    with_toolchain rustc --version --verbose | sed 's/^/rustc: /'
} > "$dist/BUILDINFO"
printf 'release: wrote %s\n' "$dist" >&2
cat "$dist/SHA256SUMS"
