#!/usr/bin/env bash
# Build one Heimdall release archive (m08-plan U3a; ADR-0014 sections 4.2 and 4.4).
#
# Usage: bash tools/packaging/build-release.sh <target> [--features <list>] [--allow-dirty] [--offline]
#   <target>: aarch64-apple-darwin (on a macOS arm64 host), x86_64-unknown-linux-gnu or
#             aarch64-unknown-linux-gnu (cross-built through zig, glibc 2.31 floor).
#             The Windows archive is built on the PC by build-release.ps1.
# Exit code: 0 when the archive was built and passed verify_artifact.py; 1 when the build,
# the inventory or the verification failed; 2 on a usage or setup error (an unknown target, a
# missing rustup target or tool, a dirty tree without --allow-dirty, a home path with spaces).
#
# What it does, in order:
#   1. refuses a dirty tree (or records `tree_clean: false` with --allow-dirty);
#   2. builds `heimdall` with `cargo build --release --locked --target <target>` in the one
#      ./target directory, with build-host paths remapped (the home directory, the cargo and
#      rustup homes and this checkout become /builder, /cargo, /rustup and /heimdall), for
#      Rust and for the bundled C code;
#   3. stages target/release-artifacts/heimdall-<version>-<target>/ with the executable and
#      whichever release documents exist in the tree, the SBOM (the pinned cargo-cyclonedx
#      under target/tools, checked by provenance.py against cargo's selected graph and the
#      packages this build compiled), THIRD-PARTY-NOTICES.txt, BUILD-RECORD.json and the
#      inner MANIFEST.sha256, which lists every file except itself;
#   4. packs a deterministic .tar.gz and verifies it (verify_artifact.py), passing the
#      builder's home, cargo, rustup and checkout paths and user name as forbidden text,
#      with the one exact login-entry label allowed;
#   5. copies the SBOM and the build record beside the archive and rewrites the external
#      index target/release-artifacts/SHA256SUMS over every archive and record there. The
#      index is never packed (ADR-0014 section 4.4).
# Nothing is executed from the built artifact, nothing is uploaded, and nothing outside
# ./target is written except one temporary file removed on exit.
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
cd "$repo"
here=tools/packaging
export PYTHONDONTWRITEBYTECODE=1

usage() { sed -n '2,10p' "$here/build-release.sh" | sed 's/^# \{0,1\}//' >&2; exit 2; }
target=""; features=""; allow_dirty=no; offline=()
while [ $# -gt 0 ]; do
    case "$1" in
        --features) [ $# -ge 2 ] || usage; features=$2; shift 2 ;;
        --allow-dirty) allow_dirty=yes; shift ;;
        --offline) offline=(--offline); shift ;;
        -*) usage ;;
        *) [ -z "$target" ] || usage; target=$1; shift ;;
    esac
done
[ -n "$target" ] || usage

zig_target=""
case "$target" in
    aarch64-apple-darwin)
        [ "$(uname -s)-$(uname -m)" = "Darwin-arm64" ] || { echo "build-release: $target is built on a macOS arm64 host" >&2; exit 2; } ;;
    x86_64-unknown-linux-gnu) zig_target=x86_64-linux-gnu.2.31 ;;
    aarch64-unknown-linux-gnu) zig_target=aarch64-linux-gnu.2.31 ;;
    *) echo "build-release: unsupported target $target (Windows: build-release.ps1 on the PC)" >&2; exit 2 ;;
esac
for tool in cargo rustc rustup git python3; do
    command -v "$tool" >/dev/null || { echo "build-release: $tool not found" >&2; exit 2; }
done
if ! rustup target list --installed | grep -qx "$target"; then
    echo "build-release: the rust target is not installed: rustup target add $target" >&2; exit 2
fi
[ -z "$zig_target" ] || command -v zig >/dev/null || { echo "build-release: zig not found" >&2; exit 2; }
sbom_tool="$repo/target/tools/bin/cargo-cyclonedx"
sbom_tool_version=0.5.10
if [ ! -x "$sbom_tool" ] || [ "$("$sbom_tool" cyclonedx --version | awk '{print $NF}')" != "$sbom_tool_version" ]; then
    echo "build-release: the pinned SBOM tool is missing: cargo install --locked --version =$sbom_tool_version --root target/tools cargo-cyclonedx" >&2; exit 2
fi

cargo_home=${CARGO_HOME:-$HOME/.cargo}
rustup_home=${RUSTUP_HOME:-$HOME/.rustup}
for p in "$HOME" "$cargo_home" "$rustup_home" "$repo"; do
    case "$p" in *[[:space:]]*) echo "build-release: a build path contains whitespace; the C path remap cannot express it" >&2; exit 2 ;; esac
done

clean=yes
if [ -n "$(git status --porcelain)" ]; then
    [ "$allow_dirty" = yes ] || { echo "build-release: the tree is not clean (commit first, or --allow-dirty for a rehearsal)" >&2; exit 2; }
    clean=no
fi
commit=$(git rev-parse HEAD)
commit_time=$(TZ=UTC git show -s --date=format-local:%Y-%m-%dT%H:%M:%SZ --format=%cd HEAD)
version=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)
[ -n "$version" ] || { echo "build-release: no workspace version" >&2; exit 2; }

# --- path remapping -----------------------------------------------------------------
# rustc applies the last matching --remap-path-prefix, so the general one comes first.
sep=$'\x1f'
remap=(
    "--remap-path-prefix=$HOME=/builder"
    "--remap-path-prefix=$rustup_home=/rustup"
    "--remap-path-prefix=$cargo_home=/cargo"
    "--remap-path-prefix=$repo=/heimdall"
)
encoded=$(IFS=$sep; echo "${remap[*]}")
flags_text="--remap-path-prefix=<home>=/builder --remap-path-prefix=<rustup-home>=/rustup --remap-path-prefix=<cargo-home>=/cargo --remap-path-prefix=<checkout>=/heimdall"
cflags="-ffile-prefix-map=$HOME=/builder -ffile-prefix-map=$rustup_home=/rustup -ffile-prefix-map=$cargo_home=/cargo -ffile-prefix-map=$repo=/heimdall"
t_env=$(echo "$target" | tr '-' '_')
t_ENV=$(echo "$t_env" | tr '[:lower:]' '[:upper:]')

build_env=(
    "CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-4}"
    "CARGO_ENCODED_RUSTFLAGS=$encoded"
    "CFLAGS_$t_env=$cflags"
    "SOURCE_DATE_EPOCH=$(git show -s --format=%ct HEAD)"
)
if [ -n "$zig_target" ]; then
    shims="$repo/target/hm-pack-shims"
    mkdir -p "$shims"
    cat >"$shims/zigcc-$target.sh" <<EOF
#!/usr/bin/env bash
# zig cc for $target, glibc 2.31 floor (tools/packaging/build-release.sh). Drops the
# triple cc-rs and rustc pass (zig has its own -target) and the one linker flag zig's
# linker does not accept (rustc's Cortex-A53 erratum 843419 workaround on aarch64, as
# cargo-zigbuild also drops it), keeps everything else.
args=()
for a in "\$@"; do
  case "\$a" in
    --target=*|-m64|-Wl,--fix-cortex-a53-843419) ;;
    *) args+=("\$a") ;;
  esac
done
exec zig cc -target $zig_target "\${args[@]}"
EOF
    printf '#!/usr/bin/env bash\nexec zig ar "$@"\n' >"$shims/zigar.sh"
    chmod 0755 "$shims/zigcc-$target.sh" "$shims/zigar.sh"
    build_env+=(
        "CARGO_TARGET_${t_ENV}_LINKER=$shims/zigcc-$target.sh"
        "CC_$t_env=$shims/zigcc-$target.sh"
        "AR_$t_env=$shims/zigar.sh"
    )
fi

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
started=$(now)
feature_args=()
[ -z "$features" ] || feature_args=(--features "$features")
echo "== build-release: $target at ${commit:0:12} (tree clean: $clean)"
mkdir -p "$repo/target/release-artifacts"
messages="$repo/target/release-artifacts/.build-messages-$target.json"
env "${build_env[@]}" cargo build --release --locked ${offline[@]+"${offline[@]}"} -p heimdall \
    --target "$target" ${feature_args[@]+"${feature_args[@]}"} --message-format=json-render-diagnostics \
    >"$messages" || { echo "build-release: cargo build failed" >&2; exit 1; }
finished=$(now)

# --- stage ----------------------------------------------------------------------------
name="heimdall-$version-$target"
out="$repo/target/release-artifacts"
stage="$out/$name"
case "$stage" in "$repo"/target/release-artifacts/heimdall-*) rm -rf -- "$stage" ;; esac
mkdir -p "$stage"
install -m 0755 "target/$target/release/heimdall" "$stage/heimdall"

# Release documents that exist in the tree are packaged; the candidate build (m08-plan U3b)
# makes the list mandatory.
missing=()
for f in LICENSE SECURITY.md; do
    if [ -f "$f" ]; then install -m 0644 "$f" "$stage/$f"; else missing+=("$f"); fi
done
if [ -f "$here/install.sh" ]; then install -m 0755 "$here/install.sh" "$stage/install.sh"; else missing+=(install.sh); fi

signature=none
if [ "$target" = aarch64-apple-darwin ]; then
    signature="ad-hoc (linker-signed); not notarized"
fi

feat_opt=()
[ -z "$features" ] || feat_opt=(--features "$features")
py() { python3 -I "$here/provenance.py" "$@"; }
py sbom --target "$target" ${feat_opt[@]+"${feat_opt[@]}"} ${offline[@]+"${offline[@]}"} \
    --commit "$commit" --time "$commit_time" --tool "$sbom_tool" --build-messages "$messages" \
    --out "$stage/heimdall-$target.cdx.json" || exit 1
py notices --target "$target" ${feat_opt[@]+"${feat_opt[@]}"} ${offline[@]+"${offline[@]}"} \
    --out "$stage/THIRD-PARTY-NOTICES.txt" || exit 1
py build-record --target "$target" ${feat_opt[@]+"${feat_opt[@]}"} --commit "$commit" --time "$commit_time" \
    --clean "$clean" --flags "$flags_text" --started "$started" --finished "$finished" \
    --signature "$signature" --stage "$stage" --out "$stage/BUILD-RECORD.json" || exit 1
py manifest --stage "$stage" || exit 1
rm -f -- "$messages"

# --- verify, pack, verify -------------------------------------------------------------
forbid=$(mktemp "${TMPDIR:-/tmp}/hm-forbid.XXXXXX")
trap 'rm -f -- "$forbid"' EXIT
# The builder's paths and user name. The user name is forbidden everywhere except inside the
# exact macOS login-entry label prefix, which embeds the repository owner's account name
# (crates/runtime/src/autostart/render.rs). Here the two names are the same string, so a
# global allowance would hide a real local leak; only those exact bytes are masked. If the
# label is renamed (owner input B17), this allowance goes away.
{ echo "$HOME"; echo "$repo"; echo "$cargo_home"; echo "$rustup_home"; } | sort -u >"$forbid"
# A user name shorter than 4 characters would match ordinary text everywhere, so it is not
# forbidden as a bare string. That is said out loud, never done silently; the home path
# above and the verifier's own home-path rule still cover it.
if [ "$(id -un | awk '{ print length($0) }')" -ge 4 ]; then id -un >>"$forbid"; else echo "== note: the builder's user name is shorter than 4 characters and is not forbidden as a bare string"; fi
label=$(sed -n 's/^pub const LAUNCH_AGENT_LABEL_PREFIX: &str = "\(.*\)";$/\1/p' crates/runtime/src/autostart/render.rs | head -1)
[ -n "$label" ] || { echo "build-release: the login-entry label was not found in crates/runtime/src/autostart/render.rs" >&2; exit 2; }

verify() { python3 -I "$here/verify_artifact.py" "$1" --target "$target" --forbid-file "$forbid" --allow-exact "$label"; }
verify "$stage" || { echo "build-release: the staged tree failed verification; no archive written" >&2; exit 1; }
archive="$out/$name.tar.gz"
rm -f -- "$archive"
py pack --stage "$stage" --time "$commit_time" --out "$archive" || exit 1
verify "$archive" || { rm -f -- "$archive"; echo "build-release: the archive failed verification and was removed" >&2; exit 1; }

# --- external records and the index ---------------------------------------------------
install -m 0644 "$stage/heimdall-$target.cdx.json" "$out/$name.cdx.json"
install -m 0644 "$stage/BUILD-RECORD.json" "$out/$name.build-record.json"
py index --dir "$out" || exit 1
python3 -I "$here/verify_artifact.py" "$archive" --target "$target" --forbid-file "$forbid" --allow-exact "$label" --index "$out/SHA256SUMS" >/dev/null ||
    { echo "build-release: the archive does not match the external index" >&2; exit 1; }

echo "== archive: target/release-artifacts/$name.tar.gz"
echo "== sha256:  $(shasum -a 256 "$archive" | cut -d' ' -f1)"
echo "== index:   target/release-artifacts/SHA256SUMS (external; commit it, never pack it)"
if [ ${#missing[@]} -gt 0 ]; then
    echo "== not yet in the tree, so not packaged: ${missing[*]}"
fi
