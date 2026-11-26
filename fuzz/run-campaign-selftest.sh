#!/usr/bin/env bash
# shellcheck disable=SC2034  # rc and id1 are read inside the eval strings of check()
# Self-test of run-campaign.sh's setup accounting (review M08-W2-RC03). No container, no
# network, no toolchain: run-campaign.sh runs its own setup and build-id scripts on this host
# (HM_FUZZ_LOCAL_ROOT) over a scratch copy of a tiny fake repository, with shims for cargo and
# rustc. It checks that only a setup that completes records a build identity.
#
# Usage: bash fuzz/run-campaign-selftest.sh
# Exit code: 0 when every case passes; 1 otherwise. Everything lives in one mktemp directory,
# removed at the end.
set -u
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
T=$(mktemp -d "${TMPDIR:-/tmp}/hm-fuzz-selftest.XXXXXX")
trap 'rm -rf -- "$T"' EXIT
fails=0; n=0
check() { n=$((n + 1)); if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; fails=$((fails + 1)); fi; }

# --- a fake repository: the files setup copies, one linked crate, the campaign script
R=$T/repo
mkdir -p "$R/fuzz/fuzz_targets" "$R/crates/linked/src" "$R/crates/unlinked/src"
cp "$here/run-campaign.sh" "$R/fuzz/run-campaign.sh"
printf '[workspace]\nmembers = ["crates/*"]\n' >"$R/Cargo.toml"
printf '# fake root lock\n' >"$R/Cargo.lock"
printf '[toolchain]\nchannel = "1.0.0"\n' >"$R/rust-toolchain.toml"
printf '[package]\nname = "fuzz"\n' >"$R/fuzz/Cargo.toml"
printf '# fake fuzz lock\n' >"$R/fuzz/Cargo.lock"
printf 'fn main() {}\n' >"$R/fuzz/fuzz_targets/t.rs"
printf 'pub fn a() {}\n' >"$R/crates/linked/src/lib.rs"
printf 'pub fn b() {}\n' >"$R/crates/unlinked/src/lib.rs"

# --- shims, where run-campaign.sh puts the volume's cargo home on PATH
L=$T/root
mkdir -p "$L/vol/cargo/bin"
cat >"$L/vol/cargo/bin/cargo" <<'EOF'
#!/usr/bin/env bash
# cargo shim: `+nightly tree` lists the one linked crate; `+nightly fuzz build` succeeds, or
# fails (SHIM_BUILD=fail), or rewrites the lock file (SHIM_BUILD=relock), or waits to be
# killed (SHIM_BUILD=hang, after touching $SHIM_HANG_FLAG).
shift  # +nightly
case "$1" in
    tree) echo "fuzz v0.0.0 ($V/work/src/fuzz)"; echo "linked v0.0.0 ($V/work/src/crates/linked)" ;;
    fuzz)
        [ "$2" = --version ] && { echo "cargo-fuzz 0.0.0 (shim)"; exit 0; }
        case "${SHIM_BUILD:-ok}" in
            ok) exit 0 ;;
            fail) echo "error: shim build failure"; exit 1 ;;
            relock) echo "# rewritten by the build" >>Cargo.lock; exit 0 ;;
            hang) : >"$SHIM_HANG_FLAG"; sleep 60; exit 0 ;;
        esac ;;
    *) exit 3 ;;
esac
EOF
printf '#!/bin/sh\necho "rustc 1.0.0-nightly (shim)"\n' >"$L/vol/cargo/bin/rustc"
chmod 0755 "$L/vol/cargo/bin/cargo" "$L/vol/cargo/bin/rustc"

camp() { env HM_FUZZ_LOCAL_ROOT="$L" bash "$R/fuzz/run-campaign.sh" "$@"; }
out=$L/vol/work/out
reset_lock() { printf '# fake fuzz lock\n' >"$R/fuzz/Cargo.lock"; }

# 1. A setup that completes records an identity, and it covers the toolchain inputs.
camp setup >"$T/o1" 2>&1; rc=$?
check "a completed setup exits 0 and records an identity" '[ "$rc" = 0 ] && [ -s "$out/build-id" ] && [ ! -e "$out/build-id.pending" ]'
check "the identity names the linked crate, the toolchain file, the pinned base image and the toolchain line" \
    'grep -q " linked-crates=crates/linked toolchain-file=product-rust-toolchain.toml image=debian@sha256:[0-9a-f]\{64\} nightly=" "$out/build-id" && grep -q "cargo-fuzz=" "$out/build-id" && grep -q "rustflags=-Clink-arg=-fuse-ld=lld" "$out/build-id"'
id1=$(cut -d" " -f1 "$out/build-id")
check "build-id show prints the same identity and writes nothing" '[ "$(camp build-id show 2>/dev/null | cut -d" " -f1)" = "$id1" ] && [ "$(cut -d" " -f1 "$out/build-id")" = "$id1" ]'
check "build-id refuses while an identity exists" 'camp build-id >/dev/null 2>&1; [ $? = 2 ]'

# 2. The identity changes with each input the ruling lists.
for f in Cargo.toml Cargo.lock rust-toolchain.toml; do
    cp "$R/$f" "$T/keep"; echo "# changed" >>"$R/$f"
    camp setup >/dev/null 2>&1
    check "changing $f changes the identity" '[ "$(cut -d" " -f1 "$out/build-id" 2>/dev/null)" != "$id1" ]'
    cp "$T/keep" "$R/$f"
done
camp setup >/dev/null 2>&1
check "with the inputs restored, the identity is the first one again" '[ "$(cut -d" " -f1 "$out/build-id")" = "$id1" ]'

# 3. A setup stopped after its identity step leaves no identity, and build-id will not record one.
HM_FUZZ_TEST_STOP_AFTER=identity camp setup >"$T/o3" 2>&1; rc=$?
check "a setup stopped after the identity step exits 1 and leaves no identity" '[ "$rc" = 1 ] && [ ! -e "$out/build-id" ] && [ -s "$out/build-id.pending" ]'
camp build-id >"$T/o3b" 2>&1; rc=$?
check "build-id then refuses: a setup started and did not finish" '[ "$rc" = 2 ] && grep -q "a setup started and did not finish" "$T/o3b" && [ ! -e "$out/build-id" ]'

# 4. A setup whose build fails leaves no identity.
SHIM_BUILD=fail camp setup >"$T/o4" 2>&1; rc=$?
check "a setup whose every target fails to build exits non-zero and leaves no identity" '[ "$rc" != 0 ] && [ ! -e "$out/build-id" ]'

# 5. A setup whose build rewrites the lock file leaves no identity.
SHIM_BUILD=relock camp setup >"$T/o5" 2>&1; rc=$?
check "a setup whose build rewrites the fuzz lock refuses and leaves no identity" '[ "$rc" != 0 ] && [ ! -e "$out/build-id" ] && grep -q "Cargo.lock changed during setup" "$T/o5"'
rm -f "$R/fuzz/Cargo.lock.new"; reset_lock

# 6. A setup killed during its build leaves no identity, though one was recorded before.
camp setup >/dev/null 2>&1
check "(a completed setup recorded an identity before the kill)" '[ -s "$out/build-id" ]'
set -m
SHIM_BUILD=hang SHIM_HANG_FLAG="$T/hang" camp setup >"$T/o6" 2>&1 &
job=$!
set +m
i=0; while [ $i -lt 100 ] && [ ! -e "$T/hang" ]; do sleep 0.1; i=$((i + 1)); done
# The setup's own process group (job control gave it one), by its exact id.
kill -KILL -- "-$job" 2>/dev/null; wait "$job" 2>/dev/null
check "a setup killed during its build leaves no identity" '[ -e "$T/hang" ] && [ ! -e "$out/build-id" ]'
check "and build-id refuses after the kill" 'camp build-id >/dev/null 2>&1; [ $? = 2 ] && [ ! -e "$out/build-id" ]'

# 7. The local mode covers setup and build-id only.
check "run refuses in the local mode" 'camp run 1 >/dev/null 2>&1; [ $? = 2 ]'

if [ "$fails" = 0 ]; then echo "run-campaign-selftest: PASS ($n checks)"; exit 0; fi
echo "run-campaign-selftest: FAIL ($fails of $n)"; exit 1
