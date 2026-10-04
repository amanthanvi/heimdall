#!/bin/sh
# Native self-test driver for the Rust G02 prototype. Runs every step, records the
# REAL exit status of each, and writes logs plus summary.json under
# $HP_SELFTEST_OUT (default: tests/evidence/artifacts/g02-rust/selftest/attempt-4-round3b).
# Never touches ~/.ssh or a real agent (SSH_AUTH_SOCK is unset; fake agents live in
# per-test temp dirs). Containers run with --network none and --pull never, from images
# pinned by digest. POSIX sh.
#
# Each step has an expectation: "exit0", or "nonzero" for red proofs (new tests run
# against the round-1 or round-2 binaries, whose digests are checked against their manifests).
# summary.json records both; "met" says whether the real exit status matched.
set -u
unset SSH_AUTH_SOCK
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
REPO=$(CDPATH= cd -- "$HERE/../.." && pwd -P)
OUT="${HP_SELFTEST_OUT:-$REPO/tests/evidence/artifacts/g02-rust/selftest/attempt-4-round3b}"
rm -rf "$OUT"
mkdir -p "$OUT"
STEPS="$OUT/steps.tsv"
: > "$STEPS"
cd "$HERE" || exit 1
ZB="$HERE/target/tools/bin/cargo-zigbuild"
export PYTHONDONTWRITEBYTECODE=1
FIX="$REPO/tests/fixtures/g02/profiles"
DEBIAN="debian:bookworm-slim@sha256:0c8bbb8e987a035fe1d9704eb2e571b7e9a836e1caa46345290674b45b69e417"
PYIMG="python:3.13-slim-bookworm@sha256:5024f48ba9441d4b13a95d3945abc6365538e3a31109833367a1923523c6efed"
# linux/amd64 runs are emulated (informational). The only local amd64 Linux image is an
# alpine 3.22 amd64 retag (hp-g02-alpine-amd64:3.22), pinned here by image ID.
AMD64IMG="${HP_AMD64_IMAGE:-sha256:c83674e1999044d33d751661371b873539f47e5b5c5ca3320c7e0377acca6238}"
R1="$HERE/target/round1-dist"   # round-1 artifacts for red proofs (see step round1-digests)
R2="$HERE/target/round2-dist"   # round-2 artifacts for round-3b red proofs (see step round2-digests)

# step <name> <expect: exit0|nonzero> <command string> : sh -c, log to $OUT/<name>.log
step() {
  name=$1; expect=$2; shift 2
  printf '== %s\n' "$name" >&2
  t0=$(date +%s)
  sh -c "$1" >"$OUT/$name.log" 2>&1
  rc=$?
  t1=$(date +%s)
  printf '%s\t%s\t%s\t%s\t%s\n' "$name" "$rc" "$expect" "$((t1 - t0))" "$(printf '%s' "$1" | tr '\n\t' '  ')" >>"$STEPS"
  printf '   exit %s, expected %s (%ss)\n' "$rc" "$expect" "$((t1 - t0))" >&2
}

date -u +%Y-%m-%dT%H:%M:%SZ > "$OUT/started_at.txt"

# --- toolchain facts ---------------------------------------------------------------
step toolchain exit0 'rustc -vV; cargo -V; rustup -V 2>/dev/null | head -1; rustup component list --installed | grep -E "rust-src|rust-std"; zig version; "'"$ZB"'" --version; python3 --version; uname -mrs; sw_vers 2>/dev/null; docker version --format "docker server {{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}}"; docker image inspect '"$DEBIAN"' '"$PYIMG"' --format "{{.RepoDigests}} {{.Architecture}}"'

# --- static checks and host tests (macOS arm64) ------------------------------------
step fmt exit0 'cargo fmt --check'
step clippy exit0 'cargo clippy --locked --all-targets -- -D warnings'
step clippy-windows exit0 'cargo clippy --locked --target x86_64-pc-windows-gnu --all-targets -- -D warnings'
step host-cargo-test exit0 'HEIMDALL_G02_FIXTURES="'"$FIX"'" cargo test --locked -- --test-threads=4'
step unsafe-scan exit0 'echo "unsafe tokens in src/ and build.rs (expected: only src/sigdisp.rs):"; grep -rn "unsafe" src build.rs; grep -n "deny(unsafe_code)\|forbid(unsafe_code)" src/lib.rs src/main.rs'

# --- distributable build -------------------------------------------------------------
step build-sh exit0 '/bin/sh ./build.sh'
cp dist/manifest.json "$OUT/manifest.json" 2>/dev/null
step artifact-inspect exit0 'file dist/*/heimdall-proto*; otool -L dist/darwin-arm64/heimdall-proto; codesign -dv dist/darwin-arm64/heimdall-proto 2>&1 | grep -E "Identifier|flags"; echo "windows DLL imports:"; strings dist/windows-x64/heimdall-proto.exe | grep -iE "^[a-z0-9_.-]+\.dll$" | sort -u; ls -l dist/*/heimdall-proto* dist/THIRD-PARTY-NOTICES.txt; for f in dist/*/heimdall-proto*; do printf "%s home-path-strings=%s tput=%s tmux=%s infocmp=%s\n" "$f" "$(strings -a "$f" | grep -c -F "$HOME")" "$(strings -a "$f" | grep -c -w tput)" "$(strings -a "$f" | grep -ci tmux)" "$(strings -a "$f" | grep -c infocmp)"; done; echo "std panic-path markers:"; for f in dist/*/heimdall-proto*; do printf "%s: %s\n" "$f" "$(strings -a "$f" | grep -oE "/rust/deps/[A-Za-z0-9_.+-]+" | sort -u | tr "\n" " ")"; done'
step darwin-hardened-runtime exit0 'out=$(DYLD_PRINT_LIBRARIES=1 ./dist/darwin-arm64/heimdall-proto version --json 2>&1 >/dev/null); echo "dyld output with DYLD_PRINT_LIBRARIES=1: [${out}]"; [ -z "$out" ]'
step repro-other-checkout exit0 'd=$(mktemp -d /tmp/hp-rs-repro-XXXXXX)/checkout/rust; mkdir -p "$d"; rsync -a --exclude target --exclude dist --exclude __pycache__ ./ "$d/"; (cd "$d" && CARGO_ZIGBUILD="'"$ZB"'" sh ./build.sh) >/dev/null 2>&1; echo "rebuild exit $?"; python3 -c "
import json,sys
a=json.load(open(\"dist/manifest.json\")); b=json.load(open(sys.argv[1]))
ok=True
for x,y in zip(a[\"targets\"],b[\"targets\"]):
    same=x[\"sha256\"]==y[\"sha256\"]; ok&=same
    print(x[\"target\"], x[\"sha256\"], y[\"sha256\"], \"identical\" if same else \"DIFFERENT\")
same=a[\"notices\"][\"sha256\"]==b[\"notices\"][\"sha256\"]; ok&=same
print(\"notices\", \"identical\" if same else \"DIFFERENT\")
sys.exit(0 if ok else 1)" "$d/dist/manifest.json"; rc=$?; rm -rf "$(dirname "$(dirname "$d")")"; exit $rc'
step panic-variant-build exit0 'cargo build --locked --features test-panic --target-dir target/panic && "'"$ZB"'" zigbuild --locked --features test-panic --target aarch64-unknown-linux-musl --target-dir target/panic'

# --- macOS: dist artifact without toolchain on PATH ----------------------------------
step host-test-bins exit0 'cargo test --locked --no-run --message-format=json 2>/dev/null | python3 tools/list_test_bins.py cli > target/host-cli-test.txt && cat target/host-cli-test.txt'
step darwin-dist-version exit0 'env -i HOME=/tmp PATH=/usr/bin:/bin ./dist/darwin-arm64/heimdall-proto version --json'
step darwin-dist-cli-tests exit0 'env -i HOME=/tmp PATH=/usr/bin:/bin HEIMDALL_G02_FIXTURES="'"$FIX"'" HEIMDALL_PROTO_BIN="$PWD/dist/darwin-arm64/heimdall-proto" "$(cat target/host-cli-test.txt)" --test-threads=4'
step darwin-k15-measure exit0 'HEIMDALL_G02_FIXTURES="'"$FIX"'" HEIMDALL_PROTO_BIN="$PWD/dist/darwin-arm64/heimdall-proto" "$(cat target/host-cli-test.txt)" k15 --nocapture'
step darwin-dist-pty exit0 'python3 tests/pty_tui.py dist/darwin-arm64/heimdall-proto --panic-binary target/panic/debug/heimdall-proto'
step darwin-early-sigint exit0 'python3 tools/early_sigint_probe.py dist/darwin-arm64/heimdall-proto 30'
step relocated-tests exit0 'd=$(mktemp -d /tmp/hp-rs-reloc-XXXXXX); rsync -a --exclude target --exclude dist --exclude __pycache__ ./ "$d/rust/"; cd "$d/rust" && HEIMDALL_G02_FIXTURES="'"$FIX"'" cargo test --locked --offline -- --test-threads=4; rc=$?; cd /; rm -rf "$d"; exit $rc'

# --- Linux: cross-built static binaries in clean containers -------------------------
for triple in aarch64-unknown-linux-musl x86_64-unknown-linux-musl; do
  step "cross-test-build-$triple" exit0 '"'"$ZB"'" test --locked --no-run --target '"$triple"' --message-format=json 2>/dev/null | python3 tools/list_test_bins.py all > target/tests-'"$triple"'.txt && cat target/tests-'"$triple"'.txt'
done
if docker info >/dev/null 2>&1; then
  step linux-arm64-dist-version exit0 "docker run --rm --pull never --platform linux/arm64 --network none -v '$REPO:/repo:ro' $DEBIAN sh -c 'uname -m; for t in cargo rustc go node bun python3; do command -v \$t || echo \"\$t: not on PATH\"; done; /repo/prototypes/rust/dist/linux-arm64/heimdall-proto version --json'"
  step linux-arm64-native-tests exit0 "sh tools/linux_tests.sh arm64 aarch64-unknown-linux-musl linux-arm64"
  step linux-arm64-k15-measure exit0 "HP_TEST_ONLY=/cli- HP_TEST_ARGS='k15 --nocapture' sh tools/linux_tests.sh arm64 aarch64-unknown-linux-musl linux-arm64"
  step linux-arm64-dist-pty exit0 "sh tools/linux_pty.sh arm64 prototypes/rust/dist/linux-arm64/heimdall-proto prototypes/rust/target/panic/aarch64-unknown-linux-musl/debug/heimdall-proto"
  step linux-arm64-early-sigint exit0 "docker run --rm --pull never --platform linux/arm64 --network none -e PYTHONDONTWRITEBYTECODE=1 -v '$REPO:/repo:ro' $PYIMG python3 /repo/prototypes/rust/tools/early_sigint_probe.py /repo/prototypes/rust/dist/linux-arm64/heimdall-proto 30"
  # Round 3b: review2 defect 1 under a real RLIMIT_NPROC (non-root uid; ignored test, run alone).
  step linux-arm64-nproc exit0 "HP_LINUX_USER=10001:10001 HP_TEST_ONLY=/cli- HP_TEST_ARGS='linux_nproc --ignored --test-threads=1 --nocapture' sh tools/linux_tests.sh arm64 aarch64-unknown-linux-musl linux-arm64"
  step linux-amd64-dist-version exit0 "docker run --rm --pull never --platform linux/amd64 --network none -v '$REPO:/repo:ro' $AMD64IMG sh -c 'uname -m; /repo/prototypes/rust/dist/linux-x64/heimdall-proto version --json'"
  # Round 3b: the RUST_MIN_STACK test is skipped under amd64 emulation only. Rosetta
  # itself aborts the process (SIGTRAP, "could not find free space for allocation") on
  # the huge thread-stack mmap before heimdall-proto can handle the failure: an emulator
  # artifact, recorded by the observation step below. Native arm64 runs it.
  step linux-amd64-native-tests-emulated exit0 "HP_LINUX_TEST_IMAGE=$AMD64IMG HP_TEST_ARGS='--test-threads=4 --skip run_thread_spawn_failure_never_orphans_child' sh tools/linux_tests.sh amd64 x86_64-unknown-linux-musl linux-x64"
  step linux-amd64-emulated-min-stack-observation exit0 "docker run --rm --pull never --platform linux/amd64 --network none -v '$REPO:/repo:ro' $AMD64IMG sh -c 'RUST_MIN_STACK=999999999999999 /repo/prototypes/rust/dist/linux-x64/heimdall-proto run --meta-file /tmp/m -- sh -c \"echo child-ran\"; echo \"heimdall-proto exit status under amd64 emulation: \$?\"; test -f /tmp/m && cat /tmp/m || echo \"no meta file\"'"
else
  printf 'docker\t-1\texit0\t0\tdocker unavailable\n' >>"$STEPS"
fi

# --- red proofs: the round-1 binaries against the round-2 tests ---------------------
if [ -d "$R1" ]; then
  step round1-digests exit0 'shasum -a 256 '"$R1"'/*/heimdall-proto; python3 -c "
import hashlib,sys
want={\"darwin-arm64\":\"4f8521433fc3be19d932bcc82a99e6dcdf1868e5b602502faf391b98217f6513\",\"linux-arm64\":\"9bbd19c36229cb4bd34022c0fa16762e6d995dfd70935f9c78d88c4354a83dfb\",\"linux-x64\":\"10e6bf896dd64b835328287c916171c808e0da32ef4b83b1a4267e51fe029856\"}
ok=all(hashlib.sha256(open(sys.argv[1]+\"/\"+t+\"/heimdall-proto\",\"rb\").read()).hexdigest()==h for t,h in want.items())
print(\"round-1 manifest digests match:\", ok); sys.exit(0 if ok else 1)" '"$R1"
  step red-round1-darwin-cli-tests nonzero 'HEIMDALL_G02_FIXTURES="'"$FIX"'" HEIMDALL_PROTO_BIN='"$R1"'/darwin-arm64/heimdall-proto "$(cat target/host-cli-test.txt)" --test-threads=4'
  step red-round1-darwin-pty nonzero 'python3 tests/pty_tui.py '"$R1"'/darwin-arm64/heimdall-proto'
  step red-round1-darwin-early-sigint exit0 'python3 tools/early_sigint_probe.py '"$R1"'/darwin-arm64/heimdall-proto 30'
  if docker info >/dev/null 2>&1; then
    step red-round1-linux-arm64-native-tests nonzero "sh tools/linux_tests.sh arm64 aarch64-unknown-linux-musl linux-arm64 prototypes/rust/target/round1-dist/linux-arm64/heimdall-proto"
    step red-round1-linux-arm64-pty nonzero "sh tools/linux_pty.sh arm64 prototypes/rust/target/round1-dist/linux-arm64/heimdall-proto"
    step red-round1-linux-arm64-early-sigint exit0 "docker run --rm --pull never --platform linux/arm64 --network none -e PYTHONDONTWRITEBYTECODE=1 -v '$REPO:/repo:ro' $PYIMG python3 /repo/prototypes/rust/tools/early_sigint_probe.py /repo/prototypes/rust/target/round1-dist/linux-arm64/heimdall-proto 30"
  fi
else
  printf 'round1-digests\t-1\texit0\t0\tround-1 binaries not present under target/round1-dist\n' >>"$STEPS"
fi

# --- round 3b red proofs: the round-2 binaries against the round-3b tests -------------
if [ -d "$R2" ]; then
  step round2-digests exit0 'shasum -a 256 '"$R2"'/*/heimdall-proto; python3 -c "
import hashlib,sys
want={\"darwin-arm64\":\"d9838f89f746c6d79df7c57b1831443cd3956cdadfdd6e34c776f3ef65a67e11\",\"linux-arm64\":\"77d10192ec9192d09370b13b97ae04af1c59b11e3bda8604825597581a6ccb42\",\"linux-x64\":\"28c8dee00e34be705c38170f84a611f023693ecfb567e24bfe16e9fb84661272\"}
ok=all(hashlib.sha256(open(sys.argv[1]+\"/\"+t+\"/heimdall-proto\",\"rb\").read()).hexdigest()==h for t,h in want.items())
print(\"round-2 manifest digests match:\", ok); sys.exit(0 if ok else 1)" '"$R2"
  step red-round2-darwin-thread-spawn nonzero 'HEIMDALL_G02_FIXTURES="'"$FIX"'" HEIMDALL_PROTO_BIN='"$R2"'/darwin-arm64/heimdall-proto "$(cat target/host-cli-test.txt)" thread_spawn --nocapture'
  step round2-darwin-pty-k6e-k6d exit0 'HP_PTY_ONLY=k6 python3 tests/pty_tui.py '"$R2"'/darwin-arm64/heimdall-proto'
  if docker info >/dev/null 2>&1; then
    step red-round2-linux-arm64-thread-spawn nonzero "HP_TEST_ONLY=/cli- HP_TEST_ARGS='thread_spawn --nocapture' sh tools/linux_tests.sh arm64 aarch64-unknown-linux-musl linux-arm64 prototypes/rust/target/round2-dist/linux-arm64/heimdall-proto"
    step red-round2-linux-arm64-nproc nonzero "HP_LINUX_USER=10001:10001 HP_TEST_ONLY=/cli- HP_TEST_ARGS='linux_nproc --ignored --test-threads=1 --nocapture' sh tools/linux_tests.sh arm64 aarch64-unknown-linux-musl linux-arm64 prototypes/rust/target/round2-dist/linux-arm64/heimdall-proto"
    step round2-linux-arm64-pty-k6e-k6d exit0 "HP_PTY_ONLY=k6 sh tools/linux_pty.sh arm64 prototypes/rust/target/round2-dist/linux-arm64/heimdall-proto"
  fi
else
  printf 'round2-digests\t-1\texit0\t0\tround-2 binaries not present under target/round2-dist\n' >>"$STEPS"
fi
# Sensitivity of the new K6e case: the round-1 job-control design (child in its own
# foreground group, self-SIGSTOP) must fail it.
if [ -d "$R1" ]; then
  step sensitivity-round1-darwin-k6e nonzero 'HP_PTY_ONLY=k6e python3 tests/pty_tui.py '"$R1"'/darwin-arm64/heimdall-proto'
  if docker info >/dev/null 2>&1; then
    step sensitivity-round1-linux-arm64-k6e nonzero "HP_PTY_ONLY=k6e sh tools/linux_pty.sh arm64 prototypes/rust/target/round1-dist/linux-arm64/heimdall-proto"
  fi
fi

# --- shared conformance harness (read-only; tests/g02 is not this prototype's to edit).
# HP_SELFTEST_RUN_HARNESS=1 runs the full catalogue on darwin and, through
# tests/g02/linux/run.sh, on linux-arm64. Records and harness artifacts are written under
# /tmp ($HP_HARNESS_TMP); the records and console logs are copied into $OUT/harness-*/.
H="$REPO/tests/g02/conformance.py"
if [ -f "$H" ] && [ -n "${HP_SELFTEST_RUN_HARNESS:-}" ]; then
  PY=python3
  [ -x "$REPO/tests/g02/.venv/bin/python" ] && PY="$REPO/tests/g02/.venv/bin/python"
  HT="${HP_HARNESS_TMP:-/tmp/hp-rs-round3b-harness}"
  rm -rf "$HT"; mkdir -p "$HT/darwin" "$HT/linux" "$OUT/harness-darwin" "$OUT/harness-linux"
  step harness-darwin exit0 "cd '$REPO' && '$PY' '$H' --bin '$HERE/dist/darwin-arm64/heimdall-proto' --candidate rust --out '$HT/darwin/record.json' --artifacts-dir '$HT/darwin/artifacts' --case-id G02-rust-round3b-darwin"
  cp "$HT/darwin/record.json" "$OUT/harness-darwin/record.json" 2>/dev/null
  if docker info >/dev/null 2>&1; then
    step harness-linux-arm64 exit0 "cd '$REPO' && sh tests/g02/linux/run.sh --artifact-dir '$HERE/dist/linux-arm64' --candidate rust --out '$HT/linux/record.json' --artifacts-out '$HT/linux/artifacts' --case-id G02-rust-round3b-linux-arm64"
    cp "$HT/linux/record.json" "$OUT/harness-linux/record.json" 2>/dev/null
  fi
fi

# No full canary value anywhere in this attempt's evidence (tests/evidence/README.md rule).
step canary-scan exit0 'if grep -rlE "HEIMDALL_CANARY_[A-Za-z0-9_-]{8,}" "'"$OUT"'"; then exit 1; fi; echo "no canary value in '"$(basename "$OUT")"'"'

python3 - "$OUT" "$REPO" "$HOME" <<'PY'
import json, os, sys
out, repo, home = sys.argv[1], sys.argv[2], sys.argv[3]
rel = os.path.relpath(out, repo)
steps = []
for line in open(os.path.join(out, "steps.tsv"), encoding="utf-8"):
    name, rc, expect, secs, cmd = line.rstrip("\n").split("\t", 4)
    rc = int(rc)
    met = (rc == 0) if expect == "exit0" else (rc not in (0, -1))
    steps.append({"step": name, "exit_code": rc, "expect": expect, "met": met, "seconds": int(secs),
                  "command": cmd.replace(home, "~"), "log": f"{rel}/{name}.log"})
# Logs must not carry the builder's home path.
for p in [os.path.join(dp, fn) for dp, _, fns in os.walk(out) for fn in fns]:
    fn = os.path.basename(p)
    if os.path.isfile(p) and fn.endswith((".log", ".json", ".tsv")):
        t = open(p, encoding="utf-8", errors="replace").read()
        if home in t:
            open(p, "w", encoding="utf-8").write(t.replace(home, "~"))
json.dump({"started_at": open(os.path.join(out, "started_at.txt")).read().strip(), "steps": steps,
           "all_expectations_met": all(s["met"] for s in steps)},
          open(os.path.join(out, "summary.json"), "w"), indent=1, ensure_ascii=False)
for s in steps:
    print(f'{s["exit_code"]:>4}  {"ok " if s["met"] else "MISS"} {s["expect"]:<7} {s["step"]}')
PY
