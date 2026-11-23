#!/usr/bin/env bash
# Build and run the fuzz targets inside one container (m08-plan U1a; ADR-0014 section 2.3).
#
# Usage: bash fuzz/run-campaign.sh setup              build the toolchain image state and every target
#        bash fuzz/run-campaign.sh run <seconds> [target...]   run targets (default: all), 2 at a time
#        bash fuzz/run-campaign.sh report             print each target's last result lines
#        bash fuzz/run-campaign.sh build-id           record the build identity of an existing build
#        bash fuzz/run-campaign.sh crashes <dir>      copy crash inputs out (they may be hostile bytes)
#        bash fuzz/run-campaign.sh clean              remove the container volume, by exact name
# Exit code: 0 on success; 1 when a build fails or a target reports a crash, hang or memory
# blow-up; 2 on a usage or setup error.
#
# Linker: lld. With M06's code the sanitizer-instrumented runtime binary is about 250 MB,
# and the default linker fails on arm64 with `relocation truncated to fit: R_AARCH64_CALL26`.
# What is pinned: the base image, the rustup installer (version and SHA-256), the nightly
# toolchain, cargo-fuzz and libfuzzer-sys (PINS
# below and fuzz/Cargo.toml). The product's own toolchain pin is not touched: the nightly
# exists only in the volume this script creates.
# Where things live: the repository is mounted READ-ONLY. Sources are copied into the volume
# `hm-m08-fuzz` (cargo home, rustup home, a work copy, the build directory, the corpus). The
# checkout gets no build output. `setup` needs the network (toolchain and crates); `run`
# has none (--network none).
# Limits per container: 2 CPUs, 4 GiB memory (8 GiB and one compile job for `setup`) (the Mac rule of 2026-11-22). Per input: 10 s,
# 1 GiB. A container capped at 2 CPUs takes no heavy-gate slot; run one capped container
# (fuzz or soak) at a time.
set -euo pipefail

IMAGE="debian:13-slim"
NIGHTLY="nightly-2026-11-15"
CARGO_FUZZ="0.13.2"
RUSTUP_VERSION="1.29.3"
RUSTUP_SHA_AARCH64="9f608c142e0e38a78957d0661ba1dfaf0b6fb37184cfaa4b9a0aa57af6184282"
RUSTUP_SHA_X86_64="b1c8cb14e30889e7e2999e6b69e62d9e9b9ffc0f4df8180564d306d9680e6c55"
VOLUME="hm-m08-fuzz"
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)

# target:max_len (just above each boundary's own cap, ADR-0014 section 2.1)
TARGETS="sshconf_parse:1052672 gitedit_scan:1052672 agent_reply:266240 control_frame:1052672
signing_request:266240 userauth_request:70000 registry_hm1:70000 project_manifest:1052672 runtime_config:1052672
sshconf_eval:1052672 frame_codec:1052672 registry_line:1052672 issuer_protocol:1052672 issuer_backup:70000
known_hosts_match:70000 runtime_instance:70000 registry_script:70000"

command -v docker >/dev/null || { echo "run-campaign: docker not found" >&2; exit 2; }
in_container() { # NETWORK SCRIPT [ARGS...]
    local net=$1 script=$2; shift 2
    docker run --rm --network "$net" --cpus 2 --memory "${HM_FUZZ_MEMORY:-4g}" --pids-limit 512 \
        -v "$repo":/src:ro -v "$VOLUME":/vol \
        -e CARGO_HOME=/vol/cargo -e RUSTUP_HOME=/vol/rustup -e CARGO_BUILD_JOBS="${HM_FUZZ_JOBS:-2}" \
        -e RUSTFLAGS="-Clink-arg=-fuse-ld=lld" -e RUSTUP_VERSION="$RUSTUP_VERSION" -e RUSTUP_SHA_AARCH64="$RUSTUP_SHA_AARCH64" -e RUSTUP_SHA_X86_64="$RUSTUP_SHA_X86_64" -e NIGHTLY="$NIGHTLY" -e CARGO_FUZZ="$CARGO_FUZZ" -e TARGETS="$TARGETS" \
        "$IMAGE" bash -euo pipefail -c "$script" campaign "$@"
}

# The build identity (review M08-W1-R08(a)): a SHA-256 over every file of the workspace
# crates the fuzz crate links (from `cargo tree`), the fuzz crate's manifest, lock file and
# targets, as copied into the volume and built. Written to /vol/work/out/build-id; each run
# line carries it, and the report sums time per build.
BUILD_ID_SCRIPT='
    export PATH=/vol/cargo/bin:$PATH
    cd /vol/work/src
    dirs=$(cargo "+$NIGHTLY" tree --offline --manifest-path fuzz/Cargo.toml --prefix none -e normal,build 2>/dev/null \
        | grep -o "(/vol/work/src/crates/[^)]*)" | tr -d "()" | sed "s#^/vol/work/src/##" | sort -u)
    [ -n "$dirs" ] || { echo "run-campaign: cannot list the crates the fuzz crate links" >&2; exit 1; }
    id=$( { find $dirs -type f ! -path "*/target/*"; find fuzz/fuzz_targets -type f; echo fuzz/Cargo.toml; echo fuzz/Cargo.lock; } \
        | LC_ALL=C sort | xargs sha256sum | sha256sum | cut -c1-16)
    printf "%s linked-crates=%s\n" "$id" "$(echo $dirs | tr " " ",")" >/vol/work/out/build-id
    echo "build-id: $id"
'

case "${1:-}" in
setup)
    docker volume create "$VOLUME" >/dev/null
    # The sanitizer build of the runtime crate was killed at 4 GiB: build with 8 GiB and one job.
    HM_FUZZ_MEMORY=8g; HM_FUZZ_JOBS=1
    in_container bridge '
        export PATH=/vol/cargo/bin:$PATH
        apt-get update -qq >/dev/null
        apt-get install -y -qq --no-install-recommends ca-certificates curl build-essential lld >/dev/null
        if ! command -v rustup >/dev/null; then
            # The installer is pinned by version and digest and checked before it runs;
            # nothing is piped from the network into a shell.
            case "$(uname -m)" in
                aarch64) ru_arch=aarch64-unknown-linux-gnu; ru_sha=$RUSTUP_SHA_AARCH64 ;;
                x86_64) ru_arch=x86_64-unknown-linux-gnu; ru_sha=$RUSTUP_SHA_X86_64 ;;
                *) echo "run-campaign: no pinned rustup installer for $(uname -m)" >&2; exit 2 ;;
            esac
            curl -fsS -o /tmp/rustup-init "https://static.rust-lang.org/rustup/archive/$RUSTUP_VERSION/$ru_arch/rustup-init"
            echo "$ru_sha  /tmp/rustup-init" | sha256sum -c - >/dev/null || { echo "run-campaign: the rustup installer does not match its pinned digest" >&2; exit 1; }
            chmod 0755 /tmp/rustup-init
            /tmp/rustup-init -y --profile minimal --default-toolchain none >/dev/null
            rm -f /tmp/rustup-init
        fi
        rustup toolchain install "$NIGHTLY" --profile minimal >/dev/null
        cargo "+$NIGHTLY" install --locked --version "=$CARGO_FUZZ" cargo-fuzz >/dev/null 2>&1 || cargo "+$NIGHTLY" install --locked --version "=$CARGO_FUZZ" cargo-fuzz
        rm -rf /vol/work/src && mkdir -p /vol/work/src /vol/work/corpus /vol/work/out
        # The product toolchain file is deliberately not copied: it would select stable.
        cp -R /src/Cargo.toml /src/Cargo.lock /src/crates /src/fuzz /vol/work/src/
        cd /vol/work/src/fuzz
        rm -rf target && ln -s /vol/work/target target && mkdir -p /vol/work/target
        cp /src/fuzz/Cargo.lock Cargo.lock 2>/dev/null || true
        # Each target is built on its own, so one that does not link is named and the rest
        # still build. A target that is not built is never reported as run.
        : >/vol/work/out/built.txt; : >/vol/work/out/build-failures.txt
        for t in $TARGETS; do
            name=${t%%:*}
            if cargo "+$NIGHTLY" fuzz build "$name" >"/vol/work/out/build-$name.log" 2>&1; then
                echo "$name" >>/vol/work/out/built.txt
            else
                echo "$name: $(grep -m1 -E "^error" "/vol/work/out/build-$name.log" | cut -c1-160)" >>/vol/work/out/build-failures.txt
            fi
        done
        echo "built: $(wc -l </vol/work/out/built.txt) of $(echo $TARGETS | wc -w)"
        sed "s/^/NOT BUILT: /" /vol/work/out/build-failures.txt
        [ -s /vol/work/out/built.txt ]
        echo "rustc: $(rustc "+$NIGHTLY" --version)"; echo "cargo-fuzz: $(cargo "+$NIGHTLY" fuzz --version)"
        sha256sum Cargo.lock | cut -d" " -f1 > /vol/work/out/fuzz-lock.sha256
    '
    in_container none "$BUILD_ID_SCRIPT"
    # The lock file cargo wrote is brought back so the dependency set is pinned in the tree.
    docker run --rm --network none -v "$VOLUME":/vol:ro "$IMAGE" cat /vol/work/src/fuzz/Cargo.lock >"$repo/fuzz/Cargo.lock.new"
    # HM_FUZZ_RELOCK=1 accepts a changed lock file, for a deliberate dependency change.
    if [ "${HM_FUZZ_RELOCK:-0}" != 1 ] && [ -f "$repo/fuzz/Cargo.lock" ] && ! cmp -s "$repo/fuzz/Cargo.lock" "$repo/fuzz/Cargo.lock.new"; then
        echo "run-campaign: fuzz/Cargo.lock changed during setup; review fuzz/Cargo.lock.new" >&2; exit 1
    fi
    mv "$repo/fuzz/Cargo.lock.new" "$repo/fuzz/Cargo.lock"
    ;;
run)
    secs=${2:-}; case "$secs" in ''|*[!0-9]*) echo "run-campaign: run <seconds> [target...]" >&2; exit 2 ;; esac
    shift 2
    in_container none '
        export PATH=/vol/cargo/bin:$PATH
        secs=$1; shift
        cd /vol/work/src/fuzz
        want="$*"
        # A build made before setup recorded its identity runs as "unknown", which the report
        # never counts; run-campaign.sh build-id records it.
        build=$(cut -d" " -f1 /vol/work/out/build-id 2>/dev/null || true)
        [ -n "$build" ] || build=unknown
        run_one() {
            local name=${1%%:*} max=${1##*:}
            mkdir -p "/vol/work/corpus/$name" "/vol/work/artifacts/$name"
            [ -d "/src/fuzz/seeds/$name" ] && cp -n /src/fuzz/seeds/$name/* "/vol/work/corpus/$name/" 2>/dev/null || true
            local code=0
            cargo "+$NIGHTLY" fuzz run "$name" "/vol/work/corpus/$name" -- \
                -max_total_time="$secs" -timeout=10 -rss_limit_mb=1024 -max_len="$max" \
                -artifact_prefix="/vol/work/artifacts/$name/" -print_final_stats=1 \
                >"/vol/work/out/$name.log" 2>&1 || code=$?
            echo "$name exit $code $(date -u +%Y-%m-%dT%H:%M:%SZ) secs=$secs build=$build" >>/vol/work/out/results.txt
        }
        n=0
        for t in $TARGETS; do
            name=${t%%:*}
            if [ -n "$want" ] && ! echo " $want " | grep -q " $name "; then continue; fi
            if ! grep -qx "$name" /vol/work/out/built.txt 2>/dev/null; then echo "$name: not built, skipped"; continue; fi
            run_one "$t" &
            n=$((n + 1))
            if [ $((n % 2)) = 0 ]; then wait; fi
        done
        wait
    ' "$secs" "$@"
    bash "${BASH_SOURCE[0]}" report
    ;;
report)
    in_container none '
        bad=0
        for t in $TARGETS; do
            name=${t%%:*}
            if grep -q "^$name:" /vol/work/out/build-failures.txt 2>/dev/null; then echo "$name: NOT BUILT on this tree (its last result below is from an earlier tree)"; bad=1; fi
            [ -f "/vol/work/out/$name.log" ] || { echo "$name: not run"; continue; }
            last=$(grep "^$name exit" /vol/work/out/results.txt | tail -1 || true)
            cov=$(grep -E "^#[0-9]+.*cov: " "/vol/work/out/$name.log" | tail -1 | sed -E "s/.*(cov: [0-9]+ ft: [0-9]+ corp: [^ ]+).*/\1/" || true)
            execs=$(grep "stat::number_of_executed_units" "/vol/work/out/$name.log" | tail -1 | awk "{print \$2}" || true)
            lastnew=$(grep -E "^#[0-9]+[[:space:]]+(NEW|REDUCE)" "/vol/work/out/$name.log" | tail -1 | awk "{print \$1}" || true)
            # Each extraction ends in "|| true": a log with no such line (a target stopped
            # before its first coverage line) must not end the report under pipefail.
            found=$(ls "/vol/work/artifacts/$name" 2>/dev/null | wc -l | tr -d " " || true)
            # Time counts per build (review M08-W1-R08(a)): runs of the current build, plus the
            # earlier runs /src/fuzz/accounting.txt declares equivalent to it (a line
            # "<build-id> <since-UTC> <reason>": unrecorded runs ending at or after that time).
            build=$(cut -d" " -f1 /vol/work/out/build-id 2>/dev/null || true)
            since=$(awk -v b="$build" "\$1 == b {print \$2}" /src/fuzz/accounting.txt 2>/dev/null | head -1)
            own=$(grep "^$name exit 0 .* build=$build\$" /vol/work/out/results.txt | sed -E "s/.*secs=([0-9]+).*/\\1/" | awk "{s+=\$1} END{print s+0}" || true)
            [ -n "$build" ] || own=0
            legacy=0
            if [ -n "$since" ]; then
                legacy=$(grep "^$name exit 0 " /vol/work/out/results.txt | grep -v " build=" | awk -v t="$since" "\$4 >= t" | sed -E "s/.*secs=([0-9]+).*/\\1/" | awk "{s+=\$1} END{print s+0}" || true)
            fi
            total=$((own + legacy))
            all=$(grep "^$name exit 0 " /vol/work/out/results.txt | sed -E "s/.*secs=([0-9]+).*/\\1/" | awk "{s+=\$1} END{print s+0}" || true)
            # Coverage (edges) when the last run had loaded its corpus, against its end: equal
            # means that run found no new coverage. The stopping rule is claimed only from a
            # last run of at least 1800 s with the two equal (ADR-0014 section 2.3).
            covinit=$(grep -E "^#[0-9]+[[:space:]]+INITED" "/vol/work/out/$name.log" | tail -1 | sed -E "s/.*cov: ([0-9]+).*/\\1/" || true)
            covend=$(grep -E "^#[0-9]+.*cov: " "/vol/work/out/$name.log" | tail -1 | sed -E "s/.*cov: ([0-9]+).*/\\1/" || true)
            # Features are recorded beside edges; the rule reads edges (ruled 2026-11-23).
            ftinit=$(grep -E "^#[0-9]+[[:space:]]+INITED" "/vol/work/out/$name.log" | tail -1 | sed -E "s/.* ft: ([0-9]+).*/\\1/" || true)
            ftend=$(grep -E "^#[0-9]+.*cov: " "/vol/work/out/$name.log" | tail -1 | sed -E "s/.* ft: ([0-9]+).*/\\1/" || true)
            newunits=$(grep "stat::new_units_added" "/vol/work/out/$name.log" | tail -1 | awk "{print \$2}" || true)
            lastsecs=$(echo "$last" | sed -E "s/.*secs=([0-9]+).*/\\1/")
            case "$lastsecs" in "" | *[!0-9]*) lastsecs=0 ;; esac
            rule="not met"
            if [ -n "$covinit" ] && [ "$covinit" = "$covend" ] && [ "${lastsecs:-0}" -ge 1800 ] && [ "${total:-0}" -ge 7200 ] && [ "$found" = 0 ]; then rule="met"; fi
            # The rule also needs the last run to be of the counted build.
            case "$last" in
                *" build=$build") ;;
                *" build="*) rule="not met" ;;
                *) echo "$last" | awk -v t="$since" "t == \"\" || \$4 < t {exit 1}" || rule="not met" ;;
            esac
            echo "$name: ${last#* } | counted ${total}s (this build ${own}s, declared earlier ${legacy}s; all runs ${all}s) | ${cov:-no coverage line} | execs ${execs:-?} | last new input at ${lastnew:-?} | last run cov ${covinit:-?} -> ${covend:-?}, ft ${ftinit:-?} -> ${ftend:-?}, new units ${newunits:-?} | findings $found | stopping rule: $rule"
            [ "$found" = 0 ] || bad=1
            case "$last" in *"exit 0 "*) ;; *) bad=1 ;; esac
        done
        [ ! -f /vol/work/out/fuzz-lock.sha256 ] || sed "s/^/fuzz lock sha256: /" /vol/work/out/fuzz-lock.sha256
        [ ! -f /vol/work/out/build-id ] || sed "s/^/build: /" /vol/work/out/build-id
        exit $bad
    '
    ;;
build-id)
    # For a build made before setup recorded its identity. The volume's copy of the sources
    # is the one that was built (setup is its only writer), so its digest is the build's.
    # An existing identity is never replaced.
    in_container none '[ ! -s /vol/work/out/build-id ] || { echo "run-campaign: build-id exists: $(cat /vol/work/out/build-id)" >&2; exit 2; }'
    in_container none "$BUILD_ID_SCRIPT"
    ;;
crashes)
    out=${2:-}; [ -n "$out" ] || { echo "run-campaign: crashes <dir>" >&2; exit 2; }
    mkdir -p "$out"
    docker run --rm --network none -v "$VOLUME":/vol:ro "$IMAGE" tar -C /vol/work -cf - artifacts | tar -C "$out" -xf -
    ;;
clean)
    docker volume rm "$VOLUME"
    ;;
*)
    sed -n '2,9p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
esac
