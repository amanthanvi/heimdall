#!/usr/bin/env bash
# Build and run the fuzz targets inside one container (m08-plan U1a; ADR-0014 section 2.3).
#
# Usage: bash fuzz/run-campaign.sh setup              build the toolchain image state and every target
#        bash fuzz/run-campaign.sh run <seconds> [target...]   run targets (default: all), 2 at a time
#        bash fuzz/run-campaign.sh report             print each target's last result lines
#        bash fuzz/run-campaign.sh crashes <dir>      copy crash inputs out (they may be hostile bytes)
#        bash fuzz/run-campaign.sh clean              remove the container volume, by exact name
# Exit code: 0 on success; 1 when a build fails or a target reports a crash, hang or memory
# blow-up; 2 on a usage or setup error.
#
# What is pinned: the base image, the nightly toolchain, cargo-fuzz and libfuzzer-sys (PINS
# below and fuzz/Cargo.toml). The product's own toolchain pin is not touched: the nightly
# exists only in the volume this script creates.
# Where things live: the repository is mounted READ-ONLY. Sources are copied into the volume
# `hm-m08-fuzz` (cargo home, rustup home, a work copy, the build directory, the corpus). The
# checkout gets no build output. `setup` needs the network (toolchain and crates); `run`
# has none (--network none).
# Limits per container: 2 CPUs, 4 GiB memory (the Mac rule of 2026-11-22). Per input: 10 s,
# 1 GiB. Start every `setup` and `run` through /tmp/hm-tools/heavy-gate.sh, never beside
# another heavy job.
set -euo pipefail

IMAGE="debian:13-slim"
NIGHTLY="nightly-2026-11-15"
CARGO_FUZZ="0.13.2"
VOLUME="hm-m08-fuzz"
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)

# target:max_len (just above each boundary's own cap, ADR-0014 section 2.1)
TARGETS="sshconf_parse:1052672 gitedit_scan:1052672 agent_reply:266240 control_frame:1052672
signing_request:266240 userauth_request:70000 registry_hm1:70000 project_manifest:1052672 runtime_config:1052672
sshconf_eval:1052672 frame_codec:1052672 registry_line:1052672 issuer_protocol:1052672 issuer_backup:70000
known_hosts_match:70000"

command -v docker >/dev/null || { echo "run-campaign: docker not found" >&2; exit 2; }
in_container() { # NETWORK SCRIPT [ARGS...]
    local net=$1 script=$2; shift 2
    docker run --rm --network "$net" --cpus 2 --memory 4g --pids-limit 512 \
        -v "$repo":/src:ro -v "$VOLUME":/vol \
        -e CARGO_HOME=/vol/cargo -e RUSTUP_HOME=/vol/rustup -e CARGO_BUILD_JOBS=2 \
        -e NIGHTLY="$NIGHTLY" -e CARGO_FUZZ="$CARGO_FUZZ" -e TARGETS="$TARGETS" \
        "$IMAGE" bash -euo pipefail -c "$script" campaign "$@"
}

case "${1:-}" in
setup)
    docker volume create "$VOLUME" >/dev/null
    in_container bridge '
        export PATH=/vol/cargo/bin:$PATH
        apt-get update -qq >/dev/null
        apt-get install -y -qq --no-install-recommends ca-certificates curl build-essential >/dev/null
        if ! command -v rustup >/dev/null; then
            curl -fsS https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none >/dev/null
        fi
        rustup toolchain install "$NIGHTLY" --profile minimal >/dev/null
        cargo "+$NIGHTLY" install --locked --version "=$CARGO_FUZZ" cargo-fuzz >/dev/null 2>&1 || cargo "+$NIGHTLY" install --locked --version "=$CARGO_FUZZ" cargo-fuzz
        rm -rf /vol/work/src && mkdir -p /vol/work/src /vol/work/corpus /vol/work/out
        # The product toolchain file is deliberately not copied: it would select stable.
        cp -R /src/Cargo.toml /src/Cargo.lock /src/crates /src/fuzz /vol/work/src/
        cd /vol/work/src/fuzz
        rm -rf target && ln -s /vol/work/target target && mkdir -p /vol/work/target
        cp /src/fuzz/Cargo.lock Cargo.lock 2>/dev/null || true
        cargo "+$NIGHTLY" fuzz build
        echo "rustc: $(rustc "+$NIGHTLY" --version)"; echo "cargo-fuzz: $(cargo "+$NIGHTLY" fuzz --version)"
        sha256sum Cargo.lock | cut -d" " -f1 > /vol/work/out/fuzz-lock.sha256
    '
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
        run_one() {
            local name=${1%%:*} max=${1##*:}
            mkdir -p "/vol/work/corpus/$name" "/vol/work/artifacts/$name"
            [ -d "/src/fuzz/seeds/$name" ] && cp -n /src/fuzz/seeds/$name/* "/vol/work/corpus/$name/" 2>/dev/null || true
            local code=0
            cargo "+$NIGHTLY" fuzz run "$name" "/vol/work/corpus/$name" -- \
                -max_total_time="$secs" -timeout=10 -rss_limit_mb=1024 -max_len="$max" \
                -artifact_prefix="/vol/work/artifacts/$name/" -print_final_stats=1 \
                >"/vol/work/out/$name.log" 2>&1 || code=$?
            echo "$name exit $code $(date -u +%Y-%m-%dT%H:%M:%SZ) secs=$secs" >>/vol/work/out/results.txt
        }
        n=0
        for t in $TARGETS; do
            name=${t%%:*}
            if [ -n "$want" ] && ! echo " $want " | grep -q " $name "; then continue; fi
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
            [ -f "/vol/work/out/$name.log" ] || { echo "$name: not run"; continue; }
            last=$(grep "^$name exit" /vol/work/out/results.txt | tail -1)
            cov=$(grep -E "^#[0-9]+.*cov: " "/vol/work/out/$name.log" | tail -1 | sed -E "s/.*(cov: [0-9]+ ft: [0-9]+ corp: [^ ]+).*/\1/")
            execs=$(grep "stat::number_of_executed_units" "/vol/work/out/$name.log" | tail -1 | awk "{print \$2}")
            lastnew=$(grep -E "^#[0-9]+[[:space:]]+(NEW|REDUCE)" "/vol/work/out/$name.log" | tail -1 | awk "{print \$1}")
            found=$(ls "/vol/work/artifacts/$name" 2>/dev/null | wc -l | tr -d " ")
            echo "$name: ${last#* } | ${cov:-no coverage line} | execs ${execs:-?} | last new input at ${lastnew:-?} | findings $found"
            [ "$found" = 0 ] || bad=1
            case "$last" in *"exit 0 "*) ;; *) bad=1 ;; esac
        done
        cat /vol/work/out/fuzz-lock.sha256 2>/dev/null | sed "s/^/fuzz lock sha256: /"
        exit $bad
    '
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
