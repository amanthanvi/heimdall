#!/usr/bin/env bash
# Container entry point of a soak run (m08-plan U5a). Runs as root only to start one
# process per lane account; everything else runs unprivileged.
# Usage: entry.sh SECONDS SEED TICK [LANES]   (LANES: SL, S or L; the archive is at /a, output at /out)
set -u
# Refuse outside a container (review M08-W0-R08): this script installs into /usr/local/bin,
# starts an sshd and agents, and runs a release build. Only run-soak.sh's container runs it.
in_container() { [ -f /.dockerenv ] || [ -f /run/.containerenv ] || grep -qE '(docker|containerd|kubepods|libpod)' /proc/1/cgroup 2>/dev/null; }
in_container || { echo "refused: this runs only inside the M08 container (no container was detected)" >&2; exit 2; }
if env | grep -q '^HEIMDALL_TEST_'; then echo "refused: a HEIMDALL_TEST_* variable is set in the environment of a release run" >&2; exit 2; fi
seconds=$1; seed=$2; tick=$3; lanes=${4:-SL}
start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
mkdir -p /out/S /out/L && chown soaks /out/S && chown soakl /out/L
install -m 0755 /a/heimdall /usr/local/bin/heimdall-under-test
printf '{"container_started_at":"%s","planned_s":%s,"seed":%s,"tick_s":%s,"kernel":"%s","arch":"%s","binary_sha256":"%s"}\n' \
    "$start" "$seconds" "$seed" "$tick" "$(uname -r)" "$(uname -m)" "$(sha256sum /a/heimdall | cut -d' ' -f1)" >/out/run.json
ps=""; pl=""
case "$lanes" in *S*)
    runuser -u soaks -- bash /src/tools/benchmarks/m08/lane.sh S /usr/local/bin/heimdall-under-test /out/S "$seconds" "$seed" "$tick" >/out/S/lane.log 2>&1 &
    ps=$! ;;
esac
case "$lanes" in *L*)
    runuser -u soakl -- bash /src/tools/benchmarks/m08/lane.sh L /usr/local/bin/heimdall-under-test /out/L "$seconds" "$seed" "$tick" >/out/L/lane.log 2>&1 &
    pl=$! ;;
esac
# The runtime is non-dumpable, so its own account cannot list its descriptors. Root can:
# one line per runtime process per interval, for the analysis (ADR-0014 section 6.2 item 3).
(
    t0=$(date +%s)
    while [ ! -e /out/end.json ]; do
        for pair in soaks:S soakl:L; do
            for pid in $(pgrep -u "${pair%%:*}" -x heimdall 2>/dev/null); do
                n=$(ls "/proc/$pid/fd" 2>/dev/null | wc -l)
                printf '{"t":%s,"pid":%s,"fds":%s}\n' "$(( $(date +%s) - t0 ))" "$pid" "$n" >>"/out/${pair##*:}/root-samples.ndjson"
            done
        done
        sleep "$tick"
    done
) &
cs=0; cl=0
[ -z "$ps" ] || { wait "$ps"; cs=$?; }
[ -z "$pl" ] || { wait "$pl"; cl=$?; }
printf '{"container_stopped_at":"%s","lanes":"%s","lane_S_exit":%s,"lane_L_exit":%s}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$lanes" "$cs" "$cl" >/out/end.json
[ "$cs" = 0 ] && [ "$cl" = 0 ]
