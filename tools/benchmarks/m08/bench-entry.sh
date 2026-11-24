#!/usr/bin/env bash
# Container entry point of a benchmark run (m08-plan W2-3). Runs as root only to install the
# executable and start the world as the unprivileged account `soaks`.
# Usage: bench-entry.sh DESTINATIONS SAMPLES SETTLE_S IDLE_WINDOW_S IDLE_WINDOWS
#        (the archive's Linux executable at /a/heimdall, output at /out)
set -u
in_container() { [ -f /.dockerenv ] || [ -f /run/.containerenv ] || grep -qE '(docker|containerd|kubepods|libpod)' /proc/1/cgroup 2>/dev/null; }
in_container || { echo "refused: this runs only inside the M08 container (no container was detected)" >&2; exit 2; }
if env | grep -q '^HEIMDALL_TEST_'; then echo "refused: a HEIMDALL_TEST_* variable is set in the environment of a release run" >&2; exit 2; fi
mkdir -p /out/bench && chown soaks /out/bench
install -m 0755 /a/heimdall /usr/local/bin/heimdall-under-test
printf '{"container_started_at":"%s","kernel":"%s","arch":"%s","cpus_seen":%s,"mem_total_kib":%s,"binary_sha256":"%s"}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(uname -r)" "$(uname -m)" "$(nproc)" \
    "$(awk '/^MemTotal:/{print $2}' /proc/meminfo)" "$(sha256sum /a/heimdall | cut -d' ' -f1)" >/out/run.json
runuser -u soaks -- env ${BENCH_CAPTURE:+BENCH_CAPTURE=1} bash /src/tools/benchmarks/m08/bench-world.sh /usr/local/bin/heimdall-under-test /out/bench "$@" >/out/bench/world.log 2>&1
code=$?
printf '{"container_stopped_at":"%s","exit":%s}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$code" >/out/end.json
exit $code
