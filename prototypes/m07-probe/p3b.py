#!/usr/bin/env python3
"""M07 design probe P3b (disposable; never imported; docs/architecture/m07-plan.md §8).

P3 stopped at 3000 destinations because one import bundle is capped at 1 MiB
(`portable_cmd.rs` MAX_BUNDLE_FILE_BYTES). P3b grows the catalog with bundles of
2500 *new* destinations each until `inspect destinations` no longer fits one control
frame (ADR-0006 §2.2), records what the CLI (JSON and human) and the TUI show, and
measures TUI key latency at each size (debug build).

Same boundaries as probe.py: scratch HOME/HEIMDALL_HOME, cleared environment, no
SSH_AUTH_SOCK, `.invalid` host names never contacted, the runtime stopped by
`service stop` then by its exact PID only if still alive.

Usage: p3b.py <heimdall binary> <output json>
"""

import json
import os
import shutil
import signal
import subprocess
import sys
import time

sys.argv = [sys.argv[0], sys.argv[1], sys.argv[2]]
HERE = os.path.dirname(os.path.abspath(__file__))
SRC = open(os.path.join(HERE, "probe.py"), encoding="utf-8").read()
# Reuse probe.py's helpers without running its main().
SRC = SRC.replace('if __name__ == "__main__":\n    main()\n', "")
NS = {"__name__": "probe_helpers", "__file__": os.path.join(HERE, "probe.py")}
exec(compile(SRC, "probe.py", "exec"), NS)  # noqa: S102 (our own disposable script)

cli, Tui, pct, ms = NS["cli"], NS["Tui"], NS["pct"], NS["ms"]
SCRATCH, OUT = NS["SCRATCH"], NS["OUT"]
env = NS["env"]
BIN = NS["BIN"]
HOME = NS["HOME"]


def bundle_range(lo, hi, path):
    b = {
        "schema": "heimdall-portable/1",
        "created_at": "2026-11-21T00:00:00Z",
        "destinations": [
            {"id": "d%06d" % i, "alias": "host-%06d" % i,
             "hostname": "h%06d.example.invalid" % i, "account": "probe", "port": 22}
            for i in range(lo, hi)
        ],
    }
    with open(path, "w") as f:
        json.dump(b, f, separators=(",", ":"))
    return os.path.getsize(path)


def key_row(n, keys=12):
    screen_path = os.path.join(SCRATCH, "screen-%d.txt" % n)
    t = Tui(40, 120, {"HEIMDALL_TEST_TUI_SCREEN": screen_path})
    settled = t.wait_for(b"Runtime: connected", 90, screen_path)
    t.read_for(6)
    lat = [t.key_latency(b"\t" if i % 2 == 0 else b"\x1b[Z", limit=10.0) for i in range(keys)]
    got = [x for x in lat if x is not None]
    # Destinations tab: what does it show at this size?
    os.write(t.master, b"2")
    t.read_for(3)
    try:
        dest_screen = open(screen_path, encoding="utf-8").read().splitlines()
    except OSError:
        dest_screen = []
    code = t.quit()
    return {
        "catalog_destinations": n, "runtime_connected_ms": ms(settled),
        "key_samples": len(lat), "key_no_output": len(lat) - len(got),
        "key_p50_ms": ms(pct(got, 50)), "key_p95_ms": ms(pct(got, 95)),
        "key_max_ms": ms(max(got) if got else None), "quit_exit": code,
        "destinations_tab_head": [l.rstrip() for l in dest_screen[:4]],
        "destinations_tab_mentions_frame_limit": any("frame limit" in l for l in dest_screen),
    }


def main():
    result = {"binary": "target/debug/heimdall (debug build)", "rows": []}
    service = subprocess.Popen([BIN, "service", "run"], env=env(), cwd=HOME,
                               stdin=subprocess.DEVNULL,
                               stdout=open(os.path.join(SCRATCH, "service.log"), "wb"),
                               stderr=subprocess.STDOUT, start_new_session=True)
    try:
        for _ in range(100):
            if cli("--json", "service", "status")[0] == 0:
                break
            time.sleep(0.1)
        have = 0
        for hi in [1000, 3500, 6000, 8500, 11000]:
            path = os.path.join(SCRATCH, "b-%d.json" % hi)
            size = bundle_range(have, hi, path)
            ic, iout, _, _ = cli("--json", "import", path, "--yes", timeout=600)
            try:
                icode = json.loads(iout.decode().strip().splitlines()[-1]).get("code")
            except Exception:  # noqa: BLE001
                icode = None
            if ic == 0:
                have = hi
            c, out, err, dt = cli("--json", "inspect", "destinations")
            try:
                e = json.loads(out.decode().strip().splitlines()[-1])
                code_s = e.get("code")
                items = len((e.get("data") or {}).get("items") or [])
                msg = ((e.get("data") or {}).get("error") or {}).get("message")
            except Exception as ex:  # noqa: BLE001
                code_s, items, msg = "unparsed: %s" % ex, None, None
            hc, hout, herr, _ = cli("destination", "list")
            row = {
                "catalog_destinations": have, "bundle_bytes": size, "import_exit": ic,
                "import_code": icode, "inspect_exit": c, "inspect_code": code_s,
                "inspect_items": items, "inspect_stdout_bytes": len(out), "inspect_ms": ms(dt),
                "inspect_error_message": msg, "human_list_exit": hc,
                "human_list_stdout_lines": hout.count(b"\n"),
                "human_list_stderr_head": herr.decode(errors="replace")[:200],
            }
            if have in (1000, 3500) or c != 0:
                row["tui"] = key_row(have)
            result["rows"].append(row)
            if c != 0:
                break
    finally:
        sc = cli("service", "stop")[0]
        try:
            service.wait(15)
        except subprocess.TimeoutExpired:
            os.kill(service.pid, signal.SIGTERM)  # the exact PID this script started
            service.wait(10)
        result["service_stop_exit"] = sc
        result["service_exit"] = service.returncode
    shutil.rmtree(SCRATCH)
    result["scratch_removed"] = not os.path.exists(SCRATCH)
    with open(OUT, "w") as f:
        json.dump(result, f, indent=1)


main()
