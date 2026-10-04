#!/usr/bin/env python3
"""Run the shared G02 harness against reviewer mutations of the reference copy; summarise results."""
import json
import os
import subprocess
import sys
import time

REPO = "<repo>"
BIN = "/tmp/hm-review-mut/reference_impl.py"
OUT = "/tmp/hm-review-runs"

GEN = "usage.*,profile.*,version.*,common.*,canary.*"
MUTS = [
    # (name, scope, description)
    ("type_error_echoes_value", GEN, "revision/port error message quotes the offending value (serde-style 'invalid value: 70000')"),
    ("malformed_echo_source_line", GEN, "malformed TOML: stderr shows the source line(s) around the error (toml-crate style snippet)"),
    ("schema_version_warning_echoes_name", GEN, "unsupported-schema_version warning also quotes the value of `name`"),
    ("dup_check_quadratic", GEN, "duplicate id/alias detection uses lists (O(n^2) in the number of destinations)"),
    ("profile_tmp_hardcoded", GEN, "profile show writes a cache file to a hard-coded /tmp path (K11)"),
    ("agent_per_read_timeout", "agent.*,common.*,canary.*", "--timeout-ms restarts before every read (per-read socket timeout, not a total deadline)"),
    ("agent_default_timeout_60s", "agent.*,common.*,canary.*", "default timeout without --timeout-ms is 60 s instead of 5 s"),
    ("agent_nkeys_short_tolerated", "agent.*,common.*,canary.*", "nkeys within the bound but fewer keys in the frame: returns the keys present (AGENT_OK)"),
    ("agent_zero_frame_crash", "agent.*,common.*,canary.*", "reply frame of length 0 is indexed: IndexError traceback, exit 1"),
    ("agent_short_answer_crash", "agent.*,common.*,canary.*", "type-12 frame shorter than 5 bytes: struct.error traceback, exit 1"),
    ("agent_keyblob_inner_clamp", "agent.*,common.*,canary.*", "key-type string length inside key_blob exceeding the blob is clamped instead of rejected"),
    ("run_second_signal_exits", "run.*,common.*,canary.*", "a second SIGINT/SIGTERM makes heimdall-proto exit at once (force-quit), not waiting for the child"),
    ("run_pump_output", "run.*,common.*,canary.*", "child stdout/stderr are pipes copied byte-exactly by heimdall-proto (child loses the inherited fds / tty)"),
    ("run_child_new_session", "run.*,common.*,canary.*", "child started in a new session (setsid): no controlling terminal, /dev/tty unavailable"),
    ("run_meta_tmp_sibling", "run.*,common.*,canary.*", "--meta-file written via '<path>.tmp' which is left next to it (K11 write outside named paths)"),
    ("run_leaves_tty_raw", "run.*,common.*,canary.*", "when stdin is a tty, heimdall-proto puts it in raw mode for the child and never restores it"),
    ("tui_narrow_threshold_60", "tui.*,common.*,canary.*", "alias-only layout below 60 columns instead of below 50"),
    ("tui_slow_filter", "tui.*,common.*,canary.*", "each filter edit on a >50-destination profile takes 1.0 s"),
    ("tui_status_filter_only_while_typing", "tui.*,common.*,canary.*", "status line shows the active filter only while in filter mode (lost after Enter)"),
    ("tui_stty_absolute", "tui.*,common.*,canary.*", "TUI executes /bin/stty -g by absolute path at start (K16 helper process)"),
    ("tui_tmux_probe_by_term", "tui.*,common.*,canary.*", "TUI runs `tmux display-message` (PATH lookup) when TERM starts with tmux/screen (K16)"),
]


def main():
    only = set(sys.argv[1:])
    res = []
    for name, scope, desc in MUTS:
        if only and name not in only:
            continue
        rec = "%s/mut-%s.json" % (OUT, name)
        art = "%s/mut-%s-art" % (OUT, name)
        env = dict(os.environ, REV_MUTATE=name)
        env.pop("SSH_AUTH_SOCK", None)
        t0 = time.monotonic()
        p = subprocess.run([sys.executable, "tests/g02/conformance.py", "--bin", BIN, "--candidate", "go", "--out", rec,
                            "--artifacts-dir", art, "--pass-env", "REV_MUTATE", "--selftest", "--only", scope],
                           cwd=REPO, env=env, capture_output=True, text=True)
        dt = time.monotonic() - t0
        failing = []
        try:
            r = json.load(open(rec))
            for c in r["observed_result"]["checks"]:
                if c["outcome"] != "pass":
                    failing.append({"id": c["id"], "outcome": c["outcome"],
                                    "first": (c["failed_assertions"] or [c.get("error") or ""])[0][:140]})
            summary = r["observed_result"]["summary"]
        except Exception as exc:  # noqa
            summary = {"error": repr(exc)}
        row = {"mutation": name, "description": desc, "scope": scope, "exit_code": p.returncode,
               "caught": p.returncode != 0 and bool(failing), "failing_checks": failing, "summary": summary,
               "seconds": round(dt, 1)}
        res.append(row)
        print("%-38s exit=%d caught=%s %s" % (name, p.returncode, row["caught"], [f["id"] for f in failing][:4]),
              flush=True)
    path = "%s/mutation-results%s.json" % (OUT, ("-" + "-".join(sorted(only))) if only else "")
    with open(path, "w") as fh:
        json.dump(res, fh, indent=1, ensure_ascii=False)
    print("written", path)


if __name__ == "__main__":
    main()
