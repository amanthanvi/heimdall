#!/usr/bin/env python3
"""Add a "round3" section (go and rust re-measurement) to tests/evidence/g02-measurements.json.

  HM_G02_CANDS=go,rust tests/g02/.venv/bin/python tools/benchmarks/g02/assemble_round3.py

Reads tests/evidence/artifacts/g02-measure/round3/{host-raw,host-summary,idle-long-raw,idle-long-summary}.json
(written by measure.py / idle_long.py via run_round3.sh).  The round-2 content of g02-measurements.json
(and therefore the frozen ts rows) is left untouched; the "round3" key is replaced on every run.
No measurement happens here, except gzip -9 of the already-verified artifact files (size only).
"""
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import g02bench as B  # noqa: E402

OUT = B.REPO / "tests" / "evidence" / "g02-measurements.json"
R3 = B.ART / "round3"
C = ["go", "rust"]


def jl(name):
    return json.loads((R3 / name).read_text())


def git(*a):
    return subprocess.run(["git", "-C", str(B.REPO)] + list(a), capture_output=True, text=True).stdout.strip()


def pick(d, keys):
    return {k: d.get(k) for k in keys}


def lat(d):
    return pick(d, ["n", "min", "p50", "p95", "max", "p50_ci95", "p95_ci95"])


def pct(a, b):
    return None if not a else round(100.0 * (b - a) / a, 1)


def gzip9_bytes(path):
    p = subprocess.run(["/usr/bin/gzip", "-9", "-n", "-c", str(path)], capture_output=True, check=True)
    return len(p.stdout)


LIMITS = [
    "Single machine (Apple M5 Max, 18 cores) shared with other workloads; no isolation was attempted. At the start the 1-minute load average was about 3.0-3.3 (background: a dev app near 25% of one core and a speech-to-text process near 22% of one core, which was still running at the start; nothing build- or test-heavy was running, so the run was not delayed). Load stayed about 1.5-5.1 through the run (load_summary, environment.load_per_pass). Round 2 ran at about 1.5-7. Numbers are comparable between candidates in this run; round-to-round differences of a few percent are within what this noise can produce.",
    "The pty control floor moved between rounds: control first-frame p50 was 4.3 / 4.0 ms (homelab / large-100) in round 2 and 6.3 / 5.7 ms in round 3, and the /usr/bin/true spawn floor was 2.26 ms in round 2 and 2.10 ms in round 3. The rust first-frame rise (+24% / +8.5% raw p50) is of the same size as the pty floor shift; the p50_minus_control_p50_ms rows show rust at 0.9 / 4.6 ms above the floor in round 3 versus 1.4 / 5.5 ms in round 2. Whether the pty floor shift is machine state or a measurement artifact of the 2-candidate rotation was not isolated.",
    "Because the candidate set is go, rust and control (3 members) instead of go, rust, ts and control (4 members), the round-robin neighbours and cache pressure differ from round 2; the method is otherwise unchanged (same scripts, same arguments, g02bench.CANDIDATES now honours HM_G02_CANDS).",
    "Latencies come from Python spawn plus a pyte terminal emulator, not a real terminal; the control rows show the spawn and pty floors. Keystroke latency has no control row. The go filter-typing p95 (about 16 ms) matches a 60 fps renderer tick; that explanation is an inference from round 2 and was not isolated. K17 (filter p95 <= 100 ms) is read here as the filter_type_ms p95 of this method (420 filter keystrokes per candidate: 60 sessions x 7 characters); this record is not a gate verdict.",
    "RSS is /usr/bin/time -l maximum resident set size (macOS bytes); not comparable to Windows working set or Linux RSS. The 300 s idle hold report max RSS of a process that also ran first frame.",
    "Idle CPU is a 300 s hold, 3 reps per candidate, via /usr/bin/time -l (10 ms CPU resolution), large-100 viewer only, darwin-arm64; it is not a product TUI with live connections. The 30 s per-pass estimate in per_pass_drift is coarse and kept for comparability only.",
    "go idle CPU (0.35% of one core, 1.04-1.06 s CPU per 300 s, roughly half user and half sys) is nonzero and not 0.0x%; round 2 gave 0.34%. Spec 15.1 target is < 0.5%: go sits at about 70% of that margin. The cause (a periodic tick versus other work) was not investigated here.",
    "Cold-first-exec rows compare the first execution of a freshly copied file with later ones (per_pass_drift); not a reboot-cold measurement.",
    "Only darwin-arm64 binaries were executed. linux and windows artifacts were hashed and sized only (sha256 verified against dist/manifest.json); no clean-environment, conformance, or Windows/Linux timing runs were part of this task. Windows artifacts were never run (blocked: no Windows host).",
    "Artifact sizes: exe bytes are raw; gzip9_exe_bytes is `gzip -9 -n` of the file; tar_gz9_bytes is the round-2 method (tar of the artifact directory, gzip level 9, mtime 0). All eight go/rust artifact sha256 differ from round 2 (rebuilt after rounds 3b/3c); sizes changed by 0-0.9%.",
    "Conformance status is not judged here; ts rows remain the frozen round-2 ones in the round-2 content of this file.",
]


def main():
    assert B.CANDIDATES == C, "run with HM_G02_CANDS=go,rust"
    old = json.loads(OUT.read_text())
    r2 = old["observed_result"]
    r2t = r2["tables"]
    raw = jl("host-raw.json")
    P = jl("host-summary.json")["pooled_across_passes"]
    meta = raw["meta"]
    idle = jl("idle-long-summary.json")
    idle_raw = jl("idle-long-raw.json")
    members = C + ["control"]

    tables = {
        "startup_version_json_ms": {m: lat(P["startup_version"][m]) for m in members},
        "startup_profile_show_large100_ms": {m: lat(P["startup_profile"][m]) for m in members},
        "tui_first_frame_ms_homelab_3_dest": {m: lat(P["tui_first_frame"]["homelab"][m]["ms"]) | {
            "failed": P["tui_first_frame"]["homelab"][m]["failed"],
            "first_byte_p50": P["tui_first_frame"]["homelab"][m]["ms_first_byte"].get("p50")} for m in members},
        "tui_first_frame_ms_large100": {m: lat(P["tui_first_frame"]["large"][m]["ms"]) | {
            "failed": P["tui_first_frame"]["large"][m]["failed"],
            "first_byte_p50": P["tui_first_frame"]["large"][m]["ms_first_byte"].get("p50")} for m in members},
        "tui_keystroke_to_update_ms_large100_all_keys": {c: lat(v["all_keys_ms"]) | {
            "sessions": v["sessions"], "failed_sessions": v["failed_sessions"],
            "j_move_p50_p95": [v["move_j_ms"]["p50"], v["move_j_ms"]["p95"]],
            "filter_type_p50_p95": [v["filter_type_ms"]["p50"], v["filter_type_ms"]["p95"]],
            "filter_type_n": v["filter_type_ms"]["n"],
            "filter_type_p95_ci95": v["filter_type_ms"].get("p95_ci95"),
            "to_first_output_byte_p50_p95": [v["all_keys_first_byte_ms"]["p50"], v["all_keys_first_byte_ms"]["p95"]]}
            for c, v in P["tui_keystroke_large100"].items()},
        "peak_rss_bytes_time_l": {
            ph: {m: {"p50": v["max_rss_bytes"]["p50"], "max": v["max_rss_bytes"]["max"], "n": v["max_rss_bytes"]["n"],
                     "peak_footprint_max": v["peak_footprint_bytes"]["max"]}
                 for m, v in P[k].items()}
            for ph, k in (("version", "rss_version"), ("profile_large100", "rss_profile_large"), ("tui_workload", "rss_tui_workload"))},
    }
    # the control floors, called out separately
    floors = {
        "startup_version_json_ms_control_usr_bin_true": lat(P["startup_version"]["control"]),
        "startup_profile_ms_control_usr_bin_true": lat(P["startup_profile"]["control"]),
        "tui_first_frame_ms_homelab_control_printf_via_pty": lat(P["tui_first_frame"]["homelab"]["control"]["ms"]),
        "tui_first_frame_ms_large100_control_printf_via_pty": lat(P["tui_first_frame"]["large"]["control"]["ms"]),
        "rss_version_control_bytes": tables["peak_rss_bytes_time_l"]["version"]["control"],
        "rss_profile_control_bytes": tables["peak_rss_bytes_time_l"]["profile_large100"]["control"],
        "note": "keystroke latency has no control row in measure.py (round 2 and 3 alike); the pty-path floor is the control first-frame row (control printf through the same pty path)",
    }

    per_pass = {}
    for p in jl("host-summary.json")["per_pass"]:
        s = p["summary"]
        per_pass["pass%d" % p["pass"]] = {
            "wall_s": p["wall_s"],
            "startup_version_p50_ms": {m: v["p50"] for m, v in s["startup_version"].items()},
            "startup_profile_p50_ms": {m: v["p50"] for m, v in s["startup_profile"].items()},
            "tui_first_frame_large_p50_ms": {m: v["ms"]["p50"] for m, v in s["tui_first_frame"]["large"].items()},
            "tui_keystroke_all_p50_ms": {c: v["all_keys_ms"]["p50"] for c, v in s["tui_keystroke_large100"].items()},
            "tui_keystroke_filter_p95_ms": {c: v["filter_type_ms"]["p95"] for c, v in s["tui_keystroke_large100"].items()},
            "tui_idle_extra_cpu_percent_of_one_core_est_30s": {c: v.get("extra_idle_cpu_percent_of_one_core_est") for c, v in s["tui_idle_cpu"].items()},
            "cold_first_exec_p50_ms": {c: {k: v[k].get("p50") for k in ("first_ms", "second_ms", "third_ms")} for c, v in s["cold_first_exec"].items()},
        }

    # artifacts: raw bytes, tar.gz-9 (round-2 method), plain gzip -9 of each file, sha256
    inv = meta["artifact_inventory_start"]
    artifacts = {}
    for c in C:
        artifacts[c] = {}
        for t in B.TARGETS:
            r = inv[c][t]
            files = []
            for f in r["files"]:
                files.append({"path": f["path"], "bytes": f["bytes"], "sha256": f["sha256"],
                              "gzip9_bytes": gzip9_bytes(B.artifact_dir(c, t) / f["path"])})
            artifacts[c][t] = {"exe_bytes": r["exe_bytes"], "sidecar_bytes": r["sidecar_bytes"], "total_bytes": r["total_bytes_on_disk"],
                               "gzip9_exe_bytes": next(f["gzip9_bytes"] for f in files if f["path"] == B.exe_name(t)),
                               "tar_gz9_bytes": r["tar_gz9_bytes"], "manifest_matches_disk": r["manifest_matches_disk"], "files": files}

    # comparison with round 2 (go, rust; ts is frozen and shown from round 2 only)
    def cmp_lat(name):
        out = {}
        for c in C:
            a, b = r2t[name][c], tables[name][c]
            out[c] = {"round2_p50_p95": [a["p50"], a["p95"]], "round3_p50_p95": [b["p50"], b["p95"]],
                      "p50_change_pct": pct(a["p50"], b["p50"]), "p95_change_pct": pct(a["p95"], b["p95"])}
        out["control_floor_round2_round3_p50"] = [r2t[name]["control"]["p50"], tables[name]["control"]["p50"]] if "control" in r2t[name] and "control" in tables[name] else None
        out["ts_round2_frozen_p50_p95"] = [r2t[name]["ts"]["p50"], r2t[name]["ts"]["p95"]]
        return out

    cmpt = {k: cmp_lat(k) for k in ("startup_version_json_ms", "startup_profile_show_large100_ms",
                                    "tui_first_frame_ms_homelab_3_dest", "tui_first_frame_ms_large100",
                                    "tui_keystroke_to_update_ms_large100_all_keys")}
    for name in ("tui_first_frame_ms_homelab_3_dest", "tui_first_frame_ms_large100", "startup_version_json_ms", "startup_profile_show_large100_ms"):
        f2, f3 = r2t[name]["control"]["p50"], tables[name]["control"]["p50"]
        cmpt[name]["p50_minus_control_p50_ms"] = {c: {"round2": round(r2t[name][c]["p50"] - f2, 3), "round3": round(tables[name][c]["p50"] - f3, 3)} for c in C}
    cmpt["tui_filter_typing_p50_p95"] = {c: {"round2": r2t["tui_keystroke_to_update_ms_large100_all_keys"][c]["filter_type_p50_p95"],
                                             "round3": tables["tui_keystroke_to_update_ms_large100_all_keys"][c]["filter_type_p50_p95"]} for c in C}
    cmpt["tui_filter_typing_p50_p95"]["ts_round2_frozen"] = r2t["tui_keystroke_to_update_ms_large100_all_keys"]["ts"]["filter_type_p50_p95"]
    cmpt["peak_rss_bytes_p50_max"] = {
        ph: {c: {"round2_p50_max": [r2t["peak_rss_bytes_time_l"][ph][c]["p50"], r2t["peak_rss_bytes_time_l"][ph][c]["max"]],
                 "round3_p50_max": [tables["peak_rss_bytes_time_l"][ph][c]["p50"], tables["peak_rss_bytes_time_l"][ph][c]["max"]],
                 "p50_change_pct": pct(r2t["peak_rss_bytes_time_l"][ph][c]["p50"], tables["peak_rss_bytes_time_l"][ph][c]["p50"])}
             for c in C} for ph in ("version", "profile_large100", "tui_workload")}
    r2art = r2["artifact_bytes_and_sha256"]
    cmpt["artifact_exe_bytes_and_sha256_by_target"] = {
        c: {t: {"round2_bytes": r2art[c][t]["exe_bytes"], "round3_bytes": artifacts[c][t]["exe_bytes"],
                "bytes_change_pct": pct(r2art[c][t]["exe_bytes"], artifacts[c][t]["exe_bytes"]),
                "round2_tar_gz9": r2art[c][t]["tar_gz9_bytes"], "round3_tar_gz9": artifacts[c][t]["tar_gz9_bytes"],
                "sha256_same_as_round2": ({f["path"]: f["sha256"] for f in r2art[c][t]["files"]} == {f["path"]: f["sha256"] for f in artifacts[c][t]["files"]})}
            for t in B.TARGETS} for c in C}
    r2idle = r2["idle_long_hold_300s"]["per_candidate"]
    cmpt["idle_cpu_300s_net_pct_of_one_core"] = {c: {"round2_mean_max": [r2idle[c]["net_pct_mean"], r2idle[c]["net_pct_max"]],
                                                     "round3_mean_max": [idle["summary"][c]["net_pct_mean"], idle["summary"][c]["net_pct_max"]]} for c in C}
    cmpt["idle_cpu_300s_net_pct_of_one_core"]["ts_round2_frozen_mean_max"] = [r2idle["ts"]["net_pct_mean"], r2idle["ts"]["net_pct_max"]]

    idle_long = {
        "method": "idle_long.py unchanged from round 2 (HM_G02_CANDS=go,rust): %d reps x 2 candidates, round-robin, start member rotated per rep; "
                  "per visit one %.0f s idle hold after the first large-100 frame and one %.0f s short hold under /usr/bin/time -l; "
                  "gross = idle cpu / idle real; net = (idle cpu - mean short cpu) / (idle real - mean short real)" % (
                      idle["meta"]["params"]["reps"], idle["meta"]["params"]["idle_s"], idle["meta"]["params"]["short_s"]),
        "params": idle["meta"]["params"], "order": idle["meta"]["order"], "started_at": idle["meta"]["started_at"],
        "finished_at": idle["meta"]["finished_at"], "artifact_sha256_unchanged": idle["meta"]["artifact_sha256_unchanged"],
        "load": [{k: v for k, v in l.items() if k in ("label", "at", "loadavg", "top_cpu_usage_sample2")} for l in idle_raw["meta"]["load"]],
        "per_candidate": idle["summary"], "spec_target_pct_of_one_core": 0.5,
    }

    load_before = (R3 / "load-before.txt").read_text() if (R3 / "load-before.txt").exists() else None
    sec = {
        "round": 3,
        "scope": "go and rust darwin-arm64 only, re-measured with the round-2 scripts and arguments after rounds 3b/3c changed their run/TUI code. "
                 "ts is frozen and was not re-measured: its rows stay in the round-2 content of this file. Artifacts are prototypes/{go,rust}/dist as found (not rebuilt), "
                 "sha256 verified against dist/manifest.json before the run (artifact_inventory_pre) and unchanged after it. "
                 "The only script change: g02bench.CANDIDATES honours HM_G02_CANDS (candidate subset); no method change. Because the subset has 2 candidates + control instead of 3 + control, "
                 "the round-robin neighbours differ from round 2.",
        "build_commit": git("rev-parse", "HEAD") + ("+dirty" if git("status", "--porcelain", "--", "prototypes", "tools", "tests/g02") else ""),
        "started_at": meta["started_at"], "finished_at": meta["finished_at"],
        "commands": ["tools/benchmarks/g02/run_round3.sh (HM_G02_CANDS=go,rust; measure.py --idle-s 30 --idle-reps 2 --out-dir .../round3; idle_long.py --idle-s 300 --reps 3 --out-dir .../round3)",
                     "HM_G02_CANDS=go,rust tests/g02/.venv/bin/python tools/benchmarks/g02/assemble_round3.py"],
        "params": meta["params"],
        "environment": {"host": pick(meta["hardware"], ["hw.model", "hw.memsize", "machdep.cpu.brand_string", "kern.osversion", "hw.ncpu", "uname", "sw_vers"]),
                        "load_before_run_snapshot": load_before,
                        "load_in_run": meta["load"], "load_per_pass": {("pass%d" % p["pass"]): p["load"] for p in raw["passes"]},
                        "power": meta["load"][0].get("pmset_batt_first_line"), "python": meta["python"], "run_env": meta["env_used"]},
        "artifact_sha256_unchanged_during_run": meta["artifact_inventory_end_sha_unchanged"],
        "artifact_inventory_pre": "tests/evidence/artifacts/g02-measure/round3/artifact-inventory-pre.json (manifest_matches_disk true for all 8 go/rust targets)",
        "tables": tables,
        "harness_floors_control_rows": floors,
        "comparison_round2_vs_round3": cmpt,
        "idle_long_hold_300s": idle_long,
        "per_pass_drift": per_pass,
        "artifact_bytes_and_sha256": artifacts,
        "evidence_paths": ["tests/evidence/artifacts/g02-measure/round3/" + n for n in (
            "host-raw.json", "host-summary.json", "idle-long-raw.json", "idle-long-summary.json", "artifact-inventory-pre.json",
            "measure-run.log", "idle-long-run.log", "run_round3.log", "load-before.txt")] + [
            "tools/benchmarks/g02/run_round3.sh", "tools/benchmarks/g02/assemble_round3.py", "tools/benchmarks/g02/g02bench.py"],
        "load_summary": {
            "one_minute_loadavg_min_max_over_all_captures": [min(l["loadavg"][0] for ps in raw["passes"] for l in ps["load"]),
                                                              max(l["loadavg"][0] for ps in raw["passes"] for l in ps["load"])],
            "idle_hold_one_minute_loadavg_min_max": [min(l["loadavg"][0] for l in idle_raw["meta"]["load"]), max(l["loadavg"][0] for l in idle_raw["meta"]["load"])],
            "cores": meta["hardware"].get("hw.ncpu")},
        "limitations": LIMITS,
    }
    old["round3"] = sec
    OUT.write_text(json.dumps(old, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("wrote round3 section to", OUT)


if __name__ == "__main__":
    main()
