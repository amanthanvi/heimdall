#!/usr/bin/env python3
"""Assemble tests/evidence/g02-measurements.json from the raw files in tests/evidence/artifacts/g02-measure/.

  tests/g02/.venv/bin/python tools/benchmarks/g02/assemble.py

Reads host-raw.json, host-summary.json, clean-{darwin,linux,windows}.json, idle-long-summary.json (written by
measure.py, clean_env.py and idle_long.py) and, for the round-1 comparison and the reused ts clean runs,
round1/ and round1-record.json.  No measurement happens here; numbers are copied/derived from the raw files.
"""
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import g02bench as B  # noqa: E402

OUT = B.REPO / "tests" / "evidence" / "g02-measurements.json"


def jl(name):
    return json.loads((B.ART / name).read_text())


R1 = "round1/"


def git(*a):
    return subprocess.run(["git", "-C", str(B.REPO)] + list(a), capture_output=True, text=True).stdout.strip()


def pick(d, keys):
    return {k: d.get(k) for k in keys}


def main():
    raw = jl("host-raw.json")
    summ = jl("host-summary.json")
    cd, cl, cw = jl("clean-darwin.json"), jl("clean-linux.json"), jl("clean-windows.json")
    r1rec = jl("round1-record.json")
    r1cd, r1cl = jl(R1 + "clean-darwin.json"), jl(R1 + "clean-linux.json")
    idle = jl("idle-long-summary.json")
    idle_raw = jl("idle-long-raw.json")
    P = summ["pooled_across_passes"]
    meta = raw["meta"]
    inv = meta["artifact_inventory_start"]
    C = B.CANDIDATES

    def lat(d):
        return pick(d, ["n", "min", "p50", "p95", "max", "p50_ci95", "p95_ci95"])

    tables = {
        "startup_version_json_ms": {m: lat(v) for m, v in P["startup_version"].items()},
        "startup_profile_show_large100_ms": {m: lat(v) for m, v in P["startup_profile"].items()},
        "tui_first_frame_ms_homelab_3_dest": {m: lat(v["ms"]) | {"failed": v["failed"], "first_byte_p50": v["ms_first_byte"].get("p50")}
                                              for m, v in P["tui_first_frame"]["homelab"].items()},
        "tui_first_frame_ms_large100": {m: lat(v["ms"]) | {"failed": v["failed"], "first_byte_p50": v["ms_first_byte"].get("p50")}
                                        for m, v in P["tui_first_frame"]["large"].items()},
        "tui_keystroke_to_update_ms_large100_all_keys": {c: lat(v["all_keys_ms"]) | {
            "sessions": v["sessions"], "failed_sessions": v["failed_sessions"],
            "j_move_p50_p95": [v["move_j_ms"]["p50"], v["move_j_ms"]["p95"]],
            "filter_type_p50_p95": [v["filter_type_ms"]["p50"], v["filter_type_ms"]["p95"]],
            "to_first_output_byte_p50_p95": [v["all_keys_first_byte_ms"]["p50"], v["all_keys_first_byte_ms"]["p95"]]}
            for c, v in P["tui_keystroke_large100"].items()},
        "peak_rss_bytes_time_l": {
            ph: {m: {"p50": v["max_rss_bytes"]["p50"], "max": v["max_rss_bytes"]["max"], "n": v["max_rss_bytes"]["n"],
                     "peak_footprint_max": v["peak_footprint_bytes"]["max"]}
                 for m, v in P[k].items()}
            for ph, k in (("version", "rss_version"), ("profile_large100", "rss_profile_large"), ("tui_workload", "rss_tui_workload"))},
    }
    per_pass = {}
    for p in summ["per_pass"]:
        s = p["summary"]
        per_pass["pass%d" % p["pass"]] = {
            "wall_s": p["wall_s"],
            "startup_version_p50_ms": {m: v["p50"] for m, v in s["startup_version"].items()},
            "startup_profile_p50_ms": {m: v["p50"] for m, v in s["startup_profile"].items()},
            "tui_first_frame_large_p50_ms": {m: v["ms"]["p50"] for m, v in s["tui_first_frame"]["large"].items()},
            "tui_keystroke_all_p50_ms": {c: v["all_keys_ms"]["p50"] for c, v in s["tui_keystroke_large100"].items()},
            "tui_idle_extra_cpu_percent_of_one_core_est": {c: v.get("extra_idle_cpu_percent_of_one_core_est") for c, v in s["tui_idle_cpu"].items()},
            "tui_idle_raw_cpu_s": {c: {"idle_mean_s": v["idle_cpu_s"].get("mean"), "idle_n": v["idle_cpu_s"].get("n"),
                                       "short_mean_s": v["short_cpu_s"].get("mean"), "idle_real_mean_s": v["idle_real_s"].get("mean")}
                                   for c, v in s["tui_idle_cpu"].items()},
            "cold_first_exec_p50_ms": {c: {k: v[k].get("p50") for k in ("first_ms", "second_ms", "third_ms")} for c, v in s["cold_first_exec"].items()},
        }

    artifacts = {}
    for c in C:
        artifacts[c] = {}
        for t in B.TARGETS:
            r = inv[c][t]
            artifacts[c][t] = {"exe_bytes": r["exe_bytes"], "sidecar_bytes": r["sidecar_bytes"], "sidecars": r["sidecar_paths"],
                               "total_bytes": r["total_bytes_on_disk"], "tar_gz9_bytes": r["tar_gz9_bytes"],
                               "manifest_matches_disk": r["manifest_matches_disk"],
                               "files": [{"path": f["path"], "bytes": f["bytes"], "sha256": f["sha256"]} for f in r["files"]]}

    cd_c = dict(cd["candidates"])
    cd_c["ts"] = r1cd["candidates"]["ts"]            # ts artifacts unchanged since round 1 (sha verified below): reuse
    cl_runs = dict(cl["runs"])
    cl_runs.update({k: v for k, v in r1cl["runs"].items() if k.startswith("ts/")})
    cl_musl = dict(cl["musl_probe_alpine_arm64"]["results"])
    cl_musl["ts"] = r1cl["musl_probe_alpine_arm64"]["results"]["ts"]
    clean = {"darwin_arm64_env_i": {c: {v: {"checks_passed": sum(1 for k in x["checks"] if k["pass"]), "checks_total": len(x["checks"]),
                                            "files_created_in_fresh_TMPDIR": x["files_created_in_fresh_TMPDIR"],
                                            "files_created_in_fresh_HOME": x["files_created_in_fresh_HOME"],
                                            "files_created_in_fresh_cwd": x["files_created_in_fresh_cwd"]}
                                        for v, x in d["variants"].items()} | {"dynamic_libs": [l.split(" (")[0].strip() for l in d["otool_L"][1:]]}
                                    for c, d in cd_c.items()},
             "linux": {k: {"image_ref": v["image_ref"], "emulation": v["emulation"], "checks_passed": sum(1 for x in v["checks"] if x["pass"]),
                           "checks_total": len(v["checks"]), "new_files_after_setup": v["docker_diff_new_entries_after_setup"],
                           "ldd": v["ldd"][:6], "error": v.get("error")} for k, v in cl_runs.items()},
             "musl_probe_alpine_arm64": {c: {"rc": r.get("rc"), "stderr": r.get("stderr_head", "")[:120]} for c, r in cl_musl.items()},
             "reused_from_round1": ["ts darwin-arm64 (env -i, both variants)", "ts/linux-arm64", "ts/linux-x64", "ts musl probe"],
             "windows": {c: [{"path": f["path"], "bytes": f["bytes"], "file": f["file"]} for f in v["files"]] for c, v in cw["artifacts"].items()}}

    r1t = r1rec["observed_result"]["tables"]
    r1art = r1rec["observed_result"]["artifact_bytes_and_sha256"]

    def pct(a, b):
        return None if not a else round(100.0 * (b - a) / a, 1)

    def cmp_lat(name):
        out = {}
        for c in C:
            a, b = r1t[name][c], tables[name][c]
            out[c] = {"round1_p50_p95": [a["p50"], a["p95"]], "round2_p50_p95": [b["p50"], b["p95"]],
                      "p50_change_pct": pct(a["p50"], b["p50"]), "p95_change_pct": pct(a["p95"], b["p95"])}
        return out

    comparison = {k: cmp_lat(k) for k in ("startup_version_json_ms", "startup_profile_show_large100_ms",
                                          "tui_first_frame_ms_homelab_3_dest", "tui_first_frame_ms_large100",
                                          "tui_keystroke_to_update_ms_large100_all_keys")}
    comparison["peak_rss_bytes_p50_max"] = {
        ph: {c: {"round1_p50_max": [r1t["peak_rss_bytes_time_l"][ph][c]["p50"], r1t["peak_rss_bytes_time_l"][ph][c]["max"]],
                 "round2_p50_max": [tables["peak_rss_bytes_time_l"][ph][c]["p50"], tables["peak_rss_bytes_time_l"][ph][c]["max"]],
                 "p50_change_pct": pct(r1t["peak_rss_bytes_time_l"][ph][c]["p50"], tables["peak_rss_bytes_time_l"][ph][c]["p50"])}
             for c in C} for ph in ("version", "profile_large100", "tui_workload")}
    comparison["artifact_darwin_arm64_exe_bytes"] = {
        c: {"round1": r1art[c]["darwin-arm64"]["exe_bytes"], "round2": artifacts[c]["darwin-arm64"]["exe_bytes"],
            "change_pct": pct(r1art[c]["darwin-arm64"]["exe_bytes"], artifacts[c]["darwin-arm64"]["exe_bytes"])} for c in C}
    r1_idle30 = {("pass%d" % k): {c: r1rec["observed_result"]["per_pass_drift"]["pass%d" % k]["tui_idle_extra_cpu_percent_of_one_core_est"][c] for c in C} for k in (1, 2)}
    sha_same = {c: {t: ({f["path"]: f["sha256"] for f in r1art[c][t]["files"]} == {f["path"]: f["sha256"] for f in artifacts[c][t]["files"]})
                    for t in B.TARGETS} for c in C}
    idle_long = {
        "method": "idle_long.py: %d reps x 3 candidates, each rep visits the candidates round-robin with the start member rotated; "
                  "per visit one %.0f s idle hold after the first large-100 frame and one %.0f s short hold, both under /usr/bin/time -l; "
                  "gross = idle cpu / idle real, net = (idle cpu - mean short cpu) / (idle real - mean short real)" % (
                      idle["meta"]["params"]["reps"], idle["meta"]["params"]["idle_s"], idle["meta"]["params"]["short_s"]),
        "params": idle["meta"]["params"], "order": idle["meta"]["order"], "started_at": idle["meta"]["started_at"],
        "finished_at": idle["meta"]["finished_at"], "artifact_sha256_unchanged": idle["meta"]["artifact_sha256_unchanged"],
        "load": [{k: v for k, v in l.items() if k in ("label", "at", "loadavg", "top_cpu_usage_sample2")} for l in idle_raw["meta"]["load"]],
        "per_candidate": idle["summary"],
        "spec_target_pct_of_one_core": 0.5,
    }

    rec = {
        "case_id": "G02-measurements",
        "status": "verified",
        "requirement_ids": [],
        "build_commit": git("rev-parse", "HEAD") + ("+dirty" if git("status", "--porcelain", "--", "prototypes", "tools", "tests/g02") else ""),
        "artifact_digest": None,
        "environment": {
            "host": pick(meta["hardware"], ["hw.model", "hw.memsize", "machdep.cpu.brand_string", "kern.osversion", "hw.ncpu", "hw.perflevel0.logicalcpu", "hw.perflevel1.logicalcpu", "uname", "sw_vers"]),
            "load_before_after": meta["load"],
            "load_per_pass": {("pass%d" % p["pass"]): p["load"] for p in raw["passes"]},
            "power": meta["load"][0].get("pmset_batt_first_line"),
            "docker": cl["docker"], "images": {k: {"ref": v["reference_used"], "inspect": v["inspect"], "source_index": v["source_index"]} for k, v in cl["images"].items()},
            "python": meta["python"], "pyte": meta["pyte"], "pty": meta["pty_size"],
            "run_env": meta["env_used"],
        },
        "provider_versions": [{"name": "python", "version": meta["python"]}, {"name": "pyte", "version": "0.8.2"},
                              {"name": "docker", "version": cl["docker"]["version"]},
                              {"name": "/usr/bin/time", "version": "macOS BSD time -l"}],
        "started_at": raw["meta"]["started_at"].replace("Z", "+00:00"),
        "round": 2,
        "supersedes": "tests/evidence/artifacts/g02-measure/round1-record.json (round 1, started 2026-10-03T20:19:50Z)",
        "commands_or_harness": [
            "tests/g02/.venv/bin/python tools/benchmarks/g02/measure.py --idle-s 30 --idle-reps 2   (identical arguments to round 1; defaults: passes=2, warmup=10, n=100, rss-n=15, tui-n=30, key-sessions=30, cold-n=5)",
            "tests/g02/.venv/bin/python tools/benchmarks/g02/clean_env.py windows   (static facts, all three candidates)",
            "HM_G02_CANDS=go,rust tests/g02/.venv/bin/python tools/benchmarks/g02/clean_env.py darwin",
            "HM_G02_CANDS=go,rust tests/g02/.venv/bin/python tools/benchmarks/g02/clean_env.py linux",
            "tests/g02/.venv/bin/python tools/benchmarks/g02/idle_long.py --idle-s 300 --reps 3",
            "tests/g02/.venv/bin/python tools/benchmarks/g02/assemble.py",
            "tools/benchmarks/g02/run_round2.sh ran the steps above in sequence in one session (output logs in tests/evidence/artifacts/g02-measure/)",
        ],
        "observed_result": {
            "verdict": "pass",
            "verdict_scope": "criterion = comparable fresh G02 measurements for all three candidates with one methodology on this machine, and the distributable artifacts run in clean environments without each candidate's toolchain. "
                             "Windows artifacts were inspected statically only (native execution blocked). This is not a product-requirement verdict and not a selection of a candidate.",
            "methodology": {
                "interleaving": "round-robin over go, rust, ts and a no-op control; the starting member rotates every iteration; 2 independent passes (A then B) at different times",
                "startup": "subprocess spawn to exit wall time (perf_counter), stdout captured and checked after timing; 10 warmups then 100 samples per candidate per pass (200 pooled); control = /usr/bin/true",
                "rss": "/usr/bin/time -l, maximum resident set size (bytes, macOS) and peak memory footprint; 15 runs per candidate per pass after 1-2 warmups (30 pooled); TUI RSS covers first frame, 20 x j, '/' + 'host-05', Esc, q on large-100",
                "tui_first_frame": "launch (before Popen) until the pyte screen shows every alias and the N/M status (homelab 3/3; large-100 first 10 aliases and 100/100); arrival time of the chunk after which the predicate became true, pyte parse time excluded; 30 per pass; control = /usr/bin/printf through the same pty path",
                "tui_keystroke": "write of one key to chunk arrival that makes the expected screen state true: j moves selection to expected alias, filter characters make status line show typed text and expected N/100, Esc restores 100/100; 30 sessions per pass x (20 j + 7 filter chars + Esc); also time to first output byte",
                "tui_idle": "user+sys CPU from /usr/bin/time -l of a TUI held idle 30 s after first frame minus a 2 s hold, 2 runs per candidate per pass; time -l resolution is 10 ms so this is a coarse estimate (unchanged from round 1). Round 2 adds idle_long: 300 s holds, 3 reps per candidate, interleaved (see idle_long_hold_300s)",
                "cold_first_exec": "fresh copy of dist/darwin-arm64 to /tmp, version --json executed 3 times in a row (first execution of a freshly written file vs next two); not a reboot-cold measurement",
                "env": "PATH=/usr/bin:/bin, HOME/TMPDIR/cwd in a private /tmp sandbox, TERM=xterm-256color for TUI, no SSH_AUTH_SOCK; pty 80x24",
            },
            "round2_scope": "Round 2 re-measures all three darwin-arm64 artifacts in one session with the round-1 methodology (same scripts, same arguments) because the go and rust artifacts changed after round 1 (sha256 differs); ts artifacts are byte-identical to round 1 (see artifact_sha256_same_as_round1). Clean-environment darwin/linux runs were repeated for go and rust only; ts clean runs are reused from round 1 (clean_environment_runs.reused_from_round1). Windows static inspection was re-run for all three (cheap, static).",
            "artifact_sha256_same_as_round1": sha_same,
            "tables": tables,
            "comparison_round1_vs_round2": comparison,
            "tui_idle_30s_estimate_round1_pct_of_one_core": r1_idle30,
            "idle_long_hold_300s": idle_long,
            "per_pass_drift": per_pass,
            "artifact_bytes_and_sha256": artifacts,
            "artifact_sha256_unchanged_during_run": meta["artifact_inventory_end_sha_unchanged"],
            "clean_environment_runs": clean,
            "fake_agent_contact": {"darwin": cd["fake_agent_contact"], "linux": cl["fake_agent_contact"]},
            "windows": {"status": "blocked", "blocked_on": cw["blocked_on"]},
            "spec_15_1_context": "First useful TUI frame P95 <= 750 ms, key handling P95 <= 100 ms, idle RSS <= 150 MiB, idle CPU < 0.5% of a core (5-minute sample). "
                                 "These slice numbers cover a trivial local profile viewer, not the product, and do not settle those budgets.",
        },
        "evidence_paths": [
            "tools/benchmarks/g02/g02bench.py", "tools/benchmarks/g02/measure.py", "tools/benchmarks/g02/clean_env.py", "tools/benchmarks/g02/idle_long.py",
            "tools/benchmarks/g02/assemble.py", "tools/benchmarks/g02/run_round2.sh",
            "tests/evidence/artifacts/g02-measure/host-raw.json", "tests/evidence/artifacts/g02-measure/host-summary.json",
            "tests/evidence/artifacts/g02-measure/idle-long-raw.json", "tests/evidence/artifacts/g02-measure/idle-long-summary.json",
            "tests/evidence/artifacts/g02-measure/clean-darwin.json", "tests/evidence/artifacts/g02-measure/clean-linux.json",
            "tests/evidence/artifacts/g02-measure/clean-windows.json", "tests/evidence/artifacts/g02-measure/measure-run.log",
            "tests/evidence/artifacts/g02-measure/idle-long-run.log", "tests/evidence/artifacts/g02-measure/clean-darwin-run.log",
            "tests/evidence/artifacts/g02-measure/clean-linux-run.log", "tests/evidence/artifacts/g02-measure/clean-windows-run.log",
            "tests/evidence/artifacts/g02-measure/round1-record.json", "tests/evidence/artifacts/g02-measure/round1/",
        ],
        "limitations": [
            "Single machine (Apple M5 Max, 18 cores, macOS 27.0) shared with other agent workloads. Round-2 1-minute load average was about 6-7 of 18 cores at the start of pass 1 and about 1.5-2.6 for most of pass 2 and the idle hold (see environment.load_per_pass and idle_long_hold_300s.load); round 1 ran at about 4-10. The load differed between rounds and between passes, so small round-to-round differences (a few percent) are within what this noise can produce; no attempt was made to isolate the machine. Numbers are comparable between candidates and rounds here, not portable to other hardware.",
            "Latencies come from Python spawn plus a pyte terminal emulator, not a real terminal: a floor of about 2.2 ms (spawn) and 4.0-4.3 ms (pty path) is included, shown by the control rows. pyte answers only DA/DSR queries; a real terminal answers more capability queries, which could change the ts first-frame time.",
            "Keystroke latency excludes pyte parse time but includes pty and scheduler delay. The go filter-typing P95 of about 16 ms is consistent with a 60 fps renderer tick; that explanation is an inference and was not isolated.",
            "RSS uses /usr/bin/time -l (macOS rusage max RSS, bytes). It is not comparable to Windows working set or Linux RSS. Idle memory over time was not measured separately (the idle holds report max RSS of a process that also ran first frame).",
            "Idle CPU: the 300 s hold (3 reps per candidate, interleaved) is the spec 15.1 style 5-minute sample for the large-100 profile viewer only, on darwin-arm64, via /usr/bin/time -l (10 ms CPU resolution); it excludes the 2 s startup+first-frame CPU by subtracting a 2 s hold. It says nothing about a product TUI with a live agent connection, host probing, or file watching. The 30 s estimate in the main run is kept for round-1 comparability and is coarser.",
            "Cold-start in the spec sense (after reboot or purged page cache) was not measured; the cold_first_exec rows only compare the first run of a freshly copied file with later runs.",
            "linux-x64 ran emulated (linux/amd64 on an arm64 Docker Desktop VM; /proc/cpuinfo showed VirtualApple in round 1, which suggests Rosetta, an inference); it proves loading and behavior, not native x86-64 speed or behavior. Linux timings in the records are incidental, not benchmarks.",
            "Linux binaries were copied into containers with docker cp and run as root with --network none; the shared fake-agent socket used a docker volume. The TUI check ran through docker exec -it in a host pty.",
            "Native Windows execution blocked: no Windows host. Windows artifacts were inspected for file type, size, sha256 and PE headers only. Nothing about Windows named-pipe, console, or signal behavior is established.",
            "macOS: artifacts are ad-hoc signed only (not notarized); Gatekeeper/quarantine behavior for downloaded files was not tested. The writes check lists files in fresh TMPDIR/HOME/cwd only; writes elsewhere were not traced (no fs_usage/dtruss without privileges). Linux docker diff covers the whole container filesystem except mounted volumes.",
            "ts clean-environment runs (darwin, linux-arm64, linux-x64, musl probe) are reused from round 1, not re-run: the ts artifacts have identical sha256 to round 1 (artifact_sha256_same_as_round1). The ts timing rows were re-measured in round 2. The fake-agent contact counts for the round-2 darwin/linux clean runs cover go and rust only (4 connections each); the darwin note text inside clean-darwin.json still says 6 because it is a fixed string in clean_env.py.",
            "Conformance status is not judged here. The task packet states round-2 conformance: go 133p/0f/0e darwin and linux, rust 133p/0f/0e darwin and linux, ts darwin 126p/7f/0e and linux 127p/6f/0e; this record does not re-verify those counts, and ts timing rows were measured on a candidate that fails some conformance checks.",
            "Prototype REPORT.md numbers were not reused; all numbers here were measured fresh, from prototypes/*/dist as found (never rebuilt by this task).",
        ],
    }
    OUT.write_text(json.dumps(rec, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("wrote", OUT)


if __name__ == "__main__":
    main()
