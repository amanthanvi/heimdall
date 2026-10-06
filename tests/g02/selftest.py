#!/usr/bin/env python3
"""Prove the G02 harness against tests/g02/reference_impl.py (contract section 9 incl. 9.1, 9.2, the round-3
rulings of 9.3: K6d, K6e, K17, K18, K10 exit form, and the round-3c rulings of 9.4: K6e child-initiated stop,
K12 closed stdout).

1. Baseline: the full harness run against the unmutated reference must exit 0 with every check passing.
2. Mutations: every defect in reference_impl.MUTATIONS is injected via REF_MUTATE and the relevant
   check groups are run; each run must exit 1 with at least one failing check, and a mutation listed in
   INTENDED must be caught by the check(s) written for it, not merely by some check.
3. Harness mutations (HARNESS_MUTATIONS): defects injected into the harness itself through
   HM_G02_HARNESS_MUTATE (accepted only with --selftest).  The final canary self-check must fire: exit 3,
   and the record and artifacts on disk hold no full canary value afterwards.
4. --repeat-baseline N: N further full baseline runs; a check that is not 'pass' in every run is reported
   as flaky (and fails the self-test).
5. Platform-gated mutations (PLATFORM_GATED): a defect that only shows where the kernel produces the
   condition: K3a (ECONNRESET on an AF_UNIX stream; Darwin never does) and a back-to-back double signal
   forward (standard signals do not queue; where the kernel merges them, harness.signal_duplicate_probe
   says so).  Such a mutation is run everywhere; where the record shows the condition is not producible
   it is reported "not observable here" and must be caught on the other platform instead.
6. Linux (K13): --linux runs this same self-test inside the digest-pinned linux/arm64 container via
   tests/g02/linux/run.sh --selftest (full catalogue baseline, every mutation, harness mutations) and
   merges its results; --linux-results FILE merges an earlier run's selftest-linux.json.  On Darwin the
   self-test cannot PASS without a Linux result.
7. Every record, artifact and the generated report are scanned for full canary values.
8. Conforming variants (reference_impl.VARIANTS, CONFORMING below): behaviour a section 9 ruling explicitly
   allows (for example K10 exit form: dying of the re-raised signal).  Each is injected like a mutation, but
   the run must PASS (exit 0, every check in scope passes): the harness must not reject allowed behaviour.
9. Blame (INTENDED_FIRST_ASSERTION): for some mutations the intended check must fail with a specific FIRST
   failing assertion, so the defect is attributed to the right step (K6e late re-stop after `fg`; K6e child
   self-stop not reported versus `fg` not resuming the child; K12 closed-stdout error results: the first
   failing assertion must be the first error-result case, not a success-result case).
10. Observation mutations (OBSERVED): defects in non-gating observations (K6c, Q16, the section 9.4 SIGSTOP form;
   K12 error results were observed here until harness 2.4.2 and are gated since the Q17 ruling) - the run may
   pass, but the record's observation must show the defect and the
   baseline's must not.
12. Race mutations (RACE): a defect that shows only through a scheduling race the harness cannot force (harness
   2.4.1: run_mirror_nograce, the round-4 review's rv_nograce).  It is run and its result is reported, but it is
   NOT required to be caught; the README says why and the question is escalated.
11. Harness/environment faults (HARNESS_EXPECT): injected through HM_G02_HARNESS_MUTATE; a failed harness
   precondition must give outcome 'error' (invalid evidence), never 'fail'; a non-gating probe's precondition
   must not affect the gated check; a re-injected emulator defect must make the dependent checks fail.

  selftest.py [--out tests/g02/SELFTEST.md] [--json-out FILE] [--workdir DIR] [--only m1,m2]
              [--repeat-baseline N] [--linux [--linux-args "..."] | --linux-results FILE]
Exit code 0 only if every baseline passes and every mutation is caught (on every required platform).
"""
import argparse
import datetime
import json
import os
import platform
import re
import shlex
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

CANARY_VALUE_RE = re.compile(rb"HEIMDALL_CANARY_[A-Za-z0-9]")

GENERIC = ("canary_echo", "wrong_exit_schema", "ignore_oversize", "oversize_off_by_one", "sort_destinations",
           "port_default_wrong", "meta_echo", "stdout_extra_newline", "usage_json_missing", "usage_plain_stdout",
           "stray_write", "schema_version_no_warning", "accept_bool_revision", "profile_control_chars_ok",
           "profile_c1_ok", "profile_label_control_ok", "profile_meta_control_rejected", "plain_exit_wrong",
           "stray_tmp_write", "type_error_echoes_value", "malformed_echo_source_line",
           "schema_version_warning_echoes_name", "stderr_echoes_value")

# mutations whose code path is reached from more than one group
SCOPE_OVERRIDE = {
    "nonregular_file_accepted": "profile.*,tui.non_regular_file,common.*,canary.*",
    "parser_deep_crash": "profile.*,tui.parser_resource_bound,common.*,canary.*",
    "parser_deep_slow": "profile.*,tui.parser_resource_bound,common.*,canary.*",
    "parser_deep_memory": "profile.*,tui.parser_resource_bound,common.*,canary.*",
    "version_tput_probe": "version.*,common.*,canary.*",
    "run_double_signal": "harness.signal_duplicate_probe,run.*",
    "run_meta_tmp_left": "run.*,common.*,canary.*",
    # K12 closed stdout (section 9.4): the defect is in the shared output path of version/profile/agent
    "plain_epipe_exit1": "version.*,common.*,k12.*,canary.*",
    "plain_epipe_sigpipe": "version.*,common.*,k12.*,canary.*",
    # round 7 (M00-T05-harness-r4-fix) / 2.4.2: K12 error results on a closed stdout (gating since Q17)
    "json_error_epipe_exit1": "k12.*,common.*,canary.*",
    "json_error_sigpipe": "k12.*,common.*,canary.*",
    # a race the harness cannot force: only the K6e Ctrl-Z/fg check can show it (RACE below)
    "run_mirror_nograce": "run.k6e_job_control",
}

# mutation -> the check(s) written for it; the self-test requires that THESE checks fail
INTENDED = {
    "profile_control_chars_ok": "profile.control_chars_rejected",
    "profile_c1_ok": "profile.control_chars_rejected",
    "profile_label_control_ok": "profile.control_chars_rejected",
    "profile_meta_control_rejected": "profile.control_chars_in_meta_ok",
    "plain_exit_wrong": "common.exit_codes_without_json",
    "stray_tmp_write": "common.no_stray_writes",
    "stray_write": "common.no_stray_writes",
    "agent_control_passthrough": "agent.control_chars_sanitized",
    "agent_c1_passthrough": "agent.control_chars_sanitized",
    "agent_keytype_unsanitized": "agent.control_chars_sanitized",
    "agent_keytype_strict": "agent.control_chars_sanitized",
    "agent_eof_as_protocol": ["agent.eof_before_reply", "agent.reset_before_reply"],
    "agent_partial_eof_unavailable": ["agent.eof_after_partial_header", "agent.reset_after_partial_header"],
    "agent_reset_unhandled": ["agent.reset_before_reply", "agent.reset_after_partial_header"],
    "agent_failure_payload_refused": "agent.failure_with_payload",
    "run_meta_state_by_exit": "run.meta_state",
    "run_meta_launch_state_ok": "run.meta_state",
    "run_argv_lossy": "run.argv_invalid_utf8",
    "run_tty_no_forward": "run.explicit_signal_with_tty",
    "run_takes_foreground": ["run.k6a_pipeline_peer_not_stopped", "run.k6a_background_script_tty"],
    "run_forward_ignored": "run.k6a_inherited_ignore",
    "run_reset_ignored_in_child": "run.k6a_inherited_ignore",
    "nonregular_file_accepted": ["profile.non_regular_file", "tui.non_regular_file"],
    "parser_deep_crash": ["profile.parser_resource_bound", "tui.parser_resource_bound"],
    "parser_deep_slow": ["profile.parser_resource_bound", "tui.parser_resource_bound"],
    "parser_deep_memory": ["profile.parser_resource_bound", "tui.parser_resource_bound"],
    "version_tput_probe": "common.no_helper_processes",
    "tui_tmux_probe": "common.no_helper_processes",
    "tui_filter_keeps_selection": "tui.filter_edit_resets_selection",
    "tui_backspace_keeps_selection": "tui.filter_edit_resets_selection",
    "tui_esc_keeps_selection": "tui.filter_edit_resets_selection",
    "tui_sigterm_exit0": "tui.sigterm_restores_terminal",
    "tui_sigterm_prints": "tui.sigterm_restores_terminal",
    "tui_sighup_unhandled": "tui.sighup_exit_129",
    "tui_hangup_exit130": "tui.hangup_exit_129",
    "tui_stray_home_write": "common.no_stray_writes",
    "tui_stderr_canary": "canary.no_canary_anywhere",
    # round 3 (M00-T05-harness-r2-fix): defects the round-2 harness passed
    "type_error_echoes_value": ["profile.error_value_not_echoed", "profile.invalid_port"],
    "malformed_echo_source_line": "profile.error_value_not_echoed",
    "schema_version_warning_echoes_name": ["profile.error_value_not_echoed", "profile.invalid_schema_version"],
    "agent_zero_frame_crash": "agent.malformed_zero_length_frame",
    "agent_short_answer_crash": ["agent.malformed_answer_type_only", "agent.malformed_answer_short"],
    "agent_nkeys_short_ok": "agent.malformed_nkeys_short",
    "agent_per_read_timeout": "agent.timeout_whole_response",
    "agent_default_timeout_60s": "agent.timeout_default_5000",
    "run_second_signal_force_quit": ["run.repeated_signals", "run.explicit_signal_with_tty"],
    "run_pipe_stdio": "run.stdio_inherited",
    "run_meta_tmp_left": "common.no_stray_writes",
    "tui_term_probe": "common.no_helper_processes",
    "tui_narrow_threshold_60": "tui.resize_narrow_hides_host",
    # round 4 (M00-T05-harness-r3, contract section 9.3): gaps found by the round-2 prototype reviews
    "run_shared_drop": "run.k6d_shared_mode_explicit_signals",
    "run_fg_restop": "run.k6e_job_control",
    "tui_slow_filter": "tui.large_100_filter_latency",
    "stderr_echoes_value": ["profile.error_value_not_echoed", "profile.invalid_port"],
    # round 5 (M00-T05-harness-r3-fix): defects the round-3 harness passed (independent review rv_*)
    "tui_rows_lag": "tui.large_100_filter_latency",
    "tui_slow_first_filter_key": "tui.large_100_filter_latency",
    "run_fg_restop_late": "run.k6e_job_control",
    # round 6 (M00-T05-harness-r4, contract section 9.4): the round-3b review findings the 2.3.0 harness passed
    "run_ignore_child_stop": "run.k6e_child_self_stop",
    "run_child_stop_no_continue": "run.k6e_child_self_stop",
    "plain_epipe_exit1": "k12.closed_stdout_exit_parity",
    "plain_epipe_sigpipe": "k12.closed_stdout_exit_parity",
    # round 7 (M00-T05-harness-r4-fix): the round-4 harness review's missed mutations
    "run_mirror_killpg": "run.k6a_child_self_stop_not_spread",
    # harness 2.4.2 (M00-T05-harness-q17): the Q17 ruling makes K12 closed-stdout error results gating
    "json_error_epipe_exit1": "k12.closed_stdout_exit_parity",
    "json_error_sigpipe": "k12.closed_stdout_exit_parity",
}

# mutation -> (check id, text of the assertion that must be the FIRST failing gating assertion of that check):
# the defect must be blamed on the right step, not merely caught later by some other assertion
INTENDED_FIRST_ASSERTION = {
    "run_fg_restop_late": ("run.k6e_job_control", "the job is not stopped again after `fg`: no 'Stopped' notice and "
                                                  "the child is not stopped from the `fg` until the next step"),
    # K6e child-initiated stop: the stop is never reported (the Rust round-3b defect) ...
    "run_ignore_child_stop": ("run.k6e_child_self_stop", "stop 1: the shell reports the job stopped ('Stopped') and "
                                                         "prompts again, with no user action"),
    # ... or it is reported, but `fg` never resumes the child
    "run_child_stop_no_continue": ("run.k6e_child_self_stop", "stop 1: `fg` resumes the child"),
    # K12 closed stdout, error results (Q17): the three success-result cases pass, so the first failing assertion is
    # the first error-result case (profile show of a missing file)
    "json_error_epipe_exit1": ("k12.closed_stdout_exit_parity",
                               "[profile-missing] error result, stdout closed by its reader: the wait status "
                               "without --json equals the one with --json"),
    "json_error_sigpipe": ("k12.closed_stdout_exit_parity",
                           "[profile-missing] error result, stdout closed by its reader: the wait status "
                           "without --json equals the one with --json"),
}

# mutations of non-gating observations (K6c): the run need not fail, but the record's observation must show the
# defect and the baseline's must not.  name -> (description of the expectation, extractor, predicate on the value)
# An optional 4th element condenses the observation for the report (default: the whole value, shortened).
def _k6es_form(name):
    return lambda obs: ((obs.get("k6e_child_self_stop") or {}).get(name) or {})


def _k6es_resumed_flags(v):
    return [st.get("resumed_before_fg") for job in v.get("jobs") or [] for st in job.get("stops") or []]


OBSERVED = {
    "run_child_sigpipe_ignored": (
        "observations.k6c_other_inherited_signal_state['sigpipe-non-python'].classification == 'child_always_ignores' "
        "and inherited_sigpipe_ignore_kept is false (harness 2.2.0 reported kept=true)",
        lambda obs: ((obs.get("k6c_other_inherited_signal_state") or {}).get("sigpipe-non-python") or {}),
        lambda v: v.get("classification") == "child_always_ignores" and v.get("inherited_sigpipe_ignore_kept") is False,
        lambda v: {k: v.get(k) for k in ("classification", "inherited_sigpipe_ignore_kept")}),
    # round 7 (M00-T05-harness-r4-fix): the round-4 harness review's missed mutations whose defect section 9.4 / Q16
    # leave non-gating
    "run_cont_child_first": (
        "observations.k6e_child_self_stop['bash-SIGTSTP'] shows resumed_before_fg true for a self-stop (Q16, recorded "
        "not gated; harness 2.4.0 recorded it but the self-test did not require it)",
        _k6es_form("bash-SIGTSTP"),
        lambda v: any(x is True for x in _k6es_resumed_flags(v)),
        lambda v: {"resumed_before_fg": _k6es_resumed_flags(v)}),
    "run_mirror_tstp_only": (
        "observations.k6e_child_self_stop['bash-SIGSTOP'] fails at 'the shell reports the job stopped' (section 9.4 "
        "records SIGSTOP, not gated)",
        _k6es_form("bash-SIGSTOP"),
        lambda v: v.get("ok") is False and not v.get("not_run")
        and "the shell reports the job stopped" in str((v.get("first_failed_step") or {}).get("desc") or ""),
        lambda v: {"ok": v.get("ok"), "not_run": v.get("not_run"),
                   "first_failed_step": str((v.get("first_failed_step") or {}).get("desc") or "")[:110]}),
}

# race mutations: run and reported, NOT required to be caught (see the module docstring, item 12, and the README)
RACE = {
    "run_mirror_nograce": "K6e: a stale child stop report mirrored without the 200 ms grace re-stops the job after "
                          "`fg` only in a scheduling race (inferred: the launcher stopped between reading 'still "
                          "stopped' and stopping itself); darwin-arm64 2026-10-05 "
                          "(selftest-results/2026-10-05-r7/nograce-experiments): 0/15 Ctrl-Z/fg cycles in each of six "
                          "bash -i variants, idle and under 18 CPU burners, 0/12 killpg cycles; harness 2.4.0's stress "
                          "record: 2 re-stops in 160 cycles under 20 burners",
}

# conforming variant -> the --only scope whose checks must all PASS with the variant injected
CONFORMING = {
    "tui_reraise_signal": "tui.sigterm_restores_terminal,tui.sighup_exit_129,tui.hangup_exit_129",
    "tui_filter_70ms": "tui.large_100_filter_latency",
    "run_job_control_own_group": "run.*",
    "closed_stdout_sigpipe_both": "version.*,common.*,k12.*,canary.*",
    # round 7 (M00-T05-harness-r4-fix): the round-4 harness review's conforming controls
    "run_mirror_sigstop_always": "run.*",
    "run_mirror_delay_1s": "run.*",
}

# harness mutations that are not canary leaks: an injected harness/environment fault and the check outcomes it
# must produce (precondition failures are 'error' = invalid evidence, never 'fail' = candidate failure; a re-injected
# emulator defect must make the checks that depend on it fail).  name -> (description, scope, {check: outcome},
# required verdict, optional (extractor, predicate) on observations)
HARNESS_EXPECT = {
    "k6d_env_not_shared": (
        "K6d: the job that contains heimdall-proto is reported as not holding the terminal foreground (simulated "
        "layout failure; harness 2.2.0 recorded it as a non-gating observation and the check passed on delivery alone)",
        "run.k6d_shared_mode_explicit_signals", {"run.k6d_shared_mode_explicit_signals": "error"}, "inconclusive", None),
    "bash_no_job_control": (
        "K6e: bash reports 'no job control' (simulated broken environment; harness 2.2.0 recorded the precondition as a "
        "gating assertion, outcome 'fail')",
        "run.k6e_job_control", {"run.k6e_job_control": "error"}, "inconclusive", None),
    "k6c_probe_no_yes": (
        "K6c SIGPIPE probe: no `yes` on PATH (simulated; harness 2.2.0 failed the gated K6a check through t.require for a "
        "non-gating probe)",
        "run.k6a_inherited_ignore", {"run.k6a_inherited_ignore": "pass"}, "inconclusive",
        (lambda obs: ((obs.get("k6c_other_inherited_signal_state") or {}).get("sigpipe-non-python") or {}),
         lambda v: v.get("classification") == "probe_invalid")),
    "k6es_control_no_stop": (
        "K6e child-initiated stop: the direct-exec control child does not stop itself (simulated: it sends itself "
        "SIGWINCH instead of SIGTSTP); the control is a harness precondition, so the check must be 'error', never 'fail'",
        "run.k6e_child_self_stop", {"run.k6e_child_self_stop": "error"}, "inconclusive", None),
    "emulator_no_scroll": (
        "pty emulator without SU/SD (stock pyte 0.8.2, harness defect (g)): the reference TUI scrolls with SU/SD, "
        "so the K17 row check and the emulator regression check must fail",
        "tui.large_100_filter_latency,harness.screen_scroll_region",
        {"tui.large_100_filter_latency": "fail", "harness.screen_scroll_region": "fail"}, "fail", None),
}

# defects injected into the harness itself (HM_G02_HARNESS_MUTATE): the canary self-check must fire
HARNESS_MUTATIONS = {
    "canary_in_desc": ("assertion text names a fixture canary by value (the round-1 defect)",
                       "profile.invalid_forbidden_key,canary.*"),
    "canary_in_artifact": ("an artifact is written without redaction and holds the per-run env canary",
                           "profile.invalid_forbidden_key,canary.*"),
}

# mutation -> (observation key in the record, predicate): can this host produce the condition?
PLATFORM_GATED = {
    # K3a: Darwin delivers an AF_UNIX reset as EOF
    "agent_reset_unhandled": ("k3a_reset_delivery",
                              lambda v: bool(v) and all(x == "ECONNRESET" for x in v.values())),
    # K6: standard signals do not queue; where the kernel merges two back-to-back kill() calls the double
    # forward is not observable (harness.signal_duplicate_probe)
    "run_double_signal": ("harness_os_probe_back_to_back_signal_merge",
                          lambda v: bool(v) and v.get("duplicates_observable") is True),
}


def intended_of(name):
    v = INTENDED.get(name)
    return [] if v is None else ([v] if isinstance(v, str) else list(v))


def scope_for(name):
    if name in SCOPE_OVERRIDE:
        return SCOPE_OVERRIDE[name]
    if name in GENERIC:
        return "usage.*,profile.*,version.*,common.*,canary.*"
    if name.startswith("agent_"):
        return "agent.*"
    if name.startswith("run_"):
        return "run.*"
    if name.startswith("version_"):
        return "version.*"
    if name.startswith("tui_"):
        return "tui.*,common.*,canary.*"
    raise SystemExit("no scope for mutation %s" % name)


def container_extra():
    """Inside the Linux runner (run.sh --selftest) the image metadata arrives via HM_G02_* variables."""
    if not os.environ.get("HM_G02_IMAGE"):
        return None
    return {"container": {"runner": "tests/g02/linux/run.sh --selftest", "image_ref": os.environ["HM_G02_IMAGE"],
                          "image_id": os.environ.get("HM_G02_IMAGE_ID"), "base_image": os.environ.get("HM_G02_BASE"),
                          "image_packages": os.environ.get("HM_G02_PKGS", "").split(),
                          "docker_server": os.environ.get("HM_G02_DOCKER"), "network": "none",
                          "user": "%d:%d" % (os.getuid(), os.getgid())}}


def scan_tree(root):
    """Files below root that contain a full canary value (paths only)."""
    bad = []
    for p in Path(root).rglob("*"):
        if p.is_file():
            try:
                if CANARY_VALUE_RE.search(p.read_bytes()):
                    bad.append(os.path.relpath(p, root))
            except OSError:
                pass
    return bad


def run_harness(workdir, label, mutate, only, candidate="go", ref_candidate="go", harness_mutate=None):
    out = Path(workdir) / ("%s.json" % label)
    art = Path(workdir) / ("%s-artifacts" % label)
    env = dict(os.environ)
    env.pop("SSH_AUTH_SOCK", None)
    env["REF_CANDIDATE"] = ref_candidate
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    for k, v in (("REF_MUTATE", mutate), ("HM_G02_HARNESS_MUTATE", harness_mutate)):
        if v:
            env[k] = v
        else:
            env.pop(k, None)
    argv = [sys.executable, str(HERE / "conformance.py"), "--bin", str(HERE / "reference_impl.py"),
            "--candidate", candidate, "--out", str(out), "--artifacts-dir", str(art),
            "--pass-env", "REF_MUTATE,REF_CANDIDATE", "--selftest"]
    extra = container_extra()
    if extra:
        argv += ["--environment-extra", json.dumps(extra)]
    if os.environ.get("HM_G02_COMMIT"):
        argv += ["--build-commit", os.environ["HM_G02_COMMIT"]]
    if only:
        argv += ["--only", only]
    t0 = time.monotonic()
    try:
        p = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=1800)
        rc, err_tail = p.returncode, p.stderr[-300:]
    except subprocess.TimeoutExpired as exc:   # never hang the self-test; record it
        rc, err_tail = "timeout(1800s)", str(exc)[-300:]
    dt = time.monotonic() - t0
    rec = json.loads(out.read_text(encoding="utf-8")) if out.exists() else None
    failed, summary, outcomes, failed_all, errors = [], None, {}, {}, {}
    if rec:
        summary = rec["observed_result"]["summary"]
        for c in rec["observed_result"]["checks"]:
            outcomes[c["id"]] = c["outcome"]
            if c["outcome"] != "pass":
                first = (c["failed_assertions"] or [c.get("error") or ""])[0]
                failed.append((c["id"], c["outcome"], first))
                failed_all[c["id"]] = list(c["failed_assertions"] or [])
                errors[c["id"]] = c.get("error")
    return {"label": label, "mutate": mutate, "harness_mutate": harness_mutate, "only": only, "exit": rc,
            "seconds": round(dt, 1), "summary": summary, "failed": failed,
            "status": rec["status"] if rec else None,
            "verdict": rec["observed_result"].get("verdict") if rec else None,
            "outcomes": outcomes, "failed_all": failed_all, "errors": errors, "stderr_tail": err_tail,
            "observations": rec["observed_result"].get("observations", {}) if rec else {},
            "environment": rec.get("environment") if rec else None,
            "record_path": str(out), "artifacts_path": str(art)}


def base_good(b):
    return b["exit"] == 0 and b["summary"] and b["summary"]["pass"] == b["summary"]["total"] \
        and b["status"] == "verified" and b["verdict"] == "pass"


def run_platform(args, workdir):
    """The whole self-test on this host.  Returns a JSON-serialisable result dict."""
    import reference_impl
    muts = sorted(reference_impl.MUTATIONS)
    hmuts = sorted(HARNESS_MUTATIONS)
    if args.only:
        wanted = args.only.split(",")
        unknown = [m for m in wanted if m not in muts and m not in hmuts and m not in CONFORMING
                   and m not in HARNESS_EXPECT]
        if unknown:
            raise SystemExit("unknown mutations: %s" % unknown)
        muts = [m for m in muts if m in wanted]
        hmuts = [m for m in hmuts if m in wanted]
    unit = subprocess.run([sys.executable, str(HERE / "minischema.py")], capture_output=True, text=True)
    plat = platform.system()
    print("[%s] baseline (unmutated reference, all checks) ..." % plat, flush=True)
    base = run_harness(workdir, "baseline", None, None)
    print("  exit=%s summary=%s failed=%s" % (base["exit"], base["summary"], [f[0] for f in base["failed"]]), flush=True)
    mismatch = run_harness(workdir, "candidate-mismatch", None, "version.valid", candidate="rust", ref_candidate="go")
    print("  candidate-mismatch exit=%s failed=%s" % (mismatch["exit"], [f[0] for f in mismatch["failed"]]), flush=True)

    results = []
    for m in muts:
        r = run_harness(workdir, "mut-" + m, m, scope_for(m))
        failed_ids = [f[0] for f in r["failed"]]
        r["intended"] = intended_of(m)
        if m in OBSERVED:
            what, get, pred = OBSERVED[m][:3]
            summ = OBSERVED[m][3] if len(OBSERVED[m]) > 3 else (lambda v: v)
            seen, base_seen = get(r["observations"]), get(base["observations"])
            r["intended"] = ["observation: " + what]
            r["observed_value"] = summ(seen)
            r["baseline_value"] = summ(base_seen)
            r["caught"] = r["exit"] in (0, 1) and bool(pred(seen)) and not pred(base_seen)
        else:
            r["caught"] = r["exit"] == 1 and bool(r["failed"]) and all(i in failed_ids for i in r["intended"])
        if m in INTENDED_FIRST_ASSERTION:
            cid, text = INTENDED_FIRST_ASSERTION[m]
            fa = r["failed_all"].get(cid) or []
            r["first_assertion"] = fa[0] if fa else None
            r["intended"] = r["intended"] + ["first failing assertion of %s: '%s ...'" % (cid, text[:60].replace("`", ""))]
            r["caught"] = r["caught"] and bool(fa) and text in fa[0]
        r["observable"] = True
        r["race"] = m in RACE
        gate = PLATFORM_GATED.get(m)
        if gate:
            key, pred = gate
            seen = r["observations"].get(key) or {}
            r["observable"] = pred(seen)
            r["host_delivery"] = seen
        results.append(r)
        print("%-34s exit=%s caught=%s%s%s by %s" % (m, r["exit"], r["caught"], "" if r["observable"] else
                                                    " (condition not observable on this host)",
                                                    " (race: recorded, not required)" if r["race"] else "",
                                                    failed_ids[:4]), flush=True)

    import reference_impl as _ri
    variants = sorted(set(CONFORMING) & set(getattr(_ri, "VARIANTS", {})))
    missing = sorted(set(CONFORMING) ^ set(getattr(_ri, "VARIANTS", {})))
    if missing:
        raise SystemExit("CONFORMING and reference_impl.VARIANTS disagree: %s" % missing)
    if args.only:
        variants = [v for v in variants if v in args.only.split(",")]
    vresults = []
    for v in variants:
        r = run_harness(workdir, "var-" + v, v, CONFORMING[v])
        r["accepted"] = r["exit"] == 0 and not r["failed"] and bool(r["summary"]) \
            and r["summary"]["pass"] == r["summary"]["total"]
        vresults.append(r)
        print("variant:%-26s exit=%s accepted=%s failed=%s k10=%s" % (
            v, r["exit"], r["accepted"], [f[0] for f in r["failed"]][:4],
            r["observations"].get("k10_exit_form")), flush=True)

    eresults = []
    for hm in sorted(HARNESS_EXPECT):
        if args.only and hm not in args.only.split(","):
            continue
        desc, scope, want, verdict, obs = HARNESS_EXPECT[hm]
        r = run_harness(workdir, "hexp-" + hm, None, scope, harness_mutate=hm)
        got = {cid: r["outcomes"].get(cid) for cid in want}
        ok = r["exit"] == 1 and got == want and r["verdict"] == verdict
        for cid, o in want.items():
            if o == "error":
                ok = ok and str(r["errors"].get(cid) or "").startswith("harness precondition failed")
        if obs:
            ok = ok and bool(obs[1](obs[0](r["observations"])))
        if hm == "k6c_probe_no_yes":      # the probe precondition must not fail the gated K6a check
            ok = r["exit"] in (0, 1) and got == want and r["verdict"] == verdict and bool(obs[1](obs[0](r["observations"])))
        r["expected_outcomes"], r["got_outcomes"], r["caught"] = want, got, ok
        eresults.append(r)
        print("harness-expect:%-22s exit=%s caught=%s outcomes=%s verdict=%s" % (hm, r["exit"], ok, got, r["verdict"]),
              flush=True)

    hresults = []
    for hm in hmuts:
        r = run_harness(workdir, "hmut-" + hm, None, HARNESS_MUTATIONS[hm][1], harness_mutate=hm)
        sc = r["observations"].get("canary_selfcheck") or {}
        leftovers = []
        if Path(r["record_path"]).exists():
            leftovers += ["record"] if CANARY_VALUE_RE.search(Path(r["record_path"]).read_bytes()) else []
        if Path(r["artifacts_path"]).exists():
            leftovers += scan_tree(r["artifacts_path"])
        r["selfcheck"] = {"result": sc.get("result"), "record_hits": len(sc.get("record_hits") or []),
                          "artifact_hits": len(sc.get("artifact_hits") or []), "labels": sorted(
                              {h["canary"] for h in (sc.get("record_hits") or []) + (sc.get("artifact_hits") or [])})}
        r["leftover_canary_files"] = leftovers
        r["caught"] = r["exit"] == 3 and bool(sc.get("record_hits") or sc.get("artifact_hits")) \
            and str(sc.get("result", "")).startswith("LEAK") and not leftovers and r["status"] == "in_progress"
        hresults.append(r)
        print("harness:%-26s exit=%s caught=%s selfcheck=%s" % (hm, r["exit"], r["caught"], r["selfcheck"]), flush=True)

    repeats = []
    for i in range(args.repeat_baseline):
        print("[%s] extra baseline run %d/%d ..." % (plat, i + 1, args.repeat_baseline), flush=True)
        rb = run_harness(workdir, "baseline-repeat-%d" % (i + 1), None, None)
        print("  exit=%s summary=%s failed=%s" % (rb["exit"], rb["summary"], [f[0] for f in rb["failed"]]), flush=True)
        repeats.append(rb)
    flaky = sorted({cid for b in [base] + repeats for cid, o in b["outcomes"].items() if o != "pass"})
    leaks = scan_tree(workdir)
    out = {
        "platform": plat, "release": platform.release(), "machine": platform.machine(),
        "python": sys.version.split()[0], "environment": base["environment"], "unit_rc": unit.returncode,
        "baseline": base, "repeats": repeats, "flaky": flaky, "mismatch": mismatch,
        "mutations": results, "harness_mutations": hresults, "harness_expect": eresults, "variants": vresults,
        "canary_leak_files": leaks,
    }
    out["base_ok"] = base_good(base)
    out["repeats_ok"] = all(base_good(b) for b in repeats)
    out["mismatch_ok"] = mismatch["exit"] == 1 and any(f[0] == "version.valid" for f in mismatch["failed"])
    out["observable_caught"] = all(r["caught"] for r in results if r["observable"] and not r["race"])
    out["unobservable"] = [r["mutate"] for r in results if not r["observable"]]
    out["race_results"] = {r["mutate"]: r["caught"] for r in results if r["race"]}
    out["harness_caught"] = all(r["caught"] for r in hresults) and all(r["caught"] for r in eresults)
    out["variants_accepted"] = all(r["accepted"] for r in vresults)
    out["ok"] = bool(out["base_ok"] and out["repeats_ok"] and out["mismatch_ok"] and out["observable_caught"]
                     and out["harness_caught"] and out["variants_accepted"] and unit.returncode == 0 and not leaks)
    for r in results + hresults + eresults + vresults + [base, mismatch] + repeats:
        r.pop("outcomes", None)            # flakiness is computed above; keep the JSON small
    return out


def run_linux(args, workdir):
    """tests/g02/linux/run.sh --selftest <workdir>/linux (the same self-test inside the container)."""
    ldir = Path(workdir) / "linux"
    argv = [str(HERE / "linux" / "run.sh"), "--selftest", str(ldir), "--"] + shlex.split(args.linux_args or "")
    if args.only:
        argv += ["--only", args.only]
    print("linux self-test: %s" % " ".join(argv), flush=True)
    t0 = time.monotonic()
    p = subprocess.run(argv, timeout=4 * 3600)
    print("linux self-test exit=%s in %.0fs" % (p.returncode, time.monotonic() - t0), flush=True)
    res = ldir / "selftest-linux.json"
    if not res.exists():
        return {"error": "run.sh --selftest exit %s, no selftest-linux.json" % p.returncode}
    data = json.loads(res.read_text(encoding="utf-8"))
    data["runner_exit"] = p.returncode
    data["results_path"] = str(res)
    return data


def md_platform_summary(L, name, P):
    b = P["baseline"]
    L.append("### %s (%s %s, %s, Python %s)\n" % (name, P["platform"], P["release"], P["machine"], P["python"]))
    env = P.get("environment") or {}
    if env.get("container"):
        c = env["container"]
        L.append("- container: image `%s` (`%s`), base `%s`, packages %s, docker server %s, network %s, user %s" % (
            c.get("image_ref"), c.get("image_id"), c.get("base_image"), ", ".join("`%s`" % x for x in c.get("image_packages") or []),
            c.get("docker_server"), c.get("network"), c.get("user")))
    L.append("- minischema unit self-test: exit %s" % P["unit_rc"])
    L.append("- baseline, unmutated reference, full catalogue: exit **%s**, summary `%s`, record status `%s`, verdict `%s`, %ss" % (
        b["exit"], json.dumps(b["summary"]), b["status"], b["verdict"], b["seconds"]))
    for r in P["repeats"]:
        L.append("- %s (flake detection), full catalogue: exit **%s**, summary `%s`, verdict `%s`, %ss" % (
            r["label"], r["exit"], json.dumps(r["summary"]), r["verdict"], r["seconds"]))
    L.append("- checks not passing in at least one of the %d baseline runs (flaky): %s" % (
        1 + len(P["repeats"]), ", ".join("`%s`" % f for f in P["flaky"]) or "none"))
    m = P["mismatch"]
    L.append("- wrong `--candidate rust` against a reference reporting `go` (`--only version.valid`): exit **%s**, failed %s" % (
        m["exit"], [f[0] for f in m["failed"]]))
    ks = (b.get("observations") or {}).get("k3a_reset_delivery")
    L.append("- K3a reset delivery observed by the baseline: `%s`" % ks)
    muts = P["mutations"]
    L.append("- race mutations (recorded, NOT required to be caught; see RACE in selftest.py): %s" % (
        ", ".join("`%s` %s" % (r["mutate"], "caught" if r["caught"] else "not caught") for r in muts if r.get("race"))
        or "none"))
    L.append("- reference mutations caught: **%d / %d** observable on this host (race mutations excluded)%s" % (
        sum(1 for r in muts if r["observable"] and r["caught"] and not r.get("race")),
        sum(1 for r in muts if r["observable"] and not r.get("race")),
        ("; not observable on this platform (must be caught on the other one): %s" % ", ".join("`%s`" % x for x in P["unobservable"]))
        if P["unobservable"] else ""))
    L.append("- harness mutations (canary self-check) caught: **%d / %d**" % (
        sum(1 for r in P["harness_mutations"] if r["caught"]), len(P["harness_mutations"])))
    L.append("- harness/environment faults with the required check outcome (precondition -> `error`, emulator defect "
             "-> `fail`): **%d / %d**" % (sum(1 for r in P.get("harness_expect", []) if r["caught"]),
                                         len(P.get("harness_expect", []))))
    L.append("- conforming variants accepted (must pass): **%d / %d**" % (
        sum(1 for r in P.get("variants", []) if r["accepted"]), len(P.get("variants", []))))
    lat = (b.get("observations") or {}).get("large100_keystroke_to_update_ms") or {}
    L.append("- baseline K17 filter latency: p95 `%s` ms over %d edits in %d filter sessions (bound %s ms; update = "
             "%s)" % (lat.get("filter_p95"), len(lat.get("filter") or []), len(lat.get("sessions") or []),
                      lat.get("k17_bound_ms"), lat.get("update_predicate")))
    k6c = (((b.get("observations") or {}).get("k6c_other_inherited_signal_state") or {}).get("sigpipe-non-python")
           or {})
    L.append("- baseline K6c SIGPIPE probe classification (reference, CPython runtime): `%s`" % k6c.get("classification"))
    k6e = (b.get("observations") or {}).get("k6e_job_control") or {}
    L.append("- baseline K6e forms: %s" % ", ".join("`%s` %s%s" % (k, "ok" if v.get("ok") else "NOT ok: %s" % (
        v.get("not_run") or v.get("first_failed_step")), "" if v.get("gating", True) else " (non-gating)")
        for k, v in k6e.items()))
    k6es = (b.get("observations") or {}).get("k6e_child_self_stop") or {}
    L.append("- baseline K6e child self-stop forms (section 9.4): %s" % (", ".join("`%s` %s%s, notice/$? %s" % (
        k, "ok" if v.get("ok") else "NOT ok: %s" % (v.get("not_run") or (v.get("first_failed_step") or {}).get("desc")),
        "" if v.get("gating") else " (non-gating)", json.dumps(v.get("notice_and_status")))
        for k, v in k6es.items()) or "none"))
    k12c = (b.get("observations") or {}).get("k12_closed_stdout") or {}
    L.append("- baseline K12 closed-stdout wait statuses (section 9.4): %s" % (", ".join("`%s` json `%s` / plain `%s`" % (
        k, (v.get("json") or {}).get("wait_status"), (v.get("plain") or {}).get("wait_status"))
        for k, v in k12c.items()) or "none"))
    k12e = (b.get("observations") or {}).get("k12_closed_stdout_errors") or {}
    L.append("- baseline K12 closed-stdout wait statuses of error results (gating since harness 2.4.2, Q17): %s" % (
        ", ".join("`%s` json `%s` / plain `%s`" % (k, (v.get("json") or {}).get("wait_status"),
                                                   (v.get("plain") or {}).get("wait_status"))
                  for k, v in (k12e.get("cases") or {}).items()) or "none"))
    k6as = (b.get("observations") or {}).get("k6a_child_self_stop") or {}
    L.append("- baseline K6a child self-stop layouts (other job member stopped after s / shell reported a stop): %s" % (
        ", ".join("`%s` %s / %s" % (k, v.get("peer_stopped_after_s"), v.get("shell_reported_stop"))
                  for k, v in k6as.items()) or "none"))
    L.append("- full canary values in any record/artifact of this self-test's work directory: %s" % (
        P["canary_leak_files"] or "none"))
    L.append("- platform result: **%s**\n" % ("PASS" if P["ok"] else "FAIL"))


def write_md(path, started, host, linux, ok, reasons):
    import reference_impl
    L = []
    L.append("# G02 harness self-test (generated by `tests/g02/selftest.py`)\n")
    L.append("Generated %s on %s %s (%s), Python %s. Do not edit by hand; re-run "
             "`python3 tests/g02/selftest.py --repeat-baseline 2 --linux`.\n" % (
                 started, platform.system(), platform.release(), platform.machine(), sys.version.split()[0]))
    L.append("Subject: `tests/g02/reference_impl.py` (a minimal Python implementation of contract sections 2, 3, 4, 6 plus a small "
             "raw-ANSI `tui` stand-in, used ONLY to validate the harness; it says nothing about any language candidate). "
             "Harness version %s, contract incl. section 9 (K1-K12, K3a), 9.1 (K6a, K10, K13-K16), 9.2 (K6b, K6c) and "
             "9.3 (K6d, K6e, K17, K18, K10 exit form) and 9.4 (K6e child-initiated stop, K12 closed stdout).\n" % _harness_version())
    L.append("Every exit code below is the real exit status of the command that was run in this pass.\n")
    L.append("## Verdict: **%s**\n" % ("PASS" if ok else "FAIL"))
    if reasons:
        L.append("Failure reasons: %s\n" % "; ".join(reasons))
    L.append("## Platforms\n")
    md_platform_summary(L, "Host", host)
    if linux and "error" not in linux:
        md_platform_summary(L, "Linux container (K13: linux-arm64, `tests/g02/linux/run.sh --selftest`)", linux)
    else:
        L.append("### Linux container\n\n- **not done** (%s): platform-gated mutations and K13 cannot be proven\n" % (
            (linux or {}).get("error") or "no --linux / --linux-results given"))
    L.append("## Commands\n")
    L.append("```sh\npython3 tests/g02/conformance.py --bin tests/g02/reference_impl.py --candidate go --out <rec> "
             "--artifacts-dir <dir> --pass-env REF_MUTATE,REF_CANDIDATE --selftest           # baseline\n"
             "REF_MUTATE=<name> python3 tests/g02/conformance.py ... --only <scope>               # each reference mutation\n"
             "HM_G02_HARNESS_MUTATE=<name> python3 tests/g02/conformance.py ... --only <scope>    # each harness mutation (exit 3 expected)\n"
             "tests/g02/linux/run.sh --selftest <dir> -- <selftest args>                         # the same inside the Linux container\n```\n")
    L.append("## Harness mutations (canary self-check)\n")
    L.append("| harness mutation | injected harness defect | scope | host exit | host caught | Linux exit | Linux caught | self-check (host) |")
    L.append("|---|---|---|---|---|---|---|---|")
    lh = {r["harness_mutate"]: r for r in (linux or {}).get("harness_mutations", [])}
    for r in host["harness_mutations"]:
        name = r["harness_mutate"]
        lr = lh.get(name) or {}
        L.append("| `%s` | %s | `%s` | %s | %s | %s | %s | %s |" % (
            name, HARNESS_MUTATIONS[name][0], r["only"], r["exit"], "yes" if r["caught"] else "**NO**",
            lr.get("exit", "-"), ("yes" if lr.get("caught") else "**NO**") if lr else "-",
            "%s; record strings %d, artifact hits %d; labels %s; canary values left on disk: %s" % (
                r["selfcheck"]["result"], r["selfcheck"]["record_hits"], r["selfcheck"]["artifact_hits"],
                r["selfcheck"]["labels"], r["leftover_canary_files"] or "none")))
    L.append("")
    L.append("## Harness and environment faults (required check outcomes)\n")
    L.append("| harness mutation | injected fault | scope | required outcomes / verdict | host exit | host outcomes | host ok | Linux exit | Linux ok |")
    L.append("|---|---|---|---|---|---|---|---|---|")
    le = {r["harness_mutate"]: r for r in (linux or {}).get("harness_expect", [])}
    for r in host.get("harness_expect", []):
        name = r["harness_mutate"]
        lr = le.get(name) or {}
        L.append("| `%s` | %s | `%s` | `%s` / `%s` | %s | `%s` | %s | %s | %s |" % (
            name, HARNESS_EXPECT[name][0], r["only"], json.dumps(r["expected_outcomes"]), HARNESS_EXPECT[name][3],
            r["exit"], json.dumps(r["got_outcomes"]), "yes" if r["caught"] else "**NO**", lr.get("exit", "-"),
            ("yes" if lr.get("caught") else "**NO**") if lr else "-"))
    L.append("")
    L.append("## Conforming variants (must pass)\n")
    L.append("| variant | allowed behaviour | scope | host exit | host accepted | Linux exit | Linux accepted | K10 exit form seen (host) |")
    L.append("|---|---|---|---|---|---|---|---|")
    lv = {r["mutate"]: r for r in (linux or {}).get("variants", [])}
    for r in host.get("variants", []):
        name = r["mutate"]
        lr = lv.get(name) or {}
        L.append("| `%s` | %s | `%s` | %s | %s | %s | %s | `%s` |" % (
            name, reference_impl.VARIANTS[name], r["only"], r["exit"], "yes" if r["accepted"] else "**NO**",
            lr.get("exit", "-"), ("yes" if lr.get("accepted") else "**NO**") if lr else "-",
            json.dumps(r["observations"].get("k10_exit_form"))))
    L.append("")
    L.append("## Reference mutation results\n")
    L.append("`scope` is the `--only` selection used for that run (the baselines cover the whole catalogue). `caught by` lists "
             "failing checks with the first failing assertion (host run; the Linux run where the host cannot produce the "
             "condition). A mutation with intended checks counts as caught only if all of them fail.\n")
    L.append("| mutation | injected defect | scope | intended check(s) | host exit | host caught | Linux exit | Linux caught | caught by (first failing assertion) |")
    L.append("|---|---|---|---|---|---|---|---|---|")
    lm = {r["mutate"]: r for r in (linux or {}).get("mutations", [])}
    for r in host["mutations"]:
        name = r["mutate"]
        lr = lm.get(name) or {}
        src = r["failed"] if r["observable"] or not lr else lr.get("failed") or []
        if not r["observable"] and not src:
            src = r["failed"]
        by = "<br>".join("`%s` [%s]" % (f[0], f[2].replace("|", "\\|")[:90]) for f in src[:5])
        if len(src) > 5:
            by += "<br>... +%d more" % (len(src) - 5)
        if "observed_value" in r:
            by = ("observation `%s` (baseline `%s`)" % (json.dumps(r["observed_value"], ensure_ascii=False,
                                                                   default=str)[:400].replace("|", "\\|"),
                                                        json.dumps(r["baseline_value"], ensure_ascii=False,
                                                                   default=str)[:400].replace("|", "\\|"))
                  + ("<br>" + by if by else ""))
        host_caught = ("yes" if r["caught"] else "**NO**") if r["observable"] else \
            "not observable here (%s)" % json.dumps(r.get("host_delivery"))
        if r.get("race"):
            host_caught = "race, not required: %s" % ("caught" if r["caught"] else "not caught")
        L.append("| `%s` | %s | `%s` | %s | %s | %s | %s | %s | %s |" % (
            name, reference_impl.MUTATIONS[name], r["only"], "<br>".join("`%s`" % i for i in r["intended"]) or "-",
            r["exit"], host_caught, lr.get("exit", "-"),
            (("race, not required: %s" % ("caught" if lr.get("caught") else "not caught")) if lr.get("race") else
             ("yes" if lr.get("caught") else "**NO**") if lr.get("observable", True) else
             "not observable (%s)" % json.dumps(lr.get("host_delivery"))) if lr else "-",
            by or "-"))
    L.append("")
    L.append("## Baseline detail\n")
    for name, P in (("host", host), ("Linux", linux if linux and "error" not in linux else None)):
        if P:
            L.append("- %s baseline wall time %ss; non-passing checks: %s" % (
                name, P["baseline"]["seconds"], [f[0] for f in P["baseline"]["failed"]] or "none"))
    text = "\n".join(L) + "\n"
    if CANARY_VALUE_RE.search(text.encode("utf-8")):
        text = re.sub(r"HEIMDALL_CANARY_[A-Za-z0-9_]*", "[REDACTED_CANARY]", text)
        reasons.append("the generated report contained a full canary value (redacted)")
    Path(path).write_text(text, encoding="utf-8")


def _harness_version():
    m = re.search(r'^HARNESS_VERSION = "([^"]+)"', (HERE / "conformance.py").read_text(encoding="utf-8"), re.M)
    return m.group(1) if m else "?"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(HERE / "SELFTEST.md"))
    ap.add_argument("--json-out", help="machine-readable results (used to merge the Linux run)")
    ap.add_argument("--workdir")
    ap.add_argument("--only", help="comma list of mutation names (reference or harness; default: all)")
    ap.add_argument("--repeat-baseline", type=int, default=0,
                    help="additional full baseline runs used to detect flaky checks")
    ap.add_argument("--linux", action="store_true", help="also run this self-test in the Linux container (run.sh)")
    ap.add_argument("--linux-args", default="--repeat-baseline 1", help="selftest.py arguments for the Linux run")
    ap.add_argument("--linux-results", help="merge an existing selftest-linux.json instead of running Linux")
    ap.add_argument("--linux-results-wait", type=int, default=0,
                    help="seconds to wait for --linux-results to appear (Linux self-test started concurrently)")
    args = ap.parse_args()
    workdir = args.workdir or tempfile.mkdtemp(prefix="hmg02-selftest-", dir="/tmp")
    Path(workdir).mkdir(parents=True, exist_ok=True)
    started = datetime.datetime.now().astimezone().isoformat(timespec="seconds")

    host = run_platform(args, workdir)
    linux = None
    if args.linux_results:
        end = time.monotonic() + args.linux_results_wait
        while not Path(args.linux_results).exists() and time.monotonic() < end:
            time.sleep(10)          # a concurrently started Linux self-test may still be running
        if Path(args.linux_results).exists():
            linux = json.loads(Path(args.linux_results).read_text(encoding="utf-8"))
            linux["results_path"] = args.linux_results
        else:
            linux = {"error": "%s did not appear within %d s" % (args.linux_results, args.linux_results_wait)}
    elif args.linux:
        linux = run_linux(args, workdir)

    reasons = []
    for k in ("base_ok", "repeats_ok", "mismatch_ok", "observable_caught", "harness_caught", "variants_accepted"):
        if not host[k]:
            reasons.append("host %s=False" % k)
    if host["unit_rc"]:
        reasons.append("host minischema unit test exit %s" % host["unit_rc"])
    if host["canary_leak_files"]:
        reasons.append("host canary values left in %d files" % len(host["canary_leak_files"]))
    linux_needed = platform.system() != "Linux"
    if linux_needed:
        if not linux or "error" in linux:
            reasons.append("no Linux self-test result (K13; platform-gated mutations unproven)")
        else:
            if not linux.get("verdict_ok", linux.get("ok")):
                reasons.append("Linux self-test FAIL")
            lm = {r["mutate"]: r for r in linux.get("mutations", [])}
            hm = {r["mutate"]: r for r in host["mutations"]}
            for name in host["unobservable"]:
                lr = lm.get(name)
                if not (lr and lr.get("observable") and lr.get("caught")):
                    reasons.append("platform-gated %s (not observable on this host) not caught on Linux" % name)
            for name in linux.get("unobservable", []):
                hr = hm.get(name)
                if not (hr and hr.get("observable") and hr.get("caught")):
                    reasons.append("platform-gated %s (not observable on Linux) not caught on this host" % name)
    ok = not reasons and host["ok"]
    write_md(args.out, started, host, linux, ok, reasons)
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(dict(host, verdict_ok=ok, reasons=reasons), indent=1,
                                                  ensure_ascii=False, default=str) + "\n", encoding="utf-8")
    if reasons:
        print("FAILURE REASONS: %s" % "; ".join(reasons), flush=True)
        print("  records kept in %s" % workdir, flush=True)
    print("\nSELFTEST %s -> %s (workdir %s)" % ("PASS" if ok else "FAIL", args.out, workdir), flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
