#!/usr/bin/env python3
"""Reference implementation of the G02 slice contract, for validating the harness ONLY.

NOT a prototype, NOT production code.  It implements docs/g02/slice-contract.md
sections 1-4 and 6 (profile show, agent list, run, version) plus a deliberately
small `tui` stand-in (reference_tui.py) so the TUI checks of the harness can
themselves be exercised.  Python standard library only.

Mutation switch: environment variable REF_MUTATE="name1,name2" injects the known
defects listed in MUTATIONS below.  The harness must catch every one of them
(tests/g02/selftest.py proves this).  REF_CANDIDATE selects the `candidate`
field reported by `version` (default "go").
"""
import base64
import errno
import hashlib
import json
import os
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

try:
    import tomllib
except ImportError:  # pragma: no cover
    sys.stderr.write("reference_impl needs Python >= 3.11 (tomllib)\n")
    sys.exit(1)

MUT = set(x for x in os.environ.get("REF_MUTATE", "").split(",") if x)

# name -> one-line description (used by selftest.py and the README)
MUTATIONS = {
    # profile / common
    "canary_echo": "error message echoes the offending value (leaks canary)",
    "wrong_exit_schema": "SCHEMA_INVALID exits 1 instead of 2",
    "ignore_oversize": "1 MiB input bound is not enforced",
    "oversize_off_by_one": "bound is >= 1 MiB instead of > 1 MiB",
    "sort_destinations": "destination order not preserved",
    "port_default_wrong": "default port is 2222 instead of 22",
    "meta_echo": "[meta] content is echoed in the output",
    "stdout_extra_newline": "JSON followed by two newlines",
    "usage_json_missing": "--json usage error prints no JSON result",
    "usage_plain_stdout": "usage error without --json writes to stdout",
    "stray_write": "writes a file into the working directory",
    "schema_version_no_warning": "unsupported schema_version gives no warning",
    "accept_bool_revision": "revision = true accepted as integer",
    "profile_control_chars_ok": "control characters in profile string values accepted (K2)",
    "profile_c1_ok": "C1 control code points in profile values accepted (K2)",
    "profile_label_control_ok": "control characters inside labels accepted (K2)",
    "profile_meta_control_rejected": "control characters inside [meta] rejected (K2)",
    "plain_exit_wrong": "without --json, SCHEMA_INVALID exits 1 (K12: exit codes must match --json)",
    "stray_tmp_write": "leaves a cache file in $TMPDIR (K11)",
    "nonregular_file_accepted": "--file opened with a blocking open and no regular-file check: a FIFO blocks, a device is parsed (K14)",
    "parser_deep_crash": "deep nesting crashes the parser (uncaught RecursionError, exit 1) (K15)",
    "parser_deep_slow": "deep nesting takes 2.5 s before SCHEMA_INVALID (K15)",
    "parser_deep_memory": "deep nesting allocates and touches 320 MiB before SCHEMA_INVALID (K15)",
    "type_error_echoes_value": "port and revision range/type errors quote the offending value in the message",
    "malformed_echo_source_line": "malformed TOML: the offending source line is printed to stderr (TOML-library snippet style)",
    "schema_version_warning_echoes_name": "unsupported schema_version warning also quotes the profile name",
    "stderr_echoes_value": "the JSON result is clean, but a stderr diagnostic quotes the offending port/revision/duplicate value (K18)",
    # agent
    "agent_fp_wrong": "fingerprint keeps base64 padding",
    "agent_ignore_nkeys": "nkeys bound (1024) not enforced",
    "agent_nkeys_off_by_one": "nkeys bound is >= 1024 instead of > 1024",
    "agent_accept_trailing": "trailing bytes after last key tolerated",
    "agent_ignore_frame_bound": "frame length bound (262144) not enforced",
    "agent_frame_off_by_one": "frame bound is >= 262144 instead of > 262144",
    "agent_refused_as_protocol": "SSH_AGENT_FAILURE reported as AGENT_PROTOCOL_ERROR",
    "agent_no_timeout": "--timeout-ms ignored (fixed 4 s)",
    "agent_sigint_slow": "SIGINT handled only after 0.8 s",
    "agent_sigint_wrong_exit": "SIGINT exits 1 instead of 130",
    "agent_extra_request": "sends REQUEST_IDENTITIES twice",
    "agent_other_type": "also sends a type-1 request",
    "agent_comment_strict": "invalid UTF-8 comment rejected instead of U+FFFD",
    "agent_single_read": "assumes the whole reply arrives in one read",
    "agent_wrong_type_ok": "unexpected message type treated as empty success",
    "agent_overrun_ok": "string length beyond frame is clamped instead of rejected",
    "agent_emit_blob": "raw key blob emitted in each identity",
    "agent_connect_fail_protocol": "connect failure reported as AGENT_PROTOCOL_ERROR",
    "agent_control_passthrough": "control characters in comment/key_type kept (only JSON-escaped) (K1)",
    "agent_c1_passthrough": "C1 control code points in comment/key_type kept (K1)",
    "agent_keytype_unsanitized": "key_type control characters kept; only the comment is sanitised (K1)",
    "agent_keytype_strict": "invalid UTF-8 in key_type rejected instead of U+FFFD (K1)",
    "agent_eof_as_protocol": "peer EOF before any reply byte reported as AGENT_PROTOCOL_ERROR (K3)",
    "agent_partial_eof_unavailable": "EOF after a partial frame header reported as AGENT_UNAVAILABLE (K3)",
    "agent_failure_payload_refused": "type-5 frame with payload accepted as AGENT_REFUSED (K4)",
    "agent_reset_unhandled": "ECONNRESET from the agent socket not handled: traceback, exit 1 (K3a)",
    "agent_zero_frame_crash": "zero-length frame indexes the missing type byte: traceback, exit 1",
    "agent_short_answer_crash": "type-12 frame shorter than 5 bytes unpacked without a length check: traceback, exit 1",
    "agent_nkeys_short_ok": "fewer keys than the declared nkeys (within the bound) accepted as AGENT_OK",
    "agent_per_read_timeout": "--timeout-ms applied per read (idle timeout) instead of to the whole response",
    "agent_default_timeout_60s": "default --timeout-ms is 60000 instead of 5000",
    # run
    "run_extra_stdout": "writes a newline to stdout after the child",
    "run_exit_255_to_1": "child exit 255 mapped to 1",
    "run_shell": "joins argv and runs it through a shell",
    "run_no_forward_term": "SIGTERM is not forwarded (proto dies first)",
    "run_forward_then_exit": "forwards signals but exits without waiting for the child",
    "run_signal_exit_wrong": "child killed by signal exits 1 instead of 128+N",
    "run_launch_126": "launch failure exits 126 instead of 127",
    "run_meta_exit_for_signal": "meta reports exit_code 137 and signal null for signalled child",
    "run_drop_env": "child does not inherit the environment",
    "run_drop_cwd": "child runs in / instead of the working directory",
    "run_strip_empty_arg": "empty-string arguments dropped",
    "run_text_mode": "child stdout passed through a text decode/encode",
    "run_stderr_noise": "writes a banner to stderr before the child",
    "run_no_dashdash_ok": "missing -- tolerated (argv taken from the rest)",
    "run_kill_child_early": "child killed with SIGKILL when proto receives SIGTERM",
    "run_double_signal": "forwards each signal twice",
    "run_stdin_devnull": "child stdin is /dev/null instead of inherited",
    "run_meta_launch_ok": "launch failure reported as launched=true",
    "run_meta_state_by_exit": "meta state is 'failed' when the child exits non-zero (K5)",
    "run_meta_launch_state_ok": "meta state is 'succeeded' for CHILD_LAUNCH_FAILED (K5)",
    "run_argv_lossy": "non-UTF-8 argv bytes replaced with U+FFFD before exec (K8)",
    "run_tty_no_forward": "with a controlling terminal, explicit signals are not forwarded (job control only) (K6)",
    "run_takes_foreground": "child runs in its own process group made the terminal's foreground group via /dev/tty; signals still forwarded (K6a)",
    "run_forward_ignored": "signals inherited as ignored are still caught and forwarded (K6a)",
    "run_reset_ignored_in_child": "inherited SIG_IGN reset to SIG_DFL before the child starts, then forwarded (K6a)",
    "run_second_signal_force_quit": "a second SIGINT/SIGTERM makes heimdall-proto exit 130 at once, before the child",
    "run_pipe_stdio": "child stdout/stderr are pipes copied byte-exactly to heimdall-proto's stdout/stderr (not inherited)",
    "run_meta_tmp_left": "meta file written via '<meta>.tmp' that is copied, not renamed: the .tmp file is left behind",
    "run_shared_drop": "shared mode (controlling terminal held by heimdall-proto's group, stdin/stdout a pipe or not the group leader): SIGINT/SIGHUP/SIGQUIT/SIGWINCH assumed terminal-generated and silently dropped (K6d; the Go round-2 finding)",
    "run_fg_restop": "under job control a later `fg` (the third its SIGCONT handler sees) re-stops the job at once with SIGTSTP to its own group; earlier ones work (K6e; the Go round-2 Linux finding)",
    "run_fg_restop_late": "under job control the second `fg` re-stops the job 700 ms later with SIGTSTP to its own group (K6e; round-3 review rv_restop_700ms: the 0.5 s look after `fg` missed it and a later step took the blame)",
    "run_ignore_child_stop": "a child that stops itself (kill(getpid(), SIGTSTP), OpenSSH ~^Z) is ignored: heimdall-proto waits only for the child's exit, so the shell never learns that the job stopped (K6e child-initiated stop, section 9.4; the Rust round-3b finding)",
    "run_child_stop_no_continue": "job-control launcher (child in its own foreground process group when heimdall-proto leads its group and holds the terminal) that answers a child stop by taking the terminal back and stopping itself, but on `fg` never hands the terminal back to the child or continues it (K6e child-initiated stop, section 9.4)",
    "plain_epipe_exit1": "without --json, a write error on stdout (EPIPE: the reader closed) is fatal: 'panic' message, exit 1, while --json ignores it and exits normally (K12 closed stdout, section 9.4; the Rust round-3b println! finding)",
    "plain_epipe_sigpipe": "without --json, SIGPIPE is reset to the default before writing, so a closed stdout kills heimdall-proto with SIGPIPE, while --json ignores the write error and exits normally (K12 closed stdout, section 9.4)",
    "run_child_sigpipe_ignored": "the child is started without restoring the runtime's own SIGPIPE ignore (Popen restore_signals=False): every child runs with SIGPIPE ignored, also when heimdall-proto inherited the default (K6c observation; round-3 review rv_child_sigpipe_ignored)",
    # version
    "version_wrong_candidate": "version reports candidate 'rust'",
    "version_tput_probe": "version runs `tput colors` (PATH lookup) when TERM_PROGRAM is set (K16)",
    # tui
    "tui_no_cursor_restore": "cursor left hidden on exit",
    "tui_no_alt_leave": "alternate screen not left on exit",
    "tui_color_always": "color SGR emitted even with NO_COLOR",
    "tui_ctrlc_exit1": "Ctrl-C exits 1 instead of 130",
    "tui_quit_prints_selected": "q prints SELECTED",
    "tui_sigterm_no_restore": "SIGTERM exits without restoring the terminal",
    "tui_case_sensitive": "filter is case sensitive",
    "tui_no_prefix": "selected row has no '> ' prefix",
    "tui_esc_keeps_filter": "Esc does not clear the filter",
    "tui_ignore_resize_hide": "narrow terminals still show account@host",
    "tui_termios_not_restored": "terminal attributes left in raw mode",
    "tui_crash_small": "crashes below 30 columns",
    "tui_filter_alias_only": "filter ignores host",
    "tui_select_wrong_text": "prints 'SELECT alias' instead of 'SELECTED alias'",
    "tui_no_tty_check": "starts without checking for a TTY",
    "tui_slow_resize": "re-layout delayed by 400 ms",
    "tui_enter_in_filter_selects": "Enter in filter mode selects immediately",
    "tui_no_alt_screen": "never enters the alternate screen",
    "tui_exit0_on_ctrlc_in_filter": "Ctrl-C in filter mode is ignored",
    "tui_no_hide_cursor": "cursor never hidden while active",
    "tui_status_missing": "status line has no shown/total counts",
    "tui_no_unicode_filter": "non-ASCII filter characters ignored",
    "tui_filter_keeps_selection": "typing a filter character keeps the old selection index (K9)",
    "tui_backspace_keeps_selection": "Backspace keeps the old selection index (K9)",
    "tui_esc_keeps_selection": "Esc clear keeps the old selection index (K9)",
    "tui_sigterm_exit0": "SIGTERM restores the terminal but exits 0 (K10)",
    "tui_sigterm_prints": "SIGTERM prints SELECTED for the current row (K10: no stdout)",
    "tui_sighup_unhandled": "SIGHUP not handled: killed without restoring the terminal (K10)",
    "tui_hangup_exit130": "terminal hangup (EOF/EIO on the tty) exits 130 instead of 129 (K10)",
    "tui_stray_home_write": "writes a state file into $HOME (K11)",
    "tui_stderr_canary": "TUI writes an inherited secret (the canary env var) to stderr (section 1)",
    "tui_tmux_probe": "TUI runs `tmux display-message` (PATH lookup) when TMUX is set (K16)",
    "tui_term_probe": "TUI runs `infocmp` (PATH lookup) when TERM starts with tmux or screen (K16)",
    "tui_narrow_threshold_60": "rows show only the alias below 60 columns instead of below 50",
    "tui_slow_filter": "each filter edit on a profile with more than 50 destinations takes 150 ms before the screen update (K17)",
    "tui_rows_lag": "on a profile with more than 50 destinations the N/M status updates at once but the list rows are redrawn only 150 ms after the last filter edit (K17; round-3 review rv_rows_lag)",
    "tui_slow_first_filter_key": "on a profile with more than 50 destinations the first filter edit after `/` takes 150 ms, later ones are immediate (K17; round-3 review rv_delay_first_key)",
}

# Conforming variants (NOT defects): selftest.py requires the checks in their scope to PASS, proving the harness
# accepts behaviour that a section 9 ruling explicitly allows.
VARIANTS = {
    "tui_reraise_signal": "after restoring the terminal, the TUI re-raises SIGTERM/SIGHUP (also after a hangup) "
                          "with the default disposition: wait status 'killed by signal' instead of exit 143/129 "
                          "(allowed by K10 exit form, section 9.3)",
    "tui_filter_70ms": "every filter edit on a profile with more than 50 destinations takes 70 ms before the screen "
                       "update: slow, but inside the K17 p95 bound of 100 ms (round-3 review control rv_delay_90ms, "
                       "lowered to keep 30 ms margin for pty/emulator overhead while the host and Linux self-tests "
                       "run concurrently; observed overhead about 6 ms on an idle darwin host)",
    "closed_stdout_sigpipe_both": "SIGPIPE is reset to the default before writing the result, with and without --json: a "
                                  "closed stdout kills heimdall-proto with SIGPIPE in both modes (allowed: section 9.4 "
                                  "K12 requires equal wait statuses, not a particular one)",
    "run_job_control_own_group": "job-control alternative (round-3 review control rv_jc2): when heimdall-proto is its "
                                 "own process-group leader, holds the terminal foreground and has a terminal on stdin "
                                 "and stdout, the child gets its own process group made the foreground; heimdall-proto "
                                 "stops itself when the child stops, on SIGCONT hands the terminal back to the child if "
                                 "it holds the foreground and continues it, and when the child stops with SIGTTIN/SIGTTOU "
                                 "while heimdall-proto holds the foreground it hands over the terminal and continues it "
                                 "(allowed by K6/K6b: alone in its group, K6a holds)",
}

MAX_FILE = 1048576
MAX_FRAME = 262144
MAX_KEYS = 1024
EXIT_USAGE, EXIT_DEP = 2, 5


# --------------------------------------------------------------------------
# output helpers
def out_json(doc, exit_code):
    data = json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
    if "stdout_extra_newline" in MUT:
        data += b"\n"
    plain = "--json" not in sys.argv
    if (plain and "plain_epipe_sigpipe" in MUT) or "closed_stdout_sigpipe_both" in MUT:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)       # mutation: a closed stdout kills the plain path
    try:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    except BrokenPipeError:
        # K12 (section 9.4): the reader of stdout has gone; the exit status is the same with and without --json.
        # Point fd 1 at /dev/null so the interpreter's final flush cannot fail again.
        if plain and "plain_epipe_exit1" in MUT:
            err("panicked: failed printing to stdout: Broken pipe")
            exit_code = 1
        nul = os.open(os.devnull, os.O_WRONLY)
        os.dup2(nul, 1)
        os.close(nul)
    sys.exit(exit_code)


def err(msg):
    sys.stderr.write("heimdall-proto: %s\n" % msg)
    sys.stderr.flush()


def result(state, code, data=None, warnings=None):
    return {"schema_version": "1", "state": state, "code": code, "data": data,
            "warnings": warnings or [], "next": None}


def fail(code, exit_code, key_path, message, warnings=None, use_json=True):
    err("%s: %s" % (code, message))
    if exit_code == EXIT_USAGE and code == "SCHEMA_INVALID" and "wrong_exit_schema" in MUT:
        exit_code = 1
    if "--json" not in sys.argv and code == "SCHEMA_INVALID" and "plain_exit_wrong" in MUT:
        exit_code = 1
    if use_json:
        out_json(result("failed", code, {"error": {"key_path": key_path, "message": message}}, warnings), exit_code)
    sys.exit(exit_code)


def usage(msg, use_json):
    err(msg)
    if "usage_plain_stdout" in MUT and not use_json:
        sys.stdout.write("usage: heimdall-proto profile|agent|run|tui|version\n")
        sys.stdout.flush()
    if use_json and "usage_json_missing" not in MUT:
        out_json(result("failed", "USAGE_ERROR", {"error": {"key_path": None, "message": msg}}), EXIT_USAGE)
    sys.exit(EXIT_USAGE)


def parse_flags(args, valued, boolean, use_json):
    """Return dict of flags; any unknown flag or missing value is a usage error."""
    flags = {}
    i = 0
    while i < len(args):
        a = args[i]
        if a in valued:
            if i + 1 >= len(args):
                usage("flag %s needs a value" % a, use_json)
            flags[a] = args[i + 1]
            i += 2
        elif a in boolean:
            flags[a] = True
            i += 1
        else:
            usage("unknown argument", use_json)
    return flags


# --------------------------------------------------------------------------
# profile show
ALLOWED_TOP = {"schema_version", "name", "revision", "meta", "destinations"}
ALLOWED_DEST = {"id", "alias", "host", "port", "account", "labels"}


def is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def is_control(cp):
    """C0 (U+0000-U+001F), DEL (U+007F) or C1 (U+0080-U+009F) code point (contract K1/K2)."""
    if "profile_c1_ok" in MUT and 0x80 <= cp <= 0x9F:
        return False
    return cp <= 0x1F or 0x7F <= cp <= 0x9F


def has_control(text):
    if "profile_control_chars_ok" in MUT:
        return False
    return any(is_control(ord(c)) for c in text)


def control_in_meta(v):
    if isinstance(v, str):
        return any(ord(c) <= 0x1F or 0x7F <= ord(c) <= 0x9F for c in v)
    if isinstance(v, dict):
        return any(control_in_meta(k) or control_in_meta(x) for k, x in v.items())
    if isinstance(v, list):
        return any(control_in_meta(x) for x in v)
    return False


def validate_profile(doc):
    """Return (profile_dict, None) or (None, (key_path, message, warnings))."""
    def bad(path, msg, warnings=None, value=None):
        if "canary_echo" in MUT and value is not None:
            msg = "%s (value: %s)" % (msg, value)
        return None, (path, msg, warnings or [])

    if "schema_version" not in doc:
        return bad("schema_version", "missing required key")
    sv = doc["schema_version"]
    if not (is_int(sv) and sv == 1):
        warnings = [] if "schema_version_no_warning" in MUT else [
            "unsupported schema_version %s" % (sv if is_int(sv) else "(non-integer)")]
        if warnings and "schema_version_warning_echoes_name" in MUT:
            warnings[0] += " in profile %r" % (doc.get("name"),)
        return bad("schema_version", "unsupported schema_version", warnings)
    for k in doc:
        if k not in ALLOWED_TOP:
            return bad(k, "unknown key", value=doc[k])
    if not isinstance(doc.get("name"), str) or not doc["name"]:
        return bad("name", "name must be a non-empty string")
    if has_control(doc["name"]):
        return bad("name", "control character in string value", value=doc["name"])
    if "profile_meta_control_rejected" in MUT and control_in_meta(doc.get("meta")):
        return bad("meta", "control character in string value")
    rev = doc.get("revision")
    rev_int = is_int(rev) or ("accept_bool_revision" in MUT and isinstance(rev, bool))
    if not rev_int or rev < 1:
        if "stderr_echoes_value" in MUT:
            err("hint: revision value %r" % (rev,))
        if "type_error_echoes_value" in MUT:
            return bad("revision", "revision must be an integer >= 1, got %r" % (rev,))
        return bad("revision", "revision must be an integer >= 1")
    dests = doc.get("destinations", [])
    if not isinstance(dests, list) or not all(isinstance(d, dict) for d in dests):
        return bad("destinations", "destinations must be an array of tables")
    out = []
    ids, aliases = set(), set()
    for n, d in enumerate(dests):
        base = "destinations[%d]" % n
        for k in d:
            if k not in ALLOWED_DEST:
                return bad("%s.%s" % (base, k), "unknown key", value=d[k])
        for k in ("id", "alias", "host", "account"):
            if not isinstance(d.get(k), str) or not d[k]:
                return bad("%s.%s" % (base, k), "required string missing or empty")
            if has_control(d[k]):
                return bad("%s.%s" % (base, k), "control character in string value", value=d[k])
        port = d.get("port", 2222 if "port_default_wrong" in MUT else 22)
        if not is_int(port) or not 1 <= port <= 65535:
            if "stderr_echoes_value" in MUT:
                err("hint: port value %r" % (port,))
            if "type_error_echoes_value" in MUT:
                return bad("%s.port" % base, "port must be an integer in 1..65535, got %r" % (port,))
            return bad("%s.port" % base, "port must be an integer in 1..65535")
        labels = d.get("labels", [])
        if not isinstance(labels, list) or not all(isinstance(x, str) for x in labels):
            return bad("%s.labels" % base, "labels must be an array of strings")
        for li, lab in enumerate(labels):
            if has_control(lab) and "profile_label_control_ok" not in MUT:
                return bad("%s.labels[%d]" % (base, li), "control character in string value", value=lab)
        if d["id"] in ids:
            if "stderr_echoes_value" in MUT:
                err("hint: duplicate id %r" % (d["id"],))
            return bad("%s.id" % base, "duplicate id")
        if d["alias"] in aliases:
            if "stderr_echoes_value" in MUT:
                err("hint: duplicate alias %r" % (d["alias"],))
            return bad("%s.alias" % base, "duplicate alias")
        ids.add(d["id"])
        aliases.add(d["alias"])
        out.append({"id": d["id"], "alias": d["alias"], "host": d["host"], "port": port,
                    "account": d["account"], "labels": list(labels)})
    if "sort_destinations" in MUT:
        out.sort(key=lambda x: x["alias"])
    prof = {"name": doc["name"], "revision": rev, "destinations": out}
    if "meta_echo" in MUT and "meta" in doc:
        prof["meta"] = doc["meta"]
    return prof, None


def load_profile_file(path):
    """Return the parsed profile or exit with the contract's error result."""
    # K14: never block on a FIFO; only a regular file is a profile.
    flags = os.O_RDONLY if "nonregular_file_accepted" in MUT else os.O_RDONLY | os.O_NONBLOCK
    try:
        fd = os.open(path, flags)
    except OSError:
        fail("USAGE_ERROR", EXIT_USAGE, None, "cannot read file")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) and "nonregular_file_accepted" not in MUT:
            fail("USAGE_ERROR", EXIT_USAGE, None, "not a regular file")
        size = st.st_size
        too_big = size >= MAX_FILE if "oversize_off_by_one" in MUT else size > MAX_FILE
        if too_big and "ignore_oversize" not in MUT:
            fail("INPUT_TOO_LARGE", EXIT_USAGE, None, "input exceeds 1048576 bytes")
        chunks = []
        try:
            while True:
                b = os.read(fd, 65536)
                if not b:
                    break
                chunks.append(b)
        except OSError:
            fail("USAGE_ERROR", EXIT_USAGE, None, "cannot read file")
        raw = b"".join(chunks)
    finally:
        os.close(fd)
    try:
        doc = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        if "malformed_echo_source_line" in MUT and isinstance(exc, tomllib.TOMLDecodeError):
            import re
            m = re.search(r"at line (\d+)", str(exc))
            if m:
                src = raw.decode("utf-8", "replace").splitlines()
                n = int(m.group(1))
                if 1 <= n <= len(src):
                    err("TOML error at line %d:\n  %d | %s" % (n, n, src[n - 1]))
        fail("SCHEMA_INVALID", EXIT_USAGE, None, "malformed TOML")
    except RecursionError:
        # K15: nesting deeper than the parser's recursion limit is rejected, quickly and boundedly
        if "parser_deep_crash" in MUT:
            raise
        if "parser_deep_slow" in MUT:
            time.sleep(2.5)
        if "parser_deep_memory" in MUT:
            ballast = b"x" * (320 << 20)
            os.write(2, b"%d\n" % len(ballast))
        fail("SCHEMA_INVALID", EXIT_USAGE, None, "nesting too deep")
    prof, bad = validate_profile(doc)
    if bad:
        fail("SCHEMA_INVALID", EXIT_USAGE, bad[0], bad[1], bad[2])
    return prof


def cmd_profile(args):
    use_json = "--json" in args
    if not args or args[0] != "show":
        usage("unknown profile subcommand", use_json)
    flags = parse_flags(args[1:], {"--file"}, {"--json"}, use_json)
    if "--file" not in flags:
        usage("missing --file", use_json)
    if "stray_write" in MUT:
        with open("stray-cache.tmp", "w") as fh:
            fh.write("x")
    if "stray_tmp_write" in MUT:
        with open(os.path.join(os.environ.get("TMPDIR", "/tmp"), "hm-ref-extracted.bin"), "w") as fh:
            fh.write("x")
    prof = load_profile_file(flags["--file"])
    out_json(result("succeeded", "PROFILE_OK", {"profile": prof}), 0)


# --------------------------------------------------------------------------
# agent list
class Cancelled(Exception):
    pass


class AgentFail(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code, self.msg = code, msg


_cancel = {"flag": False}


def _on_sigint(signum, frame):
    _cancel["flag"] = True


_timeout = {"s": 5.0}


def _wait_readable(sock, deadline):
    if "agent_per_read_timeout" in MUT:
        deadline = time.monotonic() + _timeout["s"]     # mutation: idle timeout per read
    while True:
        if _cancel["flag"]:
            raise Cancelled
        left = deadline - time.monotonic()
        if left <= 0:
            raise AgentFail("AGENT_UNAVAILABLE", "timed out waiting for the agent")
        r, _, _ = select.select([sock], [], [], min(left, 0.01))
        if r:
            return


def _recv_exact(sock, n, deadline, first=False):
    """Read exactly n bytes.  first=True: these are the first reply bytes (contract K3:
    EOF/reset before any reply byte is AGENT_UNAVAILABLE, after >= 1 byte AGENT_PROTOCOL_ERROR)."""
    buf = bytearray()
    while len(buf) < n:
        _wait_readable(sock, deadline)
        try:
            chunk = sock.recv(min(65536, n - len(buf)))
        except ConnectionResetError:     # contract K3a: a reset is classified like EOF
            if "agent_reset_unhandled" in MUT:
                raise
            chunk = b""
        if not chunk:
            nothing = first and not buf
            if "agent_eof_as_protocol" in MUT:
                nothing = False
            if "agent_partial_eof_unavailable" in MUT and first:
                nothing = True
            if nothing:
                raise AgentFail("AGENT_UNAVAILABLE", "agent closed the connection without replying")
            raise AgentFail("AGENT_PROTOCOL_ERROR", "connection closed mid-frame")
        buf += chunk
    return bytes(buf)


def _take_string(buf, pos):
    if pos + 4 > len(buf):
        raise AgentFail("AGENT_PROTOCOL_ERROR", "truncated string length")
    (n,) = struct.unpack(">I", buf[pos:pos + 4])
    pos += 4
    if n > len(buf) - pos:
        if "agent_overrun_ok" in MUT:
            n = len(buf) - pos
        else:
            raise AgentFail("AGENT_PROTOCOL_ERROR", "string exceeds frame")
    return buf[pos:pos + n], pos + n


def sanitize(raw):
    """Contract K1: invalid UTF-8 and every C0/DEL/C1 control code point become U+FFFD."""
    text = raw.decode("utf-8", errors="replace")
    if "agent_control_passthrough" in MUT:
        return text
    def ctl(cp):
        if "agent_c1_passthrough" in MUT:
            return cp <= 0x1F or cp == 0x7F
        return cp <= 0x1F or 0x7F <= cp <= 0x9F
    return "".join("\ufffd" if ctl(ord(c)) else c for c in text)


def parse_identities(body):
    pos = 1
    if len(body) < 5 and "agent_short_answer_crash" not in MUT:
        raise AgentFail("AGENT_PROTOCOL_ERROR", "short identities answer")
    (nkeys,) = struct.unpack(">I", body[1:5])
    pos = 5
    limit_hit = nkeys >= MAX_KEYS if "agent_nkeys_off_by_one" in MUT else nkeys > MAX_KEYS
    if limit_hit and "agent_ignore_nkeys" not in MUT:
        raise AgentFail("AGENT_PROTOCOL_ERROR", "too many keys")
    ids = []
    for _ in range(nkeys):
        if ("agent_ignore_nkeys" in MUT or "agent_nkeys_short_ok" in MUT) and pos >= len(body):
            break
        blob, pos = _take_string(body, pos)
        comment, pos = _take_string(body, pos)
        kt, _ = _take_string(blob, 0)
        if "agent_keytype_strict" in MUT:
            try:
                kt.decode("utf-8")
            except UnicodeDecodeError:
                raise AgentFail("AGENT_PROTOCOL_ERROR", "bad key type")
        key_type = kt.decode("utf-8", errors="replace") if "agent_keytype_unsanitized" in MUT else sanitize(kt)
        if "agent_comment_strict" in MUT:
            try:
                ctext = comment.decode("utf-8")
            except UnicodeDecodeError:
                raise AgentFail("AGENT_PROTOCOL_ERROR", "bad comment")
        else:
            ctext = sanitize(comment)
        fp = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii")
        if "agent_fp_wrong" not in MUT:
            fp = fp.rstrip("=")
        ident = {"key_type": key_type, "fingerprint": "SHA256:" + fp, "comment": ctext}
        if "agent_emit_blob" in MUT:
            ident["blob"] = base64.b64encode(blob).decode("ascii")
        ids.append(ident)
    if pos != len(body) and "agent_accept_trailing" not in MUT:
        raise AgentFail("AGENT_PROTOCOL_ERROR", "trailing bytes after last key")
    return ids


def agent_list(path, timeout_s):
    _timeout["s"] = timeout_s
    deadline = time.monotonic() + (4.0 if "agent_no_timeout" in MUT else timeout_s)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        try:
            s.settimeout(max(0.05, timeout_s))
            s.connect(path)
        except (OSError, ValueError):
            code = "AGENT_PROTOCOL_ERROR" if "agent_connect_fail_protocol" in MUT else "AGENT_UNAVAILABLE"
            raise AgentFail(code, "cannot connect to agent socket")
        s.setblocking(False)
        s.sendall(struct.pack(">IB", 1, 11))
        if "agent_extra_request" in MUT:
            s.sendall(struct.pack(">IB", 1, 11))
        if "agent_other_type" in MUT:
            s.sendall(struct.pack(">IB", 1, 1))
        if "agent_single_read" in MUT:
            _wait_readable(s, deadline)
            data = s.recv(65536)
            if len(data) < 5:
                raise AgentFail("AGENT_PROTOCOL_ERROR", "short read")
            (length,) = struct.unpack(">I", data[:4])
            body = data[4:4 + length]
            if len(body) != length:
                raise AgentFail("AGENT_PROTOCOL_ERROR", "truncated frame")
        else:
            (length,) = struct.unpack(">I", _recv_exact(s, 4, deadline, first=True))
            over = length >= MAX_FRAME if "agent_frame_off_by_one" in MUT else length > MAX_FRAME
            if over and "agent_ignore_frame_bound" not in MUT:
                raise AgentFail("AGENT_PROTOCOL_ERROR", "frame too large")
            if length == 0 and "agent_zero_frame_crash" not in MUT:
                raise AgentFail("AGENT_PROTOCOL_ERROR", "empty frame")
            if over:  # mutation: trust the length and wait for the bytes
                body = _recv_exact(s, length, deadline)
            else:
                body = _recv_exact(s, length, deadline)
        mtype = body[0]
        if mtype == 5 and len(body) != 1 and "agent_failure_payload_refused" not in MUT:
            raise AgentFail("AGENT_PROTOCOL_ERROR", "SSH_AGENT_FAILURE frame with payload")
        if mtype == 5:
            code = "AGENT_PROTOCOL_ERROR" if "agent_refused_as_protocol" in MUT else "AGENT_REFUSED"
            raise AgentFail(code, "agent refused the request")
        if mtype != 12:
            if "agent_wrong_type_ok" in MUT:
                return []
            raise AgentFail("AGENT_PROTOCOL_ERROR", "unexpected message type")
        return parse_identities(body)
    finally:
        s.close()


def cmd_agent(args):
    use_json = "--json" in args
    if not args or args[0] != "list":
        usage("unknown agent subcommand", use_json)
    flags = parse_flags(args[1:], {"--socket", "--timeout-ms"}, {"--json"}, use_json)
    if "--socket" not in flags:
        usage("missing --socket", use_json)
    try:
        timeout_ms = int(flags.get("--timeout-ms", "60000" if "agent_default_timeout_60s" in MUT else "5000"))
        if timeout_ms <= 0:
            raise ValueError
    except ValueError:
        usage("--timeout-ms must be a positive integer", use_json)
    signal.signal(signal.SIGINT, _on_sigint)
    try:
        ids = agent_list(flags["--socket"], timeout_ms / 1000.0)
    except Cancelled:
        if "agent_sigint_slow" in MUT:
            time.sleep(0.8)
        err("cancelled")
        out_json(result("cancelled", "CANCELLED", None), 1 if "agent_sigint_wrong_exit" in MUT else 130)
    except AgentFail as e:
        fail(e.code, EXIT_DEP, None, e.msg)
    out_json(result("succeeded", "AGENT_OK", {"identities": ids}), 0)


# --------------------------------------------------------------------------
# run
FORWARD = [signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT, signal.SIGWINCH]


def write_meta(path, code, launched, exit_code, sig):
    if not path:
        return
    state = "succeeded" if code == "CHILD_EXITED" else "failed"     # contract K5
    if "run_meta_state_by_exit" in MUT and code == "CHILD_EXITED" and exit_code != 0:
        state = "failed"
    if "run_meta_launch_state_ok" in MUT and code == "CHILD_LAUNCH_FAILED":
        state = "succeeded"
    doc = result(state, code, {"launched": launched, "exit_code": exit_code, "signal": sig})
    if "run_meta_tmp_left" in MUT:
        import shutil
        with open(path + ".tmp", "w", encoding="utf-8") as fh:
            fh.write(json.dumps(doc, ensure_ascii=False) + "\n")
        shutil.copyfile(path + ".tmp", path)
        return
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(doc, ensure_ascii=False) + "\n")


STOP_GRACE_S = 0.2


def wait_mirroring_stops(child):
    """Wait for the child's exit; when the child stops (also by itself, e.g. kill(getpid(), SIGTSTP) as OpenSSH's
    ~^Z escape does), stop heimdall-proto too, so the shell that waits for heimdall-proto sees the job stop (K6e,
    section 9.4).  The child shares heimdall-proto's process group, so the shell's `fg`/`bg` (SIGCONT to the group)
    continues both.  A stop report can be stale when it is read: a terminal Ctrl-Z stops the whole group, and the
    shell's `fg` continues it member by member, so heimdall-proto may run again and read the child's stop report
    before the child has been continued (seen on darwin: a re-stop after `fg`).  So a stop is mirrored only if no
    'continued' (or exit) report follows within STOP_GRACE_S; a stale report must not stop heimdall-proto again."""
    flags = os.WUNTRACED | os.WCONTINUED
    while True:
        try:
            _pid, st = os.waitpid(child.pid, flags)
        except ChildProcessError:            # reaped by Popen.send_signal's poll() in a forwarding handler
            return child.returncode
        if os.WIFCONTINUED(st):
            continue
        while os.WIFSTOPPED(st):
            end = time.monotonic() + STOP_GRACE_S
            while True:
                try:
                    _pid, st2 = os.waitpid(child.pid, flags | os.WNOHANG)
                except ChildProcessError:
                    return child.returncode
                if _pid != 0 or time.monotonic() >= end:
                    break
                time.sleep(0.005)
            if _pid == 0:                     # still stopped: mirror the stop to the shell
                sig = os.WSTOPSIG(st)
                if sig not in (signal.SIGTSTP, signal.SIGTTIN, signal.SIGTTOU) or signal.getsignal(sig) != signal.SIG_DFL:
                    sig = signal.SIGSTOP
                os.kill(os.getpid(), sig)
                break
            st = st2
        if os.WIFSTOPPED(st) or os.WIFCONTINUED(st):
            continue
        rc = -os.WTERMSIG(st) if os.WIFSIGNALED(st) else os.WEXITSTATUS(st)
        child.returncode = rc
        return rc


def cmd_run(args):
    meta = None
    i = 0
    while i < len(args) and args[i] != "--":
        if args[i] == "--meta-file" and i + 1 < len(args):
            meta = args[i + 1]
            i += 2
        else:
            if "run_no_dashdash_ok" in MUT:
                break
            usage("expected --meta-file <path> then -- <argv...>", False)
    if i >= len(args):
        usage("missing --", False)
    argv = args[i + 1:] if args[i] == "--" else args[i:]
    if not argv:
        usage("empty command", False)
    if "run_strip_empty_arg" in MUT:
        argv = [a for a in argv if a != ""]
    if "run_argv_lossy" in MUT:
        argv = [os.fsencode(a).decode("utf-8", "replace") for a in argv]
    if "run_stderr_noise" in MUT:
        err("starting child")
    popen_kw = {}
    if "run_drop_env" in MUT:
        popen_kw["env"] = {"PATH": os.environ.get("PATH", "")}
    if "run_drop_cwd" in MUT:
        popen_kw["cwd"] = "/"
    if "run_text_mode" in MUT:
        popen_kw["stdout"] = subprocess.PIPE
    if "run_stdin_devnull" in MUT:
        popen_kw["stdin"] = subprocess.DEVNULL
    if "run_pipe_stdio" in MUT:
        popen_kw["stdout"] = subprocess.PIPE
        popen_kw["stderr"] = subprocess.PIPE
    # K6a: a signal inherited as ignored stays ignored in the child (exec semantics) and is not forwarded.
    inherited_ign = set(s for s in FORWARD if signal.getsignal(s) == signal.SIG_IGN)
    if "run_reset_ignored_in_child" in MUT:
        for s in inherited_ign:
            signal.signal(s, signal.SIG_DFL)
        inherited_ign = set()
    if "run_forward_ignored" in MUT:
        inherited_ign = set()
    fg_tty = None
    if "run_takes_foreground" in MUT:
        # mutation: shell-style job control on the controlling terminal, even as a member of another job
        try:
            fg_tty = os.open("/dev/tty", os.O_RDWR)
            popen_kw["process_group"] = 0
            signal.signal(signal.SIGTTOU, signal.SIG_IGN)
        except OSError:
            fg_tty = None
    job_control = "run_tty_no_forward" in MUT and os.isatty(0)
    if job_control:
        # mutation: shell-style job control - the child becomes the foreground process group and
        # heimdall-proto relies on the terminal alone (explicit signals to it are dropped).
        signal.signal(signal.SIGTTOU, signal.SIG_IGN)
        popen_kw["process_group"] = 0
    JC = False
    if ("run_job_control_own_group" in MUT or "run_child_stop_no_continue" in MUT) and os.isatty(0) and os.isatty(1):
        try:
            JC = os.getpgrp() == os.getpid() and os.tcgetpgrp(0) == os.getpgrp()
        except OSError:
            JC = False
    if "run_child_sigpipe_ignored" in MUT:
        popen_kw["restore_signals"] = False       # mutation: the child inherits CPython's own SIGPIPE ignore
    if JC:
        def _jc_pre():
            signal.signal(signal.SIGTTOU, signal.SIG_IGN)
            os.setpgid(0, 0)
            try:
                os.tcsetpgrp(0, os.getpid())
            except OSError:
                pass
            signal.signal(signal.SIGTTOU, signal.SIG_DFL)
        popen_kw["preexec_fn"] = _jc_pre
        signal.signal(signal.SIGTTOU, signal.SIG_IGN)
    try:
        if "run_shell" in MUT:
            child = subprocess.Popen(" ".join(argv), shell=True, **popen_kw)
        else:
            child = subprocess.Popen(argv, **popen_kw)
    except OSError as e:
        err("cannot launch %s: %s" % (os.fsdecode(argv[0]) if argv[0] else "(empty)", errno.errorcode.get(e.errno, "error")))
        write_meta(meta, "CHILD_LAUNCH_FAILED", "run_meta_launch_ok" in MUT, None, None)
        sys.exit(126 if "run_launch_126" in MUT else 127)

    shared_drop = set()
    if "run_shared_drop" in MUT:
        # mutation (K6d): a Go-style "shared mode" that treats SIGINT/SIGHUP/SIGQUIT/SIGWINCH as terminal-generated
        # whenever its group holds the terminal foreground and it is not alone, and drops them
        try:
            tfd = os.open("/dev/tty", os.O_RDONLY | os.O_NOCTTY | os.O_NONBLOCK)
        except OSError:
            tfd = None
        if tfd is not None:
            try:
                piped = False
                for fd in (0, 1):
                    try:
                        m = os.fstat(fd).st_mode
                        piped = piped or stat.S_ISFIFO(m) or stat.S_ISSOCK(m)
                    except OSError:
                        pass
                if (piped or os.getpgrp() != os.getpid()) and os.tcgetpgrp(tfd) == os.getpgrp():
                    shared_drop = {signal.SIGINT, signal.SIGHUP, signal.SIGQUIT, signal.SIGWINCH}
            except OSError:
                pass
            finally:
                os.close(tfd)
    if "run_fg_restop_late" in MUT and os.isatty(0):
        lfc = {"n": 0}

        def on_cont_late(signum, frame):
            # mutation (K6e): the second continue into the terminal foreground (`fg`) re-stops the job 700 ms later
            end = time.monotonic() + 0.2
            while True:
                try:
                    if os.tcgetpgrp(0) == os.getpgrp():
                        break
                except OSError:
                    return
                if time.monotonic() > end:
                    return              # a `bg` continue
                time.sleep(0.005)
            lfc["n"] += 1
            if lfc["n"] == 2:
                time.sleep(0.7)
                os.kill(0, signal.SIGTSTP)
        signal.signal(signal.SIGCONT, on_cont_late)
    if "run_fg_restop" in MUT and os.isatty(0):
        fgc = {"n": 0}

        def on_cont(signum, frame):
            # mutation (K6e): the third continue into the terminal foreground (`fg`) re-stops the job at once.
            # A shell may send SIGCONT just before it hands over the terminal: allow 200 ms for the handover.
            end = time.monotonic() + 0.2
            while True:
                try:
                    if os.tcgetpgrp(0) == os.getpgrp():
                        break
                except OSError:
                    return
                if time.monotonic() > end:
                    return              # a `bg` continue
                time.sleep(0.005)
            fgc["n"] += 1
            if fgc["n"] == 3:
                os.kill(0, signal.SIGTSTP)
        signal.signal(signal.SIGCONT, on_cont)

    copiers = []
    if "run_pipe_stdio" in MUT:
        import threading

        def copy(src, fd):
            while True:
                b = os.read(src.fileno(), 65536)
                if not b:
                    break
                while b:
                    b = b[os.write(fd, b):]
        copiers = [threading.Thread(target=copy, args=(child.stdout, 1), daemon=True),
                   threading.Thread(target=copy, args=(child.stderr, 2), daemon=True)]
        for th in copiers:
            th.start()
    seen = {"n": 0}

    def forward(signum, frame):
        if signum in shared_drop:
            return                            # mutation run_shared_drop: silently lost
        if "run_second_signal_force_quit" in MUT and signum in (signal.SIGINT, signal.SIGTERM):
            seen["n"] += 1
            if seen["n"] >= 2:
                os._exit(130)                 # mutation: "press Ctrl-C again to force quit"
        if "run_no_forward_term" in MUT and signum == signal.SIGTERM:
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
            os.kill(os.getpid(), signal.SIGTERM)
            return
        if "run_kill_child_early" in MUT and signum == signal.SIGTERM:
            child.kill()
            return
        try:
            child.send_signal(signum)
            if "run_double_signal" in MUT:
                child.send_signal(signum)
        except ProcessLookupError:
            pass
        if "run_forward_then_exit" in MUT and signum in (signal.SIGTERM, signal.SIGINT):
            os._exit(143)

    if fg_tty is not None:
        try:
            os.tcsetpgrp(fg_tty, child.pid)
        except OSError:
            pass
    if job_control:
        try:
            os.tcsetpgrp(0, child.pid)
        except OSError:
            pass
        for s in FORWARD:
            signal.signal(s, signal.SIG_IGN)
    else:
        for s in FORWARD:
            if s not in inherited_ign:
                signal.signal(s, forward)
    if "run_text_mode" in MUT:
        # mutation: the child's stdout is re-coded through text (lossy for binary data).  Copied chunk by chunk, and
        # copying stops when heimdall-proto's own stdout reader has gone (closing the pipe ends the child with
        # EPIPE/SIGPIPE): reading an endless child (the K6c `yes` probe) into memory exhausted the Linux runner's
        # 2 GiB container limit and the kernel killed the harness (round-6 self-test).
        while True:
            chunk = os.read(child.stdout.fileno(), 65536)
            if not chunk:
                break
            try:
                sys.stdout.buffer.write(chunk.decode("utf-8", "replace").encode("utf-8"))
                sys.stdout.buffer.flush()
            except BrokenPipeError:
                nul = os.open(os.devnull, os.O_WRONLY)
                os.dup2(nul, 1)
                os.close(nul)
                break
        child.stdout.close()
    if JC:
        def jc_on_cont(signum, frame):
            if "run_child_stop_no_continue" in MUT:
                return              # mutation: the child is never handed the terminal or continued on `fg`
            end = time.monotonic() + 0.2
            fgnow = False
            while True:
                try:
                    if os.tcgetpgrp(0) == os.getpgrp():
                        fgnow = True
                        break
                except OSError:
                    break
                if time.monotonic() > end:
                    break
                time.sleep(0.005)
            if fgnow:
                try:
                    os.tcsetpgrp(0, child.pid)
                except OSError:
                    pass
            try:
                os.killpg(child.pid, signal.SIGCONT)
            except OSError:
                pass
        signal.signal(signal.SIGCONT, jc_on_cont)
        while True:
            _pid, _st = os.waitpid(child.pid, os.WUNTRACED)
            if os.WIFSTOPPED(_st):
                # bash sends no SIGCONT when `fg` takes a job that is already running (after `bg`): the child
                # then stops with SIGTTIN/SIGTTOU on its next terminal access; if heimdall-proto holds the
                # foreground now, hand the terminal over and continue the child
                if os.WSTOPSIG(_st) in (signal.SIGTTIN, signal.SIGTTOU):
                    try:
                        _isfg = os.tcgetpgrp(0) == os.getpgrp()
                    except OSError:
                        _isfg = False
                    if _isfg:
                        try:
                            os.tcsetpgrp(0, child.pid)
                        except OSError:
                            pass
                        os.killpg(child.pid, signal.SIGCONT)
                        continue
                try:
                    os.tcsetpgrp(0, os.getpgrp())
                except OSError:
                    pass
                os.kill(os.getpid(), signal.SIGSTOP)
                continue
            rc = -os.WTERMSIG(_st) if os.WIFSIGNALED(_st) else os.WEXITSTATUS(_st)
            child.returncode = rc
            break
        try:
            os.tcsetpgrp(0, os.getpgrp())
        except OSError:
            pass
    elif "run_ignore_child_stop" in MUT:
        rc = child.wait()           # mutation: waits only for the exit; a child's own stop goes unnoticed
    else:
        rc = wait_mirroring_stops(child)
    for th in copiers:
        th.join()
    if fg_tty is not None:
        try:
            os.tcsetpgrp(fg_tty, os.getpgrp())
        except OSError:
            pass
    if job_control:
        try:
            os.tcsetpgrp(0, os.getpgrp())
        except OSError:
            pass
    if rc < 0:
        sig = -rc
        code = 1 if "run_signal_exit_wrong" in MUT else 128 + sig
        if "run_meta_exit_for_signal" in MUT:
            write_meta(meta, "CHILD_EXITED", True, 128 + sig, None)
        else:
            write_meta(meta, "CHILD_EXITED", True, None, sig)
    else:
        code = 1 if (rc == 255 and "run_exit_255_to_1" in MUT) else rc
        write_meta(meta, "CHILD_EXITED", True, rc, None)
    if "run_extra_stdout" in MUT:
        sys.stdout.write("\n")
        sys.stdout.flush()
    sys.exit(code)


# --------------------------------------------------------------------------
def cmd_version(args):
    use_json = "--json" in args
    parse_flags(args, set(), {"--json"}, use_json)
    if "version_tput_probe" in MUT and os.environ.get("TERM_PROGRAM"):
        try:
            subprocess.run(["tput", "colors"], capture_output=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            pass
    cand = "rust" if "version_wrong_candidate" in MUT else os.environ.get("REF_CANDIDATE", "go")
    out_json(result("succeeded", "VERSION_OK", {
        "name": "heimdall-proto", "version": "0.0.0-g02", "candidate": cand,
        "runtime": "python-%d.%d.%d (reference)" % sys.version_info[:3],
        "tui_framework": "reference_tui (raw ANSI)", "tui_framework_version": "0"}), 0)


def cmd_tui(args):
    flags = parse_flags(args, {"--file"}, set(), False)
    if "--file" not in flags:
        usage("missing --file", False)
    sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
    import reference_tui
    prof = load_profile_file(flags["--file"])
    sys.exit(reference_tui.run(prof["destinations"], MUT, usage))


def main():
    args = sys.argv[1:]
    use_json = "--json" in args
    if not args:
        usage("missing subcommand", use_json)
    cmd, rest = args[0], args[1:]
    if cmd == "profile":
        cmd_profile(rest)
    elif cmd == "agent":
        cmd_agent(rest)
    elif cmd == "run":
        cmd_run(rest)
    elif cmd == "version":
        cmd_version(rest)
    elif cmd == "tui":
        cmd_tui(rest)
    else:
        usage("unknown subcommand", use_json)


if __name__ == "__main__":
    main()
