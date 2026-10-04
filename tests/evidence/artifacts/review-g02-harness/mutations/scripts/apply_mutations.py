#!/usr/bin/env python3
"""Reviewer-owned mutations of the G02 reference implementation (copy in /tmp only).

Each mutation is selected with REV_MUTATE=name[,name].  The original harness files are never edited.
"""
import re
import sys
from pathlib import Path

D = Path(__file__).resolve().parent
impl = (D / "reference_impl.py").read_text()
tui = (D / "reference_tui.py").read_text()


def sub(text, old, new, count=1):
    if text.count(old) < 1:
        sys.exit("pattern not found: %r" % old[:80])
    return text.replace(old, new, count)


# ---------------------------------------------------------------- reference_impl.py
impl = sub(impl, 'MUT = set(x for x in os.environ.get("REF_MUTATE", "").split(",") if x)\n',
           'MUT = set(x for x in os.environ.get("REF_MUTATE", "").split(",") if x)\n'
           'RM = set(x for x in os.environ.get("REV_MUTATE", "").split(",") if x)\n'
           '_TO = {"s": 5.0}\n')

# P1 type_error_echoes_value: serde-style messages that quote the offending value
impl = sub(impl, '        return bad("revision", "revision must be an integer >= 1")\n',
           '        return bad("revision", "revision must be an integer >= 1" + (" (invalid value: %r)" % (rev,) if "type_error_echoes_value" in RM else ""))\n')
impl = sub(impl, '            return bad("%s.port" % base, "port must be an integer in 1..65535")\n',
           '            return bad("%s.port" % base, "port must be an integer in 1..65535" + (" (invalid value: %r)" % (port,) if "type_error_echoes_value" in RM else ""))\n')

# P2 malformed_echo_source_line: toml-crate style error snippet showing the source line on stderr
impl = sub(impl, '    except (UnicodeDecodeError, tomllib.TOMLDecodeError):\n        fail("SCHEMA_INVALID", EXIT_USAGE, None, "malformed TOML")\n',
           '    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as _e:\n'
           '        if "malformed_echo_source_line" in RM:\n'
           '            import re as _re\n'
           '            _m = _re.search(r"line (\\d+)", str(_e))\n'
           '            _lines = raw.decode("utf-8", "replace").splitlines()\n'
           '            _n = int(_m.group(1)) if _m else len(_lines)\n'
           '            for _k in range(max(1, _n - 1), min(len(_lines), _n) + 1):\n'
           '                err("  %d | %s" % (_k, _lines[_k - 1]))\n'
           '        fail("SCHEMA_INVALID", EXIT_USAGE, None, "malformed TOML")\n')

# P4 schema_version_warning_echoes_name: warning also quotes another key's value
impl = sub(impl, '            "unsupported schema_version %s" % (sv if is_int(sv) else "(non-integer)")]\n',
           '            "unsupported schema_version %s" % (sv if is_int(sv) else "(non-integer)")\n'
           '            + ((" in profile %s" % doc.get("name")) if "schema_version_warning_echoes_name" in RM else "")]\n')

# P5 dup_check_quadratic: duplicate detection with lists (O(n^2))
impl = sub(impl, '    ids, aliases = set(), set()\n',
           '    ids, aliases = (([], []) if "dup_check_quadratic" in RM else (set(), set()))\n')
impl = sub(impl, '        ids.add(d["id"])\n        aliases.add(d["alias"])\n',
           '        (ids.append if isinstance(ids, list) else ids.add)(d["id"])\n'
           '        (aliases.append if isinstance(aliases, list) else aliases.add)(d["alias"])\n')

# R12 profile_tmp_hardcoded: cache in a hard-coded /tmp path (K11)
impl = sub(impl, '    prof = load_profile_file(flags["--file"])\n    out_json(result("succeeded", "PROFILE_OK", {"profile": prof}), 0)\n',
           '    if "profile_tmp_hardcoded" in RM:\n'
           '        with open("/tmp/hm-review-k11-%d.cache" % os.getuid(), "w") as fh:\n'
           '            fh.write("x")\n'
           '    prof = load_profile_file(flags["--file"])\n    out_json(result("succeeded", "PROFILE_OK", {"profile": prof}), 0)\n')

# A1 agent_per_read_timeout: deadline restarts before every read (like a per-read socket timeout)
impl = sub(impl, '        left = deadline - time.monotonic()\n',
           '        if "agent_per_read_timeout" in RM and not getattr(_wait_readable, "_armed", False):\n'
           '            _wait_readable._armed = True\n'
           '            deadline = time.monotonic() + _TO["s"]\n'
           '        left = deadline - time.monotonic()\n')
impl = sub(impl, '        r, _, _ = select.select([sock], [], [], min(left, 0.01))\n        if r:\n            return\n',
           '        r, _, _ = select.select([sock], [], [], min(left, 0.01))\n        if r:\n'
           '            _wait_readable._armed = False\n            return\n')

# A2 agent_default_timeout_60s
impl = sub(impl, '        timeout_ms = int(flags.get("--timeout-ms", "5000"))\n',
           '        timeout_ms = int(flags.get("--timeout-ms", "60000" if "agent_default_timeout_60s" in RM else "5000"))\n'
           '        _TO["s"] = timeout_ms / 1000.0\n')

# A3 agent_nkeys_short_tolerated: stop at the end of the frame instead of failing (bound still enforced)
impl = sub(impl, '    for _ in range(nkeys):\n',
           '    for _ in range(nkeys):\n'
           '        if "agent_nkeys_short_tolerated" in RM and pos >= len(body):\n'
           '            break\n')

# A4 agent_zero_frame_crash: a length-0 frame is indexed (IndexError traceback, exit 1)
impl = sub(impl, '            if length == 0:\n',
           '            if length == 0 and "agent_zero_frame_crash" not in RM:\n')

# A5 agent_short_answer_crash: type-12 frame shorter than 5 bytes is unpacked (struct.error, exit 1)
impl = sub(impl, '    if len(body) < 5:\n        raise AgentFail("AGENT_PROTOCOL_ERROR", "short identities answer")\n',
           '    if len(body) < 5 and "agent_short_answer_crash" not in RM:\n        raise AgentFail("AGENT_PROTOCOL_ERROR", "short identities answer")\n')

# A6 agent_keyblob_inner_clamp: the key-type string inside key_blob is clamped to the blob
impl = sub(impl, '        kt, _ = _take_string(blob, 0)\n',
           '        if "agent_keyblob_inner_clamp" in RM and len(blob) >= 4:\n'
           '            (_n,) = struct.unpack(">I", blob[:4])\n'
           '            kt = blob[4:4 + _n]\n'
           '        else:\n'
           '            kt, _ = _take_string(blob, 0)\n')

# R11 run_meta_tmp_sibling: meta written via <path>.tmp that is left behind (K11)
impl = sub(impl, '    with open(path, "w", encoding="utf-8") as fh:\n        fh.write(json.dumps(doc, ensure_ascii=False) + "\\n")\n',
           '    if "run_meta_tmp_sibling" in RM:\n'
           '        with open(path + ".tmp", "w", encoding="utf-8") as fh:\n'
           '            fh.write(json.dumps(doc, ensure_ascii=False) + "\\n")\n'
           '    with open(path, "w", encoding="utf-8") as fh:\n        fh.write(json.dumps(doc, ensure_ascii=False) + "\\n")\n')

# R2 run_pump_output: child stdout/stderr are pipes copied byte-exactly by heimdall-proto
# R5 run_child_new_session: child started in a new session (no controlling terminal)
impl = sub(impl, '    if "run_stdin_devnull" in MUT:\n        popen_kw["stdin"] = subprocess.DEVNULL\n',
           '    if "run_stdin_devnull" in MUT:\n        popen_kw["stdin"] = subprocess.DEVNULL\n'
           '    if "run_pump_output" in RM:\n'
           '        popen_kw["stdout"] = subprocess.PIPE\n'
           '        popen_kw["stderr"] = subprocess.PIPE\n'
           '    if "run_child_new_session" in RM:\n'
           '        popen_kw["start_new_session"] = True\n')
impl = sub(impl, '    rc = child.wait()\n',
           '    if "run_pump_output" in RM:\n'
           '        import threading as _th\n'
           '        def _pump(src, fd):\n'
           '            while True:\n'
           '                b = os.read(src.fileno(), 65536)\n'
           '                if not b:\n'
           '                    return\n'
           '                while b:\n'
           '                    b = b[os.write(fd, b):]\n'
           '        _ts = [_th.Thread(target=_pump, args=(child.stdout, 1)), _th.Thread(target=_pump, args=(child.stderr, 2))]\n'
           '        for _t in _ts:\n'
           '            _t.start()\n'
           '    rc = child.wait()\n'
           '    if "run_pump_output" in RM:\n'
           '        for _t in _ts:\n'
           '            _t.join()\n')

# R1 run_second_signal_exits: a second identical SIGINT/SIGTERM forces an immediate exit
impl = sub(impl, '    def forward(signum, frame):\n',
           '    _seen = {}\n\n    def forward(signum, frame):\n'
           '        if "run_second_signal_exits" in RM and signum in (signal.SIGINT, signal.SIGTERM):\n'
           '            _seen[signum] = _seen.get(signum, 0) + 1\n'
           '            if _seen[signum] >= 2:\n'
           '                os._exit(128 + signum)\n')

# ---------------------------------------------------------------- reference_tui.py
tui = sub(tui, 'def run(dests, MUT, usage):\n',
          'RM = set(x for x in os.environ.get("REV_MUTATE", "").split(",") if x)\n\n\ndef run(dests, MUT, usage):\n')
# T1 tui_narrow_threshold_60
tui = sub(tui, '        narrow = cols < 50 and "tui_ignore_resize_hide" not in MUT\n',
          '        narrow = cols < (60 if "tui_narrow_threshold_60" in RM else 50) and "tui_ignore_resize_hide" not in MUT\n')
# T8 tui_status_filter_only_while_typing
tui = sub(tui, '        status = "%d/%d  /%s%s" % (len(sh), len(dests), st["filter"], "_" if st["filtering"] else "")\n',
          '        status = "%d/%d  /%s%s" % (len(sh), len(dests), st["filter"] if (st["filtering"] or "tui_status_filter_only_while_typing" not in RM) else "", "_" if st["filtering"] else "")\n')
# T2 tui_slow_filter: 1.0 s per filter edit on large profiles
tui = sub(tui, '            elif key == "BACKSPACE":\n',
          '            elif key == "BACKSPACE" and "tui_slow_filter" in RM and len(dests) > 50:\n'
          '                time.sleep(1.0)\n'
          '                st["filter"] = st["filter"][:-1]\n'
          '                st["sel"] = 0\n'
          '            elif key == "BACKSPACE":\n')
tui = sub(tui, '                st["filter"] += key\n',
          '                if "tui_slow_filter" in RM and len(dests) > 50:\n'
          '                    time.sleep(1.0)\n'
          '                st["filter"] += key\n')
# K16 tui_stty_absolute / tui_tmux_probe_by_term
tui = sub(tui, '    started = False\n',
          '    if "tui_stty_absolute" in RM:\n'
          '        import subprocess\n'
          '        subprocess.run(["/bin/stty", "-g"], stdin=0, capture_output=True, timeout=5)\n'
          '    if "tui_tmux_probe_by_term" in RM and os.environ.get("TERM", "").startswith(("tmux", "screen")):\n'
          '        import subprocess\n'
          '        try:\n'
          '            subprocess.run(["tmux", "display-message", "-p", "x"], capture_output=True, timeout=5)\n'
          '        except (OSError, subprocess.SubprocessError):\n'
          '            pass\n'
          '    started = False\n')

(D / "reference_impl.py").write_text(impl)
(D / "reference_tui.py").write_text(tui)
print("patched")
