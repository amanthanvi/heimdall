#!/usr/bin/env python3
"""Does the TUI execute programs found on PATH or write files controlled by env vars?

Usage: tui_env_probe.py <bin> <profile.toml> <out-json>
"""
import json, os, pty, select, signal, sys, tempfile, time

BIN, PROF, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
results = []


def run(name, extra_env, fake_tmux=True, tmux_sleep=0):
    d = tempfile.mkdtemp(prefix="hrg-tuienv-")
    fb = os.path.join(d, "fakebin")
    os.mkdir(fb)
    marker = os.path.join(d, "TMUX_WAS_EXECUTED")
    if fake_tmux:
        with open(os.path.join(fb, "tmux"), "w") as f:
            f.write("#!/bin/sh\necho \"$@\" > '%s'\nsleep %d\necho 'Tc: (flag) true'\n" % (marker, tmux_sleep))
        os.chmod(os.path.join(fb, "tmux"), 0o755)
    home = os.path.join(d, "home"); os.mkdir(home)
    env = {"PATH": fb + ":/usr/bin:/bin", "HOME": home, "TMPDIR": home, "TERM": "xterm-256color", "LANG": "C.UTF-8"}
    env.update({k: v.replace("@D", d) for k, v in extra_env.items()})
    before = set(os.listdir(d))
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(home)
        os.execve(BIN, [BIN, "tui", "--file", PROF], env)
    buf = bytearray()
    t_start = time.monotonic()
    first_alt = None
    end = time.monotonic() + 1.5 + tmux_sleep
    while time.monotonic() < end:
        r, _, _ = select.select([fd], [], [], 0.05)
        if r:
            try:
                buf.extend(os.read(fd, 65536))
            except OSError:
                break
            if first_alt is None and b"\x1b[?1049h" in buf:
                first_alt = round(time.monotonic() - t_start, 3)
    os.write(fd, b"q")
    end = time.monotonic() + 3
    status = None
    while time.monotonic() < end:
        r, _, _ = select.select([fd], [], [], 0.05)
        if r:
            try:
                b = os.read(fd, 65536)
                if not b:
                    break
                buf.extend(b)
            except OSError:
                break
        wp, st = os.waitpid(pid, os.WNOHANG)
        if wp:
            status = st
            break
    if status is None:
        os.kill(pid, signal.SIGKILL)
        _, status = os.waitpid(pid, 0)
    os.close(fd)
    created = sorted(set(os.listdir(d)) - before) + [os.path.join("home", x) for x in os.listdir(home)]
    r = {"case": name, "env_added": list(extra_env.keys()), "exit": os.waitstatus_to_exitcode(status),
         "tmux_executed": os.path.exists(marker),
         "tmux_args": open(marker).read().strip() if os.path.exists(marker) else None,
         "files_created": created,
         "truecolor_sgr_seen": b"38;2;" in buf or b"48;2;" in buf, "alt_screen_entered_after_s": first_alt}
    results.append(r)
    print(json.dumps(r))


run("baseline_no_tmux_env", {})
run("TMUX_set", {"TMUX": "/tmp/fake-tmux-sock,1,0"})
run("TMUX_set_tmux_hangs_5s", {"TMUX": "/tmp/fake-tmux-sock,1,0"}, tmux_sleep=5)
run("UV_DEBUG_set", {"UV_DEBUG": "@D/uv-debug.log"})
run("TEA_TRACE_and_TEA_DEBUG_set", {"TEA_TRACE": "@D/tea-trace.log", "TEA_DEBUG": "true"})
json.dump({"bin": BIN, "results": results}, open(OUT, "w"), indent=1)
