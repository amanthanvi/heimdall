"""M00-T05-r4-x2-xrev-T3-verify: drive the cases in tmux (a real terminal emulator) on a private socket.

Usage: python3 -I tmux_drive.py --socket <name> --bins <bins-dir> --profiles <dir> --cases <cases.json>
                                --sandbox-root <dir> --out <dir> [--reps 3] [--variants default,xterm]
                                [--cases-only R1,R2] <build>...

For every (build, case, TERM variant, repeat): a detached tmux session of the exact size runs the
binary (via a tiny wrapper that waits for a flag file, so `pipe-pane` records every byte the program
writes), keys are sent with `send-keys -H` (exact bytes: UTF-8 of the character, 7f for Backspace, 0d
for Enter), and after the output settles the pane is read with `capture-pane -p` (text), `-p -e`
(with SGR), and `display -p` (cursor position). Ctrl-C (03) ends the program; the session is killed by
its exact name on this socket only.

TERM variants:
  default: TERM as tmux sets it (default-terminal, tmux-256color here), with tmux's own TMUX,
           TMUX_PANE, TERM_PROGRAM and TERM_PROGRAM_VERSION kept: what a tmux user has.
  xterm:   TERM=xterm-256color and no TMUX variables: the cross-review's pyte environment, so the
           program's bytes should be the same and only the terminal differs.
Everything else is the pyte environment: PATH=/usr/bin:/bin, private HOME and TMPDIR, en_US.UTF-8.
Output: <out>/<build>/<case>-<variant>-r<rep>.json (screens after every key, cursor, byte chunks).
"""
import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

KEYS = {"enter": b"\r", "bs": b"\x7f", "esc": b"\x1b", "ctrl-c": b"\x03", "up": b"\x1b[A", "down": b"\x1b[B"}


def esc(b):
    return b.decode("utf-8", "backslashreplace").encode("unicode_escape").decode("ascii")


class Tmux:
    def __init__(self, sock, conf):
        self.sock = sock
        self.conf = conf

    def run(self, *args, check=True):
        r = subprocess.run(["tmux", "-L", self.sock, "-f", self.conf] + list(args), capture_output=True)
        if check and r.returncode != 0:
            raise RuntimeError("tmux %s: rc=%d %s" % (args[0], r.returncode, r.stderr.decode("utf-8", "replace")[:200]))
        return r.stdout

    def has_session(self, s):
        return subprocess.run(["tmux", "-L", self.sock, "has-session", "-t", "=" + s], capture_output=True).returncode == 0


def wait_stable(path, quiet, maxwait, minbytes=1):
    """Wait until the file at `path` has not grown for `quiet` s (and has at least minbytes), or maxwait."""
    end = time.monotonic() + maxwait
    last_size, last_change = -1, time.monotonic()
    while time.monotonic() < end:
        try:
            sz = os.path.getsize(path)
        except OSError:
            sz = 0
        if sz != last_size:
            last_size, last_change = sz, time.monotonic()
        elif sz >= minbytes and time.monotonic() - last_change >= quiet:
            return sz
        time.sleep(0.02)
    return last_size


def one(tm, build, binpath, case_id, case, variant, rep, profiles, sandbox_root, out_dir, settle):
    cols, rows = map(int, case["size"].split("x"))
    sandbox = tempfile.mkdtemp(prefix="hvt-", dir=sandbox_root)
    os.mkdir(os.path.join(sandbox, "home"))
    os.mkdir(os.path.join(sandbox, "tmp"))
    prof = os.path.join(sandbox, case["profile"] + ".toml")
    shutil.copyfile(os.path.join(profiles, case["profile"] + ".toml"), prof)
    bytes_path = os.path.join(sandbox, "bytes.bin")
    flag = os.path.join(sandbox, "go")
    base_env = ("PATH=/usr/bin:/bin HOME=%s/home LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8 TMPDIR=%s/tmp"
                % (sandbox, sandbox))
    if variant == "default":
        env = base_env + ' TERM="$TERM" TMUX="$TMUX" TMUX_PANE="$TMUX_PANE" TERM_PROGRAM="$TERM_PROGRAM" TERM_PROGRAM_VERSION="$TERM_PROGRAM_VERSION"'
    else:
        env = base_env + " TERM=xterm-256color"
    wrapper = os.path.join(sandbox, "wrapper.sh")
    with open(wrapper, "w") as fh:
        fh.write("#!/bin/sh\nwhile [ ! -e '%s' ]; do sleep 0.02; done\n" % flag)
        # record the environment the program really gets (the env string, expanded by this shell)
        fh.write("echo %s | sed -e 's#%s#<sandbox>#g' > '%s/env.txt'\n" % (env, sandbox, sandbox))
        fh.write("exec env -i %s '%s' tui --file '%s'\n" % (env, binpath, prof))
    sess = "v%d-%s-%s-%s" % (rep, build, case_id, variant)
    rec = {"build": build, "case": case_id, "variant": variant, "rep": rep, "size": case["size"], "keys": case["keys"],
           "tmux_session": sess, "screens": []}
    try:
        pane = tm.run("new-session", "-d", "-P", "-F", "#{pane_id}", "-s", sess, "-x", str(cols), "-y", str(rows),
                      "sh '%s'" % wrapper).decode().strip()
        rec["pane_id"] = pane
        size = tm.run("display", "-p", "-t", pane, "#{pane_width}x#{pane_height}").decode().strip()
        rec["pane_size"] = size
        if size != "%dx%d" % (cols, rows):
            tm.run("resize-window", "-t", pane, "-x", str(cols), "-y", str(rows))
            rec["pane_size_after_resize"] = tm.run("display", "-p", "-t", pane, "#{pane_width}x#{pane_height}").decode().strip()
        rec["tmux_version"] = tm.run("display", "-p", "-t", pane, "#{version}").decode().strip()
        rec["default_terminal"] = tm.run("show", "-gv", "default-terminal").decode().strip()
        tm.run("pipe-pane", "-t", pane, "-o", "cat >> '%s'" % bytes_path)
        open(flag, "w").close()
        offsets = [0]
        n = wait_stable(bytes_path, quiet=0.5, maxwait=6.0)
        offsets.append(n)

        def capture(label):
            text = tm.run("capture-pane", "-p", "-t", pane).decode("utf-8", "replace")
            with_sgr = tm.run("capture-pane", "-p", "-e", "-t", pane).decode("utf-8", "replace")
            cur = tm.run("display", "-p", "-t", pane, "#{cursor_x} #{cursor_y} #{pane_width}x#{pane_height}").decode().split()
            lines = text.split("\n")
            if lines and lines[-1] == "":
                lines = lines[:-1]
            lines = [l.rstrip() for l in lines]
            while len(lines) < rows:
                lines.append("")
            rec["screens"].append({"label": label, "lines": lines[:rows], "sgr": with_sgr.rstrip("\n").split("\n"),
                                   "cursor": [int(cur[0]), int(cur[1])], "pane": cur[2]})
        capture("start")
        for k in case["keys"]:
            b = KEYS.get(k, k.encode("utf-8"))
            tm.run("send-keys", "-t", pane, "-H", *["%02x" % x for x in b])
            n = wait_stable(bytes_path, quiet=settle, maxwait=3.0, minbytes=offsets[-1] + 1)
            offsets.append(max(n, offsets[-1]))
            capture(k)
        # exit
        try:
            tm.run("send-keys", "-t", pane, "-H", "03", check=False)
        except Exception:  # noqa
            pass
        t_end = time.monotonic() + 3.0
        while time.monotonic() < t_end and tm.has_session(sess):
            time.sleep(0.05)
        rec["exited_by_itself"] = not tm.has_session(sess)
        if tm.has_session(sess):
            tm.run("kill-session", "-t", "=" + sess, check=False)
        data = open(bytes_path, "rb").read() if os.path.exists(bytes_path) else b""
        chunks = []
        labels = ["start"] + list(case["keys"])
        for i, lab in enumerate(labels):
            a, b2 = offsets[i], offsets[i + 1] if i + 1 < len(offsets) else len(data)
            piece = data[a:b2]
            chunks.append({"key": lab, "n": len(piece), "esc": esc(piece), "b64": base64.b64encode(piece).decode()})
        rec["chunks"] = chunks
        rec["tail_after_last_key_esc"] = esc(data[offsets[-1]:])
        try:
            rec["program_env"] = open(os.path.join(sandbox, "env.txt")).read().strip()
        except OSError:
            rec["program_env"] = None
    except Exception as exc:  # noqa
        rec["error"] = repr(exc)[:300]
        if tm.has_session(sess):
            tm.run("kill-session", "-t", "=" + sess, check=False)
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)
    os.makedirs(os.path.join(out_dir, build), exist_ok=True)
    with open(os.path.join(out_dir, build, "%s-%s-r%d.json" % (case_id, variant, rep)), "w", encoding="utf-8") as fh:
        json.dump(rec, fh, ensure_ascii=False, indent=1)
    last = rec["screens"][-1]["lines"] if rec.get("screens") else []
    print("%s %s %s r%d -> %s" % (build, case_id, variant, rep, [l for l in last if l]), flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--socket", required=True)
    ap.add_argument("--conf", required=True, help="tmux.conf used for this server (status off, default-terminal)")
    ap.add_argument("--bins", required=True)
    ap.add_argument("--profiles", required=True)
    ap.add_argument("--cases", required=True)
    ap.add_argument("--sandbox-root", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--variants", default="default,xterm")
    ap.add_argument("--cases-only", default=None)
    ap.add_argument("--settle", type=float, default=0.4)
    ap.add_argument("builds", nargs="+")
    a = ap.parse_args()
    cases = json.load(open(a.cases, encoding="utf-8"))["cases"]
    if a.cases_only:
        cases = {k: v for k, v in cases.items() if k in a.cases_only.split(",")}
    tm = Tmux(a.socket, a.conf)
    for build in a.builds:
        binpath = os.path.join(a.bins, build, "heimdall-proto")
        for cid, case in cases.items():
            for variant in a.variants.split(","):
                for rep in range(1, a.reps + 1):
                    one(tm, build, binpath, cid, case, variant, rep, a.profiles, a.sandbox_root, a.out, a.settle)


if __name__ == "__main__":
    main()
