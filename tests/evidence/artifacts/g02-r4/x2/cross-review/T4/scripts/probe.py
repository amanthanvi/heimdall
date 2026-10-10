#!/usr/bin/env python3
"""T4 cross-review probe matrix (darwin-arm64). Run with python3 -I.

Usage: probe.py --fixtures <dir with homelab.toml, invalid-duplicate-alias.toml>
                --swap-dylib <swap_open.dylib> --out <dir>
                [--only-toctou] name=/path/to/heimdall-proto [name=... ...]

For every subject binary, a fresh sandbox is created with tempfile.mkdtemp(prefix="hmx4-",
dir="/tmp") (short, so AF_UNIX paths fit), the layout is built, every case runs, and the
sandbox is removed. Each case records exit code, envelope code/message/key_path, elapsed time
and a verdict against the T4 expectation:

  accept       exit 0, PROFILE_OK, stdout byte-identical to the direct path's
  same         exit code, envelope code, key_path and message equal to the direct path's
  reject       exit 2, USAGE_ERROR, returned within 2 s (K14)
  toctou-*     the target is swapped between the program's pre-check and its open(2)
               (swap_open.dylib); reject variants expect exit 2 USAGE_ERROR within 2 s
  tui-*        pty run of `tui --file`; ok: list with 3/3 drawn, q exits 0;
               reject: exit 2 within 2 s and the alternate screen never entered

Nothing listens: the AF_UNIX node is bound and closed, never listen()ed. Every child is
started by this script and, on timeout, killed by its exact PID (Popen.kill). Output written
to --out is redacted (sandbox path -> <sbx>, $HOME -> <home>).
"""
import fcntl
import json
import os
import re
import select
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import termios
import time

HOME = os.path.expanduser("~")
OK_CODES = ("PROFILE_OK",)


def redact(s, sbx):
    if isinstance(s, bytes):
        s = s.decode("utf-8", "replace")
    for p in (os.path.realpath(sbx), sbx):
        s = s.replace(p, "<sbx>")
    return s.replace(HOME, "<home>")


def envelope(out):
    try:
        doc = json.loads(out.decode("utf-8"))
        err = ((doc.get("data") or {}).get("error") or {}) if isinstance(doc.get("data"), dict) else {}
        return doc.get("code"), err.get("message"), err.get("key_path", "<none>")
    except (UnicodeDecodeError, ValueError, AttributeError):
        return None, None, None


def base_env(sbx, extra=None):
    env = {"PATH": "/usr/bin:/bin", "HOME": os.path.join(sbx, "home"), "LANG": "en_US.UTF-8",
           "TERM": "xterm-256color", "TMPDIR": os.path.join(sbx, "tmp")}
    if extra:
        env.update(extra)
    return env


def run(binary, args, cwd, env, stdin=subprocess.DEVNULL, timeout=6.0):
    t0 = time.monotonic()
    p = subprocess.Popen([binary] + args, cwd=cwd, env=env, stdin=stdin, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, start_new_session=True)
    try:
        out, err = p.communicate(timeout=timeout)
        rc = p.returncode
    except subprocess.TimeoutExpired:
        p.kill()  # exact PID of the child this script started
        out, err = p.communicate()
        rc = None
    return rc, out, err, time.monotonic() - t0


CSI = re.compile(rb"\x1b\[[0-9;?<>=]*[ -/]*[@-~]|\x1b[()][0-9A-Za-z]|\x1b[=>78]|\x1b\][^\x07]*\x07")


def run_tui(binary, path, cwd, env, ready_timeout=10.0):
    """tui --file path on a fresh pty (24x80, controlling terminal). Returns dict."""
    m, s = os.openpty()
    fcntl.ioctl(s, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))

    def pre():
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    t0 = time.monotonic()
    p = subprocess.Popen([binary, "tui", "--file", path], stdin=s, stdout=s, stderr=s, cwd=cwd, env=env,
                         start_new_session=True, preexec_fn=pre, close_fds=True)
    os.close(s)
    buf = b""
    ready_at = None
    sent_q = False
    rc = None
    killed = False
    deadline = t0 + ready_timeout
    while True:
        r, _, _ = select.select([m], [], [], 0.05)
        if r:
            try:
                chunk = os.read(m, 65536)
            except OSError:
                chunk = b""
            buf += chunk
        if ready_at is None:
            plain = CSI.sub(b"", buf)
            if b"3/3" in plain and b"lab-server" in plain:
                ready_at = time.monotonic() - t0
                os.write(m, b"q")
                sent_q = True
                deadline = time.monotonic() + 5.0
        rc = p.poll()
        if rc is not None:
            end = time.monotonic() + 0.3
            while time.monotonic() < end:
                r, _, _ = select.select([m], [], [], 0.05)
                if not r:
                    continue
                try:
                    chunk = os.read(m, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
            break
        if time.monotonic() > deadline:
            p.kill()  # exact PID
            p.wait()
            rc = None
            killed = True
            break
    os.close(m)
    return {"rc": rc, "elapsed": round(time.monotonic() - t0, 3), "ready_at": ready_at, "sent_q": sent_q,
            "killed": killed, "alt_enter": b"\x1b[?1049h" in buf, "alt_leave": b"\x1b[?1049l" in buf,
            "usage_error_text": b"USAGE_ERROR" in buf or b"not a regular file" in buf or b"cannot" in buf,
            "tail": CSI.sub(b"", buf)[-200:]}


def symlink(target, link):
    os.symlink(target, link)
    return link


def build_layout(sbx, fixtures):
    L = {}
    j = lambda *a: os.path.join(sbx, *a)
    for d in ("home", "tmp", "dotfiles", "dot files ü", "config", "deep", "nonreg", "nonreg/adir", "perm",
              "toctou"):
        os.makedirs(j(d), exist_ok=True)
    homelab = os.path.join(fixtures, "homelab.toml")
    shutil.copyfile(homelab, j("dotfiles", "homelab.toml"))
    shutil.copyfile(homelab, j("dot files ü", "prøfile ü.toml"))
    L["real"] = j("dotfiles", "homelab.toml")
    L["real_u"] = j("dot files ü", "prøfile ü.toml")
    L["abs"] = symlink(L["real"], j("config", "abs.toml"))
    L["rel"] = symlink("../dotfiles/homelab.toml", j("config", "rel.toml"))
    L["chain2"] = symlink("rel.toml", j("config", "chain2.toml"))
    L["chain_abs_rel"] = symlink(L["abs"], j("config", "chain-abs.toml"))
    L["u_link"] = symlink("../dot files ü/prøfile ü.toml", j("config", "lïnk wïth spåce ü.toml"))
    # deep chain of 20 relative links: deep/l0 -> l1 -> ... -> l19 -> ../dotfiles/homelab.toml
    for i in range(20):
        tgt = "l%d" % (i + 1) if i < 19 else "../dotfiles/homelab.toml"
        symlink(tgt, j("deep", "l%d" % i))
    L["chain20"] = j("deep", "l0")
    # 40 links: beyond MAXSYMLINKS (32 on darwin) -> ELOOP
    for i in range(40):
        tgt = "m%d" % (i + 1) if i < 39 else "../dotfiles/homelab.toml"
        symlink(tgt, j("deep", "m%d" % i))
    L["chain40"] = j("deep", "m0")
    symlink(j("dotfiles"), j("linked-dir"))
    L["via_dirlink"] = j("linked-dir", "homelab.toml")
    symlink("../dotfiles", j("config", "ldir"))
    L["via_rel_dirlink"] = j("config", "ldir", "homelab.toml")
    # same-as-direct targets
    open(j("dotfiles", "empty.toml"), "wb").close()
    L["empty"] = j("dotfiles", "empty.toml")
    L["empty_link"] = symlink(L["empty"], j("config", "empty.toml"))
    with open(j("dotfiles", "big.toml"), "wb") as f:
        f.write(b'schema_version = 1\nname = "x"\nrevision = 1\n# ' + b"x" * (1024 * 1024) + b"\n")
    L["big"] = j("dotfiles", "big.toml")
    L["big_link"] = symlink(L["big"], j("config", "big.toml"))
    shutil.copyfile(os.path.join(fixtures, "invalid-duplicate-alias.toml"), j("dotfiles", "dup.toml"))
    L["dup"] = j("dotfiles", "dup.toml")
    L["dup_link"] = symlink(L["dup"], j("config", "dup.toml"))
    # permission-denied targets
    shutil.copyfile(homelab, j("perm", "noread.toml"))
    os.chmod(j("perm", "noread.toml"), 0)
    L["noread"] = j("perm", "noread.toml")
    L["noread_link"] = symlink(L["noread"], j("config", "noread.toml"))
    os.makedirs(j("perm", "locked"))
    shutil.copyfile(homelab, j("perm", "locked", "homelab.toml"))
    os.chmod(j("perm", "locked"), 0)
    L["locked"] = j("perm", "locked", "homelab.toml")
    L["locked_link"] = symlink(L["locked"], j("config", "locked.toml"))
    # non-regular targets
    os.mkfifo(j("nonreg", "fifo"))
    L["fifo"] = j("nonreg", "fifo")
    L["l_fifo"] = symlink(L["fifo"], j("config", "to-fifo.toml"))
    L["l_fifo_rel"] = symlink("../nonreg/fifo", j("config", "to-fifo-rel.toml"))
    L["l_fifo_chain"] = symlink("to-fifo-rel.toml", j("config", "to-fifo-chain.toml"))
    os.mkfifo(j("nonreg", "fifo-fed"))
    L["fifo_fed"] = j("nonreg", "fifo-fed")
    L["l_fifo_fed"] = symlink(L["fifo_fed"], j("config", "to-fifo-fed.toml"))
    sk = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sk.bind(j("nonreg", "sock"))  # creates the node; never listen()ed
    sk.close()
    L["sock"] = j("nonreg", "sock")
    L["l_sock"] = symlink(L["sock"], j("config", "to-sock.toml"))
    L["dir"] = j("nonreg", "adir")
    L["l_dir"] = symlink(L["dir"], j("config", "to-dir.toml"))
    L["l_dir_rel"] = symlink("../nonreg/adir", j("config", "to-dir-rel.toml"))
    for dev in ("null", "zero", "urandom", "tty"):
        L["l_dev_" + dev] = symlink("/dev/" + dev, j("config", "to-dev-%s.toml" % dev))
    L["dangling_abs"] = symlink(j("dotfiles", "missing ü.toml"), j("config", "dangling-abs.toml"))
    L["dangling_rel"] = symlink("../dotfiles/missing.toml", j("config", "dangling-rel.toml"))
    L["self_loop"] = symlink("self.toml", j("config", "self.toml"))
    symlink("loop-b.toml", j("config", "loop-a.toml"))
    symlink("loop-a.toml", j("config", "loop-b.toml"))
    L["loop2"] = j("config", "loop-a.toml")
    return L


def cases(L, sbx):
    """(id, kind, args-builder, extra) ; args use --json unless 'plain' kind."""
    cfg = os.path.join(sbx, "config")
    C = []
    acc = [("abs_symlink", L["abs"]), ("rel_symlink", L["rel"]), ("chain_2_rel", L["chain2"]),
           ("chain_abs_then_link", L["chain_abs_rel"]), ("chain_20", L["chain20"]),
           ("spaces_nonascii_link_and_target", L["u_link"]), ("parent_dir_symlink_abs", L["via_dirlink"]),
           ("parent_dir_symlink_rel", L["via_rel_dirlink"])]
    for cid, p in acc:
        C.append({"id": cid, "kind": "accept", "path": p, "direct": L["real_u"] if "nonascii" in cid else L["real"]})
    C.append({"id": "relative_file_arg_cwd_config", "kind": "accept", "path": "rel.toml", "cwd": cfg, "direct": L["real"]})
    C.append({"id": "relative_file_arg_other_cwd", "kind": "accept", "path": "config/chain2.toml", "cwd": sbx, "direct": L["real"]})
    C.append({"id": "dev_stdin_from_regular_file", "kind": "accept", "path": "/dev/stdin", "stdin_file": L["real"], "direct": L["real"]})
    for cid, p in (("plain_abs_symlink", L["abs"]), ("plain_rel_symlink", L["rel"])):
        C.append({"id": cid, "kind": "accept-plain", "path": p, "direct": L["real"]})
    for cid, p, d in (("same_empty_file", L["empty_link"], L["empty"]), ("same_oversize", L["big_link"], L["big"]),
                      ("same_duplicate_alias", L["dup_link"], L["dup"]),
                      ("same_permission_denied_file", L["noread_link"], L["noread"]),
                      ("same_permission_denied_dir", L["locked_link"], L["locked"])):
        C.append({"id": cid, "kind": "same", "path": p, "direct": d})
    C.append({"id": "same_trailing_slash_on_file_link", "kind": "same", "path": L["abs"] + "/", "direct": L["real"] + "/"})
    rej = [("fifo_direct", L["fifo"]), ("l_fifo_abs", L["l_fifo"]), ("l_fifo_rel", L["l_fifo_rel"]),
           ("l_fifo_chain", L["l_fifo_chain"]), ("l_fifo_with_writer_and_data", L["l_fifo_fed"]),
           ("l_socket", L["l_sock"]), ("l_directory", L["l_dir"]), ("l_directory_rel", L["l_dir_rel"]),
           ("l_dev_null", L["l_dev_null"]), ("l_dev_zero", L["l_dev_zero"]), ("l_dev_urandom", L["l_dev_urandom"]),
           ("l_dev_tty", L["l_dev_tty"]), ("dangling_abs", L["dangling_abs"]), ("dangling_rel", L["dangling_rel"]),
           ("self_loop", L["self_loop"]), ("loop_2", L["loop2"]), ("chain_40_eloop", L["chain40"])]
    for cid, p in rej:
        C.append({"id": cid, "kind": "reject", "path": p})
    C.append({"id": "dev_stdin_from_pipe_writer_open", "kind": "reject", "path": "/dev/stdin", "stdin_pipe": True})
    C.append({"id": "dev_fd0_from_pipe_writer_open", "kind": "reject", "path": "/dev/fd/0", "stdin_pipe": True})
    for cid, p in (("plain_l_fifo", L["l_fifo"]), ("plain_l_dev_zero", L["l_dev_zero"]), ("plain_dangling", L["dangling_abs"])):
        C.append({"id": cid, "kind": "reject-plain", "path": p})
    return C


def do_case(binary, c, L, sbx, fixtures):
    env = base_env(sbx)
    cwd = c.get("cwd", sbx)
    plain = c["kind"].endswith("plain")
    args = ["profile", "show", "--file", c["path"]] + ([] if plain else ["--json"])
    stdin = subprocess.DEVNULL
    keep = []
    fed = None  # fd whose buffered profile bytes must still be unread after the run
    nbytes = len(open(L["real"], "rb").read())
    if c.get("stdin_file"):
        stdin = open(c["stdin_file"], "rb")
        keep.append(stdin)
    if c.get("stdin_pipe"):
        r, w = os.pipe()
        os.write(w, open(L["real"], "rb").read())  # data present, writer stays open: a reader would block
        stdin = r
        keep += [r, w]
        fed = r
    if c["id"] == "l_fifo_with_writer_and_data":
        wfd = os.open(L["fifo_fed"], os.O_RDWR | os.O_NONBLOCK)  # a writer end that holds a valid profile
        os.write(wfd, open(L["real"], "rb").read())
        keep.append(wfd)
        fed = wfd
    left = None
    try:
        rc, out, err, el = run(binary, args, cwd, env, stdin=stdin)
        if fed is not None:
            left = bytes_left(fed)
    finally:
        for k in keep:
            if isinstance(k, int):
                os.close(k)
            else:
                k.close()
    code, msg, kp = envelope(out) if not plain else (None, None, None)
    res = {"id": c["id"], "kind": c["kind"], "rc": rc, "code": code, "message": msg, "elapsed": round(el, 3)}
    if fed is not None:
        res["pipe_bytes_left"] = left
        res["pipe_bytes_written"] = nbytes
    if c["kind"] in ("accept", "accept-plain", "same"):
        dargs = ["profile", "show", "--file", c["direct"]] + ([] if plain else ["--json"])
        drc, dout, derr, _ = run(binary, dargs, sbx, env)
        dcode, dmsg, dkp = envelope(dout) if not plain else (None, None, None)
        res.update({"direct_rc": drc, "direct_code": dcode, "direct_message": dmsg})
        if c["kind"] == "accept":
            ok = rc == 0 and code == "PROFILE_OK" and out == dout
        elif c["kind"] == "accept-plain":
            ok = rc == 0 and drc == 0 and out == dout and len(out) > 0
        else:
            ok = rc == drc and code == dcode and kp == dkp and msg == dmsg and rc is not None
        res["stdout_equal_direct"] = out == dout
    elif c["kind"] == "reject":
        ok = rc == 2 and code == "USAGE_ERROR" and el <= 2.0 and (fed is None or left == nbytes)
    else:  # reject-plain
        ok = rc == 2 and el <= 2.0 and out == b""
    res["verdict"] = "PASS" if ok else "FAIL"
    res["stderr_head"] = redact(err[:160], sbx)
    return res


def bytes_left(fd):
    """Drain what is still buffered in a pipe/FIFO we hold (non-blocking); returns the count.
    A refusal that never read the input leaves every byte the probe wrote."""
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
    n = 0
    while True:
        try:
            b = os.read(fd, 65536)
        except BlockingIOError:
            break
        if not b:
            break
        n += len(b)
    return n


def hooked_copy(binary, sbx, name):
    dst = os.path.join(sbx, name)
    shutil.copyfile(binary, dst)
    os.chmod(dst, 0o755)
    # ad-hoc re-sign WITHOUT the hardened runtime so dyld honours DYLD_INSERT_LIBRARIES
    subprocess.run(["codesign", "--force", "--sign", "-", dst], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   check=True)
    return dst


def toctou_cases(binary, sbx, fixtures, dylib):
    hp = hooked_copy(binary, sbx, "hp-hooked")
    T = os.path.join(sbx, "toctou")
    homelab = os.path.join(fixtures, "homelab.toml")
    out = []
    scen = ["to_fifo", "to_fifo_with_data", "to_dev_zero", "to_directory", "to_dangling", "to_other_regular",
            "plain_path_to_fifo_with_data"]
    for i, sc in enumerate(scen):
        d = os.path.join(T, "s%d" % i)
        os.makedirs(d)
        real = os.path.join(d, "real.toml")
        shutil.copyfile(homelab, real)
        link = os.path.join(d, "profile.toml")
        nxt = os.path.join(d, "next")
        keep = []
        if sc.startswith("plain_path"):
            shutil.copyfile(homelab, link)  # a plain regular file, no link
        else:
            os.symlink(real, link)
        if sc == "to_fifo":
            os.mkfifo(os.path.join(d, "fifo"))
            os.symlink(os.path.join(d, "fifo"), nxt)
        elif sc in ("to_fifo_with_data", "plain_path_to_fifo_with_data"):
            os.mkfifo(os.path.join(d, "fifo"))
            wfd = os.open(os.path.join(d, "fifo"), os.O_RDWR | os.O_NONBLOCK)
            os.write(wfd, open(homelab, "rb").read())
            keep.append(wfd)
            if sc.startswith("plain_path"):
                os.rename(os.path.join(d, "fifo"), nxt)  # the FIFO node itself replaces the file
            else:
                os.symlink(os.path.join(d, "fifo"), nxt)
        elif sc == "to_dev_zero":
            os.symlink("/dev/zero", nxt)
        elif sc == "to_directory":
            os.makedirs(os.path.join(d, "adir"))
            os.symlink(os.path.join(d, "adir"), nxt)
        elif sc == "to_dangling":
            os.symlink(os.path.join(d, "missing.toml"), nxt)
        elif sc == "to_other_regular":
            other = os.path.join(d, "other.toml")
            with open(other, "w", encoding="utf-8") as f:
                f.write('schema_version = 1\nname = "swapped-in"\nrevision = 7\n')
            os.symlink(other, nxt)
        log = os.path.join(d, "swap.log")
        env = base_env(sbx, {"DYLD_INSERT_LIBRARIES": dylib, "HMX_SWAP_PATH": link, "HMX_SWAP_FROM": nxt,
                             "HMX_SWAP_LOG": log})
        left = None
        nbytes = len(open(homelab, "rb").read())
        try:
            rc, o, e, el = run(hp, ["profile", "show", "--file", link, "--json"], d, env)
            if keep:
                left = bytes_left(keep[0])
        finally:
            for k in keep:
                os.close(k)
        code, msg, _ = envelope(o)
        swapped = os.path.exists(log) and open(log).read().strip()
        name = None
        try:
            name = json.loads(o.decode())["data"]["profile"]["name"]
        except Exception:
            pass
        if sc == "to_other_regular":
            ok = (rc == 2 and code == "USAGE_ERROR") or (rc == 0 and name == "swapped-in")
        else:
            ok = rc == 2 and code == "USAGE_ERROR" and el <= 2.0 and (left is None or left == nbytes)
        out.append({"id": "toctou_" + sc, "kind": "toctou", "rc": rc, "code": code, "message": msg,
                    "pipe_bytes_left": left, "pipe_bytes_written": nbytes if keep else None,
                    "profile_name": name, "elapsed": round(el, 3), "swap": swapped or "no-swap (refused before open)",
                    "verdict": ("PASS" if ok else "FAIL") if swapped else ("PASS" if (rc == 2 and code == "USAGE_ERROR") else "FAIL"),
                    "stderr_head": redact(e[:160], sbx)})
    return out


def tui_cases(binary, L, sbx):
    env = base_env(sbx)
    res = []
    for cid, p, want in (("tui_abs_symlink", L["abs"], "ok"), ("tui_rel_chain", L["chain2"], "ok"),
                         ("tui_nonascii_link", L["u_link"], "ok"), ("tui_direct_regular", L["real"], "ok"),
                         ("tui_l_fifo", L["l_fifo"], "reject"), ("tui_l_dev_null", L["l_dev_null"], "reject"),
                         ("tui_l_directory", L["l_dir"], "reject"), ("tui_dangling", L["dangling_rel"], "reject"),
                         ("tui_loop", L["loop2"], "reject")):
        r = run_tui(binary, p, sbx, env)
        if want == "ok":
            ok = r["ready_at"] is not None and r["rc"] == 0 and not r["killed"] and r["alt_leave"]
        else:
            ok = r["rc"] == 2 and r["elapsed"] <= 2.0 and not r["alt_enter"]
        r["tail"] = redact(r["tail"], sbx)
        r.update({"id": cid, "kind": "tui-" + want, "verdict": "PASS" if ok else "FAIL"})
        res.append(r)
    return res


def main(argv):
    fixtures = argv[argv.index("--fixtures") + 1]
    dylib = argv[argv.index("--swap-dylib") + 1]
    outdir = argv[argv.index("--out") + 1]
    only_toctou = "--only-toctou" in argv
    subjects = [a.split("=", 1) for a in argv if "=" in a and not a.startswith("--")]
    os.makedirs(outdir, exist_ok=True)
    all_res = {}
    for name, binary in subjects:
        sbx = tempfile.mkdtemp(prefix="hmx4-", dir="/tmp")
        try:
            L = build_layout(sbx, fixtures)
            res = []
            if not only_toctou:
                for c in cases(L, sbx):
                    res.append(do_case(binary, c, L, sbx, fixtures))
                res += tui_cases(binary, L, sbx)
            res += toctou_cases(binary, sbx, fixtures, dylib)
            all_res[name] = res
            nfail = sum(1 for r in res if r["verdict"] == "FAIL")
            print("%s: %d cases, %d FAIL" % (name, len(res), nfail), flush=True)
        finally:
            for p in (os.path.join(sbx, "perm", "locked"),):
                if os.path.isdir(p):
                    os.chmod(p, 0o700)
            shutil.rmtree(sbx)
    text = json.dumps(all_res, indent=1, ensure_ascii=False)
    if ("HEIMDALL_" + "CANARY_") in text:  # split so this file itself never matches a canary scan
        print("canary string in probe output", file=sys.stderr)
        return 3
    with open(os.path.join(outdir, "probe-results.json"), "w", encoding="utf-8") as f:
        f.write(text + "\n")
    names = [n for n, _ in subjects]
    ids = []
    for n in names:
        for r in all_res[n]:
            if r["id"] not in ids:
                ids.append(r["id"])
    with open(os.path.join(outdir, "probe-matrix.tsv"), "w", encoding="utf-8") as f:
        f.write("case\t" + "\t".join(names) + "\n")
        for cid in ids:
            row = [cid]
            for n in names:
                r = next((x for x in all_res[n] if x["id"] == cid), None)
                if r is None:
                    row.append("-")
                    continue
                row.append("%s rc=%s %s %.2fs" % (r["verdict"], r["rc"], r.get("code") or "", r["elapsed"]))
            f.write("\t".join(row) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
