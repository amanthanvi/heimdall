#!/usr/bin/env python3
"""G02 clean-environment runs.

  tests/g02/.venv/bin/python tools/benchmarks/g02/clean_env.py {darwin|linux|windows|all}

darwin   darwin-arm64 artifacts under `env -i PATH=/usr/bin:/bin TMPDIR=<fresh empty dir>`; every file
         created in the fresh TMPDIR (and, in a second variant, a fresh HOME and cwd) is listed.
linux    linux-arm64 (native in the Docker Desktop VM) and linux-x64 (emulated) artifacts, with their
         sidecars, copied with `docker cp` into containers of a minimal image pinned by digest (no
         Go/Rust/Node/Bun); `docker diff` before/after shows every file the programs created.
windows  file type, size, sha256 and PE header facts only (no Windows host: native execution blocked).

Raw results: tests/evidence/artifacts/g02-measure/clean-{darwin,linux,windows}.json
Boundaries: containers carry the label heimdall.g02measure=1 and are created and removed by this
script by exact name; no network (--network none), no published ports; containers/networks labelled
heimdall.fixture are never touched.  The fake agent only listens on a Unix socket (a docker volume
shared between containers, or a private /tmp dir on the host).
"""
import base64
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tests" / "g02"))
import g02bench as B  # noqa: E402
import harness_lib as H  # noqa: E402

# Round 2: HM_G02_CANDS=go,rust restricts the darwin/linux clean runs to those candidates (default: all three).
CANDS = [c for c in os.environ.get("HM_G02_CANDS", ",".join(B.CANDIDATES)).split(",") if c]
assert all(c in B.CANDIDATES for c in CANDS), CANDS
HOMELAB = B.FIX / "homelab.toml"
SPACED_REL = "spaced dir ü/prøfile homelab.toml"
SPACED = B.FIX / SPACED_REL
HOMELAB_TOML = tomllib.loads(HOMELAB.read_text(encoding="utf-8"))
HOMELAB_DESTS = HOMELAB_TOML["destinations"]
PASS_ARGS = ["a b", "c'd\"e", "$HOME;*", "line1\nline2", "ü東", "-n", "", "back\\slash"]
PASS_EXPECT = b"".join(a.encode() + b"|" for a in PASS_ARGS)
BIN_OUT = b"a\x00b\xff\xfec"
STDIN_DATA = b"in\x00\xff\nsecond line\n"
LABEL = "heimdall.g02measure=1"

# Images pinned by digest.  The arm64/amd64 references are the per-platform manifest digests inside the
# debian:bookworm-slim index sha256:3783cc01... (read with `docker manifest inspect`).
IMAGES = {
    "debian-arm64": {"ref": "debian@sha256:0c8bbb8e987a035fe1d9704eb2e571b7e9a836e1caa46345290674b45b69e417",
                     "platform": "linux/arm64",
                     "index": "debian:bookworm-slim index sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251"},
    "debian-amd64": {"ref": "debian@sha256:f3034a6ec3c1205360777c4aae76234998866ad18806ae62b63a3f84ccad782b",
                     "platform": "linux/amd64",
                     "index": "debian:bookworm-slim index sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251"},
    "python-arm64": {"ref": "python@sha256:e041b488453556787172f43845c9e0e90b9fb4a91452498420fb2011b23241b6",
                     "platform": "linux/arm64",
                     "index": "python:3.13-alpine index sha256:2dd78ad5cf13a0b68f5134dc49aa9950203a8cf4b7463431b9f3b398287c5059"},
    "alpine-arm64": {"ref": "alpine@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8",
                     "platform": "linux/arm64",
                     "index": "alpine:3.22 (reference is the index digest as stored locally)"},
}


# ------------------------------------------------------------------ helpers
def clip(b, n=4096):
    return b[:n]


def rec_run(label, argv, env=None, cwd=None, stdin=None, timeout=30, pre=None):
    """Run argv, return a JSON-serialisable record with real rc, bounded stdout/stderr (hex when non-text)."""
    t0 = time.perf_counter()
    try:
        p = subprocess.run(argv, input=stdin, stdin=None if stdin is not None else subprocess.DEVNULL,
                           capture_output=True, env=env, cwd=cwd, timeout=timeout)
        rc, out, err, to = p.returncode, p.stdout, p.stderr, False
    except subprocess.TimeoutExpired as e:
        rc, out, err, to = None, e.stdout or b"", e.stderr or b"", True
    r = {"label": label, "rc": rc, "timed_out": to, "wall_ms": round((time.perf_counter() - t0) * 1e3, 1),
         "stdout_len": len(out), "stdout_sha256": hashlib.sha256(out).hexdigest(), "stdout_hex_head": clip(out, 256).hex(),
         "stderr_len": len(err), "stderr_text": clip(err).decode("utf-8", "replace")}
    try:
        r["stdout_text"] = clip(out).decode("utf-8")
    except UnicodeDecodeError:
        r["stdout_text"] = None
    r["_out"] = out
    return r


def strip_raw(r):
    r = dict(r)
    r.pop("_out", None)
    return r


def jload(r):
    try:
        return json.loads(r["_out"])
    except Exception:
        return None


def check(name, ok, detail=None):
    return {"check": name, "pass": bool(ok), "detail": detail}


def profile_ok(r, expect_dests=HOMELAB_DESTS):
    d = jload(r)
    ok = bool(d) and r["rc"] == 0 and d.get("code") == "PROFILE_OK"
    if ok:
        got = d["data"]["profile"]["destinations"]
        exp = [(x["alias"], x["host"], x.get("port", 22), x["account"]) for x in expect_dests]
        ok = [(x["alias"], x["host"], x["port"], x["account"]) for x in got] == exp
    return ok


def passthrough_checks(runner, label_prefix):
    """runner(argv_after_binary, stdin=None, meta=None) -> (record, meta_json_or_None)."""
    res = []
    r, meta = runner(["run", "--meta-file", "{META}", "--", "printf", "%s|"] + PASS_ARGS)
    res.append(strip_raw(r) | {"meta": meta})
    res.append(check(label_prefix + "argv passthrough byte-for-byte", r["_out"] == PASS_EXPECT and r["rc"] == 0,
                     {"rc": r["rc"], "stdout_hex": r["_out"].hex()[:200]}))
    r, meta = runner(["run", "--meta-file", "{META}", "--", "sh", "-c", "exit 7"])
    res.append(strip_raw(r) | {"meta": meta})
    res.append(check(label_prefix + "exit code 7 propagated + meta", r["rc"] == 7 and meta and meta.get("code") == "CHILD_EXITED"
                     and meta["data"].get("exit_code") == 7, {"rc": r["rc"], "meta": meta}))
    r, meta = runner(["run", "--meta-file", "{META}", "--", "sh", "-c", "kill -TERM $$"])
    res.append(strip_raw(r) | {"meta": meta})
    res.append(check(label_prefix + "child killed by SIGTERM -> 143 + meta signal 15",
                     r["rc"] == 143 and meta and meta["data"].get("signal") == 15, {"rc": r["rc"], "meta": meta}))
    r, meta = runner(["run", "--meta-file", "{META}", "--", "sh", "-c", 'printf "a\\000b\\377\\376c"'])
    res.append(strip_raw(r) | {"meta": meta})
    res.append(check(label_prefix + "binary stdout (NUL, invalid UTF-8) unmodified", r["_out"] == BIN_OUT and r["rc"] == 0,
                     {"stdout_hex": r["_out"].hex()}))
    r, meta = runner(["run", "--", "cat"], stdin=STDIN_DATA)
    res.append(strip_raw(r))
    res.append(check(label_prefix + "stdin passthrough (binary)", r["_out"] == STDIN_DATA and r["rc"] == 0,
                     {"stdout_hex": r["_out"].hex()}))
    r, meta = runner(["run", "--meta-file", "{META}", "--", "/nonexistent/heimdall-g02-nope"])
    res.append(strip_raw(r) | {"meta": meta})
    res.append(check(label_prefix + "launch failure -> 127 + CHILD_LAUNCH_FAILED",
                     r["rc"] == 127 and meta and meta.get("code") == "CHILD_LAUNCH_FAILED"
                     and meta["data"].get("launched") is False, {"rc": r["rc"], "meta": meta}))
    return res


def agent_expect(keys):
    return [{"key_type": k["key_type"], "fingerprint": k["computed_fingerprint"], "comment": k["comment"]} for k in keys]


def agent_ok(r, keys):
    d = jload(r)
    if not d or r["rc"] != 0 or d.get("code") != "AGENT_OK":
        return False
    return d["data"]["identities"] == agent_expect(keys)


def tui_first_frame(pyte, argv, env, cwd, timeout=10.0):
    """Launch argv in a pty, wait for the homelab first frame, quit with q.  Returns a record."""
    p = B.Pty(pyte, argv, env, cwd, 24, 80)
    aliases = [d["alias"] for d in HOMELAB_DESTS]
    r = p.wait_until(lambda: all(a in p.text() for a in aliases) and
                     (B.status_of(p.lines()) or (0, 0))[:2] == (3, 3), timeout, p.t0)
    screen = p.text()
    alt = b"\x1b[?1049h" in p.raw
    rc, forced, err = p.finish()
    return {"first_frame": r is not None, "ms": r["ms_to_update"] if r else None, "alt_screen_seen": alt,
            "exit_code": rc, "forced_kill": forced, "stderr_text": clip(err).decode("utf-8", "replace"),
            "screen_head": "\n".join(screen.splitlines()[:5])}


def list_tree(root):
    out = []
    for p in sorted(Path(root).rglob("*")):
        try:
            st = p.lstat()
        except OSError:
            continue
        out.append({"path": str(p.relative_to(root)), "type": "dir" if p.is_dir() else "file", "bytes": st.st_size})
    return out


# ------------------------------------------------------------------ darwin
def darwin():
    pyte = B.load_pyte()
    sb = Path(tempfile.mkdtemp(prefix="hmg02c-", dir="/tmp"))      # short path for Unix socket
    out = {"started_at": B.utc(), "target": "darwin-arm64", "host": B.capture_hardware()["uname"],
           "note": "`env -i PATH=/usr/bin:/bin TMPDIR=<fresh empty dir>`; second variant also sets HOME=<fresh empty dir> "
                   "with a fresh empty cwd.  TERM is added only for the TUI checks (stated per record).",
           "candidates": {}}
    keys = H.generate_keys(sb / "keys")
    agent = H.FakeAgent(sb, sb / "agent", "clean", "normal", pubkeys=[k["pub"] for k in keys], sock_path=sb / "a.sock")
    out["fake_agent"] = {"mode": "normal", "keys": [{"key_type": k["key_type"], "fingerprint": k["computed_fingerprint"]} for k in keys]}
    try:
        for cand in CANDS:
            exe = str(B.artifact_path(cand, "darwin-arm64"))
            cres = {"artifact": exe, "sha256": B.sha256_file(exe), "variants": {}}
            rc, o, _ = B.run_text(["/usr/bin/otool", "-L", exe])
            cres["otool_L"] = o.strip().splitlines()
            rc, o, e = B.run_text(["/usr/bin/codesign", "-dv", "--verbose=2", exe])
            cres["codesign"] = [l for l in (o + e).splitlines() if l.startswith(("Identifier", "Format", "CodeDirectory", "Signature", "Authority", "TeamIdentifier"))]
            rc, o, _ = B.run_text(["/usr/bin/codesign", "--verify", "--strict", exe])
            cres["codesign_verify_rc"] = rc
            rc, o, _ = B.run_text(["/usr/bin/file", "-b", exe])
            cres["file"] = o.strip()
            for variant in ("tmpdir_only", "tmpdir_home_cwd"):
                v = {"checks": [], "records": []}
                vdir = sb / ("%s-%s" % (cand, variant))
                tmpd, homed, cwd, outd = (vdir / "tmp", vdir / "home", vdir / "cwd", vdir / "out")
                for d in (tmpd, homed, cwd, outd):
                    d.mkdir(parents=True)
                envargs = ["PATH=/usr/bin:/bin", "TMPDIR=" + str(tmpd)]
                if variant == "tmpdir_home_cwd":
                    envargs.append("HOME=" + str(homed))
                base = ["/usr/bin/env", "-i"] + envargs
                v["env_i_args"] = envargs[:1] + ["TMPDIR=<fresh empty>"] + (["HOME=<fresh empty>"] if len(envargs) > 2 else [])
                r = rec_run("toolchain_absent", base + ["/bin/sh", "-c", "for t in go gofmt rustc cargo node bun npm; do command -v $t || echo absent:$t; done"], cwd=str(cwd))
                v["records"].append(strip_raw(r))
                v["checks"].append(check("no Go/Rust/Node/Bun on PATH", all(l.startswith("absent:") for l in r["stdout_text"].split()), r["stdout_text"]))

                def ex(argv_tail, stdin=None, **kw):
                    return rec_run(" ".join(argv_tail[:3]), base + [exe] + argv_tail, cwd=str(cwd), stdin=stdin, **kw)

                r = ex(["version", "--json"])
                d = jload(r)
                v["records"].append(strip_raw(r))
                v["checks"].append(check("version --json", r["rc"] == 0 and d and d["code"] == "VERSION_OK" and d["data"]["candidate"] == cand, d and d["data"]))
                for lab, path in (("homelab", HOMELAB), ("spaced_unicode_path", SPACED)):
                    r = ex(["profile", "show", "--file", str(path), "--json"])
                    v["records"].append(strip_raw(r))
                    v["checks"].append(check("profile show " + lab, profile_ok(r), {"rc": r["rc"]}))
                meta_i = [0]

                def runner(argv_tail, stdin=None):
                    meta_i[0] += 1
                    mp = outd / ("meta%d.json" % meta_i[0])
                    argv_tail = [str(mp) if a == "{META}" else a for a in argv_tail]
                    r = ex(argv_tail, stdin=stdin)
                    meta = None
                    if mp.exists():
                        try:
                            meta = json.loads(mp.read_text())
                        except Exception:
                            meta = {"unparsable": True}
                    return r, meta

                for item in passthrough_checks(runner, "run: "):
                    (v["checks"] if "check" in item else v["records"]).append(item)
                r = ex(["agent", "list", "--socket", agent.sock, "--json"])
                v["records"].append(strip_raw(r))
                v["checks"].append(check("agent list (fake agent, Unix socket)", agent_ok(r, keys), {"rc": r["rc"]}))
                # TUI: with TERM, and without TERM (pure env -i)
                for term in ("xterm-256color", None):
                    envd = {"PATH": "/usr/bin:/bin", "TMPDIR": str(tmpd)}
                    if variant == "tmpdir_home_cwd":
                        envd["HOME"] = str(homed)
                    if term:
                        envd["TERM"] = term
                    rec = tui_first_frame(pyte, [exe, "tui", "--file", str(HOMELAB)], envd, str(cwd))
                    rec["TERM"] = term
                    v["records"].append({"label": "tui first frame", **rec})
                    v["checks"].append(check("tui first frame + clean quit, TERM=%s" % term,
                                             rec["first_frame"] and rec["exit_code"] == 0 and not rec["forced_kill"], {k: rec[k] for k in ("ms", "exit_code", "alt_screen_seen")}))
                v["files_created_in_fresh_TMPDIR"] = list_tree(tmpd)
                v["files_created_in_fresh_HOME"] = list_tree(homed) if variant == "tmpdir_home_cwd" else "HOME unset (env -i)"
                v["files_created_in_fresh_cwd"] = list_tree(cwd)
                v["files_in_out_dir (meta files named on the command line)"] = [x["path"] for x in list_tree(outd)]
                v["all_checks_pass"] = all(c["pass"] for c in v["checks"])
                cres["variants"][variant] = v
            out["candidates"][cand] = cres
        agent.stop()
        ev = agent.events()
        out["fake_agent_contact"] = {"connect_events": sum(1 for e in ev if e["event"] == "connect"),
                                     "message_types": [e["type"] for e in ev if e["event"] == "message"],
                                     "note": "one agent-list call per candidate per variant = 6 connections, each exactly one type-11 message"}
    finally:
        agent.stop()
        shutil.rmtree(sb, ignore_errors=True)
    out["finished_at"] = B.utc()
    B.write_json(B.ART / "clean-darwin.json", out)
    return out


# ------------------------------------------------------------------ linux / docker
DENV = {k: v for k, v in os.environ.items() if k != "SSH_AUTH_SOCK"}


def docker(*args, input=None, timeout=300, check_rc=False):
    p = subprocess.run(["docker"] + list(args), input=input, stdin=None if input is not None else subprocess.DEVNULL,
                       capture_output=True, timeout=timeout, env=DENV)
    if check_rc and p.returncode != 0:
        raise RuntimeError("docker %s failed rc=%s: %s" % (" ".join(args[:3]), p.returncode, p.stderr.decode(errors="replace")[:300]))
    return p


class Container:
    def __init__(self, name, image_key, extra=(), entrypoint="sleep", cmd=("3600",), start=True):
        self.name = name
        self.img = IMAGES[image_key]
        self.created = False
        args = ["create", "--name", name, "--label", LABEL, "--network", "none", "--platform", self.img["platform"],
                "--entrypoint", entrypoint] + list(extra) + [self.img["ref"]] + list(cmd)
        p = docker(*args, timeout=900)
        if p.returncode != 0:
            raise RuntimeError("docker create %s: %s" % (name, p.stderr.decode(errors="replace")[:400]))
        self.created = True
        if start:
            self.start()

    def start(self):
        docker("start", self.name, check_rc=True)

    def cp_in(self, src, dst):
        docker("cp", src, "%s:%s" % (self.name, dst), check_rc=True, timeout=300)

    def exec(self, argv, env=None, workdir=None, stdin=None, timeout=60, tty=False):
        a = ["exec"]
        if stdin is not None:
            a.append("-i")
        if workdir:
            a += ["-w", workdir]
        for k, v in (env or {}).items():
            a += ["-e", "%s=%s" % (k, v)]
        a += [self.name] + list(argv)
        t0 = time.perf_counter()
        try:
            p = docker(*a, input=stdin, timeout=timeout)
            return {"rc": p.returncode, "out": p.stdout, "err": p.stderr, "wall_ms": (time.perf_counter() - t0) * 1e3, "timed_out": False}
        except subprocess.TimeoutExpired as e:
            return {"rc": None, "out": e.stdout or b"", "err": e.stderr or b"", "wall_ms": (time.perf_counter() - t0) * 1e3, "timed_out": True}

    def diff(self):
        p = docker("diff", self.name, check_rc=True)
        return sorted(l.strip() for l in p.stdout.decode().splitlines() if l.strip())

    def remove(self):
        """Remove by exact name after verifying our label."""
        if not self.created:
            return
        p = docker("inspect", "--format", '{{index .Config.Labels "heimdall.g02measure"}}', self.name)
        if p.returncode == 0 and p.stdout.decode().strip() == "1":
            docker("rm", "-f", self.name)
        self.created = False


def image_facts(key):
    img = IMAGES[key]
    p = docker("image", "inspect", img["ref"], "--format", "{{.Id}}|{{.Os}}/{{.Architecture}}|{{json .RepoDigests}}|{{.Size}}")
    return {"key": key, "reference_used": img["ref"], "platform_requested": img["platform"], "source_index": img["index"],
            "inspect": p.stdout.decode().strip() if p.returncode == 0 else p.stderr.decode()[:200]}


def ensure_image(key):
    img = IMAGES[key]
    p = docker("pull", "--platform", img["platform"], img["ref"], timeout=900)
    return {"pull_rc": p.returncode, "pull_tail": p.stdout.decode().strip().splitlines()[-2:] if p.returncode == 0
            else p.stderr.decode()[-300:]}


def linux():
    pyte = B.load_pyte()
    out = {"started_at": B.utc(), "images": {}, "docker": {}, "runs": {}}
    p = docker("version", "--format", "client={{.Client.Version}} server={{.Server.Version}} os/arch={{.Server.Os}}/{{.Server.Arch}}")
    out["docker"]["version"] = p.stdout.decode().strip()
    p = docker("info", "--format", "{{.Name}} | {{.OperatingSystem}} | kernel {{.KernelVersion}} | {{.Architecture}} | cpus {{.NCPU}} | mem {{.MemTotal}}")
    out["docker"]["info"] = p.stdout.decode().strip()
    for k in IMAGES:
        out["images"][k] = {"pull": ensure_image(k)} | image_facts(k)
    sb = Path(tempfile.mkdtemp(prefix="hmg02l-", dir="/tmp"))
    keys = H.generate_keys(sb / "keys")
    agentdir = sb / "agent"
    agentdir.mkdir()
    shutil.copy(B.FAKE_AGENT, agentdir / "fake_agent.py")
    for i, k in enumerate(keys):
        shutil.copy(k["pub"], agentdir / ("k%d.pub" % i))
    vol = "hm-g02m-sock"
    docker("volume", "create", "--label", LABEL, vol, check_rc=True)
    agent = None
    created = []
    try:
        agent = Container("hm-g02m-agent", "python-arm64", extra=["-v", vol + ":/sock"], entrypoint="python3",
                          cmd=["/agent/fake_agent.py", "--socket", "/sock/agent.sock", "--mode", "normal",
                               "--log", "/sock/contact.jsonl", "--ready-file", "/sock/ready"] + sum(
                                   [["--pubkey", "/agent/k%d.pub" % i] for i in range(len(keys))], []),
                          start=False)
        agent.cp_in(str(agentdir) + "/.", "/agent")
        agent.start()
        for _ in range(100):
            if agent.exec(["test", "-e", "/sock/ready"])["rc"] == 0:
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("fake agent container never became ready")
        out["fake_agent"] = {"image": IMAGES["python-arm64"]["ref"], "mode": "normal",
                             "keys": [{"key_type": k["key_type"], "fingerprint": k["computed_fingerprint"]} for k in keys]}

        for arch, target, imgkey in (("arm64", "linux-arm64", "debian-arm64"), ("x64", "linux-x64", "debian-amd64")):
            for cand in CANDS:
                name = "hm-g02m-%s-%s" % (cand, arch)
                art = B.artifact_dir(cand, target)
                rec = {"image": image_facts(imgkey)["inspect"], "image_ref": IMAGES[imgkey]["ref"], "checks": [], "records": [],
                       "emulation": None if arch == "arm64" else "emulated x86-64 (linux/amd64 under Docker Desktop on Apple silicon), not native",
                       "artifact_sha256": B.sha256_file(art / "heimdall-proto"),
                       "artifact_files": [str(p.relative_to(art)) for p in sorted(art.rglob("*")) if p.is_file()]}
                c = None
                try:
                    c = Container(name, imgkey, extra=["-v", vol + ":/sock"])
                    created.append(c)
                    c.exec(["mkdir", "-p", "/work", "/tmp/hmtmp", "/out"])
                    c.cp_in(str(art) + "/.", "/opt/hm")
                    c.cp_in(str(B.FIX) + "/.", "/fx")
                    c.exec(["chmod", "755", "/opt/hm/heimdall-proto"])
                    diff_before = c.diff()
                    env = {"PATH": "/usr/bin:/bin", "TMPDIR": "/tmp/hmtmp", "TERM": "xterm-256color"}

                    def sh(label, cmd, stdin=None, timeout=120, env_=None):
                        r = c.exec(cmd, env=env_ or env, workdir="/work", stdin=stdin, timeout=timeout)
                        o = r["out"]
                        item = {"label": label, "rc": r["rc"], "timed_out": r["timed_out"], "wall_ms": round(r["wall_ms"], 1),
                                "stdout_len": len(o), "stdout_sha256": hashlib.sha256(o).hexdigest(), "stdout_hex_head": o[:256].hex(),
                                "stderr_len": len(r["err"]), "stderr_text": r["err"][:3000].decode("utf-8", "replace"), "_out": o}
                        try:
                            item["stdout_text"] = o[:4096].decode("utf-8")
                        except UnicodeDecodeError:
                            item["stdout_text"] = None
                        return item

                    r = sh("os_and_libc", ["sh", "-c", "uname -m; sed -n 's/^PRETTY_NAME=//p' /etc/os-release; ldd --version 2>&1 | head -1; "
                                                        "ls /proc/sys/fs/binfmt_misc 2>&1 | tr '\\n' ' '"])
                    rec["records"].append(strip_raw(r))
                    rec["os_and_libc"] = r["stdout_text"].strip().splitlines()
                    r = sh("toolchain_absent", ["sh", "-c", "for t in go gofmt rustc cargo node nodejs npm bun python3 python gcc cc; do command -v $t || echo absent:$t; done; "
                                                            "ls -d /usr/local/go /usr/local/cargo /root/.cargo /root/.bun /usr/local/lib/node_modules 2>&1 | head -5"])
                    rec["records"].append(strip_raw(r))
                    lines = r["stdout_text"].split("\n")
                    rec["checks"].append(check("no Go/Rust/Node/Bun (nor python/gcc) in the image", all(l.startswith(("absent:", "ls:")) or not l for l in lines), r["stdout_text"]))
                    r = sh("ldd", ["sh", "-c", "ldd /opt/hm/heimdall-proto 2>&1 | head -12; file /opt/hm/heimdall-proto 2>&1 | head -1"])
                    rec["ldd"] = r["stdout_text"].strip().splitlines()
                    r = sh("version", ["/opt/hm/heimdall-proto", "version", "--json"])
                    d = jload(r)
                    rec["records"].append(strip_raw(r))
                    rec["checks"].append(check("version --json", r["rc"] == 0 and d and d["code"] == "VERSION_OK" and d["data"]["candidate"] == cand, d and d["data"]))
                    for lab, path in (("homelab", "/fx/homelab.toml"), ("spaced_unicode_path", "/fx/" + SPACED_REL)):
                        r = sh("profile_show_" + lab, ["/opt/hm/heimdall-proto", "profile", "show", "--file", path, "--json"])
                        rec["records"].append(strip_raw(r))
                        rec["checks"].append(check("profile show " + lab, profile_ok(r), {"rc": r["rc"]}))
                    mi = [0]

                    def runner(argv_tail, stdin=None):
                        mi[0] += 1
                        mp = "/out/meta%d.json" % mi[0]
                        argv_tail = [mp if a == "{META}" else a for a in argv_tail]
                        r = sh(" ".join(argv_tail[:4]), ["/opt/hm/heimdall-proto"] + argv_tail, stdin=stdin)
                        m = c.exec(["cat", mp])
                        meta = None
                        if m["rc"] == 0:
                            try:
                                meta = json.loads(m["out"])
                            except Exception:
                                meta = {"unparsable": True}
                        return r, meta

                    for item in passthrough_checks(runner, "run: "):
                        (rec["checks"] if "check" in item else rec["records"]).append(item)
                    r = sh("agent_list", ["/opt/hm/heimdall-proto", "agent", "list", "--socket", "/sock/agent.sock", "--json"])
                    rec["records"].append(strip_raw(r))
                    rec["checks"].append(check("agent list against fake_agent.py in a python image (shared volume)", agent_ok(r, keys), {"rc": r["rc"]}))
                    # TUI through `docker exec -it` in a host pty: proves the sidecar loads in the clean image.
                    argv = [shutil.which("docker") or "docker", "exec", "-it", "-w", "/work", "-e", "TERM=xterm-256color", "-e", "TMPDIR=/tmp/hmtmp", "-e", "PATH=/usr/bin:/bin",
                            name, "/opt/hm/heimdall-proto", "tui", "--file", "/fx/homelab.toml"]
                    rec_t = tui_first_frame(pyte, argv, DENV, "/tmp", timeout=40.0 if arch == "x64" else 15.0)
                    rec["records"].append({"label": "tui first frame via docker exec -it (latency includes docker exec; not a benchmark)", **rec_t})
                    rec["checks"].append(check("tui first frame + clean quit (docker exec -it)", rec_t["first_frame"] and rec_t["exit_code"] == 0 and not rec_t["forced_kill"],
                                               {k: rec_t[k] for k in ("ms", "exit_code", "alt_screen_seen")}))
                    diff_after = c.diff()
                    rec["docker_diff_new_entries_after_setup"] = [e for e in diff_after if e not in diff_before]
                    rec["docker_diff_setup_entries_count"] = len(diff_before)
                    rec["all_checks_pass"] = all(x["pass"] for x in rec["checks"])
                except Exception as e:  # record, keep going with other candidates
                    rec["error"] = repr(e)[:500]
                    rec["all_checks_pass"] = False
                finally:
                    if c:
                        c.remove()
                out["runs"]["%s/%s" % (cand, target)] = rec
        # agent contact log
        r = agent.exec(["cat", "/sock/contact.jsonl"])
        ev = [json.loads(l) for l in r["out"].decode().splitlines() if l.strip()]
        out["fake_agent_contact"] = {"connect_events": sum(1 for e in ev if e["event"] == "connect"),
                                     "message_types": [e["type"] for e in ev if e["event"] == "message"],
                                     "message_bytes": [e["bytes"] for e in ev if e["event"] == "message"],
                                     "disconnect_reasons": [e["reason"] for e in ev if e["event"] == "disconnect"]}
        # supplementary: musl (alpine) probe of the linux-arm64 artifacts, version only
        out["musl_probe_alpine_arm64"] = {"image": image_facts("alpine-arm64")["inspect"], "image_ref": IMAGES["alpine-arm64"]["ref"], "results": {}}
        for cand in CANDS:
            c = None
            try:
                c = Container("hm-g02m-alpine-%s" % cand, "alpine-arm64")
                c.cp_in(str(B.artifact_dir(cand, "linux-arm64")) + "/.", "/opt/hm")
                r = c.exec(["/opt/hm/heimdall-proto", "version", "--json"], env={"PATH": "/usr/bin:/bin"})
                out["musl_probe_alpine_arm64"]["results"][cand] = {"rc": r["rc"], "stdout_head": r["out"][:300].decode("utf-8", "replace"),
                                                                    "stderr_head": r["err"][:300].decode("utf-8", "replace")}
            except Exception as e:
                out["musl_probe_alpine_arm64"]["results"][cand] = {"error": repr(e)[:300]}
            finally:
                if c:
                    c.remove()
    finally:
        for c in created:
            c.remove()
        if agent:
            agent.remove()
        docker("volume", "rm", vol)
        shutil.rmtree(sb, ignore_errors=True)
    out["finished_at"] = B.utc()
    B.write_json(B.ART / "clean-linux.json", out)
    return out


# ------------------------------------------------------------------ windows
def pe_facts(path):
    with open(path, "rb") as fh:
        head = fh.read(4096)
        if head[:2] != b"MZ":
            return {"pe": False}
        off = struct.unpack_from("<I", head, 0x3C)[0]
        fh.seek(off)
        pe = fh.read(256)
    if pe[:4] != b"PE\0\0":
        return {"pe": False}
    machine, nsec, ts = struct.unpack_from("<HHI", pe, 4)
    opt_magic = struct.unpack_from("<H", pe, 24)[0]
    subsystem = struct.unpack_from("<H", pe, 24 + 68)[0]
    return {"pe": True, "machine": hex(machine), "machine_name": {0x8664: "x86-64", 0xAA64: "arm64", 0x14C: "x86"}.get(machine, "other"),
            "sections": nsec, "optional_header_magic": hex(opt_magic), "subsystem": subsystem,
            "subsystem_name": {3: "console", 2: "gui"}.get(subsystem, "other")}


def windows():
    out = {"started_at": B.utc(), "status": "blocked", "blocked_on": "native Windows x86-64 host (none available; no emulation or Wine used)", "artifacts": {}}
    for cand in B.CANDIDATES:
        d = B.artifact_dir(cand, "windows-x64")
        files = []
        for p in sorted(d.rglob("*")):
            if p.is_file():
                rc, o, _ = B.run_text(["/usr/bin/file", "-b", str(p)])
                files.append({"path": str(p.relative_to(d)), "bytes": p.stat().st_size, "sha256": B.sha256_file(p), "file": o.strip(),
                              "pe": pe_facts(p) if p.suffix in (".exe", ".dll") else None})
        out["artifacts"][cand] = {"files": files, "total_bytes": sum(f["bytes"] for f in files)}
    out["finished_at"] = B.utc()
    B.write_json(B.ART / "clean-windows.json", out)
    return out


def main():
    what = sys.argv[1] if len(sys.argv) > 1 else "all"
    os.environ.pop("SSH_AUTH_SOCK", None)
    if what in ("darwin", "all"):
        r = darwin()
        print("darwin", {c: {v: x["all_checks_pass"] for v, x in d["variants"].items()} for c, d in r["candidates"].items()})
    if what in ("windows", "all"):
        windows()
        print("windows done")
    if what in ("linux", "all"):
        r = linux()
        print("linux", {k: v.get("all_checks_pass") for k, v in r["runs"].items()})


if __name__ == "__main__":
    main()
