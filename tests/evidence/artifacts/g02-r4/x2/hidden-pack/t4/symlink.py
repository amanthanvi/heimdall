"""T4 hidden tests: the seeded bug (a profile reached through a symlink is refused).

Repro from specs/T4.md plus related edge cases.  Expected behaviour is the frozen contract: a --file
that resolves to a regular file is read like that file (§2, §5); anything that is not a regular file
after resolution is still USAGE_ERROR within 2 s and never blocks (K14); the size bound still holds.
"""
import json
import os
import re
import shutil
import time
from pathlib import Path

import hm
from hm import check, Abort

T = "T4"
FIXDIR = Path(__file__).resolve().parent.parent / "t2" / "fixtures"
HOMELAB = FIXDIR / "clean.toml"          # byte copy of tests/fixtures/g02/profiles/homelab.toml


def show(ctx, path, timeout=10):
    return ctx.run(["profile", "show", "--file", str(path), "--json"], timeout=timeout)


def same_as_direct(t, ctx, label, link, target):
    rc_d, out_d, _, _ = show(ctx, target)
    t.precondition("direct path gives PROFILE_OK", rc_d == 0, rc_d)
    rc, out, err, el = show(ctx, link)
    t.eq("[%s] exit code" % label, rc, 0)
    try:
        doc = json.loads(out.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        t.check("[%s] stdout is one JSON document" % label, False, "JSON", out[:200])
        return
    t.eq("[%s] code" % label, doc.get("code"), "PROFILE_OK")
    t.eq("[%s] stdout identical to the direct path's" % label, out, out_d)


@check(T, "T4.repro_absolute_symlink", "repro: profile show via an absolute symlink to a regular profile")
def _(t, ctx):
    real = ctx.new_dir("dotfiles") / "homelab.toml"
    shutil.copyfile(HOMELAB, real)
    cfg = ctx.new_dir("config")
    link = cfg / "profile.toml"
    os.symlink(str(real), link)
    same_as_direct(t, ctx, "absolute symlink", link, real)


@check(T, "T4.relative_and_chained", "relative symlink, a chain of two links, spaces and non-ASCII names")
def _(t, ctx):
    base = ctx.new_dir("spaced dir ü")
    real = base / "real prøfile.toml"
    shutil.copyfile(HOMELAB, real)
    sub = base / "links ü"
    sub.mkdir()
    rel = sub / "rel link.toml"
    os.symlink(os.path.join("..", "real prøfile.toml"), rel)
    same_as_direct(t, ctx, "relative symlink", rel, real)
    chain = base / "chain ü.toml"
    os.symlink(str(rel), chain)
    same_as_direct(t, ctx, "chain of two symlinks", chain, real)
    # a symlinked directory in the middle of the path
    ldir = ctx.new_dir("ldir") / "via-dir-link"
    os.symlink(str(base), ldir)
    same_as_direct(t, ctx, "symlinked parent directory", ldir / "real prøfile.toml", real)


@check(T, "T4.still_rejected_nonregular", "a symlink to a FIFO / directory / device, or a dangling symlink: "
                                          "USAGE_ERROR (exit 2) within 2 s, never blocks (K14)")
def _(t, ctx):
    d = ctx.new_dir("nonreg")
    fifo = d / "fifo.toml"
    os.mkfifo(fifo)
    dirt = ctx.new_dir("a dir")
    cases = [("symlink to FIFO", fifo), ("symlink to directory", dirt), ("symlink to /dev/null", Path("/dev/null")),
             ("dangling symlink", d / "missing ü.toml")]
    for label, target in cases:
        link = d / ("link-%d.toml" % len(os.listdir(d)))
        os.symlink(str(target), link)
        rc, out, err, el = show(ctx, link, timeout=5)
        t.check("[%s] returns within 2 s" % label, rc is not None and el <= 2.0, "<= 2 s", "%.2f s rc=%r" % (el, rc))
        t.eq("[%s] exit code" % label, rc, 2)
        try:
            doc = json.loads(out.decode("utf-8"))
            t.eq("[%s] code" % label, doc.get("code"), "USAGE_ERROR")
        except (UnicodeDecodeError, ValueError):
            t.check("[%s] stdout is one JSON document" % label, False, "JSON", out[:200])


@check(T, "T4.symlink_bounds_and_errors", "through a symlink: oversize -> INPUT_TOO_LARGE, invalid -> SCHEMA_INVALID "
                                          "with the same key path as the direct path")
def _(t, ctx):
    d = ctx.new_dir("bounds")
    big = d / "big.toml"
    big.write_bytes(b'schema_version = 1\nname = "x"\nrevision = 1\n# ' + b"x" * (1024 * 1024) + b"\n")
    bad = d / "dup.toml"
    bad.write_text(HOMELAB.read_text(encoding="utf-8").replace('alias = "nas"', 'alias = "lab-server"'),
                   encoding="utf-8")
    for label, target, code in (("oversize", big, "INPUT_TOO_LARGE"), ("duplicate alias", bad, "SCHEMA_INVALID")):
        link = d / ("link-" + target.name)
        os.symlink(str(target), link)
        rc_d, out_d, _, _ = show(ctx, target)
        rc, out, err, _ = show(ctx, link)
        t.eq("[%s] exit code" % label, rc, 2)
        try:
            doc, dd = json.loads(out.decode()), json.loads(out_d.decode())
        except (UnicodeDecodeError, ValueError):
            t.check("[%s] stdout is one JSON document" % label, False, "JSON", out[:200])
            continue
        t.eq("[%s] code" % label, doc.get("code"), code)
        t.eq("[%s] data.error.key_path equals the direct path's" % label,
             ((doc.get("data") or {}).get("error") or {}).get("key_path", "<missing>"),
             ((dd.get("data") or {}).get("error") or {}).get("key_path", "<missing>"))


@check(T, "T4.plain_mode_exit", "without --json the symlinked profile also exits 0")
def _(t, ctx):
    real = ctx.new_dir("plain") / "p.toml"
    shutil.copyfile(HOMELAB, real)
    link = real.parent / "link.toml"
    os.symlink("p.toml", link)
    rc, out, err, _ = ctx.run(["profile", "show", "--file", str(link)])
    t.eq("exit code without --json", rc, 0)


@check(T, "T4.tui_via_symlink", "tui --file <symlink> shows the profile and q exits 0")
def _(t, ctx):
    real = ctx.new_dir("tui") / "homelab.toml"
    shutil.copyfile(HOMELAB, real)
    link = real.parent / "tui-link.toml"
    os.symlink(str(real), link)
    s = hm.H.PtySession(ctx.pyte, [ctx.bin, "tui", "--file", str(link)], ctx.env(), str(ctx.sandbox), 24, 80)
    try:
        lat = s.wait_for(lambda x: all(a in x.text() for a in ("lab-server", "nas", "vps-東京"))
                         and re.search(r"(?<![\d.])3/3(?!\d)", x.text()) is not None, 10.0)
        t.check("list with 3/3 shown within 10 s", lat is not None, "3 aliases and 3/3",
                "screen=%r rc=%r" % (s.text()[:300], s.poll()))
        if s.poll() is None:
            s.send("q")
        t.eq("q exits 0", s.wait_exit(5.0), 0)
    finally:
        s.close()
