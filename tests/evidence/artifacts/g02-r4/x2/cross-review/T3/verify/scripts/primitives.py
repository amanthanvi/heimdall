"""M00-T05-r4-x2-xrev-T3-verify: minimal byte sequences that isolate the wide-character primitives the
cases depend on, fed to tmux (private socket), xterm.js headless, and the harness's pyte screen.

Usage: python3 -I primitives.py --socket <name> --conf <tmux.conf> --xtermjs <dir> --repo <repo-root>
                                --sandbox-root <dir> --out <file.json>
Each primitive is a byte string written to a 20x3 terminal; the resulting rows and cursor are recorded.
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

PRIMS = {
    "E1-wide-onto-right-half": {
        "bytes": b"\x1b[H\x1b[2J> vps-\xe6\x9d\xb1\xe4\xba\xac\x1b[8G\xe4\xba\xac",
        "what": "R1 mechanism: '> vps-東京' (東 at cols 7-8, 京 at 9-10), CHA 8 (right half of 東), write 京",
        "xterm_rule": "> vps- 京  (東 vanishes: its right half is overwritten; the new 京 takes cols 8-9 and overwrites the old 京's left half, so the old 京 vanishes too)"},
    "E2-narrow-onto-right-half": {
        "bytes": b"\x1b[H\x1b[2J  \xe5\x90\x8d\xe5\x8f\xa4\xe5\xb1\x8b-backup\x1b[8G-b",
        "what": "R2 mechanism: '  名古屋-backup', CHA 8 (right half of 屋), write '-b'",
        "xterm_rule": "  名古 -bbackup  (屋 vanishes; '-' at col 8, 'b' over the old '-')"},
    "E3-BS-then-EL-on-right-half": {
        "bytes": b"\x1b[H\x1b[2J1/3\x1b[5G/\xe4\xba\xac\x08\x1b[K\x1b[7G",
        "what": "R4 status-line bytes: '1/3', CHA 5, '/京', BS (onto the right half of 京), EL, CHA 7",
        "xterm_rule": "1/3 /  (EL starting on the right half of a wide character erases the whole character)"},
    "E4-EL-from-after-wide": {
        "bytes": b"\x1b[H\x1b[2J1/3\x1b[5G/\xe4\xba\xac\x1b[K",
        "what": "control: same as E3 without the BS: EL starts after 京",
        "xterm_rule": "1/3 /京"},
    "E5-VPA-keeps-column": {
        "bytes": b"\x1b[H\x1b[2J  vps-\xe6\x9d\xb1\xe4\xba\xac\r\n\n1/3 /\xe6\x9d\xb1\x1b[8G\x1b[1d\xe4\xba\xac",
        "what": "R1 as emitted: row 3 '1/3 /東' leaves the cursor at col 8 after CHA 8; VPA 1 moves to row 1 keeping col 8; 京 written there",
        "xterm_rule": "row 1: '  vps- 京'"},
}


def esc(b):
    return b.decode("utf-8", "backslashreplace").encode("unicode_escape").decode("ascii")


def tmux_run(sock, conf, sandbox_root, data):
    sb = tempfile.mkdtemp(prefix="hvp-", dir=sandbox_root)
    f = os.path.join(sb, "bytes.bin")
    with open(f, "wb") as fh:
        fh.write(data)
    sess = "prim-%d" % int(time.time() * 1000)
    base = ["tmux", "-L", sock, "-f", conf]
    pane = subprocess.check_output(base + ["new-session", "-d", "-P", "-F", "#{pane_id}", "-s", sess, "-x", "20", "-y", "3",
                                           "cat '%s'; sleep 20" % f]).decode().strip()
    time.sleep(0.6)
    text = subprocess.check_output(base + ["capture-pane", "-p", "-t", pane]).decode("utf-8", "replace")
    cur = subprocess.check_output(base + ["display", "-p", "-t", pane, "#{cursor_x} #{cursor_y}"]).decode().split()
    subprocess.run(base + ["kill-session", "-t", "=" + sess], capture_output=True)
    shutil.rmtree(sb, ignore_errors=True)
    lines = [l.rstrip() for l in text.split("\n")]
    while lines and lines[-1] == "":
        lines.pop()
    return {"rows": lines, "cursor": [int(cur[0]), int(cur[1])]}


def xterm_run(xdir, data):
    js = r"""
const path=require('path');const a=process.argv.slice(-2);const {Terminal}=require(path.join(a[0],'node_modules','@xterm','headless'));
const t=new Terminal({cols:20,rows:3,allowProposedApi:true,scrollback:0});
const data=Buffer.from(a[1],'base64');
t.write(new Uint8Array(data),()=>{const b=t.buffer.active;const rows=[];const cells=[];
for(let y=0;y<3;y++){const l=b.getLine(y);rows.push(l?l.translateToString(true):'');const cs=[];
for(let x=0;x<20;x++){const c=l.getCell(x);if(c&&(c.getChars()!==''||c.getWidth()===0))cs.push([x,c.getChars(),c.getWidth()]);}cells.push(cs);}
console.log(JSON.stringify({rows:rows,cursor:[b.cursorX,b.cursorY],cells:cells}));t.dispose();});
"""
    out = subprocess.check_output(["node", "-e", js, "--", os.path.abspath(xdir), base64.b64encode(data).decode()])
    return json.loads(out.decode())


def pyte_run(repo, data):
    code = r"""
import sys, json
sys.path.insert(0, sys.argv[1] + "/tests/g02")
import harness_lib as H
pyte = H.load_pyte()
scr = H.make_screen(pyte, 20, 3)
st = H.make_stream(pyte, scr)
st.feed(bytes.fromhex(sys.argv[2]))   # harness make_stream builds a pyte ByteStream
rows = [l.rstrip() for l in scr.display]
raw = [[(x, scr.buffer[y][x].data) for x in range(20) if scr.buffer[y][x].data not in (" ",)] for y in range(3)]
print(json.dumps({"rows": rows, "cursor": [scr.cursor.x, scr.cursor.y], "raw_cells": raw}, ensure_ascii=False))
"""
    py = os.path.join(repo, "tests", "g02", ".venv", "bin", "python")
    out = subprocess.check_output([py, "-I", "-c", code, repo, data.hex()])
    return json.loads(out.decode())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--socket", required=True)
    ap.add_argument("--conf", required=True)
    ap.add_argument("--xtermjs", required=True)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--sandbox-root", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    res = {}
    for name, p in PRIMS.items():
        r = {"what": p["what"], "bytes": esc(p["bytes"]), "xterm_rule_expectation": p["xterm_rule"]}
        r["tmux"] = tmux_run(a.socket, a.conf, a.sandbox_root, p["bytes"])
        r["xtermjs"] = xterm_run(a.xtermjs, p["bytes"])
        try:
            r["pyte_harness"] = pyte_run(a.repo, p["bytes"])
        except Exception as exc:  # noqa
            r["pyte_harness"] = {"error": repr(exc)[:300]}
        res[name] = r
        print("== %s: %s" % (name, p["what"]))
        print("   bytes   : %s" % r["bytes"])
        print("   tmux    : %s cursor=%s" % (r["tmux"]["rows"], r["tmux"]["cursor"]))
        print("   xterm.js: %s cursor=%s" % (r["xtermjs"]["rows"], r["xtermjs"]["cursor"]))
        print("   pyte    : %s cursor=%s" % (r["pyte_harness"].get("rows"), r["pyte_harness"].get("cursor")))
    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump(res, fh, ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
