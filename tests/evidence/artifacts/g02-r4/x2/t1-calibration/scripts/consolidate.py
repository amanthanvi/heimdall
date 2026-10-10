"""M00-T05-r4-x2-t1cal: copy the probe outputs from the scratch out-dir into raw/ in the repository.

Usage: python3 -I -B consolidate.py <scratch-out-dir> <raw-dir>
- darwin-zsh: the P14 runs are replaced by darwin-zsh-p14rerun (the first zsh pass hit zsh history
  expansion in the probe's own `echo ...$!@` line; fixed with `unsetopt bang_hist`; marked).
- Transcripts are kept for rep 1 of every (build, scenario) and for any later rep whose `cmp`
  differs from rep 1 (or that saw a re-stop); identical later reps keep `cmp` and all fields but
  drop the transcript (`transcript_omitted`).
- Fails if any home path, the user name or a canary-prefixed string would be written.
"""
import json
import os
import shutil
import sys

SETS = ["darwin-bash", "linux-bash", "darwin-zsh", "race-darwin-bash", "race-linux-bash",
        "recover-darwin-bash", "recover-linux-bash", "p9e-darwin-bash", "p9e-darwin-zsh", "p9e-linux-bash"]


def main():
    src, dst = sys.argv[1:3]
    home = os.path.expanduser("~")
    user = os.path.basename(home)
    bad = [home, "HEIMDALL_" + "CANARY_"] + ([user] if len(user) >= 4 else [])
    os.makedirs(dst, exist_ok=True)
    for s in SETS:
        sd = os.path.join(src, s)
        if not os.path.isdir(sd):
            continue
        dd = os.path.join(dst, s)
        os.makedirs(dd, exist_ok=True)
        for f in sorted(os.listdir(sd)):
            p = os.path.join(sd, f)
            if f.endswith(".json"):
                d = json.load(open(p))
                if s == "darwin-zsh":
                    rp = os.path.join(src, "darwin-zsh-p14rerun", f)
                    if os.path.exists(rp):
                        d["runs"] = [r for r in d["runs"] if r["scenario"] != "P14"]
                        for r in json.load(open(rp))["runs"]:
                            r["probe_rerun"] = "first zsh pass of P14 failed in the probe itself (zsh history expansion); rerun after `unsetopt bang_hist`"
                            d["runs"].append(r)
                first = {}
                for r in d["runs"]:
                    k = r["scenario"]
                    c = json.dumps(r.get("cmp"), sort_keys=True)
                    if k not in first:
                        first[k] = c
                    elif c == first[k] and not (r.get("cmp") or {}).get("restops") and "error" not in r:
                        if "transcript" in r:
                            del r["transcript"]
                            r["transcript_omitted"] = "same cmp as rep 1"
                text = json.dumps(d, indent=1)
            elif f.endswith(".log") or f.endswith(".txt"):
                text = open(p).read()
            else:
                continue
            for b in bad:
                if b in text:
                    raise SystemExit("refusing to write %s/%s: contains a forbidden string" % (s, f))
            open(os.path.join(dd, f), "w").write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
