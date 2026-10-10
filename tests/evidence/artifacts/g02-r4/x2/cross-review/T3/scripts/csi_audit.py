"""M00-T05-r4-x2-xrev-T3: which control sequences does each build emit, per TERM, and which of them does the
emulator (pyte 0.8.2 + harness 2.4.2 additions) not implement?  Used to keep emulator gaps from being reported as
product defects.

Usage: tests/g02/.venv/bin/python -I csi_audit.py <bins-dir> <build>...
"""
import re
import sys
sys.dont_write_bytecode = True   # no __pycache__ next to the evidence scripts
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import probe_lib as L  # noqa: E402
import probes as P  # noqa: E402

CSI = re.compile(rb"\x1b\[([<=>?]?)([0-9;:]*)([ -/]*)([@-~])")
PYTE_FINALS = set("@ABCDEFGHJKLMPXacdefghlmnr'") | {"S", "T"}   # pyte 0.8.2 csi table + harness SU/SD
TERMS = ["xterm-256color", "screen", "tmux-256color", "linux", "xterm-kitty", "dumb", None]
SEQ = ["/", "a", "東", "bs", "bs", "e", "x", "esc", "?", "?", "down", "down", "/", "京", "enter"]


def main():
    bins = sys.argv[1]
    for name in sys.argv[2:]:
        b = P.build_info(bins, name)
        for t in TERMS:
            r = P.mk(b, "wide", 10, 60, env={"TERM": t})
            try:
                r.s.settle(1.0)
                for k in SEQ:
                    if k in L.KEYS:
                        r.s.key(L.KEYS[k])
                    else:
                        r.s.send(k)
                    r.s.settle(0.2)
                raw = bytes(r.s.raw)
            finally:
                r.close()
            seen = {}
            for m in CSI.finditer(raw):
                key = (m.group(1) + m.group(3) + m.group(4)).decode()
                seen[key] = seen.get(key, 0) + 1
            unknown = {k: v for k, v in seen.items() if (k[-1] not in PYTE_FINALS or len(k) > 1)
                       and not (k in ("?h", "?l", ">m", "?u", "<u", ">u", "=u", "?$p", "?c", "$q"))}
            print("%-16s TERM=%-15s finals=%s  not-in-emulator=%s" % (
                name, t if t else "(unset)", "".join(sorted(k for k in seen if len(k) == 1)), unknown))


if __name__ == "__main__":
    main()
