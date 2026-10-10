"""M00-T05-r4-x2-xrev-T3: minimal repro with byte capture.  Runs one key sequence on several builds and prints,
for the last key, the screen and the exact bytes the program wrote in response (escaped).

Usage: tests/g02/.venv/bin/python -I repro_bytes.py [VAR=value|VAR=<unset>]... <bins-dir> <profile> <rows>x<cols> <keys,comma,separated> <build>...
  keys: names from probe_lib.KEYS (up, down, enter, esc, bs) or literal characters; 'R<rows>x<cols>' resizes.
"""
import signal
import sys
sys.dont_write_bytecode = True   # no __pycache__ next to the evidence scripts
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import probe_lib as L  # noqa: E402
import probes as P  # noqa: E402


def main():
    args = sys.argv[1:]
    env = {}
    while args and "=" in args[0]:
        k, v = args.pop(0).split("=", 1)
        env[k] = v if v != "<unset>" else None
    bins, profile, size, keys = args[:4]
    rows, cols = map(int, size.split("x"))
    for name in args[4:]:
        b = P.build_info(bins, name)
        r = P.mk(b, profile, rows, cols, env=env or None)
        try:
            r.start()
            seq = keys.split(",")
            for i, k in enumerate(seq):
                before = len(r.s.raw)
                if k.startswith("R") and "x" in k:
                    rr, cc = map(int, k[1:].split("x"))
                    r.resize(rr, cc)
                else:
                    r.key(k)
                if i == len(seq) - 1:
                    out = bytes(r.s.raw[before:])
            for k_st in r.steps[:-1]:
                if not k_st.get("ok"):
                    print("  [earlier step failed] %s: %s %s" % (k_st["step"], k_st.get("issues"),
                          [l for l in k_st.get("screen", []) if l]))
            st = r.steps[-1]
            print("=== %s  last key %r  oracle ok=%s" % (name, seq[-1], st.get("ok")))
            for y, l in enumerate(L.screen_rows(r.s)):
                ul = L.underlined_cols(r.s, y)
                if l or ul:
                    print("  %2d |%s|%s" % (y, l, ("  ul=%s" % ul) if ul else ""))
            if st.get("issues"):
                print("  issues:", st["issues"])
            print("  bytes:", out.decode("utf-8", "backslashreplace").encode("unicode_escape").decode("ascii"))
        finally:
            r.close()


if __name__ == "__main__":
    main()
