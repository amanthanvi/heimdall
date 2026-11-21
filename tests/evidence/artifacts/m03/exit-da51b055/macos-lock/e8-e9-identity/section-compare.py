# section-compare.py BINS_DIR: the comparison that wrote section-compare.txt. BINS_DIR holds e8/, e9/ and
# e9b/, each with heimdall, e2e_exit_m03 and integration_session_lock (build-compare.sh). Uses
# macho-compare.py's parser (same directory as this file).
import os, re, sys
here = os.path.dirname(os.path.abspath(__file__))
src = open(os.path.join(here, "macho-compare.py")).read().split("\na, b = parse")[0]
ns = {}
exec(src, ns)
bins = sys.argv[1]
# The per-session component of an incremental codegen-unit object name: `.<7 chars>.rcgu.o`, also inside
# an rlib member `(... .rcgu.o)`.
norm = lambda p: re.sub(r"\.[0-9a-z]{7}\.rcgu\.o(\)?)$", r".<session>.rcgu.o\1", re.sub(r"/tmp/hm-lockid-[^/]+/wt", "<wt>", p))
print("E8 7b75c4c1 vs E9 2b79aac1, debug profile (lock-macos.sh's build commands), one scratch worktree path; control: the E9 tree rebuilt after touching its sources")
for b in ("heimdall", "e2e_exit_m03", "integration_session_lock"):
    for x, y, label in (("e8", "e9", "E8 vs E9"), ("e9", "e9b", "E9 vs E9 rebuilt")):
        A = ns["parse"](os.path.join(bins, x, b)); B = ns["parse"](os.path.join(bins, y, b))
        secs = set(A["sections"]) | set(B["sections"])
        dsec = [s for s in secs if A["sections"].get(s) != B["sections"].get(s)]
        oa = [t[0] for t in A["stabs"] if t[1] == 0x66]; ob = [t[0] for t in B["stabs"] if t[1] == 0x66]
        raw = sum(1 for p, q in zip(oa, ob) if p != q)
        other = lambda st: [t for t in st if t[1] != 0x66]
        print("%-25s %-17s sections %d, differing %d; non-debug symbols identical %s; LC_UUID %s; other stabs identical %s; N_OSO object paths differing %d of %d, identical once the per-session name component is masked: %s"
              % (b, label, len(secs), len(dsec), A["syms"] == B["syms"], "same" if A["uuid"] == B["uuid"] else "different",
                 other(A["stabs"]) == other(B["stabs"]), raw, len(oa), [norm(p) for p in oa] == [norm(q) for q in ob]))
