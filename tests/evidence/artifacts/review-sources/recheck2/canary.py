"""Count HEIMDALL_CANARY_<value> occurrences (prefix followed by a value char) in given files/dirs; .gz decompressed."""
import gzip, os, re, sys
pat = re.compile(rb"HEIMDALL_CANARY_[A-Za-z0-9]")
files = hits = 0
for root in sys.argv[1:]:
    paths = [root] if os.path.isfile(root) else [os.path.join(d, f) for d, _, fs in os.walk(root) for f in fs]
    for p in paths:
        data = open(p, "rb").read()
        if p.endswith(".gz"):
            data = gzip.decompress(data)
        files += 1
        n = len(pat.findall(data))
        if n:
            hits += n
            print("HIT", p, n)
print("files=%d hits=%d" % (files, hits))
sys.exit(1 if hits else 0)
