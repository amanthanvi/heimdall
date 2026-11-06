"""Compare two redacted ssh -G diagnostic outputs case by case (W5c-sshconf)."""
import sys


def parse(path):
    cases = {}
    order = []
    cur = None
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.rstrip("\n")
        if line.startswith("### case="):
            head = line[len("### "):]
            parts = dict()
            # case=<n> file=<f> args=<...> env=<e> exit=<c>
            name = head.split(" file=")[0][len("case="):]
            args = head.split(" args=")[1].split(" env=")[0]
            env = head.split(" env=")[1].split(" exit=")[0]
            code = head.rsplit(" exit=", 1)[1]
            key = f"{name} [{args}] env={env}"
            cur = {"exit": code, "lines": []}
            cases[key] = cur
            order.append(key)
        elif line.startswith("###"):
            cur = None
        elif cur is not None:
            cur["lines"].append(line)
    return cases, order


a, order = parse(sys.argv[1])
b, _ = parse(sys.argv[2])
only_kw = len(sys.argv) > 3 and sys.argv[3] == "kw"
for key in order:
    if key.startswith("kw_") != only_kw:
        continue
    x, y = a.get(key), b.get(key)
    if y is None:
        print(f"== {key}: missing in second")
        continue
    if x["exit"] == y["exit"] and x["lines"] == y["lines"]:
        continue
    print(f"== {key}: exit {x['exit']} vs {y['exit']}")
    xs, ys = set(x["lines"]), set(y["lines"])
    for l in x["lines"]:
        if l not in ys:
            print(f"   - {l}")
    for l in y["lines"]:
        if l not in xs:
            print(f"   + {l}")
