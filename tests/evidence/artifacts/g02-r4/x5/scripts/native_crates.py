"""Usage: cargo metadata --format-version 1 --locked | python3 -I native_crates.py <pkglist>
<pkglist>: lines "name vX.Y.Z" from `cargo tree -e normal,build --prefix none -f '{p}'`
(cargo tree applies the real per-target feature resolution; cargo metadata's resolve does
not, so metadata is used only to locate each package's sources).
Prints the package count and every package that has a build-dependency on cc or cmake or
ships C/C++/asm source files. Only names/versions are printed (no paths)."""
import json, os, sys

m = json.load(sys.stdin)
want = set()
for line in open(sys.argv[1]):
    parts = line.split()
    if len(parts) >= 2 and parts[0] != "x5-iroh":
        want.add((parts[0], parts[1].lstrip("v")))
pk = {(p["name"], p["version"]): p for p in m["packages"]}
out = []
for key in sorted(want):
    p = pk.get(key)
    if p is None:
        out.append(f"{key[0]} {key[1]} (not in metadata)")
        continue
    bdeps = sorted({d["name"] for d in p["dependencies"] if d.get("kind") == "build"} & {"cc", "cmake"})
    n = 0
    for _dp, _dn, fn in os.walk(os.path.dirname(p["manifest_path"])):
        n += sum(1 for f in fn if f.endswith((".S", ".s", ".asm", ".c", ".cc", ".cpp")))
    if bdeps or n:
        out.append(f'{key[0]} {key[1]} build-deps={"+".join(bdeps) or "-"} native-src-files={n}')
print(f"packages={len(want)}")
for line in out:
    print("  " + line)
