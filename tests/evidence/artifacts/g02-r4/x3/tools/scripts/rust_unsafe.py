# Grep-based unsafe/FFI/C/asm surface for the crates in a cargo-tree crate list.
# Usage: python3 -I rust_unsafe.py <metadata.json> <cargo-tree-list.txt>
# Counts are over ALL .rs files of each crate (not cfg-filtered): an upper bound.
import json, os, re, sys
meta = json.load(open(sys.argv[1]))
want = set()
for line in open(sys.argv[2]):
    parts = line.split()
    if len(parts) >= 2: want.add((parts[0], parts[1].lstrip("v")))
RE_UNSAFE = re.compile(r"\bunsafe\b")
RE_BLOCK = re.compile(r"\bunsafe\s*\{")
RE_FN = re.compile(r"\bunsafe\s+(?:extern\s+\"[^\"]*\"\s+)?fn\b")
RE_IMPL = re.compile(r"\bunsafe\s+impl\b")
RE_ASM = re.compile(r"\b(?:global_)?asm!\s*[\(\{]")
RE_EXTERN = re.compile(r"\bextern\s+\"(?:C|system|C-unwind)\"\s*\{")
RE_FORBID = re.compile(r"#!\[\s*(?:forbid|deny)\s*\(\s*unsafe_code")
rows = []
for p in meta["packages"]:
    key = (p["name"], p["version"])
    if key not in want: continue
    root = os.path.dirname(p["manifest_path"])
    c = dict(unsafe=0, blocks=0, fns=0, impls=0, asm=0, extern_blocks=0, cfiles=0, forbid=0)
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in ("target", ".git")]
        for f in fn:
            fp = os.path.join(dp, f)
            if f.endswith((".c", ".cc", ".cpp", ".h", ".S", ".s", ".asm")): c["cfiles"] += 1
            if not f.endswith(".rs"): continue
            try: t = open(fp, encoding="utf-8", errors="replace").read()
            except OSError: continue
            c["unsafe"] += len(RE_UNSAFE.findall(t)); c["blocks"] += len(RE_BLOCK.findall(t))
            c["fns"] += len(RE_FN.findall(t)); c["impls"] += len(RE_IMPL.findall(t))
            c["asm"] += len(RE_ASM.findall(t)); c["extern_blocks"] += len(RE_EXTERN.findall(t))
            if RE_FORBID.search(t) and (f == "lib.rs" or f == "main.rs"): c["forbid"] = 1
    build = any("custom-build" in t["kind"] for t in p["targets"])
    links = p.get("links") or ""
    rows.append((p["name"], p["version"], c, build, links))
print("crate\tversion\tunsafe_tokens\tunsafe_blocks\tunsafe_fns\tunsafe_impls\tasm_macros\textern_C_blocks\tC_or_asm_files\tbuild_rs\tlinks\tforbid_or_deny_unsafe_code_at_root")
tot = dict(crates=0, with_unsafe=0, tokens=0, with_c=0, with_asm=0, with_build=0, with_extern=0, forbid=0)
for n, v, c, b, l in sorted(rows):
    print(f"{n}\t{v}\t{c['unsafe']}\t{c['blocks']}\t{c['fns']}\t{c['impls']}\t{c['asm']}\t{c['extern_blocks']}\t{c['cfiles']}\t{int(b)}\t{l}\t{c['forbid']}")
    tot["crates"] += 1; tot["tokens"] += c["unsafe"]; tot["with_unsafe"] += c["unsafe"] > 0
    tot["with_c"] += c["cfiles"] > 0; tot["with_asm"] += c["asm"] > 0; tot["with_build"] += b
    tot["with_extern"] += c["extern_blocks"] > 0; tot["forbid"] += c["forbid"]
print("#TOTALS", json.dumps(tot))
