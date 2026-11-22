#!/usr/bin/env python3
"""M08 design probe (disposable; never imported by production code).

Question: what does a dependency and licence inventory of the shipped `heimdall`
binary look like per release target, using only `cargo metadata` (no new tool),
and how does it differ from a lockfile-wide scan?

Usage: python3 -I inventory.py <metadata-json> <target-triple>
Reads `cargo metadata --format-version 1 --locked --offline --filter-platform <triple>`
output from a file. Prints a JSON summary; no paths, no user names.
"""
import json, sys, collections

def main():
    meta = json.load(open(sys.argv[1])); triple = sys.argv[2]
    pk = {p["id"]: p for p in meta["packages"]}
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    root = next(i for i, p in pk.items() if p["name"] == "heimdall")
    seen, stack, build_only = set(), [(root, False)], set()
    runtime = set()
    while stack:
        nid, via_build = stack.pop()
        if (nid, via_build) in seen: continue
        seen.add((nid, via_build))
        (build_only if via_build else runtime).add(nid)
        for d in nodes[nid]["deps"]:
            kinds = {k["kind"] for k in d["dep_kinds"]}
            if kinds == {"dev"}: continue           # dev-only edges never ship
            if None in kinds or "normal" in kinds: stack.append((d["pkg"], via_build))
            if "build" in kinds: stack.append((d["pkg"], True))
    build_only -= runtime
    third = [pk[i] for i in runtime if pk[i]["source"] is not None]
    lic = collections.Counter(p.get("license") or ("FILE:" + str(bool(p.get("license_file")))) for p in third)
    out = {
        "target": triple,
        "workspace_crates_linked": sorted(pk[i]["name"] for i in runtime if pk[i]["source"] is None),
        "third_party_linked": len(third),
        "third_party_build_only": len([i for i in build_only if pk[i]["source"] is not None]),
        "lockfile_packages_total": len([p for p in meta["packages"] if p["source"] is not None]),
        "licence_expressions": dict(sorted(lic.items(), key=lambda kv: -kv[1])),
        "no_licence_field": sorted(p["name"] + " " + p["version"] for p in third if not p.get("license")),
        "with_build_script": sorted(p["name"] for p in third if any("custom-build" in t["kind"] for t in p["targets"])),
        "links_native": sorted(p["name"] for p in third if p.get("links")),
        "non_registry_sources": sorted({p["source"].split("+")[0] for p in third} - {"registry"}),
    }
    json.dump(out, sys.stdout, indent=1, sort_keys=True); print()

main()
