#!/usr/bin/env python3
"""Reference model of the T2 lint rules (specs/T2.md), used only to cross-check the hand-written
expected/*.json.  Input must be a schema-valid profile (it does not re-implement validation).

usage: python3 lint_ref.py PROFILE.toml   -> prints the expected `data` object
"""
import json
import sys
import tomllib

MESSAGES = {
    "duplicate-endpoint": "destinations share the same host and port",
    "privileged-port": "port below 1024 other than 22",
    "root-account": "account is root",
    "duplicate-label": "label repeated within a destination",
    "label-case-variant": "labels differ only in letter case",
}


def ascii_lower(s):
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in s)


def lint(doc):
    ds = doc.get("destinations", [])
    out = []

    def f(rule, paths, ids):
        out.append({"rule": rule, "key_paths": paths, "destination_ids": ids, "message": MESSAGES[rule]})

    groups = {}
    for i, d in enumerate(ds):
        groups.setdefault((ascii_lower(d["host"]), d.get("port", 22)), []).append(i)
    for key, idx in sorted(groups.items(), key=lambda kv: kv[1][0]):
        if len(idx) > 1:
            f("duplicate-endpoint", ["destinations[%d].host" % i for i in idx], [ds[i]["id"] for i in idx])
    for i, d in enumerate(ds):
        p = d.get("port", 22)
        if p < 1024 and p != 22:
            f("privileged-port", ["destinations[%d].port" % i], [d["id"]])
    for i, d in enumerate(ds):
        if d["account"] == "root":
            f("root-account", ["destinations[%d].account" % i], [d["id"]])
    for i, d in enumerate(ds):
        labels = d.get("labels", [])
        seen = {}
        for j, l in enumerate(labels):
            seen.setdefault(l, []).append(j)
        for l, js in sorted(seen.items(), key=lambda kv: kv[1][0]):
            if len(js) > 1:
                f("duplicate-label", ["destinations[%d].labels[%d]" % (i, j) for j in js], [d["id"]])
    classes = {}
    for i, d in enumerate(ds):
        for j, l in enumerate(d.get("labels", [])):
            classes.setdefault(ascii_lower(l), []).append((i, j, l))
    for key, occ in sorted(classes.items(), key=lambda kv: kv[1][0][:2]):
        if len({l for _, _, l in occ}) > 1:
            ids = []
            for i, _, _ in occ:
                if ds[i]["id"] not in ids:
                    ids.append(ds[i]["id"])
            f("label-case-variant", ["destinations[%d].labels[%d]" % (i, j) for i, j, _ in occ], ids)
    return {"findings": out}


if __name__ == "__main__":
    with open(sys.argv[1], "rb") as fh:
        print(json.dumps(lint(tomllib.load(fh)), indent=1, ensure_ascii=False))
