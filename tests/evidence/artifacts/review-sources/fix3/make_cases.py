#!/usr/bin/env python3
"""M00-T02-fix3: build crafted inputs for the CLI-level checks of compare, fetch and upstream.

Usage (repository root): python3 -I -B make_cases.py <scratch_dir>
Reads docs/sources/fetch-baseline.json and docs/sources/pins.json (read only) and writes into <scratch_dir>:
  case_gone.json            baseline with S01 answered HTTP 404 (S02 HTTP 410 in case_gone410.json)
  case_failed.json          baseline with S01 answered HTTP 403 (a bot-challenge page)
  case_rawmoved_rawprimary  S01 (raw-primary) raw bytes moved, text same: RAW_ONLY and off-pin
  case_rawmoved_normprimary S06 (normalized-primary) raw bytes moved, text same: RAW_ONLY and on-pin
  case_both_rawmoved        both of the above
  case_offpin_ident_A/B     two identical files in which S06's normalized hash differs from the pin:
                            IDENTICAL between them, off-pin against pins.json
  case_content.json         S06 normalized hash changed: CONTENT
  case_content_and_gone     S06 CONTENT and S01 GONE
  pins_badblob.json         pins.json with S29's pinned blob_sha changed (fetch --only S29 then sees a mismatch)
  pins_badupstream.json     pins.json with S19's recorded upstream.url changed (upstream refuses before any GET)
"""
import copy
import json
import os
import sys

out = sys.argv[1]
os.makedirs(out, exist_ok=True)
base = json.load(open("docs/sources/fetch-baseline.json"))
pins = json.load(open("docs/sources/pins.json"))


def variant(name, edit):
    d = copy.deepcopy(base)
    by = {r["id"]: r for r in d["results"]}
    edit(by)
    with open(os.path.join(out, name + ".json"), "w") as f:
        json.dump(d, f, indent=1, sort_keys=True)
        f.write("\n")


def status(i, code):
    def e(by):
        by[i]["http_status"] = code
    return e


def raw(i):
    def e(by):
        by[i]["raw_body_sha256"] = "0" * 64
    return e


def norm(i):
    def e(by):
        by[i]["normalized_text_sha256"] = "1" * 64
    return e


def both(*fs):
    def e(by):
        for f in fs:
            f(by)
    return e


variant("case_gone", status("S01", 404))
variant("case_gone410", status("S02", 410))
variant("case_failed", status("S01", 403))
variant("case_rawmoved_rawprimary", raw("S01"))
variant("case_rawmoved_normprimary", raw("S06"))
variant("case_both_rawmoved", both(raw("S01"), raw("S06")))
variant("case_offpin_ident_A", norm("S06"))
variant("case_offpin_ident_B", norm("S06"))
variant("case_content", norm("S06"))
variant("case_content_and_gone", both(norm("S06"), status("S01", 404)))

p = copy.deepcopy(pins)
[s for s in p["sources"] if s["id"] == "S29"][0]["pin"]["blob_sha"] = "0" * 40
json.dump(p, open(os.path.join(out, "pins_badblob.json"), "w"), indent=1)
p = copy.deepcopy(pins)
[s for s in p["sources"] if s["id"] == "S19"][0]["upstream"]["url"] += "x"
json.dump(p, open(os.path.join(out, "pins_badupstream.json"), "w"), indent=1)
print("wrote", len(os.listdir(out)), "files")
