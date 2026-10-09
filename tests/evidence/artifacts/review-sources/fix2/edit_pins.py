#!/usr/bin/env python3
"""M00-T02-fix2: the edits applied to docs/sources/pins.json, kept for provenance.

Phases (run from the repository root, python3 -I):
  skeleton                 add `tag_pins` (no ids yet) and `auxiliary_sources` A01-A04 (no pin_v2 yet)
  fill <tags.json> <aux_fetch.json>
                           copy resolved tag ids and the auxiliary fetch results into pins.json
  text                     relabel legacy v1 hashes, S23 primary kind, drift notes, E6/E9 facts,
                           S24 excerpt ellipses, method / reopen / reproducibility wording
  review                   corrections after the internal adversarial review (E6 fact scope, E8 count,
                           S05/S21 quotable excerpts, S28 note, drift-note timestamps, reopen wording)
The file is rewritten with json.dumps(indent=1) + "\n", the format it already had.
Each phase ran once, in order, on 2026-10-09 against the pins.json of d096a64; `text` is not idempotent.
"""
import json
import sys

P = "docs/sources/pins.json"


def load():
    with open(P) as f:
        return json.load(f)


def save(d):
    with open(P, "w") as f:
        f.write(json.dumps(d, indent=1) + "\n")


TAGS = [
    ("bubbletea", "charmbracelet/bubbletea", "v2.0.10", "Bubble Tea release v2.0.10 (Go module charm.land/bubbletea/v2)"),
    ("ratatui", "ratatui/ratatui", "ratatui-v0.30.2", "Ratatui GitHub release tag for crate 0.30.2"),
    ("opentui", "anomalyco/opentui", "v0.5.14", "OpenTUI release v0.5.14 (npm @opentui/* 0.5.14)"),
    ("iroh.rust_crate", "n0-computer/iroh", "v1.3.0", "Iroh GitHub release tag for crate 1.3.0"),
    ("iroh.javascript", "n0-computer/iroh-ffi", "v1.1.0", "iroh-ffi release v1.1.0 (npm @number0/iroh 1.1.0)"),
    ("pigeons", "n0-computer/pigeons", "v0.2.1", "Pigeons release v0.2.1 (crate iroh-pigeons 0.2.1; release assets)"),
    ("win32_openssh", "PowerShell/Win32-OpenSSH", "10.0.0.0p2-Preview", "Win32-OpenSSH latest release (Preview)"),
    ("win32_openssh", "PowerShell/Win32-OpenSSH", "v9.8.3.0p2-Preview", "Win32-OpenSSH release (Preview)"),
    ("win32_openssh", "PowerShell/Win32-OpenSSH", "v9.8.2.0p2-Preview", "Win32-OpenSSH release (Preview)"),
    ("win32_openssh", "PowerShell/Win32-OpenSSH", "v9.8.1.0p1-Preview", "Win32-OpenSSH release (Preview)"),
    ("win32_openssh", "PowerShell/Win32-OpenSSH", "v9.8.0.0p1-Preview", "Win32-OpenSSH release (Preview)"),
    ("win32_openssh", "PowerShell/openssh-portable", "v10.0.0.0",
     "openssh-portable source tag v10.0.0.0, the tag G03-S02 cites (tests/evidence/artifacts/g03/sources/source-pins.json); "
     "that the 10.0.0.0p2-Preview binaries were built from it is not established here"),
    ("smallstep.step_ca", "smallstep/certificates", "v0.30.2", "step-ca release v0.30.2"),
    ("smallstep.step_cli", "smallstep/cli", "v0.31.0", "step CLI release v0.31.0"),
]

AUX = [
    {
        "id": "A01",
        "url": "https://docs.iroh.computer/languages",
        "claim": "Iroh language bindings: status (Official or Community) and platform notes per language",
        "claim_status": "supported",
        "excerpt": "\"C Official Raw FFI via iroh-c-ffi, build from source\" ; \"Go Community FFI bindings via iroh-ffi\" ; "
                   "\"bindings are built and maintained by community members rather than the number0 team. They aren’t "
                   "covered by official support, may lag behind iroh releases, and cover fewer platforms\" (table cells flattened by the normalizer)",
        "supports": "candidates.iroh.other_bindings (go: Community status; c: Official, build from source)",
        "note": "Auxiliary source added by M00-T02-fix2 (finding m5); not a spec section 19 source.",
    },
    {
        "id": "A02",
        "url": "https://docs.iroh.computer/languages/go",
        "claim": "Iroh Go binding: experimental, Linux musl only, no stable tag, module host",
        "claim_status": "supported",
        "excerpt": "\"iroh-go is still considered experimental but ready for testing\" ; \"Platform Architectures Linux x86_64, aarch64 (musl)\" ; "
                   "\"We’re aiming to publish a stable tag once we see more usage and adoption of the Go bindings.\" ; "
                   "\"go get git.coopcloud.tech/decentral1se/iroh-go\"",
        "supports": "candidates.iroh.other_bindings.go",
        "note": "Auxiliary source added by M00-T02-fix2 (finding m5). The page does not contain the words \"highly experimental\" or \"cgo\" (see escalation E9).",
    },
    {
        "id": "A03",
        "url": "https://docs.iroh.computer/languages/c",
        "claim": "Iroh C binding: iroh-c-ffi, source build only, platform list",
        "claim_status": "supported",
        "excerpt": "\"Use iroh from C via the iroh-c-ffi bindings.\" ; \"Platform Architectures Linux x86_64 (glibc) macOS arm64 Windows x86_64\" ; "
                   "\"There are no prebuilt binaries; you build the static/shared library from source and link against it.\"",
        "supports": "candidates.iroh.other_bindings.c",
        "note": "Auxiliary source added by M00-T02-fix2 (finding m5).",
    },
    {
        "id": "A04",
        "url": "https://docs.iroh.computer/compatibility",
        "claim": "Iroh operating-system support table",
        "claim_status": "supported",
        "excerpt": "\"iroh supports all major operating systems.\" ; \"OS Supported Linux Yes macOS Yes Windows Yes Android Yes iOS Yes "
                   "WebAssembly (browser) Yes FreeRTOS Yes\" (table cells flattened by the normalizer)",
        "supports": "candidates.iroh.docs_platform_compat_page",
        "note": "Auxiliary source added by M00-T02-fix2 (finding m5). A vendor support statement, not Heimdall evidence.",
    },
]


def skeleton():
    d = load()
    d["tag_pins"] = [{"candidate": c, "repo": r, "tag": t, "label": lab, "ref_sha": None, "annotated": None,
                      "commit": None, "resolved_at_utc": None} for c, r, t, lab in TAGS]
    aux = []
    for a in AUX:
        e = dict(a)
        e["fetched_url"] = a["url"]
        aux.append(e)
    d["auxiliary_sources"] = aux
    save(d)


def fill(tags_path, aux_path):
    d = load()
    with open(tags_path) as f:
        tags = {(r["repo"], r["tag"]): r for r in json.load(f)["results"]}
    for t in d["tag_pins"]:
        r = tags[(t["repo"], t["tag"])]
        if r.get("result") not in ("unpinned", "same"):
            raise SystemExit("tag %s %s not resolved: %s" % (t["repo"], t["tag"], r.get("result")))
        t.update({"ref_sha": r["ref_sha"], "annotated": r["annotated"], "commit": r["commit"],
                  "resolved_at_utc": r["retrieved_at_utc"], "advertisement_url": r["advertisement_url"]})
    with open(aux_path) as f:
        res = {r["id"]: r for r in json.load(f)["results"]}
    for a in d["auxiliary_sources"]:
        r = res[a["id"]]
        if r["http_status"] != 200:
            raise SystemExit("aux %s HTTP %s" % (a["id"], r["http_status"]))
        a["retrieved_at_utc"] = r["retrieved_at_utc"]
        a["pin_v2"] = {
            "retrieved_at_utc": r["retrieved_at_utc"],
            "fetched_url": r["fetched_url"],
            "http_status": r["http_status"],
            "primary": "normalized_text_sha256",
            "raw_body_sha256": r["raw_body_sha256"],
            "raw_bytes": r["raw_bytes"],
            "normalized_text_sha256": r["normalized_text_sha256"],
            "normalized_text_chars": r["normalized_text_chars"],
            "normalizer_version": r["normalizer_version"],
            "markers": r["markers"],
            "snapshot": {"path": "docs/sources/snapshots/%s.txt.gz" % a["id"],
                         "gz_sha256": r["snapshot"]["gz_sha256"], "content": "normalized text, one line"},
            "baseline": "docs/sources/fetch-baseline-aux.json",
        }
    save(d)


HTML_V1_TEXT = ("S14", "S15", "S20", "S21", "S22", "S23", "S28")
MD_V1 = ("S24", "S25", "S26", "S31", "S32", "S33")
MAIN_DRIFT = {  # observed by `fetch_pins.py upstream` on 2026-10-09T05:36Z (fix2/upstream1.*)
    "S16": ("cba7dd7", "3f9e64b03cf10e51adb4c07923c5ee46936f3c84", "2/2"),
    "S18": ("8d7b5e9", "4f3e0620416439ba191f7d60a15fdac5f22272e5", "3/3"),
    "S34": ("3b75e60", "132b65548125543e14dee24854f2be2aeac7b33f", "3/3"),
}

METHOD = (
    "v2 (M00-T02-fix, revised by M00-T02-fix2): `python3 -I docs/sources/tools/fetch_pins.py fetch` (stdlib, GET only) "
    "fetches every source and records raw-body sha256, normalized-text sha256 (normalizer v1, documented in the script "
    "docstring), size, HTTP status and date markers; baseline in docs/sources/fetch-baseline.json (retrieved "
    "2026-10-03T21:18Z), identical repeat run in docs/sources/fetch-repeat.json. Auxiliary sources A01-A04 (Iroh binding "
    "and platform pages, added by fix2) have their own baseline, docs/sources/fetch-baseline-aux.json (2026-10-09). GitHub "
    "sources are fetched at the pinned commit via raw.githubusercontent.com/<repo>/<sha>/<path> and their git blob sha1 is "
    "recomputed and compared with the pinned blob; `fetch_pins.py upstream` separately reports drift on the branch the spec "
    "URL names. 27 non-git spec sources and A01-A04 have a deterministic compressed normalized-text snapshot under "
    "docs/sources/snapshots/. Release tags are resolved to immutable commit ids in `tag_pins` (`fetch_pins.py tags`). "
    "v1 hashes: for the 28 HTML and GitHub sources the v1 `text_sha256` came from a script that was not retained and "
    "cannot be reproduced; it is kept as `pin.legacy_text_sha256_unreproducible` and is not a drift detector. For the 6 "
    "`.md` sources (S24-S26, S31-S33) the v1 `text_sha256` equals the v2 raw-body sha256, so v1 hashed the same raw .md "
    "bytes; it is kept as `pin.legacy_raw_body_sha256_v1` and counts as reproduced. v1 method text (superseded): curl -sL "
    "GET of each spec URL (HTML converted to text, sha256 of text and of raw body; raw HTML hashes are advisory only), gh "
    "api GET for GitHub, crates.io and npm registry GET. WITHDRAWN (no record reproduces it): the v1 sentence \"Text "
    "sha256 re-fetched ~10 minutes apart: all 34 stable\"."
)

E6_FACTS = [
    "Inbox client observed natively (G03, 2026-10-06, tests/evidence/g03-win-env-inventory.json, record status verified): "
    "on the owner's Windows 11 Pro build 26300.9550 x86-64, C:\\WINDOWS\\System32\\OpenSSH\\ssh.exe reports "
    "\"OpenSSH_for_Windows_9.5p2, LibreSSL 3.8.2\", file version 9.5.6.3, sha256 "
    "0b8b5653141c6e02e8afc043d1703dcd6410f1606422ff3ba5eb52dc56a5cce9. Spec section 3.2 says Windows tests include "
    "\"the installed Windows OpenSSH client\"; the inbox build is Microsoft-distributed with Windows and has no release "
    "tag to pin. One host, one observation; not a floor.",
    "Same host: the Win32-OpenSSH GitHub MSI was installed at C:\\Program Files\\OpenSSH (ssh.exe reports "
    "\"OpenSSH_for_Windows_10.0p2 Win32-OpenSSH-GitHub, LibreSSL 3.8.2\", file version 10.0.0.0, sha256 "
    "6890c128c86cc2c38aad9fcb32a82b851ff3d38c714a1f656b8e445d7cd5e1c6), first on PATH, and the ssh-agent and sshd "
    "services ran from it. Git for Windows 2.55.0.windows.3 bundles MSYS \"OpenSSH_10.3p1, OpenSSL 3.5.7 9 Jun 2026\". "
    "The G03 Windows and WSL Mode A probes gave the same status and criteria with 9.5p2 and 10.0p2 "
    "(docs/research/g03-windows-wsl.md sections 0.1 and 0.2).",
    "Both Microsoft builds report LibreSSL 3.8.2 in their version banner. The LibreSSL licence, and the licences of any "
    "other third-party component in the release binaries, are not recorded here: the LICENCE quoted above covers the "
    "openssh-portable source tree only. Microsoft's licence terms for the inbox Feature-on-Demand build are not recorded "
    "either.",
    "Vendor positioning recorded by the G03 pins (tests/evidence/artifacts/g03/sources/): G03-S01 records the GitHub "
    "releases as labelled \"preview-release (non-production ready)\" (release-list metadata, no stored excerpt); G03-S08 "
    "(Microsoft Learn, excerpt stored) says Microsoft's openssh-portable fork releases \"might differ from the version in "
    "Windows\".",
]

TAG_FIELDS = {  # candidate path -> (field holding the tag label, field to add with the commit)
    ("bubbletea",): ("latest_stable_tag", "latest_stable_tag_commit"),
    ("ratatui",): ("github_release", "github_release_commit"),
    ("opentui",): ("latest_release", "latest_release_commit"),
    ("pigeons",): ("latest_release", "latest_release_commit"),
    ("win32_openssh",): ("latest_release_tag", "latest_release_commit"),
    ("smallstep", "step_ca"): ("latest_release", "latest_release_commit"),
    ("smallstep", "step_cli"): ("latest_release", "latest_release_commit"),
}


def text():
    d = load()
    d["task_id"] = "M00-T02 (v1) + M00-T02-fix (v2) + M00-T02-fix2"
    d["method"] = METHOD
    by = {s["id"]: s for s in d["sources"]}
    for i in HTML_V1_TEXT:
        p = by[i]["pin"]
        extra = "; v1 also recorded the site-displayed version 0.30.2" if i == "S28" else ""
        p["type"] = "legacy_v1_text_sha256"
        p["value"] = ("superseded: the v1 text hash is kept only as legacy_text_sha256_unreproducible (not a drift "
                      "detector); the reproducible pin is pin_v2" + extra)
    for i in MD_V1:
        p, v2 = by[i]["pin"], by[i]["pin_v2"]
        h = p.pop("legacy_text_sha256_unreproducible")
        if h != v2["raw_body_sha256"]:
            raise SystemExit("%s: v1 hash does not equal the v2 raw hash" % i)
        p["type"] = "legacy_v1_md_body_sha256"
        p["value"] = ("superseded: the v1 value is the sha256 of the raw .md body (legacy_raw_body_sha256_v1, equal to "
                      "pin_v2.raw_body_sha256); the pin is pin_v2")
        p["legacy_raw_body_sha256_v1"] = h
        p["legacy_v1_note"] = ("v1 (2026-10-02T23:56Z) recorded this hash as text_sha256. It equals pin_v2.raw_body_sha256 "
                               "(2026-10-03T21:18Z), so v1 hashed the same raw .md bytes; relabelled from "
                               "legacy_text_sha256_unreproducible by M00-T02-fix2 (finding m4).")
        v2["raw_reproduced_vs_v1_pin"] = True
    s23 = by["S23"]["pin_v2"]
    s23["primary"] = "normalized_text_sha256"
    s23["primary_change"] = {
        "from": "raw_body_sha256", "to": "normalized_text_sha256", "by": "M00-T02-fix2 (finding m3)", "date": "2026-10-09",
        "reason": ("Static-site HTML: the raw bytes changed (46148 to 45864 bytes, new etag) between 2026-10-03T21:18Z and "
                   "2026-10-09T05:17Z (first seen by the recheck) with identical normalized text, so a raw primary flagged a rebuild as drift. The pinned "
                   "normalized hash is unchanged and still matched on 2026-10-09."),
    }
    by["S23"]["note"] = ("Primary pin kind changed from raw to normalized by M00-T02-fix2 (pin_v2.primary_change). The raw "
                         "hash stays as the record of the bytes fetched on 2026-10-03.")
    for i, (pc, blob, frs) in MAIN_DRIFT.items():
        by[i]["note"] = ("Drift on main observed 2026-10-09T05:36Z by `fetch_pins.py upstream`: the main-branch blob is %s, "
                         "not the pinned blob %s. The pin is the commit permalink %s; `fetch` reads that commit and its "
                         "blob sha1 matches. Quoted excerpt fragments still on main: %s. The commit that changed the path "
                         "on main was not looked up (no GitHub API request)." % (blob, by[i]["pin"]["blob_sha"], pc, frs))
    by["S17"]["note"] += (" Re-observed 2026-10-09T05:36Z by `fetch_pins.py upstream`: main blob "
                          "35c8b0a7365837aa1e9c00e28aea744f8e12ae21, quoted excerpt fragments still on main 2/2.")
    by["S24"]["excerpt"] = ("\"Offload the burden from the model and use code where possible. ... Don't make the model "
                            "fill arguments you already know. ... Combine functions that are always called in sequence.\" ; "
                            "\"Aim for fewer than 20 functions available at the start of a turn\"")
    by["S24"]["note"] = ("sha is of the .md variant served by the same site. M00-T02-fix2: the first quote joins three list "
                         "headings that are not adjacent on the page; the ellipses now mark the gaps (finding m9c).")
    by["S26"]["note"] += (" M00-T02-fix2: on 2026-10-09 `compare` classifies S26 as CONTENT (edit in the Fast-mode / EU "
                          "data-residency passage, Last-Modified 2026-10-08T23:50Z); all 5 excerpt fragments are still in "
                          "the live text (fix2/excerpts_today.out). The snapshot keeps the pinned text.")
    by["S28"]["note"] = ("Page text hash stable across two fetches in v1/v2; the site's live counters (crate count, stars, "
                         "downloads) change the normalized text, so `compare` reports CONTENT for S28 (observed 2026-10-09) "
                         "even when the cited sentence is unchanged; check the excerpt before treating it as drift.")
    # candidates
    c = d["candidates"]
    tags = {(t["repo"], t["tag"]): t for t in d["tag_pins"]}
    repo_of = {("bubbletea",): "charmbracelet/bubbletea", ("ratatui",): "ratatui/ratatui",
               ("opentui",): "anomalyco/opentui", ("pigeons",): "n0-computer/pigeons",
               ("win32_openssh",): "PowerShell/Win32-OpenSSH", ("smallstep", "step_ca"): "smallstep/certificates",
               ("smallstep", "step_cli"): "smallstep/cli"}
    for path, (tagf, commitf) in TAG_FIELDS.items():
        e = c
        for k in path:
            e = e[k]
        e[commitf] = tags[(repo_of[path], e[tagf])]["commit"]
    c["iroh"]["rust_crate"]["github_release_tag"] = "v1.3.0"
    c["iroh"]["rust_crate"]["github_release_commit"] = tags[("n0-computer/iroh", "v1.3.0")]["commit"]
    c["iroh"]["javascript"]["ffi_repo_release_commit"] = tags[("n0-computer/iroh-ffi", "v1.1.0")]["commit"]
    c["win32_openssh"]["recent_tag_commits"] = {t["tag"]: t["commit"] for t in d["tag_pins"]
                                                 if t["repo"] == "PowerShell/Win32-OpenSSH"}
    c["pigeons"]["release_assets_note"] = "asset names only; asset digests are not recorded (tag_pins pins the tag commit)"
    c["iroh"]["other_bindings"] = {
        "python_swift_kotlin": ("A01 lists Python (Official, prebuilt wheels), Swift (Official, iOS + macOS) and Kotlin "
                                "(Official, JVM + Android), built on iroh-ffi/uniffi; versions not individually checked"),
        "go": ("Community binding (A01: \"built and maintained by community members rather than the number0 team\"), "
               "module git.coopcloud.tech/decentral1se/iroh-go (A02 `go get` line), \"still considered experimental\" "
               "(A02), platforms Linux x86_64 and aarch64, musl (A02), no stable tag yet (A02: \"aiming to publish a "
               "stable tag\"). Not on A01/A02: the words \"highly experimental\" and any cgo requirement (escalation E9)."),
        "c": ("iroh-c-ffi, listed as Official, build from source (A01); \"There are no prebuilt binaries\"; platforms "
              "Linux x86_64 (glibc), macOS arm64, Windows x86_64; a raw C API generated with safer-ffi, not built on "
              "iroh-ffi/uniffi (A03)"),
        "sources": ["A01", "A02", "A03"],
    }
    c["iroh"]["docs_platform_compat_page"] = ("A04 (https://docs.iroh.computer/compatibility): Linux, macOS, Windows, "
                                             "Android, iOS, WebAssembly (browser), FreeRTOS: Yes. Vendor statement, not "
                                             "Heimdall evidence.")
    w = c["win32_openssh"]
    w["notes"] = ("Upstream sync is current in source (merge of OpenSSH 10.3p1 on 2026-09-25) but the newest published "
                  "Windows release is 10.0.0.0p2-Preview from 2025-10-27, so source head is ahead of any release. Every "
                  "one of the 5 latest releases carries \"Preview\" in its tag. The Windows 11/Server inbox OpenSSH is a "
                  "separate Microsoft-distributed build with no release tag to pin; G03 observed 9.5p2 (file version "
                  "9.5.6.3) on one Windows 11 host on 2026-10-06 (e6_facts).")
    w["e6_facts"] = E6_FACTS + [
        "Release tag 10.0.0.0p2-Preview resolves to commit %s in PowerShell/Win32-OpenSSH (tag_pins, lightweight tag); "
        "release asset digests (MSI/zip) are not recorded." % tags[("PowerShell/Win32-OpenSSH", "10.0.0.0p2-Preview")]["commit"]]
    w["status_of_e6"] = ("E6 restated: licensing is a BSD-style LICENCE in openssh-portable (not absent). The open owner "
                         "decision is the support baseline: whether a Preview-only release line, with source ahead of "
                         "releases, may be called a supported Windows OpenSSH baseline, and how the inbox build relates "
                         "to it. Facts for the owner, not a decision: e6_facts.")
    d["candidates_provenance"] = (
        "Producer-observed 2026-10-02 (v1) and 2026-10-03 (M00-T02-fix). Independently checked by the review of "
        "2026-10-03 (tests/evidence/artifacts/m00-wf3/review-sources.json; gh api, crates.io, npm and Go proxy reads): "
        "versions, release tags and dates, licence fields, rust-version/engines and repo heads of the candidates as they "
        "stood in v1. Produced after that review and so not covered by it: the corrected Win32-OpenSSH source row "
        "(openssh-portable e581929, LICENCE blob and sha256, NOASSERTION, no releases on openssh-portable, misc.c "
        "sample) and the Bubble Tea tag commit. The recheck of 2026-10-09 "
        "(tests/evidence/artifacts/review-sources/recheck/) verified the LICENCE bytes at e581929 (blob and sha256) and "
        "the Bubble Tea v2.0.10 commit d5bfd5c (Go proxy origin), and the @opentui/core tarball. Still producer-observed "
        "only: e581929 as the latestw_all head on 2026-09-25, the NOASSERTION licence field, the empty release list of "
        "openssh-portable, the misc.c sample. tag_pins (2026-10-09, fix2) were resolved from the public git ref "
        "advertisements and re-checked the same day.")
    # escalations
    es = {e["id"]: e for e in d["escalations"]}
    es["E6"]["summary"] += (" M00-T02-fix2 added facts for the owner (candidates.win32_openssh.e6_facts): the inbox "
                            "build observed by G03 (OpenSSH_for_Windows 9.5p2, LibreSSL 3.8.2, file version 9.5.6.3, "
                            "Windows 11 build 26300.9550), the MSI 10.0p2 on the same host, the unrecorded LibreSSL "
                            "licence of the release binaries, and the vendor positioning in G03-S01/G03-S08. Still not "
                            "decided here.")
    d["escalations"].append({
        "id": "E9",
        "source": "A02 (docs.iroh.computer/languages/go) vs docs/decisions/0002-language-tui-distribution.md:373",
        "summary": ("ADR-0002 section 7 says the community Go binding is \"highly experimental\" and \"needs cgo\". The "
                    "pinned docs page A02 says \"iroh-go is still considered experimental\" and lists Linux x86_64 and "
                    "aarch64 (musl); neither \"highly experimental\" nor cgo appears on A01 or A02. The cgo requirement "
                    "is an inference (a Go binding over the iroh-ffi native library) or comes from module inspection in "
                    "tests/evidence/artifacts/g02-r4/x5/RESULTS.md. Wording fix for ADR-0002 is the orchestrator's; "
                    "not changed here."),
    })
    d["reopen_conditions"] = [
        ("`fetch_pins.py compare` against docs/sources/fetch-baseline.json (or fetch-baseline-aux.json) classifies a "
         "source cited by a gate that is still open as CONTENT (normalized text changed), or reports primary_same=no "
         "for it; read docs/sources/snapshots/<id>.txt.gz to see what the pin said. MARKER_ONLY, and RAW_ONLY with "
         "primary_same=yes, are not drift; FETCH_FAILED means re-run, not drift."),
        ("`fetch_pins.py upstream` reports a GitHub source drifted on the branch its spec URL names and not every "
         "quoted excerpt fragment is still there (on 2026-10-09 S16, S17, S18 and S34 had drifted on main with all "
         "fragments present)."),
        "`fetch_pins.py tags` reports a moved or missing release tag (exit 2).",
        "A candidate dependency ships a new major/minor release before G02 selection is locked.",
        "Win32-OpenSSH (PowerShell/Win32-OpenSSH) publishes a release tag without \"Preview\", or PowerShell/openssh-portable changes LICENCE.",
        "Iroh JS publishes darwin-x64, Pigeons changes its ProxyCommand integration, telemetry or service behavior, or A02 changes the Go binding's status or platforms.",
        "Owner amends spec 19, or docs/compatibility/matrix.md cites a source not listed here or in its own pin lists.",
    ]
    r = d["reproducibility"]
    r["baseline_aux"] = "docs/sources/fetch-baseline-aux.json"
    r["raw_stability"] = (
        "v1 to v2 (about 21 h, 2026-10-02T23:56Z to 2026-10-03T21:18Z): 21 sources reproduced the v1 raw-body sha256: "
        "S01-S05, S10, S16-S19, S23, S27, S29, S30, S34 (v1 raw hash) and S24, S25, S26, S31, S32, S33 (v1 recorded the "
        "raw .md hash as text_sha256; relabelled by M00-T02-fix2). 13 did not: S06-S09, S11-S15, S20-S22, S28. v2 to "
        "2026-10-09T05:31Z (about 5.3 days, fix2 run of the committed fetcher): raw unchanged for 19 (S01-S05, S10, "
        "S16-S19, S24, S25, S27, S29-S34), changed for 15 (S06-S09, S11-S15, S20-S23, S26, S28). Primary kinds since "
        "M00-T02-fix2: raw_body_sha256 for the 7 GitHub permalinks (S16-S19, S27, S29, S34) and the 7 OpenBSD/OpenSSH "
        "pages (S01-S05, S10, S30), whose raw hash held over the whole interval; normalized_text_sha256 for the other 20 "
        "spec sources (CMS or static-site HTML, and .md variants of doc sites, whose bytes can change in a rebuild "
        "without a text change) and for A01-A04.")
    r["verify"] = ("python3 -I docs/sources/tools/fetch_pins.py fetch --out /tmp/new.json && python3 -I "
                   "docs/sources/tools/fetch_pins.py compare docs/sources/fetch-baseline.json /tmp/new.json (exit 0 = all "
                   "IDENTICAL; 4 = text identical, only raw bytes or date markers moved; 3 = a fetch failed; 2 = CONTENT "
                   "change or missing source; read the drifted id's snapshot with `gzip -dc "
                   "docs/sources/snapshots/<id>.txt.gz`). Also: `fetch --set aux` + compare against "
                   "fetch-baseline-aux.json; `upstream`; `tags`; `excerpts --set all --fetch-git`; `selftest`.")
    r["fix2_rerun"] = (
        "2026-10-09, M00-T02-fix2 (tests/evidence/artifacts/review-sources/fix2/): the committed fetcher (as of d096a64) "
        "fetched all 34 with HTTP 200 (exit 0); compare against the baseline: IDENTICAL 15, RAW_ONLY 10, MARKER_ONLY 7, "
        "CONTENT 2 (S26 page edit, S28 live counters), FETCH_FAILED 0; every primary pin held except S23 (raw, text "
        "identical; now normalized-primary), S26 and S28. The committed snapshots all verify against the baseline; fresh "
        "snapshots are byte-identical except S26 and S28. See fix2/README.md for the runs with the revised fetcher.")
    d["fix2_edited_at_utc"] = "2026-10-09"
    save(d)


def review():
    """Corrections after the internal adversarial review of fix2 (see README.md, "Internal review").
    The drift-note times were later edited in place from 05:50Z to 06:14Z, the time of the final upstream run."""
    d = load()
    w = d["candidates"]["win32_openssh"]["e6_facts"]
    old = ("The G03 Windows and WSL Mode A probes gave the same status and criteria with 9.5p2 and 10.0p2 "
           "(docs/research/g03-windows-wsl.md sections 0.1 and 0.2).")
    if old not in w[1]:
        raise SystemExit("e6_facts[1] text not found")
    w[1] = w[1].replace(old, (
        "Both builds were compared only in some probes: P-W02 (SSH_AUTH_SOCK selection; the record has agent "
        "contact rows for both builds) and P-W03 (IdentityAgent forms) per docs/research/g03-windows-wsl.md section "
        "0.1, and the five WSL Mode A probes P-A01-P-A05 (run r3-msi10, same status and criteria, section 0.2). The "
        "other executed native Windows probes used the inbox 9.5p2 only."))
    es = {e["id"]: e for e in d["escalations"]}
    es["E8"]["summary"] = ("31 compressed normalized-text snapshots of third-party documentation are committed for "
                           "independent verification: the 27 non-git spec sources and the auxiliary sources A01-A04 "
                           "(docs/sources/snapshots/README.md). Copyright stays with the publishers. If the repository "
                           "is ever published, the owner should decide whether to keep, replace with hashes plus "
                           "archive URLs, or remove them; not decided here.")
    d["reopen_conditions"][-1] = ("Owner amends spec 19, or docs/compatibility/matrix.md cites a source not listed in "
                                  "this file or in tests/evidence/artifacts/g03/sources/source-pins.json.")
    by = {s["id"]: s for s in d["sources"]}
    by["S28"]["note"] = by["S28"]["note"].replace("Page text hash stable across two fetches in v1/v2;",
                                                  "Normalized text identical in the v2 baseline and repeat runs;")
    by["S05"]["excerpt"] = ("AuthenticationMethods, AuthorizedKeysFile, AuthorizedPrincipalsFile, TrustedUserCAKeys all "
                            "present; \"AuthorizedPrincipalsFile Specifies a file that lists principal names that are "
                            "accepted for certificate authentication.\" ; \"TrustedUserCAKeys Specifies a file containing "
                            "public keys of certificate authorities that are trusted to sign user certificates for "
                            "authentication\"")
    by["S21"]["excerpt"] = ("\"Platform Architectures iOS device and simulator Android aarch64, armv7 macOS arm64, x86_64 "
                            "Linux x86_64, aarch64, armv7 (glibc and musl) Windows x86_64, aarch64\" (table cells "
                            "flattened by the normalizer) ; \"iroh is written in Rust, so the Rust crate is the most "
                            "fully-featured way to use it.\"")
    for i in ("S05", "S21"):
        by[i]["note"] = ((by[i]["note"] + " ") if by[i]["note"] else "") + (
            "M00-T02-fix2: verbatim quotes from the snapshot were added to the excerpt so that `fetch_pins.py "
            "excerpts` can check it (it had no quoted fragment).")
    for i in ("S16", "S18", "S34"):
        by[i]["note"] = by[i]["note"].replace("observed 2026-10-09T05:36Z by `fetch_pins.py upstream`",
                                              "observed by `fetch_pins.py upstream` at 2026-10-09T05:36Z and again "
                                              "at 06:14Z (fix2/upstream1.json, final_upstream.json)")
    by["S17"]["note"] = by["S17"]["note"].replace("Re-observed 2026-10-09T05:36Z by `fetch_pins.py upstream`",
                                                  "Re-observed by `fetch_pins.py upstream` at 2026-10-09T05:36Z and "
                                                  "06:14Z")
    ob = d["candidates"]["iroh"]["other_bindings"]
    ob["python_swift_kotlin"] = ("A01 lists Python (Official, prebuilt wheels), Swift (Official, iOS + macOS) and "
                                 "Kotlin (Official, JVM + Android); A03 says these bindings, like JavaScript, are built "
                                 "on iroh-ffi/uniffi; versions not individually checked")
    save(d)


if __name__ == "__main__":
    ph = sys.argv[1]
    if ph == "skeleton":
        skeleton()
    elif ph == "fill":
        fill(*sys.argv[2:4])
    elif ph == "text":
        text()
    elif ph == "review":
        review()
    else:
        raise SystemExit("unknown phase " + ph)
