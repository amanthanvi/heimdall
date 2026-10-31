#!/usr/bin/env python3
"""M00-T02-fix4: dated notes in docs/sources/pins.json (kept for provenance). No pinned value is touched.

Run once from the repository root with `python3 -I -B`. It appends a dated "claim re-read" note to S16, S17, S18 and
S34 (the four GitHub sources that drifted on `main` and are cited by the still-open gate G07), replaces the last
sentence of the S29 note with the recorded disposition, adds one pointer sentence to reopen_conditions[0] and [1],
and sets fix4_edited_at_utc. The facts come from the fix4 runs (fix4/24_upstream.out, fix4/27_drift_diffs.out) and
the recheck3 contextual reads (recheck3/claim-S16.out ... claim-S34.out); the wording of each note is the ledger's
(docs/sources/drift-2026-10-31.md). The script refuses to run twice (it checks the notes still end as expected).
Nothing that `fetch`, `compare`, `verify` or `excerpts` reads is changed: only `note` and `reopen_conditions` text.
"""
import json

P = "docs/sources/pins.json"
LEDGER = "docs/sources/drift-2026-10-31.md"
raw = open(P, encoding="utf-8").read()
d = json.loads(raw)
assert json.dumps(d, indent=1) + "\n" == raw, "pins.json is not in the canonical dump format"
before = {s["id"]: {k: v for k, v in s.items() if k != "note"} for s in d["sources"]}
S = {s["id"]: s for s in d["sources"]}

S16 = (" Claim re-read 2026-10-31 (M00-T02-fix4, %s): holds. Main (blob 0c328c50317c) still has both quoted statements (2/2); "
       "the new text adds route-walking, credential and fork-key details around them and leaves 'identity is independent of the route' "
       "unchanged. The pinned permalink stays the citation of record." % LEDGER)
S17 = (" Claim re-read 2026-10-31 (M00-T02-fix4, %s): holds, with a qualification. Main (blob 698ddac7a73f) still says the supervisor owns "
       "transport retry policy and that reconnection does not automatically replay mutations (2/2). An adjacent detail changed: the pin says "
       "credential expiry does not close the socket; main says the server closes a socket when its session is revoked or expires and the driver "
       "renews a live socket's token in its last minute. The spec cites S17 for supervision and the replay boundary only, so no cited claim "
       "changes; a gate that wants T3's expiry behavior as a precedent (G07, G09) must read both versions. The pinned permalink stays the "
       "citation of record." % LEDGER)
S18 = (" Claim re-read 2026-10-31 (M00-T02-fix4, %s): holds, with a qualification. Main (blob 4c9bbcb780be) still has the three quoted "
       "statements (3/3), but the relay's not proxying environment sessions now has one stated exception: automation webhooks are forwarded "
       "to the environment's tunnel (and can be held by the relay while the environment is offline, if the environment opts in). The "
       "control/transport/session separation precedent stands with that exception. The pinned permalink stays the citation of record." % LEDGER)
S34 = (" Claim re-read 2026-10-31 (M00-T02-fix4, %s; first found by recheck3, claim-S34.out): changed, adjacent to the excerpted statements. "
       "The three quoted fragments are still on main (3/3) and the narrow statements hold (a bootstrap exchange can narrow a grant but not widen "
       "it; projects are not filesystem sandboxes). But the pin says ordinary pairing does not grant access-management or relay-management "
       "authority, while main says the default grant includes access and relay management, and that terminal:operate (a shell as the server's "
       "user) or orchestration:operate (can start a full-access agent) can mint a session with every scope through `t3 auth session issue`, so "
       "withholding management from the default would not be a boundary. Main also names the file-reading scope filesystem:read (the pin calls it "
       "orchestration:read) and adds that a URL minted before the grant was revoked keeps working until it expires. Disposition: qualification recorded. "
       "The immutable pin stays the experiment baseline; main's defaults are not promoted into any Heimdall contract; G07's authority-boundary "
       "investigation (plan.md section 3, G07: attempt privileged management as a limited client; pairing must not become unlimited owner authority) is "
       "retained, reopened on this point, and its owner re-reads the main section." % LEDGER)
S29_LAST_OLD = " Whether a gate that is still open relies on the Zig version is not checked here."
S29_LAST_NEW = (" Disposition (orchestrator, M00-T02-fix4, 2026-10-31, %s): qualification recorded, pin kept. G02 keeps the pinned, "
                "frozen TypeScript candidate (prototypes/ts depends on the published @opentui/core 0.5.14, not on a source build); that candidate "
                "was rejected on the security-assumption and child/IPC gates (ADR-0002 section 3 and 3.3), which do not depend on the Zig version, "
                "so it is not re-tested. The Zig requirement (0.16.0 at the pin, 0.17.0 on HEAD) is a requirement for building OpenTUI from a "
                "checkout; no gate, matrix row or spec sentence relies on it. `upstream` keeps exiting 2 while the quoted Zig line is absent from "
                "HEAD: that standing exit is accepted and recorded here, and the excerpt keeps quoting the pin." % LEDGER)

# preconditions: nothing has been appended yet
for i in ("S16", "S17", "S18", "S34"):
    assert "M00-T02-fix4" not in S[i]["note"], i + " already edited"
assert S["S29"]["note"].endswith(S29_LAST_OLD), "S29 note does not end as expected"
for i, add in (("S16", S16), ("S17", S17), ("S18", S18), ("S34", S34)):
    S[i]["note"] = S[i]["note"] + add
S[("S29")]["note"] = S["S29"]["note"][: -len(S29_LAST_OLD)] + S29_LAST_NEW

rc = d["reopen_conditions"]
assert "fix4" not in rc[0] and "fix4" not in rc[1]
rc[0] += (" Dated dispositions of the 2026-10-31 drift (21 spec and 4 auxiliary CONTENT sources, 4 branch-drifted GitHub sources, 1 lost "
          "fragment): %s." % LEDGER)
rc[1] += (" Re-read on 2026-10-31 (M00-T02-fix4): S16 holds; S17 and S18 hold with qualifications; S34 changed adjacent to its excerpts "
          "(default grants), so G07's authority-boundary investigation is retained; S29 lost its Zig 0.16.0 fragment and is closed by the "
          "recorded G02 disposition (%s)." % LEDGER)
d["fix4_edited_at_utc"] = "2026-10-31"

after = {s["id"]: {k: v for k, v in s.items() if k != "note"} for s in d["sources"]}
assert before == after, "a non-note field changed"
with open(P, "w", encoding="utf-8") as f:
    f.write(json.dumps(d, indent=1) + "\n")
print("notes added to S16 S17 S18 S34, S29 note closed, reopen_conditions[0] and [1] extended; no other field changed")
