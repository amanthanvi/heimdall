# M02 revision-3 independent design review — proceed after fixes

Reviewer: Codex GPT-6.1 Sol (reasoning effort high), independent, read-only, separate worktree.
Saved by the orchestrator on 2026-11-01. The findings are verbatim; the assessment and
command sections are condensed, as marked. The full text is in the reviewer's T3 thread
for task M02-T00-design-review-round3.

**Task:** M02-T00-design-review-round3
**Commit reviewed:** `d96a9b1cd024ed371018a02e535191a11a0dd3ca`
**Verdict:** **proceed after fixes**

Revision 3 repairs most of the round-2 issues. The fail-closed landing, separate approval types, historical prepared facts, fresh eligibility checks, and discriminating confirmation-key controls are substantial improvements. However, the recovery table still omits reachable states, identity-only restoration can discard a newer in-place edit, and the frozen writer interface does not specify how it obtains target bytes. Correct those before freezing wave 0's transaction interfaces. The `config_tree_changed` completeness claim also needs narrowing.

ADR7 = `docs/decisions/0007-existing-access-integration.md`; M02 = `docs/architecture/m02-plan.md`.

## Round-2 findings

| Finding | Status | Revision-3 assessment |
|---|---|---|
| M2-R01 — premature settlement prevents update restoration | **Resolved** | ADR7:312–317, 459–462, 490–504 retain displaced P until the transaction check and durable `item.committed`; M02:832–851 tests. |
| M2-R02 — interrupted restores and unsafe settlement | **Partially resolved** | Durable restore phases, quarantine settlement and explicit missing/foreign outcomes address the original cases (ADR7:368–393, 743–808); the table remains incomplete and identity-only handling loses some edits (M2-S01–S03). |
| M2-R03 — undetermined digests reuse consent | **Resolved** | ADR7:266–297; M02:1025–1029. |
| M2-R04 — stored facts outlive declarations | **Resolved** | ADR7:1123–1152; M02:289–290, 320–336, 1247–1262. |
| M2-R05 — inherited fallback identities can prompt | **Resolved** | ADR7:1154–1182; M02:337–342, 1253–1259 (design under the owner-declaration model, not proof of provider behavior). |
| M2-R06 — mutable-tree authorization race | **Resolved** | ADR7:964–985; M02:603–609, 632–645. The new post-run completeness claim is M2-S04. |
| M2-R07 — wave-0 contract not implementable | **Partially resolved** | Typed receipts, separate approvals, two-phase activation, rescoped kind mapping (M02:214–241, 252–306, 2030–2074); the writer port lacks a target-content source (M2-S05). |
| M2-R08 — nondiscriminating tests | **Resolved** | M02:1192–1201; ADR7:904–908, 594–605, 612–642. |
| QR3 — "any scope" wording | **Resolved** | ADR7:632–640, 1845–1846; M02:1735. |

## New findings

### M2-S01 — major — The recovery table omits reachable create and post-validation states
**Locations:** ADR7:743–754, 794–818, 836–850; M02:751–753, 852–857. **Observed:** create recovery inherits only F0–F1 and F8–F9 and adds C1–C5; there is no create row for a last receipt of `file.exchanged` (written before post-validation) nor for `file.restore_started`. F3 leaves `path S, aside ∅` unspecified; F4 does not specify `path S, aside X/∅` after a valid post-validation; C1–C4 have no catch-all for a foreign active entry after the created S was replaced. **Failure (inference):** (1) first adoption creates the user config, writes `file.exchanged`, crashes before `file.post_validated` — no applicable row; (2) create-undo writes `restore_started` and crashes before `settling` — no row; (3) a displaced file disappears after `post_validated{valid}` before an outcome record — F4's precondition fails while T1 promises restoration. **Fix:** define a total transition function over step shape, receipt phase and observations, with conservative conflict outcomes for every unmatched combination; crash tests after every create receipt and before create-restore settlement, plus missing/foreign-aside cases after post-validation; generate observations independently of the table's row inventory.

### M2-S02 — major — Restoring and settling by identity alone can delete a newer in-place edit
**Locations:** ADR7:368–390, 795–806, 898–903; M02:744–753. **Observed:** restore receives S and D identities, verifies identities, then settles S through quarantine; nothing preserves changed bytes in S. ADR7:898–903 excludes only a writer that opened the file before the commit point. **Failure (inference):** an update exchanges P (S active); an editor opens the now-active P by path and rewrites it in place (identity S unchanged); the user-file check fails and requires restoring old P; restore exchanges and settles S, deleting the editor's newer content — contradicting A22 (`spec.md:1125–1131`). **Fix:** distinguish identity ownership from unchanged content; before discarding a restored-away staged entry verify its expected content digest and preserve/report modified content as a conflict artifact; carry the expected digest through the restore/settlement contract; test an in-place edit opened after the forward exchange, followed by transaction rollback and restart.

### M2-S03 — major — F0x can claim a foreign Git lock without ownership evidence
**Locations:** ADR7:339–341, 666–668, 734–737, 784–785. **Observed:** F0x permits deleting an unreceipted aside entry after type, owner, link-count and target-digest checks, on the grounds that the name is random and exclusively created; B_git's staged name is the deterministic Git lock name, an intent can exist before exclusive creation succeeds, and the design promises a lock Heimdall did not create is never removed. **Failure (inference):** another Git writer owns `<global file>.lock` after the setup intent is durable; Heimdall crashes before recording a result; if the foreign lock contains the planned target bytes, F0x's checks pass and recovery deletes it. **Fix:** treat an unreceipted deterministic Git lock as unowned — preserve it and report a conflict; if automatic recovery is required, specify a crash-surviving ownership mechanism not based on content equality; test a pre-existing foreign lock containing exactly the target bytes.

### M2-S04 — medium — `config_tree_changed: false` cannot establish a complete command inventory
**Locations:** ADR7:986–990; M02:599–602, 636–642. **Observed:** the post-run check rereads digests only for files the static pass read, then claims `executed_config_commands` is complete when `config_tree_changed` is false. **Failure (inference):** a new file matching an Include glob appears with `Match exec` before SSH reads it (no previously read file changed); or an included file is changed for SSH's read and restored before the comparison. **Fix:** define the field as a comparison of observed snapshots and never derive inventory completeness from equality; rewalk include expansion when reporting differences; state that the list contains constructs found before execution; add new-glob-member and change-then-revert controls.

### M2-S05 — major — The frozen writer port does not specify how it obtains target bytes
**Locations:** M02:181–193, 1938–1942, 1994–2001; ADR7:710–730. **Observed:** `ProjectionWriter::apply` receives only `SetupIntent` and a receipt sink; `SetupIntent` carries digests, consent and file steps, each target absent or a SHA-256 — neither rendered content nor the `ProjectionSpec`. `preview` receives a spec but no durable content object or retained preview state is defined. **Failure (inference):** a fresh writer instance receives an approved first-adoption intent, or resumes before a file was staged, and cannot reconstruct the new alias section or public-key bytes from a digest. **Fix:** freeze an explicit source of target content (nonsecret rendered bytes bound to target digests, or sufficient immutable rendering input supplied to both apply and recovery); define restart behavior with no in-memory preview cache; test a fresh writer with no prior `preview`, including recovery before staging a remaining file.

## Assessments (condensed)
- **Recovery/quarantine/serialization:** quarantine repairs the check-to-unlink race within the same-user threat model; the table is not complete (M2-S01); row-vector coverage cannot establish completeness; `setup_in_progress` is appropriate — perform the empty-set check and admission in one store transaction and add simultaneous-admission and restart tests.
- **QR7–QR11, P7–P9:** all sound; QR7 matches `crates/contract/src/request.rs:596–605` and `crates/ipc/src/session.rs:21–24`; P7 needs M2-S05 first; P8 needs atomic admission; P9 discloses the later-created XDG-file residual.
- **M01 compatibility:** the U0b "Today" descriptions match `operations.rs` (Facts, `ensure_data`, `drive`, recovery), `store/src/ext.rs` (`intent_update_allowed`, receipt/intent JSON tolerance, grant queries) and `domain/src/operation.rs`; byte-identical re-encoding remains a required test.
- **Wave 0:** proceed after correcting M2-S01–S03 and M2-S05 in the frozen transaction contract, and M2-S04 in the probe contract; no owner-only decision needed.
- **Commands:** inspection only (git, rg, nl, sed, Python gzip read of pinned S01); no builds, `check.sh`, native harness or network. Changed files: none.
