NOT CLOSED — R01 still permits replay when fence evidence is lost or expires too early; R02's adoption path has a blocking rollback window.

Scope: 11df9a00..04c20baa, static design re-check only. ADR-0009 §2.1 determines blocking severity.
ADR = docs/decisions/0014-hardening-and-release-artifacts.md; M08 = docs/architecture/m08-plan.md.
R01 open — ADR §3.6 replay-fence steps 3–5; M08 U2b/§11: ordinary retained-ledger and readable-store traces are addressed, but attendance and a retention-length wait cannot establish freshness.
R02 open — ADR §3.6 “Store generations”: the generation switch fixes partial SQLite-family moves; adoption publishes CURRENT before durably fencing the legacy family, with no recovery rule for that interval.
RC-N01 fixed — ADR §3.6 operation record/Reset; M08 U2b/§7.2 journey 5: reset has its own completed generation and restart/repeated-operation cases, so it is no longer mistaken for an incomplete restore.
R10 fixed — M08 §9 P2 and probe record limitations: the Syft result is expressly a recorded summary, not independently checked; missing component evidence is no longer called reproducible.

Choices 1–4:
1. Sound basic ordering: sync the external request-ledger append before the first store write; ADR-0006 §7.3 already requires the store write before external effects. No request payload or clear identifier is specified; hashes remain correlation metadata. Namespace and lifetime need correction (N01/N03).
2. Not acceptable as the fallback: an attended retry can still repeat the same completed request, and a quiet period cannot make an unknown caller-minted ID new. Reauthorization does not repair missing evidence.
3. Copying avoids split-family moves, but the subsequent legacy-schema write creates a two-step adoption protocol that needs its own durable recovery order. The one-way pre-release rollback boundary must appear in ADR §3.2 and M08 §7.2, not only the layout paragraph (N02).
4. Consistent: CURRENT selects the generation; transactional SQLite migration updates that selected database. This does not select a different generation or require a switch. Migration annotations must be recoverable completion metadata, not an alternate generation-selection authority.

Replay/reopening traces:
- Old store readable, ledger present OR lost: later terminal operation/idempotency records carry forward; after reopen and reauthorization the retry returns the terminal answer without executing again, within their retained lifetime.
- Old store unreadable, intact retained ledger: the post-backup digest becomes a stored REQUEST_STALE answer before publication; reopening/reauthorization does not clear it. This closes the original concrete trace while its entry survives.
- Old store AND ledger unreadable/lost: non-interactive mutations are blocked only during the quiet period; an attended same-ID retry is admitted immediately. After the quiet period, an unidentifiable old ID can also be admitted non-interactively. Neither path proves a new logical request.
- Old decision references are explicitly refused after reauthorization; uncarried operation/effect references are epoch-stale. Carried terminal answers remain history. Runner reconciliation adopts applied effects from the runner's ledger rather than resending them; that part follows ADR-0012 §7.

Findings / required changes:
N01 — blocking, continuing R01; ADR §3.6 fence steps 3–4; M08 U2b/§11. Store corruption plus ledger loss and an ordinary owner retry can duplicate a durable effect: terminal attendance is not a freshness discriminator. Require a verifiable new-request boundary and fail closed when it cannot be established, for attended requests too; replace the test that expects the bypass with a no-duplicate-effect case.
The retention rule is also incomplete: ADR-0006 §7.4 retains unresolved keys indefinitely, starts retention at settlement, then keeps expired-key markers for 30 more days. Trimming the ledger or ending the quiet period at ordinary operation retention can admit still-protected IDs. Specify preservation/carry-forward of these markers and unresolved-key fences, including when only the ledger remains readable; test those boundaries. This meets ADR-0009 §2.1 through ordinary recovery and lasting operation/remote effects.
N02 — blocking, adoption regression within R02; ADR §3.6 Adoption/Interruption; ADR §3.2(7–8); M08 U2b/§7.2 journeys 3–4. Crash after CURRENT publication but before the legacy schema-fence transaction: an older executable can still serve the flat copy. A revocation made there is absent when the newer executable next follows CURRENT, reviving the earlier authority state.
Durably fence the legacy family before publishing/serving the adopted generation, with a resumable adoption intent covering the pre-publication interruption; do not rely on older builds understanding CURRENT. Document the one-way adoption/rollback boundary and test crash → older-build rollback → newer restart, not just completed adoption → older-build refusal. Ordinary crash/user rollback with lost revocation meets ADR-0009 §2.1.
N03 — moderate, nonblocking namespace regression; ADR §3.6 fence step 3/H9; M08 U0/U2b. SHA-256(principal, request ID) omits operation kind and caller role, plus remote_client required by ADR-0012 §3.7. Distinct valid caller/kind keys collapse, and the digest cannot identify the ordinary idempotency key described in ADR-0006 §7.1. Hash the canonically encoded full key and specify digest lookup for fence records; test equal IDs across clients/kinds.

Crash/recovery and evidence limits:
- For an already-adopted store, the specified database/record/directory flushes precede temporary-pointer flush and rename; faults before publication select the untouched old generation, faults after publication select the completed new one. Missing/dangling pointers refuse service. Unique generations and predecessor records support retention across repeated restore/reset; cleanup must preserve committed predecessors.
- Windows write-through and POSIX directory sync are design requirements, not observed results here. Planned process-kill/I/O-error cases establish no power-loss durability; that limitation is explicit and appropriate. No production implementation or native fault results exist in this revision.
- Beyond the findings above, no further contradiction found with spec §11.4/§13.3, plan §5 M08/§10, ADR-0012 or ADR-0009; publication remains separately authorized and P2 supplies no release-gate evidence.

Checks run (actual exit codes):
- git fetch origin docs/m08-hardening-and-release-plan: 0; git rev-parse HEAD 11df9a00 04c20baa: 0. HEAD remained de097dac; review content came from the fixed Git objects.
- git diff 11df9a00 04c20baa, --stat, --numstat, and --check: 0 each; four paths, +159/-57. git diff --exit-code over spec.md, plan.md, ADR-0009 and ADR-0012: 0 (unchanged).
- Read-only git show/cat/sed/rg/Python inspection: 0 for executed inspection batches. Python four-path scope, JSON parse and matching P2/limitation assertions: 0. No build, Heimdall execution, runtime/native test, key/agent/keychain access, publishing, or network beyond fetch.
- git status --short before/after inspection: 0, empty. Report readback, privacy, line-count and final repository status checks: 0.
Changed files: only /tmp/hm-tools/m08-design-recheck2-out/report.md; no repository edits or scratch retained. Risk: unresolved design failures above; this report does not certify runtime behavior.
