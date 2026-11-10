# M03 wave 0 worklog (untracked; integrator)

Goal: U0 + U0b phase 1 as one uncommitted change set in this worktree (base 410ec237).
No commit, no push. Acceptance: check.sh exit 0 (all steps incl. new), code golden 30 rows,
crate graph clean + mutants caught, M01/M02 unchanged, deps pinned ≥ 2 weeks old + recorded.

## Constraints / decisions
- `todo = "deny"` in workspace lints: skeleton bodies are fail-closed errors, never todo!().
- missing_docs warn + clippy -D warnings: every pub item documented.
- Shared brief for all subagents: `.m03-wave0-brief.md`. Per-agent questions files
  `.m03-wave0-questions-<agent>.md`, merged by me into `.m03-wave0-questions.md`.
- Test env var names fixed by me (brief §6). Test target placement fixed by me (brief §5).
- Phases: P0 = A1 types (contract+domain+crate skeletons), B2 ipc row 1, T tools, V verify, D deps.
  P1 = A2 interfaces (ports, managed API, Txn sigs, migration, Operations sigs, registry/
  credential/issuer/enroll skeletons, testkit managed). P2 = bodies in parallel (store, app
  narrowing/signing, app issuance/ensure/policy, runtime rows, CLI/testcfg, tests+schemas). P3 = docs,
  integration, check.sh x2.

## Progress
- [x] Integrator wrote `crates/domain/src/claims.rs` (Claim type, empty CLAIMS) + `pub mod claims;`.
- [x] P0 launched: A1 (opus, contract+domain), B2 (opus, ipc row 1), T (sonnet, tools + check.sh
  steps crate-graph/claims-table/release-gate), V (sonnet, m03-wave0-verify.md), D (sonnet, deps).
- Revised phase plan: after A1 → launch A2 (interfaces + new crates + testkit managed), S (store
  migration/Txn/tests), X (contract tests, schemas/examples, domain goldens) in parallel.
  After A2 → G (app::managed bodies + rows 5/20/25/26/27), O (rows 2/3/4/9–12/22/19), R (runtime rows
  6/7/8/13/14/17/18/23/28, config FORBIDDEN_KEYS), C (CLI tree, testcfg row 16, e2e).
- Note: tokio RwLock is FIFO-fair (A3 assumption) — check G uses it or equivalent.
- [x] T done: crate_graph.py, claims_table.py, release-gate.sh + check.sh steps. Self-tests PASS.
  release-gate: 17/21 pass; 4 M03 vars not yet refused (C must add to testcfg, keep "HEIMDALL_TEST_" in text).
- [x] D done: dependencies.md §5 (M03), `.m03-wave0-deps.md` has exact TOML + 6 lock downgrades
  (aes 0.9.3, ctutils 0.4.6, inout 0.2.5, uuid 1.29.0, zcheapstr 1.1.0, js-sys 0.3.106/wasm-bindgen 0.2.129).
  Extra windows-sys features: Win32_System_Memory, Win32_System_LibraryLoader. Questions D Q1–Q4.
  To apply in N (new crates) phase.
- [x] B2 done: row 1 (ipc signing) + 10 tests in ipc_signing_m03; ipc tests/clippy (host+win) 0.
  Questions B2 Q1–Q6 (PeerIdentity vs PeerInfo; unpermitted signature sent as-is → escalate).
  TODO me: ipc lib.rs crate docs test-target list mention.
- [x] V done: docs/architecture/m03-wave0-verify.md; E1–E14. Integrator readings adopted (fail-closed,
  escalated): E1 A1 writes check body; E2 recovery-path index names U5/U10 tests as planned; E4 M03
  not-available helper in a new module outside M02_SOURCES; E5 PeerIdentity; E6 (a) re-validation
  covers env-permission, (b) detect read-only → gate → re-run end_in under gates, (c) cutoff set =
  active/degraded grants of the policy's profile whose bound it lowers, (d) gates in Inner +
  Operations::signing_gates(); E7 refuse EndpointKind::Issuer in both listener constructors; E8 separate
  M03 reason list + helper owner_reconcile; E9 option (a); E10 cancel of enrollment kinds refused in
  phase 1; E11 mechanical test edits only; E12 Txn::open_enrollments, table-absent = none; E14 managed
  port calls in app/src/managed.rs.
- [x] A1 done (types; workspace check+clippy 0; 3 expected golden/schema failures → X).
  API index `.m03-wave0-api.md`. Integrator pre-added all M03 [[test]] targets + placeholders
  (model_managed_domain, integration_store_m03, model_signing_gates, model_operations_m03,
  model_narrowing_m03, integration_runtime_m03, e2e_cli_m03).
- [ ] P1 launched: A2 (app ports + managed gates, row 24, row 21 types), S (store 0006 + ext_m03 + tests),
  N (4 crates + deps + lock downgrades + testkit managed), X (independent goldens + examples + schemas).
- Next (after A2): G (narrowing rows 5,7,20,25,26,27), O (rows 2,3,4,9–12,19,21,22), R (runtime rows
  6,8,13,14,17,18?,23,28 + E7 ipc Issuer refusal + FORBIDDEN_KEYS), C (CLI tree + testcfg row 16 + uninstall row 18).
- [x] A2 done (ports, managed gates row 24, 19 tests). Integrator enabled tokio test-util in app/runtime dev-deps (A2-Q1).
- [x] N done (4 crates, deps, 71 pkgs, lock downgrades, testkit managed: FakeSessionLockSource full,
  ScratchSecretStore fail-closed). Integrator renamed golden to tests/contracts/golden/issuer-protocol.json (N2).
- [ ] P2 launched: G (opus), O (opus), R (opus), C (sonnet). S, X still running.
- [x] S done: migration 0006, SCHEMA_VERSION 6, ext_m03 (all §5 item 18 methods + helpers incl.
  open_enrollments, seed_enrollment test support), 21 tests; store suites green. Questions S1–S6
  (S1: partial unique index blocks removing an abandoned line once a new enrollment is open → escalate).
- Orchestrator RULED S1 (user message): partial unique index covers only enrollment-path states
  (planned, applying, outcome_unknown, verifying, applied_unverified, verified, reverifying, held);
  excludes removal/rollback states, abandoned, finals; cancel returns to removal_origin. 3 store tests.
  Integrator addition: manual_pending kept IN the index (omitted from the ruling's list; live by its
  principle) → flagged for confirmation. Sent to S (resumed).
- Orchestrator CONFIRMED manual_pending inside the index (part of S1, ruled). Relayed to S.
- [x] S1 applied by S (positive IN list incl. manual_pending; 3 tests; 24+77 pass). Follow-up to escalate: a removal of an abandoned line that goes to `held` (in-index) collides with a new live enrollment (GenerationConflict) — consequence of `held` being shared by removal and enrollment paths. Also S's extra: cancel with origin ≠ persisted removal_origin refused (fail-closed).
- Orchestrator RULED S1 follow-up: (1) cancel with wrong origin refused — confirmed; (2) held with removal_origin set is outside the index; test added. Relayed to S.
- [x] S1 follow-up applied by S (removal_origin_set column; predicate excludes held+origin; 25+77 pass, clippy 0).
- [x] X done: contracts 89 tests, model_managed_domain 21, 22 examples, schemas regenerated (additive only),
  goldens (reasons 62, transitions 88 rows, recovery paths 54 planned). X found 3 code defects → integrator
  fixed: (1) foreign manual-removal cancel from abandoned origin (enrollment.rs cancel_target),
  (2) pending CA no longer issues grant certificates (issuance.rs check_ca → UnknownCa),
  (3) DestinationClock hand-written Deserialize tolerating unknown sibling keys. All contract+domain tests green.
  Open: X-Q1..Q8 (X-Q1–Q3 transition-table design questions) → escalate.
- [x] C done: M03 CLI tree (33 lines), handlers in m03_cmd/issuer_cmd/enroll_cmd/connections_cmd
  (USAGE_ERROR exit 2 = M01 envelope, built at run time), testcfg M03_ENV, uninstall refusal
  (CONFIG_CONFLICT exit 6 / bundle_required), release-gate 21/21 PASS. TODO me: add `enroll` probe for
  HEIMDALL_TEST_SCRIPT_PAUSE_DIR to release-gate.sh. Questions C1–C6.
- [x] G done: rows 5,7,20,25,26,27; 46 tests in model_narrowing_m03 (5x clean); preserve suites green.
  Key call G-Q1: zero-gate narrowing commits in one serializable txn with no marks (all wave-0 cases) →
  escalate. G-Q2 row 27 storage (requested_at = op created_at; committed_at = Tombstone.revoked_at).
  Notes R's runtime_m03.rs clippy needless_update (R in progress).
- [x] O done: rows 2,3,4,9,10,11,12,19,21,22,E10 (7 child modules); 36 tests; preserve suites + host & win clippy 0.
  Q4 asks to add `interaction_required` reason → not added (would diverge from plan's reason table; never produced in wave 0) → escalate.
- Orchestrator RULED G-Q1 (accepted with condition: any gated member ⇒ full protocol for the whole set; 2 tests;
  comment) → sent to G. RULED O-Q4 (accepted; no interaction_required in wave 0) → recorded in questions-O.
- [x] R done: rows 6,7(sup),8,13,14,17,23,28,E7,item 22,w0_no_reachable_todo; 20 tests; host+win clippy 0.
  Integrator replaced R's E9 workaround with domain `procstat::parse_start_time` (group not checked),
  platform uses it; tests green.
- [ ] G applying G-Q1 condition (in progress). Then: merge questions, ADR-0006 rev 4, full check.sh x2.
- [x] G-Q1 condition applied (48 tests). G-Q13 NEW (open, escalate): gate dropped at last-instance release while a signer holds it → future late signature; unreachable in wave 0.
- check1: all steps 0 except test (101): testkit repo::no_other_test_reads_the_compile_time_root — runtime_m03.rs:398, operations_m03.rs:1983 used CARGO_MANIFEST_DIR → fixed to repo_root(). ipc lib.rs docs test list updated (B2-Q7).
- check2: ALL steps exit 0 (2010 passed, 0 failed, 8 ignored).
- check3: ALL steps exit 0 (2010 passed, 0 failed, 8 ignored). Two consecutive clean runs (2, 3).
- Hygiene: removed target/x86_64-pc-windows-gnu and target/tmp; target/ 34G kept for the orchestrator's
  review re-run (delete target/ when integrated). No prototypes/*/target. Secret/home-path scan of all
  changed + new files: clean.
- DONE. Remaining: phase-2 rows (wave 4), U1–U13 bodies, native runs, orchestrator rulings on open index rows.

## Round 2 (orchestrator rulings ADR-0008 §17.15, 2026-11-08)
- Sent: item 1 G-Q13 → A2 (gate never dropped with holder/mark + test); item 2 B2-Q3 → B2 (permit-less
  signature only for ungated grant; refuse+record; 2 tests); item 3 R4 → R (nominally_expired keeps record);
  items 4–6 X-Q1..Q3 → A1 (code) + X (golden, independent).
- Done by me: item 7 plan §5 item 3 example → bare 64-hex; item 10 `//` comment at SessionConfig.lock_behavior
  (not `///`, to keep the config schema unchanged); index statuses updated (21 ruled, 78 provisional).
- Remaining: collect 5 agents, check.sh once, reply (diff stat, new/changed tests, step exits).
- [x] item 2 (B2): SignOutcome.ungated + ungated_signature(); signature() requires a permit; permit-less undeclared → failure + SigningSession.refused_permitless + tracing warn; 2 tests; ipc tests/clippy host+win 0.
- [x] items 4–6 code (A1): manual-recovery events carry `purpose` (append|rollback|removal); system form refuses them;
  reconcile_damaged in remove_unknown/rollback_unknown → held; removal recovery absent→removed, present→held.
  A1 reading to confirm: rollback recovery absent→verification_failed, present→held. 6 golden pairs pending X.
- [x] item 3 (R): nominally_expired keeps record (grant still revoked once); bounded_complete-only removed;
  BoundedReport.nominally_expired; 2 new tests, 1 changed; runtime/app tests + clippy 0. No settle path in wave 0 (U10).
- Orchestrator CONFIRMED A1 readings (rollback purpose; purpose field frozen) — §17.15 item 6; recorded in index; sent to X.
- [x] item 1 (A2): gates kept while held/marked (retiring), release_exclusive, Narrowing::release_instance; 6 new + 1 updated test. X: golden cites §17.15 item 6; 21 pass. All agents done → check.sh round 2.
- check4 (after §17.15): ALL steps exit 0, 2020 passed, 0 failed, 8 ignored. Cross-build dir removed.

## Round 3 (independent code review, fix first; ADR-0008 §17.16) — branch m03/wave0 @ 87b9a263 (orchestrator commit)
- R1 (policy narrowing), R2 (env-permission removal under narrowing), R3 (defer releases gates) → G.
  R4 (permit continuous expiry from paired readings) → A2. R5 (foreign removal cancel validation) → S.
  Each with named regression + mutation check. Index: G-Q10, V-E6(a) overturned.
- [x] R5 (S): removal_origin_kept shared rule (ext_m03.rs:168), applied in transition_foreign_removal (:1284) and transition_enrollment (:527, same hole). Regressions foreign_removal_cancel_cannot_downgrade_absence_history (mutation: FAILS at store_m03.rs:2198 'downgrading cancel admitted', restored cmp-identical) + enrollment_transition_cannot_downgrade_absence_history (not mutation-checked separately). 27+77+19 pass, clippy 0.
- [x] R5 second regression mutation-checked: FAILS at store_m03.rs:2271 (flag reset admitted) with transition_enrollment fix reverted; restored cmp-identical; passes.
- [x] R4 (A2): authorize.rs:296–326 paired (Instant, ops clock) reading at step start; expiries absolute; refuse if expired after read (DeadlinePassed) or boot differs. Regression authorization_latency_never_extends_continuous_budget (mutation: FAILS at narrowing_m03.rs:2844 'continuous expiry past original budget end by 500ms'; restored cmp-identical; passes). app/runtime tests + clippy 0.
- [x] R1–R3 (G): policy_commit narrows every authority-reducing action (narrowing.rs:1152, policy_reader :944); Operations::set_environment_permissions (:1055); Narrowing::acquire releases holds before deferring and restarts in order (managed.rs:716/729/736). 4 regressions, all mutation-checked. Tests + clippy 0. → check.sh x2.
- Orchestrator: check R1 pause routing (ADR-0006 §13.6 item 1). My read: authorize.rs has no pause check; pause routed at narrowing.rs:958. Stopped my check.sh x2 (task b77myh8kc; no worktree processes left; cargo PIDs 74713.. are another session in the main checkout — not touched). Sent pause/connection-policy review + regression to G.
- [x] Pause follow-up (G): (a) probe: authorize never refused on pause (no M01 semantic change); pause + set_connection_policy removed from narrowing set (narrowing.rs:967, doc 928–947); kept: revoke_on_lock, cutoff earlier, env-permission removal. 2 regressions mutation-checked (fail at narrowing_m03.rs:3168). → check.sh x2.
- check5: all 0 (2029 passed). check6: test 101 — two_real_policy_cutoffs_overlapping_commit_within_bound flaky (random grant IDs; 32-candidate search for A<B). Sent to G to make deterministic + 200x stress + re-mutation. Then check.sh x2 again.
- [x] Deflaked (G): B = max of 8 pre-created grants; ≤128 candidates for A<B (P(miss)<1e-120). 200/200 pass; mutation still fails at :3153. → check.sh x2.
- check7, check8: ALL steps exit 0, 2029 passed, 0 failed, 8 ignored. Round 3 done. Diff vs 87b9a263: 6 files +988 -92. Cross-build dir and logs removed.
