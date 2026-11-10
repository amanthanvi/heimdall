# M03 wave 2 worklog (untracked; integrator)

Goal: U2 (signer + endpoints), U3 (issuer child + protocol + client), U8 (projection + consumer
integration + M02 residuals) as one integrated, uncommitted change set in this worktree (base
`961c6201`, main after wave 1 `c97e6be2`). No commit, push, stash, reset or checkout. Acceptance:
units' plan tests pass here or are precisely accounted for (native-only, owner-blocked, docker,
needs-later-unit); `check.sh` every step exit 0; host and Windows clippy clean; Linux
type-check clean (`linux-xcheck.sh --workspace`). Owed: INT-Q10 (U2+U8), `assess_read_only`
(U3, §17.15 item 8), test store kind only if U3 registers through the wire (§17.17 item 13),
wave-1 leftovers (purpose/session_bind in U2, KeyVault::sign on the blocking pool, two certs
per VerificationSession, `build_and_sign` + `harden_process` in U3, `retiring → unloaded` U3,
ManagedRunContext's real managed block U8), ADR-0007 §13 residuals (U8).

## Constraints / decisions
- Shared brief `.m03-wave2-brief.md`; readings `.m03-wave2-api.md`; questions
  `.m03-wave2-questions.md`; Windows per-package helper `.m03-wave2-xcheck-windows.sh`.
- Three agents (Opus 5.5): U2, U3, U8. The integrator runs INT-Q10 itself in
  `tests/integration/managed_identity_forms.rs` (target `integration_managed_identity_forms`,
  host heimdall-credential).
- R3 (verification signatures refused by `Operations` in production) escalated as INT-Q13.

## Progress
- [x] Read plan §0, U2/U3/U8, §2–§4; ADR-0008 D2, D3, D5 §6.5, D10, §17.15–§17.18; wave-1 API
  notes and worklog.
- [x] Reserved edits: 6 `[[test]]` targets in 4 manifests + placeholder files; dev-deps
  (credential: testkit managed, tokio test-util, heimdall-store; issuer: tokio test-util,
  heimdall-store). `cargo check -p heimdall-credential -p heimdall-issuer -p heimdall-localenv
  -p heimdall --tests` → 0. Cargo.lock: +1 line (`heimdall-store` in heimdall-credential).
- [x] Three unit agents started (T3 delegate_task, shared checkout, claude-opus-5-5 inherited):
  U2 signer, U3 issuer, U8 projection. Integrator: INT-Q10 next.

## Unit notes
(Agents may append one dated line per cross-unit fact.)
- 2026-11-10 U8: `render::DEFAULT_MANAGED_IDENTITY_FORM = CertificateAsIdentityFile` (INT-Q10) is the one selector for P and `connect`; R7's slot path function is `heimdall_localenv::projection::content::managed_slot_paths` (refuses unsafe destination IDs, U8-Q3); `testkit::managed::ManagedRunContext`'s block now comes from the real renderer (form `CertificateAsIdentityFileAndCertificateFile`, route lines left to the caller).
- 2026-11-10 U3: `TimeGate::assess_read_only` body landed (persists nothing; fails closed without a same-boot runtime anchor/confirmation); unit tests follow in app `timegate.rs` tests — integrator may flip `AuthorizationTime` default to `ReadOnly` once U3 reports them green. U3-Q1 (store by-ID getters private) filed.
- 2026-11-10 U3: `assess_read_only` tests green (`integration_issuer_child`: `assess_read_only_on_open_read_only_store_writes_nothing`, `assess_read_only_fails_closed_without_anchor`); U0b `model_narrowing_m03::authorize_refuses_each_predicate` now fails at narrowing_m03.rs:757 (it asserted the wave-0 stub); fix suggested in `.m03-wave2-api.md` §U3.

## Commands (integrator) with exit codes
- `cargo check -p heimdall-credential -p heimdall-issuer -p heimdall-localenv -p heimdall --tests` → 0

## INT-Q10 (integrator)
- Wrote `tests/integration/managed_identity_forms.rs` (cross-platform: unix socket or named pipe via
  M01 listeners + `ipc::signing::serve`; agent lists only the certificate; D10 block shape).
- Host 10.5p1: `cargo test -p heimdall-credential --test integration_managed_identity_forms -- --nocapture` → 0.
  D10 as written 255 (also with 0600 files); cert-as-IdentityFile forms 0/cert; verification shape asks `plain`.
- Built `heimdall-w2-intq10-u2404:local` (ubuntu:24.04 + openssh-client/server; network only at build);
  `ssh -V` = `OpenSSH_9.6p1 Ubuntu-3ubuntu13.20`. Cross-built test (zig shims) → container `--network none`,
  user hmtest: first run (5 forms + control) → 0, same results as 10.5p1. Rerun with context rows pending
  (app mid-edit by U3: cross build exit 101 at that moment).
- Decision: default `ManagedIdentityForm::CertificateAsIdentityFile`; INT-Q10 row in questions file.
- Incident: U2 and the integrator added async-trait/tokio/tokio-util to credential's manifest at the same
  time (duplicate keys); removed the integrator's copy.
- Container rerun with context rows (build 0, run 0): 9.6p1 identical to 10.5p1 on every row, incl. D10 with
  0600 files 255 and the verification shape asking `plain`. API §INT-Q10 table complete.

## Unit reports
- U8 done (2026-11-10): render.rs `Section`/`ManagedIdentityForm` (default `CertificateAsIdentityFile`),
  owned-launch pins and refusals, projection managed sections + slot_free disclosure + deadline wording,
  `LocalProjection::writing` (state_dir), client-aware agents, connect/run flows fail closed, testkit
  `ManagedRunContext` via the real renderer (CONTEXT_IDENTITY_FORM = both lines, for U11's `ssh -G` check).
  Its targets green (integration_projection_managed 13, e2e_consumer_m03 6, M02 suites unchanged); clippy +
  both cross checks 0. Failing at report time: `heimdall --bin` `m03_lines_answer_without_touching_the_home`
  and `e2e_cli_m03::w0_m03_cli_commands_report_not_available_and_never_panic`, both from U3's in-flight
  `internal issuer` arm. Questions U8-Q1..Q6. Requests: destination_view `preference` (U8-Q6, wire field:
  escalated, not done), service/testcfg `LocalProjection::writing` wiring (U10), doctor slot_free (not U8's
  path), managed identity-selection classification (U6/U0b).
- U2 done (2026-11-10): signer/endpoints/table + `integration_managed_signer` (35 passed, 1 ignored = B3
  cross-account row; ×3 runs, all under `AuthorizationTime::ReadOnly`). clippy 0, linux-xcheck 0, Windows
  helper 0 except the integrator's `managed_identity_forms.rs` (unused `home` on Windows) and fmt of the same
  file → integrator fixed both (fmt check 0, Windows helper `-p heimdall-credential` 0). Questions U2-Q1
  (who persists `credential_instances`: register is in-memory; U10) and U2-Q2 (install store view: refused
  `store_view_unavailable`, `INSTALL_STORE_VIEW_WIRED = false`). Verification endpoint lists K_verify + current
  cert, accepts the plain-K_verify request only with the current positive cert presented; negative cert never
  signed for. Spot-read of `signer.rs` sign path (steps 1–5, budget overrun drops the permit, poisoned bind).
- INT-Q10 test gained the product row `rendered_p_<form>` (P's section from `render_sections` with
  `ManagedIdentityForm::select(None)`; dev-dep heimdall-sshconf on heimdall-credential, lock: heimdall-credential
  array only). Host 10.5p1 → 0 (rendered row 0/cert/1); container 9.6p1 (`/tmp/hm-w2-intq10-build/run.sh`) → 0,
  rendered row 0/cert/1.
- Container validation of `integration_managed_signer` (9.6p1, x86-64 emulated): 34 passed, 1 failed
  (`sign_during_revoke_is_linearized`: "both outcomes seen: 0 / 2000", the non-vacuity check: under emulation
  the revocation always won). Integrator fix in U2's test: the revocation's start is jittered in real time over
  0..2× a measured uncontended signature latency. Host → 0; container `--exact` → 0. session_bind row on 9.6p1:
  `sent=yes accepted=1 refused=0 signs_bound=1` (validation only).
- U3 done (2026-11-10): ca/check/child/client, issuance_ro body, `assess_read_only(_in)`, `internal issuer` arm
  (m03_cmd.rs; one expectation 2→5 on a pipe), tests (issuer_child 30, linearization 6). Reserved hunks under
  integrator authorization: operations.rs `issuance_predicate` split + `issuance_check_read_only`,
  verification_m03.rs `verification_check_read_only`. Questions U3-Q1..Q4. Test store kind NOT landed (no wire
  registration). U3-Q4 (testkit `managed` in heimdall's production dep for the scratch store) left for U10:
  not needed in wave 2; fail closed (exit 69).

## Integration (integrator)
- R2 flip (§17.15 item 8): `AuthorizationTime` default `Peek` → `ReadOnly` (narrowing.rs; authorize.rs docs).
  U0b test `authorize_refuses_each_predicate` updated (both seams: admit ok, wall pulled back → TimeUncertain);
  new regression `authorization_time_defaults_to_read_only_assessment`; mutation (default back to Peek) → 101,
  restored → 0. Runtime suites: model_narrowing_m03 56, model_operations 186, model_operations_m03 36,
  integration_runtime_m03 22 → 0.
- U3-Q1 resolved: `Txn::issuance_entry`/`verification_entry` pub (store ext.rs/ext_m03.rs, docs only) and
  `issuance_ro::stored_entry` by ID. `cargo test -p heimdall-issuer` → 0 (12+30+29+6).
- `cargo fmt --all --check` → 0; `cargo clippy --workspace --all-targets --locked -- -D warnings` → 0.
- check.sh run 1 → exit 1: every step 0 except `test` 101; 2474 passed, 1 failed, 188 ignored. The failure:
  `e2e_cli_m03::w0_m03_cli_commands_report_not_available_and_never_panic` (`internal issuer` on a pipe now runs
  U3's child arm, exit 5, not the wave-0 envelope). Integrator fix in `tests/e2e/cli_m03.rs` (U0's): the line
  leaves the wave-0 list; new assertions: exit 5, empty stdout, no home created. `cargo test -p heimdall --test
  e2e_cli_m03` → 0 (3).
- Independent adversarial review (Opus, read-only, no builds) started on the signer/issuer/owned-launch code.
- check.sh run 2 → **exit 0**, every step 0: 2475 passed, 0 failed, 188 ignored.
- Internal adversarial review (Opus, read-only): no high/medium; three low + one hypothesis. Handled:
  1. (low) Environment endpoint's fresh read did not check the requested pair or that the slot is `held`
     (authorize.rs, U0b's wave-0 code): now requires an unreleased binding of the grant that **holds** that
     pair's slot in this environment. Regression `environment_endpoint_requires_the_pairs_held_slot_in_the_store`
     (managed_signer.rs); mutation (pair check dropped) → 101; restored → 0 (36 passed, 1 ignored).
  2. (low) `check_owned_ssh_arguments` missed `-o '=ControlPersist=yes'`, `'"ControlMaster"yes'`: render.rs
     `option_keyword` now follows OpenSSH `strdelim` (`config_token`). Each spelling checked with `ssh -G -o …`
     (10.5p1): `=ControlPersist=yes` → controlpersist yes; ` =ForkAfterAuthentication=yes` → ssh exit 255;
     `"ControlMaster"yes`, `Control"Master" yes` → controlmaster true; ` "ControlPath" /tmp/x` → controlpath set;
     `==ControlMaster=yes` and an unmatched quote → nothing set. Regression cases added to
     `render::tests::owned_arguments_follow_ssh_option_parsing`; mutation → 101; restored → 0.
  3. (low, latent) `install_verification` checks no CA/pair: added to INT-Q13 (factory gets no plan; fail closed).
  4. (hypothesis) verification entry for a retiring-but-not-unloaded CA: confirmed by reading (the predicate
     never reads CA state; CaSet caches it). check.rs now re-reads the CA state in the snapshot for verification
     entries (`active|pending`, else `ca_not_loaded`). Regression
     `verification_entry_for_retiring_ca_refused_from_snapshot` (issuer_child.rs); mutation → 101; restored →
     issuer_child 31 passed.
- check.sh run 3 (final, after the review fixes) → **exit 0**, every step 0: 2477 passed, 0 failed,
  188 ignored; native-harness-selftest 316 passed, 0 failed. `linux-xcheck.sh --workspace` → 0.
- Cleanup: image `heimdall-w2-intq10-u2404:local` removed by name (no `heimdall.fixture` container left; the
  pre-existing `heimdall-g02-harness` image untouched); `/tmp/hm-w2-intq10-build` and the integrator's
  `/tmp/hm-w2-*` logs removed; `target/x86_64-unknown-linux-gnu` (5.8G) and `target/x86_64-pc-windows-gnu`
  (2.5G) removed (target 35G → 26G; `target/debug` kept for the orchestrator); no `prototypes/*/{target,
  node_modules,dist}`. Helper `.m03-wave2-xcheck-windows.sh` removed (`tools/validation/clippy-windows.sh`
  is the whole-workspace equivalent).
- Notes archived to `tests/evidence/artifacts/review-m03-code/wave2-notes/` (dot dropped, paths redacted).
