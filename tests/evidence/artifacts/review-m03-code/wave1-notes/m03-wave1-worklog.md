# M03 wave 1 worklog (untracked; integrator)

Goal: U1, U4, U5, U9, U11 as one integrated, uncommitted change set in this worktree (base
`9b3984ba`, main after the M02 exit `47edb97d` and wave 0 `4a4a4f74`). No commit, push, stash,
reset or checkout. Acceptance: units' plan tests pass here or are precisely accounted for
(native-only, owner-blocked, docker, needs-later-unit); `check.sh` every step exit 0; host and
Windows clippy clean; Linux type-check clean.

## Constraints / decisions
- Shared brief `.m03-wave1-brief.md`; readings `.m03-wave1-api.md`; questions
  `.m03-wave1-questions.md`; cross-target helper `.m03-wave1-xcheck.sh` (all untracked; removed or
  left for the orchestrator at the end, reported).
- Seven agents (Opus 5.5): U1, U4, U5-pure, U5-scripts, U5-io, U9, U11. U5 split three ways
  because its scope (≈150 plan tests) spans the pure crate, the shell scripts and the I/O crate.
- Docker tests: `#[ignore = "docker: …"]` + `HM_DOCKER_TESTS=1` assertion; run explicitly here.
- Owner-blocked tests: `#[ignore = "blocked: Bn …"]`. Later-unit deps: fake the port or "not done".
- Already-pinned workspace deps may be added to a unit crate's own manifest (lock: heimdall-*
  dependency arrays only); recorded per unit.

## Progress
- [x] Read plan §0–§5, §7; ADR-0008 §17.14–§17.16, §18; wave-0 API, worklog, index rows.
- [x] Integrator landed: `SecretCaKey` API (`cert.rs`) + `SystemRng` (`vault.rs`) + credential deps
  getrandom/thiserror; credential lib tests 4 passed (`cargo test -p heimdall-credential --lib`).
- [x] Reserved edits: `app/src/lib.rs` `pub mod lock;`, `runtime/src/lib.rs` `pub mod
  session_lock;`, `testkit/src/lib.rs` 8 U11 modules; placeholders; 11 `[[test]]` targets in 7
  manifests; dev-deps. `cargo check --workspace --all-targets` exit 0, no warnings. Cargo.lock: +16
  lines, heimdall-* arrays only.
- [x] `.m03-wave1-xcheck.sh linux|windows -p heimdall-credential`: both finished clean.
- [x] Seven unit agents done (U1, U4, U5-pure, U5-scripts, U5-io, U9, U11); reports integrated.
- [x] Integration: rustfmt on 11 U4 files; Windows dead_code fix in `tests/e2e/issuer_ceremony.rs`;
  U9 observation prefix `m03 observation:` (INT-Q4).
- [x] check.sh run 1 → exit 1 (clippy-windows 101, test 101 = M02 a27 only, native-harness-selftest 1).
- [x] Root cause of a27: CF/Security/CoreGraphics linked → `__CF_USER_TEXT_ENCODING` injected at load
  (C probe) → escalated INT-Q2, M02 test unchanged.
- [x] check.sh run 2 → exit 1: only `test` 101 (a27); 2360 passed, 1 failed, 187 ignored.
- [x] Independent adversarial review (Opus, read-only): fixed findings 1 (inspect lock-before-content),
  3 (HeldForeign never proof), 4 (exact ready line), scratch passphrase race; escalated 2, 5, deletion
  scope, bootstrap 30 (INT-Q5..Q8). Verifier clock: INT-Q3 (date+awk, plausibility guard).
- [x] Re-runs: registry, enroll (host 75+51), issuer, testkit scratch: exit 0. Docker: up.sh 0;
  enroll_registry --ignored 172 passed; enroll_verify docker row passed; down.sh 0 CLEANUP CONFIRMED;
  rebuilt acl image removed by exact name.
- [x] check.sh run 3 → exit 1: every step 0 except `test` 101, the one failure being M02
  `e2e_run_m02::a27_cwd_and_env_preserved_plus_only_documented_additions` (INT-Q2); 2361 passed,
  1 failed, 187 ignored; native-harness-selftest 315/0; clippy-windows 0.
- [x] Hygiene: removed target/x86_64-pc-windows-gnu and target/x86_64-unknown-linux-gnu (target 27G
  kept for the orchestrator); no prototypes/*/target; /tmp scratch of all agents and integrator gone;
  Docker: no heimdall containers; only the pre-existing heimdall-g02-harness image remains.

## Unit notes
(Agents may append one dated line per cross-unit fact.)
- 2026-11-10 U4: stores/backup/ceremony/retire/bundle landed (API §U4). Observed on this host (Darwin 27.2): a read of a **locked** file keychain with interaction disabled returns `errSecAuthFailed` (-25293), not `errSecInteractionNotAllowed`; U4 maps both to `interaction_not_allowed` (`issuer_store_locked`).
- 2026-11-10 U5-pure: registry `hm1::parse`, `classify_step`, `step::{remote_step, trust_pins, check_effective}`, `fence::*`, `plan::{build, plan_digest}` landed (see API file U5-pure); `CaView` gains `issuer` + `context` (U5P-Q1).
- 2026-11-10 U1: `cert::{CertificateProfile, build_and_sign, validate_installed, key_id}` landed and compile (signatures in `.m03-wave1-api.md` U1).
- 2026-11-10 U1: `vault::KeyVault`, `purpose::{parse_userauth, check, check_bound, GrantCertificates}`, `session_bind::{parse, verify, accept}`, `sys::{lock_pages, harden_process}` landed; seeded derivation = U11's rule (answered under Requests).
- 2026-11-10 U5-scripts: `registry::script::{inspect,bootstrap,append,remove,fence}` + param types + `test_form` landed and compile (signatures and the pause protocol in `.m03-wave1-api.md` U5-scripts).
- 2026-11-10 U11: testkit M03 fixture interfaces landed and listed in .m03-wave1-api.md §U11 (TestCa, SshdConfig M03 fields, TwoHosts/ThreeHosts, RegistryGuard, PauseHooks + pause protocol, Truncation, Faults, LaggingClock, WrongKey, PrincipalsNotEnforced, lock pause control, procstat, shells, managed, installation, owner_digest).
- 2026-11-10 U9: `heimdall_runtime::session_lock::PlatformSessionLockSource` and `heimdall_app::lock` (effective behaviour + R3 floor, disclosure, labels, `run_lock_passes` driver) landed; macOS polls CGSession (distributed notifications reach only a main-thread run loop, U9-Q4); signatures in `.m03-wave1-api.md` U9.
- 2026-11-10 U5-io: enroll remote/verify/trace and localenv target/known_hosts raw keys landed (API file U5-io section); Verifier has the U11 nonce_known pause via with_test_pause_dir.
- 2026-11-10 U5-scripts: M00-T03 fixtures brought UP by U5-scripts at 11:17Z (up.sh exit 0) for the docker_dash rows; U5-scripts runs down.sh when done (tell the integrator if you need them kept).
- 2026-11-10 U5-scripts: M00-T03 fixtures torn down at 11:30Z (`down.sh` exit 0, CLEANUP CONFIRMED); U11 shell image removed by down.sh; U5-scripts' own `heimdall-u5s-debian-acl:local` removed by exact name.

## Commands (integrator) with exit codes
- `cargo test -p heimdall-credential --lib` → 0 (4 passed)
- `cargo check --workspace --all-targets` → 0

## Round 2 (orchestrator rulings ADR-0008 §17.17, 2026-11-10)
- Item 6: `classify.rs` already read write_failed as Uncertain; unit test
  `write_failed_exit_30_is_uncertain_for_append_and_remove` added; mutation (disable) → 101.
- Item 5: `crates/enroll/src/sys.rs` (Linux `pre_exec`: `set_parent_process_death_signal(Some(Signal::KILL))`
  + `getppid()` race check), `PARENT_DEATH_SIGNAL_APPLIED = cfg!(target_os = "linux")`; test asserts on Linux
  that ssh dies before the agent answers. Host clippy 0; linux xcheck enroll 0; macOS cli_ tests pass.
  rustix 1.1.6 names the constant `Signal::KILL` (the ruling's `Signal::Kill`).
- Item 1: A27 test accepts at most one `__CF_USER_TEXT_ENCODING` (exact form) on macOS when absent from
  the input; pass-through case with this user's uid; form test. Mutation (drop tolerance) → 101. ADR-0007
  §8 sentence. CF rewrites foreign-uid/malformed values (INT-Q9).
- Item 4: `ResolveInput.lock_floor` (+2 initializers), floor merged at the two `no_mechanism` args,
  `with_lock_and_connection(.., floor)` at both call sites (6744 via `let floor`), origin =
  `lock::origin_behavior(&policies, floor)`. Regression passes; mutation (floor dropped) → 101.
- Item 3: `retire::{delete_recorded, RecordedItems, NoRecordedItems, LocatorNotRecorded,
  LocatorMismatch}`; `StoreEffects::new(store, recorded, unload)`, `StoreItemDeletion::new(store,
  recorded)`; old fingerprint-wide `delete_confirmed_absent` fn removed. Two regressions (shared OS store,
  macOS shared keychain); mutation (old behaviour) → both 101.
- Item 2: Darwin `kern.bootsessionuuid`, `HM_BOOT_STABLE` gate on the boot shortcut (BSD timestamp rows
  need the group proof); goldens regenerated; start_identity test updated; new
  `timestamp_boot_identity_difference_alone_never_proves_gone` (macOS host, `uname` shim). Two mutations
  → 101. Docker: up.sh 0, 172 passed, verifier docker row passed, down.sh 0 CLEANUP CONFIRMED; acl image
  removed by exact name.
- Text: ADR-0008 M-F23, utilities, gone rule, shell table macOS/BSD rows, verifier command, D9 macOS row
  (⟨r7⟩); overview §9 items 5 (U4-Q2), 6 (poll) and new 7 (enroll sys.rs).
- Notes archived to `tests/evidence/artifacts/review-m03-code/wave1-notes/` (paths redacted);
  `.m03-wave1-xcheck.sh` → `tools/validation/linux-xcheck.sh` (Linux only; shellcheck 0;
  `--workspace` → 0 after gating the macOS-only test fn and a `type_complexity` fix).
- check.sh (round 2): every step exit 0; 2368 passed, 0 failed, 187 ignored; native-harness-selftest
  315/0.

## Round 3 (independent review W1-R01–R03; native Linux and Windows runs; 2026-11-10)
- B3: `M02_REPO_DIRS` + `docs/architecture tests/model` (only `managed_domain.rs` read outside); X29 extended.
- B6/B7: platform-correct client path (`remote.rs` tests) and pipe forms (`target.rs` test).
- B5: cause — the test read any `HEIMDALL_E2E_BIN` as a release CLI; both native harnesses ship the debug
  CLI. Now the profile comes from the CLI's own answer; old logic reproduced failing here with E2E_BIN set.
- B4: shell table by family; an unrowed version prints `m03 observation: shell_table_row`.
- A3: `SourceSnapshot.{locked_entries, last_locked, unknown_entries}`, `locked_since`; native rows wait for a
  real `locked` reading; unit test `unknown_never_counts_as_a_real_lock_observation` (mutation → 101).
- A1/A2: `store::attributes::{AttributeStore, AttributeBackend}` (env-scoped put/get/delete/list);
  Linux = AttributeStore<SecretServiceBackend>; macOS list scoped to the account; Windows default dir per
  environment; `store_and_check` adopts exactly one installation-scoped item. Regressions: shared fake
  attribute store (all hosts), macOS shared disposable keychain, Linux private-session row (gated). Both
  mutations → 101.
- B1: verify fixture sshd offers `PerSourcePenalties` and drops it only when `sshd -t` names it.
- B2: cause found in a disposable Ubuntu 24.04 container (OpenSSH 9.6p1 Ubuntu-3ubuntu13.20, same as
  the devbox): K_env `.pub` as IdentityFile + cert-only agent → 9.6 signs with the absent file key.
  Tests use a decoy IdentityFile; new observation test; INT-Q10 escalated.
- C: debug-only `Verifier::with_test_trace_dump`; the positive verification test prints
  `m03 observation: client_trace_row` lines for an unrecorded client and fails. Container (9.6p1): every
  10.5p1 pattern string observed identically; positive accepted, negative refused. Not recorded (devbox
  rerun is the source).
- Also found in the container: Ubuntu 9.6p1 lists `gssapikeyexchange`, so `effective_config_has_every_trust_pin`
  now runs the Q23 two passes; CLI-death rows need an init that reaps orphans (`--init`; systemd on the
  devbox).
- D (for U13): the devbox has 12 GB free; the full 72-binary tar hit ENOSPC. The M03 Linux harness needs
  batching (HM_ONLY lists) or debug-info stripping for the exit runs.
- Round 3 checks: Docker up.sh 0, `integration_enroll_registry --ignored` 172 passed, the Debian 13
  verifier row passed, down.sh 0 CLEANUP CONFIRMED; check.sh every step 0 (2372 passed, 0 failed,
  187 ignored; native-harness-selftest 316/0); clippy-windows 0; linux-xcheck --workspace 0.

## Round 4 (9.6p1 trace row from the devbox run at `5b36b3d8`; 2026-11-10)
- Recorded `RECORDED` row portable 9.6p1..9.6p1 from the devbox log's `m03 observation: client_trace_row
  family=portable version=9.6p1` lines only (source comment: observed on the devbox, `5b36b3d8`). Observed:
  server_version, host_key_matched, offered, accepted, can_continue, publickey_failure.
- **Missing from that log:** the host-key-failure lines (no attempt failed host verification). Not inferred:
  the row's `host_key_failure` is empty, so on 9.6p1 a host-key failure classifies as transport-inconclusive
  (fail closed). `verification_host_key_mismatch_holds_no_rollback` now prints
  `… field=host_key_failure` observation lines for such a row and fails (not a pass) until they are recorded.
- Tests that used 9.6p1 as the unrecorded example now use 9.7p1 (trace unit test, verify unit test,
  `trace_patterns_keyed_by_release_family`, the doctor-finding and unrecorded-client verification tests).
- Validation only, not a source: `integration_enroll_verify` cross-built for x86_64 Linux ran in a disposable
  `--network none` Ubuntu 24.04 container (`OpenSSH_9.6p1 Ubuntu-3ubuntu13.20`): 50 passed, 1 failed (the
  host-key test above, by design), 1 ignored; it printed "Host key verification failed." and
  "REMOTE HOST IDENTIFICATION HAS CHANGED" for both attempts. Image and scratch removed.
- ADR-0008 §17.18 and `wave1.md` (orchestrator's) untouched; INT-Q10 unchanged (wave 2).
- Round 4 checks: check.sh every step 0 (2372 passed, 0 failed, 187 ignored; native-harness-selftest 316/0).
  Devbox rerun: `HM_ONLY="integration_enroll_verify heimdall_enroll-unit"`.

## Round 5 (9.6p1 host-key-failure patterns from the second devbox run; 2026-11-10)
- Source: the devbox rerun on the round-4 tree (`HM_ONLY="integration_enroll_verify heimdall_enroll-unit"`):
  `… field=host_key_failure` lines, both attempts against a changed host key, both exit 255.
- 9.6p1 `host_key_failure` = "Host key verification failed.", "REMOTE HOST IDENTIFICATION HAS CHANGED",
  " has changed and you have requested strict checking." (each in both attempts). The unknown-host lines
  (`No … host key is known for`) were not observed on 9.6p1 and are not recorded. Row comment and evidence
  name both devbox runs.
- `verification_host_key_mismatch_holds_no_rollback` restored to its `5b36b3d8` form; the
  `observe_host_key_failure_trace` helper removed (nothing else used it).
- New unit test `devbox_9_6p1_changed_host_key_trace_is_a_host_key_failure`: each 9.6p1 string occurs in
  the observed (redacted) trace, which parses as a host-key failure with no other event; adding an
  unobserved string → 101. `only_recorded_rows_have_patterns` now requires every recorded row to carry
  host-key-failure strings.
- Validation only: disposable `--network none` Ubuntu 24.04 container (`OpenSSH_9.6p1
  Ubuntu-3ubuntu13.20`): `heimdall_enroll` lib 13/13, `integration_enroll_verify` 51 passed, 0 failed,
  1 ignored. Image and scratch removed.
- check.sh every step 0 (2373 passed, 0 failed, 187 ignored; native-harness-selftest 316/0).
