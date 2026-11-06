# M03 work breakdown (managed credentials and meaningful deadline behaviour): revision 1

**Status:** proposed, revision 1 (task M03-T00-design). It has not been reviewed yet.

**Inputs:**
* plan §5 M03 (T01–T06, exit evidence), §3 G04 and G09, §6, §10, §13 (the eleven requirements M03
  owns: R-UX-03, R-AU-04, R-AU-05, R-AU-08, R-CR-02 to R-CR-07, R-SE-07);
* spec §4.3, §6, §7, §8.1, §8.7, §10, §11.3–§11.6, §13.2–§13.6, §14, §15.1–§15.2, §16, and §17 A03,
  A07, A09, A10, A23, A33, plus the cases those requirements cite (A05, A08, A11, A24, A28, A30, A31);
* `docs/decisions/0008-managed-credential-integration.md` revision 1, this plan's design ADR (below:
  "ADR-0008");
* ADR-0005 (recipe B1, accepted), which ADR-0008 implements;
* ADR-0006 revision 3 through §15, with §13.1–§13.20 ruled. This plan extends it with the revision-4
  deltas of §5;
* ADR-0007 revision 5 with §12.1–§12.41, including its §13 residuals for M03;
* ADR-0004 (the delegated decisions, the ADR-0004 §2 lock rule, the ADR-0004 §3 authorizations);
* `docs/research/g04-managed-credentials.md`;
* `docs/architecture/{m01-plan,m02-plan,m02-exit-draft,overview,dependencies}.md`;
* `tests/fixtures/MANIFEST.md`;
* `progress.md`, for blocked inputs B1–B10 and lessons.

**Basis:** the code at `1f5b8156`. M02's exit is not closed, and its Windows native fixes are being made
elsewhere. Every dependency on an M02 internal that may still change is marked **⟨M02?⟩** and listed in
§0.4.

**Status discipline** (M01 rule E15, carried): every unit stays `implemented_unverified` until U13's
evidence records exist, whatever its local tests say.

**Skeleton rule** (as in M01 and M02): U0 creates every type, trait and function named below. Bodies are
`todo!("M03-Uxx …")` where they are not yet implemented. A unit replaces the bodies it owns and adds
tests. Shared signatures, tables and limits change only through the integrator, with an ADR-0006 or
ADR-0008 revision.

**No `todo!()` is reachable** from any of:
* a request, through the session or the dispatcher;
* a CLI command;
* restart recovery;
* a supervisor pass;
* any store method that U0b's code calls.

Code that its driver has not yet replaced **fails closed** instead:
* requests: `CAPABILITY_UNAVAILABLE`, reason `driver_unavailable`, before any record is written;
* the new decision kinds: refused, not consumed;
* CLI: M01's "not available in this build" envelope;
* restart: an M03 operation stays unresolved and untouched;
* the managed adapter is not registered, so a managed pair resolves to `CAPABILITY_UNAVAILABLE`
  (`driver_unavailable`).

The wave-0 acceptance tests in U0b prove each of these.

**Not decided by this plan:** ADR-0008 §17 Q1–Q17 and the plan-level questions in §6. Units build
against the recommended answers. Where a unit depends on one, it says so, and the integrator flips the
switch if the ruling differs.

---

## 0. Ground rules for every unit

### 0.1 Ownership and test targets

* Write only inside the owner paths below, plus the unit's own test files.
* These files change only through the integrator (U0, U0b):
  * `Cargo.toml`, `Cargo.lock`, `clippy.toml`;
  * `crates/contract/**`;
  * `crates/domain/**`;
  * `crates/app/src/{ports,context,ensure,lib,operations,events,error}.rs`;
  * `crates/store/migrations/**`, the `Txn` signatures and `crates/store/src/{ext,ext_m02,ext_m03}.rs`;
  * `crates/runtime/src/dispatch.rs` and the capability list in `crates/ipc/src/session.rs`;
  * `crates/ipc/src/signing.rs` (the `Signer` trait change, U0b row 1);
  * `crates/heimdall/src/cli.rs` (the clap tree);
  * the shared test fakes: `crates/testkit/src/lib.rs` and `crates/heimdall/src/testcfg.rs`;
  * ADR-0006, ADR-0008 and this file.
* Test targets follow the M01 convention (m01-plan §0; review F09):
  * every suite is a real `[[test]]` with `path = "../../tests/<layer>/<name>.rs"`, hosted by the crate
    that already has the dependency edges;
  * no `#[path]` inclusion;
  * `check.sh` fails a target that runs 0 tests;
  * platform-only tests are `#[cfg]`-gated and listed in the case index as `platform_only`;
  * tests that read compile-time repository paths are listed in `build_host_paths` (the M02 exit
    lesson).

### 0.2 Fixtures and the owner's material

AGENTS.md; ADR-0008 D13.

* **Disposable material only.** Every key, CA, certificate, agent, keychain item, DPAPI blob and
  registry a test uses is created by that test run, in its scratch directory or a disposable container
  or distribution, and destroyed by it.
* **Never touched:**
  * the owner's `~/.ssh` (read only for the harness's before/after digest), Git configuration and
    agents;
  * 1Password;
  * the login keychain or any keychain on the search list;
  * the Secret Service collections of the owner's session;
  * Credential Manager;
  * any DPAPI blob outside the run's scratch;
  * any real server.
* **Isolation is not configuration** (ADR-0007 §9). Every client a test runs gets only `-F <scratch user
  config>`, `-o UserKnownHostsFile=<scratch>`, `-o GlobalKnownHostsFile=<scratch empty>` and, where
  non-interactive, `-o BatchMode=yes`.
  * **M03 exception:** the production verification (ADR-0008 D5 §6.5) and `connect`'s managed options
    (D10 item 4) are **product** command lines, under test like any product output.
  * Tests never add `IdentityAgent`, `IdentityFile`, `CertificateFile` or `IdentitiesOnly` to a client
    they run.
* **The default-identity guard** (M02 U7) still applies to every client the test starts.
* **The registry guard** (U11 `RegistryGuard`) applies to every enrollment a test runs. The target
  registry must be:
  * under the run's scratch directory (loopback sshd, explicit `--registry-path`);
  * inside a disposable Docker container labelled `heimdall.fixture`; or
  * inside the disposable WSL distribution.

  Anything else is `FixtureUnsafe` before any `ssh` runs.
* **The issuer store under test:**
  * `ScratchSecretStore` in the test configuration;
  * on Windows, real DPAPI on a scratch path (ADR-0004 §3);
  * on macOS, a disposable **file** keychain outside the search list, for the keychain code path only.

  `ScratchSecretStore` and `HEIMDALL_TEST_*` exist only in test-configured builds. U0b's guard test
  proves a release build refuses them.
* **Canaries.** `HEIMDALL_CANARY_*` strings, plus each run's own secret bytes (the seeded K_env, the test
  K_ca, the D5 passphrase), are scanned in:
  * every envelope, event, log line, error, doctor report, rendered file, run record and side-channel
    line;
  * the state database file, the materialized and runtime directories;
  * the process arguments and environments of every process the run started.

  The pty transcript of an issuer ceremony is the **one** place the passphrase may appear (A33).
* **Keys** are generated per run and never committed. Synthetic public keys may be committed only where
  a file header says so.
* **Servers** run only as `LoopbackSshd` (non-root, `127.0.0.1`, ephemeral port), as M00-T03 Docker
  fixtures published on `127.0.0.1`, or as the disposable WSL distribution's sshd on its loopback. There
  are no other listeners.

### 0.3 Evidence discipline

* Statuses: `not_started`, `in_progress`, `blocked`, `implemented_unverified`, `verified`,
  `deferred_with_decision`. Nothing else.
* Records follow `tests/evidence/record.schema.json` and **the lowest-row rule** (ADR-0004 §4): a case
  with any `blocked` row is `blocked`, naming the exact missing input or platform. Its rows that ran may
  be `verified`.
* **Native claims need native runs.** These are never closed by mocks, cross-compiles, containers on
  another OS, or a fake lock source:
  * lock continuity, store availability, endpoint ACLs;
  * the behaviour of a remote shell;
  * a client's signature count and its `session-bind` behaviour;
  * sleep, logout and reboot.
* A row whose input is missing stays `blocked`. It is never weakened into a different claim.
* **The claim table** (ADR-0008 D12) is the only path from a verified record to a reported `verified`
  capability value. It is updated by an integrator commit after U13's records are `verified`. Then the
  claim-reporting tests re-run on that build (§3, "claim update").
* A command not executed has no output. Expected output is never presented as observed. Logs are kept
  until read (the M02 lesson).

### 0.4 Assumptions about M02 internals that may change

Marked ⟨M02?⟩ where used. The integrator re-checks each against the M02 exit build before wave 0, as M02
wave 0 did, and records any delta as an ADR-0008 revision.

| # | Assumption | Used by |
|---|---|---|
| M1 | `CredentialAdapter` keeps `read_sources`/`prepare_from`/`renew`/`reconcile`/`revoke` and the drop contract (`app::ports`, ADR-0007 §7) | U6, U0b |
| M2 | `PrepareOutcome`, `ConsumerIntegration.pairs` and `PreparedFacts` keep their shapes (ADR-0006 §15.1 items 7, 8, 15) | U6, U0b |
| M3 | The projection P, its closed directive set, `ProjectionWriter`'s stateless contract and the setup operations stay as committed. In particular the Windows `RenderPath::windows` behaviour for verbatim paths, which the Windows failure group 1 at `cb16c2d6` is changing | U8 |
| M4 | The Windows projection replace (`ReplaceFileW` with backup) is fixed for the sharing-violation and `NotFound` failures at `cb16c2d6`. U8's slot files on Windows reuse that primitive | U6, U8 |
| M5 | Launch and connect hold the binding through `BindForm::Launch { executable, holder }` with `ProcessHolder { pid, start-time token }`, and `run` execs on Unix and spawns-and-waits on Windows (ADR-0007 §8) | U7, U8 |
| M6 | The catalog stays as committed: `DestinationDefinition::Managed { hostname, port, account, identity }`, one account per managed destination | U5, U8, U0b |
| M7 | The Windows harness's WSL fixture sshd account mapping (at `cb16c2d6` it authenticates only the WSL account while clients log in as the Windows user) is fixed or explicitly parameterized | U11, U13 (Windows rows) |
| M8 | The evidence generator (`tests/native/m02/m02-evidence.py`), the case index format and `run-windows-local.ps1`'s bundle format stay as committed | U13 |
| M9 | The migration sequence ends at `0005_existing_access` (`SCHEMA_VERSION` 5) | U0 |
| M10 | `localenv::known_hosts` reads known-hosts files passively, including hashed entries, and returns the matching key lines for (HostName, Port) | U5 |
| M11 | The M02 static evaluator determines HostName, Port, User and route directives for a managed alias, with explicit `undetermined` | U5, U8 |
| M12 | `testcfg`'s env-gated pattern and `ScratchHome::isolation_args` stay as committed | U11, all tests |

### 0.5 Build and handoff

* Build hygiene follows AGENTS.md:
  * one `./target`, with no `CARGO_TARGET_DIR` or `--target-dir`;
  * remove cross-built `target/x86_64-*` and `target/aarch64-unknown-linux-*` after native runs;
  * `rm -rf` only the scratch directories you created, never by glob;
  * run the `du -sh` check before finishing, and prune per AGENTS.md if `target` exceeds 3 GB;
  * Docker fixtures are torn down with `down.sh`, which must print `CLEANUP CONFIRMED`;
  * a disposable WSL distribution is `--terminate`d and `--unregister`ed by name, never `wsl
    --shutdown`.
* Before handing off, every unit runs `bash tools/validation/check.sh` and records the exit codes and
  test counts.
* Subagents do not commit or push. The integrator integrates, scans what it pushes (secrets, canaries,
  home paths, personal data), and chains the commit after the scan with `&&` (the M02 lesson).

---

## 1. Units

Fifteen units: **U0** and **U0b** (the integrator's), and **U1–U13**. Crate and module names follow
ADR-0008 §18.

### U0: Integrator skeleton and contract revision 4

* **Owner:** the integrator.
* **Owner paths:**
  * the root `Cargo.toml` and `Cargo.lock`;
  * the new crate manifests and skeleton `lib.rs` files for `crates/{credential,issuer,enroll}`;
  * `crates/contract/**` (the §5 deltas): the new modules `crates/contract/src/{enrollment,issuer,managed}.rs`;
  * the new domain modules `crates/domain/src/{enrollment,verification,claims,connection,managed}.rs`,
    and the new variants and fields in `crates/domain/src/{decision,operation,grant,revocation,policy,issuance,resource}.rs`
    (types only; bodies in U0b);
  * `crates/app/src/ports.rs`: the new ports `SignatureAuthority`, `IssuerPort`, `VerificationRunner`,
    `SessionLockSource` and `ConnectionControl`, the `RevokeOutcome` and `AdapterDescriptor` additions,
    and the new `Limits` fields. Remote enrollment steps are client-executed, so they have no port
    (ADR-0008 D5 §6.3);
  * migration `crates/store/migrations/0006_managed_credentials.sql`, with `SCHEMA_VERSION` 6 and the
    `Txn` signatures of §5 item 18;
  * the `crates/heimdall/src/cli.rs` clap tree for every M03 command (§5 item 24), with handlers in
    per-command files that return M01's "not available in this build" envelope until their unit lands;
  * `schemas/public-api/**` (regenerated);
  * `crates/domain/src/claims.rs` (empty table) and the `check.sh` step `claims-table`
    (`tools/validation/claims_table.py`);
  * `tests/contracts/golden/enroll-scripts/` (empty until U5);
  * `docs/architecture/{overview,dependencies}.md`;
  * ADR-0006 revision 4.
* **Does:**
  * applies §5 after the ADR-0008 Q1–Q17 rulings;
  * records the new dependencies in `dependencies.md` (ADR-0008 §18), each with exact version, licence,
    reason and rejected alternatives, pinned at least two weeks old;
  * extends overview §1 with the three crates and overview §9 with the three new `unsafe` modules
    (`crates/credential/src/sys.rs`, `crates/issuer/src/sys.rs`,
    `crates/runtime/src/session_lock/sys.rs`), each with an invariant table;
  * keeps the code golden at **30 rows**: no new code. The new sub-reasons go in a separate golden;
  * lands **together with U0b phase 1** as one integrator change set, because new `Request`,
    `OperationKind` and `DecisionKind` variants break M01/M02's exhaustive matches until U0b handles
    them.
* **Frozen in wave 0.** Later units build on these and do not change them without an ADR-0008 revision:
  * **The ports** (§5 item 19), with their error enums and drop contracts.
  * **The issuer wire protocol `heimdall-issuer/1`** (ADR-0008 D3 item 3; §5 item 20): message enums,
    framing limit (64 KiB), `IssuerRefusal` variants.
  * **`EnrollmentRecord`**, `EnrollmentState`, the event enum and the pure
    `domain::enrollment::transition(state, event) -> Result<EnrollmentState, InvalidTransition>`, exactly
    the ADR-0008 D5 §6.2 table.
  * **`VerificationEntry`** and `domain::verification::check(VerificationCheck) -> Result<(),
    VerificationRefusal>` (signature only).
  * **`CertificateBounds.ca_fingerprint: Option<String>`** (serde default; M01 rows decode as `None`, and
    an M03 reservation requires `Some`).
  * **`RemoteObligation.kind`** (`needs_remote_action` | `bounded_by_expiry { until }`; absent ⇒
    `needs_remote_action`, so M01 records are unchanged).
  * **The slot state machine** `domain::managed::slot_transition` (ADR-0008 D10 item 2 table).
  * **The HM1 output grammar** and the script exit codes (ADR-0008 D5 §6.3; §5 item 21).
  * **The claim entry type** `domain::claims::Claim` and the validator's rules (ADR-0008 D12 item 3).
  * **The test-configuration gates:** `ScratchSecretStore`, `HEIMDALL_TEST_KEY_SEED`,
    `FakeSessionLockSource` and the script pause directory. Each is compiled only under the test
    configuration.
* **Tests:**
  * `contract_code_table_unchanged_30_rows`;
  * `contract_reason_golden` (every §5 item 14 reason with its code);
  * schema export byte-identical;
  * the new examples round-trip exactly:
    `schemas/examples/{request.issuer.*,request.enrollment.*,enrollment-plan,enrollment-result,ensure-data.managed,revoke-data.managed,inspect.enrollments,inspect.issuer,inspect.connections}.json`;
  * `journaled_operation_kinds_match_their_request_kind`, extended (§5 item 12):
    * `enrollment.apply`, `enrollment.verify` and `enrollment.remove` are journaled;
    * `issuer.register`, `issuer.unlock`, `issuer.retire`, `enrollment.reconcile`,
      `enrollment.abandon`, `enrollment.step`, `enrollment.step_result` and `connections.close` are
      effectful and synchronous;
    * `issuer.status`, `issuer.bundle` and `enrollment.preview` are read-only;
    * the helper still matches `Request` without a wildcard;
  * `decision_kind_wire_forms` for `RegisterIssuer`, `RetireIssuer`, `EnrollAccount` and
    `RemoveEnrollment`;
  * `enrollment_transition_table_golden`: every (state, event) pair, with the allowed ones exactly as in
    ADR-0008 D5 §6.2 and every other one refused;
  * `slot_transition_table_golden`;
  * `ensure_data_without_m03_fields_decodes` (an M02 document reads with `lock_continuity:
    not_verified`, empty `conditions` and absent `revocation`), and
    `enforcement_without_m03_fields_decodes_unknown`;
  * `remote_obligation_without_kind_decodes_needs_remote_action`;
  * migration 0005→0006 on a populated database. The M01 and M02 rows decode unchanged and re-encode
    byte-identically:
    * `issuance_log` entries without `ca_fingerprint`;
    * remote-revocation records in the current and the legacy form;
    * cleanup intents;
    * catalog and projection rows.

    A newer `user_version` is refused;
  * `claims_table_empty_validates`, and `claims_table_rejects_entry_for_blocked_record` (a fixture entry
    pointing at a `blocked` record fails the step);
  * `issuer_endpoint_kind_reserved_never_bound`: the documentation test asserting that no listener
    constructor accepts `EndpointKind::Issuer` (ADR-0008 Q1).

### U0b: M01/M02 integration (existing code that M03 must change)

* **Owner:** the integrator. **Phase 1** (wave 0, with U0): every change, fail closed for the new
  requests, plus the M03 store bodies. **Phase 2** (wave 4, with U10): the activation change set (new
  capabilities offered, decision kinds completed, the managed adapter registered).
* **Preserve list.** It must not regress any of:
  * the M01 idempotency, decision completion, recovery, IPC permission, framing, exit-code,
    remote-revocation (`claim_seq`, `effect_seq`, per-obligation caps) and cleanup-intent paths;
  * M02's bounded adapter calls, setup admission and holders.

  The M01 and M02 suites run unchanged.

| Row | Today (at `1f5b8156`) | Change | Phase | Tests |
|---|---|---|---|---|
| 1 | `ipc::signing::Signer { identities(), sign(key_blob, data, flags) }`, no connection context | `Signer` methods take `&SigningSession { peer: PeerInfo, endpoint: EndpointRef, bind: Option<SessionBindRecord> }`. `serve()` creates one per connection and handles `session-bind@openssh.com` by calling `Signer::session_bind(&mut SigningSession, payload) -> bool` (success or failure frame). `NoIdentities` is adapted (empty list, failure) | 1 | the M01 signing suites unchanged; `signing_session_carries_peer_and_endpoint`; `session_bind_reaches_signer_and_answers_success_or_failure` |
| 2 | `domain::issuance::check` knows no CA; `app::operations::permitted_extensions` gives `permit-pty` plus agent forwarding | `IssuanceCheck.enrolled_cas: &[String]` (the CAs whose `verified` enrollment covers the pair, newest first). New refusals `UnknownCa` (no `ca_fingerprint`, or a CA not in the set) and `CaNotVerifiedForPair`. `issuance::extension_profile(grant, pair)` implements ADR-0008 D6 item 1; `permitted_extensions` becomes a wrapper with identical output for M01 grants | 1 | one refusal test per new variant; `extension_profile_matches_adr_0005_3_4_table`; the M01 issuance tests unchanged |
| 3 | `Operations::reserve_issuance(IssuanceRequest)` takes the caller's bounds | The reserve transaction **selects** `ca_fingerprint` itself from `enrollments` (newest `active` CA with a `verified` enrollment for the pair, ADR-0008 D4 item 3). A request naming another CA is refused (`UnknownCa`). Publish re-checks it | 1 | `reserve_selects_newest_verified_ca_for_pair`; `publish_voids_when_enrollment_removed_between_reserve_and_publish`; `publish_voids_when_ca_retired_between` |
| 4 | — | `Operations::{reserve_verification, publish_verification, void_verification}` over the `verification_issuance` table, with `verification::check` (ADR-0008 D5 §6.5 item 2), `TimeGate` inside the transaction, and the per-pair residual | 1 | one refusal per predicate; `verification_entries_counted_in_pair_residual`; `reserved_verification_never_published_after_restart` |
| 5 | — | `Operations::authorize_signature(SignatureRequestFacts) -> SignatureDecision`, implementing `SignatureAuthority`: ADR-0008 D2 item 3 in one read transaction plus the gate, with automatic re-validation on a stale generation (ADR-0006 §13.5 ruling 2) | 1 | `authorize_refuses_each_predicate`; `authorize_revalidates_after_unrelated_generation_move`; `authorize_linearizes_with_revoke_commit` |
| 6 | Remote-revocation obligations have backoff and cap only | `RemoteObligation.kind`; the supervisor's `revocation_pass` clears `bounded_by_expiry` obligations on safe time when wall ≥ `until`, with no adapter call and no attempt counted (ADR-0008 D7 item 3). `RevokeOutcome.remote_effects: Vec<RemoteEffectReport>`. `RevocationCause::SessionLocked` | 1 | `bounded_obligation_clears_at_until_on_safe_time_without_adapter_call`; `bounded_obligation_never_clears_on_uncertain_time`; `bounded_obligation_consumes_no_attempt`; the M01 obligation suites unchanged |
| 7 | QR17: a timed-out immediate `revoke` counts as made | `AdapterDescriptor.remote_credential_effect: bool` (false for M02 adapters). When true, a timed-out immediate call **keeps its cleanup intent**, and the supervisor retries it with bounded, jittered backoff (ADR-0007 §12.13; ADR-0008 D7 item 5) | 1 | `timed_out_immediate_revoke_with_remote_effect_keeps_intent_and_retries`; `m02_adapters_unchanged_timed_out_immediate_counts_as_made` |
| 8 | Restart recovery knows no credential instances | At start: every `installed` credential instance whose vault slot does not exist in this process becomes `lost` (ADR-0008 D2 table), in one transaction before any listener binds. The supervisor gains the hook `managed_reissue_pass`; its body is U6/U10's, and it is a no-op while the managed adapter is unregistered | 1 | `installed_instances_become_lost_at_restart`; `lost_instance_grant_degraded_credential_reissue_pending` |
| 9 | `ensure` resolution picks the adapter from the catalog identity's mechanism (ADR-0007 §7, "one mechanism per grant") | Per pair: `managed_certificate` when `pair_preferences` says so and the projection rendering it is applied, together with a `verified` enrollment. Otherwise the identity's mechanism. Mixed ⇒ `mixed_mechanisms` (unchanged, ADR-0008 Q5). `projection_pending` and `pair_not_enrolled` refusals. `EnsureRequest.connection` enters the canonical hash when present (omitted otherwise, so M01/M02 hashes are unchanged). The `required.unattended` rule of ADR-0008 D6 item 7 | 1 | `mechanism_per_pair_resolution_table`; `projection_pending_refused`; `connection_absent_hash_unchanged_from_m02`; `strict_request_hash_differs`; `unattended_requires_claim_and_continue` |
| 10 | `GrantOrigin` has `covered` and `adapter` add-only | Adds add-only `lock_behavior: Option<LockBehavior>` and `connection: Option<ConnectionPolicy>`, recorded once at grant creation | 1 | `origin_lock_and_connection_add_only` |
| 11 | `StandingPolicy` has no lock or connection fields; `PolicyAction` has pause, resume, cutoff and clear | `StandingPolicy.{lock_behavior, connection}` (serde default `continue`, `graceful`/`disabled`). `PolicyAction::{SetLockBehavior, SetConnectionPolicy}`. `is_widening_policy_action` extended: `continue`, `graceful` and `owned_masters` are widening. Narrowing moves the generation | 1 | `lock_behavior_narrowing_immediate_widening_needs_decision`; `connection_policy_widening_classification`; `merged_policy_fail_closed_for_lock_and_connection` |
| 12 | `DegradedReason::MechanismUnavailable` only | Adds `CredentialReissuePending`, `IssuerUnavailable` and `PairUnenrolled`, with their sign rule (ADR-0008 D2 item 3). `IssuerUnavailable` and `PairUnenrolled` permit signing with an installed key: the server refuses an unenrolled pair itself, and the other pairs keep working. `CredentialReissuePending` has no key. `MechanismUnavailable` refuses | 1 | `degraded_reason_sign_rule_table` |
| 13 | Dispatch has no arm for `Request::{Issuer, Enrollment, Connections}` or the catalog action `SetPreference` | Arms that fail closed (`driver_unavailable`, nothing written) in phase 1. In phase 2 they call U10's drivers, and `ipc::session` offers `issuer/1`, `enrollment/1`, `managed-credentials/1` and `connections/1` | 1, 2 | `w0_m03_requests_fail_closed_before_any_record`; `w0_m03_capabilities_not_offered`; phase 2: `capabilities_offered_after_activation` |
| 14 | Decision dispatch knows the M01/M02 kinds | The new kinds are refused and not consumed in phase 1, and completed in phase 2 (U10) | 1, 2 | `w0_new_decision_kinds_refused_not_consumed` |
| 15 | — | The store bodies of `crates/store/src/ext_m03.rs` for every §5 item 18 `Txn` method | 1 | `integration_store_m03::*` (one per method: CAS, uniqueness, FKs, generation moves) |
| 16 | `testcfg` has the M01/M02 gates | `ScratchSecretStore` selection, `HEIMDALL_TEST_KEY_SEED`, `FakeSessionLockSource`, `HEIMDALL_TEST_SCRIPT_PAUSE_DIR`. Each is env-gated and compiled only under the test configuration | 1 | `release_build_ignores_m03_test_gates` (built in release mode by `check.sh`'s release-gate step: the variables are set and have no effect) |
| 17 | Restart recovery dispatches M01/M02 kinds | M03 journaled kinds stay **unresolved** at restart and are reported in `runtime_lifecycle` with `{phase: unresolved, kind, reason: owner_reconcile}` (ADR-0008 D5 §6.4) | 1 | `w0_open_enrollment_operations_stay_unresolved_at_restart` |
| 18 | Uninstall knows M02's owned artifacts | Uninstall lists remaining enrollments (non-final states) and refuses `--purge-state` while any remain, unless `--keep-remote-enrollments` is given (ADR-0008 §18). The CLI body is U12 | 1 (refusal), U12 (CLI) | `uninstall_refuses_purge_with_live_enrollments` |
| 19 | `holders::holder_pass` releases bindings on an observed exit | It also registers a `dedicated` row in `owned_connections` when the holder's resolved executable is the verified `ssh` client (the closing is U7's), and removes it on an observed exit | 1 | `holder_registers_dedicated_only_for_verified_ssh` |

* **Wave-0 acceptance** (all of these must pass before wave 1):
  * every row above;
  * no `todo!()` reachable from a request, a CLI command, restart recovery, a supervisor pass or a store
    method U0b calls (`w0_no_reachable_todo` walks the dispatch table);
  * every M01 and M02 suite unchanged;
  * `check.sh` exits 0 twice.

---

### U1: `heimdall-credential` core (keys, certificates, purpose, session-bind, memory protection)

* **Owner paths:**
  * `crates/credential/src/{vault,cert,purpose,session_bind,sys}.rs`;
  * `tests/integration/credential_cert.rs` and `tests/integration/credential_memory.rs` (hosted by
    `heimdall-credential`);
  * `tests/adversarial/signer_requests.rs` (hosted by `heimdall-credential`).
* **Scope:** the pieces of ADR-0008 D1, D2 items 4–5 and D6 item 2 that need no store, runtime or
  endpoint.
* **Interfaces:**
  * **`vault::KeyVault`**:
    * `generate_ed25519(&self) -> Result<(VaultSlot, PublicKeyInfo), VaultError>`. `PublicKeyInfo` holds
      `{ openssh_line, blob, fingerprint }`;
    * `sign(&self, &VaultSlot, data: &[u8]) -> Result<Vec<u8>, VaultError>`;
    * `destroy(&self, &VaultSlot)`;
    * `contains(&self, &VaultSlot) -> bool`.

    `VaultSlot` is an opaque random 128-bit handle; its hex is the `key_handle_ref` persisted in the
    credential instance. `SecretKey` is private to the module, as ADR-0008 D1 says.
  * **Seeded generation:** `KeyVault::with_test_seed(seed)` exists only under the test configuration
    (U0b row 16).
  * **`cert`:**
    * `CertificateProfile::from_bounds(&CertificateBounds) -> CertificateProfile`;
    * `build_and_sign(profile, subject: &PublicKey, ca: &SecretCaKey) -> Result<Certificate,
      CertError>`, used only by the issuer (U3);
    * `validate_installed(&Certificate, reserved: &CertificateBounds, subject_fp, ca_fp) -> Result<(),
      CertRefusal>`, which implements every refusal of ADR-0008 D6 item 2.
  * **`purpose`:** `parse_userauth(data: &[u8]) -> Result<UserAuthRequest { session_id, user, method:
    Publickey | PublickeyHostbound { server_host_key }, algorithm, key_blob }, PurposeRefusal>`, using
    `ssh-encoding` only. Then `check(&UserAuthRequest, grant_keys: &GrantKeys, accounts: &[AccountName],
    flags: u32) -> Result<(), PurposeRefusal>`.
  * **`session_bind`:** `parse(payload) -> Result<SessionBind { host_key, session_id, signature,
    is_forwarding }, _>` and `verify(&SessionBind) -> bool`, with `ssh-agent-lib` types and `ssh-key`
    verification.
  * **`sys`:** `lock_pages(&mut [u8]) -> MemLock` and `harden_process() -> HardeningReport { dumpable,
    core_limit, mlock_ok }`. Unsafe, with an invariant table.
* **Tests:**
  * Positive:
    * `ed25519_key_signs_and_verifies`;
    * `certificate_profile_matches_adr_0005_3_4`: one principal; extensions from `clear` plus
      `permit-pty`; key ID `heimdall:<env>:<grant>:<serial>`; random serial; `valid_after = issuance −
      60 s`; `valid_before` as reserved;
    * `certificate_accepted_by_fixture_sshd`: a `LoopbackSshd` in each form accepts a certificate built
      by `build_and_sign` from a test CA (M-F16);
    * `userauth_parsed_for_publickey_and_hostbound`, against requests captured from real clients
      through U11's counting proxy;
    * `session_bind_verified_for_each_host_key_type`: Ed25519, ECDSA and RSA host keys from real sshd
      handshakes.
  * Negative:
    * `sshsig_request_refused`;
    * `trailing_bytes_refused`;
    * `wrong_user_refused`;
    * `key_blob_not_grant_key_refused`;
    * `rsa_sha1_flag_on_ed25519_refused`;
    * `non_userauth_message_refused`;
    * `cert_validator_refuses_each_deviation`, a generated test over every field of ADR-0008 D6 item 2:
      principal count 0 or 2, a foreign principal, a critical option, an extra extension, validity
      mismatches, the wrong CA, the wrong subject, the wrong serial or key ID, a host certificate;
    * `session_bind_bad_signature_refused`;
    * `session_bind_forwarding_flag_reported`.
  * Memory:
    * `secret_key_has_no_clone_debug_serialize` (compile-fail doc tests);
    * `vault_destroy_removes_slot_and_sign_fails`;
    * `mlock_failure_degrades_not_refuses`;
    * `core_dumps_disabled_after_harden` (`getrlimit` read back);
    * `linux_signer_not_ptraceable_by_same_user` (`platform_only` Linux; records
      `/proc/sys/kernel/yama/ptrace_scope`; M-F19).
  * Adversarial:
    * truncated and oversized userauth requests;
    * declared lengths past the end;
    * 1 MiB of random data;
    * proptest ≥ 256 cases with a fixed seed. Nothing panics; everything is refused.
* **Acceptance:** every test above passes; no `unsafe` outside `sys.rs`; the canary scan is clean.
* **Depends on:** U0.

### U2: The signer and its endpoints

* **Owner paths:**
  * `crates/credential/src/{signer,endpoints,table}.rs`;
  * `tests/integration/managed_signer.rs` (hosted by `heimdall-credential`, with a dev-dependency on
    `heimdall-app` for a fixture `SignatureAuthority`).
* **Scope:** ADR-0008 D2 items 1–3 and 6–7, and the credential-instance state machine.
* **Interfaces:**
  * `ManagedSigner` implements `ipc::signing::Signer` (U0b row 1), once per endpoint kind:
    * `Environment`, `Binding(BindingId)` and `Verification(OperationId)`;
    * every `sign` calls `SignatureAuthority::authorize(SignatureRequestFacts { endpoint, grant_or_op,
      key_fingerprint, user, session_bind })` **after** `purpose::check` and **before** `KeyVault::sign`;
    * counters per verification endpoint: `signatures(key_fp) -> u32` and `session_binds() -> u32`.
  * `EndpointRegistry` (reusing M01's `ipc::{unix,windows}` listeners and peer checks):
    * `environment() -> EndpointRef`;
    * `create_binding(binding, generation) -> EndpointRef`, as a generation-tagged `ManagedResource`
      (`Endpoint`);
    * `create_verification(op) -> VerificationEndpoint`;
    * `remove(&ManagedResource)`, generation-bound (R-RT-04).
  * `SignerTable`:
    * `register(grant, slot, pub_info, pairs)`, which writes the credential instance `pending` with
      `subject_registered`;
    * `install(grant, pair, cert, &PublishedEntry) -> Result<(), InstallRefusal>`, D2 item 6;
    * `materialize(binding, pairs)` and `unmaterialize(binding)` for the environment listing;
    * `destroy_grant(grant)`, D2 item 7;
    * `list(endpoint) -> Vec<(blob, comment)>`, capped at 64 identities. Comments are
      `heimdall:<grant-short>`, never a label.
* **Tests:**
  * Positive:
    * `environment_endpoint_lists_only_materialized_bindings`;
    * `binding_endpoint_lists_only_its_grant`;
    * `fresh_login_through_environment_endpoint`: a real `ssh` with a scratch `-F` that includes P, to
      a `LoopbackSshd` in account form;
    * `one_signature_per_login`;
    * `session_bind_observed_per_client`, which records per client version whether `session-bind` is
      sent (macOS 10.5p1, devbox 9.6p1, Windows 10.3p1, WSL 9.6p1; M-F2).
  * Negative:
    * `signature_refused_after_deadline` (virtual clock, both the wall and the continuous branch);
    * `signature_refused_after_tombstone_commit`;
    * `signature_refused_on_time_uncertain`;
    * `signature_refused_for_mechanism_unavailable`;
    * `signature_refused_for_revoke_on_lock_unless_unlocked`;
    * `forwarded_session_refused_without_agent_forwarding`;
    * `add_remove_lock_unlock_smartcard_extension_refused_on_real_signer`;
    * `identities_capped_at_64`;
    * `endpoint_refuses_other_principal`. On Unix the peer-UID check runs with a forged credential in a
      test double. The cross-account rows are `blocked` on B2 (Windows) and B3 (macOS) where no second
      account exists.
  * Interrupted:
    * `sign_during_revoke_is_linearized`: across 1000 interleavings, a signature either completes before
      the tombstone commit or is refused;
    * `authorization_timeout_refuses` (2 s);
    * `crash_after_install_makes_instance_lost_at_restart`, with U0b row 8.
  * Cleanup:
    * `destroyed_key_makes_installed_certificate_unusable` (ADR-0005 §9.3: after `destroy_grant`, a
      login with the slot certificate fails and the agent lists nothing);
    * `binding_endpoint_removed_by_generation` (cleaning generation N leaves N+1);
    * `windows_pipe_dacl_owner_only_for_each_endpoint_kind` (`platform_only` Windows; `icacls` and the
      M01 owner-SID check);
    * `unix_endpoint_dirs_0700_sockets_0600`.
* **Acceptance:** the tests pass on macOS, the devbox and Windows (fixture level), and the per-client
  rows are recorded.
* **Depends on:** U1, U0b rows 1, 5 and 8, U11.

### U3: The issuer child, its protocol and the client

* **Owner paths:**
  * `crates/issuer/src/{protocol,child,client,ca,check}.rs`;
  * the `internal issuer` entry in `crates/heimdall/src/main.rs` (one match arm, through U0's tree);
  * `tests/integration/issuer_child.rs` and `tests/model/issuer_linearization.rs` (hosted by
    `heimdall-issuer`, with dev-dependencies on `heimdall-app` and `heimdall-testkit`).
* **Scope:** ADR-0008 D3.
* **Interfaces:**
  * `child::run(stdin, stdout, store: Box<dyn SecretStore>, db: &Path, clock: Arc<dyn Clock>) -> i32`.
    It refuses a TTY stdin, speaks `heimdall-issuer/1`, opens the store read-only, implements D3
    item 4 steps 1–5, and zeroizes on EOF and on shutdown.
  * `ca::CaSet`: CAs by fingerprint, with states `active` and `pending`; `sign(entry, subject) ->
    Certificate` (through `cert::build_and_sign`).
  * `check::verify_reservation(ro_store, entry_ref, subject, now: TimeAnchor) -> Result<CertificateBounds,
    IssuerRefusal>`: the read-only predicate re-run plus the ceilings.
  * `client::ChildIssuer` implements `app::ports::IssuerPort`:
    * `start()`, `status()`;
    * `sign(IssuanceRef, &PublicKeyLine) -> Result<CertificateLine, IssuerError>`, with a per-request
      10 s bound and `request_id` matching;
    * late replies are discarded and zeroized;
    * the supervision states of D3 item 7, with bounded, jittered backoff from the injectable `Jitter`;
    * the exact-PID and start-token identity of the child.
* **Tests:**
  * Positive:
    * `issuer_signs_reserved_entry_with_exact_bounds`;
    * `hello_load_status_round_trip`;
    * `issuer_exits_and_zeroizes_on_stdin_eof`.
  * Negative, one per `IssuerRefusal`:
    * `entry_not_reserved_published_voided_missing`;
    * `entry_stale_after_60s`;
    * `subject_mismatch`;
    * `predicate_refusal_after_tombstone_committed_post_reserve`;
    * `ceiling_two_principals` (a reservation forced in through a test-only store write);
    * `ceiling_x11_extension`;
    * `ceiling_validity_too_long`;
    * `subject_is_a_ca_key`;
    * `ca_not_loaded`;
    * `rate_limited_after_600_per_minute`.

    Also: `issuer_refuses_tty_stdin`, `oversized_frame_closes_channel`, and
    `issuer_path_never_exists_through_runtime_lifecycle` (start, issue, restart, stop: the
    `issuer.sock` path is absent at every step; ADR-0008 Q1).
  * Interrupted:
    * `late_reply_after_drop_is_discarded_and_nothing_published`;
    * `issuer_crash_mid_sign_reservation_counted_never_published`;
    * `restart_backoff_bounded_and_jittered` (virtual clock);
    * `store_unavailable_reports_reason_and_no_fallback`;
    * `runtime_death_closes_issuer` (the runtime is killed by exact PID; the issuer sees EOF and exits
      within 2 s).
  * The linearization model (ADR-0005 §9.3 R2/R12): deterministic interleavings of {revoke, cutoff,
    delegation change, deadline passage with no edit, `TIME_UNCERTAIN` onset, lock revocation} against
    {reserve, issuer read-only check, sign, publish, install}, with a crash at each step. Pass:
    * no certificate is published once any predicate fails;
    * the issuer refuses whenever its read-only snapshot shows a failing predicate;
    * a receiver with a stale generation, a tombstone or an unsafe deadline discards;
    * every `reserved`/`published` entry counts in `latest_possible_credential_expiry`;
    * a `reserved` entry is never published after a crash.
* **Acceptance:** the tests pass; the protocol golden (`tests/contracts/golden/issuer-protocol.json`) is
  byte-stable.
* **Depends on:** U1, U4 (the `SecretStore` trait from U0; `ScratchSecretStore` from U4), U0b rows 2–4.

### U4: Platform stores, the D5 backup, the ceremonies and the recovery bundle

* **Owner paths:**
  * `crates/issuer/src/{store/mod,store/macos,store/windows,store/linux,store/scratch,backup,ceremony,bundle,sys}.rs`;
  * `tests/integration/issuer_store.rs` and `tests/e2e/issuer_ceremony.rs` (pty, hosted by `heimdall`).
* **Scope:** ADR-0008 D1 (the K_ca rows) and D4.
* **Interfaces:**
  * `SecretStore`:
    * `kind() -> StoreKind`;
    * `availability() -> StoreAvailability`;
    * `put(&CaFingerprint, &SecretCaKey) -> Result<StoreItemRef, StoreError>`;
    * `get(&CaFingerprint) -> Result<SecretCaKey, StoreError>`;
    * `delete(&StoreItemRef)`;
    * `list() -> Vec<StoreItemRef>`.

    Items are labelled `heimdall-issuer/<fingerprint>` and carry the environment ID attribute. **No
    implementation has a plaintext fallback.**
  * The implementations:
    * `MacosLoginKeychain`: SecAccess trusting only the current executable; user interaction disabled
      on reads. It can be pointed at a disposable file keychain under the test configuration only;
    * `WindowsDpapi`: CurrentUser, Heimdall entropy, `CRYPTPROTECT_UI_FORBIDDEN`; the blob in
      `%LOCALAPPDATA%\Heimdall\issuer\<fingerprint>.dpapi` with a protected owner-only DACL, or a
      scratch path under the test configuration;
    * `LinuxSecretService`: the login collection over a DH session;
    * `ScratchSecretStore`: test configuration only.
  * `backup::{write(path, &SecretCaKey, &Passphrase) -> BackupInfo { sha256, created_at }, verify(path,
    expected_pub, &Passphrase), restore(path, &Passphrase) -> SecretCaKey}`, in the OpenSSH format with
    bcrypt-pbkdf and aes256-ctr through `ssh-key` `encryption`.
  * `ceremony::{init, rotate_begin, restore, unlock}(tty: &mut dyn Tty, client: &mut OwnerSession, …)`.
    The step order and crash points are those of ADR-0008 D4 item 1. `Tty` is the controlling terminal
    (`/dev/tty`, `CONIN$`/`CONOUT$`), or a pty in tests.
  * `bundle::export(&StoreView, redact: Redaction) -> RecoveryBundle` (the §5 item 9 shape).
* **Tests:**
  * Positive:
    * `d5_backup_restores_with_stock_ssh_keygen`: `ssh-keygen -y -P <pass> -f <backup>` prints the CA
      public key (M-F16);
    * `scratch_store_round_trip`;
    * `windows_dpapi_round_trip_across_processes` (`platform_only` Windows; a scratch path);
    * `windows_dpapi_blob_dacl_owner_only`;
    * `macos_keychain_code_path_against_disposable_file_keychain` (`platform_only` macOS; **not** the
      login keychain; recorded as mechanism evidence only);
    * `linux_secret_service_round_trip_in_private_session` (`platform_only` Linux; `dbus-run-session`
      plus `gnome-keyring-daemon` with a scratch `HOME`, only if gnome-keyring is installed on the host;
      otherwise the row is `blocked` with that observation, and nothing is installed);
    * `init_ceremony_registers_ca_and_environment_permissions` (pty);
    * `rotate_begin_creates_pending_ca_with_its_backup`;
    * `bundle_lists_cas_enrollments_markers_and_instructions`.
  * Negative:
    * `no_plaintext_when_store_unavailable`, for each store kind and each unavailability: no file
      appears in the state, data, config or runtime directories, and `CAPABILITY_UNAVAILABLE` carries
      the reason;
    * `passphrase_only_on_tty_transcript` (A33: absent from stdout, stderr, JSON, logs, the store, the
      bundle and process arguments);
    * `init_refuses_non_tty_and_non_interactive`;
    * `init_denied_zeroizes_and_stores_nothing`;
    * `backup_out_existing_file_refused`;
    * `wrong_passphrase_restore_refused`;
    * `macos_interaction_not_allowed_maps_to_store_locked` (a locked disposable file keychain);
    * `restore_requires_not_stolen_flag`;
    * `key_only_restore_reports_unbounded_unknown` (ADR-0005 §9.3 R6/R11). An old certificate is
      issued under a long policy; the database is removed; K_ca is restored with a shorter policy.
      `latest_possible_credential_expiry` is then `unknown` and `revocation.remote` is
      `unbounded_unknown`. Rotation closes each account's residual when its old line is removed; an
      unreachable account stays `pending_until_line_removed`; no serial is reused.
  * Interrupted:
    * `crash_before_store_write_registers_nothing`;
    * `crash_between_store_and_register_leaves_orphan_reported`;
    * `replace_orphan_deletes_exact_item_only`;
    * `crash_during_backup_write_leaves_no_store_item`.
  * Cleanup:
    * `retire_deletes_store_item_and_issuer_zeroizes`;
    * `bundle_contains_no_private_material` (canary and secret-bytes scan);
    * `bundle_redacts_hostnames`.
* **Acceptance:** the tests pass. The Windows DPAPI rows run natively. The macOS keychain row is
  labelled mechanism-only. The Linux Secret Service row runs or is `blocked` with its observation.
* **Depends on:** U1, U0.

### U5: Enrollment remote protocol and production verification

* **Owner paths:**
  * `crates/enroll/src/{plan,script,remote,parse,registry,verify}.rs`;
  * `tests/contracts/golden/enroll-scripts/{inspect,append,remove}.sh`;
  * `tests/integration/enroll_registry.rs` and `tests/integration/enroll_verify.rs` (hosted by
    `heimdall-enroll`, with dev-dependencies on `heimdall-testkit` and `heimdall-credential`).
* **Scope:** ADR-0008 D5 §6.1, §6.3, §6.5, §6.7 (classification) and §6.8 (procedure).
* **Interfaces:**
  * `plan::EnrollmentPlan::build(&CatalogView, &KnownHostsView, &CaView, EnrollmentSpec) ->
    Result<EnrollmentPlan, PlanRefusal>`: the ADR-0008 D5 §6.1 preconditions, with `plan_digest` over
    every field.
  * `script::{inspect, append, remove}(params) -> RemoteScript`. Values are validated literals in single
    quotes. Under the test configuration only, `HM_PAUSE <name>` points are inserted.
  * `remote::SshStepRunner`: a **CLI-side library**, the client-executed steps of ADR-0008 D5 §6.3.
    * `run(&RemoteStep, tty: TtyMode) -> StepReport { exit_status, stdout, stderr_excerpt }`;
    * it runs the verified client with the step's alias, options, remote command and script on stdin;
    * the owner's terminal is attached when the step is interactive, and `BatchMode=yes` is set
      otherwise;
    * it is bounded, kills the child on drop, and never parses or alters what the owner types.
  * `registry::classify_step(stage, &StepResult, &Expected) -> StepClass`: the runtime's pure
    classification of a reported result.
    * Its classes are `Confirmed`, `AlreadyPresent`, `NotApplied`, `Uncertain`, `HostTrustChanged`,
      `ProviderLocked`, `InteractionRequired` and `Held`.
    * Exit 255 with no `HM1 v=1` line is `NotApplied` for `inspect` and `Uncertain` for `append` and
      `remove`.
  * `parse::hm1(stdout) -> Result<Hm1Record, ParseError>`: bounded, and the first line must be
    `HM1 v=1`.
  * `registry` (pure):
    * `expected_line(ca_pub, principal, marker)`;
    * `post_image_without(preimage, line)`;
    * `check_post_append(pre, post, line)`;
    * `check_post_remove(post_image, post)`;
    * `classify_reconcile(observation, expected) -> ReconcileClass`, exactly the ADR-0008 D5 §6.7
      table.
  * `verify::Verifier` implements `app::ports::VerificationRunner`: `run(&EnrollmentPlan, positive:
    &CertificateLine, negative: &CertificateLine, endpoint: &VerificationEndpoint) ->
    VerificationOutcome`. It uses the generated configuration and known-hosts file of ADR-0008 D5 §6.5
    item 3, and the outcome table.
* **Tests:**
  * Pure (proptest ≥ 256 cases, fixed seed):
    * `post_image_preserves_every_other_byte` (CRLF, no final newline, a BOM, comments, options,
      near-duplicate lines);
    * `check_post_append_accepts_admin_append_after_ours_rejects_damage`;
    * `reconcile_classification_table_every_row`;
    * `plan_refusals_each_precondition`;
    * `plan_digest_covers_every_field`.
  * Protocol on every target shell (`registry_protocol_on_target_shell`, one row per target: dash on
    Docker Debian 13; the WSL Ubuntu 24.04; the devbox's `/bin/sh` through `LoopbackSshd`; macOS
    `/bin/sh` through `LoopbackSshd`):
    * `append_creates_registry_exclusively_mode_0600`;
    * `append_creates_ssh_dir_0700_when_absent` (ADR-0008 Q8);
    * `append_newline_decided_at_append_time`;
    * `append_idempotent_by_marker_exit_10`;
    * `inspect_reports_metadata_and_content`;
    * `remove_compare_then_rename_preserves_unrelated_bytes`.
  * Negative:
    * `symlinked_registry_refused`;
    * `hardlinked_registry_refused`;
    * `acl_indicator_refused` (`setfacl` inside the WSL distribution and Docker; `chmod +a` on a macOS
      scratch file);
    * `foreign_owned_registry_refused` (Docker: a root-owned file);
    * `group_writable_dir_refused`;
    * `registry_too_large_refused`;
    * `non_posix_or_noisy_login_refused_as_registry_unsupported` (a login rc that prints before the
      script: nothing written);
    * `host_key_mismatch_is_host_trust_changed_nothing_written`;
    * `strict_host_key_checking_overrides_user_accept_new`;
    * `registry_guard_refuses_non_scratch_target` (U11).
  * Interleaving (U11's pause hooks; ADR-0005 §9.3 R1):
    * `admin_append_between_inspect_and_append_preserved`;
    * `admin_append_without_newline_in_append_window_detected_damaged`;
    * `admin_edit_before_final_check_remove_restarts`;
    * `three_compare_failures_give_registry_changed`;
    * `rotation_add_preserves_admin_edit`;
    * `admin_edit_inside_remove_window_is_lost`, recorded as the **disclosed limitation**, never as a
      pass.
  * Lost response:
    * `ssh_killed_after_append_is_uncertain_then_reconciled_applied`;
    * `ssh_killed_before_append_reconciled_not_applied`;
    * `unreachable_after_append_stays_unknown`;
    * `retry_after_lost_reply_never_appends_twice`.
  * Verification:
    * `verify_positive_one_signature_negative_zero` (per client; M-F1);
    * `verify_negative_records_zero_signatures`;
    * `verify_never_reads_user_config`. The user configuration offers an extra key that **would**
      authenticate, as a canary key; it is never offered, and the positive passes only through the
      certificate;
    * `verify_on_account_without_log_access` (Docker `enrollable`; the WSL non-root user);
    * `principals_not_enforced_detected_and_rolled_back` (a fixture line without `principals=`, written
      by the test as an "administrator mistake");
    * `verification_failed_when_server_reads_another_registry` (`AuthorizedKeysFile` points elsewhere);
    * `verification_host_key_mismatch_holds_no_rollback`;
    * `verification_unreachable_leaves_applied_unverified`;
    * `verification_known_host_ambiguous_refused`;
    * `log_attestation_reported_unavailable`.
  * Goldens: `release_scripts_match_golden_and_have_no_pause_points`.
* **Acceptance:** every target shell row passes or is `blocked` with its exact platform. The interleaving
  limitation is recorded as such. The registry guard holds in every test.
* **Depends on:** U0, U11, U2 (the verification endpoint), M10, M11.

### U6: The managed credential adapter

* **Owner paths:**
  * `crates/adapters/src/managed/{mod,prepare,reissue,report,files}.rs`;
  * `tests/integration/managed_adapter.rs` (hosted by `heimdall-adapters`, with dev-dependencies on
    `heimdall-issuer`, `heimdall-credential` and `heimdall-testkit`).
* **Scope:** ADR-0008 D6, D7 items 2, 5 and 6–7 (the managed part), and D12's computation.
* **Interfaces:**
  * `ManagedCertificateAdapter` implements `CredentialAdapter` ⟨M02?⟩ M1:
    * `descriptor()`:
      * mechanism `managed_certificate`;
      * `external_side_effects: true`, `remote_credential_effect: true` (U0b row 7);
      * `interaction: None`;
      * `lock_continuity` from the claim table for the running platform (`Unknown` when absent);
    * `read_sources(pairs)` reads the enrollments, slots, verification evidence, claim-table entries and
      the issuer status;
    * `prepare_from` runs ADR-0008 D6 item 1 steps 1–7, each step recorded as a stage receipt under the
      effect token;
    * `renew` is the re-issue of D6 item 4 (`reissue::eligible` must hold);
    * `reconcile(grant, token)`: `Applied` when every pair is published and installed; `NotApplied`
      when nothing is published; `Unknown` otherwise;
    * `revoke(grant, now)` runs D7 item 2, for the grant and its cascade, and returns `remote_effects`.
  * `reissue::eligible(&GrantSnapshot, &GrantOrigin, &TimeStatus, &Admission, lock_behavior) ->
    Result<(), ReissueRefusal>`: pure, the ADR-0005 §3.7 rules 1–5.
  * `report::compute(&Grant, &PreparedManaged, &[Claim], &Platform, &[EnrollmentEvidence]) ->
    ManagedReport`, which fills the §5 item 8 and 9 fields.
  * `files`:
    * `write_binding_files(binding, key_pub, certs)` under `<runtime_dir>/b/<16 hex>/`;
    * `write_slot(env, pair, generation, key_pub, cert)` and `clear_slot(env, pair, generation)` under
      `<data_dir>/managed/<destination-id>/`.

    Both are atomic and generation-bound. Windows uses the M02 replace primitive ⟨M02?⟩ M4.
* **Tests:**
  * Positive:
    * `activation_issues_one_certificate_per_pair_covering_grant`;
    * `report_for_local_managed_binding_with_empty_claim_table` (a golden against ADR-0005 §7.2:
      `lock_continuity: not_verified`; every unclaimed mechanism field `unknown`; `destination_scope:
      verified_server_principals` from the enrollment evidence; `issuer_isolation: same_user_process`);
    * `report_with_fixture_claim_table_reports_verified_with_record`;
    * `child_gets_own_key_endpoint_and_subset_certificates_bounded_by_parent`;
    * `reissue_after_process_restart_same_boot_restores_usability`.
  * Negative:
    * `pair_not_enrolled_refused`;
    * `projection_pending_refused`;
    * `mixed_mechanisms_refused`;
    * `issuer_unavailable_no_fallback_to_existing_identity`;
    * `offline_until_beyond_bound_capability_unavailable`;
    * `unattended_minimum_requires_claim_continue_and_no_interaction`;
    * `expired_grant_never_reissued` (exit claim "an expired grant cannot renew itself");
    * `renew_never_extends_deadline_or_pairs` (property, ≥ 256 cases);
    * `reissue_refused_for_revoke_on_lock`;
    * `reissue_waits_on_time_uncertain_until_confirmed` (virtual clock with `reboot()`);
    * `reissue_never_from_process_files` (a planted stale socket or PID file does not count).
  * Interrupted:
    * `crash_at_each_prepare_step_recovers_per_table` (key, reserve, sign, publish, install,
      materialize);
    * `dropped_prepare_installs_nothing_after_drop`;
    * `timed_out_immediate_revoke_keeps_intent_and_retries` (QR17).
  * A07:
    * `revoke_during_each_issuance_step`. With a real issuer child, revoke, cutoff, deadline passage and
      `TIME_UNCERTAIN` are each injected at reserve, sign, publish and install. The result is always
      refused or voided, and counted;
    * `revoke_with_unreachable_destination_reports_bounded_remote_effect` (`remote_effects` with `until`
      = the pair's maximum `valid_before`; `destination_clock_error: unmeasured`);
    * `revoke_cascades_to_children_destroying_their_keys`;
    * `stale_approval_cannot_reactivate_after_revoke` (R-SE-07, through the real adapter);
    * `bounded_obligation_completes_revocation_after_valid_before`.
  * Cleanup:
    * `release_destroys_key_without_tombstone`;
    * `expiry_clears_slot_and_binding_files`;
    * `residual_counts_reserved_and_published_excludes_voided`;
    * `no_leftover_vault_slots_after_every_test` (a vault counter hook, test configuration only).
* **Acceptance:** the tests pass on all three platforms at fixture level, with the native Windows issuer
  backed by DPAPI.
* **Depends on:** U1–U4, U0b, U11.

### U7: Connection control (owned masters, owned dedicated connections, policies)

* **Owner paths:**
  * `crates/runtime/src/connections.rs`;
  * `tests/integration/connections.rs` (hosted by `heimdall-runtime`) and `tests/e2e/deadline_m03.rs`
    (hosted by `heimdall`).
* **Scope:** ADR-0008 D8.
* **Interfaces:**
  * `ConnectionSupervisor` implements `app::ports::ConnectionControl`:
    * `start_master(binding, pair) -> Result<OwnedConnection, ConnError>`;
    * `close_master(&OwnedConnection, reason)`;
    * `close_dedicated(&OwnedConnection, reason)`;
    * `effective_policy(grant) -> ConnectionPolicy`, the fail-closed merge of D8 item 1.
  * The supervisor passes `connection_deadline_pass` (scheduled by the deadline scheduler at each
    admission deadline) and `connection_restart_pass` (first at start). U10 calls them from
    `supervisor.rs`.
  * Process signalling:
    * Linux: `pidfd_open` and `pidfd_send_signal` through `rustix` `process`;
    * macOS: `kill` after `proc_pidinfo` re-verification (the existing `platform.rs` reads);
    * Windows: `OpenProcess`, creation time, `TerminateProcess` (the existing `platform.rs`).

    An unverifiable holder is never signalled.
* **Tests (A23):**
  * Positive:
    * `owned_master_admits_sessions_before_deadline`;
    * `graceful_keeps_dedicated_connection_after_deadline_and_new_auth_refused`;
    * `strict_closes_dedicated_connection_at_deadline`;
    * `revocation_closes_dedicated_under_both_policies`;
    * `ordinary_client_uses_owned_master_when_present_direct_otherwise` (M-F5).
  * Negative:
    * `owned_master_closed_at_deadline_new_mux_session_refused`;
    * `preaccepted_control_connection_closed_with_master` (the E7P pattern; ADR-0005 §3.8);
    * `user_controlmaster_ignored_for_managed_alias` (P is read first);
    * `unmanaged_alias_master_reported_not_controlled`;
    * `forward_through_master_refused_without_permit_port_forwarding` (settles the ADR-0005 §3.4 `[I]`);
    * `o_stop_and_o_exit_behaviour_recorded_per_client` (the E7/E7P rerun on 10.5p1 and 9.6p1, as
      observations);
    * `remote_process_survives_close_reported_not_terminated`;
    * `run_of_non_ssh_program_reports_existing_connections_not_controlled`;
    * `windows_owned_multiplexing_reported_unavailable` (`platform_only` Windows; M-F7: one `ssh -M`
      attempt against the fixture, its refusal recorded, then `CAPABILITY_UNAVAILABLE`
      `multiplexing_unsupported`).
  * Interrupted:
    * `runtime_restart_closes_masters_of_ended_grants_first`;
    * `unverifiable_holder_never_signalled` (a PID reused by a fixture process with another start
      time);
    * `master_start_failure_retried_bounded_jittered_and_clients_connect_directly`;
    * `time_uncertain_closes_masters_keeps_graceful_dedicated`;
    * `strict_close_races_child_exit_cleanly`.
  * Cleanup:
    * `master_socket_removed_only_if_same_inode`;
    * `no_leftover_processes` (the harness counts by exact PIDs it started);
    * `owned_connections_rows_cleared_on_exit`.
* **Acceptance:** the A23 tests pass on macOS and the devbox with real masters. Windows reports and
  enforces multiplexing as unavailable, and its dedicated-connection rows pass natively.
* **Depends on:** U2, U6, U8, U0b row 19.

### U8: Projection and consumer integration, plus the M02 residuals

* **Owner paths:** these are M02 files, edited only for M03:
  * `crates/sshconf/src/render.rs`: the directive-set revision;
  * `crates/localenv/src/projection/{plan,content}.rs`: managed sections and the preference;
  * `crates/localenv/src/projection/mod.rs`: the `state_dir` refusal;
  * `crates/localenv/src/agents.rs`: the client-aware `Include` expansion;
  * `crates/heimdall/src/{connect_cmd,run_cmd,launch_flow}.rs`: managed options, the slot check and
    auto-materialize;
  * `tests/integration/projection_managed.rs` (hosted by `heimdall-localenv`) and
    `tests/e2e/consumer_m03.rs` (hosted by `heimdall`).
* **Scope:** ADR-0008 D10, and the ADR-0007 §13 residuals that are deferred to M03 with a decision.
* **Interfaces:**
  * `render::Section::ManagedCertificate { alias, hostname, port, user, endpoint, key_pub, cert,
    control_path: None | Some(path) }`: the D10 item 1 directive order and the ADR-0007 §4 value rules;
    Windows pipes as `//./pipe/…`.
  * `projection::plan` renders `ManagedCertificate` for a pair whose preference is `managed_certificate`
    (`pair_preferences`). The preview's diff shows the change, and it is consented through M02's
    `ApplyProjection` ⟨M02?⟩ M3.
  * `connect` with a managed binding adds the binding-endpoint options of D10 item 4 after
    `ensure`/`bind`.
  * `run` with a managed binding requires, or auto-materializes, the slot of every managed pair (D10
    item 5). A conflict is `prelaunch_failed` with `CONFIG_CONFLICT` `managed_slot_held`.
* **Tests:**
  * Positive:
    * `p_renders_managed_alias_with_slot_paths_and_control_none`;
    * `p_renders_owned_master_control_path_when_enabled`;
    * `ordinary_ssh_through_p_uses_environment_endpoint` (a scratch `-F` user configuration that
      includes P; `LoopbackSshd`; ADR-0007 §9);
    * `git_scp_sftp_through_managed_alias`;
    * `connect_uses_binding_endpoint_via_command_line`;
    * `run_auto_materializes_free_slot`;
    * `windows_ssh_certificate_through_heimdall_pipe` (`platform_only` Windows; M-F18);
    * `wsl_ordinary_ssh_without_f_through_managed_alias` (the disposable distribution, a real home).
  * Negative:
    * `run_refused_when_slot_held_by_other_binding`;
    * `absent_slot_fails_closed`;
    * `inherited_identityfile_makes_selection_not_exclusive_and_noninteractive_refused` (M02's fallback
      clearance on the managed alias);
    * `existing_access_aliases_render_byte_identical_to_m02` (a golden regression);
    * `projection_pending_until_setup_apply`;
    * `windows_token_change_makes_p_stale_and_ensure_projection_pending`.
  * Interrupted:
    * `crash_during_slot_write_reconciled_at_restart`;
    * `slot_cleanup_never_removes_newer_holder`.
  * M02 residuals:
    * `identity_agent_references_follow_client_include_behaviour` (ADR-0007 §12.34 item 3: an `Include`
      that the selected client would not expand adds no candidate);
    * `writing_projection_config_without_state_dir_refused` (§12.34 item 6).
* **Acceptance:** the tests pass on all three platforms (the Windows rows natively), and the M02
  projection suites run unchanged.
* **Depends on:** U2 (endpoint names), U6 (`files`), U0b row 9, M02 ⟨M02?⟩ M3, M4, M11.

### U9: The session-lock source and lock behaviour

* **Owner paths:**
  * `crates/runtime/src/session_lock/{mod,macos,windows,linux,sys}.rs`;
  * `crates/app/src/lock.rs`;
  * `tests/integration/session_lock.rs` (hosted by `heimdall-runtime`) and `tests/model/lock_behavior.rs`
    (hosted by `heimdall-app`).
* **Scope:** ADR-0008 D9.
* **Interfaces:**
  * `SessionLockSource` implementations, per the D9 item 3 table: `state() -> LockState` and
    `subscribe() -> tokio::sync::watch::Receiver<LockState>`.
    * macOS: a dedicated run-loop thread;
    * Windows: a message-only window thread;
    * Linux: `zbus` on the system bus.

    Threads are spawned once, joined at shutdown, and never call into the store.
  * `lock::effective_behavior(&GrantOrigin, &[StandingPolicy]) -> LockBehavior`.
  * `Operations::on_session_lock(LockState)`: in one pass, revoke every `revoke_on_lock` grant (cause
    `session_locked`).
  * `Operations::policy(SetLockBehavior)`: narrowing is immediate; widening goes through the decision
    record; it is refused where the source is `unavailable`.
  * The disclosure record: `meta.lock_disclosure_acknowledged_at`.
* **Tests:**
  * Positive:
    * `lock_event_revokes_revoke_on_lock_grants_with_cause_session_locked`;
    * `continue_grants_unaffected_by_lock`;
    * `unlock_restores_nothing`;
    * `disclosure_shown_once_then_recorded`.
  * Negative:
    * `revoke_on_lock_refused_where_signal_unavailable` (the devbox and the WSL distribution natively);
    * `widening_to_continue_needs_attended_decision`;
    * `unknown_state_treated_as_locked`;
    * `signer_refuses_revoke_on_lock_grant_unless_unlocked`.
  * Native (each records the observed signal and its latency):
    * `macos_lock_signal_observed` (during P1, M-F12);
    * `windows_lock_signal_observed` (during P-W1, M-F13);
    * `linux_logind_lock_signal_observed` (**`blocked` on B11**).
  * Interrupted:
    * `restart_never_reissues_revoke_on_lock_grant`;
    * `lock_revocation_between_reserve_and_publish_voids`;
    * `lock_event_storm_coalesced_bounded` (100 events in 1 s cause one revocation pass, and no
      notification storm).
* **Acceptance:** the model and fixture tests pass everywhere, and the native signal rows run on macOS
  and Windows under the ADR-0004 §2 lock rule (U13).
* **Depends on:** U0b rows 10, 11 and 6 (the cause), U2.

### U10: Application drivers and runtime wiring (lands with U0b phase 2)

* **Owner paths:**
  * `crates/app/src/{enrollment,issuer,managed}.rs`;
  * `crates/runtime/src/service.rs` (the M03 wiring) and `crates/runtime/src/supervisor.rs` (the M03
    passes: `managed_reissue_pass`, `issuer_supervision_pass`, the calls into U7's and U9's passes;
    `holder_pass` remains M02's);
  * `tests/e2e/managed_m03.rs` and `tests/e2e/enroll_m03.rs` (hosted by `heimdall`).
* **Scope:** the ADR-0008 D5 §6.4 stage driver, the issuer request handling, and the runtime's start and
  stop order.
* **Interfaces:**
  * `enrollment::{next_step, record_step_result, run_verification}`: the stage machine of ADR-0008 D5
    §6.4.
    * `next_step` writes the stage receipt (`Attempted` for a mutation) and returns the `RemoteStep` to
      the driving CLI;
    * `record_step_result` checks the `step_token`, classifies through `registry::classify_step`, and
      records the outcome together with the enrollment transition in one transaction;
    * `run_verification` runs E4 in the runtime (`VerificationRunner`, `IssuerPort`, the U0b row 4
      issuance);
    * a step result that never arrives makes the stage `Uncertain` after `enrollment_step_timeout`
      (supervisor pass).

    `enrollment::reconcile(op)` follows ADR-0008 D5 §6.7, with its `inspect` client-executed too.
  * `issuer::handle(IssuerRequest)`: register, through the `RegisterIssuer` decision; unlock; retire,
    through the `RetireIssuer` decision; status; bundle.
  * `managed`: the body of `Operations::authorize_signature`, if U0b row 5 left it to U10, and of
    `managed_reissue_pass`.
  * **The runtime start order:**
    1. open the store;
    2. M01/M02 recovery, plus U0b row 8's `lost` marking;
    3. close the owned masters of ended grants (U7);
    4. start the issuer child if a CA is registered (U3);
    5. create the environment endpoint;
    6. run `managed_reissue_pass`;
    7. bind the control endpoint and write `instance.json`.

    **The stop order:** stop accepting; close owned masters; zeroize the vault; shut the issuer down;
    remove endpoints.
* **Tests:**
  * e2e, fixture level, all platforms:
    * `enroll_preview_apply_verify_setup_apply_ensure_ssh` (the full flow on `LoopbackSshd`);
    * `enroll_requires_attended_decision`;
    * `enroll_noninteractive_provider_interaction_refused_before_write`;
    * `enroll_restart_leaves_operation_unresolved_and_reported`;
    * `enroll_reconcile_applied`, `enroll_reconcile_not_applied_within_validity`,
      `enroll_reconcile_approval_lapsed`, `enroll_reconcile_unreachable`;
    * `enroll_same_key_replays_different_params_conflict`;
    * `step_result_with_wrong_token_refused_nothing_recorded`;
    * `cli_killed_during_append_step_leaves_outcome_unknown`;
    * `step_result_timeout_marks_mutation_uncertain_and_read_retryable`;
    * `enroll_through_password_existing_access_prompts_on_owner_tty` (a `LoopbackSshd` with
      keyboard-interactive disabled and a pty-driven passphrase-protected scratch key; the passphrase
      never appears outside the pty);
    * `a10_narrow_certificate_refused_on_other_host_account_form`,
      `a10_narrow_certificate_refused_on_other_host_system_form`;
    * `enroll_second_for_same_pair_and_ca_already_enrolled`;
    * `enroll_remove_lists_affected_grants_and_degrades_them`;
    * `rotation_two_accounts_one_unreachable` (the A09 rotate exercise);
    * `foreign_removal_from_bundle`.
  * Runtime:
    * `runtime_start_order_issuer_before_listen`;
    * `issuer_crash_blocks_reissue_not_signing`;
    * `reissue_after_runtime_process_restart_same_boot` (native, every platform; ADR-0005 §9.3 R4, the
      runnable row);
    * `reissue_after_reboot_waits_for_time_confirm` (virtual clock);
    * `shutdown_zeroizes_vault_and_stops_issuer`;
    * `service_stop_via_signal_fallback_still_zeroizes` (ADR-0006 §13.7 item 8).
* **Acceptance:** the e2e flows pass on macOS, the devbox (scratch store) and Windows (DPAPI), and
  phase 2's capability and decision tests pass.
* **Depends on:** U1–U9, U11.

### U11: Test fixtures (`heimdall-testkit`, Docker fixtures)

* **Owner paths:**
  * `crates/testkit/src/{ca,registry,lock,managed,owner_digest}.rs`, and `crates/testkit/src/sshd.rs`
    (extensions);
  * `tests/fixtures/ssh/{Dockerfile,entrypoint.sh,up.sh,down.sh,lib.sh,smoke.sh}` (`enrollable2`; the
    test-CA hook for `ca1`/`ca2`);
  * `tests/fixtures/MANIFEST.md` (new rows).
* **Scope:** ADR-0008 D13.
* **Interfaces:**
  * `SshdConfig` gains `trusted_user_ca_keys: Option<PathBuf>`, `authorized_principals:
    Option<BTreeMap<String, Vec<String>>>` and `registry_seed: Option<Vec<u8>>`. The account form uses
    the scratch `AuthorizedKeysFile` as the explicit registry. `TwoHosts::start(scratch, form) ->
    (LoopbackSshd, LoopbackSshd)` with distinct destination IDs.
  * `registry::RegistryGuard::check(target) -> Result<(), FixtureUnsafe>`.
  * `registry::PauseHooks`: FIFOs in scratch; `wait_at(name)`, `release(name)`.
  * `lock::FakeSessionLockSource`.
  * `ca::TestCa`: drives the `issuer init` ceremony over a pty, and returns the fingerprint and the
    captured passphrase (for scanning only).
  * `managed::seeded_k_env(seed) -> [u8; 32]`, for scanning.
  * `owner_digest::OwnerDigest::capture()` and `assert_unchanged()`. It covers `~/.ssh`, the Git
    global files and, on macOS, the output of `security list-keychains -d user` (names only, digested).
  * Docker: `enrollable2`, seeded like `enrollable`; the hook `ca-trust-test-ca <pub>`, which writes
    the run's test CA into `ca1`/`ca2`'s `TrustedUserCAKeys` inside the container only; `down.sh` cleans
    up as in M00-T03.
* **Tests:**
  * `registry_guard_refuses_non_scratch_paths`;
  * `owner_digest_detects_change` (a self-test on a scratch tree);
  * `loopback_system_form_accepts_test_ca_certificate`;
  * `two_hosts_have_distinct_principals`;
  * `pause_hook_blocks_and_releases`;
  * `docker_enrollable2_seeded_like_enrollable`;
  * `docker_ca_hook_is_container_internal_only`;
  * `test_ca_ceremony_captures_passphrase_only_from_pty`.
* **Acceptance:** the tests pass; MANIFEST rows record owner, image, versions, reset and cleanup.
* **Depends on:** U0, and the U4 ceremony for `TestCa` (its test goes green after U4).

### U12: CLI and TUI surfaces

* **Owner paths:**
  * `crates/heimdall/src/{issuer_cmd,enroll_cmd,connections_cmd}.rs`;
  * the M03 additions to the `access` and `destination` handlers;
  * `crates/heimdall/src/uninstall_cmd.rs` (enrollment listing);
  * `crates/heimdall/src/tui/{model,view,data}.rs` (M03 views);
  * `tests/e2e/cli_m03.rs` and `tests/e2e/tui_m03.rs`.
* **Commands** (§5 item 24; ADR-0008 D4, D5, D8, D9).
  * `heimdall enroll` drives the operation as a **client-executed loop**:
    1. preview, then apply, then the attended decision;
    2. then repeatedly `Enrollment::Step`, `SshStepRunner::run` on the owner's terminal, and
       `Enrollment::StepResult`;
    3. until the operation reaches verification, which the runtime runs, or a final state.
  * `enroll reconcile` uses the same loop.
  * A Ctrl-C between `Step` and `StepResult` leaves a mutating step `Uncertain`, and the CLI says so:
    "the change may have been applied; run `heimdall enroll reconcile <op>`".
* **Tests:**
  * help and discovery goldens;
  * exit codes per the ADR-0006 §5 table for each new reason;
  * the typed `yes` confirmation for every decision kind (EOF, Ctrl-C, timeout, non-TTY and
    `--non-interactive` send nothing, exit 3);
  * the JSON envelope for each command;
  * `issuer_init_prints_passphrase_only_to_tty`;
  * `enroll_preview_shows_disclosures_and_exact_line`;
  * `access_ensure_strict_reports_strict_disconnect`;
  * `access_lock_behavior_refused_where_unavailable`;
  * `connections_list_and_owner_close`;
  * `uninstall_lists_remote_enrollments_and_refuses_purge_without_ack`.
  * TUI:
    * `managed_readiness_detail_exact_deadline_strings` (the D8 wording, graceful and strict);
    * `enrollment_states_rendered`;
    * `lock_disclosure_once`;
    * `tui_search_never_contacts_issuer_or_remote`;
    * `tui_restores_terminal_after_enroll_decision`.
* **Acceptance:** the tests pass on all three platforms. No command answers "not available".
* **Depends on:** U10.

### U13: Exit suite, native harnesses, evidence, matrix and claim update

* **Owner paths:**
  * `tests/native/m03/`:
    * `run-macos.sh`, `run-linux.sh`, `run-windows-local.ps1`, `run-wsl-distro.sh`;
    * `lock-macos.sh`, `lock-windows.ps1`;
    * `refresh-inventory.sh`, `case-index.json`, `required-inventory.json`, `runs.json`;
    * `m03-evidence.py`;
  * `tests/evidence/m03-*.json` and `tests/evidence/artifacts/m03/**`;
  * `docs/compatibility/matrix.md` (an M03 section);
  * `docs/architecture/m03-exit-draft.md`;
  * the **claim update** of `crates/domain/src/claims.rs`, as a separate integrator-reviewed commit after
    the records are `verified`.
* **Scope:** §3 and §4.
* **Harness rules:** the M02 patterns ⟨M02?⟩ M8, plus:
  * Docker fixtures on the build host (`up.sh` exit 3 on "already exist", so the harness owns the
    fixtures only after a clean `up.sh`; M02 §12.33 P01);
  * an owner-digest check before and after (U11);
  * the lock procedure (§4.4);
  * the WSL disposable distribution created and removed by name (§4.3);
  * canary and secret-bytes scans over every artifact (§0.2).
* **Exit checks owned here** (named in §3):
  * `a03_fresh_logins_while_locked_continue`;
  * `a03_new_grant_while_locked_under_standing_policy`;
  * `a03_lock_revokes_ends_grant_and_fresh_login_fails`;
  * `a03_vault_stand_in_locked_agent_does_not_matter`;
  * `a03_report_shows_verified_lock_continuity_on_this_platform` (after the claim update);
  * `a10_worker_cannot_reach_issuer_material`;
  * `a33_secret_bytes_scan_all_artifacts`.
* **Tests:** the harness self-tests (`native-harness-selftest` gains the m03 harnesses, M02 pattern),
  including:
  * `lock_harness_refuses_without_idle_15_min`;
  * `lock_harness_records_unverified_lock_as_blocked`;
  * `wsl_harness_unregisters_only_its_distribution`.
* **Acceptance:** §3's records are generated and valid; the matrix rows are written; the exit draft is
  written.
* **Depends on:** every unit.

---

## 2. Order and parallelism

```text
U0 skeleton + contract rev 4  ┐ one integrator change set (wave 0), after the ADR-0008 Q1–Q17
U0b phase 1: M01/M02 integration ┘ rulings and the M02 exit build; wave-0 acceptance before wave 1
 ├─► U1 credential core ─────────────┐
 ├─► U4 stores, backup, ceremony ────┤ (wave 1, parallel; disjoint crates/modules)
 ├─► U5 enroll: plan, scripts, pure ─┤ (U5's target and verify tests go green after U2 and U11)
 ├─► U9 session lock ────────────────┤
 └─► U11 testkit + Docker fixtures ──┘
                                      ▼
     U2 signer + endpoints (U1, U11)   U3 issuer child + client (U1, U4)   U8 projection (U2 names;   (wave 2)
                                                                           its e2e tests go green after U6)
                                      ▼
     U6 managed adapter (U1–U4)        U7 connection control (U2, U6 interfaces, U8)                  (wave 3)
                                      ▼
     U10 drivers + runtime wiring ┐ activation change set: one integrator change
     U0b phase 2: capabilities,   ┘ (wave 4)
       decision completion, adapter registered
                                      ▼
     U12 CLI + TUI (U10)                                                                              (wave 5)
                                      ▼
     U13 exit suite, native runs, lock runs, records, matrix, claim update                           (wave 6)
```

**File conflicts are designed out:**
* U0 owns every signature, `cli.rs` and the migration.
* U0b alone edits the existing M01/M02 code: `operations.rs`, `dispatch.rs`, `session.rs`,
  `signing.rs`, `revocation.rs`, `issuance.rs`, `policy.rs`, `grant.rs`, `holders.rs`, `testcfg.rs` and
  `ext_m03.rs`.
* U8 alone edits the M02 projection and launch files listed in its owner paths.
* U10 alone edits `service.rs` and `supervisor.rs`. U7's and U9's passes are functions in their own
  files, which U10 calls.
* U2 and U1 share the `heimdall-credential` crate, but not files. U3 and U4 share `heimdall-issuer`, but
  not files.
* Contract and authority changes serialize through the integrator (plan §7.3).

**Review plan.** ADR-0008 and this plan get an **independent design review** before wave 0. M02 needed
four rounds; the reviewer receives ADR-0005, ADR-0008, this plan and the code at the base, not the
author's conclusions. Each wave then gets a code review (Codex), as M02's did. The security-sensitive
waves (2–4: signer, issuer, enrollment, revocation) also get the automated security review before their
commit (plan §6.7).

---

## 3. Milestone exit mapping (plan §5 M03 "Exit evidence")

Records are `tests/evidence/m03-*.json`; the status follows the lowest-row rule. "All" means macOS
arm64, Linux x86-64 (devbox) and Windows 11 x64, plus the WSL disposable distribution where it is named.

| Exit claim / case | Proven by (tests) | Records | Platforms (§4) |
|---|---|---|---|
| **A03**: fresh authentications succeed through desktop and vault lock without the original vault staying unlocked; the configured lock-revokes alternative behaves differently, as disclosed | U13 lock procedure (§4.4): `a03_fresh_logins_while_locked_continue`, `a03_new_grant_while_locked_under_standing_policy` (D1 issuer under lock), `a03_lock_revokes_ends_grant_and_fresh_login_fails`, `a03_vault_stand_in_locked_agent_does_not_matter`. U9 `macos_lock_signal_observed`, `windows_lock_signal_observed`. U2 and U10 `reissue_after_runtime_process_restart_same_boot` (the recovery row). U4 `windows_dpapi_round_trip_across_processes` during lock | `m03-a03-lock-continuity.json`; `m03-p1-macos-screen-lock.json`; `m03-pw1-windows-lock.json` | macOS (lock rule), Windows (lock rule). Linux desktop blocked (B11). The 1Password vault row is blocked (B1); the Windows system-agent vault row is blocked (B4). The macOS login-keychain product row is blocked (B3) |
| **A07**: new local use fails immediately; descendants and stale callbacks cannot reactivate; remote-pending effects and the maximum residual are truthful | U3 the linearization model; U6 `revoke_during_each_issuance_step`, `revoke_with_unreachable_destination_reports_bounded_remote_effect`, `revoke_cascades_to_children_destroying_their_keys`, `stale_approval_cannot_reactivate_after_revoke`, `bounded_obligation_completes_revocation_after_valid_before`; U2 `sign_during_revoke_is_linearized`, `destroyed_key_makes_installed_certificate_unusable`; U0b row 6; U9 `lock_revocation_between_reserve_and_publish_voids`; U4 `key_only_restore_reports_unbounded_unknown` | `m03-a07-revocation.json` | All. The disconnected-**runner** variant is `deferred_with_decision` to M06 (G07; plan §5 M06); A07's M01 model rows stay as recorded |
| **A09**: existing access survives; only owned records change; uncertain outcomes reconcile; newer edits are not overwritten; rotation; rollback | U5 protocol, negative, interleaving and lost-response tests; U10 `enroll_*`, `rotation_two_accounts_one_unreachable`, `enroll_remove_lists_affected_grants_and_degrades_them`, `foreign_removal_from_bundle`; U11 `registry_guard_refuses_non_scratch_paths`; the harness's owner-digest check. The disclosed remove window is recorded as a limitation (U5) | `m03-a09-enrollment.json` | All (Windows as the client to the WSL fixture sshd ⟨M02?⟩ M7). Docker default-path rows on macOS; WSL default-path rows on Windows. The devbox default-path row is a gap (B8) |
| **A10**: only the intended access succeeds where enforcement is claimed; no issuer key or broader certificate escapes; unsupported scope is labelled | U5 `verify_positive_one_signature_negative_zero`, `principals_not_enforced_detected_and_rolled_back`, `verification_failed_when_server_reads_another_registry`; U10 a two-host flow per form (`a10_narrow_certificate_refused_on_other_host_account_form`, `a10_…_system_form`); U3 `ceiling_two_principals`, `issuer_path_never_exists_through_runtime_lifecycle`; U2 `environment_endpoint_lists_only_materialized_bindings` (no CA listed); U13 `a10_worker_cannot_reach_issuer_material` (scans the runtime and data directories and every bound consumer's argv and environment; on Unix, no descriptor of the issuer's pipes is open in any process the runtime spawned (masters, verification ssh), checked on the exact PIDs; on Windows the inheritable-handle residual is recorded for M04); U6 `report_*` (unverified pairs report `unknown`; existing access reports `client_routing`) | `m03-a10-scope-issuer.json` | All. Docker `ca1`/`ca2` and `enrollable`/`enrollable2` on macOS; two `LoopbackSshd` per form everywhere; the WSL distribution's sshd in both forms |
| **A23**: owned admission and closure match the policy; no certificate-only enforcement assumption; unmanaged and remote-process limits are reported accurately; OpenSSH stop behaviour tested | U7 (all its tests); U8 `p_renders_owned_master_control_path_when_enabled`; U6 report fields `owned_multiplexing`, `existing_connections`, `remote_processes`, `unmanaged_connections`; U12 `managed_readiness_detail_exact_deadline_strings` | `m03-a23-deadline-connections.json` | macOS and devbox (real masters); Windows (dedicated connections; multiplexing reported and enforced as unavailable) |
| **A33**: no secret leakage or plaintext fallback; previewed and redacted outputs; nothing collected by default | U4 `no_plaintext_when_store_unavailable`, `passphrase_only_on_tty_transcript`, `bundle_contains_no_private_material`; U1 `secret_key_has_no_clone_debug_serialize`, `core_dumps_disabled_after_harden`; U13 `a33_secret_bytes_scan_all_artifacts` (the seeded K_env, the test K_ca, the passphrase, canaries: over envelopes, events, logs, errors, the DB file, the runtime and data directories, process argv and environment, crash-artifact directories); U0b `release_build_ignores_m03_test_gates` | `m03-a33-secrets.json` | All. Support bundles and update artifacts are M08 (their rows are `deferred_with_decision`) |
| "The user can allow background work once without routine unlocks" | U10 `enroll_preview_apply_verify_setup_apply_ensure_ssh`, which counts decisions (exactly the enrollment, projection and grant approvals) and provider prompts after approval (zero); the A03 lock rows; U9 `disclosure_shown_once_then_recorded` | `m03-exit-background-once.json` | All, fixture level, plus the A03 native rows. The human walkthrough is blocked (B7) |
| "An expired grant cannot renew itself" | U6 `expired_grant_never_reissued`, `renew_never_extends_deadline_or_pairs`, `reissue_refused_for_revoke_on_lock`; U3 ceilings; the M01 A05 model rows (unchanged) | `m03-exit-no-self-renewal.json` | All |
| "Does not claim all remote processes terminate or all offline credentials revoke immediately" | U7 `remote_process_survives_close_reported_not_terminated`; U6 `revoke_with_unreachable_destination_reports_bounded_remote_effect`; the report goldens (`remote_processes: not_terminated`, `revocation.remote: bounded_by_credential_expiry`, never `immediate` remote) | `m03-exit-honest-limits.json` | All |
| "A fixed provider remains usable under its real limitations" | The M02 A11 and A35 suites re-run unchanged at the M03 build; U8 `existing_access_aliases_render_byte_identical_to_m02`; U6 `issuer_unavailable_no_fallback_to_existing_identity`; U10 `enroll_*` (the existing identity is untouched) | `m03-exit-fixed-provider.json` (references the M02 records' rows at the M03 build) | All. The M02 blocked rows (B1, B4, B6) stay blocked |
| R-UX-03 (disclose once; configurable alternatives) | U9 `disclosure_shown_once_then_recorded`, `revoke_on_lock_refused_where_signal_unavailable`; U12 help goldens | in `m03-a03-lock-continuity.json` | All. Comprehension (A30) is M09 |
| R-AU-08 (actual enforcement; reject unmet minimums) | U6 report tests; U0b row 9 `unattended_requires_claim_and_continue`; U6 `offline_until_beyond_bound_capability_unavailable` | `m03-r-au-08-reports.json` | All |
| R-SE-07 (recheck the generation before issuance and activation) | U0b rows 2–5; U3 the linearization model; U6 `stale_approval_cannot_reactivate_after_revoke` | in `m03-a07-revocation.json` | All |
| R-CR-06 (rotation and unenrollment touch only owned records; A31 part) | U5; U10 rotation and removal; U0b row 18 and U12 `uninstall_lists_remote_enrollments_and_refuses_purge_without_ack` | in `m03-a09-enrollment.json` | All |
| All of the above together | the case index (`tests/native/m03/case-index.json`) | `m03-exit-claims.json` | — |

**The claim update** (ADR-0008 D12 item 3), after the native records:
1. For each record row that is `verified` and that a capability value depends on (`lock_continuity` per
   platform from `m03-a03`; `owned_multiplexing: closed_at_deadline` and `existing_connections` from
   `m03-a23`; `new_authentication_expiry: credential_and_signer` from `m03-a23` and `m03-a07`), the
   integrator adds one `Claim` entry naming that record, its commit and its platform row.
2. `check.sh` `claims-table` validates them.
3. The claim-reporting tests (`report_with_fixture_claim_table_reports_verified_with_record`, now with
   the real table, and `a03_report_shows_verified_lock_continuity_on_this_platform`) run on that build,
   on each platform.
4. A row that stays `blocked` gets no entry, and its value stays `not_verified` or `unknown`.

---

## 4. Platform evidence plan

### 4.1 Declared targets

These are the provisional G01 floors (ADR-0004 §4), with versions recorded at run time:

* **macOS arm64:** the build host, macOS 27.x.
  * System OpenSSH client (10.5p1 at the M02 exit draft).
  * `LoopbackSshd` runs `/usr/sbin/sshd`, non-root.
  * Docker Desktop hosts the Linux server containers (M00-T03 image).
* **Linux x86-64:** the owner's devbox, Ubuntu 24.04, OpenSSH 9.6p1, headless.
  * The tests are cross-built with zig through `run-linux.sh` (the M01/M02 pattern), copied to
    `~/hm-m03-<random>`, run there, and that directory is removed.
* **Windows 11 x64:** the owner's PC. A native `x86_64-pc-windows-msvc` build and run, through
  `tests/native/m03/run-windows-local.ps1` launched by a T3 agent on the PC at Medium integrity, with
  the toolchain in scratch (ADR-0007 §12.32 items 15–17).
  * Windows OpenSSH 10.3p1 at the M02 exit draft.
  * The fixture sshd runs in WSL scratch on `127.0.0.1`.
  * Nothing is elevated. No service, firewall, registry, ssh-agent, `~/.ssh` or WSL configuration
    changes, and there is no `wsl --shutdown`.
  * The bundle is returned in the agent's report and imported.
* **WSL2:** a **disposable** distribution (`wsl --import` from the pinned Ubuntu 24.04 rootfs; ADR-0004
  §3), created and unregistered by name. It is supplementary Linux evidence; the managed WSL Mode B is
  M04.
* **Linux desktop:** declared by ADR-0005 §5.2 (Ubuntu 24.04 / Debian 13 with GNOME). **No host:
  blocked on B11.**
* **Linux arm64:** blocked on B9 (Docker on the build host is supplementary only).

### 4.2 What each platform must prove

"Runnable" means it runs in M03 with no owner input. A blocked row names its input; §7 lists them.

| Property | macOS arm64 | Linux devbox (headless) | Windows 11 | WSL disposable distribution | Linux desktop |
|---|---|---|---|---|---|
| **K_env custody** (signer memory; destroyed at end; not ptraceable where claimed) | Runnable: vault tests, `core_dumps_disabled_after_harden`, `destroyed_key_makes_installed_certificate_unusable` | Runnable, plus `linux_signer_not_ptraceable_by_same_user` (ptrace_scope recorded) | Runnable (no extra process mitigation: disclosed) | Runnable (mechanism) | Blocked (B11) |
| **K_ca product store**: write, read at issuer start, across process restart | **Blocked (B3)** for the login keychain. Runnable mechanism: `macos_keychain_code_path_against_disposable_file_keychain` and the scratch store. Data-protection keychain blocked (B13) | **Product behaviour runnable:** no Secret Service on headless, so `issuer_store_unavailable`, no plaintext. Scratch store for mechanism | **Runnable product rows:** DPAPI CurrentUser blob (scratch path), round trip across processes, issuer start from it, owner-only DACL. Cross-user refusal blocked (B2) | Product behaviour: `issuer_store_unavailable`. Scratch store for mechanism | Blocked (B11): Secret Service over DH, availability after login |
| **Lock continuity (A03)**: fresh logins and a new grant while the desktop is locked | **Runnable under the ADR-0004 §2 rule** (§4.4): the signer and issuer from memory, the scratch-store K_ca loaded before the lock. The product login-keychain read during lock is blocked (B3) | Not applicable: there is no desktop lock on a headless host. `revoke_on_lock` refused (`lock_signal_unavailable`) | **Runnable under the lock rule:** the signer and issuer from memory, **DPAPI unprotect during lock** (an issuer restart forced while locked), fresh logins from Windows ssh through the Heimdall pipe | Not applicable (no lock signal): refused | Blocked (B11) |
| **Lock-revokes alternative** | Runnable: CG lock signal observed, then revocation, then fresh logins refused | Refusal verified | Runnable: WTS signal observed, then revocation | Refusal verified | Blocked (B11) |
| **Locked vault** | Stand-in runnable: a disposable `ssh-agent` (the source provider) locked with `ssh-add -x` during A03. 1Password blocked (B1) | Same stand-in | Stand-in: the FakeAgent pipe in `Locked` mode (labelled). Windows system agent blocked (B4), 1Password blocked (B1) | Same stand-in as Linux | Blocked (B11) |
| **Deadline across sleep** | Virtual clock runnable (U2, U6 `advance_continuous_only`). **Native sleep blocked (B12)** | Virtual clock | Virtual clock; native blocked (B12) | — | Blocked (B11, B12) |
| **Deadline across logout and reboot** | Same-boot process restart runnable (`reissue_after_runtime_process_restart_same_boot`). Logout and reboot blocked (B12, plus B3 for a disposable account) | Process restart runnable. Reboot of the devbox not authorized (owner's machine): blocked (B12) | Process restart runnable. Sign-out and reboot blocked (B12) | `wsl --terminate` of the disposable distribution is runnable as a "restart" row (a boot-ID change inside the distribution is `[U]`, recorded) | Blocked |
| **Post-reboot time** | Virtual clock: `reissue_after_reboot_waits_for_time_confirm`. `TimeSync` observation only (Q13) | `timedatectl` observation recorded (read-only) | `w32tm /query /status` observation recorded | — | — |
| **Endpoints**: owner-only, peer check, per-binding listing | Runnable (0700/0600, peer UID). Cross-user blocked (B3) | Runnable. Cross-user: no second account (devbox not authorized, B8): blocked | Runnable: owner-only protected DACL, owner-SID check. Cross-user blocked (B2) | Runnable | — |
| **Remote registry protocol** (the server's `/bin/sh`) | Runnable: Docker Debian 13 (dash) and `LoopbackSshd` (macOS `/bin/sh`) | Runnable: `LoopbackSshd` (Ubuntu dash) | Runnable as the **client**: the Windows ssh client to the WSL fixture sshd (dash) ⟨M02?⟩ M7 | Runnable: the distribution's root sshd and a non-root user, **default registry path, StrictModes** | — |
| **Production verification** (per client) | Runnable: client 10.5p1 against Docker (non-log account) and loopback | Runnable: client 9.6p1 | Runnable: client 10.3p1 (M-F18) | Runnable: client 9.6p1 | — |
| **Owned masters / multiplexing stop** | Runnable | Runnable | **Unavailable** (M-F7): the refusal is verified | Runnable (supplementary) | — |
| **Owned dedicated connection closing** | Runnable (`kill` after re-verification; window disclosed) | Runnable (pidfd) | Runnable (handle-pinned `TerminateProcess`) | Runnable | — |
| **Ordinary ssh without `-F`** for a managed alias | Blocked (B3) | Gap (B8): covered by WSL | Blocked (B2) | **Runnable** (a real disposable home) | — |

### 4.3 Harnesses

| Harness | Pattern | M03 additions |
|---|---|---|
| `tests/native/m03/run-macos.sh` | `check.sh` plus e2e on the build host (M02 `run-macos.sh`, with `TMPDIR=/tmp`, the `SUN_LEN` lesson) | `up.sh` for `enrollable`, `enrollable2`, `ca1` and `ca2` (owned only after a clean `up.sh`); `ca-trust-test-ca`; `LoopbackSshd` ×2 per form; the disposable file keychain created and deleted by path; the owner-digest check (§0.2), including the keychain list; `down.sh` must print `CLEANUP CONFIRMED`. Records `ssh -V`, `sshd -V`, the container versions and APFS |
| `tests/native/m03/run-linux.sh <dir> devbox` | The M02 zig cross-build, `~/hm-m03-<random>`, `nice`, a timeout, `rm -rf` of exactly that directory | Records `ssh -V`, `sshd -V`, `ptrace_scope`, `ulimit -l`, `timedatectl show -p NTPSynchronized` (read-only), and whether gnome-keyring is installed (no installation). `LoopbackSshd` per form. No Docker (B8) |
| `tests/native/m03/run-windows-local.ps1` | M02's local-mode runner (clone at commit E into scratch, toolchain in scratch, native msvc build, tests with timeouts, redaction, one bundle) | Starts the WSL scratch sshd in both forms (the system form through a scratch `sshd_config` with `TrustedUserCAKeys`). DPAPI blobs in scratch. Records `icacls` of every Heimdall pipe and blob, `w32tm /query /status` (read-only), and pipes counted before and after. Never opens `\\.\pipe\openssh-ssh-agent`. Imported with `import-windows-bundle.py` |
| `tests/native/m03/run-wsl-distro.sh` | M02's disposable distribution (G03 P-B08/09/10) | Inside it, as its root: `sshd` on `127.0.0.1` in both forms, a disposable non-root user with a real home, the Linux `heimdall` binary, the scratch store. Then the enrollment against the **default registry path**, ordinary `ssh`/`git`/`scp`/`sftp` without `-F` for the managed alias, and `uninstall`. Afterwards `wsl --terminate` and `--unregister` that distribution only |
| `tests/native/m03/lock-macos.sh`, `lock-windows.ps1` | New. §4.4 | The A03, P1 and P-W1 rows, run separately from the exit build window but bound to the exit commit |

### 4.4 The lock procedure (ADR-0004 §2)

The orchestrator may lock the macOS screen and the Windows PC itself **only after the console has been
idle for at least 15 minutes**. The owner unlocks whenever they return. The harnesses enforce this:

1. **Idle check.** macOS `ioreg -c IOHIDSystem` `HIDIdleTime`; Windows `GetLastInputInfo` (through a
   tiny harness helper in scratch). Below 15 minutes, the harness exits `blocked`
   (`console_not_idle`) without locking.
2. **Prepare, unlocked.**
   * Start the runtime from the exit build.
   * `time confirm` (attended, through a pty).
   * `issuer init` with the test store: scratch on macOS, DPAPI on Windows.
   * Enroll two loopback hosts.
   * `setup apply`.
   * Create two grants: one `continue` (8 h), and one under a `revoke_on_lock` policy.
   * A standing policy that lets a non-interactive `ensure` create a third grant later.
   * Start the source-provider stand-in agent, then lock it (`ssh-add -x`, or FakeAgent `Locked`).
3. **Lock.**
   * macOS: `pmset displaysleepnow`. It locks only if the host requires a password immediately after
     display sleep; that setting is never changed.
   * Windows: `rundll32 user32.dll,LockWorkStation`, from the interactive session through the T3
     agent.
4. **Verify the lock** through the product's query (`heimdall internal session-lock-state`, a hidden
   read-only subcommand, test configuration and release alike) and through the event recorded by U9.
   If it does not report `locked` within 30 s, the row is `blocked` (`lock_not_verified`), with the
   observation.
5. **While locked**, sampled every 60 s for up to 30 min:
   * N fresh `ssh` logins per host through P, each with a new accepted line in the loopback sshd log;
   * one non-interactive `access ensure` that creates the third grant, followed by fresh logins on it
     (ADR-0005 D1: new grants under lock);
   * on Windows, one forced issuer restart (DPAPI unprotect under lock);
   * the `revoke_on_lock` grant's revocation event and its refused fresh login;
   * no prompt observed: no new window or process for keychain or credential UI, checked by exact
     process names.
6. **Wait for the unlock** (bounded to 12 h), then post-unlock checks:
   * the `revoke_on_lock` grant is still terminal;
   * the `continue` grants are still usable;
   * nothing is reactivated.
7. **Clean up:** stop the runtime; scratch removal; the owner-digest check.

The records name the method, the idle time observed, the lock-state observations and the timings. A run
that could not lock is `blocked`, never `failed` and never `verified`.

### 4.5 Records

| Record | Case / claim | Rows |
|---|---|---|
| `m03-a03-lock-continuity.json` | A03 | macOS lock, Windows lock, macOS login-keychain product (B3), Linux desktop (B11), 1Password vault (B1), Windows system-agent vault (B4) |
| `m03-p1-macos-screen-lock.json`, `m03-pw1-windows-lock.json` | ADR-0005 §9.3 P1 and P-W1 (they supersede `g04-macos-screen-lock-probe.json` and `g04-windows-desktop-lock-probe.json`, whose `blocked_on` texts the integrator updates) | the per-property rows of §4.2 |
| `m03-a07-revocation.json` | A07 (destination variant) | All; the runner variant `deferred_with_decision` (M06) |
| `m03-a09-enrollment.json` | A09 | All; the default-path rows by platform; the disclosed-window limitation |
| `m03-a10-scope-issuer.json` | A10 | All, per form |
| `m03-a23-deadline-connections.json` | A23 | All (Windows multiplexing as "unavailable, verified") |
| `m03-a33-secrets.json` | A33 | All; support bundles and update artifacts `deferred_with_decision` (M08) |
| `m03-exit-*.json`, `m03-r-au-08-reports.json`, `m03-exit-claims.json` | the plan §5 claims | as in §3 |
| `m03-store-macos-keychain.json`, `m03-store-windows-dpapi.json`, `m03-store-linux-secret-service.json` | the K_ca custody rows (ADR-0005 §5.2) | macOS mechanism, product blocked (B3); Windows product; Linux blocked (B11), or the private-session mechanism if available |
| `m03-sleep-logout-reboot.json` | ADR-0005 §9.3 P2, P3, P4, P-W2 and R4 | process-restart rows runnable; the others blocked (B12) |

---

## 5. Contract additions: the ADR-0006 revision 4 deltas

Schema major stays `"1"` (ADR-0006 §9). Every change is **additive**:
* every new field is `#[serde(default)]` and omitted when it carries no value;
* every new enum is `#[non_exhaustive]` and `snake_case` on the wire;
* readers built before M03 tolerate unknown fields (spec §11.2).

The code table stays at 30 rows. These are the final shapes U0 implements, after the ADR-0008 Q1–Q17
rulings.

**1. IDs** (`contract::ids`): `EnrollmentId`, prefix `enr`, and `CaFingerprint`, a validated
`SHA256:<43 base64 characters>` newtype.

**2. `Request::Issuer(IssuerRequest)`** (`contract::issuer`), capability `issuer/1`.

```rust
#[serde(tag = "action", rename_all = "snake_case")]
#[non_exhaustive]
pub enum IssuerRequest {
    /// Read-only. kind "issuer.status".
    Status,
    /// Effectful, synchronous, always creates a RegisterIssuer decision (never executes on
    /// dispatch; ADR-0006 §2.3 N04 pattern). kind "issuer.register".
    Register {
        ca_public_key: String,            // OpenSSH one-line Ed25519 public key; no comment
        store: StoreKind,
        backup_sha256: String,            // hex of the D5 file's bytes
        backup_created_at: Timestamp,
        #[serde(default)] rotation_of: Option<CaFingerprint>,   // rotate-begin
        #[serde(default)] restored_without_log: bool,           // key-only restore
    },
    /// Attended sessions only (requires_attended_session). kind "issuer.unlock".
    Unlock,
    /// Creates a RetireIssuer decision. kind "issuer.retire".
    Retire { ca_fingerprint: CaFingerprint },
    /// Read-only; public metadata only. kind "issuer.bundle".
    Bundle { #[serde(default)] redact_hostnames: bool },
}

#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum StoreKind {
    MacosLoginKeychain, MacosDataProtectionKeychain, WindowsDpapi, LinuxSecretService,
    ScratchTest, // accepted only by test-configured builds; refused otherwise (USAGE_ERROR)
}
```

`IssuerStatus` (the `issuer.status` data and `inspect issuer`):

```json
{
  "state": "ready",
  "cas": [{"fingerprint": "SHA256:…", "state": "active", "store": "windows_dpapi",
           "backup_sha256": "…", "backup_created_at": "2026-11-10T14:00:00Z",
           "restored_without_log": false, "enrollments": {"verified": 2, "pending": 0}}],
  "orphan_store_items": [],
  "issuer_isolation": "same_user_process",
  "bundle_stale": false
}
```

`state` ∈ `not_initialized | starting | loading | ready | store_unavailable | crashed | unavailable |
stopping`. With `store_unavailable` it carries `"reason"`.

**3. `Request::Enrollment(EnrollmentRequest)`** (`contract::enrollment`), capability `enrollment/1`.

```rust
#[serde(tag = "action", rename_all = "snake_case")]
#[non_exhaustive]
pub enum EnrollmentRequest {
    /// Read-only, local, contacts nothing. kind "enrollment.preview". Data: EnrollmentPlan.
    Preview { spec: EnrollmentSpec },
    /// Journaled "enrollment.apply", effect class remote_mutation. Needs EnrollAccount.
    Apply { spec: EnrollmentSpec, plan_digest: PlanDigest, request_id: RequestId,
            #[serde(default)] interaction: InteractionMode, #[serde(default)] wait: WaitMode },
    /// Journaled "enrollment.verify" (re-verification; the system form's first verification).
    /// Effect class local (issues ≤5-min verification certificates; no remote mutation).
    Verify { enrollment_id: EnrollmentId, request_id: RequestId,
             #[serde(default)] wait: WaitMode },
    /// Journaled "enrollment.remove", effect class remote_mutation. Needs RemoveEnrollment.
    Remove { target: RemovalTarget, request_id: RequestId,
             #[serde(default)] interaction: InteractionMode, #[serde(default)] wait: WaitMode },
    /// Synchronous: drives an unresolved enrollment.apply/remove (ADR-0008 D5 §6.7).
    Reconcile { operation_id: OperationId, #[serde(default)] interaction: InteractionMode },
    /// Synchronous, owner channel: record abandonment (residual pending_until_line_removed).
    Abandon { enrollment_id: EnrollmentId },
    /// Synchronous: the client-executed step protocol (ADR-0008 D5 §6.3). Writes the stage
    /// receipt first (Attempted for append/remove), then returns the RemoteStep. kind "enrollment.step".
    Step { operation_id: OperationId },
    /// Synchronous: the CLI's result for the outstanding step. kind "enrollment.step_result".
    StepResult { operation_id: OperationId, step_token: String,           // 32 hex
                 exit_status: i32, stdout: String,                        // ≤ remote_stdout_max, HM1 lines only
                 stderr_excerpt: String },                                // ≤ 4 KiB, redacted, diagnostics only
}

/// What the CLI must run (no secret; the script contains only validated literals).
pub struct RemoteStep {
    pub stage: RemoteStage,              // inspect | append | remove
    pub step_token: String,
    pub alias: String,                   // the managed alias (ordinary configuration)
    pub options: Vec<String>,            // exactly the narrowing -o list of ADR-0008 D5 §6.3
    pub remote_command: String,          // "exec /bin/sh -s"
    pub script: String,                  // written to ssh's stdin
    pub timeout_ms: u64,
}

pub struct EnrollmentSpec {
    pub destination: DestinationId,
    #[serde(default)] pub account: Option<AccountName>,    // default: the managed definition's
    #[serde(default)] pub form: EnrollmentForm,            // account (default) | system
    #[serde(default)] pub registry_path: Option<String>,   // ADR-0008 D5 §6.1 rule
    #[serde(default)] pub ca_fingerprint: Option<CaFingerprint>, // default: newest active CA
}

#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RemovalTarget {
    Enrollment { enrollment_id: EnrollmentId },
    Foreign { destination: DestinationId, account: AccountName, marker: String,
              ca_fingerprint: CaFingerprint, line_sha256: String },   // from a recovery bundle
}
```

`EnrollmentPlan` (the preview data, the decision's summary, and the hash input through `plan_digest`):

```json
{
  "plan_digest": "sha256:…",
  "destination_id": "dst_…", "alias": "lab", "account": "deploy",
  "form": "account",
  "registry": {"path_display": "$HOME/.ssh/authorized_keys", "resolved_by": "remote_home"},
  "line": "cert-authority,principals=\"hm:dst_…:deploy\" ssh-ed25519 AAAA… heimdall:enr_…",
  "line_sha256": "…",
  "ca_fingerprint": "SHA256:…",
  "existing_access": {"identity_id": "idn_…", "mechanism": "native_agent",
                      "endpoint_display": "<agent>"},
  "host_key": {"algorithm": "ssh-ed25519", "fingerprint": "SHA256:…"},
  "verification": {"positive_principal": "hm:dst_…:deploy", "negative": true,
                   "max_validity_seconds": 300},
  "rollback": "compare_then_rename_by_marker",
  "disclosures": ["config_commands_run_as_ordinary_use", "ca_trust_blast_radius",
                  "remove_window", "lock_continuity_once"]
}
```

`EnrollmentResult` (the `apply`, `verify` and `remove` operation results):
* `{enrollment_id, state, verified_at?, evidence?: {client, server, operation_id}, next}`;
* `next` is `setup_apply` after a pass, `review_host_trust` for a held host key, `reconcile` for
  `outcome_unknown`, and `manual_registry_edit` with `instructions` for `registry_not_rewritable`.

`EnrollmentView` (`inspect enrollments`): one entry per record, with:
* `enrollment_id`, `destination_id`, `account`, `form`, `ca_fingerprint`, `marker`, `state`,
  `registry.path_display`;
* `verified_at` and `evidence_fresh_until`;
* `pair_residual_until` (D7 item 4);
* `live_grants: [grant_id]`;
* `open_operation_id`.

**4. `InspectSubject::{Enrollments, Issuer, Connections}`**. `ConnectionsView`: one entry per
`owned_connections` row, with `{id, kind: master | dedicated, binding_id, grant_id, destination_id,
started_at, policy: {existing, multiplexing}, closes_at: Timestamp | null, state: up | closing}`. PIDs are
not exposed.

**4a. `Request::Connections(ConnectionsRequest::Close { connection_id })`**, capability `connections/1`.
* It is synchronous and effectful, and accepted from the owner role only (as `Shutdown` is, ADR-0006
  §13.6 item 8). It is narrowing, so it needs no decision. kind `"connections.close"`.
* It closes one owned connection through `ConnectionControl::close` (reason `owner_request`). An
  unverifiable process is reported, not signalled.

**4b. Catalog action `SetPreference { destination: DestinationId, account: AccountName, mechanism:
PreferredMechanism }`** (`managed_certificate | existing`). It is the ninth `CatalogRequest` action,
journaled under `catalog` (M02), local only.
* `managed_certificate` is refused (`pair_not_enrolled`) without a `verified` enrollment for the pair.
* The preference takes effect for P only through `setup apply` (ADR-0008 D5 §6.6).

**5. `EnsureRequest.connection`**: `#[serde(default, skip_serializing_if = "Option::is_none")]
connection: Option<ConnectionRequest { existing: Option<ExistingConnectionsMode> }>`. Only `strict` is
accepted, as narrowing; `graceful` in a request is `USAGE_ERROR`. It enters the canonical request hash
**only when present** (§5 item 12), so M01 and M02 hashes are unchanged.

**6. `PolicyAction` additions:**

```rust
SetLockBehavior { policy_id: PolicyId, behavior: LockBehavior },          // continue | revoke_on_lock
SetConnectionPolicy { policy_id: PolicyId,
                      #[serde(default)] existing: Option<ExistingConnectionsMode>,   // graceful | strict
                      #[serde(default)] multiplexing: Option<MultiplexingMode> },    // disabled | owned_masters
```

`is_widening_policy_action` is true for `SetLockBehavior{continue}`, `SetConnectionPolicy{existing:
graceful}` and `SetConnectionPolicy{multiplexing: owned_masters}`. Those create `WidenPolicy` decision
records (ADR-0006 §3.1); the others are narrowing, take effect immediately, and move the generation.
`StandingPolicy` gains `lock_behavior: LockBehavior` (default `continue`) and `connection:
ConnectionPolicy` (default graceful, disabled), both serde-defaulted.

**7. `EnsureData` additions** (`contract::managed`):

```rust
#[serde(default)] pub lock_continuity: LockContinuityReport,      // verified | not_verified (default) | lock_revokes
#[serde(default, skip_serializing_if = "Vec::is_empty")] pub conditions: Vec<ReadinessCondition>,
    // signer_running | time_confirmation_after_reboot | issuer_store_unlocked_at_start
#[serde(default, skip_serializing_if = "Option::is_none")] pub refresh_condition: Option<RefreshCondition>,
    // { needed_only_after: signer_restart, source: local_issuer }
#[serde(default, skip_serializing_if = "Option::is_none")] pub revocation: Option<RevocationSemantics>,
#[serde(default, skip_serializing_if = "Vec::is_empty")] pub evidence: Vec<EvidenceEntry>,
#[serde(default, skip_serializing_if = "Option::is_none")] pub connection_policy: Option<ConnectionPolicyReport>,

pub struct RevocationSemantics {
    pub local: LocalRevocation,                 // immediate
    pub remote: RemoteRevocation,               // bounded_by_credential_expiry | not_applicable
                                                // | pending_until_line_removed | unbounded_unknown | unknown
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_possible_credential_expiry: Option<Timestamp>,   // absent = unknown
    pub destination_clock_error: ClockErrorStatus,              // unmeasured
}
pub struct EvidenceEntry {
    pub field: String,                          // e.g. "destination_scope", "lock_continuity"
    pub source: EvidenceSource,                 // runtime_verification | claim_table
    #[serde(default)] pub pair: Option<AccessPairRef>,
    #[serde(default)] pub record: Option<String>,        // claim-table record path
    #[serde(default)] pub operation_id: Option<OperationId>, // runtime verification
    #[serde(default)] pub client: Option<String>,
    #[serde(default)] pub server: Option<String>,
    pub observed_at: Timestamp,
    #[serde(default)] pub fresh_until: Option<Timestamp>,
}
pub struct ConnectionPolicyReport {
    pub existing: ExistingConnectionsMode, pub multiplexing: MultiplexingMode,
    pub wording: String,   // the exact D8 disclosure sentence(s), human text, not a code
}
```

`refresh_dependency` stays the M01 enum: `local_issuer` for managed grants. `credential_availability`
reuses `through_deadline` and `refresh_dependent`.

**8. `Enforcement` additions.** Each is `#[serde(default)]` and reads `unknown` when absent:
* `identity_selection: IdentitySelectionEnforcement`: `client_configuration_and_signer`,
  `signer_filtering`, `client_configuration`, `unknown`;
* `new_signing_expiry: NewSigningExpiry`: `signer`, `not_applicable`, `unknown`;
* `owned_multiplexing: OwnedMultiplexing`: `disabled`, `closed_at_deadline`, `unavailable`, `unknown`;
* `remote_processes: RemoteProcesses`: `not_terminated`, `unknown`;
* `unmanaged_connections: UnmanagedConnections`: `not_controlled`, `unknown`;
* `issuer_isolation: IssuerIsolation`: `same_user_process`, `not_applicable`, `unknown`;
* `ExistingConnectionsPolicy` gains `not_controlled` (a `run` of a program other than ssh; ADR-0008 D8
  item 2).

`NewAuthenticationExpiry` keeps `none` for "not enforced". ADR-0005's spelling `not_enforced` is left
to the G08 naming freeze.

**A managed `ensure` result** (the `schemas/examples/ensure-data.managed.json` fixture; values as
computed with an **empty** claim table):

```json
{
  "binding_id": "binding_…", "environment_id": "env_…", "profile_revision": 3, "grant_id": "grant_…",
  "expires_at": "2026-11-10T22:00:00Z", "usable_until": "2026-11-10T22:00:00Z",
  "offline_until": "2026-11-10T22:00:00Z", "refresh_dependency": "local_issuer",
  "refresh_condition": {"needed_only_after": "signer_restart", "source": "local_issuer"},
  "conditions": ["signer_running", "time_confirmation_after_reboot"],
  "credential_mechanism": "managed_certificate", "credential_availability": "through_deadline",
  "lock_continuity": "not_verified",
  "enforcement": {
    "destination_scope": "verified_server_principals", "new_authentication_expiry": "unknown",
    "workload_isolation": "shared_os_user", "existing_connections": "unknown", "revocation": "unknown",
    "identity_selection": "client_configuration_and_signer", "new_signing_expiry": "unknown",
    "owned_multiplexing": "disabled", "remote_processes": "not_terminated",
    "unmanaged_connections": "not_controlled", "issuer_isolation": "same_user_process"
  },
  "revocation": {"local": "immediate", "remote": "bounded_by_credential_expiry",
                 "latest_possible_credential_expiry": "2026-11-10T22:00:00Z",
                 "destination_clock_error": "unmeasured"},
  "evidence": [{"field": "destination_scope", "source": "runtime_verification",
                "pair": {"destination": "dst_…", "account": "deploy"}, "operation_id": "op_…",
                "client": "OpenSSH_10.5p1", "server": "OpenSSH_10.0p2 Debian-7+deb13u4",
                "observed_at": "2026-11-10T13:50:00Z", "fresh_until": "2027-02-08T13:50:00Z"}],
  "connection_policy": {"existing": "graceful", "multiplexing": "disabled",
                        "wording": "New connections stop at the deadline; existing sessions may stay connected."},
  "consumer": {"signing_endpoint": "<runtime>/signing.sock", "pairs": ["…"]}
}
```

* `new_signing_expiry`, `new_authentication_expiry`, `existing_connections` and the summary
  `revocation` stay `unknown` until their claim-table entries exist (ADR-0008 D12).
* Two values are **runtime evidence** for this binding:
  * `destination_scope: verified_server_principals`, from each pair's enrollment verification;
  * `identity_selection: client_configuration_and_signer`, only when the static evaluation finds the
    selection `exclusive`.
* `owned_multiplexing: disabled`, `remote_processes: not_terminated`, `unmanaged_connections:
  not_controlled`, `workload_isolation: shared_os_user` and `issuer_isolation: same_user_process` are
  **limitations or the binding's own configuration**, not enforcement claims, so they are reported from
  the start.

**9. `RevokeData` additions:**
* `#[serde(default, skip_serializing_if = "Vec::is_empty")] remote_effects: Vec<RemoteEffectReport {
  destination: DestinationId, account: AccountName, status: RemoteRevocation, until: Option<Timestamp>
  }>`;
* `#[serde(default)] destination_clock_error: ClockErrorStatus`.

`remote_pending: Vec<GrantId>` and `latest_possible_credential_expiry` are unchanged in meaning (ADR-0008
D7 item 2).

**`RecoveryBundle`** (the `issuer.bundle` data; a file written only by the CLI):
* `{schema: "heimdall-recovery-bundle/1", created_at, cas: [...], enrollments: [{marker, destination_id,
  hostname?, account, registry_path_display, form, state, ca_fingerprint, line_sha256}],
  instructions}`;
* never a private key, a passphrase or a socket path.

**10. Decision kinds** (`domain::decision::DecisionKind`):

```rust
RegisterIssuer { ca_fingerprint: CaFingerprint, store: StoreKind, backup_sha256: String,
                 rotation_of: Option<CaFingerprint>, restored_without_log: bool,
                 disclosures: Vec<DisclosureKind> },
RetireIssuer { ca_fingerprint: CaFingerprint, abandoned_enrollments: Vec<EnrollmentId> },
EnrollAccount { operation: OperationId, plan_digest: PlanDigest, summary: EnrollmentPlanSummary },
RemoveEnrollment { operation: OperationId, enrollment: EnrollmentRef, affected_grants: Vec<GrantId>,
                   pair_residual_until: Option<Timestamp> },
```

Each is completed only by `Decide` on an attended session (ADR-0006 §3.1). An `EnrollAccount` approval
copies `plan_digest` into the operation's approval basis, and it is valid for 24 h (ADR-0008 Q7).

**11. Operation kinds** (`domain::operation::OperationKind`):
* `EnrollmentApply` (`"enrollment.apply"`, effect class `remote_mutation`);
* `EnrollmentVerify` (`"enrollment.verify"`, `local`);
* `EnrollmentRemove` (`"enrollment.remove"`, `remote_mutation`).

`ALL` grows to 15. These kinds are never driven at restart (U0b row 17). Cancelling them is refused with
`CAPABILITY_UNAVAILABLE`, reason `remote_step_in_progress`, once the E3 `Attempted` receipt exists;
before that it is allowed.

**12. Hash inputs** (`app::operations`):
* `enrollment.apply`: environment, `plan_digest`, destination, account, form, registry path and CA
  fingerprint;
* `enrollment.verify`: enrollment ID;
* `enrollment.remove`: the canonical target;
* `ensure`: unchanged, plus `connection` only when present.

**13. Events** (`contract::event::EventType`):
* `Enrollment`: payload `{enrollment_id, state, operation_id}`;
* `Connection`: `{connection_id, kind, event: started | closed, reason}`;
* `SessionLock`: `{state, revoked: [grant_id]}`.

`CredentialLifecycle` payload `event` values grow to `reserved | published | voided | installed |
destroyed | lost | reissued`. No payload carries a secret, a PID or a path.

**14. Stable sub-reasons** (`data.error.reason`; the golden from U0):

| Code | New reasons |
|---|---|
| `CAPABILITY_UNAVAILABLE` (4) | `issuer_not_initialized`, `issuer_unavailable`, `issuer_store_locked`, `issuer_store_unavailable`, `pair_not_enrolled`, `pair_not_adopted`, `enrollment_unverified`, `projection_pending`, `observed_alias_unmanaged`, `route_unsupported`, `registry_unsupported`, `principal_charset`, `host_trust_undetermined`, `verification_failed`, `principals_not_enforced`, `verification_inconclusive`, `lock_continuity_unverified`, `lock_revokes_chosen`, `lock_signal_unavailable`, `multiplexing_unsupported`, `too_many_identities`, `credential_reissue_pending`, `remote_step_in_progress`, `driver_unavailable` (exists) |
| `CONFIG_CONFLICT` (6) | `already_enrolled`, `registry_changed`, `registry_not_rewritable`, `registry_too_large`, `registry_line_damaged`, `managed_slot_held` |
| `OUTCOME_UNKNOWN` (7) | `registry_outcome_unknown`, `remove_outcome_unknown` |
| `DECISION_STALE` (6) | `approval_lapsed` |
| `HOST_TRUST_CHANGED` (4) | `enrollment_host_key_mismatch` |
| `SERVICE_UNAVAILABLE` (5) | `issuer_restarting` |
| `BACKPRESSURE` (5) | `issuer_rate_limited` |
| `CREDENTIAL_EXPIRED` (4) | `grant_ended_session_locked` (use after a lock revocation) |

**15. Capabilities** (`contract::ipc::capability`): `issuer/1`, `enrollment/1`, `managed-credentials/1`
and `connections/1` are **declared and not offered** in wave 0, and offered in phase 2 (U0b row 13).

**16. Domain types:**
* `domain::enrollment`:
  * `EnrollmentRecord`, `EnrollmentState` (ADR-0008 D5 §6.2; 15 states), `EnrollmentEvent`,
    `transition`;
  * `EnrollmentForm { Account, System }`;
  * `RegistryRef { path_display, resolved_by: Explicit | RemoteHome }`;
  * `EnrollmentEvidence { client, server, operation, verified_at, fresh_until }`;
  * `PairPreference { destination, account, mechanism, projection: Pending | Applied { generation },
    enrollment }`.
* `domain::verification`:
  * `VerificationEntry { id: IssuanceId, operation, pair, purpose: Positive | Negative, bounds:
    CertificateBounds, state: IssuanceState, reserved_at, settled_at, void_reason }`;
  * `VerificationCheck`, `VerificationRefusal { OperationNotVerifying, PairMismatch, CaMismatch,
    WrongPrincipal, ExtensionsPresent, ValidityTooLong, UnknownSubjectKey, TimeUncertain,
    TooManyEntries }`;
  * `check`.
* `domain::issuance`: `CertificateBounds.ca_fingerprint: Option<CaFingerprint>`; `IssuanceRefusal` gains
  `UnknownCa` and `CaNotVerifiedForPair`; `CredentialState::Lost`; `extension_profile(grant, pair)`.
* `domain::grant`: `DegradedReason::{CredentialReissuePending, IssuerUnavailable, PairUnenrolled}`;
  `GrantOrigin.{lock_behavior, connection}`, add-only.
* `domain::revocation`: `RevocationCause::SessionLocked`; `RemoteObligation.kind: ObligationKind {
  NeedsRemoteAction (default), BoundedByExpiry { until } }`.
* `domain::policy`: `LockBehavior`, `ConnectionPolicy { existing, multiplexing }`, and the
  `StandingPolicy` fields.
* `domain::resource::ResourceKind` gains `MaterializedFile` and `Connection`.
* `domain::managed`: `SlotState`, `slot_transition`, `OwnedConnection { id, kind, binding, grant, pid,
  start_token, control_path, generation, state }`.
* `domain::claims`: `Claim { field, value, platform: Platform { os, arch }, os_floor, client_versions:
  VersionRange, signer_builds: VersionRange, record: &'static str, record_commit: &'static str }`, and
  `CLAIMS: &[Claim]` (empty in the baseline).

**17. `Limits`** (`app::Limits`). Application limits, not user configuration keys (the M02 P12 pattern):

| Limit | Value |
|---|---|
| `signature_authorization_timeout` | 2 s |
| `issuer_request_timeout` | 10 s |
| `issuer_start_timeout` | 5 s |
| `issuer_signatures_per_minute` | 600 |
| `max_certificates_per_grant` | 64 |
| `enrollment_step_timeout` | 120 s; 300 s interactive |
| `registry_max_bytes` | 128 KiB |
| `remote_stdout_max` | 1 MiB |
| `remote_stderr_max` | 64 KiB |
| `verification_max_validity` | 300 s |
| `verification_attempts` | 3 |
| `enrollment_approval_validity` | 24 h |
| `enrollment_evidence_freshness` | 90 days (ADR-0008 Q11) |
| `owned_master_close_grace` | 5 s |
| `dedicated_close_grace` | 5 s |
| `lock_event_coalesce` | 1 s |

**18. Store**: migration `0006_managed_credentials`, `SCHEMA_VERSION` 6. It adds tables only.

| Table | Columns (all `STRICT`) |
|---|---|
| `issuers` | `ca_fingerprint` PK, `public_key`, `state`, `store_kind`, `backup_sha256`, `backup_created_at`, `restored_without_log` INTEGER, `created_at`, `retired_at`, `record_json` |
| `enrollments` | `id` PK, `destination_id`, `account`, `ca_fingerprint` FK issuers, `form`, `marker` UNIQUE, `state`, `verified_at`, `record_json`. A partial UNIQUE index on (`destination_id`, `account`, `ca_fingerprint`) where `state` is not final |
| `verification_issuance` | `id` PK, `operation_id`, `destination_id`, `account`, `purpose`, `state`, `valid_before`, `reserved_at`, `record_json`; an index on (`destination_id`, `account`, `state`) |
| `pair_preferences` | (`destination_id`, `account`) PK, `mechanism`, `projection_state`, `projection_generation`, `enrollment_id`, `updated_at` |
| `managed_slots` | (`environment_id`, `destination_id`, `account`) PK, `binding_id`, `generation`, `state`, `updated_at` |
| `owned_connections` | `id` PK, `binding_id`, `grant_id`, `kind`, `pid`, `start_token`, `control_path`, `generation`, `state`, `started_at`, `record_json` |
| `meta` keys | `lock_disclosure_acknowledged_at`, `session_lock_last`, `windows_environment_pipe_token` (ADR-0008 D10 item 1) |

The policy, grant-origin and remote-revocation changes ride in their existing JSON records as defaulted
fields, with no column change. `Txn` methods:
* `insert_issuer`, `issuer`, `issuers`, `set_issuer_state`;
* `insert_enrollment`, `enrollment`, `enrollments_for_pair`, `transition_enrollment` (CAS on state; it
  calls `domain::enrollment::transition`);
* `verified_cas_for_pair`;
* `reserve_verification`, `publish_verification`, `void_verification`, `verification_entries`,
  `pair_residual`;
* `set_pair_preference`, `pair_preference`;
* `claim_slot` (CAS free → held), `release_slot` (CAS by generation), `slots_for_binding`;
* `insert_owned_connection`, `owned_connections_for_grant`, `close_owned_connection` (CAS by
  generation);
* `set_lock_disclosure_ack`, `lock_disclosure_ack`;
* `mark_lost_instances` (U0b row 8).

**19. Ports** (`app::ports`). Every one follows the M02 drop contract: no detached work, everything
bounded.

```rust
#[async_trait] pub trait SignatureAuthority: Send + Sync {
    async fn authorize(&self, facts: SignatureRequestFacts) -> SignatureDecision; // Admit | Refuse(SignRefusal)
}
#[async_trait] pub trait IssuerPort: Send + Sync {
    fn status(&self) -> IssuerStatusSnapshot;
    async fn sign(&self, entry: IssuanceRef, subject: &str) -> Result<String, IssuerError>;
    // IssuanceRef { table: Grant | Verification, id: IssuanceId }; returns an OpenSSH cert line.
    // IssuerError { Refused(IssuerRefusal), Unavailable(reason), Timeout, Protocol }
}
// No runtime port runs existing-access ssh (ADR-0008 D5 §6.3): the remote steps are
// client-executed. The pure classification the runtime applies to a StepResult is
// heimdall_enroll::registry::classify_step(stage, &StepResult, &Expected) ->
//   StepClass { Confirmed{post}, AlreadyPresent{post}, NotApplied(reason), Uncertain(reason),
//               HostTrustChanged, ProviderLocked, InteractionRequired(kind), Held(reason) }
// and the CLI-side runner is heimdall_enroll::remote::SshStepRunner (a library, not a port).
#[async_trait] pub trait VerificationRunner: Send + Sync {
    async fn run(&self, plan: &EnrollmentPlan, positive: &str, negative: &str,
                 endpoint: &VerificationEndpointRef) -> VerificationOutcome;
}
pub trait SessionLockSource: Send + Sync {
    fn state(&self) -> LockState;                                  // unlocked | locked | unknown | unavailable
    fn subscribe(&self) -> tokio::sync::watch::Receiver<LockState>;
}
#[async_trait] pub trait ConnectionControl: Send + Sync {
    async fn start_master(&self, binding: &BindingId, pair: &AccessPair) -> Result<OwnedConnection, ConnError>;
    async fn close(&self, c: &OwnedConnection, reason: CloseReason) -> Result<(), ConnError>;
}
```

The other additions: `AdapterDescriptor.remote_credential_effect: bool` (U0b row 7);
`RevokeOutcome.remote_effects: Vec<RemoteEffect>` (with `until` and `status`).

**20. Issuer wire protocol `heimdall-issuer/1`** (internal; ADR-0008 D3 item 3). It is not a public
schema. A golden fixes the message set; frames are at most 64 KiB; and the `IssuerRefusal` variants are
the `IssuanceRefusal` and `VerificationRefusal` sets plus `entry_not_reserved`, `entry_stale`,
`subject_mismatch`, `ceiling_exceeded`, `ca_not_loaded` and `rate_limited`.

**21. The remote protocol** (internal; ADR-0008 D5 §6.3):
* HM1 keys: `v`, `path_hex`, `dir`, `dir_mode`, `dir_owner_self`, `file`, `links`, `mode`, `owner_self`,
  `size`, `last_byte_newline`, `marker_lines`, `content_hex`, `status`, `reason`;
* exit codes: 0, 10, 20, 30, 31; and 255 from ssh itself;
* golden scripts in `tests/contracts/golden/enroll-scripts/`.

**22. Configuration:** no new key. `FORBIDDEN_KEYS` gains `lock_behavior` and `registry_path` under
`[x]`: authority stays out of configuration (spec §13.4).

**23. New public schemas:** `enrollment-plan.schema.json`, `enrollment-result.schema.json`,
`issuer-status.schema.json` and `recovery-bundle.schema.json`. The `ensure-data`, `revoke-data` and
`inspect` schemas are regenerated.

**24. CLI** (`cli.rs`; handlers per U12):

| Command | Request | Notes |
|---|---|---|
| `heimdall issuer init --backup-out <path>` | Issuer::Register (+ decision) | TTY only; ceremony D4 |
| `heimdall issuer status [--json]` | Issuer::Status | |
| `heimdall issuer unlock` | Issuer::Unlock | attended |
| `heimdall issuer rotate begin --backup-out <path>` | Issuer::Register{rotation_of} | ceremony |
| `heimdall issuer retire <fingerprint>` | Issuer::Retire | decision |
| `heimdall issuer restore --backup <file> [--not-stolen]` | Issuer::Register{restored_without_log?} | ceremony; passphrase typed |
| `heimdall issuer bundle --out <path> [--redact hostnames]` | Issuer::Bundle | writes the file |
| `heimdall enroll <destination> [--account A] [--form account\|system] [--registry-path P] [--ca F]` | Enrollment::Preview, then Apply | the preview is shown first; `--yes` never skips the decision |
| `heimdall enroll status [--json]` | inspect enrollments | |
| `heimdall enroll verify <enrollment>` | Enrollment::Verify | |
| `heimdall enroll remove <enrollment>` / `--from-bundle F --marker M` | Enrollment::Remove | decision |
| `heimdall enroll reconcile <operation>` | Enrollment::Reconcile | |
| `heimdall enroll abandon <enrollment>` | Enrollment::Abandon | typed confirmation |
| `heimdall destination prefer <alias> managed\|existing` | Catalog `SetPreference` (§5 item 4b) | then `setup apply` |
| `heimdall access ensure … --strict` | EnsureRequest.connection | |
| `heimdall access lock-behavior --policy P continue\|revoke-on-lock` | Policy::SetLockBehavior | |
| `heimdall access connection-policy --policy P [--existing graceful\|strict] [--multiplexing disabled\|owned]` | Policy::SetConnectionPolicy | |
| `heimdall connections [--json]`, `heimdall connections close <id>` | inspect connections; `Connections::Close` (§5 item 4a) | `close` never signals an unverified process |
| `heimdall internal issuer`, `heimdall internal session-lock-state` | — | hidden; the first refuses a TTY stdin; the second is read-only |

Exit codes are unchanged (ADR-0006 §6).

---

## 6. Questions for the orchestrator

### 6.1 Authority semantics and contract (ADR-0008 §17; full rationale there)

Units build against the recommended answers.

| # | Question | Recommended answer |
|---|---|---|
| Q1 | Is the issuer endpoint path bound at all? ADR-0006 §2.1 says it is "fixed now" | **No.** `EndpointKind::Issuer` and its path stay reserved and never bound. The issuer is a child reached only through inherited stdin/stdout pipes (ADR-0008 D3) |
| Q2 | Does the issuer re-check the reservation in the store, or sign what it is sent? | **It signs by reservation ID**, with a read-only store re-check and the pure predicate re-run in the child |
| Q3 | Does the signer run in its own process? | **No: in the runtime process**, with per-signature authorization against the store |
| Q4 | Is Recipe A (K_A) delivered in M03? | **No.** `deferred_with_decision` to M04, together with F-5's inventory. A failed B1 verification rolls the line back (`verification_failed`) |
| Q5 | Can one grant mix existing-access and managed pairs? | **Not in M03** (`mixed_mechanisms` stays). Mixed grants go to M05 |
| Q6 | Which enrollment steps need an attended owner decision? | `EnrollAccount` per (pair, CA) and `RemoveEnrollment`. Re-verification needs none |
| Q7 | May an approved append be re-run after reconcile finds it not applied? | **Yes**, within 24 h of approval, with the same CA and host key. Otherwise `DECISION_STALE` (`approval_lapsed`) |
| Q8 | May the append create `~/.ssh` when it is absent? | **Yes** (`mkdir -m 0700`), refining ADR-0005 §3.3 |
| Q9 | Where does lock-revokes live, and what does a lock do? | On the standing policy and in owner decisions, merged fail-closed. A lock is a real revocation (cause `session_locked`), and unlock restores nothing. `unknown` means locked. It is refused where no signal exists, and returning to `continue` is widening |
| Q10 | What does `strict` close, and what do owned masters do at the deadline? | Owned dedicated connections only (the holder is the verified `ssh`). `run` of other programs reports `not_controlled`. Masters close at the deadline under both policies. `owned_masters` is widening, and unsupported on Windows |
| Q11 | How long is a positive and negative verification fresh? | **90 days** (a proposal). After that scope reports `unknown` until `enroll verify` |
| Q12 | May B1 revocation obligations clear without adapter rounds? | **Yes**, through the time-bounded `bounded_by_expiry {until}` obligations, on safe time only. `needs_remote_action` obligations are unchanged |
| Q13 | Is synchronized time trusted in M03? | **No.** Observation only. Post-reboot managed issuance waits for an attended `time confirm` until M04/G09 evidence |
| Q14 | Where do `verified` platform capability values come from? | **Only from the claim table**, validated by `check.sh` and populated after verified native records |
| Q15 | Can several managed bindings for one pair share ordinary aliases in one environment? | **No:** one materialized binding per pair per environment for ordinary aliases and `run`. Others through `connect` and per-binding endpoints until G05/M05 |
| Q16 | What does a K_ca restore require? | `--not-stolen`. A key-only restore reports `unbounded_unknown`, and rotation is recommended |
| Q17 | Who runs the existing-access `ssh` of an enrollment step? | **The owner's CLI process** (client-executed steps). The runtime journals each step first and classifies the result; the claim rests only on the runtime's own verification |

### 6.2 Plan-level questions (not authority semantics)

* **P1. The unit split:** fifteen units, with U0b in two phases (wave 0 fail-closed; wave 4 activation)
  as in M02. **Recommended: yes.** Only the integrator touches existing M01/M02 dispatch, store and
  revocation code.
* **P2. Three new crates** (`heimdall-credential`, `heimdall-issuer`, `heimdall-enroll`).
  **Recommended: yes.**
  * The issuer's store FFI and the signer's memory FFI each get one small `unsafe` module, in a crate
    whose other code is safe.
  * The child process links only what it needs.
  * *Alternative:* fold them into `heimdall-adapters`. That would mix three `unsafe` surfaces with the
    M02 adapters.
* **P3. Linux D-Bus clients:** `zbus` (shared by the Secret Service client and logind), pinned,
  `cfg(target_os = "linux")` only. **Recommended: yes.**
  * *Alternative:* shelling out to `secret-tool` and `busctl monitor`. That brings stdout parsing,
    polling for lock events, and no DH session control.
  * The dependency weight is recorded in `dependencies.md`, and the devbox build time is measured.
* **P4. The WSL rootfs.** M02's exit draft §4 left the disposable distribution waiting on
  `HM_WSL_ROOTFS`, or on authorization for `HM_WSL_DOWNLOAD=1`. **Recommended: authorize the download**
  of the pinned Ubuntu 24.04 WSL image, verified by its published SHA-256 and kept in the run's scratch.
  * *Why:* ADR-0004 §3 already authorizes creating and unregistering a disposable distribution. A
    download into scratch changes nothing on the PC, and M03's default-registry-path, StrictModes and
    "ordinary ssh without `-F`" rows depend on it.
  * This is the orchestrator's decision, not an owner-only input.
* **P5. The macOS lock trigger** (§4.4). Use `pmset displaysleepnow` only, and **never change** the
  host's password-after-sleep setting. If it does not produce a verified lock, the row is `blocked`
  (`lock_not_verified`). **Recommended: yes.** The alternative, synthetic keystrokes, needs an
  accessibility grant (a TCC change).
* **P6. Lock runs are separate invocations bound to the exit commit** (§4.4), run when the console is
  idle, with the post-unlock checks completed when the owner returns. **Recommended: yes.** The exit
  record can then show `in_progress` for those rows while the rest is final.
* **P7. The limits in §5 item 17** as proposals, tunable in M08 with evidence (the M02 P12 pattern).
  **Recommended: yes.**
* **P8. The evidence generator.** `tests/native/m03/m03-evidence.py` imports the M02 generator's record
  and index helpers rather than copying them. It moves them into `tests/native/lib/` once, without
  behaviour change, under M02's self-tests. **Recommended: yes**, but only after M02 exits ⟨M02?⟩ M8.
* **P9. The design review.** One independent review of ADR-0008 and this plan before wave 0. The
  reviewer gets ADR-0005, ADR-0006, ADR-0007 §13, the code at the base and this plan, and does not see
  the author's own assessment. **Recommended: yes**, with the M02 practice that a fix round precedes
  each re-review.

---

## 7. Items blocked on owner-only inputs

Each item names the exact input. Work that does not need it proceeds, and the rows that need it stay
`blocked` (AGENTS.md). B1–B10 carry over from M02 (m02-plan §7; ADR-0004 §2–§3), and B11–B13 are new.

| ID | Missing input | Blocks in M03 |
|---|---|---|
| B1 | A **disposable 1Password account** with disposable SSH keys | A03's 1Password-vault row (lock the vault, managed logins continue); enrollment through 1Password as the source provider; the M02 A11/A35 1Password rows (carried) |
| B2 | **The disposable second Windows account** (one elevation consent) | cross-user refusal for the environment, per-binding and verification pipes; DPAPI cross-user unprotect refusal; Windows ordinary ssh without `-F` |
| B3 | **A disposable macOS standard user account** (admin consent to create and delete it) | the **macOS K_ca product-store row** (login keychain item: written at init, read at issuer start, during lock, after login, ACL behaviour across ad-hoc-signed updates); macOS ordinary ssh without `-F`; macOS cross-user endpoint refusal; with B12, the macOS logout row |
| B4 | **A disposable Windows host** whose system `ssh-agent` may hold test keys | enrollment through the Windows system agent as the source provider; A03's Windows real-agent vault row |
| B5 | **An operator at the Windows console** | the "no UAC or credential prompt during `issuer init` and enrollment" human observation. The lock rows do **not** need it (ADR-0004 §2 lock rule) |
| B6 | **A hardware security key** (FIDO2) | enrollment through a touch-required existing identity (the provider-interaction path of D5 §6.10); the M02 A11 touch row (carried) |
| B7 | **The owner as participant** | the human walkthrough of "allow background work once without routine unlocks"; observations for R-UX-03's disclosure (A30 itself is M09) |
| B8 | **Owner authorization for Docker or a disposable local user on the Linux devbox** | nothing in the exit, because WSL and loopback cover it. The explicit gaps: the devbox default-registry-path row and devbox cross-user endpoint checks |
| B9 | **A native Linux arm64 host** | every arm64 row (Docker on the build host is supplementary only) |
| B10 | Windows Developer Mode or one elevation | nothing new in M03 (carried for M02's A22 row) |
| **B11** | **A Linux desktop host**: Ubuntu 24.04 or Debian 13 with GNOME, gnome-keyring and systemd-logind, plus a disposable account | the Linux K_ca product-store row (Secret Service over DH, availability at login); P-L1 (Linux screen lock: signer, issuer, fresh logins); the logind lock signal and the Linux lock-revokes row; A03's Linux desktop row |
| **B12** | **An operator for logout, reboot and sleep cycles** on macOS and Windows (and on B11's host). ADR-0004 §2 keeps these blocked on the owner, because they end running applications | ADR-0005 §9.3 P2, P3, P4, P-W2 and P-L2; native sleep across a deadline; re-issue after logout and after reboot (R4); the synchronized-time behaviour after a real reboot |
| **B13** | **Apple Developer membership** (G04 D3; ADR-0002 Q-F) | the data-protection keychain row (P6); Secure Enclave persistent keys; the signed bundle |

Rows blocked on these inputs are listed by ID in each record's `blocked_on`, and summarized in the M03
exit draft.

---

## 8. Handed to later milestones

| Item | Milestone | Status in M03 |
|---|---|---|
| Recipe A (K_A per pair; CNG Software KSP or TPM; keychain or Secret Service persistent stores) with the G01 F-5 inventory | M04 | `deferred_with_decision` (ADR-0008 Q4) |
| Hardware K_env (ephemeral Secure Enclave, per-grant TPM) after the P1 and P-W1 hardware rows | M04 | deferred (ADR-0008 D1) |
| WSL Mode B with Windows-held managed keys (G03 B2), and container binding of a managed endpoint (spec §8.5) | M04 | not started |
| Bastion `ProxyJump` in P, `permit-port-forwarding`, enrollment and verification through jump routes (`route_unsupported` until then) | M04 | refused in M03 |
| Runtime start at login (login item, launchd agent, systemd user unit, Run key), so re-issue happens at login without a command | M04-T04 | on demand in M03 (`conditions: signer_running`) |
| Native sleep, logout and reboot rows; trust in synchronized-time signals; the Windows boot-ID source evidence | M04-T04, G09 | blocked (B12) or observation only (Q13) |
| Windows handle-list hygiene for the issuer child (the inheritable-handle residual, ADR-0006 §13.9) | M04 | disclosed |
| Mixed existing/managed grants (per-pair adapters, weakest-value summary, ADR-0005 §7.1) | M05 | refused (`mixed_mechanisms`) |
| Concurrent distinct bound contexts per pair (G05 binding strategy) | M05 | one materialized binding per pair (Q15) |
| Automatic activation on first ordinary `ssh` under a standing personal policy | M05-T02 | explicit `ensure` in M03 |
| A28 narrow-delegation demonstration (server-side attenuation evidence for children) | M05 | child keys implemented; cascade tested (A07) |
| Remote runner issuance over pairing, the authenticated time exchange, `credential_only`, A24, and A07's runner variant | M06 (G07) | `deferred_with_decision` |
| The guided lost-device flow over the recovery bundle and foreign removal | M07 | primitives delivered |
| One combined UX for enrollment plus the projection decision | M07 | two decisions in M03 |
| The three Git residuals of ADR-0007 §12.41 | M07 | re-deferred with a decision: they do not interact with managed credentials |
| Fuzzing of the HM1 parser, the issuer protocol, the userauth purpose parser and the session-bind parser; support bundles; update artifacts in A33 | M08 | bounded parsers and adversarial tests in M03 |
| The macOS signed bundle and data-protection keychain migration (ADR-0005 §12 "When D3 ships") | when B13 arrives | blocked |
| Capability-3 automation (editing `sshd_config` and principals files), KRL revocation by serial, destination restriction through session-bind (`authenticated_agent_restriction`), `log_attestation`, a separate-account issuer, logout-revokes, short renewed certificates | later, each through its own ADR | not planned for V1 unless a gate reopens (ADR-0005 §13) |
