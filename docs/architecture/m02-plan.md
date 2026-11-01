# M02 work breakdown (existing-access vertical slice): revision 3

**Inputs:**

* plan §5 M02 (T01–T06, exit evidence), §4.4, §6;
* spec §5.2, §5.4, §7.2, §8.4, §10, §11.3, §11.6, §12, §13.5, §14.3, §17
  A01/A11/A21/A22/A27/A35, and the requirements those cases cite (R-UX-01, R-UX-04,
  R-CR-01, R-CR-08, R-SS-01–04, R-AP-06, R-RT-04, R-RT-05, R-SE-04, R-DI-06);
* `docs/decisions/0007-existing-access-integration.md` revision 3 (this plan's design ADR);
* `tests/evidence/artifacts/review-m02-design/review.md` (the independent review) and the
  rulings on it in ADR-0007 §12.2;
* ⟨r3⟩ `tests/evidence/artifacts/review-m02-design/round2.md` (the second review) and the
  rulings on it in ADR-0007 §12.5;
* ADR-0006 revision 2.15 (the G08 baseline, through §13.18), which this plan extends with
  the revision-3 deltas in §5;
* ADR-0004 (E-3, E6, Q-B and the blocked inputs in §3), ADR-0002 §3.1, §5, §6;
* `docs/research/g03-windows-wsl.md`;
* `tests/fixtures/MANIFEST.md`;
* `docs/architecture/{overview,m01-plan,dependencies}.md`.

**Revision 2 (task M02-T00-design-fix)** applies findings M2-D01–M2-D10 under ADR-0007
§12.2. Changed text is marked **⟨r2⟩**, and §9 maps each finding to its changes. The units
grow from twelve to thirteen: **U0b** makes the changes to existing M01 code explicit
integrator work (M2-D08). Revision 2 was reviewed independently (`round2.md`).

**Revision 3 (task M02-T00-design-fix-2)** applies findings M2-R01–M2-R08 and the QR3
wording ruling under ADR-0007 §12.5. Changed text is marked **⟨r3⟩**, and §9.1 maps each
finding to its changes. The unit count stays at thirteen. U0b is now delivered in two
phases, like U8:
* **phase 1, wave 0, with U0:** every change, with the new requests failing closed, plus
  the M02 store bodies;
* **phase 2, wave 3:** the activation change set, landed with U5's drivers.

Revision 3 has not had an independent review.

**Status discipline (M01 rule E15 carried over):** every unit stays `implemented_unverified`
until U11's evidence records exist, whatever its local tests say.

**Skeleton rule (as in M01):** U0 creates every type, trait and function named below. Bodies
are `todo!("M02-Uxx …")` where not yet implemented. A unit replaces the bodies it owns and
adds tests. Shared signatures, tables and limits change only through the integrator, with an
ADR-0006 or ADR-0007 revision. ⟨r2⟩ Exception: no `todo!()` is added to an M01 dispatch path
that a client request can reach. Those changes are U0b's, and they land complete. ⟨r3⟩
Stated fully (M2-R07; ADR-0007 §12.5 item 7): **no `todo!()` is reachable** from any of:
* a request, through the session or the dispatcher;
* a CLI command;
* restart recovery;
* any store method that U0b's code calls.

Code that its driver has not yet replaced **fails closed** instead:
* requests: `CAPABILITY_UNAVAILABLE`, reason `driver_unavailable`, before any record is
  written;
* restart: the operation stays unresolved and untouched;
* decisions of the new kinds: refused, not consumed;
* CLI: M01's "not available in this build" envelope.

The wave-0 acceptance tests in U0b prove each of these.

**Not decided by this plan:** the open questions in ADR-0007 §12.3 (QR1–QR6, since ruled),
⟨r3⟩ §12.6 (QR7–QR11) and the plan-level questions in §6. Where a unit depends on an answer, the unit says so. The
recommended answer is the default it builds against, and the integrator flips the switch if
the ruling differs.

## 0. Ground rules for every unit

**Ownership and test targets**

* Write only inside the owner paths below, plus the unit's own test files. These files change
  only through the integrator:
  * `Cargo.toml`, `Cargo.lock`, `clippy.toml`;
  * `crates/contract/**`, `crates/domain/**`;
  * `crates/app/src/{ports,context,ensure,lib,operations,events,error}.rs` ⟨r2⟩ (U0b owns
    the M02 changes to `operations.rs`, `events.rs` and `error.rs`);
  * `crates/store/migrations/**` and the `Txn` signatures, ⟨r3⟩ and the store bodies in
    `crates/store/src/{ext,ext_m02}.rs` (U0b);
  * ⟨r3⟩ the `Request::Setup`/`Request::Catalog` arms in `crates/runtime/src/dispatch.rs`
    and the capability list in `crates/ipc/src/session.rs` (U0b);
  * `crates/heimdall/src/cli.rs` (the clap tree);
  * ⟨r2⟩ the shared test fakes: `crates/testkit/src/lib.rs` (`FakeCredentialAdapter`) and
    `crates/heimdall/src/testcfg.rs`;
  * ADR-0006, ADR-0007, this file.
* Test targets follow the M01 convention (m01-plan §0, review F09). Every suite is a real
  `[[test]]` with `path = "../../tests/<layer>/<name>.rs"`, hosted by the crate that already
  has the dependency edges. There is no `#[path]` inclusion, and `check.sh` fails a target
  that runs 0 tests.

**Fixtures and the owner's material** ⟨r2⟩ (ADR-0007 §9; M2-D09)

* Tests never touch the owner's real material:
  * never read or write `~/.ssh`, the owner's Git configuration, or `~/.gitconfig`. Git
    tests run with a scratch `HOME`, `GIT_CONFIG_NOSYSTEM=1` or a scratch
    `GIT_CONFIG_SYSTEM`, and `GIT_CONFIG_GLOBAL` unset or pointing into scratch;
  * never use the owner's agents: `SSH_AUTH_SOCK` points at a scratch **decoy counting
    agent**;
  * never open `\\.\pipe\openssh-ssh-agent` or a 1Password socket.
* Product code under test receives the user-configuration path through the env-gated test
  configuration (M01 `testcfg` pattern; never compiled into release builds).
* **Isolation is not configuration.** Every client a test runs gets only isolation on its
  command line: `-F <scratch user config>`, `-o UserKnownHostsFile=<scratch>`, `-o
  GlobalKnownHostsFile=<scratch empty file>`, and `-o BatchMode=yes` where non-interactive
  (`testkit::home::ScratchHome::isolation_args`). Never `IdentityAgent`, `IdentityFile`,
  `IdentitiesOnly`, `HostName`, `User` or `Port`: command-line values win (ADR-0007 F1).
* **Default-identity guard.** `ScratchHome::client_command` evaluates the alias under test
  statically. It refuses (`FixtureUnsafe`) unless the alias's identity list is non-empty and
  every entry is a scratch path, because ssh's default identity files come from the account
  home (ADR-0007 F19, F20).
* **Agents** are:
  * `testkit::agent::DisposableSshAgent`: `ssh-agent -D -a <scratch>/agent.sock` with
    `HOME=<scratch home>`, so its default socket directory and its stale-socket cleanup stay
    in scratch (ADR-0007 F21), stopped by exact PID;
  * `testkit::agent::CountingProxy`, a counting socket in front of a real agent;
  * `testkit::agent::FakeAgent` (U7).

  Keys are generated per run and never committed. Synthetic public keys (for example a FIDO
  `sk-` public key) may be committed as public fixtures, stated in the file header.
* SSH servers run only as `testkit::sshd::LoopbackSshd` (non-root `sshd -D`, `127.0.0.1`,
  ephemeral port, per-run host and user keys, `PerSourcePenalties no` as in MANIFEST row 1),
  or as the M00-T03 Docker fixtures published on `127.0.0.1`. There are no other listeners
  (AGENTS.md).
* Canaries: `HEIMDALL_CANARY_*` private-key canaries and fake-agent canaries are checked with
  `testkit::assert_no_canary` over every envelope, event, log line, error, doctor report,
  rendered file, run record and side-channel line (ADR-0004 §4). ⟨r2⟩ An argument canary and
  a `core.sshCommand` value canary are checked the same way.

**Tests and evidence**

* Property tests use proptest: at least 256 cases, a fixed default seed, committed
  `proptest-regressions/`, and `PROPTEST_RNG_SEED` reproduces a run.
* Platform-only tests are `#[cfg]`-gated and listed in the case index as `platform_only`.
  A platform that is missing makes a row `blocked`, with the platform named exactly.
* ⟨r2⟩ A test that settles an ADR-0007 `[I]` or `[U]` fact records its observation in its
  evidence record. Until it passes on a target, the fact stays `[I]` for that target.

**Build and handoff**

* Build hygiene follows AGENTS.md:
  * one `./target`, with no `CARGO_TARGET_DIR` or `--target-dir`;
  * remove cross-built `target/x86_64-*` and `target/aarch64-unknown-linux-*` after native
    runs;
  * `rm -rf` only the scratch directories you created, never by glob;
  * run the `du -sh` check before finishing.
* Before handing off, every unit runs `bash tools/validation/check.sh` and records the exit
  codes and test counts.

## 1. Units

### U0: Integrator skeleton and contract revision 3

* **Owner:** the integrator.
* **Owner paths:**
  * root `Cargo.toml` and `Cargo.lock`;
  * the new crate manifests and skeleton `lib.rs` files for `crates/{sshconf,localenv,adapters,launch}`;
  * `crates/contract/**` (§5 deltas);
  * the new domain types: `crates/domain/src/{catalog,projection,holder}.rs`, the new
    variants and types in `crates/domain/src/{decision,operation,resource}.rs` (§5 item 17);
  * `crates/app/src/ports.rs` (new ports and the `PrepareRequest`/`PrepareOutcome` fields);
  * migration `crates/store/migrations/0005_existing_access.sql`, with `SCHEMA_VERSION` 5 and
    the `Txn` signatures;
  * the `crates/heimdall/src/cli.rs` clap tree for every M02 command, with handlers in
    per-command files. ⟨r3⟩ Until its unit lands, each handler returns M01's "not
    available in this build" envelope, as M01 does today for `setup`, `connect`, `run`,
    `doctor` and `tui`. No handler calls `todo!()`, and none contacts the runtime;
  * `schemas/public-api/**` (regenerated);
  * `docs/architecture/{overview,dependencies}.md`;
  * `docs/sources/**`, for the 1Password excerpts below only;
  * ADR-0006 revision 3.
* **Does:**
  * applies §5 after the Q1–Q8 rulings and the QR1–QR6 answers;
  * records the new dependencies (dependency note below);
  * extends overview §1 with the four crates and overview §9 with the third `unsafe`
    module, `crates/localenv/src/sys.rs` (ADR-0007 §13);
  * moves the code golden table from 29 to 30 rows (`LAUNCH_FAILED`);
  * adds to `docs/sources` the pinned excerpts for the 1Password agent socket paths and the
    `agent.toml` location, from the agent/config and get-started pages that G03-S12 already
    pins by hash. U6 hardcodes no 1Password path until these exist (ADR-0007 §7). Until
    then, detection uses `SSH_AUTH_SOCK` and IdentityAgent references in the configuration
    only;
  * lands **together with U0b** ⟨r3⟩ phase 1 as one integrator change set, because the new
    `OperationKind`, `DecisionKind`, `Request` and `InspectSubject` variants break M01's
    exhaustive matches until U0b handles them.
* ⟨r3⟩ **Frozen in wave 0** (M2-R07; ADR-0007 §12.5 item 7). Later units build on these
  and do not change them without an ADR-0007 revision:
  * the typed local receipt payload `StageReceipt.local: Option<LocalReceipt>`: its
    serialization, defaults for old rows, migration behaviour and unknown-content rule
    (§5 item 17a);
  * the approval representations, one per decision kind: `ProjectionApproval` in
    `SetupIntent`, `DeclarationApproval` in `CatalogIntent` (§5 item 17). `LocalApproval`
    is withdrawn;
  * `RecoveryIntent.local` and its add-only rule (§5 item 17; U0b row 16);
  * the fail-closed landing (§5 item 4; U0b phase 1);
  * the journaled-kind mapping (test below) and the documented mapping of `Probe`;
  * the `replace` primitive and quarantine interface, `ProjectionWriter`, `StageSink` and
    the receipt phases that U4 writes (U4 interfaces; §5 item 15).
* **Dependency note:**
  * the `glob` crate (Include globbing, bytewise order);
  * ratatui 0.30.2 and crossterm 0.29.0 enter the lock;
  * tokio feature `process`;
  * windows-sys features `Win32_System_JobObjects`, `Win32_System_Console`,
    `Win32_UI_Shell` (profile folder) and the existing `Win32_Storage_FileSystem`
    (`ReplaceFileW`, `GetFileInformationByHandleEx`, `SetFileInformationByHandle`);
  * ⟨r2⟩ the atomic exchange and no-replace renames (Linux `renameat2`, macOS
    `renameatx_np`): through a reviewed safe wrapper if one at the pinned version provides
    both (for example rustix `fs` `renameat_with`, which would then become a normal, not
    dev-only, dependency of `heimdall-localenv`), otherwise through `sys.rs` FFI (P5, §6);
  * dev-only: `rustix` (`pty`, `termios`, `process`) for pty tests, and the `ssh-key`
    feature `ed25519` in `heimdall-testkit` for `FakeAgent` signing;
  * each gets a reason, licence and rejected alternatives in `dependencies.md`.
* **Tests:**
  * contract goldens (30 codes);
  * schema export byte-identical;
  * the new examples (`schemas/examples/{request.setup.*,request.catalog.*,doctor-report,run-record.*,setup-plan.*}.json`)
    round-trip exactly;
  * `BindForm::Launch` without `argv` (Q8);
  * ⟨r3⟩ `journaled_operation_kinds_match_their_request_kind`, which replaces revision 2's
    `operation_kind_as_str_equals_request_kind`. Revision 2's version also covered
    `Decide` and `ConfirmTime`, which have no `OperationKind`, and `Probe`, which has no
    request (M2-R07). The rescoped test checks four things:
    * for each **journaled** kind, a request example satisfies `is_effectful()` and
      `kind.as_str() == request.kind()`. The journaled kinds are those the application
      admits as an operation row: `Ensure`, `Delegate`, `Bind` and `Revoke` (M01), plus
      `SetupApply` (`"setup.apply"`), `SetupRollback`, `SetupRepair` and `Catalog`
      (`"catalog"`, every action);
    * the effectful but not journaled requests are listed explicitly: `Cancel`,
      `Release`, `Policy`, `Decide` and `ConfirmTime`. They settle synchronously under
      ADR-0006 §7 idempotency, with no operation row. The non-effectful ones are
      `Inspect`, `Observe`, `Shutdown` and `Setup(Preview)`. The helper matches `Request`
      without a wildcard, so a new variant fails to compile until it is classified;
    * `OperationKind::{Cancel, Release, Policy}` are declared and never constructed;
    * **`Probe` is documented as reserved.** There is no `Request` variant for it, and it
      is never journaled in M02: explicit probes run in the doctor or CLI process, which
      never starts the runtime (ADR-0007 §6). `as_str() == "probe"` is reserved, and the
      test asserts that no `Request::kind()` returns `"probe"`;
  * ⟨r2⟩ `run_record_classify_golden`: every row of ADR-0007 §8's reader table;
  * ⟨r2⟩ `decision_kind_wire_forms` for `ApplyProjection` and `DeclareInteraction`;
  * ⟨r3⟩ `local_receipt_wire_forms`: one golden JSON per `FilePhase` and `ItemPhase`
    variant, round-tripped exactly. A receipt without `local` decodes to `None` and
    re-encodes byte-identically, and an unknown phase fails to decode;
  * ⟨r3⟩ `approval_wire_forms`: `ProjectionApproval` and `DeclarationApproval` goldens.
    A `SetupIntent` carrying a declaration approval, or the reverse, does not decode;
  * migration 0004→0005 on a populated database, ⟨r3⟩ with M01 `stage_receipts` and
    `recovery_intents` rows decoding unchanged and re-encoding byte-identically;
  * a newer `user_version` is refused.

### U0b ⟨r2⟩: M01 integration (existing code that M02 must change)

* **Owner:** the integrator (ADR-0007 §12.2 item 8). No other unit edits these items.
* **Timing:**
  * Starts after the concurrent M01 work on `crates/app/src/operations.rs` and
    `crates/domain/src/revocation.rs` has been committed.
  * References below are to function and type names, because line numbers in
    `operations.rs` move.
  * ⟨r3⟩ **Two phases** (M2-R07; ADR-0007 §12.5 item 7):
    * **Phase 1** lands with U0 in wave 0. It contains every row below. The new requests,
      the new decision kinds and the new operation kinds **fail closed** (rows 1, 10, 17,
      18). Phase 1 also implements the M02 store bodies (row 20), so that no store method
      its code calls is a `todo!()`.
    * **Phase 2 is the activation change set.** It lands in wave 3 together with U5's
      drivers, and the integrator integrates both as one change. It completes rows 1 and
      10, offers `setup/1` (row 19), and replaces the wave-0 acceptance tests that no
      longer hold. The dispatch-level refusal stays for a runtime without a
      `ProjectionWriter`.
* **Owner paths:**
  * the items below in `crates/app/src/{operations,events,error}.rs` and
    `crates/domain/src/operation.rs`;
  * ⟨r3⟩ the entry points `crates/app/src/{setup,catalog}.rs`, with fail-closed bodies in
    phase 1 (U5 replaces the bodies in wave 3);
  * ⟨r3⟩ the two new arms in `crates/runtime/src/dispatch.rs` (`Request::Setup`,
    `Request::Catalog`), which route to those entry points;
  * ⟨r3⟩ `intent_update_allowed` in `crates/store/src/ext.rs`, and the whole of
    `crates/store/src/ext_m02.rs`: the bodies of the U0 `Txn` signatures and
    `Store::open_read_only`. In revision 2 these were U5's;
  * ⟨r3⟩ in phase 2, `ipc::session::server_capabilities()` and the `inspect capabilities`
    list;
  * ⟨r3⟩ the bodies of `heimdall_domain::catalog::{eligibility, fallback_clearance}`
    (U0 declares them; row 22);
  * the shared fakes `crates/testkit/src/lib.rs` (`FakeCredentialAdapter`, its
    `PrepareOutcome` values) and `crates/heimdall/src/testcfg.rs` (its fake `PrepareOutcome`);
  * `tests/model/m02_integration.rs` (hosted by `heimdall-runtime`), ⟨r3⟩
    `tests/integration/store_m02.rs` (hosted by `heimdall-testkit`, moved from U5) and
    `tests/e2e/wave0_fail_closed.rs` (hosted by `heimdall-runtime`).
* **Exact changes:**

| # | Function or type (M01) | Today | M02 change |
|---|---|---|---|
| 1 | `Operations::decide` (operations.rs): the `let waiting = match &d.kind` computation and the `match (&record.kind, verdict)` application | handles `ApproveAuthority`, `WidenPolicy`, `ConfirmTime` | adds `ApplyProjection { operation, .. }` and `DeclareInteraction { operation, .. }`. ⟨r3⟩ **Phase 1:** both are refused with `CAPABILITY_UNAVAILABLE` (reason `driver_unavailable`); the record stays pending and the operation is untouched. **Phase 2:** the waiting operation must be `AwaitingApproval` (else `DECISION_STALE`); no A06 delta check (they carry no `AuthorityDelta`); generation check unchanged. ⟨r3⟩ The approval written depends on the decision kind (§5 item 17): `ApplyProjection` needs `LocalIntent::Setup` with an equal `plan_digest` and sets `SetupIntent.approval = Some(ProjectionApproval { decision, plan_digest })`; `DeclareInteraction` needs `LocalIntent::Catalog` for a `DeclareInteraction` action on the same identity and sets `CatalogIntent.approval = Some(DeclarationApproval { … })`, copied from the record's fields. A kind/intent mismatch, or a differing digest or identity, is `DECISION_STALE` with nothing applied. Then `op_to(Approved)` and resume with `lead_all_bounded`. **Deny:** `settle_failed` with `CAPABILITY_UNAVAILABLE` ("the owner denied the projection change" / "the declaration"); no file is touched |
| 2 | `decision_view` (operations.rs) and `events::decision_kind_name` (events.rs) | three kinds | the two new kinds; the view shows `plan_digest`, the summary counts, `diff_text` and the restore column (bounded, ADR-0006 §3.1) |
| 3 | `Operations::bind` | `if let BindForm::Launch { argv }` checks non-empty and `MAX_ARGV_BYTES`; hash extra `{ binding_id, form }` | validates `LaunchBinding`: `executable` absolute, 1–4096 bytes, no NUL; `holder.pid > 0`; `holder.started_at` 1–64 bytes `[A-Za-z0-9._:-]`. Hash extra `{ binding_id, form: "launch", executable }` or `{ binding_id, form: "materialize" }`; `holder` is excluded (delivery metadata). `MAX_ARGV_BYTES` leaves the contract and becomes a `heimdall-launch` constant |
| 4 | `Operations::drive_bind` | `ensure_data(&b, &g, &Facts::conservative(&g, now), bound)` | `Facts::conservative(&g, tx.grant_prepared_facts(&g.id)?.as_ref(), now)`, ⟨r3⟩ followed by `Facts::with_eligibility(tx, now)` (row 5) in the same transaction; in the settling transaction, `tx.set_binding_holder(&b.id, &holder)` when a holder is given |
| 5 | `struct Facts`, `Facts::from_outcome`, `Facts::from_data`, `Facts::conservative`, `fn ensure_data` | four fields; `ensure_data` builds `ConsumerIntegration { signing_endpoint: None, ssh_config_include: None, environment: Vec::new() }` | `Facts` gains `provider` and `integration`. `from_outcome` copies them from `PrepareOutcome`; `from_data` copies `EnsureData.{provider, consumer}`; `conservative` takes the stored `PreparedFacts` and, without them, reports an empty integration and no time claim beyond `now`. ⟨r3⟩ **History and eligibility are separate (M2-R04).** `PreparedFacts` has no interaction, availability or eligibility field. The new `Facts::with_eligibility(&mut Txn, now)` computes, for every pair, `interaction`, `interaction_basis`, `declared_at`, `declaration`, `noninteractive` and `eligibility_checked_at`, plus the envelope's `credential_availability`. It reads the catalog identity and its live declaration row in **the transaction that builds the result**, using `heimdall_domain::catalog::eligibility`. That function is pure, has a U0 signature and a phase-1 body, and lives in `domain` because `app` cannot depend on `heimdall-adapters`; U6's `state` module calls it too. The rule is ADR-0007 §7's table. It runs for every result: `ensure`, attached (coalesced) bindings, `bind`, restart-rebuilt results, and `inspect identities`. Idempotent replay returns the stored envelope verbatim; the CLI's pre-launch check (U8) covers it. So `ensure`, attach, `bind`, replay and restart report the same **history**, and each fresh result reports **current** eligibility |
| 6 | the prepare stage that writes `EffectReceipt::Confirmed` after `CredentialAdapter::prepare`, and the `ReconcileOutcome::Applied` arm where the activation stage reconciles after a restart | the facts live only in `DriveLocal.prepared` | also `tx.set_grant_prepared_facts(&grant, &PreparedFacts::from(&outcome))`, in the same transaction as the receipt. ⟨r3⟩ `PreparedFacts::from` drops every interaction and eligibility field of the outcome. Facts are nonsecret, so storing them is allowed (spec §7.3) |
| 7 | `select_adapter`, `Operations::stage_resolve` | the first adapter meeting the minimums | when the catalog names identities for the scope's pairs, select the adapter whose mechanism they name (`IdentitySource` → mechanism). Pairs naming two mechanisms → `CAPABILITY_UNAVAILABLE`, reason `mixed_mechanisms` (P6). No catalog identity → the M01 behaviour. Recorded in `ResolvedIntent.adapter` as today. ⟨r3⟩ In wave 0 the catalog can only be filled through the store (tests), so requests always see the M01 behaviour |
| 8 | the `PrepareRequest` construction in the prepare stage | grant, scope, required, interactive, token, now | adds `pairs: &[PreparePair]` from the catalog (destination, account, identity record, managed alias), empty for M01 adapters |
| 9 | `WorkSpec::from_request` and the minimum check beside `select_adapter` | `capabilities`, `destination_scope_at_least`, `offline_until` | `unattended`: met only by an adapter whose `lock_continuity` is `Verified` and whose interaction is `None`; otherwise `CAPABILITY_UNAVAILABLE` (never in M02) |
| 10 | `Operations::drive` | `Ensure | Delegate`, `Revoke`, `Bind`, then `_ => Ok(())` | **exhaustive**, with no wildcard, so a future kind fails to compile instead of being skipped at restart. `Cancel`, `Release`, `Policy` and `Probe` are listed explicitly (never journaled; `Probe` reserved, U0 test). ⟨r3⟩ **Phase 1:** `SetupApply | SetupRollback | SetupRepair | Catalog => self.local_driver_unavailable(id)`. This touches no file and settles nothing. The operation keeps its state and receipts, and the `runtime_lifecycle` event lists it as unresolved with reason `driver_unavailable`, so a build that has the driver can reconcile it later. **Phase 2:** `SetupApply | SetupRollback | SetupRepair => crate::setup::drive(self, id)`, `Catalog => crate::catalog::drive(self, id)` (bodies by U5) |
| 11 | `Operations::recover_after_restart` | leads every open or unresolved operation | loop unchanged; a test asserts that every kind has a driver; the setup driver reconciles from receipts and never re-applies (ADR-0007 §5.7) |
| 12 | `heimdall_domain::operation::RecoveryIntent` | `request`, `resolved` | adds `local: Option<LocalIntent>` (serde default, omitted when absent): `LocalIntent::{Setup(SetupIntent), Catalog(CatalogIntent)}`. ⟨r3⟩ `SetupIntent.approval: Option<ProjectionApproval>` and `CatalogIntent.approval: Option<DeclarationApproval>` (§5 item 17); revision 2's shared `LocalApproval` is withdrawn |
| 13 | `heimdall_domain::operation::OperationKind` and `as_str` | 8 kinds | adds `SetupApply` (`"setup.apply"`), `SetupRollback`, `SetupRepair`, `Catalog`. Effect class `LocalResources` for setup, `Local` for catalog |
| 14 | `crates/app/src/error.rs` | code mapping | `LAUNCH_FAILED`; `ErrorData.reason` passes through |
| 15 | `FakeCredentialAdapter` (testkit) and the `testcfg` fake | five `PrepareOutcome` fields | defaults for the new fields; a configurable integration with two pairs for the tests below. ⟨r3⟩ `testcfg` also gains `HEIMDALL_TEST_CLOCK_OFFSET_S` (a file holding a signed offset, read by the CLI and by the runtime's wall clock; U8's expiry tests) |
| 16 ⟨r3⟩ | `intent_update_allowed` (store/src/ext.rs) | `request` immutable; `resolved` add-only | `local` is add-only as well. `None → Some` is allowed. Once set, its variant and every field except `approval` never change, and `approval` goes `None → Some` once and is never replaced. A `local` and a `resolved` on the same intent are refused (`GenerationConflict`) |
| 17 ⟨r3⟩ | `OperationsDispatcher::dispatch` (runtime/dispatch.rs), the exhaustive `match request` | 11 request arms | `Request::Setup(r) => render(ops.setup(&caller, r).await)` and `Request::Catalog(r) => render(ops.catalog(&caller, r).await)` |
| 18 ⟨r3⟩ | new `Operations::setup(&Caller, SetupRequest)` and `Operations::catalog(&Caller, CatalogRequest)` in `crates/app/src/{setup,catalog}.rs` | — | **Phase 1:** return `CAPABILITY_UNAVAILABLE`, reason `driver_unavailable`, effect `none`, **before** any admission: no idempotency record, operation row, decision, event or file access. U5 replaces the bodies in wave 3. After activation, `setup` keeps this refusal while `OperationsConfig.projection` is `None` |
| 19 ⟨r3⟩ | `ipc::session::server_capabilities()`, `inspect capabilities` | five capabilities | **Phase 1:** unchanged; `setup/1` is not offered. **Phase 2:** both list `setup/1` |
| 20 ⟨r3⟩ | `crates/store/src/ext_m02.rs` | — | every `Txn` method of §5 item 18 and `Store::open_read_only`, with their compare-and-swap rules: projection resources by generation and identity, declarations by revision, `commit_projection_item` as one transaction. Moved from U5, so that rows 4–7 and `inspect identities` call no `todo!()` |
| 21 ⟨r3⟩ | `Operations::inspect`, the `match req.subject` | eight subjects | `InspectSubject::Identities` (catalog identities with fresh eligibility from row 5, and each live declaration's `DeclarationRef`) and `InspectSubject::Projections` (projection resources, read-only). Both are complete in phase 1 and return empty lists while the catalog is empty |
| 22 ⟨r3⟩ | `heimdall_domain::catalog::{eligibility, fallback_clearance}` (new, pure) | — | ADR-0007 §7's eligibility table (M2-R04) and fallback clearance rule (M2-R05). One rule is used by the runtime (rows 5 and 21), the adapters (U6) and the CLI (U8) |

* **Tests, phase 1 (end-to-end through the real `Operations` and a real scratch `Store`):**
  * `u0b_bind_launch_validates_executable_and_excludes_holder_from_hash`: the same
    `request_id` with another holder replays; another executable is `REQUEST_CONFLICT`;
  * `u0b_integration_provider_and_pairs_survive_ensure_attach_bind_replay_restart`,
    ⟨r3⟩ rescoped for R04:
    * setup: a fake adapter returns two pairs, and the catalog and declarations are
      seeded through the store;
    * steps: `ensure`; a second caller coalesces; `bind`; the same request IDs are
      replayed; `Operations` restarts from the same store; `bind` again;
    * assertion: the **history** (`provider`, endpoints, aliases, selections and their
      `observed_at`) is equal and non-empty in every result, and with nothing changed the
      fresh eligibility is equal too;
  * ⟨r3⟩ `u0b_eligibility_is_recomputed_per_result_never_taken_from_prepared_facts`
    (M2-R04). After an `ensure` that reported `interaction: none` (declared), each of the
    following happens before a `bind`, and each variant runs both in-process and after an
    `Operations` restart:
    * the declaration is withdrawn;
    * the clock passes `expires_at` (fake clock);
    * a `listing_missing` lapse is recorded;
    * the identity's endpoint changes.

    In every variant the `bind` result reports `interaction: unknown`,
    `noninteractive.eligible: false` and no `declaration`. A re-declaration then shows a
    new `revision`;
  * ⟨r3⟩ `u0b_prepared_facts_have_no_interaction_field` (a serde golden of `PreparedFacts`);
  * ⟨r3⟩ `domain_eligibility_rule_table` (M2-R04). Live, same endpoint and unexpired
    gives `none`/`declared`. Withdrawn, lapsed, expired (`expires_at == now` included),
    another endpoint, or no declaration gives `unknown`. 1Password and FIDO keep their
    documented kinds whatever the declaration;
  * ⟨r3⟩ `domain_fallback_clearance_rule_table` (M2-R05), with one case each:
    * an agent-backed entry declared `none` at the same endpoint is cleared;
    * an undeclared agent-backed entry, a file-backed entry, an `sk-` entry, an
      undetermined entry and a `.pub`-less entry are uncleared;
    * every entry of an alias without a determined `IdentitiesOnly yes` is uncleared;
    * a declaration at another endpoint is uncleared;
  * `u0b_restart_dispatches_every_operation_kind`, ⟨r3⟩ phase-1 form: one journaled
    operation of each M01 kind in its open state is driven after restart. Each setup and
    catalog kind (seeded through the store) is covered by `w0_*` below;
  * `u0b_mixed_mechanisms_refused_capability_unavailable` (catalog seeded through the
    store);
  * `u0b_unattended_minimum_unknown_is_capability_unavailable`;
  * ⟨r3⟩ `u0b_recovery_intent_local_is_add_only` (row 16);
  * ⟨r3⟩ `integration_store_m02::*` (row 20). The cases cover:
    * the projection resource generation and identity CAS;
    * the declaration revision CAS and `end_interaction_declaration`;
    * `commit_projection_item` writing the receipt, resources, record and consent
      atomically, and leaving nothing behind when the store is injected to fail;
    * prepared facts, holders, and `open_setup_operations`;
    * `open_read_only` refusing a newer schema and never migrating;
  * ⟨r3⟩ **wave-0 acceptance tests** (`tests/e2e/wave0_fail_closed.rs`; M2-R07):
    * `w0_setup_1_is_not_offered`: `server_capabilities()` and `inspect capabilities`
      omit `setup/1`; a hello that *requires* it is rejected with `SCHEMA_UNSUPPORTED`
      (ADR-0006 §2.3);
    * `w0_setup_and_catalog_on_a_session_are_never_dispatched`: over a real session,
      every `SetupRequest` and `CatalogRequest` variant is answered `SCHEMA_UNSUPPORTED`.
      The dispatcher's call count stays 0, and no operation, idempotency, decision or
      event row is written;
    * `w0_setup_and_catalog_at_dispatch_are_capability_unavailable`: through
      `OperationsDispatcher::handle_as` and the `Operations` entry points, every variant is
      answered `CAPABILITY_UNAVAILABLE` with reason `driver_unavailable` and effect
      `none`. No row of any kind is written, and the scratch tree's digest is unchanged;
    * `w0_open_setup_and_catalog_operations_stay_unresolved_at_restart`: seeded open
      operations of each new kind, with receipts. After restart their state and receipts
      are unchanged, no file is touched, the lifecycle event lists them with
      `driver_unavailable`, and no panic occurs;
    * `w0_decide_on_projection_or_declaration_decision_is_refused_unconsumed`: seeded
      pending records of both kinds. `Decide approve` and `Decide deny` are each answered
      `CAPABILITY_UNAVAILABLE`, and the records stay `pending`;
    * `w0_m02_cli_commands_report_not_available_and_never_panic`: every M02 command in
      the U0 clap tree exits with M01's "not available in this build" envelope, never
      panics, and never contacts the runtime;
  * the full M01 model and integration suites still pass (regression).
* **Tests, phase 2 (activation change set, wave 3, with U5):**
  * `u0b_apply_projection_decision_resumes_exact_waiting_operation`, with deny, stale
    generation and unattended-decide variants, ⟨r3⟩ plus a `plan_digest` mismatch
    (`DECISION_STALE`, nothing applied);
  * `u0b_declare_interaction_decision_requires_attended_decide` (QR1), ⟨r3⟩ extended:
    the stored declaration equals the decision record's fields. A catalog request that
    changed the identity's endpoint after the decision makes the driver answer
    `DECISION_STALE` and write nothing;
  * ⟨r3⟩ `u0b_decision_kind_must_match_its_waiting_intent` (both mismatches are
    `DECISION_STALE`);
  * `u0b_restart_dispatches_every_operation_kind`, full form: the setup driver calls
    `ProjectionWriter::reconcile` and never `apply` (counting fake);
  * ⟨r3⟩ `u0b_setup_1_offered_after_activation`, and `w0_setup_1_is_not_offered` is
    retired;
  * ⟨r3⟩ `u0b_setup_without_projection_writer_is_capability_unavailable`, the permanent
    form of the dispatch-level `w0` test. The other `w0_*` tests are replaced by U5's
    end-to-end tests.
* **Depends on:** U0; the concurrent M01 commit. ⟨r3⟩ Phase 2 also depends on U4 and U5.

### U1: `heimdall-sshconf` lexer, parser, directive table, include loader (pure)

* **Owner paths:**
  * `crates/sshconf/src/{lex,parse,directive,include,limits}.rs`;
  * `tests/model/sshconf_parse.rs` and `tests/adversarial/sshconf_hostile.rs` (both hosted
    by `heimdall-sshconf`);
  * `tests/fixtures/sshconf/corpus/**` (inert configs: no `Match exec`; header comment
    "inert, ssh -G only").
* **Interfaces:**
  * `lex::split_args(line: &str) -> Result<Vec<String>, LexError>`: OpenSSH ≥ 8.7 rules
    [G03-S04] for quotes, backslashes, `=` after the keyword, and `#` outside quotes.
  * `parse::{ConfigFile, Line, Directive { keyword: Keyword, args: Vec<String>, span: Span },
    Span { source: SourceId, line: u32 }, parse_file(SourceId, &[u8], &Limits) -> Result<ConfigFile, ParseError>}`.
    A line that is not UTF-8 makes its directive `Keyword::Unreadable`, never a guess.
  * `directive::{Keyword::{Known(KnownKeyword), Unknown(String), Unreadable}, KnownKeyword,
    class(KnownKeyword) -> DirectiveClass { FirstWins, Accumulates, Section, Include,
    Executes, Other }, expands_tokens(KnownKeyword) -> bool, expands_env(KnownKeyword) -> bool}`.
    The keyword list follows ssh_config(5) at the S01 pin, and the classes follow
    ADR-0007 F1–F4 and F7.
  * `include::{ConfigSource` trait `{ read(&self, &Path) -> Result<SourceBytes, SourceError>;
    glob(&self, &Path) -> Result<Vec<PathBuf>, SourceError>; account_home(&self) -> &Path;
    user_dir(&self) -> &Path; system_dir(&self) -> &Path; env(&self, &str) -> Option<String> }`,
    `ConfigSet` (a cache of parsed files keyed by canonical path), `Roots { user: Option<PathBuf>, system: Option<PathBuf> }`}`.
  * `limits::Limits { file_bytes: 1 MiB, total_bytes: 8 MiB, files: 256, depth: 16,
    glob_results: 256, line_bytes: 4096 }`.
* **Tests:**
  * lexer golden cases: quoting, escapes, `=`, comments, CRLF, tabs;
  * every `KnownKeyword` classified, and accumulating directives as [S01] says (F2);
  * a relative Include resolves under the user directory or the system directory (F3);
  * glob results come in bytewise order;
  * `${VAR}` unset gives a recorded `EnvUnset` (F7);
  * an Include cycle is detected;
  * adversarial: an oversized file or line; depth 17; 257 files; a NUL byte; invalid UTF-8
    in a comment versus in a value; an Include of a FIFO (the `MemSource` fake reports
    `NotRegular`, and the real-FS case is U3's); a glob explosion; shell metacharacters in
    values stay data;
  * fuzz-ready: `parse_file` never panics on arbitrary bytes, by proptest over arbitrary
    `Vec<u8>`.

### U2: `heimdall-sshconf` evaluator, renderer, editors, identity selection, consent (pure)

* **Owner paths:**
  * `crates/sshconf/src/{eval,relevant,render,edit,consent,gitedit}.rs`;
  * `tests/model/sshconf_eval.rs`, `tests/model/sshconf_edit.rs` and ⟨r2⟩
    `tests/model/sshconf_consent.rs` (hosted by `heimdall-sshconf`).
* **Interfaces:**
  * `eval::{Query { host, user: Option<String>, local_user, client_version: OpenSshVersion,
    invocation: Invocation { Shell, Exec(Option<String>), Subsystem(String) } },
    evaluate(&mut ConfigSet, &dyn ConfigSource, &Roots, &Query, &Limits) -> Evaluation,
    Evaluation { values: BTreeMap<KnownKeyword, Resolved>, accumulated: BTreeMap<KnownKeyword,
    Vec<Candidate>>, unresolved: Vec<Unresolved>, invalid: Vec<Invalid> },
    Resolved { Unset, Determined(Value), Undetermined(Vec<Value>) },
    Value { args, span, condition: Option<Span> },
    UnresolvedReason { MatchExec, MatchLocalNetwork, Canonicalization, IncludeUnreadable,
    BoundExceeded, EnvUnset(String), TokenUnavailable(char) }}`.
  * `relevant::{RelevantBehavior` (HostName, Port, User, IdentityAgent, IdentityFile list,
    IdentitiesOnly, CertificateFile list, Proxy {Jump, Command, None} under the F10
    competition, ControlMaster/ControlPath/ControlPersist, ForwardAgent,
    StrictHostKeyChecking, User/GlobalKnownHostsFile, HostKeyAlias, CanonicalizeHostname,
    PermitLocalCommand/LocalCommand, KnownHostsCommand, AddKeysToAgent,
    PKCS11Provider/SecurityKeyProvider; each a `Resolved`)`, `relevant(&Evaluation) -> RelevantBehavior`,
    `diff(&RelevantBehavior, &RelevantBehavior) -> Vec<BehaviorChange>`,
    ⟨r2⟩ `behavior_digest(&RelevantBehavior) -> BehaviorDigest` (provenance reduced to its
    source role, ADR-0007 §5.2), ⟨r3⟩ `behavior_state(&RelevantBehavior) -> BehaviorState`,
    ⟨r2⟩ `identity_selection(&Evaluation, adopted: &Path, ⟨r3⟩ &dyn ConfigSource) ->
    IdentitySelectionReport` (ADR-0007 §3 item 3). ⟨r3⟩ The `ConfigSource` is used only to
    stat for the private key's presence (`backing`) and to read `.pub` files
    (`fingerprint`); a private key file is never opened. ⟨r2⟩ `executing_constructs(&Evaluation) ->
    Vec<Span>` (Match exec, ProxyCommand, KnownHostsCommand, LocalCommand with
    PermitLocalCommand), ⟨r3⟩ `unreadable_includes(&Evaluation) -> Vec<Unresolved>`
    (`IncludeUnreadable`, `BoundExceeded`, `TokenUnavailable` in an Include; ADR-0007 §6) `}`.
  * `render::{AliasName::parse, HostName::parse, RenderPath::{unix, windows, pipe},
    ManagedAlias { alias, hostname, port, user, identity_agent, identity_files, identities_only },
    render_managed(&[ManagedAlias], PathStyle) -> Result<Vec<u8>, RenderError>,
    render_include_block(&MarkerId, &RenderPath, Newline) -> Vec<u8>,
    ⟨r2⟩ render_git_managed(&RenderPath /* verified client */) -> Result<Vec<u8>, RenderError>,
    ⟨r2⟩ render_git_include_block(&MarkerId, &RenderPath, Newline) -> Result<Vec<u8>, RenderError>}`.
    The rules follow ADR-0007 §4.
  * `edit::{find_blocks(&[u8]) -> Vec<FoundBlock { marker, range, intact, position:
    BlockPosition { BeforeFirstSection, Conditional(Span) } }>, plan_insert(Option<&[u8]>,
    &IncludeBlock) -> Result<InsertPlan { bytes, offset, newline, had_bom }, EditRefusal>,
    plan_remove(&[u8], &MarkerId, expected_block: &[u8]) -> Result<Vec<u8>, EditRefusal>}`.
  * ⟨r2⟩ `gitedit::{find_blocks, plan_insert_top, plan_remove}`: the same contract for Git
    configuration text (insertion before the first section header, after leading `#`/`;`
    comments, blank lines and a BOM). The crate is the pure configuration-text crate, so it
    hosts this Git editor too. ⟨r3⟩ `gitedit::scan(&[u8]) -> GitScan { includes:
    Vec<GitInclude { path, conditional: bool, span }>, keys: Vec<GitKey { section,
    subsection: Option<String>, key, span }> }` reports `[include]` and `[includeIf "…"]`
    paths and every key with its section. It never evaluates a condition and never
    returns a value, only spans (ADR-0007 §5.6, M2-R08).
  * ⟨r2⟩ `consent::{ConsentItem { item: ConsentItemId, current: BehaviorState, after:
    BehaviorState, consented: Option<ConsentedStates { managed: BehaviorState, restore:
    BehaviorState }> }, classify(&[ConsentItem]) -> ConsentNeed { required: bool, reasons:
    Vec<ConsentReason> }}` (ADR-0007 §5.2). ⟨r3⟩ `BehaviorState { digest: BehaviorDigest,
    determined: bool }`, from `relevant::behavior_state(&RelevantBehavior)`: `determined`
    means no `Undetermined` directive. `classify` matches only determined states. An
    affected item with an undetermined current or after state always yields
    `required: true` with reason `undetermined_state`, whatever the digests (M2-R03).
* **Tests:**
  * first-obtained-value wins, including across Include (F1);
  * IdentityFile and CertificateFile accumulate in order (F2);
  * ProxyJump competes with ProxyCommand (F10);
  * an Include inside Host or Match is conditional (F3);
  * the include restores the containing file's section state (model of the inference in
    ADR-0007 §3; settled against real clients in U3);
  * `Match exec` gives `Undetermined` and is never executed. The `ConfigSource` fake panics
    if anything asks it to run a command, and no such API exists;
  * `Match final` and `canonical` with CanonicalizeHostname `no` and `yes`;
  * `command` and `sessiontype` per invocation;
  * an unknown keyword is `invalid` unless `IgnoreUnknown` covers it;
  * **soundness property**: random configurations with random undecidable sections, where
    every assignment's concrete evaluation lies in the candidates;
  * **unaffected-name property**: inserting B and P with literal managed aliases leaves
    `relevant()` identical for every name that is not a managed alias, with
    CanonicalizeHostname `no`, and reports it `Undetermined` otherwise;
  * **managed-values property**: directives P sets are `Determined` for a managed alias
    whatever follows B;
  * ⟨r2⟩ identity selection (M2-D01):
    * `identity_selection_exclusive_only_for_adopted_key_alone`;
    * `identity_selection_not_exclusive_with_inherited_identityfile_or_certificatefile`
      (a `Host *`, a matching wildcard, a later literal section);
    * `identity_selection_undetermined_behind_match_exec`;
  * ⟨r2⟩ `behavior_digest_ignores_line_moves_and_comments_not_values`;
  * ⟨r2⟩ consent (M2-D04):
    * `consent_byte_identical_rerender_needs_none`;
    * `consent_rollback_to_consented_restore_needs_none` (⟨r3⟩ determined states);
    * `consent_rollback_exposing_new_inherited_hostname_and_agent_needs_decision`;
    * ⟨r3⟩ `consent_undetermined_current_or_after_always_needs_decision`, which replaces
      revision 2's `consent_undetermined_after_needs_decision_unless_equal`. An equal
      digest does not help, and neither does a consented state recorded as undetermined;
    * ⟨r3⟩ `consent_match_exec_command_changed_with_same_candidates_needs_decision`
      (M2-R03). The fixture changes only the command of a `Match exec` that chooses
      between the same candidate HostNames. The behaviour digest is asserted equal before
      and after, and `classify` still requires a decision with reason
      `undetermined_state`;
    * `consent_new_alias_always_needs_decision`;
  * ⟨r3⟩ `identity_selection_reports_fingerprint_and_backing`: agent-backed (only the
    `.pub` is present), file-backed (a private key file at mode 000 is detected by stat
    and never opened), and `unknown` (no `.pub`);
  * ⟨r3⟩ gitedit `scan_reports_includes_conditional_includes_and_keys_never_values` (a
    canary value is absent from the output);
  * render: deterministic (two renders give identical bytes); sorted; refused values
    (`%` in a hostname, `${` or `"` in a path, a wildcard alias); `%%` escaping; Windows
    forward slashes and `//./pipe/`; ⟨r2⟩ the Git value rules (a spaced path single-quoted
    and Git-quoted; `'` and `"` refused);
  * edit: `plan_remove(plan_insert(x)) == x` byte-exactly for arbitrary `x` (proptest),
    including CRLF, a BOM, no trailing newline, an empty file and a missing file; insertion
    goes before the first section line or top-level directive; a duplicate marker is
    refused; an edited marker is `MarkerEdited`; a marker moved below `Host` is
    `Conditional`; bytes outside the block are never changed;
  * ⟨r2⟩ gitedit: the same round-trip property and refusals for Git text.
* **Depends on:** U0 (AST types fixed). Tests that parse text go green when U1 lands.

### U3: `heimdall-localenv` discovery, passive doctor, explicit probes, Git observation

* **Owner paths:**
  * `crates/localenv/src/{paths,fs,clients,agents,known_hosts,doctor,local_query,git,sys}.rs`
    and `crates/localenv/src/probe/**`;
  * `tests/integration/doctor.rs`, `tests/integration/sshconf_vs_ssh_g.rs` and ⟨r2⟩
    `tests/integration/git_observe.rs` (hosted by `heimdall-localenv`).
* **Interfaces:**
  * `paths::SshPaths { account_home, user_config, user_dir, system_config, system_dir }`,
    resolved through `sys::account_home()` (Unix `getpwuid_r`; Windows the profile folder;
    ADR-0007 F19), plus `SshPaths::with_test_override` (testcfg only).
  * `fs::BoundedSource: sshconf::include::ConfigSource`:
    * non-blocking open, then `fstat`; regular files only;
    * symlinks followed as OpenSSH does;
    * the limits from U1.
  * `clients::{ClientKind, ClientCandidate { path, source: ClientSource { Path, System32,
    GitBundled, Configured }, version: Option<OpenSshVersion>, sha256, selected }, resolve_clients(&Env,
    &SshPaths, &ClientsConfig, LocalQueries) -> ClientInventory}`. Windows selects the in-box
    System32 client (E6). ⟨r2⟩ `ClientInventory::accepts_bom_crlf(&ClientCandidate) -> bool`,
    from the U3 corpus observation table (ADR-0007 §4).
  * `agents::{EndpointLocator { UnixSocket(PathBuf), NamedPipe(String) }, AgentEndpoint {
    provider: ProviderKind, locator, presence, source }, detect_agents(&Env, &SshPaths, Platform)
    -> Vec<AgentEndpoint>}`. Detection is passive; on Windows it lists `\\.\pipe\` with
    `std::fs::read_dir` and opens nothing.
  * `known_hosts::lookup(&SshPaths, host, port, LocalQueries) -> Vec<HostKeyObservation>`,
    through `ssh-keygen -F` or a plain-entry parse.
  * `local_query::{LocalQueries { Enabled, Disabled }, run_version(&Path) -> Result<OpenSshVersion, _>}`.
    Bounded at 2 s; the environment is not modified; Q4.
  * ⟨r2⟩ `git::{observe_global(&Env, &ClientInventory, LocalQueries) -> GitGlobalObservation {
    file: Option<GlobalFileResolution>, values: Vec<GitValueObservation>, env_overrides:
    Vec<&'static str>, default_ssh: DefaultGitSsh }, resolve_run_selection(cwd: &Path, child_env:
    &Env, &ClientInventory, LocalQueries) -> GitSshSelection}` (ADR-0007 §5.6, §8). A
    configuration value never leaves these functions: they return scope, origin, a value
    digest and a classification. ⟨r3⟩ `observe_global` runs the queries with `--includes`,
    and walks the include graph of the system file and both global files with
    `sshconf::gitedit::scan`. The walk is bounded: 1 MiB per file, 64 files, depth 10.
    It sets `GitValueObservation.conditional` for keys reached through `includeIf`, and
    returns `GlobalFileResolution { file, rule: first_read_existing | created }` under
    ADR-0007 §5.6's first-read rule. It also returns `unreadable: Vec<OriginDisplay>`,
    which makes the item `not_applicable` (`git_config_unreadable`).
  * `doctor::{DoctorRequest { levels: BTreeSet<ProbeLevel>, ⟨r2⟩ allow_config_commands: bool,
    aliases: Option<Vec<String>>, interactive: bool, local_queries: LocalQueries, redact: bool },
    run(&LocalContext, &DoctorRequest) -> contract::doctor::DoctorReport}`.
  * `probe::{evaluate::ssh_g, agent::list_identities (through ipc::agent_client), network::banner,
    host::verify, auth::authenticate}`:
    * each probe has a timeout and runs in its own process group (Unix, `killpg` in
      `sys.rs`) or a kill-on-close job object without breakaway (Windows, `sys.rs`);
    * ⟨r2⟩ each fills `ProbeRecord.{authorization, executed_config_commands,
      effects_excluded, containment}` exactly as ADR-0007 §6 states, ⟨r3⟩ plus
      `config_tree_changed`, from re-reading the digests of every file the static pass
      read, after the level;
    * ⟨r3⟩ `evaluate`, `host_verification` and `authentication` run the real tree, so
      without `allow_config_commands` they are **always** declined
      (`config_commands_not_authorized`) before anything runs, whatever the static pass
      found (M2-R06). Revision 2 gated only on a construct being found, which is
      withdrawn;
    * ⟨r3⟩ when `sshconf::relevant::unreadable_includes` is non-empty for the alias, those
      levels are declined with `config_not_fully_readable` even with the flag.
    * ⟨r3⟩ a test-only `ProbeHook`, env-gated through `testcfg` and never compiled into
      release builds like `ReplaceHook`, has one point, `AfterStaticPass`: between the
      static pass and the start of the `ssh` child.
  * `sys`: the third `unsafe` module (overview §9). It holds `account_home`, `killpg`,
    the job objects, the profile folder, and the U4 primitives (exchange, no-replace
    renames, `ReplaceFileW`, handle-based identity and deletion). Each call is wrapped in a
    safe function with its invariant documented. ⟨r3⟩ Removal is exposed only as
    `QuarantineDir::remove_verified(&self, name, expected: FileIdentity)`. No safe
    function unlinks a name in any other directory, so production code cannot remove a
    name in a user directory (ADR-0007 §5.3).
  * The finding codes listed in §5 item 11.
* **Tests (A21):**
  * `a21_default_doctor_runs_no_exec_no_agent_no_network_no_mutation`:
    * fixture: `Match exec` canaries running `testkit::hook` in each mode (network to a
      loopback counter, an agent listing on a `FakeAgent`, creating a file, and a
      `setsid` escape), through `sh -c` on Unix and `cmd /c` on Windows (F13); a digest of
      the whole scratch tree before and after;
    * default doctor, local queries included: every counter 0, no file, tree unchanged,
      exit 0, every performed level listed, the `dynamic_match_unresolved` finding with
      file:line, and `effects_excluded` complete on the static record.
  * ⟨r2⟩ `a21_evaluate_declined_without_allow_config_commands`: nothing ran, level declined
    with reason `config_commands_not_authorized`.
  * ⟨r3⟩ `a21_inert_config_still_requires_allow_config_commands` (M2-R06): the static pass
    finds no executing construct. `evaluate`, `host_verification` and `authentication`
    are still each declined without the flag, and nothing runs (hook counters 0, no
    `ssh` child started).
  * ⟨r3⟩ `a21_match_exec_inserted_after_static_pass_never_runs_unauthorized` (M2-R06):
    * the test-only `ProbeHook` at `AfterStaticPass` inserts a `Match exec` line, running
      `hm-fixture-hook touch`, into an included file;
    * without the flag: declined, the hook's file is absent, no `ssh` child started;
    * with the flag: the hook runs, `config_tree_changed: true`, `effects_excluded`
      empty, and the inserted line is **not** claimed in `executed_config_commands`
      (the list is complete only when the tree did not change).
  * ⟨r3⟩ `a21_unreadable_include_declines_even_with_authorization`: an included file at
    mode 000, and separately an Include beyond the depth bound. Each is declined with
    `config_not_fully_readable`, with and without the flag, and nothing runs.
  * ⟨r2⟩ `a21_evaluate_authorized_runs_hooks_and_claims_no_exclusion` (M2-D06):
    * the hooks' effects happen (one accept, one agent listing, the file exists, the
      escaped PID is alive after the probe; the test kills it by the exact PID from its
      pidfile);
    * the record lists every hook's file:line in `executed_config_commands`, with
      `effects_excluded` empty and `containment: process_group`;
    * on Windows, the hook's child is killed with the job, `containment: job_object`.
  * `a21_agent_level_sends_only_request_identities`: exactly one message, type 11.
  * `a21_network_level_reads_banner_only`: 1 accept and 0 key-exchange bytes from the client
    after the banner.
  * ⟨r2⟩ `a21_host_verification_offers_nothing_to_sign`: `FakeAgent` sign count 0, for an
    alias with no executing construct ⟨r3⟩ (run with the flag, which is now always
    required).
  * ⟨r3⟩ `a21_host_verification_requires_authorization_with_or_without_constructs`, which
    replaces revision 2's `a21_host_verification_with_proxycommand_requires_authorization`.
    A ProxyCommand alias and an inert alias are both declined without the flag.
  * ⟨r2⟩ `a21_authentication_level_single_identity_fixture_signs_exactly_once`: one
    exclusive identity that the server accepts; the count is asserted for this fixture
    only.
  * `a21_hanging_match_exec_killed_with_group_at_timeout`.
  * `a21_agent_that_never_replies_times_out`.
  * `a21_fifo_include_does_not_block`, a Unix `mkfifo` fixture.
  * ⟨r2⟩ `a21_noninteractive_authentication_refused_for_unknown_or_interactive_identity`
    (Q2 as qualified), ⟨r3⟩ plus a variant with an uncleared inherited fallback identity
    (`fallback_identity_interaction`, M2-R05).
  * ⟨r2⟩ `a21_local_queries_listed_and_off_with_no_local_exec`.
  * `home_resolution_matches_ssh_g`: compares Heimdall's account home with `ssh -G` default
    paths on each platform (F19).
  * ⟨r2⟩ `doctor_reports_identity_selection_not_exclusive_with_remedy` (M2-D01).
* **Tests (A22 static half):** `integration_sshconf_vs_ssh_g::corpus_*`. For every inert
  corpus file and alias, Heimdall's `RelevantBehavior` equals `ssh -G -F <file> <alias>`
  after the default mapping.
  * They run on every target client: macOS system 10.3p1, the Linux devbox client, and
    Windows in-box 9.5p2 through the native runner.
  * The corpus covers: nested includes; Host and Match wildcards and negation; additive
    IdentityFile; unsupported syntax (an unknown keyword under IgnoreUnknown, and a
    deprecated one); `include_state_is_restored_after_included_file`; Windows `//./pipe/`
    forms; `%%`; spaced and non-ASCII paths.
  * ⟨r2⟩ `corpus_identity_list_matches_ssh_g`: the evaluator's identity list equals `ssh -G`'s
    `identityfile` lines, including that the defaults are absent once any IdentityFile is
    configured (settles F20).
  * ⟨r2⟩ `bom_and_crlf_acceptance`: per client, whether a user file with a BOM or CRLF loads
    with B effective; the result fills `accepts_bom_crlf` (ADR-0007 §4).
* **Tests (Git observation, M2-D10)** ⟨r2⟩, run with a scratch `HOME` and scratch system
  configuration:
  * `git_config_query_output_parsed` (the `--show-origin` and `--show-scope` forms);
  * ⟨r3⟩ `git_global_file_resolution_follows_read_order`, which replaces revision 2's
    `git_global_file_resolution_matches_git`. It covers four layouts: only `~/.gitconfig`,
    only XDG, both, and neither. Heimdall's choice is the first-read existing file, or
    `~/.gitconfig` to be created. `GIT_CONFIG_GLOBAL` makes it `git_global_redirected`;
  * `git_run_selection_in_cwd_reports_local_override`;
  * `git_values_never_leave_observation`: a canary `core.sshCommand` value is absent from
    every output, ⟨r3⟩ including values reached through includes and conditional
    includes;
  * ⟨r3⟩ discriminating Git fixtures (M2-R08; ADR-0007 §5.6), each in a scratch home on
    every target Git:
    * `git_both_global_files_present_values_in_either_make_item_not_applicable`: a value
      only in the XDG file, then only in `~/.gitconfig`. Each gives `not_applicable`
      with the correct origin;
    * `git_queries_use_includes_flag_and_expand_includes`: the global file includes, with
      `[include] path`, a file holding the value. Heimdall reports it with the included
      file's origin. The **control** runs the same query without `--includes` and must
      not see the value, which proves that the flag matters on that Git (settles the
      F22 `--includes` fact);
    * `git_value_through_conditional_include_is_counted_conditional`: the value sits
      behind `[includeIf "gitdir:<scratch>/work/"]`. The query run outside any repository
      misses it, which is asserted (settles the F22 conditional-include fact), and the
      static scan counts it with `conditional: true`: `not_applicable`;
    * `git_multiplicity_through_includes_counts_each_origin`: one value in the system
      file, one in the global file and one in a file the global file includes. The
      observations hold three origins with counts system 1 and global 2;
    * `git_unreadable_include_makes_item_not_applicable`: an included file at mode 000
      gives `git_config_unreadable`, and so does an include chain deeper than 10.
* **Depends on:** U1, U2, U7 (FakeAgent, hook), U6 (`ipc::agent_client`).

### U4: `heimdall-localenv` projection file transaction

* **Owner paths:**
  * `crates/localenv/src/projection/{mod,plan,replace,apply,observe,cleaner,git}.rs` and
    `crates/localenv/src/materialize.rs`;
  * `tests/integration/projection.rs` and ⟨r2⟩ `tests/integration/projection_git.rs`
    (hosted by `heimdall-localenv`).
* **Interfaces:**
  * ⟨r2⟩ `projection::replace` (ADR-0007 §5.3). ⟨r3⟩ The primitive no longer settles;
    settlement and restore are separate calls made by the transaction (M2-R01), and every
    removal goes through the quarantine (M2-R02):
    * `DirHandle::open(&Path) -> Result<DirHandle, Unmanageable>`;
    * ⟨r3⟩ `Quarantine::open_or_create(&DirHandle) -> Result<Quarantine, Unmanageable>`:
      `<dir>/.hm-quarantine`, created with `mkdirat` 0700 (Windows: owner-only DACL) and
      validated on every open (owner, mode exactly 0700, no symlink or reparse point,
      not a mount point); `Quarantine::rmdir_if_empty(self)`;
    * `FileIdentity { Unix { dev, ino }, Windows { volume, file_id } }`;
    * `validate(&DirHandle, name, &Base) -> Result<Validated { identity, sha256 }, ReplaceRefusal>`;
    * `stage(&DirHandle, staged_name, &[u8], Mode) -> Result<Staged { identity, name }, ReplaceError>`;
    * ⟨r3⟩ `recheck(&DirHandle, &Validated) -> Result<(), ReplaceRefusal>` (step 4);
    * `exchange(&DirHandle, &Staged, Option<&Validated>) -> Result<Exchanged { displaced_name }, ReplaceError>`;
    * `post_validate(&DirHandle, &Exchanged, &Validated, &Staged) -> PostValidation { Valid,
      Mismatch { ⟨r3⟩ observed: Option<FileIdentity> } }`;
    * ⟨r3⟩ `restore(&DirHandle, &Exchanged, at_path: FileIdentity /* S */, aside: FileIdentity
      /* D */) -> RestoreOutcome { Restored, ConflictPreserved { paths } }`;
    * ⟨r3⟩ `settle(&DirHandle, &Quarantine, source_name, expected: FileIdentity, slot) ->
      SettleOutcome { Settled, Missing, ForeignPutBack { path }, ForeignKept { path } }`.
      It moves with no-replace into the quarantine, verifies the identity, and returns
      before removal; `Quarantine::remove_verified(slot, expected)` then removes. The
      caller writes `file.settled` between the two;
    * ⟨r3⟩ `observe_step(&DirHandle, &FileStep, slot: Option<&str>) -> StepObservation {
      path, aside, slot: EntryObs { Absent, Present(FileIdentity) } }`, used only by
      `reconcile`.

    A test-only `ReplaceHook` mirrors the M01 `CleanupHook`. ⟨r3⟩ Its points are
    `AfterStage`, `AfterValidate`, `BeforeExchange`, `AfterExchange`, `AfterPostValidate`,
    `BeforeCommit`, `BeforeRestoreExchange`, `AfterRestoreExchange`, `BeforeSettleMove`,
    `AfterSettleMove`, `BeforeQuarantineRemove` and `BeforeReceipt(kind)`. Each point can
    run a closure (a racing writer) or abort the process (a crash). Exchange unsupported →
    `ReplaceRefusal::AtomicExchangeUnsupported`, which the plan turns into manual mode.
  * `projection::LocalProjection` implements the new port `app::ports::ProjectionWriter`
    (§5 item 15):
    * `preview(&ProjectionSpec, &PreviewIntent) -> ProjectionPlan`, read-only;
    * ⟨r2⟩ `apply(&SetupIntent, &mut dyn StageSink) -> ProjectionReceipt`, which executes
      any intent (apply, rollback, repair). The `StageSink` durably appends each stage
      receipt (ADR-0007 §5.7) before the next step. ⟨r3⟩ After each item's transaction
      check passes, `apply` calls `StageSink::commit_item`, which writes `item.committed`
      with the item's resources, projection record and consented states in one store
      transaction. It settles only after that call returns `Ok`. A sink error leaves
      everything unsettled for `reconcile` (row T1);
    * ⟨r2⟩ `reconcile(&SetupIntent, &[StageReceipt], ⟨r3⟩ &mut dyn StageSink) ->
      Result<ProjectionReconcile { items: Vec<ItemOutcome> }, ReconcileError>`, by
      identity, never by content alone. ⟨r3⟩ It implements ADR-0007 §5.7's state table
      row by row and writes the receipts it completes through the sink.
      `ReconcileError::UnreadableReceipt` leaves the operation unresolved;
    * ⟨r2⟩ `observe(&ProjectionRecord, &[AliasName]) -> Vec<AliasObservation>`: a passive
      static re-evaluation (behaviour digest, identity selection, block placement) used
      by doctor, the adapters and setup status.
  * ⟨r2⟩ `projection::git`: the B_git and P_git steps inside Git's lock protocol
    (ADR-0007 §5.6). ⟨r3⟩ B_git goes in the first-read global file chosen by
    `localenv::git::observe_global`. The displaced file leaves the lock name only at
    settlement, after the Git item's `item.committed`.
  * `projection::cleaner::ProjectionCleaner` implements the M01 port `ResourceCleaner`. ⟨r2⟩
    It deletes only when the generation matches **and** the entry has the identity and digest
    in the `ProjectionLocator`; the deletion itself is identity-bound (ADR-0007 §5.8).
    Otherwise it returns `Ok` with nothing deleted. ⟨r3⟩ It deletes through the quarantine,
    using the slot name derived from the locator, so a retry finds an entry moved before a
    crash (rows R1–R5).
  * `materialize::{key_file_path(&Fingerprint) -> PathBuf, write_public_key(&PublicKey)}`,
    written through `replace`.
* **Tests (A22 transaction half):**
  * `a22_apply_then_rollback_restores_user_bytes_exactly`;
  * `a22_user_edit_between_preview_and_apply_conflicts_user_config_changed`;
  * `a22_edit_of_managed_file_is_never_overwritten`, which also covers the rename to
    `hm-conflict-<gen>` at rollback;
  * `a22_edit_inside_marker_block_refuses_removal_and_names_lines`;
  * `a22_newer_user_edits_elsewhere_survive_rollback`;
  * `a22_marker_moved_into_host_section_reported_conditional`;
  * `a22_duplicate_marker_refused`;
  * `a22_symlinked_user_config_is_manual_mode` (Unix);
  * `a22_hardlinked_user_config_is_manual_mode`;
  * `a22_foreign_owner_or_unwritable_is_manual_mode`;
  * `a22_crlf_bom_no_trailing_newline_preserved`, and ⟨r2⟩
    `a22_bom_or_crlf_on_unaccepting_client_is_manual_mode_unchanged`;
  * `a22_missing_user_config_created_0600_and_ssh_dir_0700`;
  * `a22_render_is_deterministic_and_reapply_is_noop`;
  * ⟨r2⟩ race injection after the final comparison (M2-D03), through `ReplaceHook`:
    * `a22_race_rename_replace_after_final_check_is_restored`: another writer
      rename-replaces the user file at `BeforeExchange`. The displaced file is not V, so
      it is restored. The writer's bytes are active and intact, Heimdall's staged file is
      gone, and the result is `CONFIG_CONFLICT` `concurrent_writer`;
    * `a22_race_in_place_write_after_final_check_is_restored`;
    * `a22_race_symlink_substitution_at_boundary_is_restored` (Unix): the symlink comes
      back and its target is untouched;
    * `a22_race_third_writer_during_restore_preserves_both`: effect `partial`, and both
      files exist;
    * `a22_windows_reparse_point_user_config_is_manual_mode`: a junction for the `.ssh`
      directory (no elevation needed); the file-symlink row needs B10;
  * ⟨r2⟩ commit points (M2-D02):
    * `a22_first_adoption_failure_before_commit_leaves_only_inactive_files_then_cleaned`;
    * `a22_first_adoption_crash_after_p_before_b_reconciles_forward_or_cleans`, through
      the store `FaultHook` (in-process) and as a process crash, labelled as M01 N06
      requires;
    * `a22_first_adoption_crash_after_b_exchange_before_validation_reconciles`;
    * `a22_update_user_edit_after_p_exchange_restores_generation_n`: at `AfterExchange` of
      P, the hook edits the user file. P is restored to generation N, the result is
      `CONFIG_CONFLICT` `user_config_changed` with effect `none`, and the user's edit is
      intact;
    * `a22_update_crash_after_p_exchange_reconciles` (process crash; restart; it
      finishes or restores; `apply` is never called twice);
    * `a22_update_never_writes_user_file` (identity and bytes unchanged);
  * ⟨r3⟩ settlement after the update finishes (M2-R01):
    * `a22_update_user_edit_after_p_post_validation_restores_generation_n`: the hook at
      `AfterPostValidate` of P edits the user file. Old P is still at the displaced name,
      and the restore puts generation N back byte-for-byte with its original identity.
      The user's edit is intact, the result is `CONFIG_CONFLICT` `user_config_changed`
      with effect `none`, and no `item.committed` exists;
    * `a22_update_crash_between_post_validation_and_commit_reconciles` (row T1), as a
      process crash at `BeforeCommit` in two variants. With the user file unchanged at
      restart, recovery re-runs the check, commits and settles old P, giving generation
      N+1. With the user file edited while the runtime was down, recovery restores
      generation N. In both, `apply` is never called twice;
    * `a22_update_crash_after_commit_before_settlement_settles_never_restores` (row T2):
      a process crash at `BeforeSettleMove`. The restart settles old P through the
      quarantine and never restores;
    * `a22_update_user_edit_after_commit_is_reported_not_restored`: the edit lands after
      `item.committed`. The result is `applied`, old P is settled, and doctor reports the
      user file change;
    * `a22_settlement_never_precedes_item_committed`: a property over random
      `ReplaceHook` crash points. In the receipt log, no `file.settling` for a commit
      step's displaced entry ever comes before its item's `item.committed`;
  * ⟨r3⟩ recovery state table and durable restore phases (M2-R02; ADR-0007 §5.7):
    * `recovery_table_rows_each_have_a_test_vector`: an in-process model test. For every
      row ID of ADR-0007 §5.7 (F0–F9c, C1–C5, R1–R5, T0–T4), it builds the observed
      entries in a scratch directory together with the receipts, runs `reconcile`, and
      asserts the action, the receipts written and the outcome. A row without a vector
      fails the test;
    * `a22_crash_before_restore_exchange_restores` (row F5): a process crash at
      `BeforeRestoreExchange`;
    * `a22_crash_after_restore_exchange_before_receipt_is_recognized_as_restored`
      (row F5b), the case revision 2 misclassified. A process crash at
      `AfterRestoreExchange`, before `file.restored`. After restart the path holds D, the
      aside name holds S, and the outcome is `restored`, never "not exchanged"; S is
      settled;
    * `a22_crash_before_each_settlement_receipt_completes_settlement` (rows F8a, F8b,
      F9): process crashes at `BeforeReceipt(settling)`, `AfterSettleMove` (before
      `file.settled`) and `BeforeQuarantineRemove`. Each completes with the displaced
      entry gone and the quarantine empty;
    * `a22_displaced_entry_removed_by_another_writer_is_conflict_never_settled` (rows
      F2d, F8c): the hook removes D before `file.post_validated` in one variant, and
      before the settle move in the other. The outcome is
      `conflict_preserved`/`displaced_missing`, never `settled`, and nothing else is
      touched;
    * `a22_replacement_onto_displaced_name_during_settlement_survives` (Unix and
      Windows). At `BeforeSettleMove` another writer rename-replaces a new file onto the
      displaced name. Revision 2 could have unlinked it; now the identity check in the
      quarantine fails, the writer's file is moved back intact
      (`ForeignPutBack`/`settle_conflict{foreign}`), and nothing is deleted;
  * ⟨r3⟩ quarantine enforcement (the directory-concurrency assumption, ADR-0007 §5.3):
    * `a22_quarantine_symlink_wrong_owner_or_mode_is_manual_mode`: `.hm-quarantine` as a
      symlink, with mode 0755, or (Windows) as a junction. Each is refused, and nothing
      moves;
    * `a22_foreign_entry_in_quarantine_slot_is_put_back_never_deleted` (rows F8d, R5);
    * `a22_quarantine_removed_when_empty_and_kept_with_foreign_entries`:
      `rmdir_if_empty` never removes an entry, and `setup status` lists a kept entry;
    * `production_code_never_unlinks_outside_quarantine`: a test in
      `tests/integration/projection.rs` reads the `crates/localenv/src` sources, minus
      `#[cfg(test)]` modules, and asserts that `unlinkat`, `remove_file`, `remove_dir_all`,
      `DeleteFileW` and `FileDispositionInfoEx` appear only inside `sys::QuarantineDir`.
      `tools/validation/check.sh` is not changed;
  * ⟨r2⟩ cleanup:
    * `a22_stale_cleanup_generation_n_cannot_delete_n_plus_1`, at the deletion boundary
      with `reconcile::CleanupHook`, as M01 N06;
    * `a22_same_bytes_new_identity_is_not_deleted_by_cleanup`;
    * `a22_cleanup_target_swapped_at_deletion_is_moved_back`;
    * ⟨r3⟩ `a22_cleanup_crash_after_quarantine_move_completes_on_retry` (row R2): the
      deterministic slot is found on retry;
  * ⟨r2⟩ `exchange_supported_on_target_fs`: records, per harness, whether atomic exchange
    works (APFS, devbox ext4, WSL ext4, container overlay), and that a filesystem without
    it gives manual mode (settles F24);
  * `windows_replace_preserves_dacl`, ⟨r3⟩ `windows_replace_retains_displaced_identity_without_race`
    (renamed from revision 2's `windows_replace_retains_displaced_identity`) and
    `rendered_file_loads_on_target_client`: Windows native. `ssh -G -F` reads the rendered
    user file and P; the DACL is compared before and after through the harness; the file
    ID of the backup equals the validated identity. ⟨r3⟩ This establishes only the
    race-free case. No replacement is injected inside `ReplaceFileW`, and the evidence
    record keeps ADR-0007 §5.9 item 2 as `[U]` (M2-R08);
  * `private_key_files_never_opened`: private key files at mode 000, and adoption still
    succeeds from the `.pub` files.
* **Tests (Git, M2-D10)** ⟨r2⟩, with a scratch `HOME`, a scratch system file, and the target
  Git on each platform:
  * `git_include_applied_under_lock_and_rollback_restores_bytes`;
  * `git_existing_core_sshcommand_in_system_or_global_makes_item_not_applicable` (one value
    and several values, in each scope);
  * `git_lock_held_by_git_is_git_config_locked_nothing_written`;
  * `git_writer_during_heimdall_lock_fails_cleanly_nothing_lost`: a concurrent `git config
    --global` exits with Git's lock error; re-run afterwards, both edits are present;
  * `git_editor_write_after_final_check_is_restored`;
  * `git_crash_with_lock_holding_staged_or_displaced_reconciles`, ⟨r3⟩ with the lock
    name held until settlement, after the Git item's `item.committed`;
  * `git_rollback_after_user_added_value_keeps_user_value`;
  * `git_rollback_after_edit_inside_block_is_marker_edited`;
  * `git_user_set_after_include_wins` (settles F22's include precedence);
  * ⟨r3⟩ `git_both_global_files_present_include_goes_to_first_read_file_and_later_user_values_in_either_win`
    (M2-R08). Both global files exist with no value, so B_git goes at the top of the XDG
    file. Afterwards a `git config --global core.sshCommand …`, which writes into
    `~/.gitconfig`, wins. So does a manual value added to the XDG file below B_git. Both
    are checked with `git config --show-origin --get core.sshCommand`. This settles the
    F22 read-order fact;
  * ⟨r3⟩ `git_xdg_created_after_apply_shadowed_value_reported`. Only `~/.gitconfig`
    existed at apply. The user then creates the XDG file with a value. Heimdall's value
    wins, as disclosed, and doctor reports `git_user_value_shadowed` with both origins;
  * `git_spaced_client_path_is_quoted_and_runs` (Windows native: `[clients] ssh` at a spaced
    scratch copy of the verified client; `git ls-remote` reaches the fixture sshd).
* **Depends on:** U2, U3 (`sys`, `git`), U7 (ScratchHome).

### U5: Setup and catalog operations (app, store, runtime wiring)

* **Owner paths:**
  * `crates/app/src/{setup,catalog}.rs`, including the bodies of `setup::drive` and
    `catalog::drive` that U0b's `Operations::drive` calls, ⟨r3⟩ and the bodies of the
    `Operations::{setup, catalog}` entry points that replace U0b's fail-closed phase-1
    bodies;
  * ⟨r3⟩ `crates/runtime/src/service.rs` (M02 wiring only). The dispatch arms are U0b's
    (row 17), and the store bodies (`ext_m02.rs`, `tests/integration/store_m02.rs`) moved
    to U0b (row 20). U5 calls them and does not edit them;
  * `tests/model/setup.rs` and ⟨r2⟩ `tests/e2e/setup_dispatch.rs` (both hosted by
    `heimdall-runtime`).
* ⟨r3⟩ **Lands in wave 3 in the activation change set with U0b phase 2.** The integrator
  integrates both as one change (§2).
* **Interfaces:**
  * `Operations::{setup_preview, setup_apply, setup_rollback, setup_repair, catalog}(&Caller,
    …) -> OpResult<Completed>`, ⟨r3⟩ reached through U0b's `Operations::{setup, catalog}`
    entry points. `OperationsConfig.projection: Option<Arc<dyn ProjectionWriter>>` (the field
    is declared by U0b phase 1 with default `None`); with `None`, Setup requests keep the
    `driver_unavailable` refusal.
  * ⟨r2⟩ **Decision flow** (ADR-0007 §5.2, as qualified by §12.2 item 4):
    * the plan's `consent::classify` result decides;
    * when a decision is required, a `DecisionKind::ApplyProjection { operation, plan_digest,
      summary }` record is created with the operation in `AwaitingApproval`. Attended
      sessions get `APPROVAL_REQUIRED` and unattended ones `INTERACTION_REQUIRED`, both
      with `next.decision_ref`;
    * when none is required, the operation proceeds directly;
    * after `Decide approve`, the driver recomputes the plan; a digest mismatch is
      `CONFIG_CONFLICT` with nothing written;
    * ⟨r3⟩ the driver runs only with `SetupIntent.approval = Some(ProjectionApproval)` whose
      `plan_digest` equals the intent's, or with `consent::classify` returning
      `required: false`; any other state is refused without writing (M2-R07);
    * ⟨r3⟩ an affected item with an undetermined current or after state always takes the
      decision path (M2-R03);
    * ⟨r3⟩ a setup request while `Txn::open_setup_operations(environment)` is non-empty is
      refused with `CONFIG_CONFLICT`, reason `setup_in_progress`, before any record is
      written (ADR-0007 §5.7).
  * ⟨r2⟩ Effect discipline as in ADR-0006 §14.1 and ADR-0007 §5.7: `SetupIntent` in
    `RecoveryIntent.local`, the effect token, `Attempted`, then `ProjectionWriter::apply`
    with a `StageSink` that appends each receipt in its own transaction. On restart,
    `reconcile` is called, never a second `apply`. ⟨r3⟩ `StageSink::commit_item` calls
    `Txn::commit_projection_item`: one store transaction writes `item.committed`, the
    item's `ConfigProjection` resources at N+1, the projection record and the consented
    states (M2-R01). The sink fills each receipt's `effect` from its phase (ADR-0007 §5.7).
    An unreadable receipt (`ReconcileError::UnreadableReceipt`) leaves the operation
    unresolved and reports it in `runtime_lifecycle`.
  * The catalog has upserts with revisions; profiles reuse `upsert_profile` and snapshots.
    A `LimitedConsumer` is refused with `CAPABILITY_UNAVAILABLE`.
  * ⟨r2⟩ `DeclareInteraction` creates a `DecisionKind::DeclareInteraction` record (QR1);
    approval stores the `InteractionDeclaration`. `WithdrawDeclaration` narrows and needs no
    decision. `RemoveDestination` marks the projection stale and changes no file.
    ⟨r3⟩ The catalog driver builds the declaration **only** from
    `CatalogIntent.approval: DeclarationApproval`, which U0b's `decide` copied from the
    record. It writes it with `Txn::put_interaction_declaration(expected_revision)` at
    revision + 1. If the identity's current fingerprint or endpoint differs from the
    approval, it answers `DECISION_STALE` and writes nothing. `WithdrawDeclaration
    { revision, reason }` calls `Txn::end_interaction_declaration`. With `revision` it is a
    compare-and-swap: a newer declaration is untouched, and the result says
    `withdrawn: false`.
  * Destination identity:
    * `DestinationId` stays durable when the alias changes (spec §4.2);
    * a managed alias collision is `CONFIG_CONFLICT` with reason `alias_collision`;
    * the adapter registry maps `IdentitySource` to `native_agent` or `onepassword` (U6),
      for `ensure`.
  * The dispatcher routes `Setup` and `Catalog` behind `setup/1` ⟨r3⟩ (arms by U0b, row 17;
    the capability is offered by U0b phase 2, row 19). `Service::start` wires
    `LocalProjection`, `ProjectionCleaner` and the adapters, and gives the adapters the
    `ProjectionWriter::observe` handle.
  * `Store::open_read_only` never migrates. An older schema is reported, never upgraded
    ⟨r3⟩ (body by U0b, row 20).
* **Tests:**
  * `apply_requires_decision_attended_and_unattended`;
  * `apply_executes_exactly_the_decided_plan_digest`;
  * ⟨r2⟩ `apply_after_base_change_is_config_conflict_and_nothing_written`;
  * ⟨r2⟩ `rollback_to_consented_restore_needs_no_decision`;
  * ⟨r2⟩ `rollback_exposing_inherited_hostname_and_agent_added_after_apply_needs_decision`
    (the M2-D04 test: a user `Host *` HostName and IdentityAgent added after the apply);
  * ⟨r2⟩ `rerender_repair_to_consented_state_needs_no_decision`;
  * `same_request_id_replays_apply`;
  * `changed_plan_same_request_is_request_conflict`;
  * `limited_consumer_refused`;
  * `catalog_alias_rename_keeps_destination_id`;
  * `profile_upsert_bumps_revision_and_does_not_widen_existing_grant` (R-AU-03 spot check);
  * ⟨r2⟩ `declare_interaction_needs_attended_decision_and_lapses_on_endpoint_change_and_expiry`;
  * ⟨r2⟩ `withdraw_declaration_needs_no_decision`, ⟨r3⟩ with `reason: listing_missing`
    and a stale `revision`, which leaves a newer declaration live;
  * ⟨r3⟩ `declaration_written_from_decision_fields_only_and_stale_on_endpoint_change`
    (M2-R07);
  * ⟨r3⟩ `rollback_after_match_exec_command_edit_needs_decision` (M2-R03, end to end).
    Apply, then edit only the command of a `Match exec` that chooses between the same
    candidate HostNames for the restore state. Rollback creates an `ApplyProjection`
    decision (reason `undetermined_state`), and an unattended session gets
    `INTERACTION_REQUIRED` with `decision_ref`;
  * ⟨r3⟩ `second_setup_while_one_is_open_is_setup_in_progress`;
  * ⟨r3⟩ `declaration_changes_between_ensure_and_bind_are_seen_through_the_dispatcher`
    (M2-R04, with real catalog requests). Withdrawal, a `listing_missing` lapse and
    expiry each happen between `ensure` and `bind`, in-process and after a runtime
    restart. The `bind` result shows `interaction: unknown` and
    `noninteractive.eligible: false`;
  * restart recovery: ⟨r2⟩ `restart_reconciles_attempted_apply_never_reapplies`, for first
    adoption and update, with in-process and process-crash variants labelled as M01 N06
    requires;
  * `projection_events_carry_generation_and_change`;
  * ⟨r2⟩ end-to-end through the real dispatcher and store (M2-D08):
    * `e2e_setup_preview_apply_decide_restart_through_dispatcher`;
    * `e2e_catalog_then_ensure_bind_carry_pairs_and_selection`;
    * `e2e_setup_without_capability_is_schema_unsupported` (still true after
      activation, for a session that did not negotiate `setup/1`);
  * canary scan over every result.
* **Depends on:** U0, U0b ⟨r3⟩ (phase 1; phase 2 lands with U5), U4 (port implementation
  for integration), U6 (adapters registered).

### U6: Existing-access adapters and the bounded agent client

* **Owner paths:**
  * `crates/adapters/src/{native_agent,onepassword,detect,state,integration}.rs`;
  * `crates/ipc/src/agent_client.rs`;
  * `tests/integration/adapters.rs` (hosted by `heimdall-adapters`) and
    `tests/adversarial/agent_client_frames.rs` (hosted by `heimdall-ipc`).
* **Interfaces:**
  * `NativeAgentAdapter`, `OnePasswordAdapter`: `CredentialAdapter + ProviderProbe` (§5 item 15).
    * `descriptor()`: mechanisms `native_agent` and `onepassword`; `external_side_effects:
      false`; ⟨r2⟩ `interaction` = `ProviderDialog` for both (a native key may carry a
      confirmation constraint, ADR-0007 F23); `lock_continuity` = `Unknown` for the native
      agent and `StopsOnLock` for 1Password [S06].
    * `prepare` is local only. It checks presence passively and materializes the
      integration:
      * `ConsumerIntegration.environment` with `SSH_AUTH_SOCK`, only when every pair uses
        one endpoint;
      * `executables` and `overrides`;
      * ⟨r2⟩ `pairs`, with each pair's interaction profile and the `identity_selection`
        from `ProjectionWriter::observe`. ⟨r3⟩ The runtime stores only the historical
        part of `prepare`'s outcome (`PreparedFacts`) and recomputes interaction and
        eligibility for every result (U0b row 5).
    * `reconcile` observes the materialization.
    * `revoke` removes it. Its outcome is `remote_pending: []` with no expiry.
  * ⟨r2⟩ `state::{interaction_profile(&IdentityRecord, Option<&InteractionDeclaration>, &EndpointObservation,
    now) -> (InteractionKind, EvidenceBasis)}`: the ADR-0007 §7 table, including declaration
    lapse. ⟨r3⟩ It delegates to `heimdall_domain::catalog::eligibility` (U0b phase 1), so
    the runtime and the adapters apply one rule. A declaration counts only when it is
    `live`, its endpoint equals the current endpoint, and `expires_at > now`.
  * ⟨r3⟩ `state::fallback_clearance`, which delegates to
    `heimdall_domain::catalog::fallback_clearance(&IdentitySelectionReport,
    &[IdentityRecord], &dyn Fn(&IdentityId) -> PairEligibility, endpoint: &EndpointRef) ->
    FallbackClearance { cleared: bool, uncleared: Vec<usize /* entry index */> }`. That
    function is ADR-0007 §7's clearance rule (M2-R05), pure and integrator-owned, with its
    body in U0b phase 1. It reads `IdentitySelectionReport.identities_only`. Readiness
    (U0b), the adapters' `prepare` and the CLI's pre-launch check (U8) all use the same
    function.
  * `ipc::agent_client::{list_identities(&EndpointLocator, &ProbeBounds) -> Result<Vec<AgentIdentity
    { key_type, fingerprint, public_blob }>, AgentClientError>}`.
    * It sends only `SSH_AGENTC_REQUEST_IDENTITIES`. The reply is limited to 256 KiB and
      1024 identities, with a 2 s timeout. Comments are discarded.
    * Unix: the peer UID must equal ours. Windows: SQOS Identification, `FILE_TYPE_PIPE`, and
      the server owner must be the current user or LocalSystem for `openssh-ssh-agent`; the
      observed owner is recorded.
  * Minimum handling: `required.unattended` is satisfied only when `lock_continuity ==
    Verified && interaction == None`, so never in M02. Otherwise the result is
    `CAPABILITY_UNAVAILABLE`.
* **Tests (A11, A35 fixture level):**
  * `a11_noninteractive_ensure_never_contacts_provider`: FakeAgent message count 0 during
    `ensure`.
  * `a11_unattended_minimum_is_capability_unavailable_for_both_mechanisms`.
  * `a11_locked_native_agent_lists_nothing`: a disposable `ssh-agent` locked with
    `ssh-add -x`; settles ADR-0007 §7's `[I]`.
  * `a11_fake_onepassword_states`: the FakeAgent modes `Approve`, `ApprovalPending`, `Deny`
    and `Locked` map to `ProviderStatus` and codes as in ADR-0007 §7.
  * `a11_fido_identity_is_hardware_presence_from_public_key_alone`.
  * ⟨r2⟩ `a11_native_agent_identity_defaults_to_interaction_unknown` (M2-D05).
  * ⟨r2⟩ `a11_declared_none_reported_declared_and_lapses`: on an endpoint change, on a
    listing without the fingerprint, and at expiry.
  * ⟨r3⟩ `prepare_marks_uncleared_fallback_entries` (M2-R05): `prepare` fills
    `IdentityEntry.cleared` from the domain rule for an inherited agent-backed key that is
    undeclared (uncleared) and one that is declared (cleared).
  * ⟨r3⟩ `prepared_facts_from_outcome_drop_interaction_fields` (M2-R04).
  * `a35_identity_selected_by_public_key_with_identities_only` (exclusive fixture).
  * ⟨r2⟩ `prepare_reports_not_exclusive_for_inherited_identityfile`.
  * `adapters_never_send_sign_add_remove_lock_or_extension`, from the FakeAgent message log.
  * `enforcement_report_is_exact_for_existing_access`: `client_routing` or
    `unenforced_intent`, `none`, `shared_os_user`, `unknown`.
  * `endpoint_absent_is_service_unavailable_resource_provider`.
  * Adversarial: truncated, oversized and slow-loris replies; 1025 identities; a reply of
    the wrong message type; a Unix peer with a different UID (blocked on a second account
    where none exists).
* **Depends on:** U0, U7.

### U7: Test fixtures (`heimdall-testkit`)

* **Owner paths:**
  * `crates/testkit/src/{agent,sshd,home,hook}.rs`, the `hm-fixture-hook` bin target and the
    testkit `Cargo.toml` features;
  * `tests/integration/testkit_fixtures.rs` (hosted by `heimdall-testkit`).
* **Interfaces:**
  * `agent::FakeAgent::{start(Endpoint, FakeAgentConfig { keys: Vec<FixtureKey>, mode:
    AgentMode { Normal, Locked, ApprovalPending, Deny, ManyKeys(usize) } }) -> Running, log() ->
    Vec<AgentContact { msg_type, key_fp }>, release_pending(), stop()}`.
    * Unix socket and Windows named pipe, with an owner-only DACL.
    * Ed25519 keys are generated in memory per run.
    * `HEIMDALL_CANARY_*` comments let the canary scan catch any leak.
  * ⟨r2⟩ `agent::DisposableSshAgent::{start(&Scratch, AgentOptions { askpass_log: Option<PathBuf>,
    ⟨r3⟩ askpass_answer: AskpassAnswer { Approve, Deny } }) -> Running { socket, pid },
    add_key(&FixtureKey, KeyConstraints { confirm: bool }), ⟨r3⟩ sign_control(&FixtureKey,
    challenge: &[u8]) -> SignControl { signed: bool, askpass_delta: u32 }, stop()}`:
    `ssh-agent -D -a <scratch>/agent.sock` with `HOME=<scratch home>`, and, for confirmation
    tests, `SSH_ASKPASS=<hm-fixture-hook askpass>` plus `SSH_ASKPASS_REQUIRE=force` in the
    agent's environment. The askpass mode logs each invocation and ⟨r3⟩ answers as
    configured. Stopped by exact PID. ⟨r3⟩ `sign_control` is the **authorized disposable
    signing control** of ADR-0007 F23 (M2-R08). It runs `ssh-keygen -Y sign -n hm-fixture`
    with `SSH_AUTH_SOCK` set to the disposable agent, signing a fixture challenge with a
    key generated for this run. It reports whether a signature was produced (verified
    with `ssh-keygen -Y verify` against the fixture's allowed-signers file) and how many
    askpass invocations it caused. It never touches any other agent or key.
  * ⟨r2⟩ `agent::CountingProxy::{start(upstream: &EndpointLocator, listen: Endpoint) -> Running,
    log() -> Vec<u8 /* message type */>}`: forwards frames to a real agent and counts them.
  * `sshd::LoopbackSshd::{start(&Scratch, SshdConfig { authorized: Vec<PublicKey>,
    max_auth_tries, allow_pty, log_level_verbose }) -> Running { port, host_key_line,
    accepted_log() }}`.
    * Non-root `sshd -D -f <scratch>`, `ListenAddress 127.0.0.1`.
    * The authorized keys file lives in scratch with `restrict` options, plus `pty` where a
      test needs it.
    * Windows runs read `HM_FIXTURE_SSHD_{HOST,PORT,HOST_KEY}` from the harness (§4).
    * When a non-root `sshd` cannot start on the host (macOS `[U]`), the fixture reports
      `Unavailable` and the harness falls back to the M00-T03 Docker fixtures.
  * ⟨r2⟩ `home::ScratchHome::{new() -> ScratchHome { user_config, ssh_dir, known_hosts, config_dir,
    state_dir, git_home }, isolation_args(&self) -> Vec<OsString>, client_command(&self,
    ClientKind, alias) -> Result<Command, FixtureUnsafe>, decoy_agent(&self) -> &Running}`:
    * `isolation_args` returns only `-F`, `UserKnownHostsFile`, `GlobalKnownHostsFile` and
      `BatchMode`;
    * `client_command` applies the default-identity guard and sets `SSH_AUTH_SOCK` to the
      decoy agent;
    * scratch directories are removed on drop, pass or fail, and only paths created here
      are removed;
    * revision 1's `ssh_command` (which added `IdentityAgent`) is removed.
  * ⟨r2⟩ `hook::HookBinary`: the `hm-fixture-hook` program for `Match exec` and ProxyCommand
    fixtures. Its modes:
    * `connect <port>`;
    * `agent-list <socket|pipe>`;
    * `touch <path>`;
    * `escape <pidfile>`: on Unix `setsid` and sleep; on Windows an attempted
      `CREATE_BREAKAWAY_FROM_JOB` child;
    * `askpass <log> ⟨r3⟩ <approve|deny>`.

    Each mode exits with a documented status.
* **Tests:**
  * a FakeAgent round trip with a real `ssh` login to `LoopbackSshd`; mode semantics;
  * `ManyKeys(10)` against `max_auth_tries 3` fails without `IdentitiesOnly`;
  * `ScratchHome` cleans up;
  * nothing listens beyond `127.0.0.1`, asserted on the bound address;
  * ⟨r2⟩ `client_command_never_adds_selection_options`;
  * ⟨r2⟩ `default_identity_guard_refuses_alias_without_scratch_identities`;
  * ⟨r2⟩ `disposable_agent_runs_with_scratch_home` (asserted on the constructed command's
    environment);
  * ⟨r2⟩ `counting_proxy_counts_frames`;
  * ⟨r2⟩ `hook_modes_behave_as_documented` (⟨r3⟩ askpass `approve` exits 0, `deny`
    exits 1, and each logs once);
  * ⟨r3⟩ `f23_confirm_constraint_installed_prompts_per_signature_and_is_not_listed`
    (settles ADR-0007 F23; M2-R08). It has three parts:
    * **installation:** a key added with `confirm: true`. `sign_control` with `Approve`
      signs, with `askpass_delta == 1`. Two more signatures give a delta of 1 each, so the
      agent prompts per use. With `Deny` it gives `signed: false` and `askpass_delta == 1`;
    * **negative control:** the same key in a second disposable agent with
      `confirm: false`. `sign_control` signs with `askpass_delta == 0`, which proves that
      the oracle tells constrained from unconstrained;
    * **not passively visible:** both agents' `SSH_AGENTC_REQUEST_IDENTITIES` replies are
      equal (key blob and count; comments discarded).
* **Depends on:** U0, U2 (static evaluation for the guard).

### U8: Process contract (`heimdall-launch`), `run`, `connect`, holder release

* **Owner paths:**
  * `crates/launch/src/{resolve,env,meta,unix,windows,handoff,⟨r3⟩ eligibility}.rs`;
  * `crates/heimdall/src/{run_cmd,connect_cmd}.rs`;
  * `crates/app/src/holders.rs`;
  * `crates/runtime/src/supervisor.rs` (only the `holder_pass` addition);
  * `tests/e2e/run_m02.rs` (hosted by `heimdall` bin);
  * `tests/native/windows-launch/**` (pseudoconsole Ctrl-C and resize drivers, reusing the
    `tests/native/windows-g02/Send-ConsoleCtrl.ps1` approach).
* **Interfaces:**
  * `resolve::{resolve_program(&OsStr, &Env, &Path, Platform) -> Result<ResolvedProgram { path,
    kind: ProgramKind { Native, Batch }, via: Via { Explicit, Path } }, LaunchRefusal>,
    LaunchRefusal { NotFound, CurrentDirectory, BatchPathUnsafe, ArgumentUnescapable { index },
    NotExecutable, ⟨r2⟩ PathNotUnicode }}` (ADR-0007 §8; Q-B). `MAX_ARGV_BYTES` lives here
    now.
  * `env::EnvDelta::from_integration(&ConsumerIntegration, &Env, ⟨r2⟩ &GitSshSelection,
    Platform) -> EnvDelta`:
    * `SSH_AUTH_SOCK` only for a single endpoint;
    * on Windows, the `GIT_CONFIG_COUNT` injection under ADR-0007 §8's rule (fallback
      `GIT_SSH_COMMAND` if F22 is refuted);
    * never overrides a user's `GIT_SSH_COMMAND`, `GIT_SSH` or a `core.sshCommand` at any
      scope; it reports them as overrides.
  * ⟨r2⟩ `meta::{SideChannel::{from_fd(i32) -> Result<SideChannel, MetaError> (Unix:
    `F_GETFD`, type check, sets `FD_CLOEXEC`), create_exclusive(&Path) -> Result<SideChannel,
    MetaError>}, write(&mut self, &RunRecord) -> Result<(), MetaError>}`. A file write is
    followed by fsync. A failed `launching` write aborts the launch (ADR-0007 §8 invariant).
  * `unix::exec_replace(&ResolvedProgram, &[OsString], &EnvDelta, Option<SideChannel>) -> LaunchFailure`,
    which returns only on failure, through `CommandExt::exec`. It writes `launching` before
    exec and `prelaunch_failed` (best effort) after an exec failure.
  * `windows::spawn_and_wait(…) -> Result<u32, LaunchFailure>`, with a console control guard
    (tokio `ctrl_c`/`ctrl_break`) and no job object; it writes `launching`, ⟨r2⟩ `spawned`
    and `exited`.
  * `handoff::run_foreground(…) -> Result<ChildOutcome, LaunchFailure>`, the TUI's
    `system(3)` model.
  * `run_cmd::run(RunArgs)`, in order:
    1. `ensure` (profile);
    2. `bind(Launch(LaunchBinding { executable, holder }))`, where the holder is the
       process itself (Unix) or the launcher (Windows);
    3. ⟨r2⟩ `localenv::git::resolve_run_selection` in the child's working directory;
    4. the Q2 check, as qualified (ADR-0007 §7; QR5: any pair), ⟨r3⟩ performed by
       `launch::eligibility::check_noninteractive` immediately before step 5;
    5. launch.
  * ⟨r3⟩ `eligibility::check_noninteractive(bound: &[PairIntegration], fresh:
    &IdentitiesView /* a new `inspect identities` */, selection: &[FreshSelection], now)
    -> Result<(), PrelaunchRefusal { reason: interaction_unknown | provider_interaction |
    fallback_identity_interaction, pair, entries: Vec<ConfigProvenance> }>` (M2-R04,
    M2-R05; ADR-0007 §7). It runs under `--non-interactive` without
    `--allow-provider-interaction`, after Git resolution, as the last step before writing
    `launching`, and it checks:
    * every pair's fresh interaction is `none`;
    * every declaration the bind result relied on is still `live` in `fresh`, with the
      same `revision` and `endpoint`, and `expires_at > now`;
    * every pair's selection, re-evaluated now by a static `sshconf` pass in the CLI
      process (`FreshSelection`; passive, executes nothing), is `exclusive`, or
      `domain::catalog::fallback_clearance` clears every alternative.

    A refusal writes `prelaunch_failed` and exits 3 with `INTERACTION_REQUIRED`. A
    replayed `bind` result is checked the same way.
  * `connect_cmd::connect(alias)`: `inspect destinations`, then the verified client, ⟨r3⟩
    then, under `--non-interactive`, the same `check_noninteractive` for the alias's
    identity, then launch.
  * `Operations::release_exited_holders(&self, &dyn ProcessLiveness) -> OpResult<Vec<BindingId>>`
    and `Supervisor::holder_pass`. These are bounded, use jittered intervals (ADR-0006
    §13.6 item 4), and read liveness through the M01 `platform::process_start_time` (Q5).
    ⟨r2⟩ `HolderState::Unknown` never releases.
  * ⟨r2⟩ Test-only hooks, env-gated through `testcfg` and never compiled into release builds:
    * `HEIMDALL_TEST_PRE_EXEC_PAUSE=<fifo>` blocks after `launching` until the fifo is
      opened;
    * ⟨r3⟩ `HEIMDALL_TEST_PRE_CHECK_PAUSE=<fifo>` blocks after `bind` (and Git resolution),
      before the pre-launch eligibility check;
    * ⟨r3⟩ `HEIMDALL_TEST_CLOCK_OFFSET_S=<seconds>` (read through a file, so the offset can
      change during a pause) shifts the wall clock of the CLI and the runtime. U0b
      phase 1 adds it to the `testcfg` table;
    * `HEIMDALL_TEST_FORCE_EXEC_FAILURE` makes the exec fail after `launching`.
* **Tests (A27):**
  * `a27_binary_stdin_stdout_roundtrip_through_ssh`: 1 MiB random plus all 256 byte values
    through `heimdall run -- ssh <fixture> cat`, compared by SHA-256.
  * `a27_scp_and_sftp_binary_with_unicode_and_spaced_paths`.
  * `a27_git_clone_and_push_over_ssh_with_binary_blob`.
  * `a27_child_exit_codes_0_to_255_preserved`, plus `a27_windows_full_32bit_exit_code_preserved`.
  * `a27_signal_death_preserved` (Unix).
  * `a27_missing_executable_exits_127_with_prelaunch_record`.
  * `a27_not_executable_exits_126`.
  * ⟨r2⟩ `a27_child_exit_127_vs_exec_failure_distinguished_by_prelaunch_record`.
  * ⟨r2⟩ `a27_kill_between_launching_and_exec_is_indeterminate_never_launched` (the
    pre-exec pause, then SIGKILL by exact PID; `classify` gives `indeterminate`).
  * ⟨r2⟩ `a27_exec_failure_with_failed_meta_write_is_indeterminate`: the reader closes the
    pipe after reading `launching`, and the exec failure is forced. Heimdall exits 127 and
    does not die of SIGPIPE; `classify` gives `indeterminate`.
  * ⟨r2⟩ `a27_meta_unavailable_aborts_launch_no_child`: a marker file the child would
    create is absent; exit 127, reason `meta_unavailable`.
  * ⟨r2⟩ `a27_meta_file_existing_or_fd_invalid_is_usage_error_before_ensure`.
  * ⟨r2⟩ `a27_windows_spawned_record_is_positive_launch_proof`.
  * `a27_no_stdout_contamination_in_run_and_connect`: the bytes on stdout equal the child's
    bytes exactly.
  * `a27_shell_metacharacters_in_argv_reach_child_verbatim`.
  * `a27_ctrl_c_reaches_child_once` (Unix pty through rustix; Windows pseudoconsole).
  * `a27_resize_reaches_child` (`TIOCSWINSZ` gives SIGWINCH and the new size; ConPTY
    resize).
  * `a27_cwd_and_env_preserved_plus_only_documented_additions`.
  * `a27_windows_cmd_and_bat_targets_get_escaped_args` (16 injection argument cases from
    ADR-0002 §3.1).
  * `a27_windows_batch_path_with_percent_bang_caret_refused_127`.
  * `a27_windows_current_directory_never_searched`.
  * ⟨r2⟩ `a27_argv_canary_absent_from_ipc_store_events_logs_errors_batch_refusals_replay_and_meta`
    (Q8 as qualified).
  * ⟨r2⟩ `a27_sigpipe_ignored_by_caller_is_reset_limitation_recorded` (a recorded limitation,
    not fidelity evidence).
  * `run_retry_with_same_request_id_never_relaunches_automatically` (R-RT-05).
* **Tests (A11, Q2 as qualified):**
  * `a11_noninteractive_run_refuses_interactive_identity_before_launch`: exit 3, a
    `prelaunch_failed` record, and FakeAgent contact count 0. With
    `--allow-provider-interaction` the child launches.
  * ⟨r2⟩ `a11_confirm_constrained_native_key_refused_before_agent_contact` (M2-D05):
    * setup: a `DisposableSshAgent` holding a key added with confirmation, behind a
      `CountingProxy`, with the counting askpass;
    * ⟨r3⟩ **installation verified first** (M2-R08): `sign_control` through the proxy
      with `Approve` gives `askpass_delta == 1`, so the constraint is active on this
      agent. The proxy and askpass counters are recorded as the baseline;
    * non-interactive `run`: exit 3, `INTERACTION_REQUIRED` with reason
      `interaction_unknown`, a `prelaunch_failed` record, proxy count **delta** 0 and
      askpass count **delta** 0;
    * ⟨r3⟩ **discriminating control:** the same `run` with `--allow-provider-interaction`
      launches. The askpass delta becomes ≥ 1 (askpass set to `Deny`, so nothing signs),
      which shows the refusal prevented a real prompt. Revision 2's test also passed with
      an unconstrained key, because without the control nothing showed that a prompt
      would have happened. F23 itself is settled by U7's
      `f23_confirm_constraint_installed_prompts_per_signature_and_is_not_listed`.
  * ⟨r2⟩ `a11_declared_none_allows_noninteractive_launch_and_result_says_declared`.
  * ⟨r2⟩ `a11_multi_pair_binding_refused_when_any_pair_needs_interaction` (QR5).
  * ⟨r3⟩ fresh eligibility before launch (M2-R04):
    * `a11_declaration_withdrawn_after_bind_refused_before_launch`: `ensure` and `bind`
      report `none` (declared). The test-only pause between bind and the pre-launch check
      (`HEIMDALL_TEST_PRE_CHECK_PAUSE=<fifo>`) holds the CLI while the declaration is
      withdrawn. The launch is refused: exit 3, `interaction_unknown`,
      `prelaunch_failed`, proxy count 0;
    * `a11_redeclaration_after_bind_changes_revision_and_refuses_launch`: same as above,
      but withdraw and re-declare. The revision differs from the bind result's, so the
      launch is refused, and a fresh `run` launches;
    * `a11_declaration_expiring_between_bind_and_launch_refused`. M01's `testcfg` has no
      clock override, so U0b phase 1 adds `HEIMDALL_TEST_CLOCK_OFFSET_S` (row 15; `testcfg.rs` is integrator-owned). It is test-only and read
      by both the CLI and the runtime's wall clock, and it is advanced past `expires_at`
      during the pause;
    * `a11_lapse_recorded_by_failed_listing_between_ensure_and_bind_refuses_launch`:
      `doctor --active-probe agent` against an agent without the fingerprint records
      `WithdrawDeclaration { reason: listing_missing }`;
    * `a11_replayed_bind_result_still_gets_prelaunch_check`: the same `bind` request ID
      is replayed after a withdrawal. The replayed envelope still says `none`, and the
      launch is refused;
    * each of the above also runs **after a runtime restart** between `ensure` and
      `bind` (the restart restores history, never eligibility);
  * ⟨r3⟩ inherited fallback identities (M2-R05; ADR-0007 §7):
    * `a11_inherited_confirm_constrained_fallback_refused_noninteractive_before_agent_contact`:
      * setup: the agent behind the `CountingProxy` holds the adopted key K1
        (unconstrained, declared `none`) and K2, added with `confirm: true` (installation
        verified by `sign_control`). The user file has `Host *` / `IdentityFile
        <scratch>/k2.pub` with no `k2` private file, so K2 is agent-backed. The fixture
        sshd rejects K1 and accepts K2, and the selection is `not_exclusive`;
      * non-interactive `run`: exit 3, `INTERACTION_REQUIRED`, reason
        `fallback_identity_interaction`, naming the `Host *` line, with `prelaunch_failed`,
        proxy delta 0 and askpass delta 0;
      * **controls:** with `--allow-provider-interaction` the child launches and the
        askpass delta is ≥ 1 (askpass `Deny`), so the fallback would have prompted. After
        narrowing to `Host * !<alias>` the selection is `exclusive`, the child launches,
        the askpass delta is 0, and the login fails (K1 rejected, no fallback);
    * `a11_fallback_cleared_when_alternative_adopted_and_declared_launches`: K2
      unconstrained, adopted and declared `none`. The selection is still `not_exclusive`,
      every alternative is cleared, and the child launches;
    * `a11_file_backed_fallback_is_never_cleared`: `IdentityFile <scratch>/id_other` with
      a private file at 0600 is refused (`fallback_identity_interaction`) even when
      `id_other.pub` is adopted and declared;
    * `a11_identityfile_added_after_ensure_is_seen_by_prelaunch_check`: the `Host *`
      entry is added during the pre-check pause, and the launch is refused.
  * `a11_interactive_connect_succeeds_after_provider_approval`: pty, FakeAgent
    `ApprovalPending`, then `release_pending()`. Ordinary interactive use stays first-class.
* **Tests (holders, Q5 as qualified):**
  * `holder_exit_releases_reference_and_reused_pid_does_not_keep_it`;
  * ⟨r2⟩ `holder_unknown_liveness_never_releases`;
  * ⟨r2⟩ `windows_holder_is_launcher_and_forced_launcher_kill_is_reported`. On Windows
    native, the launcher is killed by exact PID. The binding is released after the holder
    pass while the child still runs; the test then stops the child by exact PID and records
    the limitation.
* **Tests (Git under run, M2-D10)** ⟨r2⟩:
  * `git_run_resolution_in_child_cwd_reports_local_override_and_injects_nothing`;
  * `git_run_injection_yields_to_dash_c_and_env`. It runs on every target Git, with stub
    "clients" that record which one ran, and settles F22's `GIT_CONFIG_COUNT` claim;
  * `git_run_never_records_child_arguments_or_config_values` (canaries in both);
  * `git_run_malformed_caller_git_config_count_injects_nothing`.
* `tui_handoff_ctrl_z_stops_and_fg_resumes_as_one_job` (pty, Unix).
* **Depends on:**
  * U0 for the core files (resolve, env, meta, unix, windows, handoff), in wave 1;
  * the `run`/`connect` wiring after U0b, U3 (`git`), U5 and U6.

### U9: CLI surface for setup, doctor, catalog, uninstall

* **Owner paths:**
  * `crates/heimdall/src/{setup_cmd,doctor_cmd,catalog_cmd,uninstall_cmd}.rs`;
  * M02 additions to `crates/heimdall/src/output.rs`;
  * `tests/e2e/cli_m02.rs` (hosted by `heimdall` bin);
  * additions under `schemas/examples/**`.
* **Commands:**
  * ⟨r2⟩ `setup [preview [--include-git] | apply [--include-git] | rollback [--keep-key-files] |
    repair <conflict> <resolution> | status]`. `apply`, `rollback` and `repair` preview first,
    show the plan (with the restore column) and submit `plan_digest`. There is no
    `--evaluate`;
  * `doctor [--active-probe LEVEL[,LEVEL…]] ⟨r2⟩ [--allow-config-commands] [--alias A]…
    [--no-local-exec] [--redact] [--json]`;
  * `destination {add|list|show|remove}`, `identity {list|adopt [--from-agent] [--pub FILE]|
    ⟨r2⟩ declare-interaction <id> none | withdraw-declaration <id> |remove}`,
    `profile {create|show|add|remove|list}`;
  * `uninstall [--purge-state]` (Q6).
* **Rules:**
  * `setup apply` (and a `rollback` or `repair` that needs a decision) shows the exact
    recorded plan and follows the ADR-0006 §3.1 client confirmation contract: typed
    `y`/`yes`, default No. Any other answer exits 3 with `INTERACTION_REQUIRED` and
    `next.decision_ref`.
  * ⟨r2⟩ `--allow-config-commands`:
    * on an interactive TTY it prints "runs your configuration's commands with whatever
      effects they have" and the file:line list, and requires a typed `yes`;
    * under `--non-interactive` the flag itself is the authorization, and the report
      records it;
    * ⟨r3⟩ it is required for every `evaluate`, `host_verification` and `authentication`
      level, even when the static pass lists nothing. The prompt then says "none found
      now; the configuration can change before ssh reads it". A level the static pass
      could not fully read is declined (`config_not_fully_readable`) and the prompt is not
      shown (ADR-0007 §6, M2-R06).
  * ⟨r2⟩ `identity declare-interaction` shows the decision text (ADR-0007 §7) and follows
    the confirmation contract.
  * ⟨r3⟩ `identity withdraw-declaration <id>` sends `WithdrawDeclaration { reason: owner }`.
    `doctor --active-probe agent` and `identity adopt --from-agent` send
    `WithdrawDeclaration { revision, reason: listing_missing }` for each declared
    fingerprint the listing lacked, but only when the runtime is already running; they
    never start it. Otherwise the report says `recorded: false` and prints the exact
    command (ADR-0007 §7; QR9).
  * ⟨r3⟩ `setup status` lists non-empty quarantine directories and their entries, and
    `uninstall` lists them under `remaining` (`kind: quarantine`) after removing empty
    ones.
  * `identity adopt --from-agent` is the explicit `agent` probe (ADR-0007 §6). On an
    interactive TTY it asks first and names the provider; under `--non-interactive` it is
    refused unless `--active-probe agent` is given.
  * `doctor` never starts the runtime and reads the store read-only.
  * `--json` envelopes go to stdout only; human text goes to stderr or stdout as in M01.
* **Tests:**
  * `a01_cli_adopt_observed_and_managed_aliases_then_ordinary_ssh_with_scratch_F` ⟨r2⟩
    (isolation arguments only; provider agent A contacted, decoy B 0);
  * `a01_unaffected_aliases_effective_config_identical_before_after` (static, plus `ssh -G -F`
    on inert ones);
  * `a01_no_remote_change`: the fixture sshd's authorized-keys digest is unchanged;
  * `a01_no_key_export`: no canary private key bytes anywhere, and private keys stay at
    mode 000;
  * `a01_personal_profile_without_repository`: cwd has no `.git`; `connect` and ordinary ssh
    work; `run --profile` passes after one attended decision (Q3);
  * `a11_noninteractive_errors_exit_codes`: apply gives 3, `--require-unattended` gives 4,
    an absent provider endpoint gives 5, a conflict gives 6, `LAUNCH_FAILED` gives 127, a
    usage error gives 2, each JSON-schema-valid;
  * `a21_cli_doctor_json_validates_against_schema`;
  * ⟨r2⟩ `a21_cli_allow_config_commands_prompt_text_and_typed_yes`;
  * `a22_cli_setup_conflict_then_repair`;
  * `uninstall_restores_user_bytes_and_effective_config_and_reports_remaining_items`;
  * ⟨r2⟩ `uninstall_with_incomplete_rollback_keeps_artifacts_and_purge_refuses` (Q6 as
    qualified), ⟨r3⟩ including a kept foreign quarantine entry;
  * ⟨r3⟩ `a21_cli_inert_config_still_prompts_for_allow_config_commands`;
  * ⟨r3⟩ `a11_cli_listing_lapse_recorded_only_when_runtime_running`: doctor with the
    runtime stopped reports `recorded: false` and does not start it. With the runtime
    running, the lapse is recorded, and a later `run --non-interactive` is refused;
  * `host_key_substitution_fails_closed_and_nothing_written_to_known_hosts` (the MANIFEST
    row 5 pattern on `LoopbackSshd`; R-SE-04);
  * the A35 matrix, over a real `DisposableSshAgent` behind a `CountingProxy` (Unix) or the
    FakeAgent pipe (Windows), with `LoopbackSshd` and the decoy agent at `SSH_AUTH_SOCK`:
    * `a35_matrix_ssh_git_scp_sftp_ordinary_alias_and_run_bound`, which records the
      resolved executable, the fingerprint the server accepted (fixture sshd
      `LogLevel VERBOSE`), and the contact counts (A > 0, B = 0);
    * ⟨r2⟩ `a35_wrong_key_exclusive_selection_fails_without_fallback`. Agent A holds the
      adopted key, which the server rejects, and an accepted key; the selection is
      exclusive. The login fails, and the server log shows only the adopted fingerprint
      offered;
    * ⟨r2⟩ `a35_inherited_identity_fallback_agent_backed_reported_not_exclusive` (M2-D01).
      The user file has `Host *` / `IdentityFile <scratch>/other.pub`, the other key is in
      agent A, and the server accepts it while rejecting the adopted key:
      * the login succeeds with the other fingerprint;
      * preview, doctor and `ensure` all reported `not_exclusive`, and nothing reported
        `exclusive`;
      * after the user entry is narrowed with `Host * !<alias>`, the selection is
        `exclusive` and the login fails;
    * ⟨r2⟩ `a35_inherited_identity_fallback_file_backed_reported_not_exclusive`: the same,
      with `IdentityFile <scratch>/id_other`, a private key file at 0600;
    * ⟨r3⟩ in both inherited-fallback tests, the ordinary interactive login still succeeds
      with the other fingerprint (existing auth is not second-class). The same alias
      under `run --non-interactive` is refused with `fallback_identity_interaction` before
      any agent contact (agent A count delta 0), which ties A35 to the A11 rule (M2-R05);
    * `a35_too_many_keys_succeeds_for_managed_alias_only` (`ManyKeys(10)`,
      `MaxAuthTries 3`; exclusive);
    * `a35_identity_agent_overriding_ssh_auth_sock_is_reported_and_managed_alias_unaffected`
      (a user `Host *` IdentityAgent pointing at the decoy B; the projected A wins; B
      contacts 0);
    * ⟨r2⟩ `a35_mutation_broken_identity_agent_is_detected` (M2-D09). The rendered P's
      IdentityAgent line is pointed at B, or removed, and the same oracle must report
      failure: B contacted, or the login failed;
  * pty confirmation cases (EOF, `n`, non-TTY, `yes` exactly once), as in M01 U9.
* **Depends on:** U3, U5, U8.

### U10: First useful TUI

* **Owner paths:** `crates/heimdall/src/tui/**` and `tests/e2e/tui_m02.rs` (hosted by
  `heimdall` bin).
* **Interfaces:**
  * `tui::run(TuiConfig) -> ExitCode`. Ratatui runs on the main thread. IPC runs on a worker
    thread with a current-thread tokio runtime (overview §3).
  * Views:
    * **overview**: Ready, Working, or Needs attention, from doctor `static` findings and
      `inspect`;
    * **destinations and profiles**: a list with immediate search that never probes
      (spec §12.1);
    * **detail**: provenance and freshness of each value (managed, observed, inherited,
      undetermined), the `ProviderStatus`, ⟨r2⟩ the interaction basis (`declared` with its
      date), the identity selection, and the projection state;
    * **operation detail**: observed through `observe events`;
    * **pending decisions**: a modal implementing the client confirmation contract with a
      typed `yes`, default No. ⟨r2⟩ For `ApplyProjection` it shows the before, after and
      restore columns; for `DeclareInteraction`, the decision text.
  * The connect action goes through `launch::handoff::run_foreground`.
  * Explicit probes are labelled actions that name their level. ⟨r2⟩ A level that would
    run configuration commands shows the authorization text and requires a typed `yes`.
    ⟨r3⟩ This applies to every level that runs the real tree (`evaluate`,
    `host_verification`, `authentication`), even when the static pass found nothing.
* **Tests:**
  * `TestBackend` snapshots at 40×12 and 120×40;
  * `NO_COLOR`: no meaning carried by color alone; the snapshot shows text markers;
  * keyboard-only navigation of every M02 action;
  * `search_never_probes` (FakeAgent and listener counts 0);
  * `connect_handoff_restores_terminal_after_exit_and_after_child_signal` (pty);
  * `panic_restores_terminal`;
  * `hangup_watchdog_exits` (REPORT.md §5);
  * `no_cursor_position_query_emitted` (no `ESC[6n` on the pty);
  * `decision_modal_requires_typed_yes_default_no`;
  * ⟨r2⟩ `decision_modal_shows_restore_column`;
  * ⟨r2⟩ `config_commands_authorization_requires_typed_yes`;
  * first-frame latency measured and recorded, not gated in M02 (spec §15.1 budget,
    measured in M08).
* **Depends on:** U3 (library), U5 (IPC), U8 (handoff).

### U11: M02 exit suite, native harnesses, evidence, compatibility matrix

* **Owner paths:**
  * `tests/native/m02/**`: `run-macos.sh`, `run-linux.sh`, `run-windows.sh`,
    `run-wsl-distro.sh`, `case-index.json`, `required-inventory.json`, `runs.json`, and the
    evidence generator, generalized from `tests/native/m01/m01-evidence.py`;
  * `tests/evidence/m02-*.json` and `tests/evidence/artifacts/m02/**`;
  * the M02 rows of `docs/compatibility/matrix.md`.
* **Does:**
  * assembles the cases of §3 from every unit;
  * runs §4 on each platform and writes records per plan §6.6, with real exit codes and
    redacted logs;
  * fills the matrix with exact labels (spec §3.3). ⟨r2⟩ This includes:
    * identity selection as a per-configuration fact;
    * the ADR-0007 §5.9 unsupported concurrency cases;
    * the §8 Git run-time limits;
    * the `indeterminate` Unix launch classification;
    * ⟨r3⟩ the quarantine directories (ADR-0007 §5.3) and the §5.9 item 4 residual;
    * ⟨r3⟩ the `git_user_value_shadowed` residual (ADR-0007 §5.6);
    * ⟨r3⟩ the no-interaction refusal of uncleared fallback identities (ADR-0007 §7);
    * ⟨r3⟩ the Windows `ReplaceFileW` internal window as `[U]`;
  * ⟨r2⟩ records each settled `[I]`/`[U]` fact of ADR-0007 (F20–F24, the include-state
    inference, BOM/CRLF acceptance, exchange support) per platform, ⟨r3⟩ plus the three
    added F22 facts (`--includes`, global read order, conditional includes) per target
    Git. F23 is recorded from the U7 signing control, never from the refusal test;
  * demonstrates T06 as a scripted transcript;
  * moves units from `implemented_unverified` to `verified` only when their tests passed in
    a recorded run.
* **Depends on:** all.

## 2. Order and parallelism

```text
U0 skeleton + contract rev 3  ┐ one integrator change set (wave 0), after the Q1–Q8 rulings,
U0b phase 1: M01 integration, ┘ the QR1–QR6 and §12.5 rulings, and the concurrent M01 commit;
   fail-closed gates, store bodies  ⟨r3⟩ wave-0 acceptance tests must pass before wave 1
 ├─► U1 sshconf parse ──────────────┐
 ├─► U2 sshconf eval/render/edit/   │ (wave 1, parallel; U2's text tests go green when U1 lands)
 │      consent/gitedit ────────────┤
 ├─► U7 testkit fixtures ───────────┤ (its identity guard needs U2's evaluator)
 ├─► U6 adapters + agent client ────┤ (tests need U7)
 └─► U8 core: resolve/env/meta/exec/spawn/handoff
                                    ▼
     U3 discovery/doctor/probes/git (U1,U2,U6,U7)   U4 projection files (U2,U3 sys+git,U7)  (wave 2)
                                    ▼
     U5 setup/catalog drivers + runtime wiring (U0b,U4,U6) ┐ ⟨r3⟩ activation change set:
     U0b phase 2: decide/drive arms, setup/1 offered      ┘ one integrator change
     U8 run/connect wiring + holders + pre-launch check (U0b,U3,U5,U6)                  (wave 3)
                                    ▼
     U9 CLI surface (U3,U5,U8)   U10 TUI (U3,U5,U8)                                     (wave 4)
                                    ▼
     U11 exit suite + native evidence + matrix                                          (wave 5)
```

⟨r2⟩ The units add up to **thirteen**: U0 and U0b, both the integrator's, plus eleven
implementation units. ⟨r3⟩ U8 and U0b are each delivered in two phases. The order is:
* **wave 0:** U0 with U0b phase 1;
* **wave 1:** U1, U2, U7, U6 and U8 core;
* **wave 2:** U3 and U4;
* **wave 3:** the activation change set (U5 with U0b phase 2), then U8 wiring;
* **wave 4:** U9 and U10;
* **wave 5:** U11.

File conflicts are designed out:

* U0 owns `cli.rs` and every signature;
* U0b alone edits existing M01 code (`operations.rs`, `events.rs`, `error.rs`,
  `domain/operation.rs`, ⟨r3⟩ `store/src/ext.rs`'s `intent_update_allowed`, the dispatch
  arms in `runtime/dispatch.rs`, `ipc/session.rs`'s capability list in phase 2, the shared
  fakes) and ⟨r3⟩ owns `store/src/ext_m02.rs`. U5 supplies only the bodies of the
  `setup::drive` and `catalog::drive` entry points ⟨r3⟩ and of `Operations::{setup,
  catalog}` that U0b declares with fail-closed bodies;
* U5 owns ⟨r3⟩ `runtime/service.rs` (M02 wiring), and U8 owns only `holder_pass` in
  `supervisor.rs`;
* U3 and U4 share the crate `heimdall-localenv` but disjoint files. U4 calls U3's `sys` and
  `git` modules and does not edit them.

Serialize anything that touches authority semantics, a schema version or the store
migration through the integrator (plan §7.3). Revision 1 had the independent review its
plan asked for (`review-m02-design/review.md`). Revision 2 applied it, and was re-reviewed
(`review-m02-design/round2.md`). ⟨r3⟩ Revision 3 applies that review and has not itself
been re-reviewed.

## 3. Milestone exit mapping (plan §5 M02 "Exit evidence")

| Exit claim / case | Proven by (tests) | Native runs (§4) |
|---|---|---|
| **A01**: no remote change, no key export, no mandatory prefix, unaffected aliases still work, personal profile without a repository | U2 unaffected-name and managed-values properties; U4 `a22_apply_then_rollback_*`, `private_key_files_never_opened`; U9 `a01_*` (5 tests, isolation arguments only, two agents); U5 `catalog_*`, `e2e_catalog_then_ensure_bind_*`; ⟨r3⟩ U2 `identity_selection_reports_fingerprint_and_backing` (private keys detected by stat, never opened) | macOS, Linux devbox, Windows 11 with scratch `-F`; WSL disposable distribution and Docker container with **ordinary ssh, no `-F`** |
| **A11**: ordinary access first-class; non-interactive returns explicit interaction or capability state without a popup or unapproved fallback | U6 `a11_*` (7), `a35_identity_selected_by_public_key_with_identities_only`, ⟨r3⟩ `prepare_marks_uncleared_fallback_entries`, `prepared_facts_from_outcome_drop_interaction_fields`; U0b ⟨r3⟩ `domain_eligibility_rule_table`, `domain_fallback_clearance_rule_table`; U8 `a11_*` (⟨r3⟩ 14). These are `a11_noninteractive_run_refuses_interactive_identity_before_launch`; ⟨r2⟩ `a11_confirm_constrained_native_key_refused_before_agent_contact` (⟨r3⟩ with verified installation and the discriminating control); `a11_declared_none_*`, `a11_multi_pair_*`, `a11_interactive_connect_succeeds_after_provider_approval`; ⟨r3⟩ the five fresh-eligibility tests (M2-R04: withdrawal, re-declaration, expiry, listing lapse, replay, each also across a restart); and the four fallback-identity tests (M2-R05: confirm-constrained inherited key refused with controls, cleared alternative, file-backed never cleared, entry added after `ensure`). U7 ⟨r3⟩ `f23_confirm_constraint_installed_prompts_per_signature_and_is_not_listed` (settles F23). U0b ⟨r3⟩ `u0b_eligibility_is_recomputed_per_result_never_taken_from_prepared_facts`. U5 ⟨r3⟩ `declaration_changes_between_ensure_and_bind_are_seen_through_the_dispatcher`. U9 `a11_noninteractive_errors_exit_codes`, ⟨r3⟩ `a11_cli_listing_lapse_recorded_only_when_runtime_running`, ⟨r2⟩ `a35_wrong_key_exclusive_selection_fails_without_fallback` (the "no unapproved fallback" evidence for exclusive selection). ⟨r3⟩ For non-exclusive selection the no-interaction path refuses uncleared alternatives (§12.5 item 5, qualifying QR4). U3 `a21_noninteractive_authentication_refused_*` (⟨r3⟩ with a fallback variant) | all three, fixture level; native ssh-agent lock and ⟨r2⟩ confirm-constrained key on macOS and Linux; 1Password, Windows system agent (incl. its confirm row) and hardware-key rows blocked (§7) |
| **A21**: default doctor does no exec, provider contact, signing, network or mutation; explicit probes classified and bounded | U3 `a21_*` (⟨r3⟩ 16 tests), including ⟨r2⟩ the hook classification and authorization tests and ⟨r3⟩ `a21_inert_config_still_requires_allow_config_commands`, `a21_match_exec_inserted_after_static_pass_never_runs_unauthorized` and `a21_unreadable_include_declines_even_with_authorization` (M2-R06); U9 `a21_cli_*` (⟨r3⟩ 3); U10 `search_never_probes`, `config_commands_authorization_requires_typed_yes` | all three (Windows canary through `cmd.exe`, F13) |
| **A22**: relevant behaviour correct; dynamic unknowns stay unknown; unrelated content and newer edits survive; generation deterministic | U1 corpus; U2 properties (soundness, round trip, determinism, ⟨r2⟩ consent, ⟨r3⟩ `consent_undetermined_current_or_after_always_needs_decision` and `consent_match_exec_command_changed_with_same_candidates_needs_decision`, M2-R03); U3 `corpus_*` against `ssh -G -F` per client, ⟨r2⟩ `corpus_identity_list_matches_ssh_g`, `bom_and_crlf_acceptance`, ⟨r3⟩ the five discriminating Git observation fixtures (M2-R08). U4 `a22_*` (⟨r3⟩ 42 tests). Besides race injection, commit points and identity-bound cleanup, these cover settlement after the update finishes (5, M2-R01), crashes before and after the restore exchange and before each settlement receipt, displaced-entry removal and replacement (5, M2-R02), and quarantine enforcement (3). U4 also has ⟨r3⟩ `recovery_table_rows_each_have_a_test_vector` (every ADR-0007 §5.7 row), `production_code_never_unlinks_outside_quarantine`, `exchange_supported_on_target_fs`, `windows_replace_*` (2; ⟨r3⟩ race-free case only) and the Git tests (⟨r3⟩ 12). U5 decision, consent and restart tests, ⟨r3⟩ `rollback_after_match_exec_command_edit_needs_decision` and `second_setup_while_one_is_open_is_setup_in_progress`. U0b ⟨r3⟩ `integration_store_m02::*`. U9 `a22_cli_setup_conflict_then_repair`. ⟨r2⟩ The ADR-0007 §5.9 cases are stated as unsupported and are not counted, ⟨r3⟩ including the Windows `ReplaceFileW` window (`[U]`) and writes into the quarantine (item 4) | all three clients (10.3p1, devbox client, in-box 9.5p2); Windows DACL and displaced-identity retention; exchange support per filesystem |
| **A27**: no stdout contamination or shell injection; child streams and status preserved; setup failure distinguishable | U8 `a27_*` (⟨r2⟩ 24 tests; setup failure is distinguishable by `prelaunch_failed`, and an undetectable pre-exec stop is classified `indeterminate`, never "launched"); the SIGPIPE test records a limitation, not fidelity. ⟨r3⟩ A pre-launch eligibility refusal (M2-R04/R05) is also a `prelaunch_failed` record with exit 3, asserted in the U8 `a11_*` fresh-eligibility and fallback tests. U0b ⟨r3⟩ `w0_m02_cli_commands_report_not_available_and_never_panic` covers wave 0 | all three; Windows Ctrl-C and resize through pseudoconsoles (interactive console row blocked, §7) |
| **A35**: verified executable and identity used; exact limitations; existing-auth not second-class | U6 `a35_identity_selected_by_public_key_with_identities_only`, `adapters_never_send_*`; U7 `ManyKeys`, ⟨r2⟩ `client_command_never_adds_selection_options`; U8 `a27_git_*`, `a27_scp_*`, ⟨r2⟩ Git run tests; U9 `a35_*` (⟨r2⟩ 7 tests: two counting agents, inherited fallback agent- and file-backed, mutation check; ⟨r3⟩ both inherited-fallback tests also show the interactive login succeeding while non-interactive `run` is refused before agent contact), `a01_*`; ⟨r3⟩ U3 and U4 Git fixtures for both global files, includes and conditional includes, and multiplicity (M2-R08); matrix rows (⟨r3⟩ including `git_user_value_shadowed` and the fallback refusal) | macOS and Linux: real disposable `ssh-agent` × {ssh, git, scp, sftp} × {ordinary alias, run-bound} × {wrong key, inherited fallback (agent, file), too many keys, IdentityAgent overriding SSH_AUTH_SOCK}; Windows: fixture pipe agent (selection) × the same; Windows system agent, 1Password live and Linux arm64 blocked (§7) |
| "A participant can connect without a mandatory work wrapper" | U9 `a01_cli_adopt_*` and the T06 scripted transcript | WSL disposable distribution (ordinary ssh); the human participant walkthrough is an owner input (§7 B7) |
| "No remote authentication change, key export, or provider-policy bypass was needed" | `a01_no_remote_change`, `a01_no_key_export`, `adapters_never_send_*`, the identity selection tests (IdentityAgent is the provider's own endpoint; nothing relays) | all three |
| "Does not claim managed unattended access until M03" | U6 `a11_unattended_minimum_is_capability_unavailable_*`; U0b `u0b_unattended_minimum_*`; matrix labels | all three |
| R-RT-05 (no blind replay) | U8 `run_retry_with_same_request_id_never_relaunches_automatically`; U5 `restart_reconciles_attempted_apply_never_reapplies`; U0b `u0b_restart_dispatches_every_operation_kind`; ⟨r3⟩ U0 `journaled_operation_kinds_match_their_request_kind`; U0b `w0_open_setup_and_catalog_operations_stay_unresolved_at_restart`; U4 `a22_update_crash_*` and `recovery_table_rows_each_have_a_test_vector` | all three |
| R-SE-04 (host trust never weakened) | U2 render refuses host-verification directives; U9 `host_key_substitution_fails_closed_and_nothing_written_to_known_hosts` (MANIFEST row 5 pattern on `LoopbackSshd`); U3 `known_host_mismatch` finding | all three |
| T06 clean local uninstall | U9 `uninstall_restores_user_bytes_and_effective_config_and_reports_remaining_items`, ⟨r2⟩ `uninstall_with_incomplete_rollback_keeps_artifacts_and_purge_refuses` | all three; the WSL distribution with a real home |

## 4. Platform evidence plan

The declared initial targets for M02 are the provisional G01 floors (ADR-0004 §4):

* **macOS arm64**: macOS 27, system OpenSSH 10.3p1 client. This is the build host.
* **Linux x86-64**: the owner's devbox, Ubuntu 24.04 (`linux-a` in M01); its client version
  is recorded at run time.
* **Windows 11 x64 26H2**: in-box OpenSSH 9.5p2 (E6). The PATH-first MSI 10.0p2 is recorded
  as a candidate, not selected.

WSL2 is supplementary Linux evidence; Mode A and Mode B are M04. Linux arm64 is declared but
has no native host.

| Harness | Pattern | M02 additions |
|---|---|---|
| `tests/native/m02/run-macos.sh` | `check.sh` + e2e on the build host | Starts `LoopbackSshd` from `/usr/sbin/sshd`, non-root. If that is `Unavailable` (`[U]`), it starts the M00-T03 Docker fixtures (`up.sh`, `127.0.0.1` only) and passes their ports; `down.sh` must print `CLEANUP CONFIRMED`. Disposable `ssh-agent -a` with a scratch `HOME`; `script(1)` and rustix ptys. Records Git's version and exchange support on APFS |
| `tests/native/m02/run-linux.sh <dir> <host>` | `tests/native/m01/run-linux.sh`: zig cross-build, copy to `~/hm-m02-<random>`, run under `nice` with a timeout, `rm -rf` exactly that directory | Records `ssh -V`, `sshd -V` and `git --version`. Starts `LoopbackSshd` on the host's `127.0.0.1`. Disposable `ssh-agent` in scratch with a scratch `HOME`. Never touches the host's `~/.ssh`, Git configuration or agent |
| `tests/native/m02/run-windows.sh <dir>` | `tests/native/m01/run-windows.sh`: x86_64-pc-windows-gnu, `%LOCALAPPDATA%\hm-m00\<task>-<random>`, non-elevated, through WSL interop | Starts the fixture sshd **in WSL scratch** on `127.0.0.1` (non-root, as in G03 §0.1) and passes `HM_FIXTURE_SSHD_{HOST,PORT,HOST_KEY}` to Windows tests (NAT localhost forwarding; ⟨r2⟩ checked on the actual host first, and a harness failure is recorded as such). The FakeAgent serves a `heimdall-hmtest-<random>` pipe. Pseudoconsole drivers from `tests/native/windows-launch/` for Ctrl-C and resize. ACLs are read with `icacls`/`Get-Acl`; file IDs with `fsutil file queryfileid`. Pipes are counted before and after. `\\.\pipe\openssh-ssh-agent` is never opened. Git runs with a scratch `HOME` and `GIT_CONFIG_NOSYSTEM=1` |
| `tests/native/m02/run-wsl-distro.sh` | G03 P-B08/09/10 disposable distribution (ADR-0004 §3): `wsl --import` from a pinned rootfs into scratch, never an export of an owner distribution | Inside it: a non-root user with a disposable home, the Linux `heimdall` binary, `LoopbackSshd`, a disposable `ssh-agent`. `setup apply` writes that user's real `~/.ssh/config`, then **ordinary `ssh alias`, `git`, `scp` and `sftp` without `-F`**, then `uninstall`. Afterwards `wsl --terminate` and `--unregister` **that distribution only**; never `wsl --shutdown` |
| Docker on the build host | M00-T03 image pattern | Supplementary Linux arm64: a disposable container user home, ordinary ssh without `-F`; ⟨r2⟩ records exchange support on the overlay filesystem (a missing exchange makes those rows manual mode, labelled). Labelled supplementary, never native arm64 |

Per-case platform rows. ✔ means a native run is planned; supplementary runs are labelled
as such.

| Case | macOS arm64 | Linux x86-64 devbox | Windows 11 x64 | WSL2 distribution | Blocked rows |
|---|---|---|---|---|---|
| A01 | ✔ scratch `-F` | ✔ scratch `-F` | ✔ scratch `-F`, fixture pipe agent | ✔ ordinary ssh, no `-F` | macOS and Windows ordinary-ssh-without-`-F` (B2, B3); Linux arm64 native (B9) |
| A11 | ✔ fixture + disposable ssh-agent lock + ⟨r2⟩ confirm-constrained key (⟨r3⟩ F23 signing control, inherited confirm-constrained fallback, fresh-eligibility cases) | ✔ same | ✔ fixture pipe states, ⟨r3⟩ fresh-eligibility and fallback-clearance cases with the fixture pipe agent | — | 1Password live (B1); Windows system agent, incl. its confirm-constrained row (B4); hardware touch (B6) |
| A21 | ✔ | ✔ | ✔ | — | — |
| A22 | ✔ client 10.3p1; ⟨r2⟩ APFS exchange; ⟨r3⟩ quarantine and crash-injection rows | ✔ devbox client; ext4 exchange; ⟨r3⟩ same | ✔ in-box 9.5p2, DACL and displaced-identity retention (⟨r3⟩ race-free only; the internal `ReplaceFileW` window stays `[U]`), ⟨r2⟩ junction reparse row; ⟨r3⟩ quarantine via `MoveFileExW` and handle deletion; symlink cases `platform_only` Unix | ✔ ext4 exchange | ⟨r2⟩ Windows file-symlink reparse row (B10) |
| A27 | ✔ pty | ✔ pty | ✔ pseudoconsole, batch rules, ⟨r2⟩ `spawned` record, launcher-kill holder row | — | interactive console Ctrl-C/resize observation (B5, P-W07) |
| A35 | ✔ real disposable ssh-agent × 4 clients × 2 paths × 5 fixtures | ✔ same | ✔ fixture pipe agent × in-box ssh, Git (System32 via the Q7 include and via run-time injection, and bundled MSYS as a recorded limitation), scp, sftp | ✔ ordinary path | 1Password all platforms (B1); Windows system agent (B4); Linux arm64 (B9) |

Records follow `tests/evidence/record.schema.json` and the lowest-row rule
(`tests/evidence/README.md`, ADR-0004 §4). A case with a blocked row is `blocked`, with the
input named. Its platform rows that ran may be `verified`. In-process reconstructions are
labelled as such, as in M01 N06.

## 5. Contract additions: final ADR-0006 revision 3 deltas

⟨r2⟩ This is the final form for the integrator (ADR-0007 §10 summarizes it). ⟨r3⟩ Items
4, 17 and 17a are **frozen in wave 0** (U0). All of these
are additive unless marked **changed**. Schema major stays `"1"` (ADR-0006 §9; the contract
is not frozen, §1). Every new enum is `#[non_exhaustive]` and `snake_case` on the wire.

1. **IDs.** `ids::IdentityId`, prefixed `idn`.
2. **`Request::Setup(SetupRequest)`**, tagged by `action`:
   * `Preview { intent: PreviewIntent }`: read-only, not journaled, no operation ID.
     `PreviewIntent` is tagged by `kind`:
     * `Apply { include_git: bool = false }`;
     * `Rollback { keep_key_files: bool = false, items: BTreeSet<ProjectionItem { ssh, git }>
       = {ssh, git} }`;
     * `Repair { conflict: ConflictKind, resolution: RepairResolution }`.
   * `Apply { plan_digest: PlanDigest, request_id }`.
   * `Rollback { plan_digest, request_id }`.
   * `Repair { plan_digest, request_id }`.

   `kind()` returns `"setup.preview"`, `"setup.apply"`, `"setup.rollback"` or
   `"setup.repair"`. Only Preview is not `is_effectful()`. `required_capability()` is
   `setup/1`. `requires_attended_session()` is false: the effectful actions are dispatched
   on any session, and the application creates an `ApplyProjection` decision when ADR-0007
   §5.2 requires one.

   Result types:
   * `SetupPlan { plan_digest, intent: PreviewIntent, mode: automatic|manual,
     manual_reasons: Vec<String>, files: Vec<FileChange>, git: Option<GitConfigChange>,
     aliases: Vec<AliasPreview>, consent: ConsentNeed, unaffected_names_checked: u32,
     findings: Vec<Finding> }`.
   * `FileChange { role: ProjectionFileRole { user_ssh, managed_ssh, key_file, git_include,
     git_managed }, path_display, before_sha256: Option<String>, after_sha256:
     Option<String>, diff: String (≤ 64 KiB) }`.
   * `AliasPreview { alias, kind: managed|observed, before: BehaviorSummary, after:
     BehaviorSummary, restore: Option<BehaviorSummary>, changes: Vec<BehaviorChange>,
     inherited: Vec<DirectiveObservation>, identity_selection: Option<IdentitySelectionReport> }`,
     where `BehaviorSummary { digest: String, directives: Vec<DirectiveObservation> }`.
   * `ConsentNeed { decision_required: bool, reasons: Vec<ConsentReason { item: String, kind:
     new_state|exposes_inherited|⟨r3⟩ undetermined_state|git_selection_changed }> }`. ⟨r3⟩
     `undetermined_state` replaces revision 2's `undetermined_changed`. It is given
     whenever an affected item's current or after state is undetermined (ADR-0007 §5.2,
     M2-R03).
   * `GitConfigChange { applicability: applicable|not_applicable, reason: Option<String>,
     global_file: Option<GitGlobalFile { path_display, ⟨r3⟩ file: home_gitconfig|xdg_config, resolution: first_read_existing|created }>,
     previous_values: Vec<GitValueObservation { scope: GitScope, origin_display: Option<String>,
     value_sha256: String, count: u32 }>, include_block: Option<FileChange>, managed_file:
     Option<FileChange>, effective_before: GitSshSelection, effective_after: GitSshSelection }`.
     For an applicable change, `previous_values` is empty (ADR-0007 §5.6). ⟨r3⟩
     `GitValueObservation` gains `conditional: bool` (reached through `includeIf`), and
     `GitGlobalFile` names the chosen `file` and its `resolution` (ADR-0007 §5.6
     first-read rule). Applicability counts
     the system and global scopes **including every file they include** (QR3 wording,
     §12.5 item 9). `reason` adds `git_config_unreadable`.
   * `GitSshSelection { source: env_git_ssh_command|config|env_git_ssh|default, scope:
     Option<GitScope>, classification: verified_client|bundled_msys|other|undetermined }`;
     `GitScope { system, global, local, worktree, command }`.
   * `SetupResult { generation: u64, items: Vec<ItemOutcome { item: ProjectionItem, outcome:
     applied|not_applied|restored|conflict_preserved, files: Vec<FileOutcome { role,
     path_display, state: applied|not_applied|restored|written_inactive|removed|conflict_preserved }> }>, remaining: Vec<RemainingArtifact { kind:
     backup|conflict_file|manual_block|state_store|recovery_record|⟨r3⟩ quarantine, path_display }> }`.
   * `PlanDigest` is transparent lowercase hex SHA-256.
   * `ConflictKind` = `user_config_changed | managed_file_edited | marker_edited |
     marker_duplicated | include_conditional | unmanageable_file | alias_collision |
     concurrent_writer | git_config_locked`.
   * `RepairResolution` = `rerender | remove_duplicate_markers | move_include_to_top |
     manual_mode`.
   * Manual reasons: `unmanageable_file`, `atomic_exchange_unsupported`,
     `unsupported_encoding`, `git_global_redirected`.
3. **`Request::Catalog(CatalogRequest)`**, tagged by `action`:
   * `UpsertDestination { destination: DestinationSpec { id: DestinationId, alias: String,
     definition: Managed { hostname, port: Option<u16>, account: AccountName, identity:
     IdentityId } | Observed, label: Option<String> }, request_id }`;
   * `RemoveDestination { id, request_id }`;
   * `AdoptIdentity { identity: IdentitySpec { source: NativeAgent { endpoint: EndpointRef } |
     OnePassword { endpoint: Option<EndpointRef> } | PublicKeyFile { path }, public_key: String
     (OpenSSH one-line public key), label }, request_id }`. It has no interaction field: the
     default comes from ADR-0007 §7;
   * `RemoveIdentity { id, request_id }`;
   * `UpsertProfile { profile: ProfileSpec { id: ProfileId, pairs: BTreeSet<AccessPairRef>,
     label }, request_id }`;
   * `RemoveProfile { id, request_id }`;
   * ⟨r2⟩ `DeclareInteraction { identity: IdentityId, interaction: DeclaredInteraction { none },
     request_id }`, which always creates a `DeclareInteraction` decision (QR1);
   * ⟨r2⟩ `WithdrawDeclaration { identity, ⟨r3⟩ revision: Option<u64>, reason: WithdrawReason
     { owner, listing_missing } = owner, request_id }`, narrowing, with no decision. ⟨r3⟩
     With `revision` it is a compare-and-swap: a newer declaration stays live and the
     result reports `withdrawn: false`. `listing_missing` is sent by the CLI after an
     explicit agent listing lacked the fingerprint (ADR-0007 §7; QR9). The result is
     `{ withdrawn: bool, revision: u64 }`.

   `EndpointRef { kind: unix_socket|named_pipe, locator: String }`. `kind()` is `"catalog"`,
   with the action in the hash extras.
4. **Capability `setup/1`.** It gates the Setup and Catalog requests; without it the answer
   is `SCHEMA_UNSUPPORTED`. A `LimitedConsumer` role gets `CAPABILITY_UNAVAILABLE`.
   ⟨r3⟩ **Fail-closed landing (frozen; M2-R07; ADR-0007 §12.5 item 7).** Until the
   activation change set lands (§2, wave 3):
   * `setup/1` is **not offered**: `ipc::session::server_capabilities()` and
     `inspect capabilities` omit it, so no session can negotiate it, and a hello that
     requires it is rejected with `SCHEMA_UNSUPPORTED` (ADR-0006 §2.3);
   * on a session, a Setup or Catalog request is answered `SCHEMA_UNSUPPORTED` by the
     existing gate and never dispatched (ADR-0006 §2.4, unchanged);
   * a Setup or Catalog request that reaches dispatch by any other path
     (`OperationsDispatcher::handle_as`, `Operations::{setup, catalog}`) is answered
     `CAPABILITY_UNAVAILABLE`, reason `driver_unavailable`, effect `none`. No operation,
     idempotency record, decision or event is written;
   * an open operation of a new kind found at restart stays unresolved and untouched, and
     a decision of a new kind is refused and stays pending;
   * the M02 CLI commands that have not landed return M01's "not available in this
     build" envelope.

   After activation `setup/1` is offered. A runtime with `OperationsConfig.projection =
   None` still answers Setup requests with `CAPABILITY_UNAVAILABLE` (`driver_unavailable`).
   ADR-0007 QR7 asks the orchestrator to confirm the session-layer code.
5. **Changed: `BindForm::Launch`.** It becomes `Launch(LaunchBinding { executable: String,
   holder: Option<ProcessHolder { pid: u32, started_at: String /* opaque OS start-time token */ }> })`.
   * Wire form: `{"form":"launch","executable":…,"holder":{…}}`.
   * `argv` is removed (Q8).
   * Validation: `executable` is absolute, 1–4096 bytes, with no NUL (a resolved path that
     is not Unicode is refused locally, reason `refused_path`); `holder.pid > 0`;
     `started_at` is 1–64 bytes of `[A-Za-z0-9._:-]`.
   * `MAX_ARGV_BYTES` leaves the contract and becomes a `heimdall-launch` limit.
6. **`RequiredCapabilities.unattended: bool`** (serde default `false`, omitted when false).
   It means new authentications need no human interaction until the deadline, including
   through desktop and vault lock. `Unknown` never satisfies it, so an unmet minimum gives
   `CAPABILITY_UNAVAILABLE`. CLI: `--require-unattended`. It is hashed with the other
   required capabilities.
7. **`EnsureData`** gains `credential_availability: CredentialAvailability` (serde default
   `unknown`) and `provider: Option<ProviderStatus>`.
8. **`ConsumerIntegration`** gains:
   * `executables: Vec<ConsumerExecutable { consumer: ConsumerKind { ssh, scp, sftp, git,
     ssh_keygen }, path, version: Option<String>, sha256: Option<String>, basis: EvidenceBasis }>`;
   * `overrides: Vec<ConsumerOverride { consumer, setting: String, source: OverrideSource {
     ssh_config(ConfigProvenance) | git_scope(GitScope) | environment } }>`;
   * ⟨r2⟩ `pairs: Vec<PairIntegration { destination: DestinationId, account: AccountName,
     identity: IdentityId, mechanism: String, endpoint: Option<EndpointRef>, alias:
     Option<String>, interaction: InteractionKind, interaction_basis: EvidenceBasis,
     declared_at: Option<Timestamp>, identity_selection: IdentitySelection,
     selection_observed_at: Timestamp, ⟨r3⟩ declaration: Option<DeclarationRef { revision:
     u64, endpoint: EndpointRef, expires_at: Timestamp }>, noninteractive:
     NoninteractiveEligibility { eligible: bool, reason: Option<String> /*
     interaction_unknown | provider_interaction | fallback_identity_interaction */ },
     eligibility_checked_at: Timestamp }>`.
     ⟨r3⟩ Which fields are history and which are fresh (M2-R04):
     * **history**, from `PreparedFacts`: `endpoint`, `alias`, `mechanism`,
       `identity_selection` and `selection_observed_at`;
     * **fresh**, computed in the transaction that builds each result: `interaction`,
       `interaction_basis`, `declared_at`, `declaration`, `noninteractive` and
       `eligibility_checked_at`. `noninteractive` uses the fresh interaction and the
       recorded selection; the CLI's pre-launch check repeats it with a fresh static
       selection (U8).

   All three default to empty and are omitted when empty.
9. **`contract::provider`:**
   * `ProviderKind { native_agent, onepassword, unknown }`;
   * `ProviderAvailability { available, locked, unavailable, unknown }`;
   * `InteractionKind { none, provider_approval, provider_unlock, hardware_presence,
     passphrase, unknown }`;
   * `EvidenceBasis { observed, documented, inferred, declared }`;
   * `ProbeLevel { static, evaluate, agent, network, host_verification, authentication }`;
   * `ProviderStatus { provider, availability, interaction, observed_level, observed_at,
     basis }`;
   * `CredentialAvailability { current_only, through_deadline, refresh_dependent,
     interaction_required, unknown }` (spec §4.3);
   * `ProviderInteractionRef { provider, kind }`;
   * ⟨r2⟩ `IdentitySelection { exclusive, not_exclusive, undetermined }` and
     `IdentitySelectionReport { selection, entries: Vec<IdentityEntry { kind:
     identity_file|certificate_file, source: managed|user|system|default, provenance:
     Option<ConfigProvenance>, certainty: determined|undetermined, ⟨r3⟩ fingerprint:
     Option<String>, backing: agent|file|unknown, cleared: Option<bool> }>, ⟨r3⟩
     identities_only: determined_yes|determined_no|undetermined }`. ⟨r3⟩ `cleared` is
     filled where a fallback clearance was evaluated (readiness, the pre-launch check,
     doctor), and is absent elsewhere (ADR-0007 §7, M2-R05).
10. **`NextAction.provider_interaction: Option<ProviderInteractionRef>`**, used with action
    `interact` for `PROVIDER_LOCKED` and for provider-owned `INTERACTION_REQUIRED`. It is
    never combined with `decision_ref` (spec §5.5).
11. **`contract::doctor`:**
    * `DoctorReport { levels_performed, levels_declined: BTreeSet<ProbeLevel>, clients:
      Vec<ClientObservation>, config_files: Vec<ConfigFileObservation { path_display, role:
      user|system|included|managed|git_global|git_managed, readable, sha256, bytes }>,
      aliases: Vec<AliasObservation { alias, definition: managed|observed|user_only, behavior:
      Vec<DirectiveObservation { directive, values, certainty: determined|undetermined|unset,
      provenance: Vec<ConfigProvenance { path_display, line }> }>, identity_selection:
      Option<IdentitySelectionReport> }>, providers: Vec<ProviderStatus>, projection:
      Option<ProjectionObservation { state: absent|healthy|conflict|manual|conditional,
      generation, conflict: Option<ConflictKind> }>, git: Option<GitObservation { selection:
      GitSshSelection, values: Vec<GitValueObservation> }>, findings: Vec<Finding>, probes:
      Vec<ProbeRecord> }`;
    * ⟨r2⟩ `ProbeRecord { level, target, started_at, duration_ms, outcome:
      ok|failed|timeout|refused|declined, decline_reason: Option<String>, code: Option<Code>,
      authorization: Vec<String> /* e.g. "allow_config_commands" */, executed_config_commands:
      Vec<ConfigProvenance>, effects_excluded: BTreeSet<ExcludedEffect { config_execution,
      agent_contact, provider_contact, network, signing, mutation }>, containment:
      none|process_group|job_object, ⟨r3⟩ config_tree_changed: Option<bool> }`. ⟨r3⟩
      `decline_reason` values: `config_commands_not_authorized` (every real-tree level
      without the flag) and `config_not_fully_readable` (ADR-0007 §6, M2-R06);
    * `Finding { code: String, severity: info|warning|problem, subject: ResourceRef, level:
      ProbeLevel, provenance: Option<ConfigProvenance>, message, next: NextAction }`.

    Finding codes, stable, `snake_case`, readers tolerate unknown ones:
    * configuration: `config_invalid`, `dynamic_match_unresolved`,
      `executable_directive_present`, `include_missing`, `include_conditional`,
      `include_not_first`, `projection_edited`, `marker_edited`, `alias_collision`,
      ⟨r2⟩ `identity_selection_not_exclusive`, ⟨r2⟩ `identity_selection_undetermined`,
      `identity_agent_overridden`, `too_many_identities`,
      `strict_host_key_checking_weak`, `config_permissions_unsafe`,
      `parse_unsupported_directive`, `bound_exceeded`, ⟨r2⟩ `unsupported_encoding`,
      ⟨r2⟩ `atomic_exchange_unsupported`, ⟨r2⟩ `conflict_artifact_present`,
      ⟨r3⟩ `displaced_missing`
      (revision 1's `inherited_identities` is withdrawn);
    * clients: `client_not_found`, `client_unsupported_version`, `git_ssh_unreachable_agent`,
      ⟨r2⟩ `git_ssh_command_present`, ⟨r2⟩ `git_global_redirected`,
      ⟨r2⟩ `git_config_lock_held`, ⟨r3⟩ `git_config_unreadable`, ⟨r3⟩ `git_user_value_shadowed`;
    * agents and identities: `agent_endpoint_missing`, `agent_endpoint_foreign_owner`,
      `identity_not_listed`, `identity_public_key_unknown`, `key_file_permissions_unsafe`,
      ⟨r2⟩ `interaction_unknown`, ⟨r2⟩ `interaction_declaration_lapsed`;
    * host trust: `known_host_missing`, `known_host_mismatch`;
    * environment: `home_mismatch`.

    Schema `schemas/public-api/doctor-report.json`.
12. **`contract::run_record::RunRecord`**, tagged by `type`:
    * `prelaunch_failed { schema_version, code, exit_code: i32, reason: Option<String>,
      operation_id: Option<OperationId>, binding_id: Option<BindingId> }`;
    * ⟨r2⟩ `launching { schema_version, attempt: u32 /* 1 */, executable, operation_id:
      Option, binding_id: Option, pid: u32, consumer_overrides: Vec<ConsumerOverride> }`. It
      records an attempt, not a launch;
    * ⟨r2⟩ `spawned { schema_version, pid: u32 }` (Windows launcher only; positive proof of
      launch);
    * `exited { schema_version, exit_code: i64 }` (Windows launcher only).

    ⟨r2⟩ `run_record::classify(&[RunRecord], RunPlatform) -> LaunchClassification {
    not_launched, launched, indeterminate }` is the pure, normative reader of ADR-0007 §8.
    Schema `run-record.json`.
13. **Code `LAUNCH_FAILED`.** Exit 127, or 126 when the reason is `not_executable`; it
    occurs only in `run` and `connect`. Retryable no, effect `none`, next `fix_request`.
    The golden table grows to 30 rows. Spec §11.6's code list gains it at G08, as ADR-0006
    §11 already plans for the baseline codes.
14. **`ErrorData.reason: Option<String>`.** A stable `snake_case` sub-reason:
    * the conflict kinds and manual reasons;
    * the launch reasons `not_found`, `current_directory`, `refused_batch_path`,
      `refused_argument`, `not_executable`, `exec_error`, ⟨r2⟩ `refused_path`,
      ⟨r2⟩ `meta_unavailable`;
    * the provider reasons `endpoint_absent`, `identity_not_listed`, ⟨r2⟩
      `provider_interaction`, ⟨r2⟩ `interaction_unknown`;
    * ⟨r2⟩ `mixed_mechanisms`, `config_commands_not_authorized`, `git_ssh_command_present`;
    * ⟨r3⟩ `driver_unavailable` (wave-0 landing and a runtime without a projection writer),
      `fallback_identity_interaction`, `config_not_fully_readable`,
      `git_config_unreadable`, `setup_in_progress`.
15. **Inspection and ports.**
    * `InspectSubject` gains `identities` and `projections`.
    * `ResourceRef.kind` gains the documented values `projection`, `identity`, `provider`
      and `executable`.
    * No new `EventType`: projection changes use `resource_changed` with payload
      `{generation, change: applied|rolled_back|repaired|restored|conflict}`, and decisions
      use `decision`.
    * Ports (app, integrator-owned):
      * ⟨r2⟩ `ProjectionWriter { preview(&ProjectionSpec, &PreviewIntent) -> ProjectionPlan;
        apply(&SetupIntent, &mut dyn StageSink) -> ProjectionReceipt; reconcile(&SetupIntent,
        &[StageReceipt], ⟨r3⟩ &mut dyn StageSink) -> Result<ProjectionReconcile,
        ReconcileError>; observe(&ProjectionRecord, &[AliasName]) -> Vec<AliasObservation> }`
        (U4). ⟨r3⟩ `ProjectionReceipt` and `ProjectionReconcile` both carry
        `items: Vec<ItemOutcome>`. `ReconcileError::UnreadableReceipt` leaves the
        operation unresolved;
      * ⟨r3⟩ `StageSink { append(&mut self, &LocalReceipt) -> Result<(), SinkError>;
        commit_item(&mut self, ItemCommit { item: ProjectionItem, generation: u64,
        resources: Vec<ProjectionLocator>, record: ProjectionRecord, consent: ConsentRecord })
        -> Result<(), SinkError> }`. `append` writes one `StageReceipt` per call, in its own
        store transaction, with `effect` fixed by the phase. `commit_item` writes
        `item.committed` together with the resources, the record and the consent in **one**
        transaction (`Txn::commit_projection_item`; M2-R01). U5 implements the sink over
        the store;
      * `ProviderProbe { provider(); detect(&DetectContext) -> ProviderStatus; async
        list_identities(&ProbeBounds) -> Result<IdentityListing, AdapterError> }`;
      * `ProcessLiveness { state(&ProcessHolder) -> HolderState { Alive, Exited, Unknown } }`.
    * `PrepareRequest` gains ⟨r2⟩ `pairs: &[PreparePair { destination, account, identity:
      IdentityRecord, alias: Option<AliasName> }]`.
    * `PrepareOutcome` gains `availability: CredentialAvailability`, `provider:
      Option<ProviderStatus>` and `integration: ConsumerIntegration`.
16. **Hash inputs.** These extend ADR-0006 §7.2:
    * `setup.apply`, `setup.rollback`, `setup.repair`: environment + `plan_digest` (the plan
      fixes the intent, its options and the files);
    * `catalog`: action + canonical spec;
    * `bind` (`Launch`): binding + `"launch"` + executable. `holder` is excluded as delivery
      metadata.
17. **Domain.**
    * ⟨r2⟩ `DecisionKind::ApplyProjection { operation: OperationId, plan_digest, summary:
      ProjectionSummary { intent: apply|rollback|repair, added_aliases, changed_aliases,
      removed_aliases, files: Vec<String>, git: bool, restore: Vec<ItemRestore { item,
      digest }>, diff_text: String (≤ 64 KiB) } }` (Q1; ADR-0007 §5.2);
    * ⟨r2⟩ `DecisionKind::DeclareInteraction { operation, identity: IdentityId, fingerprint,
      endpoint: EndpointRef, interaction: DeclaredInteraction, valid_until: Timestamp }` (QR1);
    * ⟨r2⟩ `operation::OperationKind::{SetupApply, SetupRollback, SetupRepair, Catalog}`;
      `RecoveryIntent.local: Option<LocalIntent>` (serde default, omitted when absent;
      ⟨r3⟩ add-only, U0b row 16). `LocalIntent` is tagged `kind`: `{"kind":"setup",…}`
      wraps `SetupIntent`, `{"kind":"catalog",…}` wraps `CatalogIntent`;
    * ⟨r3⟩ **Approval representations (frozen; M2-R07; ADR-0007 §12.5 item 7).** There is
      one type per decision kind, and each lives only in its own intent, so a mismatch
      cannot be represented:
      * `ProjectionApproval { decision: DecisionId, plan_digest: PlanDigest }`, only in
        `SetupIntent.approval`. `decide` writes it from an `ApplyProjection` record whose
        `plan_digest` equals the intent's;
      * `DeclarationApproval { decision: DecisionId, identity: IdentityId, fingerprint:
        String, endpoint: EndpointRef, interaction: DeclaredInteraction, valid_until:
        Timestamp }`, only in `CatalogIntent.approval`. `decide` copies it from a
        `DeclareInteraction` record's fields. The catalog driver builds the
        `InteractionDeclaration` from it and from nothing else;
      * a decision whose kind does not match its waiting operation's intent, or whose
        `plan_digest` or `identity` differs, is refused with `DECISION_STALE`, and
        nothing is applied;
      * revision 2's `LocalApproval { decision, plan_digest }` is withdrawn: it could not
        represent a declaration, which has no plan digest;
    * ⟨r2⟩ `domain::projection::{ProjectionSpec, ManagedAliasSpec, ProjectionRecord,
      ProjectionPlan, SetupIntent { plan_digest, intent, generation, ⟨r3⟩ approval:
      Option<ProjectionApproval>, consent: ConsentRecord, files: Vec<FileStep> }, FileStep {
      role, path, base: Base { absent | present { sha256 } }, target, commit: bool,
      staged_name, displaced_name }, FileIdentity, ProjectionLocator { role, path, identity,
      sha256 }, ConsentRecord { items: BTreeMap<ItemId, ConsentedStates { managed:
      ⟨r3⟩ BehaviorState, restore: BehaviorState, decision: DecisionId }> }, ⟨r3⟩
      BehaviorState { digest: BehaviorDigest, determined: bool }}`;
    * ⟨r3⟩ `FileIdentity` wire form: `{"platform":"unix","dev":<u64>,"ino":<u64>}` or
      `{"platform":"windows","volume":<u64>,"file_id":"<32 lowercase hex>"}`;
    * ⟨r3⟩ `domain::catalog::CatalogIntent { action: CatalogAction /* the request's action,
      canonical */, approval: Option<DeclarationApproval> }`. `approval` is `Some` only for
      a `DeclareInteraction` action;
    * `domain::catalog::{DestinationRecord, DestinationDefinition, IdentityRecord,
      IdentitySource, InteractionProfile, ⟨r2⟩ InteractionDeclaration { ⟨r3⟩ revision: u64,
      state: live|withdrawn|lapsed, interaction, fingerprint, endpoint, declared_at,
      expires_at, decision, ⟨r3⟩ ended_at: Option<Timestamp>, end_reason:
      Option<owner_withdrawn|listing_missing|endpoint_changed> }}`. ⟨r3⟩ Expiry is computed
      when read, never written;
    * ⟨r3⟩ `domain::catalog::{eligibility(&IdentityRecord, Option<&InteractionDeclaration>,
      current_endpoint: &EndpointRef, now) -> PairEligibility { interaction, basis,
      declaration: Option<DeclarationRef>, noninteractive }, fallback_clearance(&IdentitySelectionReport,
      &[IdentityRecord], &dyn Fn(&IdentityId) -> PairEligibility, endpoint: &EndpointRef) ->
      FallbackClearance { cleared, uncleared }}`. Both are pure, and their bodies are U0b
      phase 1's. They live in `domain` so that the runtime (U0b), the adapters (U6) and
      the CLI (U8) apply one rule (ADR-0007 §7);
    * `domain::holder::{ProcessHolder, HolderState}`;
    * ⟨r2⟩ `resource::OwnerRef::Projection { environment: EnvironmentId }` for projection
      resources;
    * ⟨r2⟩ `PreparedFacts` ⟨r3⟩ `{ provider: Option<ProviderStatus>, executables, overrides,
      environment, pairs: Vec<PreparedPair { destination, account, identity, mechanism,
      endpoint, alias, identity_selection: IdentitySelectionReport, selection_observed_at }>,
      recorded_at }`. It is **history only**: it has no availability, interaction or
      eligibility field, so a stored fact cannot re-establish `interaction: none`
      (M2-R04). Revision 2's `{ availability, provider, integration, recorded_at }` is
      replaced.
17a. ⟨r3⟩ **Typed local receipt payload (frozen; M2-R07; ADR-0007 §5.7).**
    * **Type.** `heimdall_domain::operation::StageReceipt` gains `#[serde(default,
      skip_serializing_if = "Option::is_none")] local: Option<LocalReceipt>`. For a local
      receipt, `stage` is `"setup.file"` or `"setup.item"`. Its `effect` is fixed by its
      phase: `Confirmed { adapter: config_projection/<environment>, credential_ref:
      "projection/<item>/<generation>" }` for `item.committed` and
      `item.finished{applied}`, and `Attempted { adapter, effect_token }` for every
      other phase.
    * **Variants:**
      * `LocalReceipt`, tagged `scope`: `file { step: u16 /* index into
        SetupIntent.files */, phase: FilePhase }` | `item { item: ProjectionItem, phase:
        ItemPhase }`;
      * `FilePhase`, tagged `kind`:
        * `staged { identity: FileIdentity }`;
        * `validated { base: Option<FileIdentity> }`, where `None` means absent;
        * `exchanged`;
        * `post_validated { verdict: valid|mismatch, observed: Option<FileIdentity> }`;
        * `restore_started { cause: file_mismatch|transaction_check }`;
        * `restored`;
        * `restore_conflict { preserved: Vec<PreservedEntry { name: String, identity:
          Option<FileIdentity> }> }`;
        * `settling { source: displaced|staged|path, expected: FileIdentity, slot: String }`;
        * `settled { disposition: quarantined|nothing_displaced }`;
        * `settle_conflict { found: missing|foreign, kept: Vec<PreservedEntry> }`;
      * `ItemPhase`, tagged `kind`: `committed { generation: u64 }`,
        `rolling_back { reason: ConflictKind }`, `finished { outcome:
        applied|not_applied|restored|conflict_preserved }`.
    * **Serialization.** The existing `stage_receipts.record_json` column, as serde JSON
      with `snake_case` names. Example:
      `{"stage":"setup.file","recorded_at":"2026-11-01T00:00:00Z","effect":{"kind":"attempted","adapter":{"mechanism":"config_projection","instance":"<environment id>"},"effect_token":"<token>"},"local":{"scope":"file","step":1,"phase":{"kind":"exchanged"}}}`.
      Goldens for every variant are in U0's `local_receipt_wire_forms`.
    * **Defaults for old rows.** A receipt without `local` (every M01 row) decodes to
      `None` and re-encodes byte-identically. The M01 readers (`next_stage`,
      `effect_so_far`, `last_token`, `may_have_external_effect`, `grant_adapters`,
      `grant_has_effect_receipt`) are unchanged. Setup operations pin no grant
      (`resolved` is `None`), so their receipts never enter the grant queries.
    * **Migration behaviour.** `0005_existing_access` adds tables only. It rewrites
      neither `stage_receipts` nor `recovery_intents`, and backfills nothing. The 0004→0005
      test checks that a populated v4 database's receipts and intents decode unchanged and
      re-encode byte-identically.
    * **Unknown content.** These domain enums are exhaustive, so an unknown phase or scope
      fails to decode. The setup driver then leaves that operation unresolved, reports it
      (`runtime_lifecycle`, `unreadable_receipts`), and infers nothing. Other operations
      are unaffected, because only the setup driver reads setup receipts. Adding a phase
      requires an ADR-0007 revision with a migration note.
18. **Store.** ⟨r3⟩ The bodies are U0b phase 1's (row 20).
    * Migration `0005_existing_access`, `SCHEMA_VERSION` 5:
      * tables `destinations` (alias unique) and `identities` (fingerprint unique);
      * ⟨r2⟩ `interaction_declarations` ⟨r3⟩ (one row per identity, never deleted,
        `revision INTEGER NOT NULL`, the record as JSON; every write is a CAS on the
        expected revision);
      * `binding_holders`;
      * ⟨r2⟩ `grant_prepared_facts` (one row per grant, nonsecret, ⟨r3⟩ history only);
      * ⟨r2⟩ `projection_consent` (per item: consented managed and restore ⟨r3⟩
        `BehaviorState`s, decision);
      * projection records in the existing `resources` table (kind `config_projection`,
        owner `projection`, locator = canonical `ProjectionLocator`);
      * ⟨r3⟩ no change to `stage_receipts` or `recovery_intents` (item 17a).
    * `Txn` methods: `{upsert,remove}_destination`, `destination`, `destination_by_alias`,
      `destinations`, `{upsert,remove}_identity`, `identity`, `identities`,
      ⟨r3⟩ `put_interaction_declaration(&IdentityId, expected_revision: u64,
      &InteractionDeclaration)`, ⟨r3⟩ `end_interaction_declaration(&IdentityId,
      expected_revision: Option<u64>, reason, at) -> Result<EndOutcome { ended: bool,
      revision }>`, ⟨r2⟩ `interaction_declaration`,
      `projection_resources`, `put_projection_resource` (generation CAS),
      ⟨r2⟩ `{set,get}_projection_consent`, `set_binding_holder`, `binding_holders`,
      ⟨r2⟩ `set_grant_prepared_facts`, ⟨r2⟩ `grant_prepared_facts`,
      ⟨r3⟩ `commit_projection_item(&OperationId, &ItemCommit, &StageReceipt)`, which writes
      the `item.committed` receipt, the resources, the projection record and the consent
      in one transaction (M2-R01), ⟨r3⟩ and `open_setup_operations(&EnvironmentId) ->
      Vec<OperationId>` (open or unresolved setup kinds; `setup_in_progress`).
    * `Store::open_read_only`.
19. **Config.**
    * An optional `[clients]` table (`ssh`, `scp`, `sftp`, `git`, `ssh_keygen`: absolute
      paths to existing regular files) with `deny_unknown_fields`.
    * ⟨r2⟩ `[setup] declaration_validity_days` (default 30, range 1–90; QR1).
    * `FORBIDDEN_KEYS` is unchanged, and config still carries no socket paths.

## 6. Questions for the orchestrator

The authority-semantics questions are in ADR-0007: Q1–Q8 with their rulings (§12.1, §12.2),
⟨r2⟩ QR1–QR6 raised by revision 2 (§12.3, ruled in §12.4), and ⟨r3⟩ QR7–QR11 raised by
revision 3 (§12.6, open). Units build against the recommended answers. P1 and P2 were
ruled in ADR-0007 §12.1, and P3–P6 in §12.4 (P5 as there qualified). ⟨r2⟩ The plan-level
questions of revision 2, none of them authority semantics:

* **P3.** Accept the thirteen-unit split, with the M01 integration as integrator unit U0b
  landing together with U0. *Recommended: yes* (M2-D08; no worker unit then needs write
  access to M01 dispatch code).
* **P4.** Withdraw `setup preview --evaluate` (ADR-0007 §5.1). *Recommended: yes*: preview
  stays executable-free, and the doctor `evaluate` level, with `--allow-config-commands`,
  is the one authorized evaluation path.
* **P5.** How to get the exchange primitive. *Recommended:* U0 checks whether a reviewed
  safe wrapper at its pinned version (for example rustix `fs` `renameat_with`) provides
  both Linux `RENAME_EXCHANGE` and macOS `RENAME_SWAP`. If so, it becomes a normal
  dependency of `heimdall-localenv`; if not, `sys.rs` calls them through FFI with the
  invariants documented.
* **P6.** One mechanism per grant in M02 (`mixed_mechanisms`, ADR-0007 §7). *Recommended:
  yes*; revisit when M03 adds managed credentials beside existing access.

⟨r3⟩ Plan-level questions raised by revision 3. None is authority semantics; those are
ADR-0007 §12.6, QR7–QR11:

* **P7. U0b in two phases, with the store bodies moved into U0b** (§2; U0b). Phase 1
  lands with U0 in wave 0: every M01 change, fail closed, the M02 store bodies, and the
  domain eligibility and clearance rules. Phase 2 lands with U5 in wave 3 as one
  activation change set. *Recommended: yes.* It is the only layout in which wave 0 has no
  reachable `todo!()`: U0b's eligibility code reads the catalog and declaration tables,
  whose bodies were U5's in revision 2 (M2-R07 item 3).
* **P8. Setup operations serialized per environment** (`setup_in_progress`, ADR-0007
  §5.7). *Recommended: yes.* The recovery table and the quarantine assume one Heimdall
  writer of the projection files at a time. Refusing a second operation is simpler and
  safer than queueing it.
* **P9. B_git in the first-read global Git file** (ADR-0007 §5.6). When both global files
  exist, this means the XDG file rather than `~/.gitconfig`. *Recommended: yes.* It keeps
  every later user value winning (M2-R08 fixtures). The decision preview names the file,
  and the owner's authority (QR3, Q7) is unchanged. The remaining case, an XDG file
  created after apply, is reported as `git_user_value_shadowed`.

## 7. Items blocked on owner-only inputs

Each item names the exact input. The work that does not need it proceeds, and rows that do
stay `blocked` (AGENTS.md).

| ID | Missing input | Blocks |
|---|---|---|
| B1 | A **disposable 1Password account** with disposable SSH keys, on a host where its agent may run (ADR-0004 §3, P-W10) | the live rows of A35 and A11 for 1Password on every platform (listing while locked `[U]`, approval prompts, Windows pipe takeover F18). Detection and fixture-level behaviour proceed |
| B2 | **The disposable second Windows account** (one elevation consent; ADR-0004 §3, P-W05) | the native Windows "ordinary ssh without `-F`" row of A01 and A35 (a real `%USERPROFILE%\.ssh\config`); cross-user checks on the projection and pipes |
| B3 | **A disposable macOS standard user account** (admin consent to create it and delete it afterwards) | the native macOS "ordinary ssh without `-F`" row of A01 and A35. This is a new ask, not in ADR-0004 |
| B4 | **A disposable Windows host** whose system `ssh-agent` service may hold test keys (ADR-0004 §3, P-W11) | the live rows of the Windows native agent (system pipe) in A35 and A11, ⟨r2⟩ including its confirm-constrained-key row |
| B5 | **An operator at the Windows console** (ADR-0004 §3, P-W07, P-A06) | the interactive-console Ctrl-C and resize observation in A27 (pseudoconsole rows proceed); the observation that setup and run raise no UAC prompt |
| B6 | **A hardware security key** (FIDO2) owned for testing | the live touch-required row of A11. The synthetic `sk-` public key covers the non-interactive refusal |
| B7 | **The owner as participant**: a short walkthrough of setup and ordinary ssh on a disposable account; and observed runs of the owner's correctly configured workflows for the G01 baseline worksheet (ADR-0001 §6, ADR-0004 §4) | the human part of "a participant can connect without a mandatory work wrapper"; the existing-access worksheet rows (P2) |
| B8 | **Owner authorization for the Linux devbox to run Docker or create a disposable local user**, only if wanted beyond the WSL distribution | nothing in the exit: the WSL disposable distribution covers Linux ordinary ssh without `-F`. Listed so the gap is explicit |
| B9 | **A native Linux arm64 host** (ADR-0004 §4) | the arm64 rows; Docker on the build host is supplementary only |
| B10 ⟨r2⟩ | **Windows Developer Mode on the Windows PC, or one elevation**, to create a file symbolic link (only if Developer Mode is off; checked by the harness without changing it) | the Windows file-symlink row of A22's reparse-point refusal. The junction row needs neither and proceeds |

## 8. Handed to later milestones

| Item | Milestone |
|---|---|
| Heimdall signing endpoints, managed credentials, CertificateFile in P, multiplexing control | M03 (ADR-0005) |
| ⟨r2⟩ Grants mixing existing-access and managed mechanisms (P6) | M03 |
| WSL Mode A executable/Git/path behaviour as a product path, Mode B bridge, bastion ProxyJump in P, forwarding | M04 |
| Personal standing policies and the first-trust disclosure (if Q3 is accepted as recommended) | M05-T02 |
| Export and import of the catalog as portable intent | M05 (A18) |
| ⟨r2⟩ A `RequiredCapabilities.exclusive_identity` minimum, if a caller needs one (QR4) | when requested; not before G08 freeze without a revision |
| Final TUI information architecture (A20) | M07 |
| Fuzzing of `sshconf::parse_file`, `sshconf::gitedit` and `ipc::agent_client`; support bundles | M08 |
| ⟨r3⟩ Snapshot evaluation: probes against a validated immutable copy of the configuration tree, needing proven path equivalence (ADR-0007 §6, §12.5 item 6) | when proposed with that proof; not in M02 |
| ⟨r3⟩ A native test that injects a replacement inside `ReplaceFileW` (ADR-0007 §5.9 item 2) | when an independently justified harness exists; the claim stays `[U]` until then |

## 9. ⟨r2⟩ Change log (revision 2, task M02-T00-design-fix)

| Finding | What changed in this file |
|---|---|
| M2-D01 | U2 `identity_selection` and its tests; U3 doctor finding test and `corpus_identity_list_matches_ssh_g`; U6 `pairs` with selection, `prepare_reports_not_exclusive_*`; U9 A35 tests: wrong key with exclusive selection, inherited fallback agent- and file-backed; §3 A11/A35 rows; §5 items 8, 9, 11 |
| M2-D02 | U4 commit-point tests (first adoption, update, crash after P's exchange, update never writes the user file); U5 restart tests; §5 item 17 `SetupIntent`/`FileStep` |
| M2-D03 | U4 `replace` interface, `ReplaceHook`, race-injection, same-bytes and identity cleanup tests, exchange support; U0 dependency note (P5); §3 A22 row (unsupported cases not counted); §4 rows |
| M2-D04 | U2 `consent` and `behavior_digest`; U5 decision flow and rollback/repair tests; U9 setup commands show the restore column; U10 modal; §5 items 2 (`ConsentNeed`, restore), 17 (`ConsentRecord`), 18 (`projection_consent`) |
| M2-D05 | U6 default `unknown`, `state::interaction_profile`, declaration tests; U8 confirm-constrained, declared and multi-pair tests; U7 `DisposableSshAgent` with askpass; U9 `declare-interaction`; §5 items 3, 8, 17, 18, 19; §7 B4 |
| M2-D06 | U2 `executing_constructs`; U3 probe records, authorization and hook classification tests; U7 `hook`; U9 `--allow-config-commands`; U10 authorization modal; `--evaluate` removed from preview (P4); §5 items 2, 11 |
| M2-D07 | U8 `meta` protocols, test-only pre-exec hooks and the five new launch-metadata tests; U0 `run_record_classify_golden`; §5 item 12 |
| M2-D08 | New unit **U0b** with the exact M01 functions and types and end-to-end tests; §0 ownership; §2 order (thirteen units); U5 e2e tests through the dispatcher and store; §5 items 15, 17, 18 |
| M2-D09 | §0 fixture rules (isolation-only command line, decoy agent, default-identity guard, agent `HOME`); U7 `ScratchHome` (old `ssh_command` removed), `CountingProxy`; U9 two-agent assertions and the mutation test |
| M2-D10 | U2 `gitedit` and the Git render rules; U3 `git.rs` and its tests; U4 `projection::git` and ten Git tests; U8 Git run resolution and four tests; §5 items 2 (`GitConfigChange`, `GitSshSelection`), 8, 11, 12 |
| Q5, Q6, Q8 qualifications | U8 holder tests (Unknown never releases; Windows launcher); U9 uninstall/purge test; U8 argument-canary test |
| Review A22/A27 notes | U3 `bom_and_crlf_acceptance`; U4 manual-mode encoding test; U8 SIGPIPE test renamed as a recorded limitation |

## 9.1 ⟨r3⟩ Change log (revision 3, task M02-T00-design-fix-2)

Source: `tests/evidence/artifacts/review-m02-design/round2.md`, rulings ADR-0007 §12.5.

| Finding | What changed in this file |
|---|---|
| M2-R01 | U4 `replace` split (no settlement inside the primitive; `restore` and `settle` called by the transaction), `ReplaceHook` points `AfterPostValidate`/`BeforeCommit`, `apply` commits through `StageSink::commit_item` before settling; U4 tests `a22_update_user_edit_after_p_post_validation_restores_generation_n`, `a22_update_crash_between_post_validation_and_commit_reconciles`, `a22_update_crash_after_commit_before_settlement_settles_never_restores`, `a22_update_user_edit_after_commit_is_reported_not_restored`, `a22_settlement_never_precedes_item_committed`; U5 sink; §5 items 15 (`StageSink`), 17a (`item.committed`), 18 (`commit_projection_item`) |
| M2-R02 | U4 quarantine interface and `observe_step`, `reconcile` with a sink implementing ADR-0007 §5.7's table; U4 tests `recovery_table_rows_each_have_a_test_vector`, crash injection before/after the restore exchange and before each settlement receipt, displaced-entry removal and replacement, quarantine enforcement, `production_code_never_unlinks_outside_quarantine`, cleaner retry; U3 `sys::QuarantineDir`; U5 `setup_in_progress`; U9 quarantine reporting; U11 matrix; §5 items 2, 11, 14, 17a, 18; P8 |
| M2-R03 | U2 `BehaviorState`, `consent` interface, tests `consent_undetermined_current_or_after_always_needs_decision` and `consent_match_exec_command_changed_with_same_candidates_needs_decision`; U5 decision flow and `rollback_after_match_exec_command_edit_needs_decision`; §5 items 2 (`undetermined_state`), 17 (`ConsentRecord`), 18 |
| M2-R04 | U0b rows 4–6, 22 and tests `u0b_eligibility_is_recomputed_per_result_never_taken_from_prepared_facts`, `u0b_prepared_facts_have_no_interaction_field`, `domain_eligibility_rule_table`; U5 declaration CAS and `declaration_changes_between_ensure_and_bind_are_seen_through_the_dispatcher`; U6 delegation and `prepared_facts_from_outcome_drop_interaction_fields`; U8 `eligibility::check_noninteractive`, pre-check pause and clock hook, five fresh-eligibility tests (each also across a restart); U9 lapse recording; §5 items 3 (`WithdrawDeclaration { revision, reason }`), 8 (history vs fresh fields), 17 (`InteractionDeclaration` revision/state, `PreparedFacts` history only), 18 |
| M2-R05 | U2 identity entry `fingerprint`/`backing`; U0b `domain_fallback_clearance_rule_table`; U6 `state::fallback_clearance`, `prepare_marks_uncleared_fallback_entries`; U8 pre-launch selection re-evaluation and four fallback tests (confirm-constrained inherited key with controls, cleared alternative, file-backed never cleared, entry added after `ensure`); U3 fallback variant; U9 A35 inherited-fallback assertions; §5 items 8, 9, 14 |
| M2-R06 | U2 `unreadable_includes`; U3 probe gating (always for real-tree levels), `config_tree_changed`, `ProbeHook`, tests `a21_inert_config_still_requires_allow_config_commands`, `a21_match_exec_inserted_after_static_pass_never_runs_unauthorized`, `a21_unreadable_include_declines_even_with_authorization`, renamed host-verification test; U9 rules and `a21_cli_inert_config_still_prompts_for_allow_config_commands`; U10; §5 items 11, 14; §8 snapshot mode |
| M2-R07 | Skeleton rule stated fully (no reachable `todo!()`, fail-closed bodies); U0 frozen interfaces, CLI stubs, `journaled_operation_kinds_match_their_request_kind` (journaled kinds only; `Probe` documented as reserved), `local_receipt_wire_forms`, `approval_wire_forms`, migration byte-identity; U0b two phases, rows 1, 10, 12 revised, rows 16–22 added, store bodies moved from U5, wave-0 acceptance tests `w0_*`, phase-2 tests; U5 ownership and activation; §2 order (activation change set); §5 items 4 (fail-closed landing), 17 (`ProjectionApproval`, `DeclarationApproval`, `CatalogIntent`; `LocalApproval` withdrawn), 17a (typed local receipt payload: type, serialization, old rows, migration, unknown content), 18; P7 |
| M2-R08 | U7 askpass `approve`/`deny`, `sign_control`, `f23_confirm_constraint_installed_prompts_per_signature_and_is_not_listed`; U8 confirm-constrained test with verified installation and a discriminating control; U4 Windows test renamed `…_without_race` (window stays `[U]`); U3 `--includes`, include-graph scan, five discriminating Git fixtures, resolution by read order; U4 both-global-files and shadowing tests; U11 records; §5 item 2 (`conditional`, `first_read_existing`); P9; §8 row |
| QR3 wording | §5 item 2 applicability text (system and global scopes, including included files) |
