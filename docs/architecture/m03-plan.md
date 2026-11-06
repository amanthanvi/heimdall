# M03 work breakdown (managed credentials and meaningful deadline behaviour): revision 2

**Status:** proposed, revision 2 (tasks M03-T00-design and M03-T00-design-fix).
* Revision 1 had two independent reviews, both "proceed after fixes":
  `tests/evidence/artifacts/review-m03-design/round1-a-codex.md` (findings M03-R01–R15) and
  `round1-b-opus.md` (F01–F27).
* **Revision 2** applies them under the orchestrator's rulings, ADR-0008 §17.1 items 1–18 and the Q/P
  amendments. Text changed by it is marked **⟨r2⟩**, and §9 maps each finding to its changes.
* Where a ruling could not be applied as written, the ruling is kept and ADR-0008 §17.2 (Q18–Q21)
  asks the question.
* Round 2 re-reviews this revision (P9 as accepted).

**Inputs:**
* plan §5 M03 (T01–T06, exit evidence), §3 G04 and G09, §6, §10, §13 (the eleven requirements M03
  owns: R-UX-03, R-AU-04, R-AU-05, R-AU-08, R-CR-02 to R-CR-07, R-SE-07);
* spec §4.3, §6, §7, §8.1, §8.7, §10, §11.3–§11.6, §13.2–§13.6, §14, §15.1–§15.2, §16, and §17 A03,
  A07, A09, A10, A23, A33, plus the cases those requirements cite (A05, A08, A11, A24, A28, A30, A31);
* `docs/decisions/0008-managed-credential-integration.md` ⟨r2⟩ revision 2, this plan's design ADR
  (below: "ADR-0008"), with its §17.1 rulings and §17.2 questions;
* ⟨r2⟩ the round-1 review records above;
* ADR-0005 (recipe B1, accepted), which ADR-0008 implements;
* ADR-0006 revision 3 through §15, with §13.1–§13.20 ruled. This plan extends it with the revision-4
  deltas of §5;
* ADR-0007 revision 5 with §12.1–§12.41, including its §13 residuals for M03;
* ADR-0004 (the delegated decisions, the ADR-0004 §2 lock rule, the ADR-0004 §3 authorizations);
* `docs/research/g04-managed-credentials.md`;
* `docs/architecture/{m01-plan,m02-plan,m02-exit-draft,overview,dependencies}.md`;
* `tests/fixtures/MANIFEST.md`;
* `progress.md`, for blocked inputs B1–B10 and lessons.

**Basis:** the code at ⟨r2⟩ `7f6f1c05` (M02 code as of `491d8f5a`). M02's exit is not closed, and its
Windows native fixes are still landing. Every dependency on an M02 internal that may still change is
marked **⟨M02?⟩** and listed in §0.4.

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

**Not decided by this plan:** ⟨r2⟩ ADR-0008 §17.2 Q18–Q21 (Q1–Q17 and P1–P9 are ruled in §17.1).
Units build against the recommended defaults stated there. Where a unit depends on one, it says so, and
the integrator flips the switch if the ruling differs.

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
  * **M03 exception:** the production verification (ADR-0008 D5 §6.5), `connect`'s managed options
    (D10 item 4) and ⟨r2⟩ the remote steps' target and existing-access pins (D5 §6.3) are **product**
    command lines, under test like any product output. ADR-0007 §9 item 1 is about tests isolating the
    configuration under test; a product step pinning its approved target is a different matter (§17.1
    item 2).
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

  The pty transcript of an issuer ceremony is the **one** place the passphrase may appear (A33). ⟨r2⟩
  The backup interop check drives stock `ssh-keygen` through a pty as well, typing the passphrase at its
  prompt. **No passphrase ever appears in argv**, in tests included (§17.1 item 17; M03-R14).
* ⟨r2⟩ **Product-store evidence.** Only a **release-profile** build run on the platform's **product
  store kind** counts for a custody-dependent claim (ADR-0008 D12 item 3; F03). On Windows such a run
  uses `HEIMDALL_HOME` in scratch with real DPAPI. On macOS it needs the login keychain of a disposable
  account (B3). Test-store runs are mechanism evidence and are labelled so.
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
wave 0 did, and records any delta as an ADR-0008 revision. ⟨r2⟩ Re-checked against `7f6f1c05`, whose M02
code is `491d8f5a`.

| # | Assumption | Used by |
|---|---|---|
| M1 | `CredentialAdapter` keeps `read_sources`/`prepare_from`/`renew`/`reconcile`/`revoke` and the drop contract (`app::ports`, ADR-0007 §7). ⟨r2⟩ M03 extends it explicitly with `IntegrationSnapshot.managed` and the `ManagedEffects` port (ADR-0008 D6 item 0); existing-access adapters are unchanged | U6, U0b |
| M2 | `PrepareOutcome`, `ConsumerIntegration.pairs` and `PreparedFacts` keep their shapes (ADR-0006 §15.1 items 7, 8, 15) | U6, U0b |
| M3 | The projection P, its closed directive set, `ProjectionWriter`'s stateless contract and the setup operations stay as committed. In particular the Windows `RenderPath::windows` behaviour for verbatim paths, which the Windows failure group 1 at `cb16c2d6` is changing. ⟨r2⟩ **Changed at `491d8f5a`:** `localenv::paths::display_path` now shows `/` separators on every platform (`~/…` under the home; ADR-0007 §12.26 item 7). Every M03 path **display** (`registry.path_display`, slot and binding file displays, bundle entries, the TUI) goes through it and is never parsed back. **Rendered** paths in P keep ADR-0007 §4's rules | U8, U5, U6, U12 |
| M4 | The Windows projection replace (`ReplaceFileW` with backup) is fixed for the sharing-violation and `NotFound` failures at `cb16c2d6`. U8's slot files on Windows reuse that primitive | U6, U8 |
| M5 | Launch and connect hold the binding through `BindForm::Launch { executable, holder }` with `ProcessHolder { pid, start-time token }`, and `run` execs on Unix and spawns-and-waits on Windows (ADR-0007 §8). ⟨r2⟩ Observed at `7f6f1c05`: `run` registers its **own** PID as holder (`run_cmd.rs`); Windows `run` spawns a separate child with **no job object** (`launch/windows.rs`); `connect` **binds nothing** (`connect_cmd.rs`). ADR-0008 D8 item 2 changes the latter two for managed launches | U7, U8 |
| M6 | The catalog stays as committed: `DestinationDefinition::Managed { hostname, port, account, identity }`, one account per managed destination; ⟨r2⟩ identities are agent-held or key-file only (`IdentitySource`), so a password-only account cannot be enrolled (ADR-0008 D5 §6.1) | U5, U8, U0b |
| M7 | The Windows harness's WSL fixture sshd account mapping (at `cb16c2d6` it authenticates only the WSL account while clients log in as the Windows user) is fixed or explicitly parameterized | U11, U13 (Windows rows) |
| M8 | The evidence generator (`tests/native/m02/m02-evidence.py`), the case index format and `run-windows-local.ps1`'s bundle format stay as committed | U13 |
| M9 | The migration sequence ends at `0005_existing_access` (`SCHEMA_VERSION` 5) | U0 |
| M10 | `localenv::known_hosts` reads known-hosts files passively, including hashed entries. ⟨r2⟩ Observed: it returns **fingerprints only** (`HostKeyObservation { key_type, fingerprint, origin_display, revoked }`). U5 adds raw public keys for the `TargetEvaluator` (ADR-0008 §17.1 item 12) | U5 |
| M11 | The M02 static evaluator determines HostName, Port, User and route directives for a managed alias, with explicit `undetermined` | U5, U8 |
| M12 | `testcfg`'s env-gated pattern and `ScratchHome::isolation_args` stay as committed | U11, all tests |
| ⟨r2⟩ M13 | **The Windows native fixes are still landing** in `heimdall-localenv` (projection, `sys/quarantine.rs`), `heimdall-launch` and `heimdall-testkit`. M03 edits in those crates (U7's `JobObject::spawn_contained` in `localenv/src/sys/mod.rs`, U8's launch-flow changes, U11's testkit extensions) are made **after** those fixes land, by rebasing onto them. Where a fix changes an interface M03 calls, the integrator re-checks and records it | U7, U8, U11 |
| ⟨r2⟩ M14 | `localenv::sys::JobObject` keeps its kill-on-close job with no breakaway (`kill_on_close`, `assign_child`), as the probes use it | U7 |
| ⟨r2⟩ M15 | `TimeGate::peek` and `check` both use a store **transaction** (`timegate.rs`), and `check` writes the high-water mark. M03 adds `assess_read_only`, which needs neither (F21) | U3, U2 |
| ⟨r2⟩ M16 | The store releases its connection mutex when a transaction returns (`store/src/lib.rs`), which is why the signing gate exists (ADR-0008 M-F24) | U2, U0b |

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


### 0.6 ⟨r2⟩ The crate graph (ADR-0008 §18; §17.1 item 12)

Production edges, checked against the manifests at `7f6f1c05`. New edges are marked **+**.

```text
registry (new, pure) → contract, domain
app        → contract, domain, store, + registry
credential (new)     → contract, domain, ipc, app
issuer (new)         → contract, domain, store, app, credential
enroll (new)         → contract, domain, registry, app
localenv   → (unchanged)          implements app::ports::TargetEvaluator
adapters   → …, + credential      implements app::ports::ManagedEffects
runtime    → …, + credential, + issuer, + enroll
heimdall   → …, + issuer, + enroll
testkit    → …, + [credential], + [issuer]   (optional feature `managed`)
```

* `app` never depends on `credential`, `issuer`, `enroll`, `adapters`, `localenv` or `runtime`. Those
  edges run through ports.
* The `check.sh` step `crate-graph` (U0, `tools/validation/crate_graph.py`) enforces this, and fails
  on any production cycle.
* Dev-dependency cycles through `testkit` are allowed, as for `ipc` today.

---

## 1. Units

Fifteen units: **U0** and **U0b** (the integrator's), and **U1–U13**. Crate and module names follow
ADR-0008 §18.

### U0: Integrator skeleton and contract revision 4

* **Owner:** the integrator.
* **Owner paths:**
  * the root `Cargo.toml` and `Cargo.lock`;
  * the new crate manifests and skeleton `lib.rs` files for `crates/{credential,issuer,enroll}` and
    ⟨r2⟩ `crates/registry` (the pure remote-registry protocol crate, §0.6);
  * ⟨r2⟩ `tools/validation/crate_graph.py` and its `check.sh` step `crate-graph` (§0.6);
  * ⟨r2⟩ the `SecretStore` trait in `crates/issuer/src/store/mod.rs` (F23), and the
    `testkit` feature `managed` in `crates/testkit/Cargo.toml`;
  * `crates/contract/**` (the §5 deltas): the new modules `crates/contract/src/{enrollment,issuer,managed}.rs`;
  * the new domain modules `crates/domain/src/{enrollment,verification,claims,connection,managed}.rs`,
    and the new variants and fields in `crates/domain/src/{decision,operation,grant,revocation,policy,issuance,resource}.rs`
    (types only; bodies in U0b);
  * `crates/app/src/ports.rs`: the new ports `SignatureAuthority` (⟨r2⟩ returning `SignPermit`),
    `IssuerPort`, `VerificationRunner`, ⟨r2⟩ `VerificationEndpoint`, `TargetEvaluator`, `ManagedEffects`,
    `SessionLockSource` (⟨r2⟩ with the latched epoch) and `ConnectionControl`; the `RevokeOutcome`,
    `AdapterDescriptor` and ⟨r2⟩ `IntegrationSnapshot.managed` additions; and the new `Limits`
    fields. Remote enrollment steps are client-executed, so they have no port (ADR-0008 D5 §6.3);
  * ⟨r2⟩ the signing-gate API in `crates/app/src/managed.rs` (`SigningGates`, `SignPermit`, the
    exclusive guard; bodies are U10's) and the read-only check's signature in
    `crates/app/src/issuance_ro.rs` (body U3's);
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
  * extends overview §1 with the ⟨r2⟩ four crates and overview §9 with the three new `unsafe` modules
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
    the ADR-0008 D5 §6.2 table. ⟨r2⟩ That is revision 2's **20-state** table (§17.1 item 7), with the
    form-dependent targets of `verifying`, the separate `rollback_unknown` and `remove_unknown`, the
    system-form states, and `→ abandoned` from every uncertain state. It also includes the
    `ApprovedTarget` and `ClockMeasurement` types.
  * ⟨r2⟩ **The signing-gate protocol** (ADR-0008 D2 item 3a): the step order, `SignPermit` held until
    the enqueue, the exclusive acquisition by narrowings, and the bounds `signing_gate_wait` (1 s),
    `signing_enqueue_timeout` (2 s) and `signing_gate_max_wait` (5 s).
  * ⟨r2⟩ **The CA states** (`active`, `pending`, `retiring`, `unloaded`, `deleted`, `retired`; ADR-0008
    D4 item 3), and the remote-obligation statuses (`pending_until`, `bounded_complete`,
    `nominally_expired`; D7 item 3).
  * ⟨r2⟩ **`RemoteStep`**, with its pins and its hard deadline, the step-result bounds, and the lock exit
    codes 40–42 (D5 §6.3).
  * ⟨r2⟩ **`ForeignRemovalTarget`** (D4 item 5) and the `foreign_removals` table.
  * **`VerificationEntry`** and `domain::verification::check(VerificationCheck) -> Result<(),
    VerificationRefusal>` (signature only).
  * **`CertificateBounds.ca_fingerprint: Option<String>`** (serde default; M01 rows decode as `None`, and
    an M03 reservation requires `Some`).
  * **`RemoteObligation.kind`** (`needs_remote_action` | ⟨r2⟩ `bounded_by_expiry { latest_valid_before,
    clock }`; absent ⇒ `needs_remote_action`, so M01 records are unchanged).
  * **The slot state machine** `domain::managed::slot_transition` (ADR-0008 D10 item 2 table).
  * **The HM1 output grammar** and the script exit codes (ADR-0008 D5 §6.3; §5 item 21).
  * **The claim entry type** `domain::claims::Claim` and the validator's rules (ADR-0008 D12 item 3),
    ⟨r2⟩ with `build_profile` and `store_kind`.
  * **The test-configuration gates:** `ScratchSecretStore`, `HEIMDALL_TEST_KEY_SEED`,
    `FakeSessionLockSource` and the script pause directory. Each is compiled only under the test
    configuration. ⟨r2⟩ `ScratchSecretStore` and `FakeSessionLockSource` live in `heimdall-testkit`
    (feature `managed`). `StoreKind::ScratchTest` is a testkit-side value, **outside** the public schema
    (F23).
* **Tests:**
  * `contract_code_table_unchanged_30_rows`;
  * `contract_reason_golden` (every §5 item 14 reason with its code);
  * schema export byte-identical;
  * the new examples round-trip exactly:
    `schemas/examples/{request.issuer.*,request.enrollment.*,enrollment-plan,enrollment-result,ensure-data.managed,revoke-data.managed,inspect.enrollments,inspect.issuer,inspect.connections}.json`;
  * `journaled_operation_kinds_match_their_request_kind`, extended (§5 item 12):
    * `enrollment.apply`, `enrollment.verify` and `enrollment.remove` are journaled;
    * `issuer.register`, `issuer.unlock`, `issuer.retire`, `enrollment.reconcile`,
      `enrollment.abandon`, `enrollment.step`, `enrollment.step_result`, `connections.close` and ⟨r2⟩
      `connections.register` are effectful and synchronous;
    * `issuer.status`, `issuer.bundle` and `enrollment.preview` are read-only;
    * the helper still matches `Request` without a wildcard;
  * `decision_kind_wire_forms` for `RegisterIssuer`, `RetireIssuer`, `EnrollAccount`, ⟨r2⟩
    `EnrollSystemForm` and `RemoveEnrollment`;
  * `enrollment_transition_table_golden`: every (state, event) pair, with the allowed ones exactly as in
    ADR-0008 D5 §6.2 and every other one refused;
  * ⟨r2⟩ `enrollment_recovery_paths_each_tested`: a case-index check that every recovery path ADR-0008
    D5 §6.4, §6.7, §6.8 and §6.9 documents names a test in U5 or U10 (§17.1 item 7). Not only every
    pair of the table is covered;
  * ⟨r2⟩ `ca_state_transition_golden` and `remote_obligation_status_golden`;
  * ⟨r2⟩ `public_schema_has_no_scratch_store_kind` (F23);
  * ⟨r2⟩ `crate_graph_step_rejects_app_edge_to_enroll` (a mutated manifest fixture fails the
    `crate-graph` step);
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
  * ⟨r2⟩ `claims_table_rejects_debug_profile_or_test_store_for_custody_claim` (F03);
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
| 1 | `ipc::signing::Signer { identities(), sign(key_blob, data, flags) }`, no connection context | `Signer` methods take `&SigningSession { peer: PeerInfo, endpoint: EndpointRef, bind: Option<SessionBindRecord> }`. `serve()` creates one per connection and handles `session-bind@openssh.com` by calling `Signer::session_bind(&mut SigningSession, payload) -> bool` (success or failure frame). ⟨r2⟩ `sign` returns `SignOutcome { frame, permit: Option<SignPermit> }`. `serve()` writes the frame, bounded by `signing_enqueue_timeout`, and drops the permit **only after** the frame is in the connection's outbound buffer; a timed-out enqueue closes the connection without the frame (ADR-0008 D2 item 3a). `NoIdentities` is adapted (empty list, failure, no permit) | 1 | the M01 signing suites unchanged; `signing_session_carries_peer_and_endpoint`; `session_bind_reaches_signer_and_answers_success_or_failure`; ⟨r2⟩ `permit_dropped_only_after_enqueue`; `enqueue_timeout_closes_without_frame` |
| 2 | `domain::issuance::check` knows no CA; `app::operations::permitted_extensions` gives `permit-pty` plus agent forwarding | `IssuanceCheck.enrolled_cas: &[String]` (the CAs whose `verified` enrollment covers the pair, newest first). New refusals `UnknownCa` (no `ca_fingerprint`, or a CA not in the set) and `CaNotVerifiedForPair`. `issuance::extension_profile(grant, pair)` implements ADR-0008 D6 item 1; `permitted_extensions` becomes a wrapper with identical output for M01 grants | 1 | one refusal test per new variant; `extension_profile_matches_adr_0005_3_4_table`; the M01 issuance tests unchanged |
| 3 | `Operations::reserve_issuance(IssuanceRequest)` takes the caller's bounds | The reserve transaction **selects** `ca_fingerprint` itself from `enrollments` (newest `active` CA with a `verified` enrollment for the pair, ADR-0008 D4 item 3). A request naming another CA is refused (`UnknownCa`). Publish re-checks it | 1 | `reserve_selects_newest_verified_ca_for_pair`; `publish_voids_when_enrollment_removed_between_reserve_and_publish`; `publish_voids_when_ca_retired_between` |
| 4 | — | `Operations::{reserve_verification, publish_verification, void_verification}` over the `verification_issuance` table, with `verification::check` (ADR-0008 D5 §6.5 item 2), `TimeGate` inside the transaction, and the per-pair residual | 1 | one refusal per predicate; `verification_entries_counted_in_pair_residual`; `reserved_verification_never_published_after_restart` |
| 5 | — | `Operations::authorize_signature(SignatureRequestFacts) -> SignatureDecision`, implementing `SignatureAuthority`: ADR-0008 D2 item 3 in one read transaction plus ⟨r2⟩ `TimeGate::assess_read_only` (no high-water write; F21), with automatic re-validation on a stale generation (ADR-0006 §13.5 ruling 2). ⟨r2⟩ Two calls: `precheck(facts)` (no gate) and `admit(facts) -> Result<SignPermit, SignRefusal>`, which takes the grant's gate shared (`signing_gate_wait`) **then** reads fresh (D2 item 3a) | 1 | `authorize_refuses_each_predicate`; `authorize_revalidates_after_unrelated_generation_move`; `authorize_linearizes_with_revoke_commit`; ⟨r2⟩ `admit_reads_fresh_after_taking_gate`; `admit_refuses_when_gate_not_obtained_in_time` |
| 6 | Remote-revocation obligations have backoff and cap only | `RemoteObligation.kind`; ⟨r2⟩ the supervisor's `revocation_pass` moves `bounded_by_expiry` obligations through `pending_until` → `bounded_complete` (measured clock: `latest_valid_before + behind_upper + rtt + 100 ppm × age` passed on safe time) or `nominally_expired` (unmeasured: `latest_valid_before` passed on safe time; never shown as cleared), with no adapter call and no attempt counted; the grant reaches `revoked` when every obligation is in one of those two (ADR-0008 D7 item 3; §17.1 item 10). `RevokeOutcome.remote_effects: Vec<RemoteEffectReport>`. `RevocationCause::SessionLocked` | 1 | ⟨r2⟩ `bounded_obligation_completes_after_measured_bound_on_safe_time`; `unmeasured_obligation_becomes_nominally_expired_never_cleared`; `bounded_obligation_never_moves_on_uncertain_time`; `bounded_obligation_consumes_no_attempt`; the M01 obligation suites unchanged |
| 7 | QR17: a timed-out immediate `revoke` counts as made | `AdapterDescriptor.remote_credential_effect: bool` (false for M02 adapters). When true, a timed-out immediate call **keeps its cleanup intent**, and the supervisor retries it with bounded, jittered backoff (ADR-0007 §12.13; ADR-0008 D7 item 5) | 1 | `timed_out_immediate_revoke_with_remote_effect_keeps_intent_and_retries`; `m02_adapters_unchanged_timed_out_immediate_counts_as_made` |
| 8 | Restart recovery knows no credential instances | At start, in one transaction before any listener binds: every `installed` credential instance whose vault slot does not exist in this process becomes `lost`, and ⟨r2⟩ every `pending` instance becomes `destroyed`, its `reserved`/`published` entries staying counted (ADR-0008 D2 table; F18). The supervisor gains the hook `managed_reissue_pass`; its body is U6/U10's, and it is a no-op while the managed adapter is unregistered | 1 | `installed_instances_become_lost_at_restart`; ⟨r2⟩ `pending_instances_destroyed_at_restart_entries_still_counted`; `lost_instance_grant_degraded_credential_reissue_pending` |
| 9 | `ensure` resolution picks the adapter from the catalog identity's mechanism (ADR-0007 §7, "one mechanism per grant") | Per pair: `managed_certificate` when `pair_preferences` says so and the projection rendering it is applied, together with a `verified` enrollment. Otherwise the identity's mechanism. ⟨r2⟩ **While the projection is pending** the pair resolves to the existing mechanism, with warning `managed_projection_pending` and `next: setup_apply`; only a request whose minimums the existing mechanism cannot meet fails with `projection_pending` (ADR-0008 D5 §6.6; F04). Mixed ⇒ `mixed_mechanisms` (unchanged, ADR-0008 Q5). `pair_not_enrolled` refusal. `EnsureRequest.connection` enters the canonical hash when present (omitted otherwise, so M01/M02 hashes are unchanged). The `required.unattended` rule of ADR-0008 D6 item 7 | 1 | `mechanism_per_pair_resolution_table`; ⟨r2⟩ `pending_projection_ensure_resolves_existing_with_warning`; `pending_projection_refused_only_for_managed_only_minimums`; `connection_absent_hash_unchanged_from_m02`; `strict_request_hash_differs`; `unattended_requires_claim_and_continue` |
| 10 | `GrantOrigin` has `covered` and `adapter` add-only | Adds add-only `lock_behavior: Option<LockBehavior>` and `connection: Option<ConnectionPolicy>`, recorded once at grant creation | 1 | `origin_lock_and_connection_add_only` |
| 11 | `StandingPolicy` has no lock or connection fields; `PolicyAction` has pause, resume, cutoff and clear | `StandingPolicy.{lock_behavior, connection}` (serde default `continue`, `graceful`/`disabled`). `PolicyAction::{SetLockBehavior, SetConnectionPolicy}`. `is_widening_policy_action` extended: `continue`, `graceful` and `owned_masters` are widening. Narrowing moves the generation | 1 | `lock_behavior_narrowing_immediate_widening_needs_decision`; `connection_policy_widening_classification`; `merged_policy_fail_closed_for_lock_and_connection` |
| 12 | `DegradedReason::MechanismUnavailable` only | Adds `CredentialReissuePending`, `IssuerUnavailable` and `PairUnenrolled`, with their sign rule (ADR-0008 D2 item 3). `IssuerUnavailable` and `PairUnenrolled` permit signing with an installed key: the server refuses an unenrolled pair itself, and the other pairs keep working. `CredentialReissuePending` has no key. `MechanismUnavailable` refuses | 1 | `degraded_reason_sign_rule_table` |
| 13 | Dispatch has no arm for `Request::{Issuer, Enrollment, Connections}` or the catalog action `SetPreference` | Arms that fail closed (`driver_unavailable`, nothing written) in phase 1. In phase 2 they call U10's drivers, and `ipc::session` offers `issuer/1`, `enrollment/1`, `managed-credentials/1` and `connections/1`. ⟨r2⟩ `Enrollment::{Step, StepResult, Reconcile}` and `Connections::{Close, Register}` are refused unless the caller's role is owner (F20) | 1, 2 | `w0_m03_requests_fail_closed_before_any_record`; `w0_m03_capabilities_not_offered`; ⟨r2⟩ `step_and_reconcile_refused_for_non_owner_role`; phase 2: `capabilities_offered_after_activation` |
| 14 | Decision dispatch knows the M01/M02 kinds | The new kinds are refused and not consumed in phase 1, and completed in phase 2 (U10) | 1, 2 | `w0_new_decision_kinds_refused_not_consumed` |
| 15 | — | The store bodies of `crates/store/src/ext_m03.rs` for every §5 item 18 `Txn` method | 1 | `integration_store_m03::*` (one per method: CAS, uniqueness, FKs, generation moves) |
| 16 | `testcfg` has the M01/M02 gates | `ScratchSecretStore` selection, `HEIMDALL_TEST_KEY_SEED`, `FakeSessionLockSource`, `HEIMDALL_TEST_SCRIPT_PAUSE_DIR`. Each is env-gated and compiled only under the test configuration | 1 | `release_build_ignores_m03_test_gates` (built in release mode by `check.sh`'s release-gate step: the variables are set and have no effect) |
| 17 | Restart recovery dispatches M01/M02 kinds | M03 journaled kinds stay **unresolved** at restart and are reported in `runtime_lifecycle` with `{phase: unresolved, kind, reason: owner_reconcile}` (ADR-0008 D5 §6.4) | 1 | `w0_open_enrollment_operations_stay_unresolved_at_restart` |
| 18 | Uninstall knows M02's owned artifacts | Uninstall lists remaining enrollments (non-final states) and refuses `--purge-state` while any remain, unless `--keep-remote-enrollments` is given (ADR-0008 §18). The CLI body is U12 | 1 (refusal), U12 (CLI) | `uninstall_refuses_purge_with_live_enrollments` |
| 19 | `holders::holder_pass` releases bindings on an observed exit | ⟨r2⟩ The holder and the **owned connection** are separate records (ADR-0008 D8 item 2; §17.1 item 8). On Unix the holder pass also writes the `dedicated` `owned_connections` row when the holder's process image is the verified `ssh` client (exec keeps the PID), and clears it on an observed exit. On Windows the row comes from the launcher's `Connections::Register` (U7), never from the holder. The closing is U7's | 1 | `holder_registers_dedicated_only_for_verified_ssh`; ⟨r2⟩ `windows_holder_never_registers_connection_itself` |

| ⟨r2⟩ 20 | Revocation, cutoff and narrowing paths in `operations.rs` commit without any signer coordination | Each narrowing path takes the **signing gate exclusively** for every affected grant (cascade included) before its commit: `revoke`, the cascade, authority withdrawn at re-validation, a cutoff set or moved earlier, environment-permission removal, lock revocation (U9), and an enrollment hold or removal that degrades a pair (U10). A revocation holds it until the managed adapter's `revoke` returns, so keys are destroyed under it (ADR-0008 D2 item 3a, D7 item 2) | 1 | `revoke_takes_gate_before_commit`; `cutoff_earlier_takes_gate`; `revalidation_withdrawal_takes_gate`; `gate_released_after_keys_destroyed` |
| ⟨r2⟩ 21 | `IntegrationSnapshot` has observations, identities, declarations and executables; `prepare_from` forbids store and live reads (`ports.rs`) | `IntegrationSnapshot.managed: Option<ManagedSources>` (enrollments and issuing-CA sets, slots, claims, issuer status, the driver's `ManagedPrepared`). The managed effect driver `app::managed::drive_preparation` runs ADR-0008 D6 item 1 around the `ManagedEffects` port, with every store transaction outside the adapter bound. Existing-access adapters are unchanged (D6 item 0; §17.1 item 12) | 1 (types, fail closed), 2 (driver) | `existing_access_prepare_contract_unchanged`; `managed_prepare_from_without_driver_results_is_protocol_error`; `driver_never_runs_store_work_inside_adapter_bound` |
| ⟨r2⟩ 22 | Catalog actions are M02's eight | The ninth, `SetPreference` (§5 item 4b), and the preference's issuing-CA set (`pair_preferences.issuing_cas`; F05) | 1 | `set_preference_refused_without_verified_enrollment`; `issuing_ca_set_updated_by_e5_and_removal` |
| ⟨r2⟩ 23 | Restart recovery does not know CA retirement | A CA in `retiring` or `unloaded` resumes its retirement at start (ADR-0008 D4 item 3); the issuer child is told not to load a `retiring` CA | 1 | `retirement_resumes_at_start_from_each_state` |

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
    `ssh-encoding` only. Then ⟨r2⟩ `check(&UserAuthRequest, grant_certs: &GrantCertificates, flags: u32)
    -> Result<PairRef, PurposeRefusal>`. The `key_blob` must be one of the grant's certificates (never
    the plain key), and `user` must be the account of the pair whose principal that certificate names
    (ADR-0008 D2 item 4; F17).
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
    * ⟨r2⟩ `plain_k_env_key_refused_certificate_required` (F17);
    * ⟨r2⟩ `user_must_match_presented_certificates_pair` (a request for pair A's account presenting pair
      B's certificate is refused; F17);
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
      `/proc/sys/kernel/yama/ptrace_scope`; M-F19). ⟨r2⟩ It runs with
      `dumpable_control_attach_succeeds` as its positive control: a dumpable scratch process attached
      the same way. The signer result counts only when the control attach succeeded (F22).
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
* **Scope:** ADR-0008 D2 items 1–3, ⟨r2⟩ 3a (the signer's side of the signing gate) and 6–7, and the
  credential-instance state machine.
* **Interfaces:**
  * `ManagedSigner` implements `ipc::signing::Signer` (U0b row 1), once per endpoint kind:
    * `Environment`, `Binding(BindingId)` and `Verification(OperationId)`;
    * ⟨r2⟩ every `sign` follows D2 item 3a:
      1. `purpose::check`;
      2. `SignatureAuthority::precheck`;
      3. `SignatureAuthority::admit`, which takes the gate shared and then reads fresh;
      4. `KeyVault::sign`;
      5. return `SignOutcome { frame, permit }`, so that `serve()` drops the permit only after the enqueue.

      A test-only pause hook sits after each step;
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
    * ⟨r2⟩ `sign_paused_after_precheck_then_revoke_is_refused` (deterministic: pause after step 2,
      revoke commits, resume, and the fresh read refuses; §17.1 item 1, Q21 default);
    * ⟨r2⟩ `sign_paused_inside_gate_delays_revoke_and_is_enqueued_before_commit` (deterministic);
    * ⟨r2⟩ `no_signature_enqueued_after_revocation_acknowledged` (deterministic: the acknowledgment
      waits for the gate);
    * ⟨r2⟩ `stuck_enqueue_is_cancelled_within_bound_and_revoke_proceeds`;
    * `sign_during_revoke_is_linearized`: across 1000 uncontrolled interleavings, added **on top of**
      the deterministic tests, a signature either is enqueued before the tombstone commit or is
      refused;
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
* **Scope:** ADR-0008 D3, ⟨r2⟩ plus the read-only issuance check `app::issuance_ro` and the read-only
  time assessment `TimeGate::assess_read_only` (§17.1 item 12; F21). U3 owns the bodies of
  `crates/app/src/issuance_ro.rs` and the `assess_read_only` addition to `crates/app/src/timegate.rs`.
* **Interfaces:**
  * `child::run(stdin, stdout, store: Box<dyn SecretStore>, db: &Path, clock: Arc<dyn Clock>) -> i32`.
    It refuses a TTY stdin, speaks `heimdall-issuer/1`, opens the store read-only, implements D3
    item 4 steps 1–5, and zeroizes on EOF and on shutdown.
  * `ca::CaSet`: CAs by fingerprint, with states `active` and `pending`; `sign(entry, subject) ->
    Certificate` (through `cert::build_and_sign`).
  * `check::verify_reservation(ro_store, entry_ref, subject, now: TimeAnchor) -> Result<CertificateBounds,
    IssuerRefusal>`: ⟨r2⟩ the ceilings, around `app::issuance_ro::assess`, which shares its snapshot
    assembly with the runtime's reserve and publish transactions.
  * ⟨r2⟩ `TimeGate::assess_read_only(&Store) -> TimeStatus`: the gate over a read-only store, persisting
    nothing.
  * ⟨r2⟩ The child's `unload { ca_fingerprint }` message for retirement (ADR-0008 D4 item 3), answered
    after zeroization.
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
    * `rate_limited_after_600_per_minute`;
    * ⟨r2⟩ `ca_retiring_refused` (a reservation for a `retiring` CA);
    * ⟨r2⟩ `generation_only_refusal_re_reserves_within_bound` (ADR-0008 D3 item 4).

    ⟨r2⟩ Read-only:
    * `issuance_ro_assess_matches_reserve_predicate` (a property over generated store states: the
      read-only verdict equals the reserve transaction's);
    * `assess_read_only_on_open_read_only_store_writes_nothing` (F21; the file's bytes and the
      high-water mark are unchanged);
    * `assess_read_only_fails_closed_without_anchor`.

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
    {reserve, issuer read-only check, sign, publish, install}, ⟨r2⟩ **for activation and for re-issue**
    (F24), and against the signer's {precheck, gate, fresh read, sign, enqueue} (§17.1 item 1), with a
    crash at each step. Pass:
    * no certificate is published once any predicate fails;
    * the issuer refuses whenever its read-only snapshot shows a failing predicate;
    * a receiver with a stale generation, a tombstone or an unsafe deadline discards;
    * every `reserved`/`published` entry counts in `latest_possible_credential_expiry`;
    * a `reserved` entry is never published after a crash;
    * ⟨r2⟩ no signature is enqueued after a narrowing's commit.
* **Acceptance:** the tests pass; the protocol golden (`tests/contracts/golden/issuer-protocol.json`) is
  byte-stable.
* **Depends on:** U1, U4 (the `SecretStore` trait from U0; `ScratchSecretStore` from U4), U0b rows 2–4.

### U4: Platform stores, the D5 backup, the ceremonies and the recovery bundle

* **Owner paths:**
  * `crates/issuer/src/{store/macos,store/windows,store/linux,backup,ceremony,retire,bundle,sys}.rs`
    (⟨r2⟩ `store/mod.rs`, the trait, is U0's; F23);
  * ⟨r2⟩ `crates/testkit/src/scratch_store.rs` (`ScratchSecretStore`);
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
    * `ScratchSecretStore`: test configuration only. ⟨r2⟩ It lives in `crates/testkit/src/scratch_store.rs`
      (feature `managed`) and implements the trait U0 froze; U4 owns that file.
  * `backup` (the OpenSSH format with bcrypt-pbkdf and aes256-ctr, through `ssh-key` `encryption`):
    * ⟨r2⟩ `prepare(&SecretCaKey, &Passphrase) -> PreparedBackup { bytes, sha256 }`: the exact file
      bytes, built and decrypted back in memory (§17.1 item 11; M03-R11);
    * ⟨r2⟩ `write_exact(path, &PreparedBackup) -> BackupInfo { sha256, created_at }`: `O_EXCL`, `fsync`,
      read back, digest compared, decrypted and compared;
    * `restore(path, &Passphrase) -> SecretCaKey`.
  * `ceremony::{init, rotate_begin, restore, unlock, replace_orphan}(tty: &mut dyn Tty, client: &mut
    OwnerSession, …)`. The step order and crash points are ⟨r2⟩ revision 2's of ADR-0008 D4 item 1:
    generate, prepare the backup bytes, register their digest, write exactly, show the passphrase,
    store, approve. `replace_orphan` follows D4 item 1's rules: warn, cross-check a bundle, prefer
    restore. `Tty` is the controlling terminal (`/dev/tty`, `CONIN$`/`CONOUT$`), or a pty in tests.
  * ⟨r2⟩ `retire::{step}(ca, state) -> next state`: the durable transitions of D4 item 3, idempotent.
  * ⟨r2⟩ `uninstall_store_plan(&[EnrollmentView], &StoreItemRef) -> StoreFate { keep(reason) |
    offer_delete }` for U12's uninstall (D4 item 6).
  * `bundle::export(&StoreView, redact: Redaction) -> RecoveryBundle` (the §5 item 9 shape).
* **Tests:**
  * Positive:
    * `d5_backup_restores_with_stock_ssh_keygen`: ⟨r2⟩ `ssh-keygen -y -f <backup>` driven **through a
      pty**, with the passphrase typed at its prompt and never in argv, prints the CA public key (M-F16;
      §17.1 item 17; M03-R14). The test also asserts that no process the test started had the
      passphrase in its argv;
    * ⟨r2⟩ `registered_digest_is_the_written_backup` (the `backup_sha256` in the decision equals the
      file's SHA-256 after writing);
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
    * ⟨r2⟩ `backup_write_mismatch_stops_before_store` (a corrupted write is caught, and nothing is
      stored or approved);
    * ⟨r2⟩ `replace_orphan_refuses_when_bundle_lists_live_enrollments_and_offers_restore` (F08);
    * ⟨r2⟩ `replace_orphan_without_bundle_requires_flag_and_typed_confirmation`;
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
    * ⟨r2⟩ `retire_resumes_after_crash_at_each_step` (a crash after `retiring`, after `unloaded` and
      after `deleted`; a restart completes it, idempotently; §17.1 item 11);
    * ⟨r2⟩ `retire_refused_while_enrollment_not_final_or_abandoned` (§17.1 item 7);
    * ⟨r2⟩ `uninstall_store_plan_keeps_item_while_enrollments_live` (F08);
    * `bundle_contains_no_private_material` (canary and secret-bytes scan);
    * `bundle_redacts_hostnames`.
* **Acceptance:** the tests pass. The Windows DPAPI rows run natively. The macOS keychain row is
  labelled mechanism-only. The Linux Secret Service row runs or is `blocked` with its observation.
* **Depends on:** U1, U0.

### U5: Enrollment remote protocol and production verification

* **Owner paths:**
  * ⟨r2⟩ the **pure** crate `crates/registry/src/{line,script,step,hm1,post_image,classify,fence}.rs`
    (`heimdall-registry`, below `app`; §0.6; §17.1 item 12);
  * `crates/enroll/src/{plan,remote,verify,trace}.rs` (`heimdall-enroll`, I/O);
  * ⟨r2⟩ `crates/localenv/src/target.rs` (the `TargetEvaluator` implementation) and the raw-key
    addition to `crates/localenv/src/known_hosts.rs` (an M02 file; ⟨M02?⟩ M10, M13);
  * `tests/contracts/golden/enroll-scripts/{inspect,append,remove}.sh`;
  * `tests/integration/enroll_registry.rs` and `tests/integration/enroll_verify.rs` (hosted by
    `heimdall-enroll`, with dev-dependencies on `heimdall-testkit` and `heimdall-credential`), and
    ⟨r2⟩ `tests/model/registry_pure.rs` (hosted by `heimdall-registry`).
* **Scope:** ADR-0008 D5 §6.1, §6.3, §6.5, §6.7 (classification) and §6.8 (procedure).
* **Interfaces:**
  * ⟨r2⟩ `localenv::target::LocalTargetEvaluator` implements `app::ports::TargetEvaluator`:
    * `evaluate(alias) -> TargetEvaluation { hostname, port, user, proxy: None | Jump | Command,
      determinism: Determined | Undetermined(reason), host_keys: Vec<RawHostKey { key_type, key_b64,
      fingerprint, origin_display, revoked }> }`;
    * it uses the M02 static evaluator and known-hosts reader, passively;
    * it is the source of the approved target at preview, and of every re-evaluation before a step
      (ADR-0008 D5 §6.1, §6.3).
  * `enroll::plan::EnrollmentPlan::build(&CatalogView, &TargetEvaluation, &CaView, EnrollmentSpec) ->
    Result<EnrollmentPlan, PlanRefusal>`:
    * the ADR-0008 D5 §6.1 preconditions, ⟨r2⟩ including `account_override_refused`,
      `route_undetermined` and `existing_access_kind_unsupported`;
    * the **approved target**;
    * the **existing-access invocation** (the pins of D5 §6.3);
    * `plan_digest` over every field.
  * `registry::script::{inspect, append, remove}(params) -> RemoteScript`. Values are validated
    literals in single quotes. ⟨r2⟩ `append` and `remove` carry the **fence** (the lock, the token, the
    mutation window, exits 40–42; D5 §6.3). Under the test configuration only, `HM_PAUSE <name>` points
    are inserted, including one between the fence re-check and the write (the disclosed window).
  * ⟨r2⟩ `registry::step::remote_step(stage, &EnrollmentPlan, token, hard_deadline) -> RemoteStep`:
    the full pin set of D5 §6.3 (target, existing access, narrowing). It is used by the runtime (U10).
  * `enroll::remote::SshStepRunner`: a **CLI-side library**, the client-executed steps of ADR-0008 D5
    §6.3.
    * `run(&RemoteStep, tty: TtyMode) -> StepReport { exit_status, stdout, stderr_excerpt }`;
    * it runs the verified client named in the step with exactly the step's pins, alias, remote command
      and script on stdin. It adds nothing and drops nothing;
    * the owner's terminal is attached when the step is interactive, and `BatchMode=yes` is set
      otherwise;
    * it is bounded, kills the child on drop, and never parses or alters what the owner types.
  * `registry::classify::classify_step(stage, &StepResult, &Expected) -> StepClass`: the runtime's pure
    classification of a reported result.
    * Its classes are `Confirmed`, `AlreadyPresent`, `NotApplied(busy | window_expired | lock_lost |
      refused)`, `Uncertain`, `HostTrustChanged`, `ProviderLocked`, `InteractionRequired` and `Held`.
    * Exit 255 with no `HM1 v=1` line is `NotApplied` for `inspect` and `Uncertain` for `append` and
      `remove`.
  * `registry::hm1::parse(stdout) -> Result<Hm1Record, ParseError>`: bounded (512 KiB), and the first
    line must be `HM1 v=1`.
  * `registry` (pure):
    * `expected_line(ca_pub, principal, marker)`;
    * `post_image_without(preimage, line)`;
    * `check_post_append(pre, post, line)`;
    * `check_post_remove(post_image, post)`;
    * `classify_reconcile(observation, expected, fence: FenceView) -> ReconcileClass`, exactly the
      ADR-0008 D5 §6.7 table, ⟨r2⟩ with the fencing rules first.
  * `enroll::verify::Verifier` implements `app::ports::VerificationRunner`: `run(&EnrollmentPlan,
    positive: &CertificateLine, negative: &CertificateLine, endpoint: &dyn VerificationEndpoint) ->
    VerificationOutcome`.
    * It uses the generated configuration and known-hosts file of ADR-0008 D5 §6.5 item 3 (⟨r2⟩ from the
      approved target).
    * ⟨r2⟩ It measures the destination clock (item 4) and parses the `-v` trace into the item 5 events
      through `enroll::trace::patterns_for(client_version)`.
    * It applies the classification tables, separately for the initial verification and for
      re-verification.
* **Tests:**
  * Pure (proptest ≥ 256 cases, fixed seed):
    * `post_image_preserves_every_other_byte` (CRLF, no final newline, a BOM, comments, options,
      near-duplicate lines);
    * `check_post_append_accepts_admin_append_after_ours_rejects_damage`;
    * `reconcile_classification_table_every_row`;
    * ⟨r2⟩ `reconcile_never_redispatches_on_absence_alone` (property: without the hard deadline passed
      and the lock gone or broken, no class authorizes a redispatch);
    * `plan_refusals_each_precondition`;
    * `plan_digest_covers_every_field`, ⟨r2⟩ including the approved target and the invocation;
    * ⟨r2⟩ `remote_step_pins_are_exactly_the_documented_set`.
  * Protocol on every target shell (`registry_protocol_on_target_shell`, one row per target: dash on
    Docker Debian 13; the WSL Ubuntu 24.04; the devbox's `/bin/sh` through `LoopbackSshd`; macOS
    `/bin/sh` through `LoopbackSshd`):
    * `append_creates_registry_exclusively_mode_0600`;
    * `append_creates_ssh_dir_0700_when_absent` (ADR-0008 Q8);
    * `append_newline_decided_at_append_time`;
    * `append_idempotent_by_marker_exit_10`;
    * `inspect_reports_metadata_and_content`;
    * `remove_compare_then_rename_preserves_unrelated_bytes`;
    * ⟨r2⟩ `remote_clock_reading_per_target` (M-F23);
    * ⟨r2⟩ `lock_mkdir_is_exclusive_per_target`.
  * ⟨r2⟩ Target binding (§17.1 item 2; M03-R02):
    * `step_pins_hostname_port_user_and_host_key`;
    * `user_config_hostname_change_cannot_redirect_append`: after approval, the user's configuration is
      edited to point the alias elsewhere, and the step is refused `route_changed` with nothing
      written;
    * `user_config_proxycommand_added_after_approval_refused`;
    * `known_host_key_changed_after_approval_refused`;
    * `account_override_refused`.
  * ⟨r2⟩ Maintenance invocation (§17.1 item 4; M03-R04):
    * `maintenance_invocation_never_contacts_heimdall_signer`: 0 signatures on every Heimdall endpoint
      during rotation, removal, rollback and reconcile;
    * `rotation_and_removal_with_all_bindings_released_and_issuer_unavailable`;
    * `certificate_file_none_behaviour_recorded_per_client` (Q19; an observation per client);
    * `existing_identity_pin_used_after_projection_switch`.
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
  * ⟨r2⟩ Fencing (§17.1 item 6; M03-R06):
    * `busy_lock_changes_nothing_exit_40`;
    * `window_expired_changes_nothing_exit_41`;
    * `lock_lost_changes_nothing_exit_42`;
    * `first_script_survives_timeout_resumes_after_reconcile_no_duplicate_no_loss` (ADR-0008 D5 §6.7);
    * `stale_lock_broken_only_after_hard_deadline_by_rename_aside`;
    * `script_suspended_in_disclosed_window_detected_as_held`, recorded as the disclosed limitation.
  * Lost response:
    * `ssh_killed_after_append_is_uncertain_then_reconciled_applied`;
    * `ssh_killed_before_append_reconciled_not_applied`;
    * `unreachable_after_append_stays_unknown`;
    * `retry_after_lost_reply_never_appends_twice`.
  * Verification:
    * `verify_positive_one_signature_negative_zero` (per client; M-F1);
    * `verify_negative_records_zero_signatures`;
    * ⟨r2⟩ `verify_trace_patterns_per_client` (M-F22: the item 5 events for each client version,
      recorded from real runs);
    * ⟨r2⟩ `verify_unrecorded_client_trace_is_inconclusive`;
    * ⟨r2⟩ `verify_negative_inconclusive_when_sshd_stopped_between_attempts`;
    * ⟨r2⟩ `verify_negative_inconclusive_when_port_closed_between_attempts`;
    * ⟨r2⟩ `verify_negative_inconclusive_on_maxstartups_between_attempts`;
    * ⟨r2⟩ `verify_negative_inconclusive_on_maxstartups_during_negative`;
    * ⟨r2⟩ `verify_negative_inconclusive_on_reset`;
    * ⟨r2⟩ `remote_clock_measurement_bounds_lag` (with U11's lagging fixture);
    * `verify_never_reads_user_config`. The user configuration offers an extra key that **would**
      authenticate, as a canary key; it is never offered, and the positive passes only through the
      certificate;
    * `verify_on_account_without_log_access` (Docker `enrollable`; the WSL non-root user);
    * `principals_not_enforced_detected_and_rolled_back` (a fixture line without `principals=`, written
      by the test as an "administrator mistake");
    * `verification_failed_when_server_reads_another_registry` (`AuthorizedKeysFile` points elsewhere);
    * `verification_host_key_mismatch_holds_no_rollback`;
    * `verification_inconclusive_leaves_applied_unverified` (⟨r2⟩ renamed from
      `verification_unreachable_leaves_applied_unverified`; it covers unreachable too);
    * ⟨r2⟩ `reverification_failure_holds_never_removes` (§17.1 item 5; M03-R05);
    * ⟨r2⟩ `reverification_inconclusive_keeps_verified_with_finding`;
    * `verification_known_host_ambiguous_refused`;
    * `log_attestation_reported_unavailable`.
  * Goldens: `release_scripts_match_golden_and_have_no_pause_points`.
* **Acceptance:** every target shell row passes or is `blocked` with its exact platform. The interleaving
  and fencing limitations are recorded as such. The registry guard holds in every test.
* **Depends on:** U0, U11, U2 (the verification endpoint), M10, M11, ⟨r2⟩ M13.

### U6: The managed credential adapter

* **Owner paths:**
  * `crates/adapters/src/managed/{mod,effects,prepare,reissue,report,files}.rs`;
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
      the issuer status ⟨r2⟩ into `IntegrationSnapshot.managed` (U0b row 21);
    * ⟨r2⟩ `prepare_from` only **computes** the `PrepareOutcome` from the snapshot and the driver's
      `ManagedPrepared` results. It runs no effect (ADR-0008 D6 item 0). Without driver results it
      returns `AdapterError::Protocol`;
    * `renew` is the re-issue of D6 item 4 (`reissue::eligible` must hold);
    * `reconcile(grant, token)`: `Applied` when every pair is published and installed; `NotApplied`
      when nothing is published; `Unknown` otherwise;
    * `revoke(grant, now)` runs D7 item 2, for the grant and its cascade, and returns `remote_effects`.
  * ⟨r2⟩ `effects::ManagedEffectsImpl` implements `app::ports::ManagedEffects`:
    * `generate_key`, `install` and `destroy`, each bounded, over the signer (U2);
    * `materialize` and `clear`, synchronous on the blocking pool, over `files`.

    The stage sequence, the store transactions and the receipts are `app::managed::drive_preparation`'s
    (U10). The adapter performs effects only when asked.
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
    * ⟨r2⟩ `projection_pending_refused_only_for_managed_only_minimums` (F04; the ordinary request
      resolves to the existing mechanism);
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
  * ⟨r2⟩ Rotation and removal (§17.1 item 15; F05):
    * `rotation_keeps_ensure_working_per_account` (two accounts; each verifies K_ca′ in turn; `ensure`
      succeeds throughout, from the newest verified CA per pair; the projection is not reset);
    * `early_removal_preview_names_grants_under_removed_ca`;
    * `removal_degrades_only_grants_under_removed_ca` (Q20 default (a); the integrator flips it if Q20
      is ruled otherwise);
    * `preference_stays_managed_while_another_verified_ca_remains`.
  * A07:
    * `revoke_during_each_issuance_step`. With a real issuer child, revoke, cutoff, deadline passage and
      `TIME_UNCERTAIN` are each injected at reserve, sign, publish and install. The result is always
      refused or voided, and counted;
    * `revoke_with_unreachable_destination_reports_bounded_remote_effect` (⟨r2⟩ `remote_effects` with
      `latest_valid_before` = the pair's maximum `valid_before`, the pair's `destination_clock`, and the
      status `pending_until`, with `until` = the measured completion bound when a measurement exists);
    * `revoke_cascades_to_children_destroying_their_keys`;
    * `stale_approval_cannot_reactivate_after_revoke` (R-SE-07, through the real adapter);
    * ⟨r2⟩ `slow_server_clock_residual_bounded_by_measurement` (§17.1 item 10; U11's lagging fixture:
      the completion bound equals `latest_valid_before + behind_upper + rtt + drift`);
    * ⟨r2⟩ `unmeasured_residual_reported_nominally_expired_never_cleared`;
    * ⟨r2⟩ `revoke_result_lists_owned_connections_and_ordinary_note` (F15);
    * ⟨r2⟩ `revoke_destroys_keys_under_exclusive_gate` (D7 item 2);
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
  * ⟨r2⟩ `JobObject::spawn_contained` in `crates/localenv/src/sys/mod.rs` (an M02 `unsafe` module,
    edited after M02's Windows fixes land; ⟨M02?⟩ M13, M14) and the Windows managed-launch path in
    `crates/launch/src/windows.rs` behind `launch_uses_kill_on_close_job` (Q18);
  * `tests/integration/connections.rs` (hosted by `heimdall-runtime`) and `tests/e2e/deadline_m03.rs`
    (hosted by `heimdall`).
* **Scope:** ADR-0008 D8, ⟨r2⟩ including the separate holder and connection records, the Windows job
  object and registration (item 2), and the stable per-slot mux path (item 3).
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

    An unverifiable holder is never signalled. ⟨r2⟩ On Unix, the executable is re-verified (the
    verified client) together with the start time.
  * ⟨r2⟩ Windows: `JobObject::spawn_contained(command) -> ContainedChild { pid, created_at, job }`.
    It creates the child suspended, assigns it to a kill-on-close job without breakaway, and resumes
    its main thread. Then `Connections::Register { binding_id, pid, created_at }` registers the owned
    connection **before** the binding reports strict control. A registration failure closes the job
    (fail closed) and writes `prelaunch_failed` (`connection_registration_failed`).
  * ⟨r2⟩ The stable mux path `<runtime_dir>/mux/<destination-id>`, its `SUN_LEN` check
    (`mux_path_too_long`), and the generation-protected replacement of D8 item 3.
* **Tests (A23):**
  * Positive:
    * `owned_master_admits_sessions_before_deadline`;
    * `graceful_keeps_dedicated_connection_after_deadline_and_new_auth_refused`;
    * `strict_closes_dedicated_connection_at_deadline`;
    * `revocation_closes_dedicated_under_both_policies`;
    * `ordinary_client_uses_owned_master_when_present_direct_otherwise` (M-F5);
    * ⟨r2⟩ `two_successive_bindings_share_the_slot_mux_path_through_ordinary_ssh` (§17.1 item 16; R15,
      F16);
    * ⟨r2⟩ `enabling_masters_needs_decision_and_setup_apply` (P renders `ControlPath none` until then).
  * ⟨r2⟩ Windows ownership (`platform_only` Windows; §17.1 item 8; R08, F02):
    * `windows_revoke_makes_exact_ssh_exe_pid_exit`;
    * `windows_strict_deadline_closes_exact_ssh_exe`;
    * `windows_launcher_death_ends_ssh_through_job` (the launcher terminated by exact PID; the
      registered `ssh.exe` exits);
    * `windows_registration_failure_fails_closed`;
    * `windows_ssh_grandchild_inside_job` (a `ProxyCommand` fixture child is in the job:
      `IsProcessInJob`);
    * `windows_non_ssh_run_has_no_job_object_by_default` (Q18 default (a)).
  * ⟨r2⟩ Unix ownership:
    * `unix_connection_row_is_holder_pid_with_verified_image`;
    * `unix_failed_exec_is_not_an_owned_connection` (the process image is still `heimdall`, so it is
      not signalled).
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
    Windows pipes as `//./pipe/…`. ⟨r2⟩ `Some(path)` is only ever the slot's **stable** mux path
    (ADR-0008 D8 item 3), rendered once owned masters are enabled and applied.
  * `projection::plan` renders `ManagedCertificate` for a pair whose preference is `managed_certificate`
    (`pair_preferences`). The preview's diff shows the change, and it is consented through M02's
    `ApplyProjection` ⟨M02?⟩ M3.
  * ⟨r2⟩ `connect` for a managed pair runs ADR-0008 D8 item 2's flow (§17.1 item 8):
    1. resolve the pair;
    2. `ensure` for the single-pair scope under the default profile covering it
       (`no_profile_covers_destination` otherwise);
    3. `bind` with the launcher as holder;
    4. launch the verified client with the binding-endpoint options of D10 item 4. On Windows this
       goes through U7's contained, registered spawn.

    Existing-access `connect` is unchanged.
  * ⟨r2⟩ The deadline wording in every result and in `connect`/`run` notices depends on the alias's
    identity selection (ADR-0008 D8 item 6; F15).
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
    * `windows_token_change_makes_p_stale_and_ensure_projection_pending`;
    * ⟨r2⟩ `connect_managed_pair_without_covering_profile_refused`;
    * ⟨r2⟩ `deadline_wording_follows_identity_selection` (exclusive and not-exclusive texts).
  * ⟨r2⟩ `connect` flow:
    * `connect_managed_pair_ensures_binds_and_launches_with_binding_endpoint`;
    * `connect_managed_holder_released_on_exit`;
    * `connect_existing_access_pair_flow_unchanged_from_m02`.
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
  * `SessionLockSource` implementations, per the D9 item 3 table. ⟨r2⟩ The interface latches events
    (§17.1 item 9; M03-R09):
    * `state() -> LockState`, the current state;
    * `lock_epoch() -> LockEpoch { epoch: u64, observed: bool }`: the epoch increments on every
      transition into `locked`, and `observed` stays set until acknowledged;
    * `wait_epoch_change()`, which notifies on each new epoch;
    * `acknowledge(epoch)`, called by the revocation pass after its revocations commit, which clears
      `observed` only for that epoch.

    A plain `watch` of the state is not used: it keeps only the last value.
    * macOS: a dedicated run-loop thread;
    * Windows: a message-only window thread;
    * Linux: `zbus` on the system bus.

    Threads are spawned once, joined at shutdown, and never call into the store.
  * `lock::effective_behavior(&GrantOrigin, &[StandingPolicy]) -> LockBehavior`.
  * `Operations::on_session_lock(LockEpoch)`: in one pass, revoke every `revoke_on_lock` grant (cause
    `session_locked`), taking the signing gates exclusively (U0b row 20), then acknowledge the epoch.
  * `Operations::policy(SetLockBehavior)`: narrowing is immediate; widening goes through the decision
    record; it is refused where the source is `unavailable`.
  * The disclosure record: `meta.lock_disclosure_acknowledged_at`. ⟨r2⟩ The disclosure is
    conditional and states the saved limits (ADR-0008 D9 item 1; F19). Linux `revoke_on_lock` carries
    `signal_unverified` until B11.
* **Tests:**
  * Positive:
    * ⟨r2⟩ `lock_then_unlock_while_consumer_paused_still_revokes` (§17.1 item 9);
    * ⟨r2⟩ `epoch_acknowledged_only_after_revocations_commit`;
    * ⟨r2⟩ `disclosure_is_conditional_and_states_saved_limits` (F19);
    * ⟨r2⟩ `linux_revoke_on_lock_labelled_signal_unverified`;
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
  stop order. ⟨r2⟩ It also covers:
  * the managed effect driver (`app::managed::drive_preparation`, D6 item 0);
  * the signing gates' bodies (`app::managed::SigningGates`, D2 item 3a);
  * the system-form path (D5 §6.9);
  * foreign removal (D4 item 5);
  * supervisor re-verification (D5 §6.5, F27);
  * retirement driving (D4 item 3).
* **Interfaces:**
  * `enrollment::{next_step, record_step_result, run_verification}`: the stage machine of ADR-0008 D5
    §6.4.
    * `next_step` ⟨r2⟩ checks the owner role and that no step is outstanding, re-evaluates the route
      through `TargetEvaluator` (`route_changed` on any difference), writes the target known-hosts file,
      writes the stage receipt (`Attempted` for a mutation, with token and hard deadline), and returns
      the `RemoteStep` (`registry::step::remote_step`) to the driving CLI;
    * `record_step_result` checks the `step_token`, classifies through `registry::classify_step`, and
      records the outcome together with the enrollment transition in one transaction;
    * `run_verification` runs E4 in the runtime (`VerificationRunner`, `IssuerPort`, the U0b row 4
      issuance);
    * a step result that never arrives makes the stage `Uncertain` after `enrollment_step_timeout`
      (supervisor pass).

    `enrollment::reconcile(op)` follows ADR-0008 D5 §6.7, with its `inspect` client-executed too, ⟨r2⟩
    fencing first (the stale lock broken only after the hard deadline), and a redispatch only on an
    attended session within the approval's validity.
  * ⟨r2⟩ `enrollment::system_form::{plan, mark_applied, mark_removed}`: the `EnrollSystemForm` decision,
    `manual_pending`, the presence and absence verifications, and `manual_removal_pending` (D5 §6.9).
  * ⟨r2⟩ `enrollment::foreign_remove(ForeignRemovalTarget)`: rebuilds the line and checks its
    `line_sha256`, refuses a redacted bundle, and records into `foreign_removals` (D4 item 5).
  * ⟨r2⟩ `managed::reverify_pass` (supervisor): re-verifies each `verified` pair after 80 days, with
    bounded jittered retries; non-interactive; no remote change (Q11 as amended; F27).
  * ⟨r2⟩ `managed::drive_preparation`: D6 item 1 around `ManagedEffects` and `IssuerPort`, with every
    store transaction outside the adapter bound.
  * ⟨r2⟩ `managed::SigningGates`: one async reader-writer lock per grant, with the shared permit for
    signing and the exclusive guard for U0b row 20's narrowings.
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
    * ⟨r2⟩ `enroll_through_passphrase_protected_key_prompts_on_owner_tty` (renamed per §17.1 item 14: a
      `LoopbackSshd` and a pty-driven passphrase-protected scratch key file; the passphrase never
      appears outside the pty);
    * ⟨r2⟩ `enroll_password_only_account_refused_existing_access_kind_unsupported` (F13);
    * ⟨r2⟩ `step_refused_when_route_changed_after_approval` (§17.1 item 2);
    * ⟨r2⟩ `second_step_refused_while_one_outstanding` (§17.1 item 6);
    * ⟨r2⟩ `reconcile_redispatch_requires_attended_session` (F20);
    * ⟨r2⟩ `enroll_system_form_manual_apply_verify_and_manual_removal_with_absence_check` (§17.1 items 7
      and 11);
    * ⟨r2⟩ `system_form_never_reported_removed_without_absence_check`;
    * ⟨r2⟩ `abandon_from_outcome_unknown_remove_unknown_and_rollback_pending`;
    * ⟨r2⟩ `ca_retirement_refused_until_every_enrollment_final_or_abandoned`;
    * ⟨r2⟩ `rotation_and_removal_with_every_managed_binding_released_and_issuer_unavailable` (§17.1
      item 4);
    * ⟨r2⟩ `e5_rotation_keeps_projection_and_adds_issuing_ca` (F05);
    * ⟨r2⟩ `supervisor_reverifies_before_freshness_lapses` (F27);
    * ⟨r2⟩ `evidence_invalidated_on_host_key_or_client_change` (Q11 as amended);
    * `a10_narrow_certificate_refused_on_other_host_account_form`,
      `a10_narrow_certificate_refused_on_other_host_system_form`;
    * `enroll_second_for_same_pair_and_ca_already_enrolled`;
    * `enroll_remove_lists_affected_grants_and_degrades_them`;
    * `rotation_two_accounts_one_unreachable` (the A09 rotate exercise);
    * ⟨r2⟩ `foreign_removal_from_second_installation_with_different_catalog` (replaces
      `foreign_removal_from_bundle`; §17.1 item 11; F07);
    * ⟨r2⟩ `foreign_removal_refuses_redacted_bundle_and_line_hash_mismatch`.
  * Runtime:
    * `runtime_start_order_issuer_before_listen`;
    * `issuer_crash_blocks_reissue_not_signing`;
    * `reissue_after_runtime_process_restart_same_boot` (native, every platform; ADR-0005 §9.3 R4, the
      runnable row);
    * `reissue_after_reboot_waits_for_time_confirm` (virtual clock);
    * `shutdown_zeroizes_vault_and_stops_issuer`;
    * ⟨r2⟩ `managed_effect_steps_run_outside_store_transactions` (row 21);
    * `service_stop_via_signal_fallback_still_zeroizes` (ADR-0006 §13.7 item 8).
* **Acceptance:** the e2e flows pass on macOS, the devbox (scratch store) and Windows (DPAPI), and
  phase 2's capability and decision tests pass.
* **Depends on:** U1–U9, U11.

### U11: Test fixtures (`heimdall-testkit`, Docker fixtures)

* **Owner paths:**
  * `crates/testkit/src/{ca,registry,lock,managed,owner_digest,installation}.rs`, and
    `crates/testkit/src/sshd.rs` (extensions; ⟨M02?⟩ M13: rebased onto M02's Windows testkit fixes).
    `scratch_store.rs` is U4's;
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
  * `lock::FakeSessionLockSource`, ⟨r2⟩ with the latched epoch and a consumer-pause control
    (`pause_consumer()`, `resume_consumer()`; §17.1 item 9).
  * ⟨r2⟩ `sshd::Faults` for the negative verification's inconclusive cases (§17.1 item 3):
    * `stop_between_attempts`, `close_port_between_attempts`;
    * `max_startups` (`MaxStartups 1:100:1` with a held unauthenticated connection, between the attempts
      and during the negative);
    * `reset_after_version_exchange`.
  * ⟨r2⟩ `sshd::LaggingClock { lag }`: the fixture sshd's own `sshd_config` sets `PATH` for sessions
    (`SetEnv`) to a scratch directory whose `awk` wrapper reports the time minus `lag` (§17.1 item 10).
    The fixture changes no clock, and the server still validates certificates with the real clock.
  * ⟨r2⟩ `installation::SecondInstallation`: a second `HEIMDALL_HOME` with its own catalog and
    destination IDs, for foreign removal (§17.1 item 11).
  * ⟨r2⟩ `sshd::ThreeHosts`: three `LoopbackSshd` with disjoint pairs, for the lock procedure (§17.1
    item 17; F09). It reads the accepted key IDs from each log.
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
  * `test_ca_ceremony_captures_passphrase_only_from_pty`;
  * ⟨r2⟩ `faults_each_produce_the_intended_transport_failure`;
  * ⟨r2⟩ `lagging_clock_fixture_reports_offset_and_changes_no_clock`;
  * ⟨r2⟩ `fake_lock_source_pauses_consumer_and_latches`;
  * ⟨r2⟩ `second_installation_has_distinct_catalog_and_ids`;
  * ⟨r2⟩ `three_hosts_key_ids_attributed_per_host`.
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
  * ⟨r2⟩ The commands that revision 2 adds:
    * `enroll <destination> --form system` and `enroll verify <enrollment> [--absence]` (D5 §6.9);
    * `enroll remove --from-bundle <file> --marker <m> --alias <local alias>` (D4 item 5);
    * `issuer init --replace-orphan <fingerprint> [--bundle <file> | --no-bundle-available]` (D4
      item 1).
  * ⟨r2⟩ Uninstall follows D4 item 6:
    * a purge that keeps remote enrollments requires a fresh bundle (`bundle_required`);
    * the K_ca store item's fate is stated (kept while enrollments live; deletion offered otherwise,
      behind a typed confirmation).
  * ⟨r2⟩ After a reboot the CLI and the TUI show `time_confirmation_after_reboot` as a pending chore
    with its one command (`heimdall time confirm`), and count it in the exit evidence (F14).
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
  * `uninstall_lists_remote_enrollments_and_refuses_purge_without_ack`;
  * ⟨r2⟩ `uninstall_purge_keeping_enrollments_requires_fresh_bundle` (F08);
  * ⟨r2⟩ `uninstall_states_store_item_fate` (F08);
  * ⟨r2⟩ `replace_orphan_cli_warns_and_cross_checks_bundle` (F08);
  * ⟨r2⟩ `enroll_system_form_cli_shows_lines_and_never_claims_removed`;
  * ⟨r2⟩ `foreign_remove_cli_refuses_redacted_bundle`;
  * ⟨r2⟩ `revoke_output_lists_owned_connections_and_ordinary_note` (F15).
  * TUI:
    * `managed_readiness_detail_exact_deadline_strings` (the D8 wording, graceful and strict, ⟨r2⟩ each
      in its exclusive and not-exclusive form; F15);
    * ⟨r2⟩ `time_confirmation_chore_shown_after_reboot` (F14);
    * ⟨r2⟩ `projection_pending_warning_and_setup_apply_hint` (F04);
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
    the records are `verified`. ⟨r2⟩ Each entry carries the run's build profile and store kind, and
    only release-profile, product-store rows qualify for custody-dependent fields (F03).
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
  * ⟨r2⟩ `a10_bound_consumer_issuer_reachability_recorded` (renamed from
    `a10_worker_cannot_reach_issuer_material`; ADR-0008 D12 item 6; F10). Per platform, with positive
    controls, it records what a same-user worker can do. It asserts:
    * no issuer path;
    * no K_ca listed on any endpoint;
    * no issuer pipe descriptor in a runtime-spawned process (Unix);
    * no K_ca bytes in the scanned artifacts.
  * `a33_secret_bytes_scan_all_artifacts`.
* **Tests:** the harness self-tests (`native-harness-selftest` gains the m03 harnesses, M02 pattern),
  including:
  * `lock_harness_refuses_without_idle_15_min`;
  * `lock_harness_records_unverified_lock_as_blocked`;
  * ⟨r2⟩ `lock_harness_uses_disjoint_pairs_and_attributes_by_key_id` (F09);
  * ⟨r2⟩ `lock_harness_post_unlock_checks_follow_remaining_deadline` (F09);
  * ⟨r2⟩ `windows_lock_run_is_release_profile_on_dpapi_store` (F03);
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
 ├─► U5 registry (pure) + enroll    ─┤ (U5's target and verify tests go green after U2 and U11;
 │      plan + localenv::target          ⟨r2⟩ heimdall-registry first, since app depends on it)
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
* ⟨r2⟩ Several M02 files are edited for M03, each by one unit, and only after M02's Windows fixes land
  (⟨M02?⟩ M13):
  * `localenv/src/{target,known_hosts}.rs` by U5;
  * `localenv/src/sys/mod.rs` and `launch/src/windows.rs` by U7;
  * the projection and `heimdall/src/{connect_cmd,run_cmd,launch_flow}.rs` by U8;
  * `testkit/src/sshd.rs` by U11;
  * `testkit/src/scratch_store.rs` by U4.
* ⟨r2⟩ `app/src/{managed,issuance_ro,timegate}.rs`:
  * U0 freezes the signatures;
  * U3 writes `issuance_ro` and `assess_read_only`;
  * U10 writes the gates, the effect driver and the passes.
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
| **A03**: fresh authentications succeed through desktop and vault lock without the original vault staying unlocked; the configured lock-revokes alternative behaves differently, as disclosed | U13's lock procedure (§4.4): `a03_fresh_logins_while_locked_continue`, `a03_new_grant_while_locked_under_standing_policy` (D1, issuer under lock), `a03_lock_revokes_ends_grant_and_fresh_login_fails`, `a03_vault_stand_in_locked_agent_does_not_matter`, ⟨r2⟩ each grant on its own pairs and attributed by certificate key ID (F09). U9 `macos_lock_signal_observed`, `windows_lock_signal_observed`, ⟨r2⟩ `lock_then_unlock_while_consumer_paused_still_revokes`. U2 and U10 `reissue_after_runtime_process_restart_same_boot` (the recovery row). U4 `windows_dpapi_round_trip_across_processes` during lock | `m03-a03-lock-continuity.json`; `m03-p1-macos-screen-lock.json`; `m03-pw1-windows-lock.json` | macOS (lock rule; ⟨r2⟩ a test-store, debug-profile run: mechanism evidence only, so no macOS claim, F03). Windows (lock rule; ⟨r2⟩ a **release-profile** run on the product DPAPI store, `HEIMDALL_HOME` in scratch, so claim-eligible). **Blocked rows:** the macOS login-keychain product row (B3), Linux desktop (B11), the 1Password vault row (B1), the Windows system-agent vault row (B4) |
| **A07**: new local use fails immediately; descendants and stale callbacks cannot reactivate; remote-pending effects and the maximum residual are truthful | U3 the linearization model (⟨r2⟩ with re-issue, lock revocation and the signing gate; F24). U2 ⟨r2⟩ `sign_paused_after_precheck_then_revoke_is_refused`, `sign_paused_inside_gate_delays_revoke_and_is_enqueued_before_commit`, `no_signature_enqueued_after_revocation_acknowledged`, then `sign_during_revoke_is_linearized` and `destroyed_key_makes_installed_certificate_unusable`. U6 `revoke_during_each_issuance_step`, `revoke_with_unreachable_destination_reports_bounded_remote_effect`, `revoke_cascades_to_children_destroying_their_keys`, `stale_approval_cannot_reactivate_after_revoke`, ⟨r2⟩ `slow_server_clock_residual_bounded_by_measurement`, `unmeasured_residual_reported_nominally_expired_never_cleared`, `revoke_destroys_keys_under_exclusive_gate`. U0b rows 6 and 20. U9 `lock_revocation_between_reserve_and_publish_voids`. U4 `key_only_restore_reports_unbounded_unknown` | `m03-a07-revocation.json` | All. The disconnected-**runner** variant is `deferred_with_decision` to M06 (G07; plan §5 M06). A07's M01 model rows stay as recorded |
| **A09**: existing access survives; only owned records change; uncertain outcomes reconcile; newer edits are not overwritten; rotation; rollback | U5: protocol, negative, interleaving, lost-response, ⟨r2⟩ target-binding, maintenance-invocation and fencing tests (incl. `first_script_survives_timeout_resumes_after_reconcile_no_duplicate_no_loss`). U10 `enroll_*`, `rotation_two_accounts_one_unreachable`, ⟨r2⟩ `rotation_and_removal_with_every_managed_binding_released_and_issuer_unavailable`, `step_refused_when_route_changed_after_approval`, `enroll_system_form_manual_apply_verify_and_manual_removal_with_absence_check`, `foreign_removal_from_second_installation_with_different_catalog`, `abandon_from_outcome_unknown_remove_unknown_and_rollback_pending`, `enroll_remove_lists_affected_grants_and_degrades_them`. U6 ⟨r2⟩ `rotation_keeps_ensure_working_per_account`. U0 ⟨r2⟩ `enrollment_recovery_paths_each_tested`. U11 `registry_guard_refuses_non_scratch_paths`; the harness's owner-digest check. The disclosed remove window and fence window are recorded as limitations (U5) | `m03-a09-enrollment.json` | All (Windows as the client to the WSL fixture sshd ⟨M02?⟩ M7). Docker default-path rows on macOS; WSL default-path rows on Windows; the devbox default path is covered by WSL (B8, not a declared row). ⟨r2⟩ **Blocked rows** (F26): enrollment with 1Password as the existing access (B1), with the Windows system agent (B4), and with a touch-required key (B6) |
| **A10**: only the intended access succeeds where enforcement is claimed; no issuer key or broader certificate escapes; unsupported scope is labelled | U5 `verify_positive_one_signature_negative_zero`, ⟨r2⟩ the negative-inconclusive tests, `principals_not_enforced_detected_and_rolled_back`, `verification_failed_when_server_reads_another_registry`. U10 a two-host flow per form (`a10_narrow_certificate_refused_on_other_host_account_form`, `a10_narrow_certificate_refused_on_other_host_system_form`). U3 `ceiling_two_principals`, `issuer_path_never_exists_through_runtime_lifecycle`. U2 `environment_endpoint_lists_only_materialized_bindings` (no CA listed). U13 ⟨r2⟩ `a10_bound_consumer_issuer_reachability_recorded` (renamed; per platform, with positive controls, what a same-user worker can do; F10). U6 `report_*` (unverified pairs report `unknown`; existing access reports `client_routing`) | `m03-a10-scope-issuer.json` | All. Docker `ca1`/`ca2` and `enrollable`/`enrollable2` on macOS; two `LoopbackSshd` per form everywhere; the WSL distribution's sshd in both forms. The Linux Secret Service reachability row is blocked (B11) |
| **A23**: owned admission and closure match the policy; no certificate-only enforcement assumption; unmanaged and remote-process limits are reported accurately; OpenSSH stop behaviour tested | U7 (all its tests, ⟨r2⟩ including the Windows ownership tests and `two_successive_bindings_share_the_slot_mux_path_through_ordinary_ssh`). U8 `p_renders_owned_master_control_path_when_enabled`, ⟨r2⟩ `deadline_wording_follows_identity_selection`, the `connect` flow tests. U6 report fields `owned_multiplexing`, `existing_connections`, `remote_processes`, `unmanaged_connections`. U12 `managed_readiness_detail_exact_deadline_strings` | `m03-a23-deadline-connections.json` | macOS and devbox (real masters); Windows (dedicated connections through the job object and registration; multiplexing reported and enforced as unavailable) |
| **A33**: no secret leakage or plaintext fallback; previewed and redacted outputs; nothing collected by default | U4 `no_plaintext_when_store_unavailable`, `passphrase_only_on_tty_transcript`, ⟨r2⟩ `d5_backup_restores_with_stock_ssh_keygen` (pty; never in argv), `bundle_contains_no_private_material`. U1 `secret_key_has_no_clone_debug_serialize`, `core_dumps_disabled_after_harden`. U13 `a33_secret_bytes_scan_all_artifacts` (the seeded K_env, the test K_ca, the passphrase and canaries, over envelopes, events, logs, errors, the DB file, the runtime and data directories, process argv and environment, crash-artifact directories). U0b `release_build_ignores_m03_test_gates` | `m03-a33-secrets.json` | All. Support bundles and update artifacts are M08 (their rows are `deferred_with_decision`) |
| "The user can allow background work once without routine unlocks" ⟨r2⟩ **within one boot** (F14) | U10 `enroll_preview_apply_verify_setup_apply_ensure_ssh`, which counts decisions (exactly the enrollment, projection and grant approvals) and provider prompts after approval (zero); the A03 lock rows; U9 `disclosure_shown_once_then_recorded`. ⟨r2⟩ After a reboot, the runtime start and one attended `time confirm` are **counted as chores** (U12 `time_confirmation_chore_shown_after_reboot`) | `m03-exit-background-once.json` | All, fixture level, plus the A03 native rows. The human walkthrough is blocked (B7). The native reboot and logout rows are blocked (B12) |
| "An expired grant cannot renew itself" | U6 `expired_grant_never_reissued`, `renew_never_extends_deadline_or_pairs`, `reissue_refused_for_revoke_on_lock`; U3 ceilings; the M01 A05 model rows (unchanged) | `m03-exit-no-self-renewal.json` | All |
| "Does not claim all remote processes terminate or all offline credentials revoke immediately" | U7 `remote_process_survives_close_reported_not_terminated`; U6 `revoke_with_unreachable_destination_reports_bounded_remote_effect`, ⟨r2⟩ `unmeasured_residual_reported_nominally_expired_never_cleared`; the report goldens (`remote_processes: not_terminated`; ⟨r2⟩ `revocation.remote: unknown` until its claim, never `immediate` remote; F11) | `m03-exit-honest-limits.json` | All |
| "A fixed provider remains usable under its real limitations" | The M02 A11 and A35 suites re-run unchanged at the M03 build; U8 `existing_access_aliases_render_byte_identical_to_m02`; U6 `issuer_unavailable_no_fallback_to_existing_identity`; U0b row 9 ⟨r2⟩ `pending_projection_ensure_resolves_existing_with_warning`; U10 `enroll_*` (the existing identity is untouched) | `m03-exit-fixed-provider.json` (references the M02 records' rows at the M03 build) | All. The M02 blocked rows (B1, B4, B6) stay blocked |
| R-UX-03 (disclose once; configurable alternatives) | U9 `disclosure_shown_once_then_recorded`, ⟨r2⟩ `disclosure_is_conditional_and_states_saved_limits`, `revoke_on_lock_refused_where_signal_unavailable`; U12 help goldens | in `m03-a03-lock-continuity.json` | All. Comprehension (A30) is M09 |
| R-AU-08 (actual enforcement; reject unmet minimums) | U6 report tests; U0b row 9 `unattended_requires_claim_and_continue`; U6 `offline_until_beyond_bound_capability_unavailable`; U0 ⟨r2⟩ `claims_table_rejects_debug_profile_or_test_store_for_custody_claim` | `m03-r-au-08-reports.json` | All |
| R-SE-07 (recheck the generation before issuance and activation) | U0b rows 2–5 and 20; U3 the linearization model; U6 `stale_approval_cannot_reactivate_after_revoke` | in `m03-a07-revocation.json` | All |
| R-CR-06 (rotation and unenrollment touch only owned records; A31 part) | U5; U10 rotation and removal; U0b row 18; U12 `uninstall_lists_remote_enrollments_and_refuses_purge_without_ack`, ⟨r2⟩ `uninstall_purge_keeping_enrollments_requires_fresh_bundle` | in `m03-a09-enrollment.json` | All |
| All of the above together | the case index (`tests/native/m03/case-index.json`) | `m03-exit-claims.json` | — |

⟨r2⟩ **What the lowest-row rule makes of the exit** (§17.1 item 17; F26):
* **The records stay `blocked`** until their inputs arrive:
  * `m03-a03-lock-continuity.json`, on B1, B3, B4 and B11;
  * `m03-a09-enrollment.json`, on B1, B4 and B6;
  * `m03-a10-scope-issuer.json`, on B11, for the Secret Service reachability row only;
  * `m03-exit-background-once.json`, on B7 and B12.
* **So `m03-exit-claims.json` is `blocked`**, even when every runnable row is `verified`.
* **What the evidence can support** is at most what M01 and M02 recorded: an exit with blocked rows.
  * Every runnable row is `verified`, and every blocked row names its input.
  * The macOS `lock_continuity` claim stays `not_verified` (B3).
* **The exit decision is the orchestrator's.** A blocked R-CR-02 row keeps the managed unattended claim
  `preview-only` for the affected platforms (plan §10.3), and does not satisfy plan §10.1 for a stable
  release.

**The claim update** (ADR-0008 D12 item 3), after the native records:
1. For each record row that is `verified` and that a capability value depends on, the integrator adds
   one `Claim` entry naming that record, its commit, its platform row, ⟨r2⟩ its **build profile** and
   its **store kind**:
   * `lock_continuity` per platform, from `m03-a03`, and only from a release-profile, product-store
     row (F03): in M03, Windows only;
   * `owned_multiplexing: closed_at_deadline` and `existing_connections`, from `m03-a23`;
   * `new_signing_expiry: signer` and `new_authentication_expiry: credential_and_signer`, from
     `m03-a23` and `m03-a07`;
   * ⟨r2⟩ `revocation.remote` and the summary `enforcement.revocation`, from `m03-a07`.
2. `check.sh` `claims-table` validates them, including the profile and store-kind rule.
3. The claim-reporting tests (`report_with_fixture_claim_table_reports_verified_with_record`, now with
   the real table, and `a03_report_shows_verified_lock_continuity_on_this_platform`) run on that build,
   on each platform.
4. A row that stays `blocked`, or that came from a test store or a debug build, gets no custody claim.
   Its value stays `not_verified` or `unknown`.

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
| **Lock continuity (A03)**: fresh logins and a new grant while the desktop is locked | **Runnable under the ADR-0004 §2 rule** (§4.4): the signer and issuer from memory, the scratch-store K_ca loaded before the lock. ⟨r2⟩ **Mechanism evidence only** (debug build, test store): it can never produce the macOS `lock_continuity` claim, which waits for a release-profile run on the login keychain (B3; F03) | Not applicable: there is no desktop lock on a headless host. `revoke_on_lock` refused (`lock_signal_unavailable`) | **Runnable under the lock rule:** the signer and issuer from memory, **DPAPI unprotect during lock** (an issuer restart forced while locked), fresh logins from Windows ssh through the Heimdall pipe. ⟨r2⟩ A **release-profile** run on the product DPAPI store kind (`HEIMDALL_HOME` in scratch), so it is claim-eligible | Not applicable (no lock signal): refused | Blocked (B11) |
| **Lock-revokes alternative** | Runnable: CG lock signal observed, then revocation, then fresh logins refused | Refusal verified | Runnable: WTS signal observed, then revocation | Refusal verified | Blocked (B11) |
| **Locked vault** | Stand-in runnable: a disposable `ssh-agent` (the source provider) locked with `ssh-add -x` during A03. 1Password blocked (B1) | Same stand-in | Stand-in: the FakeAgent pipe in `Locked` mode (labelled). Windows system agent blocked (B4), 1Password blocked (B1) | Same stand-in as Linux | Blocked (B11) |
| **Deadline across sleep** | Virtual clock runnable (U2, U6 `advance_continuous_only`). **Native sleep blocked (B12)** | Virtual clock | Virtual clock; native blocked (B12) | — | Blocked (B11, B12) |
| **Deadline across logout and reboot** | Same-boot process restart runnable (`reissue_after_runtime_process_restart_same_boot`). Logout and reboot blocked (B12, plus B3 for a disposable account) | Process restart runnable. Reboot of the devbox not authorized (owner's machine): blocked (B12) | Process restart runnable. Sign-out and reboot blocked (B12) | `wsl --terminate` of the disposable distribution is runnable as a "restart" row (a boot-ID change inside the distribution is `[U]`, recorded) | Blocked |
| **Post-reboot time** | Virtual clock: `reissue_after_reboot_waits_for_time_confirm`. `TimeSync` observation only (Q13) | `timedatectl` observation recorded (read-only) | `w32tm /query /status` observation recorded | — | — |
| **Endpoints**: owner-only, peer check, per-binding listing | Runnable (0700/0600, peer UID). Cross-user blocked (B3) | Runnable. Cross-user: no second account (devbox not authorized, B8): blocked | Runnable: owner-only protected DACL, owner-SID check. Cross-user blocked (B2) | Runnable | — |
| **Remote registry protocol** (the server's `/bin/sh`) | Runnable: Docker Debian 13 (dash) and `LoopbackSshd` (macOS `/bin/sh`) | Runnable: `LoopbackSshd` (Ubuntu dash) | Runnable as the **client**: the Windows ssh client to the WSL fixture sshd (dash) ⟨M02?⟩ M7 | Runnable: the distribution's root sshd and a non-root user, **default registry path, StrictModes** | — |
| **Production verification** (per client) | Runnable: client 10.5p1 against Docker (non-log account) and loopback | Runnable: client 9.6p1 | Runnable: client 10.3p1 (M-F18) | Runnable: client 9.6p1 | — |
| **Owned masters / multiplexing stop** | Runnable | Runnable | **Unavailable** (M-F7): the refusal is verified | Runnable (supplementary) | — |
| **Owned dedicated connection closing** | Runnable (`kill` after re-verification of start time and image; window disclosed) | Runnable (pidfd, image re-verified) | Runnable: ⟨r2⟩ the registered `ssh.exe` in a kill-on-close job; revocation ends the exact PID; the launcher's death ends it through the job (§17.1 item 8) | Runnable | — |
| ⟨r2⟩ **Remote-step target binding and fencing** (A09) | Runnable (Docker and loopback) | Runnable (loopback) | Runnable as the client, to WSL | Runnable | — |
| ⟨r2⟩ **Negative verification evidence** (`-v` trace patterns) | Runnable: client 10.5p1 patterns recorded | Runnable: 9.6p1 | Runnable: 10.3p1 | Runnable: 9.6p1 | — |
| ⟨r2⟩ **Destination clock measurement** | Runnable (lagging fixture; real lag not reproducible) | Runnable | Runnable (to WSL) | Runnable | — |
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
   * ⟨r2⟩ **The build.** On Windows the product binary is a **release-profile** build of the exit commit,
     run with `HEIMDALL_HOME` in scratch, so the issuer uses the product DPAPI store kind at a scratch
     path (claim-eligible; F03). On macOS the run uses the test store (a debug build). It is labelled
     mechanism evidence, and it can never produce the macOS `lock_continuity` claim (B3). The fixtures
     (sshd, agents) come from the test build in both cases.
   * Start the runtime from the exit build.
   * `time confirm` (attended, through a pty).
   * `issuer init`: DPAPI on Windows, the test store on macOS.
   * ⟨r2⟩ **Three loopback hosts with disjoint pairs** (U11 `ThreeHosts`; §17.1 item 17; F09), each
     enrolled and verified. Then `setup apply`.
   * ⟨r2⟩ **One grant per host, so no two grants share a slot (Q15):**
     * grant **C** (`continue`) on host 1, ending at least 13 h after the planned lock;
     * grant **R** under a `revoke_on_lock` policy, on host 2;
     * a standing policy that lets a non-interactive `ensure` create grant **N** on host 3 later.

     Each grant's bindings are materialized for its own host's pair only.
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
   * N fresh `ssh` logins to host 1 through P. Each must show a new accepted line in host 1's sshd log
     **whose certificate key ID names grant C** (`heimdall:<env>:<grant C>:<serial>`); ⟨r2⟩ the key ID,
     not the success alone, decides which grant authenticated (F09);
   * one non-interactive `access ensure` that creates grant N, followed by fresh logins to host 3
     attributed to grant N by key ID (ADR-0005 D1: new grants under lock);
   * on Windows, one forced issuer restart (DPAPI unprotect under lock), followed by a re-issue for a
     grant whose key was deliberately dropped, attributed by key ID;
   * grant R's revocation event (cause `session_locked`) and **its** refused fresh login to host 2: no
     accepted line for any key ID of grant R after the event;
   * no prompt observed: no new window or process for keychain or credential UI, checked by exact
     process names.
6. **Wait for the unlock** (bounded to 12 h), then post-unlock checks that ⟨r2⟩ depend on each grant's
   remaining deadline (F09):
   * grant R is still terminal, and nothing reactivated it;
   * grant C, if its deadline has not passed, is still usable (a fresh login attributed to C). If it
     has passed, it is `expired`, and a fresh login with its certificate is refused. The record says
     which case ran;
   * grant N, likewise by its deadline.
7. **Clean up:** stop the runtime; scratch removal; the owner-digest check.

The records name the method, the build profile and store kind, the idle time observed, the lock-state
observations, the key IDs per login and the timings. A run that could not lock is `blocked`, never
`failed` and never `verified`.

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
rulings. ⟨r2⟩ Revision 2 applies §17.1 items 1–18; Q18–Q21 are built at their stated defaults.

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
        backup_sha256: String,            // ⟨r2⟩ hex SHA-256 of the exact D5 bytes prepared in memory
                                          // before this request; written after approval (ADR-0008 D4)
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
}
// ⟨r2⟩ No test variant in the public schema (F23). Test-configured builds carry the store kind
// `scratch_test` in heimdall-testkit and register it through a test-only path; the public
// schema golden asserts its absence (U0 `public_schema_has_no_scratch_store_kind`).
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
stopping`. With `store_unavailable` it carries `"reason"`. ⟨r2⟩ Each CA's `state` ∈ `pending | active |
retiring | unloaded | deleted | retired` (ADR-0008 D4 item 3).

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
    /// Journaled "enrollment.verify" (re-verification; the system form's first verification;
    /// ⟨r2⟩ the system form's absence check). Effect class local (issues ≤5-min verification
    /// certificates; no remote mutation; never removes anything, ADR-0008 §17.1 item 5).
    Verify { enrollment_id: EnrollmentId, request_id: RequestId,
             #[serde(default)] mode: VerifyMode,                  // ⟨r2⟩ presence (default) | absence
             #[serde(default)] wait: WaitMode },
    /// Journaled "enrollment.remove", effect class remote_mutation. Needs RemoveEnrollment.
    Remove { target: RemovalTarget, request_id: RequestId,
             #[serde(default)] interaction: InteractionMode, #[serde(default)] wait: WaitMode },
    /// Synchronous: drives an unresolved enrollment.apply/remove (ADR-0008 D5 §6.7). ⟨r2⟩ Owner
    /// role only; a redispatch of an append needs an attended session (F20).
    Reconcile { operation_id: OperationId, #[serde(default)] interaction: InteractionMode },
    /// Synchronous, owner channel: record abandonment (residual pending_until_line_removed).
    Abandon { enrollment_id: EnrollmentId },
    /// Synchronous: the client-executed step protocol (ADR-0008 D5 §6.3). ⟨r2⟩ Owner role only;
    /// at most one outstanding step; re-evaluates the route first (`route_changed`). Writes the
    /// stage receipt first (Attempted for append/remove), then returns the RemoteStep.
    /// kind "enrollment.step".
    Step { operation_id: OperationId },
    /// Synchronous: the CLI's result for the outstanding step. ⟨r2⟩ Owner role only.
    /// kind "enrollment.step_result".
    StepResult { operation_id: OperationId, step_token: String,           // 32 hex
                 exit_status: i32, stdout: String,                        // ⟨r2⟩ ≤ 512 KiB, HM1 lines only
                 stderr_excerpt: String },                                // ≤ 4 KiB, redacted, diagnostics only
}

/// What the CLI must run (no secret; the script contains only validated literals).
pub struct RemoteStep {
    pub stage: RemoteStage,              // inspect | append | remove
    pub step_token: String,
    pub client: String,                  // ⟨r2⟩ the verified client's absolute path
    pub pins: StepPins,                  // ⟨r2⟩ every -o of ADR-0008 D5 §6.3, in order
    pub alias: String,                   // the managed alias (ordinary configuration for the rest)
    pub remote_command: String,          // "exec /bin/sh -s"
    pub script: String,                  // written to ssh's stdin
    pub timeout_ms: u64,
    pub hard_deadline_ms: u64,           // ⟨r2⟩ on the runtime's continuous clock, from issue
}

/// ⟨r2⟩ The pins (ADR-0008 D5 §6.3; §17.1 items 2 and 4). Rendered as `-o Key=Value` in this order.
pub struct StepPins {
    pub target: TargetPins,              // HostName, Port, User, ProxyCommand=none, ProxyJump=none,
                                         // HostKeyAlias, UserKnownHostsFile, GlobalKnownHostsFile,
                                         // StrictHostKeyChecking=yes, CheckHostIP=no, UpdateHostKeys=no
    pub existing_access: AccessPins,     // IdentityAgent, IdentityFile, IdentitiesOnly=yes,
                                         // CertificateFile=none (Q19), ControlMaster=no, ControlPath=none
    pub narrowing: NarrowingPins,        // BatchMode, ForwardAgent=no, ClearAllForwardings=yes,
                                         // PermitLocalCommand=no, RequestTTY=no
}

pub struct EnrollmentSpec {
    pub destination: DestinationId,
    #[serde(default)] pub account: Option<AccountName>,    // default: the managed definition's;
                                                           // ⟨r2⟩ any other value: USAGE_ERROR,
                                                           // account_override_refused
    #[serde(default)] pub form: EnrollmentForm,            // account (default) | system
    #[serde(default)] pub registry_path: Option<String>,   // ADR-0008 D5 §6.1 rule
    #[serde(default)] pub ca_fingerprint: Option<CaFingerprint>, // default: newest active CA
}

#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RemovalTarget {
    Enrollment { enrollment_id: EnrollmentId },
    Foreign(ForeignRemovalTarget),                                    // ⟨r2⟩ from a recovery bundle
}

/// ⟨r2⟩ The full public removal descriptor (ADR-0008 D4 item 5; §17.1 item 11; M03-R12, F07).
/// The decision and the request hash cover every field.
pub struct ForeignRemovalTarget {
    pub local_alias: String,             // this device's managed alias for the host
    pub bundle_destination_id: String,   // the bundle's ID, a label only (IDs are per installation)
    pub bundle_hostname: String,         // required: a redacted bundle is refused (bundle_redacted)
    pub bundle_port: u16,
    pub account: AccountName,
    pub marker: String,                  // heimdall:enr_…
    pub ca_public_key: String,           // the CA's OpenSSH public key
    pub line_sha256: String,             // rebuilt and checked before connecting
    pub registry_path: Option<String>,
    pub form: EnrollmentForm,            // system: manual instructions only (D5 §6.9)
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
                      "endpoint_display": "<agent>",
                      "invocation": ["-o", "IdentityAgent=<agent>", "-o", "IdentityFile=~/.ssh/lab.pub",
                                     "-o", "IdentitiesOnly=yes", "-o", "CertificateFile=none",
                                     "-o", "ControlMaster=no", "-o", "ControlPath=none"]},
  "approved_target": {"hostname": "lab.example.internal", "port": 22, "user": "deploy",
                      "proxy": "none",
                      "host_key": {"algorithm": "ssh-ed25519", "key": "AAAA…", "fingerprint": "SHA256:…"}},
  "verification": {"positive_principal": "hm:dst_…:deploy", "negative": true,
                   "max_validity_seconds": 300},
  "rollback": "compare_then_rename_by_marker",
  "disclosures": ["config_commands_run_as_ordinary_use", "ca_trust_blast_radius",
                  "remove_window", "lock_continuity_once"]
}
```

`EnrollmentResult` (the `apply`, `verify` and `remove` operation results):
* `{enrollment_id, state, verified_at?, evidence?: {client, server, operation_id, ⟨r2⟩ clock?:
  {behind_upper_ms, rtt_ms, measured_at}}, next}`;
* `next` is `setup_apply` after a pass, `review_host_trust` for a held host key, `reconcile` for
  `outcome_unknown`, and `manual_registry_edit` with `instructions` for `registry_not_rewritable`.

`EnrollmentView` (`inspect enrollments`): one entry per record, with:
* `enrollment_id`, `destination_id`, `account`, `form`, `ca_fingerprint`, `marker`, `state`,
  `registry.path_display`;
* `verified_at` and `evidence_fresh_until`;
* `pair_residual_until` (D7 item 4), ⟨r2⟩ with `destination_clock` and the residual status;
* ⟨r2⟩ `approved_target` (host, port, user, host-key fingerprint);
* ⟨r2⟩ the removal purpose for `rollback_*` versus `remove*` states;
* `live_grants: [grant_id]`;
* `open_operation_id`.

**4. `InspectSubject::{Enrollments, Issuer, Connections}`**. `ConnectionsView`: one entry per
`owned_connections` row, with `{id, kind: master | dedicated, binding_id, grant_id, destination_id,
started_at, policy: {existing, multiplexing}, closes_at: Timestamp | null, state: up | closing}`. PIDs are
not exposed.

**4a. `Request::Connections(ConnectionsRequest)`**, capability `connections/1`. Both actions are
synchronous, effectful and accepted from the owner role only (as `Shutdown` is, ADR-0006 §13.6 item 8).
* `Close { connection_id }`. It is narrowing, so it needs no decision. kind `"connections.close"`. It
  closes one owned connection through `ConnectionControl::close` (reason `owner_request`). An
  unverifiable process is reported, not signalled.
* ⟨r2⟩ `Register { binding_id, pid: u32, created_at: Timestamp }`, kind `"connections.register"`.
  The Windows launcher's durable registration of the contained `ssh.exe` (ADR-0008 D8 item 2; §17.1
  item 8).
  * The runtime checks: the binding is a `Launch` binding held by the caller's launcher; the PID's
    creation time matches; its image is the verified client.
  * A refusal makes the launcher close the job (fail closed).

**4b. Catalog action `SetPreference { destination: DestinationId, account: AccountName, mechanism:
PreferredMechanism }`** (`managed_certificate | existing`). It is the ninth `CatalogRequest` action,
journaled under `catalog` (M02), local only.
* `managed_certificate` is refused (`pair_not_enrolled`) without a `verified` enrollment for the pair.
* The preference takes effect for P only through `setup apply` (ADR-0008 D5 §6.6).
* ⟨r2⟩ The stored preference is `PairPreference { mechanism, projection, issuing_cas:
  BTreeSet<CaFingerprint> }` (F05). E5 and removal maintain `issuing_cas`; `mechanism` changes only per
  D5 §6.6.

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
    // ⟨r2⟩ the last two are always present for managed results where they apply (F03, F14)
#[serde(default, skip_serializing_if = "Option::is_none")] pub refresh_condition: Option<RefreshCondition>,
    // { needed_only_after: signer_restart, source: local_issuer }
#[serde(default, skip_serializing_if = "Option::is_none")] pub revocation: Option<RevocationSemantics>,
#[serde(default, skip_serializing_if = "Vec::is_empty")] pub evidence: Vec<EvidenceEntry>,
#[serde(default, skip_serializing_if = "Option::is_none")] pub connection_policy: Option<ConnectionPolicyReport>,

pub struct RevocationSemantics {
    pub local: LocalRevocation,                 // immediate
    pub remote: RemoteRevocation,               // bounded_by_credential_expiry | not_applicable
                                                // | pending_until_line_removed | unbounded_unknown | unknown
                                                // ⟨r2⟩ gated by the claim table exactly like
                                                // enforcement.revocation: `unknown` until a claim (F11)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_possible_credential_expiry: Option<Timestamp>,   // absent = unknown
    pub destination_clock: DestinationClock,    // ⟨r2⟩ measured { behind_upper_ms, rtt_ms, measured_at }
                                                //      | unmeasured (per pair: the weakest is shown)
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
  "revocation": {"local": "immediate", "remote": "unknown",
                 "latest_possible_credential_expiry": "2026-11-10T22:00:00Z",
                 "destination_clock": {"measured": {"behind_upper_ms": 1400, "rtt_ms": 38,
                                                    "measured_at": "2026-11-10T13:50:00Z"}}},
  "evidence": [{"field": "destination_scope", "source": "runtime_verification",
                "pair": {"destination": "dst_…", "account": "deploy"}, "operation_id": "op_…",
                "client": "OpenSSH_10.5p1", "server": "OpenSSH_10.0p2 Debian-7+deb13u4",
                "observed_at": "2026-11-10T13:50:00Z", "fresh_until": "2027-02-08T13:50:00Z"}],
  "connection_policy": {"existing": "graceful", "multiplexing": "disabled",
                        "wording": "New connections stop at the deadline; existing sessions may stay connected."},
  "consumer": {"signing_endpoint": "<runtime>/signing.sock", "pairs": ["…"]}
}
```

* `new_signing_expiry`, `new_authentication_expiry`, `existing_connections`, the summary
  `revocation` and ⟨r2⟩ `revocation.remote` stay `unknown` until their claim-table entries exist
  (ADR-0008 D12; F11). `latest_possible_credential_expiry` and `destination_clock` are computed facts
  (the issuance log and the measurement), not claims.
* ⟨r2⟩ The example is a Windows result. On macOS, `conditions` also carries
  `issuer_store_unlocked_at_start` (F03).
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
  destination: DestinationId, account: AccountName, latest_valid_before: Timestamp, destination_clock:
  DestinationClock, status: ResidualStatus /* ⟨r2⟩ pending_until | bounded_complete |
  nominally_expired | unbounded_unknown */, until: Option<Timestamp> /* the completion bound when
  measured */ }>` (ADR-0008 D7 item 3; §17.1 item 10);
* ⟨r2⟩ `#[serde(default, skip_serializing_if = "Vec::is_empty")] owned_connections:
  Vec<OwnedConnectionReport { id, kind: master | dedicated, state: closing | closed | unverified }>`
  (F15);
* ⟨r2⟩ `#[serde(default, skip_serializing_if = "Vec::is_empty")] notes: Vec<RevokeNote>`, with
  `ordinary_connections_not_closed` always present for a managed revoke (F15).

The revision-1 field `destination_clock_error` is replaced by `destination_clock` before it ships;
nothing has emitted it.

`remote_pending: Vec<GrantId>` and `latest_possible_credential_expiry` are unchanged in meaning (ADR-0008
D7 item 2).

**`RecoveryBundle`** (the `issuer.bundle` data; a file written only by the CLI):
* `{schema: "heimdall-recovery-bundle/1", created_at, redacted: bool, cas: [...], enrollments: [{marker,
  destination_id, alias, hostname?, port?, account, registry_path_display, form, state, ca_fingerprint,
  ca_public_key, line_sha256}], instructions}`. ⟨r2⟩ It holds the CA public key and the alias, hostname
  and port that foreign removal needs; a redacted bundle omits the hostname, and foreign removal refuses
  it (ADR-0008 D4 item 5);
* never a private key, a passphrase or a socket path.

**10. Decision kinds** (`domain::decision::DecisionKind`):

```rust
RegisterIssuer { ca_fingerprint: CaFingerprint, store: StoreKind, backup_sha256: String,
                 rotation_of: Option<CaFingerprint>, restored_without_log: bool,
                 disclosures: Vec<DisclosureKind> },
RetireIssuer { ca_fingerprint: CaFingerprint, abandoned_enrollments: Vec<EnrollmentId> },
EnrollAccount { operation: OperationId, plan_digest: PlanDigest, summary: EnrollmentPlanSummary },
                 // ⟨r2⟩ the summary includes the approved target and the existing-access invocation
EnrollSystemForm { operation: OperationId, plan_digest: PlanDigest, summary: EnrollmentPlanSummary,
                   sshd_lines: SystemFormLines },              // ⟨r2⟩ ADR-0008 D5 §6.9
RemoveEnrollment { operation: OperationId, target: RemovalTargetRef /* enrollment | foreign descriptor */,
                   invocation: Vec<String>, affected_grants: Vec<GrantId>,
                   pair_residual_until: Option<Timestamp> },   // ⟨r2⟩ only grants under the removed CA
```

Each is completed only by `Decide` on an attended session (ADR-0006 §3.1). An `EnrollAccount` approval
copies `plan_digest` into the operation's approval basis, and it is valid for 24 h (ADR-0008 Q7 as
amended: re-application only for the same approved target and effect, on safe elapsed time, after the
§17.1 item 6 fencing). ⟨r2⟩ The system form's manual removal is narrowing and needs no decision, only a
typed confirmation (D5 §6.9).

**11. Operation kinds** (`domain::operation::OperationKind`):
* `EnrollmentApply` (`"enrollment.apply"`, effect class `remote_mutation`);
* `EnrollmentVerify` (`"enrollment.verify"`, `local`; ⟨r2⟩ presence or absence, never removing);
* `EnrollmentRemove` (`"enrollment.remove"`, `remote_mutation`).

`ALL` grows to 15. These kinds are never driven at restart (U0b row 17). Cancelling them is refused with
`CAPABILITY_UNAVAILABLE`, reason `remote_step_in_progress`, once the E3 `Attempted` receipt exists;
before that it is allowed.

**12. Hash inputs** (`app::operations`):
* `enrollment.apply`: environment, `plan_digest`, destination, account, form, registry path, CA
  fingerprint, ⟨r2⟩ the approved target and the existing-access invocation;
* `enrollment.verify`: enrollment ID, ⟨r2⟩ mode;
* `enrollment.remove`: the canonical target, ⟨r2⟩ the full `ForeignRemovalTarget` for a foreign one,
  and the invocation;
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
| `CAPABILITY_UNAVAILABLE` (4) | `issuer_not_initialized`, `issuer_unavailable`, `issuer_store_locked`, `issuer_store_unavailable`, `pair_not_enrolled`, `pair_not_adopted`, `enrollment_unverified`, `projection_pending`, `observed_alias_unmanaged`, `route_unsupported`, `registry_unsupported`, `principal_charset`, `host_trust_undetermined`, `verification_failed`, `principals_not_enforced`, `verification_inconclusive`, `lock_continuity_unverified`, `lock_revokes_chosen`, `lock_signal_unavailable`, `multiplexing_unsupported`, `too_many_identities`, `credential_reissue_pending`, `remote_step_in_progress`, `driver_unavailable` (exists); ⟨r2⟩ `route_changed`, `route_undetermined`, `existing_access_kind_unsupported`, `no_profile_covers_destination`, `mux_path_too_long`, `ca_retiring`, `bundle_redacted`, `bundle_required` |
| `CONFIG_CONFLICT` (6) | `already_enrolled`, `registry_changed`, `registry_not_rewritable`, `registry_too_large`, `registry_line_damaged`, `managed_slot_held`; ⟨r2⟩ `registry_busy` |
| ⟨r2⟩ `USAGE_ERROR` (2) | `account_override_refused` |
| ⟨r2⟩ `LAUNCH_FAILED` (127) | `connection_registration_failed` (Windows: the contained `ssh.exe` could not be registered; the job is closed) |
| ⟨r2⟩ `REQUEST_CONFLICT` (6) | `step_token_mismatch`, `step_outstanding` |
| `OUTCOME_UNKNOWN` (7) | `registry_outcome_unknown`, `remove_outcome_unknown` |
| `DECISION_STALE` (6) | `approval_lapsed` |
| `HOST_TRUST_CHANGED` (4) | `enrollment_host_key_mismatch` |
| `SERVICE_UNAVAILABLE` (5) | `issuer_restarting` |
| `BACKPRESSURE` (5) | `issuer_rate_limited` |
| `CREDENTIAL_EXPIRED` (4) | `grant_ended_session_locked` (use after a lock revocation) |

⟨r2⟩ Warnings (not error reasons): `managed_projection_pending` (with `next: setup_apply`; F04),
`signal_unverified` (Linux `revoke_on_lock`; F19). Doctor findings: `reverification_inconclusive`,
`enrollment_evidence_stale`.

**15. Capabilities** (`contract::ipc::capability`): `issuer/1`, `enrollment/1`, `managed-credentials/1`
and `connections/1` are **declared and not offered** in wave 0, and offered in phase 2 (U0b row 13).

**16. Domain types:**
* `domain::enrollment`:
  * `EnrollmentRecord`, `EnrollmentState` (ADR-0008 D5 §6.2; ⟨r2⟩ **20 states**), `EnrollmentEvent`,
    `transition`;
  * `EnrollmentForm { Account, System }`;
  * `RegistryRef { path_display, resolved_by: Explicit | RemoteHome }`. ⟨r2⟩ `path_display` uses
    `/` separators on every platform (⟨M02?⟩ M3);
  * ⟨r2⟩ `ApprovedTarget { hostname, port, user, proxy: NoProxy, host_key: RawHostKey }`;
  * `EnrollmentEvidence { client, server, operation, verified_at, fresh_until, ⟨r2⟩ clock:
    Option<ClockMeasurement { behind_upper_ms, rtt_ms, measured_at }> }`;
  * `PairPreference { destination, account, mechanism, projection: Pending | Applied { generation },
    ⟨r2⟩ issuing_cas: BTreeSet<CaFingerprint> }` (F05: no single `enrollment` field);
  * ⟨r2⟩ `ForeignRemovalTarget` (§5 item 3) and `ForeignRemovalRecord { id, target, state, operation,
    created_at }`.
* `domain::verification`:
  * `VerificationEntry { id: IssuanceId, operation, pair, purpose: Positive | Negative, bounds:
    CertificateBounds, state: IssuanceState, reserved_at, settled_at, void_reason }`;
  * `VerificationCheck`, `VerificationRefusal { OperationNotVerifying, PairMismatch, CaMismatch,
    WrongPrincipal, ExtensionsPresent, ValidityTooLong, UnknownSubjectKey, TimeUncertain,
    TooManyEntries }`;
  * `check`;
  * ⟨r2⟩ `TraceEvents { server_version, host_key_matched, offered_certificate, accepted, not_accepted,
    publickey_failure_final }` and the classification tables of ADR-0008 D5 §6.5 as a pure function
    `classify(&AttemptResult, &AttemptResult, phase: Initial | Reverify, form) -> VerificationVerdict`.
* `domain::issuance`:
  * `CertificateBounds.ca_fingerprint: Option<CaFingerprint>`;
  * `IssuanceRefusal` gains `UnknownCa`, `CaNotVerifiedForPair` and ⟨r2⟩ `CaRetiring`;
  * `CredentialState::Lost`;
  * `extension_profile(grant, pair)`;
  * ⟨r2⟩ `CaState { Pending, Active, Retiring, Unloaded, Deleted, Retired }` and `ca_transition`.
* `domain::grant`: `DegradedReason::{CredentialReissuePending, IssuerUnavailable, PairUnenrolled}`;
  `GrantOrigin.{lock_behavior, connection}`, add-only.
* `domain::revocation`: `RevocationCause::SessionLocked`; `RemoteObligation.kind: ObligationKind {
  NeedsRemoteAction (default), BoundedByExpiry { latest_valid_before, clock: DestinationClock, ⟨r2⟩
  status: ResidualStatus } }`, with the pure `residual_step(&obligation, now: SafeNow) -> ResidualStatus`
  (ADR-0008 D7 item 3).
* `domain::policy`: `LockBehavior`, `ConnectionPolicy { existing, multiplexing }`, and the
  `StandingPolicy` fields.
* `domain::resource::ResourceKind` gains `MaterializedFile` and `Connection`.
* `domain::managed`: `SlotState`, `slot_transition`, `OwnedConnection { id, kind, binding, grant, pid,
  start_token, ⟨r2⟩ image (the verified client's path), control_path, generation, state }`; ⟨r2⟩
  `LockEpoch { epoch, observed }`.
* `domain::claims`: `Claim { field, value, platform: Platform { os, arch }, os_floor, client_versions:
  VersionRange, signer_builds: VersionRange, ⟨r2⟩ build_profile: Release | Debug, store_kind:
  Option<&'static str>, record: &'static str, record_commit: &'static str }`, and `CLAIMS: &[Claim]`
  (empty in the baseline).

**17. `Limits`** (`app::Limits`). Application limits, not user configuration keys (the M02 P12 pattern).
⟨r2⟩ Every payload limit is derived with its serialization overhead (P7 as amended):

| Limit | Value | Derivation |
|---|---|---|
| `signature_authorization_timeout` | 2 s | |
| ⟨r2⟩ `signing_gate_wait` | 1 s | a signer waiting behind a narrowing refuses after it |
| ⟨r2⟩ `signing_enqueue_timeout` | 2 s | |
| ⟨r2⟩ `signing_gate_max_wait` | 5 s | ≥ 2 s authorization + the signature + 2 s enqueue |
| `issuer_request_timeout` | 10 s | inside the 30 s adapter-call bound |
| `issuer_start_timeout` | 5 s | |
| `issuer_signatures_per_minute` | 600 | |
| `max_certificates_per_grant` | 64 | the endpoint lists at most 64 identities |
| `enrollment_step_timeout` | 120 s; 300 s interactive | |
| ⟨r2⟩ `enrollment_mutation_window` | 60 s | the script's own window (remote clock) |
| ⟨r2⟩ `enrollment_step_hard_deadline` | timeout + 60 s + 30 s | the stale-lock threshold (continuous clock) |
| ⟨r2⟩ `enrollment_busy_retries` | 3, jittered | |
| `registry_max_bytes` | 128 KiB | inspect's `od` hex is about 3.2 bytes per byte (≈ 410 KiB) ≤ `remote_stdout_max`; `remove` carries two hex payloads (≈ 4.2 × 128 KiB + 8 KiB of script ≈ 546 KiB) inside one 1 MiB control frame with its envelope |
| `remote_stdout_max` | ⟨r2⟩ **512 KiB** (F25) | `StepResult` must fit one 1 MiB control frame (`MAX_CONTROL_FRAME_BYTES`) with its JSON envelope and escaping |
| `remote_stderr_max` | 64 KiB (excerpt 4 KiB) | |
| `verification_max_validity` | 300 s | |
| `verification_attempts` | 3 | |
| ⟨r2⟩ `verification_trace_max` | 64 KiB | the `-v` stderr parsed per attempt |
| `enrollment_approval_validity` | 24 h | measured on safe time |
| `enrollment_evidence_freshness` | 90 days at most (Q11 as amended) | |
| ⟨r2⟩ `reverify_after` | 80 days | the supervisor re-verifies before the window lapses (F27) |
| ⟨r2⟩ `residual_drift_ppm` | 100 ppm of the measurement's age | §17.1 item 10 |
| `owned_master_close_grace` | 5 s | |
| `dedicated_close_grace` | 5 s | |
| `lock_event_coalesce` | 1 s | |

**18. Store**: migration `0006_managed_credentials`, `SCHEMA_VERSION` 6. It adds tables only.

| Table | Columns (all `STRICT`) |
|---|---|
| `issuers` | `ca_fingerprint` PK, `public_key`, `state` (⟨r2⟩ `pending`, `active`, `retiring`, `unloaded`, `deleted`, `retired`), `store_kind`, `backup_sha256`, `backup_created_at`, `restored_without_log` INTEGER, `created_at`, `retired_at`, `record_json` |
| `enrollments` | `id` PK, `destination_id`, `account`, `ca_fingerprint` FK issuers, `form`, `marker` UNIQUE, `state`, `verified_at`, `record_json` (⟨r2⟩ with the approved target, the clock measurement and the removal purpose). A partial UNIQUE index on (`destination_id`, `account`, `ca_fingerprint`) where `state` is not final |
| ⟨r2⟩ `foreign_removals` | `id` PK, `marker`, `local_alias`, `account`, `ca_public_key`, `line_sha256`, `state`, `operation_id`, `record_json`. **No foreign key to `issuers`** (the CA is not registered here; F07) |
| `verification_issuance` | `id` PK, `operation_id`, `destination_id`, `account`, `purpose`, `state`, `valid_before`, `reserved_at`, `record_json`; an index on (`destination_id`, `account`, `state`) |
| `pair_preferences` | (`destination_id`, `account`) PK, `mechanism`, `projection_state`, `projection_generation`, ⟨r2⟩ `issuing_cas_json` (replaces revision 1's `enrollment_id`; F05), `updated_at` |
| `managed_slots` | (`environment_id`, `destination_id`, `account`) PK, `binding_id`, `generation`, `state`, `updated_at` |
| `owned_connections` | `id` PK, `binding_id`, `grant_id`, `kind`, `pid`, `start_token`, ⟨r2⟩ `image`, `control_path`, `generation`, `state`, `started_at`, `record_json` |
| `meta` keys | `lock_disclosure_acknowledged_at`, `session_lock_last`, ⟨r2⟩ `session_lock_acknowledged_epoch`, `windows_environment_pipe_token` (ADR-0008 D10 item 1) |

The policy, grant-origin and remote-revocation changes ride in their existing JSON records as defaulted
fields, with no column change. `Txn` methods:
* `insert_issuer`, `issuer`, `issuers`, `set_issuer_state` (⟨r2⟩ CAS along `ca_transition`);
* `insert_enrollment`, `enrollment`, `enrollments_for_pair`, `transition_enrollment` (CAS on state; it
  calls `domain::enrollment::transition`);
* `verified_cas_for_pair`;
* `reserve_verification`, `publish_verification`, `void_verification`, `verification_entries`,
  `pair_residual`;
* `set_pair_preference`, `pair_preference`, ⟨r2⟩ `add_issuing_ca`, `remove_issuing_ca`;
* `claim_slot` (CAS free → held), `release_slot` (CAS by generation), `slots_for_binding`;
* `insert_owned_connection`, `owned_connections_for_grant`, `close_owned_connection` (CAS by
  generation);
* ⟨r2⟩ `insert_foreign_removal`, `transition_foreign_removal`;
* `set_lock_disclosure_ack`, `lock_disclosure_ack`, ⟨r2⟩ `set_acknowledged_lock_epoch`;
* `mark_lost_instances` (U0b row 8; ⟨r2⟩ also marks `pending` instances `destroyed`).

**19. Ports** (`app::ports`). Every one follows the M02 drop contract: no detached work, everything
bounded.

```rust
#[async_trait] pub trait SignatureAuthority: Send + Sync {
    /// ⟨r2⟩ Unlocked early refusal; never admits by itself.
    async fn precheck(&self, facts: &SignatureRequestFacts) -> Result<(), SignRefusal>;
    /// ⟨r2⟩ Takes the grant's gate shared (`signing_gate_wait`), then a fresh read under it.
    /// The permit is held until the response is enqueued (ADR-0008 D2 item 3a).
    async fn admit(&self, facts: &SignatureRequestFacts) -> Result<SignPermit, SignRefusal>;
}
#[async_trait] pub trait IssuerPort: Send + Sync {
    fn status(&self) -> IssuerStatusSnapshot;
    async fn sign(&self, entry: IssuanceRef, subject: &str) -> Result<String, IssuerError>;
    // IssuanceRef { table: Grant | Verification, id: IssuanceId }; returns an OpenSSH cert line.
    // IssuerError { Refused(IssuerRefusal), Unavailable(reason), Timeout, Protocol }
    async fn unload(&self, ca: &CaFingerprint) -> Result<(), IssuerError>;   // ⟨r2⟩ retirement
}
// No runtime port runs existing-access ssh (ADR-0008 D5 §6.3): the remote steps are
// client-executed. ⟨r2⟩ The pure classification the runtime applies to a StepResult is
// heimdall_registry::classify::classify_step(stage, &StepResult, &Expected) -> StepClass, in the
// pure crate below app (§0.6), and the CLI-side runner is heimdall_enroll::remote::SshStepRunner.
#[async_trait] pub trait VerificationRunner: Send + Sync {
    async fn run(&self, plan: &EnrollmentPlan, positive: &str, negative: &str,
                 endpoint: &dyn VerificationEndpoint) -> VerificationOutcome;
}
/// ⟨r2⟩ Implemented by heimdall-credential's verification endpoint.
pub trait VerificationEndpoint: Send + Sync {
    fn locator(&self) -> &EndpointRef;
    fn signatures(&self, key_fingerprint: &str) -> u32;
    fn session_binds(&self) -> u32;
}
/// ⟨r2⟩ Implemented by heimdall-localenv (target.rs); passive (§17.1 items 2, 12).
pub trait TargetEvaluator: Send + Sync {
    fn evaluate(&self, alias: &str) -> TargetEvaluation;
}
/// ⟨r2⟩ Implemented by heimdall-adapters::managed (ADR-0008 D6 item 0).
#[async_trait] pub trait ManagedEffects: Send + Sync {
    async fn generate_key(&self, grant: &GrantId, token: &str) -> Result<KeyRegistration, AdapterError>;
    async fn install(&self, grant: &GrantId, entry: &IssuanceEntry, cert: &str) -> Result<(), AdapterError>;
    async fn destroy(&self, grants: &[GrantId]) -> Result<(), AdapterError>;
    fn materialize(&self, binding: &BindingId, files: &MaterializeSpec) -> Result<MaterializedFiles, AdapterError>; // blocking pool
    fn clear(&self, binding: &BindingId, generation: u64) -> Result<(), AdapterError>;                          // blocking pool
}
pub trait SessionLockSource: Send + Sync {
    fn state(&self) -> LockState;                                  // unlocked | locked | unknown | unavailable
    fn lock_epoch(&self) -> LockEpoch;                             // ⟨r2⟩ { epoch, observed } (latched)
    fn acknowledge(&self, epoch: u64);                             // ⟨r2⟩ clears `observed` for that epoch only
    fn changed(&self) -> tokio::sync::futures::Notified<'_>;       // ⟨r2⟩ a wake-up only; no value is carried
}
#[async_trait] pub trait ConnectionControl: Send + Sync {
    async fn start_master(&self, binding: &BindingId, pair: &AccessPair) -> Result<OwnedConnection, ConnError>;
    async fn close(&self, c: &OwnedConnection, reason: CloseReason) -> Result<(), ConnError>;
    async fn register(&self, binding: &BindingId, pid: u32, created_at: Timestamp)  // ⟨r2⟩ Windows
        -> Result<OwnedConnection, ConnError>;
}
```

The other additions:
* `AdapterDescriptor.remote_credential_effect: bool` (U0b row 7);
* `RevokeOutcome.remote_effects: Vec<RemoteEffect>` (with `latest_valid_before`, `destination_clock`
  and `status`);
* ⟨r2⟩ `IntegrationSnapshot.managed: Option<ManagedSources>` (U0b row 21).

**20. Issuer wire protocol `heimdall-issuer/1`** (internal; ADR-0008 D3 item 3). It is not a public
schema. A golden fixes the message set; frames are at most 64 KiB; and the `IssuerRefusal` variants are
the `IssuanceRefusal` and `VerificationRefusal` sets plus `entry_not_reserved`, `entry_stale`,
`subject_mismatch`, `ceiling_exceeded`, `ca_not_loaded` and `rate_limited`. ⟨r2⟩ It gains the message
pair `{"t":"unload","ca_fingerprint":…}` → `{"t":"unloaded","ca_fingerprint":…}` for retirement
(ADR-0008 D4 item 3), sent only after the CA is `retiring` in the store.

**21. The remote protocol** (internal; ADR-0008 D5 §6.3):
* HM1 keys: `v`, `path_hex`, `dir`, `dir_mode`, `dir_owner_self`, `file`, `links`, `mode`, `owner_self`,
  `size`, `last_byte_newline`, `marker_lines`, `content_hex`, `status`, `reason`; ⟨r2⟩ `lock`
  (`none` | `held`), `lock_token`, `lock_age_s`, `remote_now` (M-F23);
* exit codes: 0, 10, 20, 30, 31; ⟨r2⟩ 40 busy, 41 window expired, 42 lock lost; and 255 from ssh itself;
* ⟨r2⟩ the fence: `mkdir <dir>/.hm-lock.<registry name>`, a `token` file inside it, the 60 s mutation
  window measured with `awk srand()`, the token re-check before the write, release by the owning token
  only, and a stale lock broken by reconcile only (rename aside);
* golden scripts in `tests/contracts/golden/enroll-scripts/`.

**22. Configuration:** no new key. `FORBIDDEN_KEYS` gains `lock_behavior` and `registry_path` under
`[x]`: authority stays out of configuration (spec §13.4).

**23. New public schemas:** `enrollment-plan.schema.json`, `enrollment-result.schema.json`,
`issuer-status.schema.json` and `recovery-bundle.schema.json`. The `ensure-data`, `revoke-data` and
`inspect` schemas are regenerated.

**24. CLI** (`cli.rs`; handlers per U12):

| Command | Request | Notes |
|---|---|---|
| `heimdall issuer init --backup-out <path>` ⟨r2⟩ `[--replace-orphan <fp> (--bundle <file> \| --no-bundle-available)]` | Issuer::Register (+ decision) | TTY only; ceremony D4 (prepared bytes); orphan rules of D4 item 1 |
| `heimdall issuer status [--json]` | Issuer::Status | |
| `heimdall issuer unlock` | Issuer::Unlock | attended |
| `heimdall issuer rotate begin --backup-out <path>` | Issuer::Register{rotation_of} | ceremony |
| `heimdall issuer retire <fingerprint>` | Issuer::Retire | decision |
| `heimdall issuer restore --backup <file> [--not-stolen]` | Issuer::Register{restored_without_log?} | ceremony; passphrase typed |
| `heimdall issuer bundle --out <path> [--redact hostnames]` | Issuer::Bundle | writes the file |
| `heimdall enroll <destination> [--account A] [--form account\|system] [--registry-path P] [--ca F]` | Enrollment::Preview, then Apply | the preview is shown first; `--yes` never skips the decision. ⟨r2⟩ `--account` must equal the catalog's (`account_override_refused`); `--form system` takes the D5 §6.9 path (`EnrollSystemForm`) |
| `heimdall enroll status [--json]` | inspect enrollments | |
| `heimdall enroll verify <enrollment> [--absence]` | Enrollment::Verify{mode} | ⟨r2⟩ `--absence`: the system form's absence check |
| `heimdall enroll remove <enrollment>` / ⟨r2⟩ `--from-bundle F --marker M --alias A` | Enrollment::Remove | decision (account form, foreign); system form: manual instructions and a typed confirmation |
| `heimdall enroll reconcile <operation>` | Enrollment::Reconcile | |
| `heimdall enroll abandon <enrollment>` | Enrollment::Abandon | typed confirmation |
| `heimdall destination prefer <alias> managed\|existing` | Catalog `SetPreference` (§5 item 4b) | then `setup apply` |
| `heimdall access ensure … --strict` | EnsureRequest.connection | |
| `heimdall access lock-behavior --policy P continue\|revoke-on-lock` | Policy::SetLockBehavior | |
| `heimdall access connection-policy --policy P [--existing graceful\|strict] [--multiplexing disabled\|owned]` | Policy::SetConnectionPolicy | |
| `heimdall connections [--json]`, `heimdall connections close <id>` | inspect connections; `Connections::Close` (§5 item 4a) | `close` never signals an unverified process |
| `heimdall internal issuer`, `heimdall internal session-lock-state` | — | hidden; the first refuses a TTY stdin; the second is read-only |
| ⟨r2⟩ `heimdall uninstall [--purge-state [--keep-remote-enrollments --bundle <file>]]` | — (M02 command, extended) | ADR-0008 D4 item 6: a fresh bundle before a purge that keeps enrollments; the K_ca store item's fate stated |

Exit codes are unchanged (ADR-0006 §6).

---

## 6. Questions for the orchestrator

### 6.1 Authority semantics and contract (ADR-0008 §17; full rationale there)

⟨r2⟩ **Ruled** in ADR-0008 §17.1, applied by revision 2:
* **Accepted as recommended, with the §17.1 items:** Q1–Q5, Q8–Q10, Q13, Q15, Q16.
* **Amended:**
  * Q6: re-verification never removes anything (item 5);
  * Q7: only the same approved target and effect, on safe elapsed time, after the item 6 fencing;
  * Q11: at most 90 days; invalidated earlier on a change of destination, account, host key, CA or
    client, or on contrary evidence; the supervisor re-verifies before the lapse;
  * Q12: replaced by item 10;
  * Q14: item 13;
  * Q17: item 14.

⟨r2⟩ **Open: raised by revision 2** (ADR-0008 §17.2). The rulings are kept; units build against the
defaults below, behind one switch each.

| # | Question | Recommended default |
|---|---|---|
| Q18 | Which launches get the kill-on-close job object? ADR-0007 §8 and §11 rejected it for `run` because it kills grandchildren left running on purpose; §17.1 item 8 says "a managed launch" | (a) **Owned-connection launches only** (the program is the verified `ssh`), amending ADR-0007 §8 for those. Non-ssh `run` keeps M02's behaviour. Switch: `launch_uses_kill_on_close_job` |
| Q19 | `-o CertificateFile=none` in the maintenance invocation: ssh_config(5) documents `none` for `IdentityFile` only, and says `CertificateFile` entries add to the list (M-F20) | (a) Keep it as written, record each client's behaviour, and rest the guarantee on the pinned `IdentityAgent` and `maintenance_invocation_never_contacts_heimdall_signer`. (b) for a client that refuses it |
| Q20 | Removing one of two verified enrollments of a pair: "degraded only when no verified enrollment remains" would leave grants whose certificate is under the removed CA reported healthy, while ADR-0005 §3.5 allows no re-issue for it | (a) **Degrade every grant whose pair certificate is under the removed CA**; the clause governs the pair's preference (stays managed while another verified CA remains) |
| Q21 | The ruling's signing-gate test pauses "right after authorization", but the same ruling holds the gate from the fresh read, so a pause there makes the revocation wait instead of refusing the signature | (a) **A pre-check outside the gate** is the pause point; a second test pauses inside the gate and asserts enqueue-before-commit |

Revision 1's table, for the record:

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

⟨r2⟩ **Ruled** in ADR-0008 §17.1:
* P1 and P2: accepted, conditional on item 12. The crate graph is checked in §0.6 and ADR-0008 §18:
  four crates, no cycle, enforced by the `crate-graph` step.
* P3: accepted. Linux evidence stays blocked until measured.
* P4: authorized (pinned by digest, into scratch, exact cleanup).
* P5 and P6: accepted.
* P7: accepted with `remote_stdout_max` 512 KiB, every limit derived with its overhead (§5 item 17).
* P8 and P9: accepted. Round 2 re-reviews this revision.

Revision 1's text, for the record:


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
| B1 | A **disposable 1Password account** with disposable SSH keys | A03's 1Password-vault row (lock the vault, managed logins continue); ⟨r2⟩ A09's row for enrollment and maintenance through 1Password as the existing access; the M02 A11/A35 1Password rows (carried) |
| B2 | **The disposable second Windows account** (one elevation consent) | cross-user refusal for the environment, per-binding and verification pipes; DPAPI cross-user unprotect refusal; Windows ordinary ssh without `-F` |
| B3 | **A disposable macOS standard user account** (admin consent to create and delete it) | the **macOS K_ca product-store row** (login keychain item: written at init, read at issuer start, during lock, after login, ACL behaviour across ad-hoc-signed updates); macOS ordinary ssh without `-F`; macOS cross-user endpoint refusal; with B12, the macOS logout row |
| B4 | **A disposable Windows host** whose system `ssh-agent` may hold test keys | enrollment through the Windows system agent as the source provider (⟨r2⟩ A09's row); A03's Windows real-agent vault row |
| B5 | **An operator at the Windows console** | the "no UAC or credential prompt during `issuer init` and enrollment" human observation. The lock rows do **not** need it (ADR-0004 §2 lock rule) |
| B6 | **A hardware security key** (FIDO2) | enrollment through a touch-required existing identity (the provider-interaction path of D5 §6.10; ⟨r2⟩ A09's row); the M02 A11 touch row (carried) |
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
| ⟨r2⟩ Enrollment of a **password-only or keyboard-interactive** account (a catalog existing-access kind M03 cannot represent; `existing_access_kind_unsupported`) | a later milestone, if spec §7.2 and §7.4 are read to require it (the G01 inventory and the orchestrator decide) | disclosed (ADR-0008 §17.1 item 14; F13) |
| ⟨r2⟩ A kill-on-close job object for `run` of non-ssh programs on managed bindings | ruled by Q18 | default: not applied (ADR-0007 §8 kept) |
| ⟨r2⟩ A real lagging destination clock (the fixtures reproduce only the measurement, not a server that accepts late) | when a fixture host with an independent clock exists | the bound computation is tested; the end-to-end case is not reproducible on shared-kernel containers |
| ⟨r2⟩ Re-issuing a pair's certificate under a newer CA within a live grant | ruled by Q20 | default: not done (ADR-0005 §3.5 kept) |

---

## 9. ⟨r2⟩ Change log (revision 2, task M03-T00-design-fix)

Each round-1 finding, with the ADR-0008 §17.1 ruling that decided it and where this plan closes it.
ADR-0008 §20 lists the design-side changes.

| Finding | Ruling | Closed in this plan |
|---|---|---|
| M03-R01 | 1 | U0 frozen (signing-gate protocol); U0b rows 1, 5, 20; U2 interfaces and the deterministic tests; U3 linearization model; §3 A07; §5 items 17, 19; §0.4 M16; ADR-0008 §17.2 Q21 (§6.1) |
| M03-R02 | 2 | U5 interfaces (`TargetEvaluator`, approved target, `remote_step`) and target-binding tests; U10 `next_step` and `step_refused_when_route_changed_after_approval`; §5 items 3, 10, 12, 14; §0.2 |
| M03-R03 | 3 | U5 verification tests (trace patterns, the negative-inconclusive set); U11 `sshd::Faults`; §5 item 16 (`TraceEvents`, `classify`); §3 A10 |
| M03-R04 | 4 | U5 maintenance-invocation tests; U10 `rotation_and_removal_with_every_managed_binding_released_and_issuer_unavailable`; §5 item 3 (`StepPins.existing_access`); §6.1 Q19 |
| M03-R05 | 5 | U5 `reverification_failure_holds_never_removes`, `reverification_inconclusive_keeps_verified_with_finding`; §5 items 3 (`Verify.mode`), 11 |
| M03-R06 | 6 | U5 fencing tests; U10 `second_step_refused_while_one_outstanding`, reconcile fencing; §5 items 14, 17, 21 |
| M03-R07 | 7 | U0 frozen (20-state table) and `enrollment_recovery_paths_each_tested`; U10 `abandon_from_outcome_unknown_remove_unknown_and_rollback_pending`, `ca_retirement_refused_until_every_enrollment_final_or_abandoned`; §5 item 16 |
| M03-R08 | 8 | U0b row 19; U7 owner paths, interfaces and the Windows/Unix ownership tests; U8 `connect` flow; §5 items 4a, 14; §0.4 M5, M14; §6.1 Q18 |
| M03-R09 | 9 | U9 interfaces and `lock_then_unlock_while_consumer_paused_still_revokes`; U11 `FakeSessionLockSource`; §5 items 16, 18, 19 |
| M03-R10 | 10 | U0b row 6; U5 `remote_clock_measurement_bounds_lag`; U6 residual tests; U11 `LaggingClock`; §5 items 7, 9, 16, 17; §8 (real lag not reproducible) |
| M03-R11 | 11 | U4 `backup::{prepare, write_exact}`, the ceremony order, `retire`, and their tests; U0b row 23; §5 items 2, 18, 20 |
| M03-R12 | 11 | §5 item 3 (`ForeignRemovalTarget`), item 18 (`foreign_removals`); U10 `foreign_remove`, system-form path; U12 commands |
| M03-R13 | 12 | §0.6 crate graph; U0 (`heimdall-registry`, `crate-graph` step, ports); U0b row 21; U3 `issuance_ro`, `assess_read_only`; U5 owner paths (registry crate, `localenv::target`, raw keys); U6 `effects`; §0.4 M1, M10, M15 |
| M03-R14 | 17 | U4 `d5_backup_restores_with_stock_ssh_keygen` (pty); §0.2 |
| M03-R15 | 16 | U7 stable mux path and `two_successive_bindings_share_the_slot_mux_path_through_ordinary_ssh`; U8 render; §5 |
| F01 | 3 | as M03-R03 |
| F02 | 8 | as M03-R08 |
| F03 | 13 | §0.2 product-store evidence; U0 `claims_table_rejects_debug_profile_or_test_store_for_custody_claim`; U13 claim update, `windows_lock_run_is_release_profile_on_dpapi_store`; §3 A03 and claim update; §4.2; §4.4 step 2; §5 items 7, 16 |
| F04 | 15 | U0b row 9; U6 test; U12 TUI hint; §3 fixed-provider row |
| F05 | 15 | U0b row 22; U6 rotation and removal tests (`rotation_keeps_ensure_working_per_account`); U10 `e5_rotation_keeps_projection_and_adds_issuing_ca`; §5 items 4b, 16, 18; §6.1 Q20 |
| F06 | 5, 7 | as M03-R05 and M03-R07; U10 system-form tests |
| F07 | 11 | U10 `foreign_removal_from_second_installation_with_different_catalog`, `foreign_removal_refuses_redacted_bundle_and_line_hash_mismatch`; U11 `SecondInstallation`; §5 items 3, 9, 18 |
| F08 | 11 | U4 `replace_orphan` and `uninstall_store_plan` tests; U12 uninstall tests and commands; §5 item 24 |
| F09 | 17 | §4.4 (three hosts, disjoint pairs, key IDs, deadline-dependent checks); U11 `ThreeHosts`; U13 harness self-tests |
| F10 | 13 | U13 `a10_bound_consumer_issuer_reachability_recorded`; §3 A10 |
| F11 | 13 | §5 items 7, 8 (`revocation.remote` gated; the example); §3 honest-limits row and claim update |
| F12 | 1 | as M03-R01 |
| F13 | 14 | U10 `enroll_through_passphrase_protected_key_prompts_on_owner_tty` (renamed), `enroll_password_only_account_refused_existing_access_kind_unsupported`; §0.4 M6; §5 item 14; §8 |
| F14 | 17 | U12 time-confirmation chore; §3 "background work once" scoped to one boot; §5 item 7 |
| F15 | 18 | U6 `revoke_result_lists_owned_connections_and_ordinary_note`; U8 `deadline_wording_follows_identity_selection`; U12 tests; §5 item 9 |
| F16 | 16 | as M03-R15 |
| F17 | 18 | U1 interfaces and `plain_k_env_key_refused_certificate_required`, `user_must_match_presented_certificates_pair` |
| F18 | 18 | U0b row 8 and `pending_instances_destroyed_at_restart_entries_still_counted`; §5 item 18 |
| F19 | 18 | U9 `disclosure_is_conditional_and_states_saved_limits`, `linux_revoke_on_lock_labelled_signal_unverified`; §5 item 14 (warnings) |
| F20 | 14 | U0b row 13; U10 `reconcile_redispatch_requires_attended_session`; §5 item 3 |
| F21 | 12 | U0b row 5; U3 read-only tests; §0.4 M15 |
| F22 | 17 | U1 `dumpable_control_attach_succeeds` |
| F23 | 12 | U0 owner paths (trait) and `public_schema_has_no_scratch_store_kind`; U4 owner paths (`scratch_store.rs`); §5 item 2 |
| F24 | 1 | U3 linearization model (re-issue, lock revocation, the gate) |
| F25 | 18, P7 | §5 items 3 and 17 (512 KiB, derived) |
| F26 | 17 | §3 "What the lowest-row rule makes of the exit"; §7 B1, B4, B6 |
| F27 | Q11 | U10 `managed::reverify_pass`, `supervisor_reverifies_before_freshness_lapses`; §5 item 17 (`reverify_after`) |

**Checks the rulings asked for:**
* **Item 8** (M02's "no job object"): ADR-0007 §8 and §11 reject kill-on-close for `run` because it kills
  grandchildren left running on purpose (M-F21). There is no conflict for owned `ssh` connections. For
  non-ssh `run`, the ruling's wording conflicts with that rationale, which is held by Q18 (ADR-0008
  §17.2; D8 item 2).
* **Item 12** (the crate graph against the manifests): revision 1 had an `app` ↔ `enroll` cycle and an
  `app` → `localenv` need against the existing `localenv` → `app` edge. Revision 2 removes both
  (`heimdall-registry` below `app`; the `TargetEvaluator` port), and §0.6 and ADR-0008 §18 give the
  checked graph.
