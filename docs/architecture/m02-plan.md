# M02 work breakdown (existing-access vertical slice): revision 2

**Inputs:**

* plan §5 M02 (T01–T06, exit evidence), §4.4, §6;
* spec §5.2, §5.4, §7.2, §8.4, §10, §11.3, §11.6, §12, §13.5, §14.3, §17
  A01/A11/A21/A22/A27/A35, and the requirements those cases cite (R-UX-01, R-UX-04,
  R-CR-01, R-CR-08, R-SS-01–04, R-AP-06, R-RT-04, R-RT-05, R-SE-04, R-DI-06);
* `docs/decisions/0007-existing-access-integration.md` revision 2 (this plan's design ADR);
* `tests/evidence/artifacts/review-m02-design/review.md` (the independent review) and the
  rulings on it in ADR-0007 §12.2;
* ADR-0006 revision 2.15 (the G08 baseline, through §13.18), which this plan extends with
  the revision-3 deltas in §5;
* ADR-0004 (E-3, E6, Q-B and the blocked inputs in §3), ADR-0002 §3.1, §5, §6;
* `docs/research/g03-windows-wsl.md`;
* `tests/fixtures/MANIFEST.md`;
* `docs/architecture/{overview,m01-plan,dependencies}.md`.

**Revision 2 (task M02-T00-design-fix)** applies findings M2-D01–M2-D10 under ADR-0007
§12.2. Changed text is marked **⟨r2⟩**, and §9 maps each finding to its changes. The units
grow from twelve to thirteen: **U0b** makes the changes to existing M01 code explicit
integrator work (M2-D08). Revision 2 itself has not had an independent review.

**Status discipline (M01 rule E15 carried over):** every unit stays `implemented_unverified`
until U11's evidence records exist, whatever its local tests say.

**Skeleton rule (as in M01):** U0 creates every type, trait and function named below. Bodies
are `todo!("M02-Uxx …")` where not yet implemented. A unit replaces the bodies it owns and
adds tests. Shared signatures, tables and limits change only through the integrator, with an
ADR-0006 or ADR-0007 revision. ⟨r2⟩ Exception: no `todo!()` is added to an M01 dispatch path
that a client request can reach. Those changes are U0b's, and they land complete.

**Not decided by this plan:** the open questions in ADR-0007 §12.3 (QR1–QR6) and the
plan-level questions in §6. Where a unit depends on an answer, the unit says so. The
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
  * `crates/store/migrations/**` and the `Txn` signatures;
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
  * the `crates/heimdall/src/cli.rs` clap tree for every M02 command, with handlers calling
    `todo!()` in per-command files;
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
  * lands **together with U0b** as one integrator change set, because the new
    `OperationKind` and `DecisionKind` variants break M01's exhaustive matches until U0b
    handles them.
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
  * ⟨r2⟩ `operation_kind_as_str_equals_request_kind` for every effectful request;
  * ⟨r2⟩ `run_record_classify_golden`: every row of ADR-0007 §8's reader table;
  * ⟨r2⟩ `decision_kind_wire_forms` for `ApplyProjection` and `DeclareInteraction`;
  * migration 0004→0005 on a populated database;
  * a newer `user_version` is refused.

### U0b ⟨r2⟩: M01 integration (existing code that M02 must change)

* **Owner:** the integrator (ADR-0007 §12.2 item 8). No other unit edits these items.
* **Timing:**
  * Starts after the concurrent M01 work on `crates/app/src/operations.rs` and
    `crates/domain/src/revocation.rs` has been committed.
  * References below are to function and type names, because line numbers in
    `operations.rs` move.
  * Lands with U0.
* **Owner paths:**
  * the items below in `crates/app/src/{operations,events,error}.rs` and
    `crates/domain/src/operation.rs`;
  * the shared fakes `crates/testkit/src/lib.rs` (`FakeCredentialAdapter`, its
    `PrepareOutcome` values) and `crates/heimdall/src/testcfg.rs` (its fake `PrepareOutcome`);
  * `tests/model/m02_integration.rs` (hosted by `heimdall-runtime`).
* **Exact changes:**

| # | Function or type (M01) | Today | M02 change |
|---|---|---|---|
| 1 | `Operations::decide` (operations.rs): the `let waiting = match &d.kind` computation and the `match (&record.kind, verdict)` application | handles `ApproveAuthority`, `WidenPolicy`, `ConfirmTime` | adds `ApplyProjection { operation, .. }` and `DeclareInteraction { operation, .. }`: the waiting operation must be `AwaitingApproval` (else `DECISION_STALE`); no A06 delta check (they carry no `AuthorityDelta`); generation check unchanged. **Approve:** set `RecoveryIntent.local.approval = Some(LocalApproval { decision, plan_digest })`, `op_to(Approved)`, resume with `lead_all_bounded`. **Deny:** `settle_failed` with `CAPABILITY_UNAVAILABLE` ("the owner denied the projection change" / "the declaration"); no file is touched |
| 2 | `decision_view` (operations.rs) and `events::decision_kind_name` (events.rs) | three kinds | the two new kinds; the view shows `plan_digest`, the summary counts, `diff_text` and the restore column (bounded, ADR-0006 §3.1) |
| 3 | `Operations::bind` | `if let BindForm::Launch { argv }` checks non-empty and `MAX_ARGV_BYTES`; hash extra `{ binding_id, form }` | validates `LaunchBinding`: `executable` absolute, 1–4096 bytes, no NUL; `holder.pid > 0`; `holder.started_at` 1–64 bytes `[A-Za-z0-9._:-]`. Hash extra `{ binding_id, form: "launch", executable }` or `{ binding_id, form: "materialize" }`; `holder` is excluded (delivery metadata). `MAX_ARGV_BYTES` leaves the contract and becomes a `heimdall-launch` constant |
| 4 | `Operations::drive_bind` | `ensure_data(&b, &g, &Facts::conservative(&g, now), bound)` | `Facts::conservative(&g, tx.grant_prepared_facts(&g.id)?.as_ref(), now)`; in the settling transaction, `tx.set_binding_holder(&b.id, &holder)` when a holder is given |
| 5 | `struct Facts`, `Facts::from_outcome`, `Facts::from_data`, `Facts::conservative`, `fn ensure_data` | four fields; `ensure_data` builds `ConsumerIntegration { signing_endpoint: None, ssh_config_include: None, environment: Vec::new() }` | `Facts` gains `availability`, `provider`, `integration`. `from_outcome` copies them from `PrepareOutcome`; `from_data` copies `EnsureData.{credential_availability, provider, consumer}`; `conservative` takes the stored `PreparedFacts` (integration, provider) and, without them, reports `CredentialAvailability::Unknown`, an empty integration and no time claim beyond `now`. `ensure_data` copies all three. So `ensure`, attached (coalesced) bindings, `bind`, replay and restart all report the same integration |
| 6 | the prepare stage that writes `EffectReceipt::Confirmed` after `CredentialAdapter::prepare`, and the `ReconcileOutcome::Applied` arm where the activation stage reconciles after a restart | the facts live only in `DriveLocal.prepared` | also `tx.set_grant_prepared_facts(&grant, &PreparedFacts::from(&outcome))`, in the same transaction as the receipt. Facts are nonsecret, so storing them is allowed (spec §7.3) |
| 7 | `select_adapter`, `Operations::stage_resolve` | the first adapter meeting the minimums | when the catalog names identities for the scope's pairs, select the adapter whose mechanism they name (`IdentitySource` → mechanism). Pairs naming two mechanisms → `CAPABILITY_UNAVAILABLE`, reason `mixed_mechanisms` (P6). No catalog identity → the M01 behaviour. Recorded in `ResolvedIntent.adapter` as today |
| 8 | the `PrepareRequest` construction in the prepare stage | grant, scope, required, interactive, token, now | adds `pairs: &[PreparePair]` from the catalog (destination, account, identity record, managed alias), empty for M01 adapters |
| 9 | `WorkSpec::from_request` and the minimum check beside `select_adapter` | `capabilities`, `destination_scope_at_least`, `offline_until` | `unattended`: met only by an adapter whose `lock_continuity` is `Verified` and whose interaction is `None`; otherwise `CAPABILITY_UNAVAILABLE` (never in M02) |
| 10 | `Operations::drive` | `Ensure | Delegate`, `Revoke`, `Bind`, then `_ => Ok(())` | **exhaustive:** `SetupApply | SetupRollback | SetupRepair => crate::setup::drive(self, id)`, `Catalog => crate::catalog::drive(self, id)` (U0b declares these `pub(crate)` entry points; U5 writes their bodies), and `Cancel`, `Release`, `Policy`, `Probe` listed explicitly as synchronous. With no wildcard, a future kind fails to compile instead of being skipped at restart |
| 11 | `Operations::recover_after_restart` | leads every open or unresolved operation | loop unchanged; a test asserts that every kind has a driver; the setup driver reconciles from receipts and never re-applies (ADR-0007 §5.7) |
| 12 | `heimdall_domain::operation::RecoveryIntent` | `request`, `resolved` | adds `local: Option<LocalIntent>` (serde default, omitted when absent): `LocalIntent::{Setup(SetupIntent), Catalog(CatalogIntent)}`, each with `approval: Option<LocalApproval>` |
| 13 | `heimdall_domain::operation::OperationKind` and `as_str` | 8 kinds | adds `SetupApply` (`"setup.apply"`), `SetupRollback`, `SetupRepair`, `Catalog`. Effect class `LocalResources` for setup, `Local` for catalog |
| 14 | `crates/app/src/error.rs` | code mapping | `LAUNCH_FAILED`; `ErrorData.reason` passes through |
| 15 | `FakeCredentialAdapter` (testkit) and the `testcfg` fake | five `PrepareOutcome` fields | defaults for the new fields; a configurable integration with two pairs for the tests below |

* **Tests (end-to-end through the real `Operations` and a real scratch `Store`):**
  * `u0b_apply_projection_decision_resumes_exact_waiting_operation`, with deny, stale
    generation and unattended-decide variants;
  * `u0b_declare_interaction_decision_requires_attended_decide` (QR1);
  * `u0b_bind_launch_validates_executable_and_excludes_holder_from_hash`: the same
    `request_id` with another holder replays; another executable is `REQUEST_CONFLICT`;
  * `u0b_integration_provider_and_pairs_survive_ensure_attach_bind_replay_restart`:
    * setup: a fake adapter returns two pairs;
    * steps: `ensure`; a second caller coalesces; `bind`; the same request IDs are
      replayed; `Operations` restarts from the same store; `bind` again;
    * assertion: `consumer`, `provider` and `credential_availability` are equal and
      non-empty in every result;
  * `u0b_restart_dispatches_every_operation_kind`: one journaled operation of each kind in
    its open state; after restart each driver runs; the setup driver calls
    `ProjectionWriter::reconcile` and never `apply` (counting fake);
  * `u0b_mixed_mechanisms_refused_capability_unavailable`;
  * `u0b_unattended_minimum_unknown_is_capability_unavailable`;
  * the full M01 model and integration suites still pass (regression).
* **Depends on:** U0; the concurrent M01 commit.

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
    source role, ADR-0007 §5.2), ⟨r2⟩ `identity_selection(&Evaluation, adopted: &Path) ->
    IdentitySelectionReport` (ADR-0007 §3 item 3), ⟨r2⟩ `executing_constructs(&Evaluation) ->
    Vec<Span>` (Match exec, ProxyCommand, KnownHostsCommand, LocalCommand with
    PermitLocalCommand) `}`.
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
    hosts this Git editor too.
  * ⟨r2⟩ `consent::{ConsentItem { item: ConsentItemId, current: BehaviorDigest, after:
    BehaviorDigest, consented: Option<ConsentedStates { managed, restore }> },
    classify(&[ConsentItem]) -> ConsentNeed { required: bool, reasons: Vec<ConsentReason> }}`
    (ADR-0007 §5.2).
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
    * `consent_rollback_to_consented_restore_needs_none`;
    * `consent_rollback_exposing_new_inherited_hostname_and_agent_needs_decision`;
    * `consent_undetermined_after_needs_decision_unless_equal`;
    * `consent_new_alias_always_needs_decision`;
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
    digest and a classification.
  * `doctor::{DoctorRequest { levels: BTreeSet<ProbeLevel>, ⟨r2⟩ allow_config_commands: bool,
    aliases: Option<Vec<String>>, interactive: bool, local_queries: LocalQueries, redact: bool },
    run(&LocalContext, &DoctorRequest) -> contract::doctor::DoctorReport}`.
  * `probe::{evaluate::ssh_g, agent::list_identities (through ipc::agent_client), network::banner,
    host::verify, auth::authenticate}`:
    * each probe has a timeout and runs in its own process group (Unix, `killpg` in
      `sys.rs`) or a kill-on-close job object without breakaway (Windows, `sys.rs`);
    * ⟨r2⟩ each fills `ProbeRecord.{authorization, executed_config_commands,
      effects_excluded, containment}` exactly as ADR-0007 §6 states;
    * ⟨r2⟩ a level that reaches an executing construct without `allow_config_commands`
      is declined (`config_commands_not_authorized`) before anything runs.
  * `sys`: the third `unsafe` module (overview §9). It holds `account_home`, `killpg`,
    the job objects, the profile folder, and the U4 primitives (exchange, no-replace
    renames, `ReplaceFileW`, handle-based identity and deletion). Each call is wrapped in a
    safe function with its invariant documented.
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
    alias with no executing construct.
  * ⟨r2⟩ `a21_host_verification_with_proxycommand_requires_authorization`.
  * ⟨r2⟩ `a21_authentication_level_single_identity_fixture_signs_exactly_once`: one
    exclusive identity that the server accepts; the count is asserted for this fixture
    only.
  * `a21_hanging_match_exec_killed_with_group_at_timeout`.
  * `a21_agent_that_never_replies_times_out`.
  * `a21_fifo_include_does_not_block`, a Unix `mkfifo` fixture.
  * ⟨r2⟩ `a21_noninteractive_authentication_refused_for_unknown_or_interactive_identity`
    (Q2 as qualified).
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
  * `git_global_file_resolution_matches_git`: three layouts (only `~/.gitconfig`, only XDG,
    neither); Heimdall's choice equals the file `git config --global --add` writes to;
    `GIT_CONFIG_GLOBAL` makes it `git_global_redirected`;
  * `git_run_selection_in_cwd_reports_local_override`;
  * `git_values_never_leave_observation`: a canary `core.sshCommand` value is absent from
    every output.
* **Depends on:** U1, U2, U7 (FakeAgent, hook), U6 (`ipc::agent_client`).

### U4: `heimdall-localenv` projection file transaction

* **Owner paths:**
  * `crates/localenv/src/projection/{mod,plan,replace,apply,observe,cleaner,git}.rs` and
    `crates/localenv/src/materialize.rs`;
  * `tests/integration/projection.rs` and ⟨r2⟩ `tests/integration/projection_git.rs`
    (hosted by `heimdall-localenv`).
* **Interfaces:**
  * ⟨r2⟩ `projection::replace` (ADR-0007 §5.3):
    * `DirHandle::open(&Path) -> Result<DirHandle, Unmanageable>`;
    * `FileIdentity { Unix { dev, ino }, Windows { volume, file_id } }`;
    * `validate(&DirHandle, name, &Base) -> Result<Validated { identity, sha256 }, ReplaceRefusal>`;
    * `stage(&DirHandle, name, &[u8], Mode) -> Staged { identity, name }`;
    * `exchange(&DirHandle, &Staged, Option<&Validated>) -> Result<Exchanged { displaced_name }, ReplaceError>`;
    * `post_validate(&DirHandle, &Exchanged, &Validated, &Staged) -> PostValidation { Valid, Mismatch }`;
    * `restore(&DirHandle, &Exchanged, &Staged) -> RestoreOutcome { Restored, ConflictPreserved { paths } }`;
    * `settle(&DirHandle, &Exchanged, &Validated)`.

    A test-only `ReplaceHook` (points `AfterValidate`, `BeforeExchange`, `AfterExchange`,
    `DuringRestore`, `BeforeSettle`) mirrors the M01 `CleanupHook`. Exchange unsupported →
    `ReplaceRefusal::AtomicExchangeUnsupported`, which the plan turns into manual mode.
  * `projection::LocalProjection` implements the new port `app::ports::ProjectionWriter`
    (§5 item 15):
    * `preview(&ProjectionSpec, &PreviewIntent) -> ProjectionPlan`, read-only;
    * ⟨r2⟩ `apply(&SetupIntent, &mut dyn StageSink) -> ProjectionReceipt`, which executes
      any intent (apply, rollback, repair). The `StageSink` durably appends each stage
      receipt (ADR-0007 §5.7) before the next step;
    * ⟨r2⟩ `reconcile(&SetupIntent, &[StageReceipt]) -> ProjectionReconcile { Applied,
      NotApplied, Restored, ConflictPreserved { paths } }`, by identity, never by content
      alone;
    * ⟨r2⟩ `observe(&ProjectionRecord, &[AliasName]) -> Vec<AliasObservation>`: a passive
      static re-evaluation (behaviour digest, identity selection, block placement) used
      by doctor, the adapters and setup status.
  * ⟨r2⟩ `projection::git`: the B_git and P_git steps inside Git's lock protocol
    (ADR-0007 §5.6).
  * `projection::cleaner::ProjectionCleaner` implements the M01 port `ResourceCleaner`. ⟨r2⟩
    It deletes only when the generation matches **and** the entry has the identity and digest
    in the `ProjectionLocator`; the deletion itself is identity-bound (ADR-0007 §5.8).
    Otherwise it returns `Ok` with nothing deleted.
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
  * ⟨r2⟩ cleanup:
    * `a22_stale_cleanup_generation_n_cannot_delete_n_plus_1`, at the deletion boundary
      with `reconcile::CleanupHook`, as M01 N06;
    * `a22_same_bytes_new_identity_is_not_deleted_by_cleanup`;
    * `a22_cleanup_target_swapped_at_deletion_is_moved_back`;
  * ⟨r2⟩ `exchange_supported_on_target_fs`: records, per harness, whether atomic exchange
    works (APFS, devbox ext4, WSL ext4, container overlay), and that a filesystem without
    it gives manual mode (settles F24);
  * `windows_replace_preserves_dacl`, ⟨r2⟩ `windows_replace_retains_displaced_identity` and
    `rendered_file_loads_on_target_client`: Windows native. `ssh -G -F` reads the rendered
    user file and P; the DACL is compared before and after through the harness; the file
    ID of the backup equals the validated identity;
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
  * `git_crash_with_lock_holding_staged_or_displaced_reconciles`;
  * `git_rollback_after_user_added_value_keeps_user_value`;
  * `git_rollback_after_edit_inside_block_is_marker_edited`;
  * `git_user_set_after_include_wins` (settles F22's include precedence);
  * `git_spaced_client_path_is_quoted_and_runs` (Windows native: `[clients] ssh` at a spaced
    scratch copy of the verified client; `git ls-remote` reaches the fixture sshd).
* **Depends on:** U2, U3 (`sys`, `git`), U7 (ScratchHome).

### U5: Setup and catalog operations (app, store, runtime wiring)

* **Owner paths:**
  * `crates/app/src/{setup,catalog}.rs`, including the bodies of `setup::drive` and
    `catalog::drive` that U0b's `Operations::drive` calls;
  * `crates/store/src/ext_m02.rs` (the bodies of the U0 `Txn` signatures, and
    `Store::open_read_only`);
  * `crates/runtime/src/{dispatch,service}.rs` (M02 routing and wiring only);
  * `tests/model/setup.rs`, `tests/integration/store_m02.rs` and ⟨r2⟩
    `tests/e2e/setup_dispatch.rs` (hosted by `heimdall-runtime`, `heimdall-testkit` and
    `heimdall-runtime` respectively).
* **Interfaces:**
  * `Operations::{setup_preview, setup_apply, setup_rollback, setup_repair, catalog}(&Caller,
    …) -> OpResult<Completed>`. `OperationsConfig.projection: Option<Arc<dyn ProjectionWriter>>`.
  * ⟨r2⟩ **Decision flow** (ADR-0007 §5.2, as qualified by §12.2 item 4):
    * the plan's `consent::classify` result decides;
    * when a decision is required, a `DecisionKind::ApplyProjection { operation, plan_digest,
      summary }` record is created with the operation in `AwaitingApproval`. Attended
      sessions get `APPROVAL_REQUIRED` and unattended ones `INTERACTION_REQUIRED`, both
      with `next.decision_ref`;
    * when none is required, the operation proceeds directly;
    * after `Decide approve`, the driver recomputes the plan; a digest mismatch is
      `CONFIG_CONFLICT` with nothing written.
  * ⟨r2⟩ Effect discipline as in ADR-0006 §14.1 and ADR-0007 §5.7: `SetupIntent` in
    `RecoveryIntent.local`, the effect token, `Attempted`, then `ProjectionWriter::apply`
    with a `StageSink` that appends each receipt in its own transaction. On restart,
    `reconcile` is called, never a second `apply`.
  * The catalog has upserts with revisions; profiles reuse `upsert_profile` and snapshots.
    A `LimitedConsumer` is refused with `CAPABILITY_UNAVAILABLE`.
  * ⟨r2⟩ `DeclareInteraction` creates a `DecisionKind::DeclareInteraction` record (QR1);
    approval stores the `InteractionDeclaration`. `WithdrawDeclaration` narrows and needs no
    decision. `RemoveDestination` marks the projection stale and changes no file.
  * Destination identity:
    * `DestinationId` stays durable when the alias changes (spec §4.2);
    * a managed alias collision is `CONFIG_CONFLICT` with reason `alias_collision`;
    * the adapter registry maps `IdentitySource` to `native_agent` or `onepassword` (U6),
      for `ensure`.
  * The dispatcher routes `Setup` and `Catalog` behind `setup/1`. `Service::start` wires
    `LocalProjection`, `ProjectionCleaner` and the adapters, and gives the adapters the
    `ProjectionWriter::observe` handle.
  * `Store::open_read_only` never migrates. An older schema is reported, never upgraded.
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
  * ⟨r2⟩ `withdraw_declaration_needs_no_decision`;
  * ⟨r2⟩ `projection_resource_generation_and_identity_cas`;
  * `open_read_only_refuses_newer_and_never_migrates`;
  * restart recovery: ⟨r2⟩ `restart_reconciles_attempted_apply_never_reapplies`, for first
    adoption and update, with in-process and process-crash variants labelled as M01 N06
    requires;
  * `projection_events_carry_generation_and_change`;
  * ⟨r2⟩ end-to-end through the real dispatcher and store (M2-D08):
    * `e2e_setup_preview_apply_decide_restart_through_dispatcher`;
    * `e2e_catalog_then_ensure_bind_carry_pairs_and_selection`;
    * `e2e_setup_without_capability_is_schema_unsupported`;
  * canary scan over every result.
* **Depends on:** U0, U0b, U4 (port implementation for integration), U6 (adapters
  registered).

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
        from `ProjectionWriter::observe`.
    * `reconcile` observes the materialization.
    * `revoke` removes it. Its outcome is `remote_pending: []` with no expiry.
  * ⟨r2⟩ `state::{interaction_profile(&IdentityRecord, Option<&InteractionDeclaration>, &EndpointObservation,
    now) -> (InteractionKind, EvidenceBasis)}`: the ADR-0007 §7 table, including declaration
    lapse.
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
  * ⟨r2⟩ `agent::DisposableSshAgent::{start(&Scratch, AgentOptions { askpass_log: Option<PathBuf> })
    -> Running { socket, pid }, add_key(&FixtureKey, KeyConstraints { confirm: bool }), stop()}`:
    `ssh-agent -D -a <scratch>/agent.sock` with `HOME=<scratch home>`, and, for confirmation
    tests, `SSH_ASKPASS=<hm-fixture-hook askpass>` plus `SSH_ASKPASS_REQUIRE=force` in the
    agent's environment. The askpass mode logs each invocation and denies. Stopped by exact
    PID.
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
    * `askpass <log>`.

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
  * ⟨r2⟩ `hook_modes_behave_as_documented`.
* **Depends on:** U0, U2 (static evaluation for the guard).

### U8: Process contract (`heimdall-launch`), `run`, `connect`, holder release

* **Owner paths:**
  * `crates/launch/src/{resolve,env,meta,unix,windows,handoff}.rs`;
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
    4. the Q2 check, as qualified (ADR-0007 §7; QR5: any pair);
    5. launch.
  * `connect_cmd::connect(alias)`: `inspect destinations`, then the verified client, then
    launch.
  * `Operations::release_exited_holders(&self, &dyn ProcessLiveness) -> OpResult<Vec<BindingId>>`
    and `Supervisor::holder_pass`. These are bounded, use jittered intervals (ADR-0006
    §13.6 item 4), and read liveness through the M01 `platform::process_start_time` (Q5).
    ⟨r2⟩ `HolderState::Unknown` never releases.
  * ⟨r2⟩ Test-only hooks, env-gated through `testcfg` and never compiled into release builds:
    * `HEIMDALL_TEST_PRE_EXEC_PAUSE=<fifo>` blocks after `launching` until the fifo is
      opened;
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
    * non-interactive `run`: exit 3, `INTERACTION_REQUIRED` with reason
      `interaction_unknown`, a `prelaunch_failed` record, proxy count 0 and askpass count
      0 (settles F23).
  * ⟨r2⟩ `a11_declared_none_allows_noninteractive_launch_and_result_says_declared`.
  * ⟨r2⟩ `a11_multi_pair_binding_refused_when_any_pair_needs_interaction` (QR5).
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
      records it.
  * ⟨r2⟩ `identity declare-interaction` shows the decision text (ADR-0007 §7) and follows
    the confirmation contract.
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
    qualified);
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
  * ⟨r2⟩ records each settled `[I]`/`[U]` fact of ADR-0007 (F20–F24, the include-state
    inference, BOM/CRLF acceptance, exchange support) per platform;
  * demonstrates T06 as a scripted transcript;
  * moves units from `implemented_unverified` to `verified` only when their tests passed in
    a recorded run.
* **Depends on:** all.

## 2. Order and parallelism

```text
U0 skeleton + contract rev 3  ┐ one integrator change set, after the Q1–Q8 rulings and the
U0b M01 integration           ┘ QR1–QR6 answers, and after the concurrent M01 commit lands
 ├─► U1 sshconf parse ──────────────┐
 ├─► U2 sshconf eval/render/edit/   │ (wave 1, parallel; U2's text tests go green when U1 lands)
 │      consent/gitedit ────────────┤
 ├─► U7 testkit fixtures ───────────┤ (its identity guard needs U2's evaluator)
 ├─► U6 adapters + agent client ────┤ (tests need U7)
 └─► U8 core: resolve/env/meta/exec/spawn/handoff
                                    ▼
     U3 discovery/doctor/probes/git (U1,U2,U6,U7)   U4 projection files (U2,U3 sys+git,U7)  (wave 2)
                                    ▼
     U5 setup/catalog ops + store + runtime (U0b,U4,U6)
     U8 run/connect wiring + holders (U0b,U3,U5,U6)                                     (wave 3)
                                    ▼
     U9 CLI surface (U3,U5,U8)   U10 TUI (U3,U5,U8)                                     (wave 4)
                                    ▼
     U11 exit suite + native evidence + matrix                                          (wave 5)
```

⟨r2⟩ The units add up to **thirteen**: U0 and U0b, both the integrator's, plus eleven
implementation units, with U8 delivered in two phases. File conflicts are designed out:

* U0 owns `cli.rs` and every signature;
* U0b alone edits existing M01 code (`operations.rs`, `events.rs`, `error.rs`,
  `domain/operation.rs`, the shared fakes). U5 supplies only the bodies of the
  `setup::drive` and `catalog::drive` entry points that U0b declares;
* U5 owns `runtime/{dispatch,service}.rs`, and U8 owns only `holder_pass` in `supervisor.rs`;
* U3 and U4 share the crate `heimdall-localenv` but disjoint files. U4 calls U3's `sys` and
  `git` modules and does not edit them.

Serialize anything that touches authority semantics, a schema version or the store
migration through the integrator (plan §7.3). Revision 1 had the independent review its
plan asked for (`review-m02-design/review.md`). Revision 2 applies it, and has not itself
been re-reviewed.

## 3. Milestone exit mapping (plan §5 M02 "Exit evidence")

| Exit claim / case | Proven by (tests) | Native runs (§4) |
|---|---|---|
| **A01**: no remote change, no key export, no mandatory prefix, unaffected aliases still work, personal profile without a repository | U2 unaffected-name and managed-values properties; U4 `a22_apply_then_rollback_*`, `private_key_files_never_opened`; U9 `a01_*` (5 tests, isolation arguments only, two agents); U5 `catalog_*`, `e2e_catalog_then_ensure_bind_*` | macOS, Linux devbox, Windows 11 with scratch `-F`; WSL disposable distribution and Docker container with **ordinary ssh, no `-F`** |
| **A11**: ordinary access first-class; non-interactive returns explicit interaction or capability state without a popup or unapproved fallback | U6 `a11_*` (7), `a35_identity_selected_by_public_key_with_identities_only`; U8 `a11_noninteractive_run_refuses_interactive_identity_before_launch`, ⟨r2⟩ `a11_confirm_constrained_native_key_refused_before_agent_contact`, `a11_declared_none_*`, `a11_multi_pair_*`, `a11_interactive_connect_succeeds_after_provider_approval`; U9 `a11_noninteractive_errors_exit_codes`, ⟨r2⟩ `a35_wrong_key_exclusive_selection_fails_without_fallback` (the "no unapproved fallback" evidence, for exclusive selection; non-exclusive selection is reported, never claimed, QR4); U3 `a21_noninteractive_authentication_refused_*` | all three, fixture level; native ssh-agent lock and ⟨r2⟩ confirm-constrained key on macOS and Linux; 1Password, Windows system agent (incl. its confirm row) and hardware-key rows blocked (§7) |
| **A21**: default doctor does no exec, provider contact, signing, network or mutation; explicit probes classified and bounded | U3 `a21_*` (13 tests), including ⟨r2⟩ the hook classification and authorization tests; U9 `a21_cli_*` (2); U10 `search_never_probes`, `config_commands_authorization_requires_typed_yes` | all three (Windows canary through `cmd.exe`, F13) |
| **A22**: relevant behaviour correct; dynamic unknowns stay unknown; unrelated content and newer edits survive; generation deterministic | U1 corpus; U2 properties (soundness, round trip, determinism, ⟨r2⟩ consent); U3 `corpus_*` against `ssh -G -F` per client, ⟨r2⟩ `corpus_identity_list_matches_ssh_g`, `bom_and_crlf_acceptance`; U4 `a22_*` (⟨r2⟩ 28 tests incl. race injection, commit points, identity-bound cleanup), `exchange_supported_on_target_fs`, `windows_replace_*` (2), the Git tests (10); U5 decision, consent and restart tests; U9 `a22_cli_setup_conflict_then_repair`. ⟨r2⟩ The ADR-0007 §5.9 cases are stated as unsupported and are not counted | all three clients (10.3p1, devbox client, in-box 9.5p2); Windows DACL and displaced-identity retention; exchange support per filesystem |
| **A27**: no stdout contamination or shell injection; child streams and status preserved; setup failure distinguishable | U8 `a27_*` (⟨r2⟩ 24 tests; setup failure is distinguishable by `prelaunch_failed`, and an undetectable pre-exec stop is classified `indeterminate`, never "launched"); the SIGPIPE test records a limitation, not fidelity | all three; Windows Ctrl-C and resize through pseudoconsoles (interactive console row blocked, §7) |
| **A35**: verified executable and identity used; exact limitations; existing-auth not second-class | U6 `a35_identity_selected_by_public_key_with_identities_only`, `adapters_never_send_*`; U7 `ManyKeys`, ⟨r2⟩ `client_command_never_adds_selection_options`; U8 `a27_git_*`, `a27_scp_*`, ⟨r2⟩ Git run tests; U9 `a35_*` (⟨r2⟩ 7 tests: two counting agents, inherited fallback agent- and file-backed, mutation check), `a01_*`; matrix rows | macOS and Linux: real disposable `ssh-agent` × {ssh, git, scp, sftp} × {ordinary alias, run-bound} × {wrong key, inherited fallback (agent, file), too many keys, IdentityAgent overriding SSH_AUTH_SOCK}; Windows: fixture pipe agent (selection) × the same; Windows system agent, 1Password live and Linux arm64 blocked (§7) |
| "A participant can connect without a mandatory work wrapper" | U9 `a01_cli_adopt_*` and the T06 scripted transcript | WSL disposable distribution (ordinary ssh); the human participant walkthrough is an owner input (§7 B7) |
| "No remote authentication change, key export, or provider-policy bypass was needed" | `a01_no_remote_change`, `a01_no_key_export`, `adapters_never_send_*`, the identity selection tests (IdentityAgent is the provider's own endpoint; nothing relays) | all three |
| "Does not claim managed unattended access until M03" | U6 `a11_unattended_minimum_is_capability_unavailable_*`; U0b `u0b_unattended_minimum_*`; matrix labels | all three |
| R-RT-05 (no blind replay) | U8 `run_retry_with_same_request_id_never_relaunches_automatically`; U5 `restart_reconciles_attempted_apply_never_reapplies`; U0b `u0b_restart_dispatches_every_operation_kind` | all three |
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
| A11 | ✔ fixture + disposable ssh-agent lock + ⟨r2⟩ confirm-constrained key | ✔ same | ✔ fixture pipe states | — | 1Password live (B1); Windows system agent, incl. its confirm-constrained row (B4); hardware touch (B6) |
| A21 | ✔ | ✔ | ✔ | — | — |
| A22 | ✔ client 10.3p1; ⟨r2⟩ APFS exchange | ✔ devbox client; ext4 exchange | ✔ in-box 9.5p2, DACL and displaced-identity retention, ⟨r2⟩ junction reparse row; symlink cases `platform_only` Unix | ✔ ext4 exchange | ⟨r2⟩ Windows file-symlink reparse row (B10) |
| A27 | ✔ pty | ✔ pty | ✔ pseudoconsole, batch rules, ⟨r2⟩ `spawned` record, launcher-kill holder row | — | interactive console Ctrl-C/resize observation (B5, P-W07) |
| A35 | ✔ real disposable ssh-agent × 4 clients × 2 paths × 5 fixtures | ✔ same | ✔ fixture pipe agent × in-box ssh, Git (System32 via the Q7 include and via run-time injection, and bundled MSYS as a recorded limitation), scp, sftp | ✔ ordinary path | 1Password all platforms (B1); Windows system agent (B4); Linux arm64 (B9) |

Records follow `tests/evidence/record.schema.json` and the lowest-row rule
(`tests/evidence/README.md`, ADR-0004 §4). A case with a blocked row is `blocked`, with the
input named. Its platform rows that ran may be `verified`. In-process reconstructions are
labelled as such, as in M01 N06.

## 5. Contract additions: final ADR-0006 revision 3 deltas

⟨r2⟩ This is the final form for the integrator (ADR-0007 §10 summarizes it). All of these
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
     new_state|exposes_inherited|undetermined_changed|git_selection_changed }> }`.
   * `GitConfigChange { applicability: applicable|not_applicable, reason: Option<String>,
     global_file: Option<GitGlobalFile { path_display, resolution: home_gitconfig|xdg_config|created }>,
     previous_values: Vec<GitValueObservation { scope: GitScope, origin_display: Option<String>,
     value_sha256: String, count: u32 }>, include_block: Option<FileChange>, managed_file:
     Option<FileChange>, effective_before: GitSshSelection, effective_after: GitSshSelection }`.
     For an applicable change, `previous_values` is empty (ADR-0007 §5.6).
   * `GitSshSelection { source: env_git_ssh_command|config|env_git_ssh|default, scope:
     Option<GitScope>, classification: verified_client|bundled_msys|other|undetermined }`;
     `GitScope { system, global, local, worktree, command }`.
   * `SetupResult { generation: u64, items: Vec<ItemOutcome { item: ProjectionItem, outcome:
     applied|not_applied|restored|conflict_preserved, files: Vec<FileOutcome { role,
     path_display, state: applied|not_applied|restored|written_inactive|removed|conflict_preserved }> }>, remaining: Vec<RemainingArtifact { kind:
     backup|conflict_file|manual_block|state_store|recovery_record, path_display }> }`.
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
   * ⟨r2⟩ `WithdrawDeclaration { identity, request_id }`, narrowing, with no decision.

   `EndpointRef { kind: unix_socket|named_pipe, locator: String }`. `kind()` is `"catalog"`,
   with the action in the hash extras.
4. **Capability `setup/1`.** It gates the Setup and Catalog requests; without it the answer
   is `SCHEMA_UNSUPPORTED`. A `LimitedConsumer` role gets `CAPABILITY_UNAVAILABLE`.
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
     selection_observed_at: Timestamp }>`.

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
     Option<ConfigProvenance>, certainty: determined|undetermined }> }`.
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
      none|process_group|job_object }`;
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
      ⟨r2⟩ `atomic_exchange_unsupported`, ⟨r2⟩ `conflict_artifact_present`
      (revision 1's `inherited_identities` is withdrawn);
    * clients: `client_not_found`, `client_unsupported_version`, `git_ssh_unreachable_agent`,
      ⟨r2⟩ `git_ssh_command_present`, ⟨r2⟩ `git_global_redirected`,
      ⟨r2⟩ `git_config_lock_held`;
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
    * ⟨r2⟩ `mixed_mechanisms`, `config_commands_not_authorized`, `git_ssh_command_present`.
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
        &[StageReceipt]) -> ProjectionReconcile; observe(&ProjectionRecord, &[AliasName]) ->
        Vec<AliasObservation> }` (U4);
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
      `RecoveryIntent.local: Option<LocalIntent { Setup(SetupIntent), Catalog(CatalogIntent) }>`;
      `LocalApproval { decision, plan_digest }`;
    * ⟨r2⟩ `domain::projection::{ProjectionSpec, ManagedAliasSpec, ProjectionRecord,
      ProjectionPlan, SetupIntent { plan_digest, intent, generation, approval, consent:
      ConsentRecord, files: Vec<FileStep> }, FileStep { role, path, base, target, commit,
      staged_name, displaced_name }, FileIdentity, ProjectionLocator { role, path, identity,
      sha256 }, ConsentRecord { items: BTreeMap<ItemId, ConsentedStates { managed: BehaviorDigest,
      restore: BehaviorDigest, decision: DecisionId }> }}`;
    * `domain::catalog::{DestinationRecord, DestinationDefinition, IdentityRecord,
      IdentitySource, InteractionProfile, ⟨r2⟩ InteractionDeclaration { interaction,
      fingerprint, endpoint, declared_at, expires_at, decision }}`;
    * `domain::holder::{ProcessHolder, HolderState}`;
    * ⟨r2⟩ `resource::OwnerRef::Projection { environment: EnvironmentId }` for projection
      resources;
    * ⟨r2⟩ `PreparedFacts { availability, provider, integration, recorded_at }`.
18. **Store.**
    * Migration `0005_existing_access`, `SCHEMA_VERSION` 5:
      * tables `destinations` (alias unique) and `identities` (fingerprint unique);
      * ⟨r2⟩ `interaction_declarations` (one live row per identity);
      * `binding_holders`;
      * ⟨r2⟩ `grant_prepared_facts` (one row per grant, nonsecret);
      * ⟨r2⟩ `projection_consent` (per item: consented managed and restore digests,
        decision);
      * projection records in the existing `resources` table (kind `config_projection`,
        owner `projection`, locator = canonical `ProjectionLocator`).
    * `Txn` methods: `{upsert,remove}_destination`, `destination`, `destination_by_alias`,
      `destinations`, `{upsert,remove}_identity`, `identity`, `identities`,
      ⟨r2⟩ `{put,withdraw}_interaction_declaration`, ⟨r2⟩ `interaction_declaration`,
      `projection_resources`, `put_projection_resource` (generation CAS),
      ⟨r2⟩ `{set,get}_projection_consent`, `set_binding_holder`, `binding_holders`,
      ⟨r2⟩ `set_grant_prepared_facts`, ⟨r2⟩ `grant_prepared_facts`.
    * `Store::open_read_only`.
19. **Config.**
    * An optional `[clients]` table (`ssh`, `scp`, `sftp`, `git`, `ssh_keygen`: absolute
      paths to existing regular files) with `deny_unknown_fields`.
    * ⟨r2⟩ `[setup] declaration_validity_days` (default 30, range 1–90; QR1).
    * `FORBIDDEN_KEYS` is unchanged, and config still carries no socket paths.

## 6. Questions for the orchestrator

The authority-semantics questions are in ADR-0007: Q1–Q8 with their rulings (§12.1, §12.2),
and ⟨r2⟩ QR1–QR6 raised by this revision (§12.3). Units build against the recommended
answers. P1 and P2 were ruled in ADR-0007 §12.1. ⟨r2⟩ The plan-level questions of this
revision, none of them authority semantics:

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
