# M02 work breakdown (existing-access vertical slice): revision 1

**Inputs:**

* plan §5 M02 (T01–T06, exit evidence), §4.4, §6;
* spec §5.2, §5.4, §7.2, §8.4, §10, §11.3, §11.6, §12, §14.3, §17 A01/A11/A21/A22/A27/A35,
  and the requirements those cases cite (R-UX-01, R-UX-04, R-CR-01, R-CR-08, R-SS-01–04,
  R-AP-06, R-RT-05, R-SE-04, R-DI-06);
* `docs/decisions/0007-existing-access-integration.md` (this plan's design ADR);
* ADR-0006 revision 2.14, the G08 baseline this plan extends through the revision-3 deltas
  in §5;
* ADR-0004 (E-3, E6, Q-B and the blocked inputs in §3), ADR-0002 §3.1, §5, §6;
* `docs/research/g03-windows-wsl.md`;
* `tests/fixtures/MANIFEST.md`;
* `docs/architecture/{overview,m01-plan,dependencies}.md`.

**Status discipline (M01 rule E15 carried over):** every unit stays `implemented_unverified`
until U11's evidence records exist, whatever its local tests say.

**Skeleton rule (as in M01):** U0 creates every type, trait and function named below. Bodies
are `todo!("M02-Uxx …")` where not yet implemented. A unit replaces the bodies it owns and
adds tests. Shared signatures, tables and limits change only through the integrator, with an
ADR-0006 or ADR-0007 revision.

**Not decided by this plan:** the questions in ADR-0007 §12 (Q1–Q8). Where a unit depends on
an answer, the unit says so. The recommended answer is the default it builds against, and
the integrator flips the switch if the ruling differs.

## 0. Ground rules for every unit

**Ownership and test targets**

* Write only inside the owner paths below, plus the unit's own test files. These files change
  only through the integrator:
  * `Cargo.toml`, `Cargo.lock`, `clippy.toml`;
  * `crates/contract/**`, `crates/domain/**`;
  * `crates/app/src/{ports,context,ensure,lib}.rs`;
  * `crates/store/migrations/**` and the `Txn` signatures;
  * `crates/heimdall/src/cli.rs` (the clap tree);
  * ADR-0006, ADR-0007, this file.
* Test targets follow the M01 convention (m01-plan §0, review F09). Every suite is a real
  `[[test]]` with `path = "../../tests/<layer>/<name>.rs"`, hosted by the crate that already
  has the dependency edges. There is no `#[path]` inclusion, and `check.sh` fails a target
  that runs 0 tests.

**Fixtures and the owner's material**

* Tests never touch the owner's real material:
  * never read or write `~/.ssh`;
  * never use the owner's agents (`SSH_AUTH_SOCK` is unset or pointed at a scratch socket);
  * never open `\\.\pipe\openssh-ssh-agent` or a 1Password socket.
* Product code under test receives the user-configuration path through the env-gated test
  configuration (M01 `testcfg` pattern; never compiled into release builds). Every `ssh`
  a test runs uses `-F <scratch user config>` (ADR-0007 §9).
* Agents are disposable `ssh-agent -a <scratch>/agent.sock -D` processes, stopped by exact
  PID, or the `testkit::agent::FakeAgent` (U7). Keys are generated per run and never
  committed. Synthetic public keys (for example a FIDO `sk-` public key) may be committed
  as public fixtures, stated in the file header.
* SSH servers run only as `testkit::sshd::LoopbackSshd` (non-root `sshd -D`, `127.0.0.1`,
  ephemeral port, per-run host and user keys, `PerSourcePenalties no` as in MANIFEST row 1),
  or as the M00-T03 Docker fixtures published on `127.0.0.1`. There are no other listeners
  (AGENTS.md).
* Canaries: `HEIMDALL_CANARY_*` private-key canaries and fake-agent canaries are checked with
  `testkit::assert_no_canary` over every envelope, event, log line, error, doctor report,
  rendered file, run record and side-channel line (ADR-0004 §4).

**Tests and evidence**

* Property tests use proptest: at least 256 cases, a fixed default seed, committed
  `proptest-regressions/`, and `PROPTEST_RNG_SEED` reproduces a run.
* Platform-only tests are `#[cfg]`-gated and listed in the case index as `platform_only`.
  A platform that is missing makes a row `blocked`, with the platform named exactly.

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
  * `crates/contract/**` (§5 deltas) and `crates/domain/src/{catalog,projection,holder}.rs`;
  * `crates/domain/src/decision.rs`, for `ApplyProjection` (Q1);
  * `crates/app/src/ports.rs` (new ports);
  * migration `crates/store/migrations/0005_existing_access.sql`, with `SCHEMA_VERSION` 5 and
    the `Txn` signatures;
  * the `crates/heimdall/src/cli.rs` clap tree for every M02 command, with handlers calling
    `todo!()` in per-command files;
  * `schemas/public-api/**` (regenerated);
  * `docs/architecture/{overview,dependencies}.md`;
  * `docs/sources/**`, for the 1Password excerpts below only;
  * ADR-0006 revision 3.
* **Does:**
  * applies §5 after the Q1–Q8 rulings;
  * records the new dependencies (§1 U0 note below);
  * extends overview §1 with the four crates and overview §9 with the third `unsafe`
    module, `crates/localenv/src/sys.rs` (ADR-0007 §13);
  * moves the code golden table from 29 to 30 rows (`LAUNCH_FAILED`);
  * adds to `docs/sources` the pinned excerpts for the 1Password agent socket paths and the
    `agent.toml` location, from the agent/config and get-started pages that G03-S12 already
    pins by hash. U6 hardcodes no 1Password path until these exist (ADR-0007 §7). Until
    then, detection uses `SSH_AUTH_SOCK` and IdentityAgent references in the configuration
    only.
* **Dependency note:**
  * the `glob` crate (Include globbing, bytewise order);
  * ratatui 0.30.2 and crossterm 0.29.0 enter the lock;
  * tokio feature `process`;
  * windows-sys features `Win32_System_JobObjects`, `Win32_System_Console`,
    `Win32_UI_Shell` (profile folder) and the existing `Win32_Storage_FileSystem`
    (`ReplaceFileW`);
  * dev-only: `rustix` (`pty`, `termios`, `process`) for pty tests, and the `ssh-key`
    feature `ed25519` in `heimdall-testkit` for `FakeAgent` signing;
  * each gets a reason, licence and rejected alternatives in `dependencies.md`.
* **Tests:**
  * contract goldens (30 codes);
  * schema export byte-identical;
  * the new examples (`schemas/examples/{request.setup.*,request.catalog.*,doctor-report,run-record.*}.json`)
    round-trip exactly;
  * `BindForm::Launch` without `argv` (Q8);
  * migration 0004→0005 on a populated database;
  * a newer `user_version` is refused.

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

### U2: `heimdall-sshconf` evaluator, renderer, user-file editor (pure)

* **Owner paths:**
  * `crates/sshconf/src/{eval,relevant,render,edit}.rs`;
  * `tests/model/sshconf_eval.rs` and `tests/model/sshconf_edit.rs` (hosted by
    `heimdall-sshconf`).
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
    PKCS11Provider/SecurityKeyProvider; each a `Resolved`)`, relevant(&Evaluation) -> RelevantBehavior,
    diff(&RelevantBehavior, &RelevantBehavior) -> Vec<BehaviorChange>}`.
  * `render::{AliasName::parse, HostName::parse, RenderPath::{unix, windows, pipe},
    ManagedAlias { alias, hostname, port, user, identity_agent, identity_files, identities_only },
    render_managed(&[ManagedAlias], PathStyle) -> Result<Vec<u8>, RenderError>,
    render_include_block(&MarkerId, &RenderPath, Newline) -> Vec<u8>}`. The rules follow
    ADR-0007 §4.
  * `edit::{find_blocks(&[u8]) -> Vec<FoundBlock { marker, range, intact, position:
    BlockPosition { BeforeFirstSection, Conditional(Span) } }>, plan_insert(Option<&[u8]>,
    &IncludeBlock) -> Result<InsertPlan { bytes, offset, newline, had_bom }, EditRefusal>,
    plan_remove(&[u8], &MarkerId, expected_block: &[u8]) -> Result<Vec<u8>, EditRefusal>}`.
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
  * render: deterministic (two renders give identical bytes); sorted; refused values
    (`%` in a hostname, `${` or `"` in a path, a wildcard alias); `%%` escaping; Windows
    forward slashes and `//./pipe/`;
  * edit: `plan_remove(plan_insert(x)) == x` byte-exactly for arbitrary `x` (proptest),
    including CRLF, a BOM, no trailing newline, an empty file and a missing file; insertion
    goes before the first section line or top-level directive; a duplicate marker is
    refused; an edited marker is `MarkerEdited`; a marker moved below `Host` is
    `Conditional`; bytes outside the block are never changed.
* **Depends on:** U0 (AST types fixed). Tests that parse text go green when U1 lands.

### U3: `heimdall-localenv` discovery, passive doctor, explicit probes

* **Owner paths:**
  * `crates/localenv/src/{paths,fs,clients,agents,known_hosts,doctor,local_query,sys}.rs`
    and `crates/localenv/src/probe/**`;
  * `tests/integration/doctor.rs` and `tests/integration/sshconf_vs_ssh_g.rs` (hosted by
    `heimdall-localenv`).
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
    System32 client (E6).
  * `agents::{EndpointLocator { UnixSocket(PathBuf), NamedPipe(String) }, AgentEndpoint {
    provider: ProviderKind, locator, presence, source }, detect_agents(&Env, &SshPaths, Platform)
    -> Vec<AgentEndpoint>}`. Detection is passive; on Windows it lists `\\.\pipe\` with
    `std::fs::read_dir` and opens nothing.
  * `known_hosts::lookup(&SshPaths, host, port, LocalQueries) -> Vec<HostKeyObservation>`,
    through `ssh-keygen -F` or a plain-entry parse.
  * `local_query::{LocalQueries { Enabled, Disabled }, run_version(&Path) -> Result<OpenSshVersion, _>}`.
    Bounded at 2 s; the environment is not modified; Q4.
  * `doctor::{DoctorRequest { levels: BTreeSet<ProbeLevel>, aliases: Option<Vec<String>>,
    interactive: bool, local_queries: LocalQueries, redact: bool }, run(&LocalContext,
    &DoctorRequest) -> contract::doctor::DoctorReport}`.
  * `probe::{evaluate::ssh_g, agent::list_identities (through ipc::agent_client), network::banner,
    host::verify, auth::authenticate}`. Each probe has a timeout and runs in its own process
    group (Unix, `killpg` in `sys.rs`) or a kill-on-close job object (Windows, `sys.rs`).
  * `sys`: the third `unsafe` module (overview §9). It holds `account_home`, `killpg`,
    `ReplaceFileW`, the profile folder and job objects. Each call is wrapped in a safe
    function with its invariant documented.
  * The finding codes listed in §5.11.
* **Tests (A21):**
  * `a21_default_doctor_runs_no_exec_no_agent_no_network_no_mutation`:
    * fixture: a canary `Match exec` whose command creates a file (`sh -c` on Unix,
      `cmd /c` on Windows, F13), a `FakeAgent` counting every message, a loopback TCP
      listener counting accepts, and a digest of the whole scratch tree before and after;
    * default doctor, local queries included: canary absent, 0 agent messages, 0 accepts,
      tree unchanged, exit 0, every performed level listed, the
      `dynamic_match_unresolved` finding with file:line.
  * `a21_evaluate_level_runs_match_exec_and_is_labelled`: canary present, probe record level
    `evaluate`.
  * `a21_agent_level_sends_only_request_identities`: exactly one message, type 11.
  * `a21_network_level_reads_banner_only`: 1 accept and 0 key-exchange bytes from the client
    after the banner.
  * `a21_host_verification_never_signs`: `FakeAgent` sign count 0.
  * `a21_authentication_level_signs_once`.
  * `a21_explicit_level_refused_without_evaluate_when_config_executes`.
  * `a21_hanging_match_exec_killed_with_descendants_at_timeout`.
  * `a21_agent_that_never_replies_times_out`.
  * `a21_fifo_include_does_not_block`, a Unix `mkfifo` fixture.
  * `a21_noninteractive_authentication_refused_for_interactive_identity` (Q2).
  * `home_resolution_matches_ssh_g`: compares Heimdall's account home with `ssh -G` default
    paths on each platform (F19).
* **Tests (A22 static half):** `integration_sshconf_vs_ssh_g::corpus_*`. For every inert
  corpus file and alias, Heimdall's `RelevantBehavior` equals `ssh -G -F <file> <alias>`
  after the default mapping.
  * They run on every target client: macOS system 10.3p1, the Linux devbox client, and
    Windows in-box 9.5p2 through the native runner.
  * The corpus covers: nested includes; Host and Match wildcards and negation; additive
    IdentityFile; unsupported syntax (an unknown keyword under IgnoreUnknown, and a
    deprecated one); `include_state_is_restored_after_included_file`; Windows `//./pipe/`
    forms; `%%`; spaced and non-ASCII paths.
* **Depends on:** U1, U2, U7 (FakeAgent), U6 (`ipc::agent_client`).

### U4: `heimdall-localenv` projection file transaction

* **Owner paths:**
  * `crates/localenv/src/{projection/mod,projection/apply,projection/observe,projection/cleaner,materialize}.rs`;
  * `tests/integration/projection.rs` (hosted by `heimdall-localenv`).
* **Interfaces:**
  * `projection::LocalProjection` implements the new port `app::ports::ProjectionWriter`
    (§5.15):
    * `preview(&ProjectionSpec) -> ProjectionPlan`, read-only;
    * `apply(&ProjectionPlan, effect_token) -> ProjectionReceipt`;
    * `rollback(&ProjectionRecord, effect_token) -> ProjectionReceipt`;
    * `reconcile(&ProjectionRecord, effect_token) -> ProjectionReconcile { Applied, NotApplied, Partial }`.
  * `projection::cleaner::ProjectionCleaner` implements the M01 port `ResourceCleaner`. It
    deletes only the generation the resource names (digest equal, else `Ok` with nothing
    deleted).
  * `materialize::{key_file_path(&Fingerprint) -> PathBuf, write_public_key(&PublicKey)}`.
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
  * `a22_crlf_bom_no_trailing_newline_preserved`;
  * `a22_missing_user_config_created_0600_and_ssh_dir_0700`;
  * `a22_render_is_deterministic_and_reapply_is_noop`;
  * `a22_crash_after_p_before_b_reconciles_forward_without_duplicate_block`, through the
    store `FaultHook` and the stage hook;
  * `a22_crash_after_b_before_receipt_reconciles_applied`;
  * `a22_stale_cleanup_generation_n_cannot_delete_n_plus_1`, at the deletion boundary with
    `reconcile::CleanupHook`, as M01 N06;
  * `windows_replace_preserves_dacl` and `rendered_file_loads_on_target_client` (Windows
    native: `ssh -G -F` reads the rendered user file and P; the DACL is compared before and
    after through the harness);
  * `private_key_files_never_opened`: private key files at mode 000, and adoption still
    succeeds from the `.pub` files.
* **Depends on:** U2, U7 (ScratchHome).

### U5: Setup and catalog operations (app, store, runtime wiring)

* **Owner paths:**
  * `crates/app/src/{setup,catalog}.rs`;
  * `crates/store/src/ext_m02.rs` (the bodies of the U0 `Txn` signatures, and
    `Store::open_read_only`);
  * `crates/runtime/src/{dispatch,service}.rs` (M02 routing and wiring only);
  * `tests/model/setup.rs` and `tests/integration/store_m02.rs` (hosted by `heimdall-runtime`
    and `heimdall-testkit` respectively).
* **Interfaces:**
  * `Operations::{setup_preview, setup_apply, setup_rollback, setup_repair, catalog}(&Caller,
    …) -> OpResult<Completed>`. `OperationsConfig.projection: Option<Arc<dyn ProjectionWriter>>`.
  * Decision flow for apply and repair, per Q1: a `DecisionKind::ApplyProjection` record is
    always created and never executed on dispatch. Attended sessions get `APPROVAL_REQUIRED`
    and unattended ones `INTERACTION_REQUIRED`, both with `next.decision_ref`. `Decide approve`
    executes exactly that plan digest, after recomputing it; a mismatch is `CONFIG_CONFLICT`.
    Rollback needs no decision.
  * Effect discipline as in ADR-0006 §14.1: recovery intent, effect token, `Attempted`
    receipt, then `ProjectionWriter::apply`. On restart, `reconcile` is called, never a
    second `apply`.
  * The catalog has upserts with revisions; profiles reuse `upsert_profile` and snapshots.
    A `LimitedConsumer` is refused with `CAPABILITY_UNAVAILABLE`.
  * Destination identity:
    * `DestinationId` stays durable when the alias changes (spec §4.2);
    * a managed alias collision is `CONFIG_CONFLICT` with reason `alias_collision`;
    * the adapter registry maps `IdentitySource` to `native_agent` or `onepassword` (U6),
      for `ensure`.
  * The dispatcher routes `Setup` and `Catalog` behind `setup/1`. `Service::start` wires
    `LocalProjection`, `ProjectionCleaner` and the adapters.
  * `Store::open_read_only` never migrates. An older schema is reported, never upgraded.
* **Tests:**
  * `apply_requires_decision_attended_and_unattended`;
  * `apply_executes_exactly_the_decided_plan_digest`;
  * `apply_after_base_change_is_config_conflict_and_decision_unconsumed`;
  * `rollback_needs_no_decision`;
  * `same_request_id_replays_apply`;
  * `changed_plan_same_request_is_request_conflict`;
  * `limited_consumer_refused`;
  * `catalog_alias_rename_keeps_destination_id`;
  * `profile_upsert_bumps_revision_and_does_not_widen_existing_grant` (R-AU-03 spot check);
  * `projection_resource_generation_cas`;
  * `open_read_only_refuses_newer_and_never_migrates`;
  * restart recovery: an `Attempted` apply is reconciled, not re-applied (in-process and
    process-crash variants, labelled as M01 N06 requires);
  * `projection_events_carry_generation_and_change`;
  * canary scan over every result.
* **Depends on:** U0, U4 (port implementation for integration), U6 (adapters registered).

### U6: Existing-access adapters and the bounded agent client

* **Owner paths:**
  * `crates/adapters/src/{native_agent,onepassword,detect,state,integration}.rs`;
  * `crates/ipc/src/agent_client.rs`;
  * `tests/integration/adapters.rs` (hosted by `heimdall-adapters`) and
    `tests/adversarial/agent_client_frames.rs` (hosted by `heimdall-ipc`).
* **Interfaces:**
  * `NativeAgentAdapter`, `OnePasswordAdapter`: `CredentialAdapter + ProviderProbe` (§5.15).
    * `descriptor()`: mechanisms `native_agent` and `onepassword`; `external_side_effects:
      false`; `interaction` from ADR-0007 §7; `lock_continuity` = `Unknown` for the native
      agent and `StopsOnLock` for 1Password [S06].
    * `prepare` is local only. It checks presence passively and materializes the
      integration (`ConsumerIntegration.environment` with `SSH_AUTH_SOCK`, `executables`,
      `overrides`).
    * `reconcile` observes the materialization.
    * `revoke` removes it. Its outcome is `remote_pending: []` with no expiry.
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
  * `a35_identity_selected_by_public_key_with_identities_only`.
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
  * `crates/testkit/src/{agent,sshd,home}.rs` and the testkit `Cargo.toml` features;
  * `tests/integration/testkit_fixtures.rs` (hosted by `heimdall-testkit`).
* **Interfaces:**
  * `agent::FakeAgent::{start(Endpoint, FakeAgentConfig { keys: Vec<FixtureKey>, mode:
    AgentMode { Normal, Locked, ApprovalPending, Deny, ManyKeys(usize) } }) -> Running, log() ->
    Vec<AgentContact { msg_type, key_fp }>, release_pending(), stop()}`.
    * Unix socket and Windows named pipe, with an owner-only DACL.
    * Ed25519 keys are generated in memory per run.
    * `HEIMDALL_CANARY_*` comments let the canary scan catch any leak.
  * `sshd::LoopbackSshd::{start(&Scratch, SshdConfig { authorized: Vec<PublicKey>,
    max_auth_tries, allow_pty, log_level_verbose }) -> Running { port, host_key_line,
    accepted_log() }}`.
    * Non-root `sshd -D -f <scratch>`, `ListenAddress 127.0.0.1`.
    * The authorized keys file lives in scratch with `restrict` options, plus `pty` where a
      test needs it.
    * Windows runs read `HM_FIXTURE_SSHD_{HOST,PORT,HOST_KEY}` from the harness (§4).
    * When a non-root `sshd` cannot start on the host (macOS `[U]`), the fixture reports
      `Unavailable` and the harness falls back to the M00-T03 Docker fixtures.
  * `home::ScratchHome::{new() -> ScratchHome { user_config, ssh_dir, known_hosts, config_dir,
    state_dir }, ssh_command(&self) -> Command (adds -F, UserKnownHostsFile, IdentityAgent from the
    scratch)}`. Scratch directories are removed on drop, pass or fail; only paths created
    here are removed.
* **Tests:** FakeAgent round trip with a real `ssh` login to `LoopbackSshd`; mode semantics;
  `ManyKeys(10)` against `max_auth_tries 3` fails without `IdentitiesOnly`; `ScratchHome`
  cleans up; nothing listens beyond `127.0.0.1`, asserted on the bound address.
* **Depends on:** U0.

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
    NotExecutable }}` (ADR-0007 §8; Q-B).
  * `env::EnvDelta::from_integration(&ConsumerIntegration, &Env) -> EnvDelta`. It sets
    `SSH_AUTH_SOCK`, and sets `GIT_SSH_COMMAND` on Windows only under the §8 rule. It never
    overrides a user's `GIT_SSH_COMMAND` or `core.sshCommand`; it reports them as overrides.
  * `meta::{SideChannel::{from_fd(i32) (Unix), create_exclusive(&Path)}, write(&RunRecord)}`.
  * `unix::exec_replace(&ResolvedProgram, &[OsString], &EnvDelta, Option<SideChannel>) -> LaunchFailure`,
    which returns only on failure, through `CommandExt::exec`.
  * `windows::spawn_and_wait(…) -> Result<u32, LaunchFailure>`, with a console control guard
    (tokio `ctrl_c`/`ctrl_break`) and no job object.
  * `handoff::run_foreground(…) -> Result<ChildOutcome, LaunchFailure>`, the TUI's
    `system(3)` model.
  * `run_cmd::run(RunArgs)`: `ensure` (profile) + `bind(Launch(LaunchBinding { executable,
    holder }))`, then launch. Q2 is enforced before launch.
  * `connect_cmd::connect(alias)`: `inspect destinations`, then the verified client, then
    launch.
  * `Operations::release_exited_holders(&self, &dyn ProcessLiveness) -> OpResult<Vec<BindingId>>`
    and `Supervisor::holder_pass`. These are bounded, use jittered intervals (ADR-0006
    §13.6 item 4), and read liveness through the M01 `platform::process_start_time` (Q5).
* **Tests (A27):**
  * `a27_binary_stdin_stdout_roundtrip_through_ssh`: 1 MiB random plus all 256 byte values
    through `heimdall run -- ssh <fixture> cat`, compared by SHA-256.
  * `a27_scp_and_sftp_binary_with_unicode_and_spaced_paths`.
  * `a27_git_clone_and_push_over_ssh_with_binary_blob`.
  * `a27_child_exit_codes_0_to_255_preserved`, plus `a27_windows_full_32bit_exit_code_preserved`.
  * `a27_signal_death_preserved` (Unix).
  * `a27_missing_executable_exits_127_with_prelaunch_record`.
  * `a27_not_executable_exits_126`.
  * `a27_child_exiting_127_distinguished_by_launching_record`.
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
  * `a27_argv_never_crosses_ipc`: a canary argument is absent from the store, events and
    logs.
  * `run_retry_with_same_request_id_never_relaunches_automatically` (R-RT-05).
  * `a11_noninteractive_run_refuses_interactive_identity_before_launch` (Q2): exit 3, a
    `prelaunch_failed` record, and FakeAgent contact count 0. With
    `--allow-provider-interaction` the child launches.
  * `a11_interactive_connect_succeeds_after_provider_approval`: pty, FakeAgent
    `ApprovalPending`, then `release_pending()`. Ordinary interactive use stays first-class.
  * `sigpipe_disposition_is_documented`.
  * `holder_exit_releases_reference_and_reused_pid_does_not_keep_it`.
  * `tui_handoff_ctrl_z_stops_and_fg_resumes_as_one_job` (pty, Unix).
* **Depends on:** U0; core files (resolve/env/meta/unix/windows/handoff) in wave 1; the
  `run`/`connect` wiring after U5 and U6.

### U9: CLI surface for setup, doctor, catalog, uninstall

* **Owner paths:**
  * `crates/heimdall/src/{setup_cmd,doctor_cmd,catalog_cmd,uninstall_cmd}.rs`;
  * M02 additions to `crates/heimdall/src/output.rs`;
  * `tests/e2e/cli_m02.rs` (hosted by `heimdall` bin);
  * additions under `schemas/examples/**`.
* **Commands:**
  * `setup [preview [--evaluate] [--include-git] | apply | rollback | repair <conflict> | status]`;
  * `doctor [--active-probe LEVEL[,LEVEL…]] [--alias A]… [--no-local-exec] [--redact] [--json]`;
  * `destination {add|list|show|remove}`, `identity {list|adopt [--from-agent] [--pub FILE]|remove}`,
    `profile {create|show|add|remove|list}`;
  * `uninstall [--purge-state]` (Q6).
* **Rules:**
  * `setup apply` shows the exact recorded plan and follows the ADR-0006 §3.1 client
    confirmation contract: typed `y`/`yes`, default No. Any other answer exits 3 with
    `INTERACTION_REQUIRED` and `next.decision_ref`.
  * `identity adopt --from-agent` is the explicit `agent` probe (ADR-0007 §6). On an
    interactive TTY it asks first and names the provider; under `--non-interactive` it is
    refused unless `--active-probe agent` is given.
  * `doctor` never starts the runtime and reads the store read-only.
  * `--json` envelopes go to stdout only; human text goes to stderr or stdout as in M01.
* **Tests:**
  * `a01_cli_adopt_observed_and_managed_aliases_then_ordinary_ssh_with_scratch_F`;
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
  * `a22_cli_setup_conflict_then_repair`;
  * `uninstall_restores_user_bytes_and_effective_config_and_reports_remaining_items`;
  * `host_key_substitution_fails_closed_and_nothing_written_to_known_hosts` (the MANIFEST
    row 5 pattern on `LoopbackSshd`; R-SE-04);
  * the A35 matrix over a real disposable `ssh-agent` (Unix) or the FakeAgent pipe
    (Windows) and `LoopbackSshd`:
    * `a35_matrix_ssh_git_scp_sftp_ordinary_alias_and_run_bound`, which records the
      resolved executable and the fingerprint the server accepted (fixture sshd
      `LogLevel VERBOSE`);
    * `a35_wrong_key_fails_without_fallback_to_other_agent_keys`;
    * `a35_too_many_keys_succeeds_for_managed_alias_only` (`ManyKeys(10)`,
      `MaxAuthTries 3`);
    * `a35_identity_agent_overriding_ssh_auth_sock_is_reported_and_managed_alias_unaffected`
      (a user `Host *` IdentityAgent pointing at a second FakeAgent; contact logs show
      which agent was used);
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
      undetermined), the `ProviderStatus`, and the projection state;
    * **operation detail**: observed through `observe events`;
    * **pending decisions**: a modal implementing the client confirmation contract with a
      typed `yes`, default No.
  * The connect action goes through `launch::handoff::run_foreground`.
  * Explicit probes are labelled actions that name their level.
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
  * fills the matrix with exact labels (spec §3.3);
  * demonstrates T06 as a scripted transcript;
  * moves units from `implemented_unverified` to `verified` only when their tests passed in
    a recorded run.
* **Depends on:** all.

## 2. Order and parallelism

```text
U0 skeleton + contract rev 3 (integrator; after Q1–Q8 rulings)
 ├─► U1 sshconf parse ──────────────┐
 ├─► U2 sshconf eval/render/edit ───┤ (wave 1, parallel; U2's text tests go green when U1 lands)
 ├─► U7 testkit fixtures ───────────┤
 ├─► U6 adapters + agent client ────┤ (tests need U7)
 └─► U8 core: resolve/env/meta/exec/spawn/handoff
                                    ▼
     U3 discovery/doctor/probes (U1,U2,U6,U7)   U4 projection files (U2,U7)     (wave 2)
                                    ▼
     U5 setup/catalog ops + store + runtime (U4,U6)   U8 run/connect wiring + holders (U5,U6)  (wave 3)
                                    ▼
     U9 CLI surface (U3,U5,U8)   U10 TUI (U3,U5,U8)                              (wave 4)
                                    ▼
     U11 exit suite + native evidence + matrix                                   (wave 5)
```

The units add up to twelve: U0 plus eleven implementation units, with U8 delivered in two
phases. File conflicts are designed out:

* U0 owns `cli.rs` and every signature;
* U5 owns `runtime/{dispatch,service}.rs`, and U8 owns only `holder_pass` in `supervisor.rs`;
* U3 and U4 share the crate `heimdall-localenv` but disjoint files.

Serialize anything that touches authority semantics, a schema version or the store
migration through the integrator (plan §7.3). Have the M02 design reviewed independently
before wave 1 (progress.md "Next"). This plan has had no independent review.

## 3. Milestone exit mapping (plan §5 M02 "Exit evidence")

| Exit claim / case | Proven by (tests) | Native runs (§4) |
|---|---|---|
| **A01**: no remote change, no key export, no mandatory prefix, unaffected aliases still work, personal profile without a repository | U2 unaffected-name and managed-values properties; U4 `a22_apply_then_rollback_*`, `private_key_files_never_opened`; U9 `a01_*` (5 tests); U5 `catalog_*` | macOS, Linux devbox, Windows 11 with scratch `-F`; WSL disposable distribution and Docker container with **ordinary ssh, no `-F`** |
| **A11**: ordinary access first-class; non-interactive returns explicit interaction or capability state without a popup or unapproved fallback | U6 `a11_*` (5), `a35_identity_selected_by_public_key_with_identities_only`; U8 `a11_noninteractive_run_refuses_interactive_identity_before_launch` (Q2; FakeAgent contact count 0) and `a11_interactive_connect_succeeds_after_provider_approval`; U9 `a11_noninteractive_errors_exit_codes`, `a35_wrong_key_fails_without_fallback_to_other_agent_keys`; U3 `a21_noninteractive_authentication_refused_*` | all three, fixture level; native ssh-agent lock on macOS and Linux; 1Password and hardware-key rows blocked (§7) |
| **A21**: default doctor does no exec, provider contact, signing, network or mutation; explicit probes classified and bounded | U3 `a21_*` (11 tests); U9 `a21_cli_doctor_json_validates_against_schema`; U10 `search_never_probes` | all three (Windows canary through `cmd.exe`, F13) |
| **A22**: relevant behaviour correct; dynamic unknowns stay unknown; unrelated content and newer edits survive; generation deterministic | U1 corpus; U2 properties (soundness, round trip, determinism); U3 `corpus_*` against `ssh -G -F` per client; U4 `a22_*` (16 tests) and `windows_replace_preserves_dacl`; U5 decision and stale-plan tests; U9 `a22_cli_setup_conflict_then_repair` | all three clients (10.3p1, devbox client, in-box 9.5p2); Windows DACL preservation |
| **A27**: no stdout contamination or shell injection; child streams and status preserved; setup failure distinguishable | U8 `a27_*` (18 tests), `sigpipe_disposition_is_documented` | all three; Windows Ctrl-C and resize through pseudoconsoles (interactive console row blocked, §7) |
| **A35**: verified executable and identity used; exact limitations; existing-auth not second-class | U6 `a35_identity_selected_by_public_key_with_identities_only`, `adapters_never_send_*`; U7 `ManyKeys`; U8 `a27_git_*`, `a27_scp_*`; U9 `a35_*` (4 tests), `a01_*`; matrix rows | macOS and Linux: real disposable `ssh-agent` × {ssh, git, scp, sftp} × {ordinary alias, run-bound} × {wrong key, too many keys, IdentityAgent overriding SSH_AUTH_SOCK}; Windows: fixture pipe agent (selection) × the same; Windows system agent, 1Password live and Linux arm64 blocked (§7) |
| "A participant can connect without a mandatory work wrapper" | U9 `a01_cli_adopt_*` and the T06 scripted transcript | WSL disposable distribution (ordinary ssh); the human participant walkthrough is an owner input (§7 B7) |
| "No remote authentication change, key export, or provider-policy bypass was needed" | `a01_no_remote_change`, `a01_no_key_export`, `adapters_never_send_*`, the identity selection test (IdentityAgent is the provider's own endpoint; nothing relays) | all three |
| "Does not claim managed unattended access until M03" | U6 `a11_unattended_minimum_is_capability_unavailable_*`; matrix labels | all three |
| R-RT-05 (no blind replay) | U8 `run_retry_with_same_request_id_never_relaunches_automatically`; U5 `restart … reconciled, not re-applied` | all three |
| R-SE-04 (host trust never weakened) | U2 render refuses host-verification directives; U9 `host_key_substitution_fails_closed_and_nothing_written_to_known_hosts` (MANIFEST row 5 pattern on `LoopbackSshd`); U3 `known_host_mismatch` finding | all three |
| T06 clean local uninstall | U9 `uninstall_restores_user_bytes_and_effective_config_and_reports_remaining_items` | all three; the WSL distribution with a real home |

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
| `tests/native/m02/run-macos.sh` | `check.sh` + e2e on the build host | Starts `LoopbackSshd` from `/usr/sbin/sshd`, non-root. If that is `Unavailable` (`[U]`), it starts the M00-T03 Docker fixtures (`up.sh`, `127.0.0.1` only) and passes their ports; `down.sh` must print `CLEANUP CONFIRMED`. Disposable `ssh-agent -a`; `script(1)` and rustix ptys |
| `tests/native/m02/run-linux.sh <dir> <host>` | `tests/native/m01/run-linux.sh`: zig cross-build, copy to `~/hm-m02-<random>`, run under `nice` with a timeout, `rm -rf` exactly that directory | Records `ssh -V`, `sshd -V` and `git --version`. Starts `LoopbackSshd` on the host's `127.0.0.1`. Disposable `ssh-agent` in scratch. Never touches the host's `~/.ssh` or agent |
| `tests/native/m02/run-windows.sh <dir>` | `tests/native/m01/run-windows.sh`: x86_64-pc-windows-gnu, `%LOCALAPPDATA%\hm-m00\<task>-<random>`, non-elevated, through WSL interop | Starts the fixture sshd **in WSL scratch** on `127.0.0.1` (non-root, as in G03 §0.1) and passes `HM_FIXTURE_SSHD_{HOST,PORT,HOST_KEY}` to Windows tests (NAT localhost forwarding). The FakeAgent serves a `heimdall-hmtest-<random>` pipe. Pseudoconsole drivers from `tests/native/windows-launch/` for Ctrl-C and resize. ACLs are read with `icacls`/`Get-Acl`. Pipes are counted before and after. `\\.\pipe\openssh-ssh-agent` is never opened |
| `tests/native/m02/run-wsl-distro.sh` | G03 P-B08/09/10 disposable distribution (ADR-0004 §3): `wsl --import` from a pinned rootfs into scratch, never an export of an owner distribution | Inside it: a non-root user with a disposable home, the Linux `heimdall` binary, `LoopbackSshd`, a disposable `ssh-agent`. `setup apply` writes that user's real `~/.ssh/config`, then **ordinary `ssh alias`, `git`, `scp` and `sftp` without `-F`**, then `uninstall`. Afterwards `wsl --terminate` and `--unregister` **that distribution only**; never `wsl --shutdown` |
| Docker on the build host | M00-T03 image pattern | Supplementary Linux arm64: a disposable container user home, ordinary ssh without `-F`. Labelled supplementary, never native arm64 |

Per-case platform rows. ✔ means a native run is planned; supplementary runs are labelled
as such.

| Case | macOS arm64 | Linux x86-64 devbox | Windows 11 x64 | WSL2 distribution | Blocked rows |
|---|---|---|---|---|---|
| A01 | ✔ scratch `-F` | ✔ scratch `-F` | ✔ scratch `-F`, fixture pipe agent | ✔ ordinary ssh, no `-F` | macOS and Windows ordinary-ssh-without-`-F` (B2, B3); Linux arm64 native (B9) |
| A11 | ✔ fixture + disposable ssh-agent lock | ✔ same | ✔ fixture pipe states | — | 1Password live (B1); Windows system agent (B4); hardware touch (B6) |
| A21 | ✔ | ✔ | ✔ | — | — |
| A22 | ✔ client 10.3p1 | ✔ devbox client | ✔ in-box 9.5p2, DACL preservation; symlink cases `platform_only` Unix | ✔ | — |
| A27 | ✔ pty | ✔ pty | ✔ pseudoconsole, batch rules | — | interactive console Ctrl-C/resize observation (B5, P-W07) |
| A35 | ✔ real disposable ssh-agent × 4 clients × 2 paths × 3 fixtures | ✔ same | ✔ fixture pipe agent × in-box ssh, Git (System32 via `core.sshCommand`/`GIT_SSH_COMMAND`, and bundled MSYS as a recorded limitation), scp, sftp | ✔ ordinary path | 1Password all platforms (B1); Windows system agent (B4); Linux arm64 (B9) |

Records follow `tests/evidence/record.schema.json` and the lowest-row rule
(`tests/evidence/README.md`, ADR-0004 §4). A case with a blocked row is `blocked`, with the
input named. Its platform rows that ran may be `verified`. In-process reconstructions are
labelled as such, as in M01 N06.

## 5. Contract additions: proposed ADR-0006 revision 3 deltas

All of these are additive unless marked **changed**. Schema major stays `"1"` (ADR-0006 §9;
the contract is not frozen, §1).

1. **IDs.** `ids::IdentityId`, prefixed `idn`.
2. **`Request::Setup(SetupRequest)`**, tagged by `action`:
   * `Preview { include_git: bool = false, evaluate: bool = false }`: read-only and not
     journaled. `evaluate` runs `ssh -G` and is labelled `evaluate`.
   * `Apply { plan_digest: PlanDigest, request_id }`.
   * `Rollback { request_id, keep_key_files: bool = false }`.
   * `Repair { conflict: ConflictKind, resolution: RepairResolution { Rerender,
     RemoveDuplicateMarkers, MoveIncludeToTop, ManualMode }, plan_digest, request_id }`.

   `kind()` returns `"setup.preview"`, `"setup.apply"`, `"setup.rollback"` or
   `"setup.repair"`. Only Preview is not `is_effectful()`. The preview result is
   `SetupPlan { plan_digest, mode: automatic|manual, managed_file: FileChange, user_file:
   Option<FileChange>, git: Option<GitConfigChange>, aliases: Vec<AliasPreview { alias, kind:
   managed|observed, changes: Vec<BehaviorChange>, inherited: Vec<DirectiveObservation> }>,
   unaffected_names_checked: u32, findings: Vec<Finding> }`, where `FileChange { path_display,
   before_sha256: Option, after_sha256, diff: String (≤ 64 KiB) }`. `PlanDigest` is
   transparent lowercase hex SHA-256. `ConflictKind` = `user_config_changed |
   managed_file_edited | marker_edited | marker_duplicated | include_conditional |
   unmanageable_file | alias_collision`.
3. **`Request::Catalog(CatalogRequest)`**, tagged by `action`:
   * `UpsertDestination { destination: DestinationSpec { id: DestinationId, alias: String,
     definition: Managed { hostname, port: Option<u16>, account: AccountName, identity:
     IdentityId } | Observed, label: Option<String> }, request_id }`;
   * `RemoveDestination { id, request_id }`;
   * `AdoptIdentity { identity: IdentitySpec { source: NativeAgent { endpoint: EndpointRef } |
     OnePassword { endpoint: Option<EndpointRef> } | PublicKeyFile { path }, public_key: String
     (OpenSSH one-line public key), label }, request_id }`;
   * `RemoveIdentity { id, request_id }`;
   * `UpsertProfile { profile: ProfileSpec { id: ProfileId, pairs: BTreeSet<AccessPairRef>,
     label }, request_id }`;
   * `RemoveProfile { id, request_id }`.

   `EndpointRef { kind: unix_socket|named_pipe, locator: String }`. `kind()` is `"catalog"`,
   with the action in the hash extras.
4. **Capability `setup/1`.** It gates the Setup and Catalog requests; without it the answer
   is `SCHEMA_UNSUPPORTED`. A `LimitedConsumer` role gets `CAPABILITY_UNAVAILABLE`.
5. **Changed: `BindForm::Launch`.** It becomes `Launch(LaunchBinding { executable: String,
   holder: Option<ProcessHolder { pid: u32, started_at: String /* opaque OS start-time token */ } > })`.
   `argv` is removed (Q8). `MAX_ARGV_BYTES` becomes a CLI-local limit.
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
   * `overrides: Vec<ConsumerOverride { consumer, setting: String, provenance: ConfigProvenance }>`.
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
   * `ProviderInteractionRef { provider, kind }`.

   Every enum is `#[non_exhaustive]`.
10. **`NextAction.provider_interaction: Option<ProviderInteractionRef>`**, used with action
    `interact` for `PROVIDER_LOCKED` and for provider-owned `INTERACTION_REQUIRED`. It is
    never combined with `decision_ref` (spec §5.5).
11. **`contract::doctor`:**
    * `DoctorReport { levels_performed, levels_declined: BTreeSet<ProbeLevel>, clients:
      Vec<ClientObservation>, config_files: Vec<ConfigFileObservation { path_display, role:
      user|system|included|managed, readable, sha256, bytes }>, aliases: Vec<AliasObservation
      { alias, definition: managed|observed|user_only, behavior: Vec<DirectiveObservation {
      directive, values, certainty: determined|undetermined|unset, provenance:
      Vec<ConfigProvenance { path_display, line }> }> }>, providers: Vec<ProviderStatus>,
      projection: Option<ProjectionObservation { state: absent|healthy|conflict|manual|conditional,
      generation, conflict: Option<ConflictKind> }>, findings: Vec<Finding>, probes:
      Vec<ProbeRecord { level, target, started_at, duration_ms, outcome:
      ok|failed|timeout|refused, code: Option<Code> }> }`;
    * `Finding { code: String, severity: info|warning|problem, subject: ResourceRef, level:
      ProbeLevel, provenance: Option<ConfigProvenance>, message, next: NextAction }`.

    Finding codes, stable, `snake_case`, readers tolerate unknown ones:
    * configuration: `config_invalid`, `dynamic_match_unresolved`,
      `executable_directive_present`, `include_missing`, `include_conditional`,
      `include_not_first`, `projection_edited`, `marker_edited`, `alias_collision`,
      `inherited_identities`, `identity_agent_overridden`, `too_many_identities`,
      `strict_host_key_checking_weak`, `config_permissions_unsafe`,
      `parse_unsupported_directive`, `bound_exceeded`;
    * clients: `client_not_found`, `client_unsupported_version`, `git_ssh_unreachable_agent`;
    * agents and identities: `agent_endpoint_missing`, `agent_endpoint_foreign_owner`,
      `identity_not_listed`, `identity_public_key_unknown`, `key_file_permissions_unsafe`;
    * host trust: `known_host_missing`, `known_host_mismatch`;
    * environment: `home_mismatch`.

    Schema `schemas/public-api/doctor-report.json`.
12. **`contract::run_record::RunRecord`**, tagged by `type`:
    * `prelaunch_failed { schema_version, code, exit_code: i32, reason: Option<String>,
      operation_id, binding_id }`;
    * `launching { schema_version, executable, operation_id, binding_id, pid: u32,
      replayed_preparation: bool }`;
    * `exited { schema_version, exit_code: i64 }` (Windows launcher only).

    Schema `run-record.json`.
13. **Code `LAUNCH_FAILED`.** Exit 127, or 126 when the reason is `not_executable`; it
    occurs only in `run` and `connect`. Retryable no, effect `none`, next `fix_request`.
    The golden table grows to 30 rows. Spec §11.6's code list gains it at G08, as ADR-0006
    §11 already plans for the baseline codes.
14. **`ErrorData.reason: Option<String>`.** A stable `snake_case` sub-reason:
    * the conflict kinds;
    * the launch reasons `not_found`, `current_directory`, `refused_batch_path`,
      `refused_argument`, `not_executable`, `exec_error`;
    * the provider reasons `endpoint_absent` and `identity_not_listed`.
15. **Inspection and ports.**
    * `InspectSubject` gains `identities` and `projections`.
    * `ResourceRef.kind` gains the documented values `projection`, `identity`, `provider`
      and `executable`.
    * No new `EventType`: projection changes use `resource_changed` with payload
      `{generation, change: applied|rolled_back|conflict|repaired}`, and decisions use
      `decision`.
    * Ports (app, integrator-owned):
      * `ProjectionWriter` (U4);
      * `ProviderProbe { provider(); detect(&DetectContext) -> ProviderStatus; async
        list_identities(&ProbeBounds) -> Result<IdentityListing, AdapterError> }`;
      * `ProcessLiveness { state(&ProcessHolder) -> HolderState { Alive, Exited, Unknown } }`.
    * `PrepareOutcome` gains `availability: CredentialAvailability`, `provider:
      Option<ProviderStatus>` and `integration: ConsumerIntegration`.
16. **Hash inputs.** These extend ADR-0006 §7.2:
    * `setup.apply`: environment + `plan_digest`;
    * `setup.rollback`: environment + `keep_key_files`;
    * `setup.repair`: environment + conflict + resolution + `plan_digest`;
    * `catalog`: action + canonical spec;
    * `bind` (`Launch`): binding + executable. `holder` is excluded as delivery metadata.
17. **Domain.**
    * `DecisionKind::ApplyProjection { plan_digest, summary: ProjectionSummary {
      added_aliases, changed_aliases, removed_aliases, files: Vec<String>, git: bool,
      diff_text: String (≤ 64 KiB) } }` (Q1);
    * `domain::catalog::{DestinationRecord, DestinationDefinition, IdentityRecord,
      IdentitySource, InteractionProfile}`;
    * `domain::projection::{ProjectionSpec, ManagedAliasSpec, ProjectionRecord, ProjectionPlan}`;
    * `domain::holder::{ProcessHolder, HolderState}`.
18. **Store.**
    * Migration `0005_existing_access`, `SCHEMA_VERSION` 5:
      * tables `destinations` (alias unique) and `identities` (fingerprint unique);
      * `binding_holders`;
      * projection records in the existing `resources` table (kind `config_projection`).
    * `Txn` methods: `{upsert,remove}_destination`, `destination`, `destination_by_alias`,
      `destinations`, `{upsert,remove}_identity`, `identity`, `identities`,
      `projection_resources`, `put_projection_resource` (generation CAS),
      `set_binding_holder`, `binding_holders`.
    * `Store::open_read_only`.
19. **Config.** An optional `[clients]` table (`ssh`, `scp`, `sftp`, `git`, `ssh_keygen`:
    absolute paths to existing regular files) with `deny_unknown_fields`. `FORBIDDEN_KEYS`
    is unchanged, and config still carries no socket paths.

## 6. Questions for the orchestrator

The authority-semantics questions Q1–Q8, with recommended answers, are in ADR-0007 §12.
Units build against the recommended answers. These questions are plan-level and not
authority semantics:

* **P1.** Accept the twelve-unit split and the U8 two-phase delivery. *Recommended: yes.*
* **P2.** Is the G01 baseline worksheet's existing-access rows (ADR-0001 §6, "measured in
  M02") in M02's exit, or is it carried to M09? It needs the owner's real workflows (B7), so
  it cannot be test material. *Recommended:* keep it out of M02's exit and record it as an
  owner-blocked G01 item.

## 7. Items blocked on owner-only inputs

Each item names the exact input. The work that does not need it proceeds, and rows that do
stay `blocked` (AGENTS.md).

| ID | Missing input | Blocks |
|---|---|---|
| B1 | A **disposable 1Password account** with disposable SSH keys, on a host where its agent may run (ADR-0004 §3, P-W10) | the live rows of A35 and A11 for 1Password on every platform (listing while locked `[U]`, approval prompts, Windows pipe takeover F18). Detection and fixture-level behaviour proceed |
| B2 | **The disposable second Windows account** (one elevation consent; ADR-0004 §3, P-W05) | the native Windows "ordinary ssh without `-F`" row of A01 and A35 (a real `%USERPROFILE%\.ssh\config`); cross-user checks on the projection and pipes |
| B3 | **A disposable macOS standard user account** (admin consent to create it and delete it afterwards) | the native macOS "ordinary ssh without `-F`" row of A01 and A35. This is a new ask, not in ADR-0004 |
| B4 | **A disposable Windows host** whose system `ssh-agent` service may hold test keys (ADR-0004 §3, P-W11) | the live rows of the Windows native agent (system pipe) in A35 and A11 |
| B5 | **An operator at the Windows console** (ADR-0004 §3, P-W07, P-A06) | the interactive-console Ctrl-C and resize observation in A27 (pseudoconsole rows proceed); the observation that setup and run raise no UAC prompt |
| B6 | **A hardware security key** (FIDO2) owned for testing | the live touch-required row of A11. The synthetic `sk-` public key covers the non-interactive refusal |
| B7 | **The owner as participant**: a short walkthrough of setup and ordinary ssh on a disposable account; and observed runs of the owner's correctly configured workflows for the G01 baseline worksheet (ADR-0001 §6, ADR-0004 §4) | the human part of "a participant can connect without a mandatory work wrapper"; the existing-access worksheet rows (P2) |
| B8 | **Owner authorization for the Linux devbox to run Docker or create a disposable local user**, only if wanted beyond the WSL distribution | nothing in the exit: the WSL disposable distribution covers Linux ordinary ssh without `-F`. Listed so the gap is explicit |
| B9 | **A native Linux arm64 host** (ADR-0004 §4) | the arm64 rows; Docker on the build host is supplementary only |

## 8. Handed to later milestones

| Item | Milestone |
|---|---|
| Heimdall signing endpoints, managed credentials, CertificateFile in P, multiplexing control | M03 (ADR-0005) |
| WSL Mode A executable/Git/path behaviour as a product path, Mode B bridge, bastion ProxyJump in P, forwarding | M04 |
| Personal standing policies and the first-trust disclosure (if Q3 is accepted as recommended) | M05-T02 |
| Export and import of the catalog as portable intent | M05 (A18) |
| Final TUI information architecture (A20) | M07 |
| Fuzzing of `sshconf::parse_file` and `ipc::agent_client`; support bundles | M08 |
