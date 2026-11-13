# M03 wave 4, round 3b: W4-N01 + ADR-0008 §17.23 (untracked; integrator + workers)

Same round as round 3 (uncommitted on top of `e566cc46`). Sources: ADR-0008 **§17.22** (W4-N01 is in its
"Sources") and **§17.23** (never edit the ADR). The common brief
`tests/evidence/artifacts/review-m03-code/wave4-notes/m03-wave4-brief.md` applies unchanged; round-3 interfaces
are in `wave4-notes/m03-wave4-r3-api.md` (R3-A..R3-D landed sections — read the R3-C2 section for the follower
and re-issue code you build on).

## Ownership

| Worker | Items | Owner regions (only these, plus their tests) |
|---|---|---|
| **X-M managed** | §17.23 item 1 (R3A-Q2: descriptor advertises `verified_server_principals`), item 5 (R3C1-Q1: per-pair selection fed; an `exclusive` fixture; non-interactive managed `delegate`; §17.22 item 10's regression switched to a real child delegation), item 6 (R3C2-Q1/Q2: typed materialization source in `MaterializeSpec`; materialization result reports the created locator; the follower names it; string derivation deleted) | `crates/app/src/ports.rs` (only `MaterializeSpec`/`MaterializedFiles` additive typed fields, authorized), `crates/app/src/managed/driver.rs`, `crates/app/src/operations/managed_driver_m03.rs`, in `operations.rs` only the follower/commit functions R3-C2 touched, `crates/adapters/src/managed/**`, `crates/credential/src/{endpoints,table}.rs` (binding creation only), `crates/runtime/src/managed_store.rs` + `managed_store/live_tests/**`, `crates/runtime/src/service.rs` `mod sources` (selection/observation feed only, if needed), tests `tests/e2e/managed_m03.rs`, `tests/integration/managed_adapter.rs` |
| **X-B issuer** | §17.23 item 3 (R3B-Q2: the second `issuer.register` repeats the pending registration's facts exactly — fingerprint, public key, store kind, backup digest — and only attaches the locator, once; a mismatch or a second different locator refuses) | `crates/app/src/operations/issuer_m03.rs`, `crates/app/src/issuer.rs`, `crates/store/src/ext_m03.rs` (issuer methods only), tests `tests/integration/issuer_m03.rs` |
| **W windows** | W4-N01: port the enrollment e2e flows to Windows (in-box `ssh.exe`, the WSL harness sshd `HM_FIXTURE_SSHD_*`, the binding endpoint's pipe form); a Windows pipe-form equivalent of the live binding-endpoint signing test; the follower's and the re-issued binding's pipe forms (after X-M lands item 6 — X-M's section below names the API) | `tests/e2e/enroll_m03.rs` (cfg structure + Windows paths), new Windows test modules/files you need (record `[[test]]` changes), `crates/testkit/src/{sshd,home,win,registry}.rs` (harness support only, additive), `tests/native/m02/run-windows-local.ps1` / `remote-lib.sh` only if the harness must export something new (record it; the orchestrator runs them), Windows-only test helpers in `crates/runtime/src/managed_store/live_tests/` **new files only** (`mod` lines in the parent are X-M's — ask under Requests) |

## Readings
- **No Windows execution is available here.** Windows code is proven by `bash tools/validation/clippy-windows.sh`
  (exit 0) and careful reading; the orchestrator runs it natively. Never claim a Windows test passed.
- **A test that needs the fixture and finds none must fail with that reason, never pass** (no early `return`,
  no `#[ignore]` for a missing fixture on Windows). A case that truly cannot run on Windows stays gated with a
  comment naming the reason (e.g. Unix-only fence `/proc` path, `pty`, the system form's `TrustedUserCAKeys`
  which the harness sshd cannot honour).
- Unix behaviour of every ported test must stay exactly as now (the macOS and devbox runs must keep passing).
- Every new regression revert-proven (worklog `.m03-wave4-r3b-worklog-<M|B|W>.md`, real exit codes).
- Questions: `.m03-wave4-r3b-questions.md` (your heading).

## X-M landed
**§17.23 item 6 (compiles; `live_tests` 21/21 incl. the 3 new item-6 tests).** Not serialized (no serde on these types).
```rust
// heimdall_app::ports (additive typed source; replaces MaterializeSpec.{public_key, certificates})
pub enum MaterializeSource {
    Fresh { public_key: String, certificates: Vec<MaterializedCertificate> }, // a new activation's binding
    InstalledKeyOf { grant: GrantId },  // a follower's own binding; a re-issue's consumer restoration
    SlotsOnly,                          // only the environment slots of an attached binding (needs environment_slots)
}
pub struct MaterializeSpec { pub generation: u64, pub source: MaterializeSource, pub environment_slots: bool }
pub struct MaterializedFiles { pub directory: PathBuf, pub files: Vec<PathBuf>, pub generation: u64,
    pub endpoint: Option<EndpointRef> }  // the binding endpoint THIS call created (None: slots-only, or one already ran)
// heimdall_adapters::managed::effects
pub const NO_LIVE_KEY: &str = "no_live_key";                   // InstalledKeyOf: no live K_env generated here
pub const BINDING_GRANT_MISMATCH: &str = "binding_grant_mismatch"; // InstalledKeyOf another grant than the attached one
// removed: BY_REFERENCE_PREFIX, the by-reference form, grant_of_fingerprint;
// app: managed_driver_m03::{follower_locator, with_follower_endpoint} deleted
// app (crate-internal): Operations::materialize_follower(&op, &grant, &binding) -> Result<EndpointRef, OpError>
//   (no leader argument); managed_driver_m03::name_follower_endpoint(&mut consumer, &EndpointRef)
```
- Follower (`stage_commit`, attached ∧ managed): `materialize(binding, {generation 1, InstalledKeyOf{grant}})`; its
  `consumer.signing_endpoint` = `files.endpoint.locator`, each pair's `endpoint` = that `EndpointRef` (whole); `None`
  → refused at the commit (`SERVICE_UNAVAILABLE`, effect `none`). The leader's `prepare::binding_endpoint` prefers
  `materialized.endpoint` (layout-from-tag only if the call reused a running endpoint).
- Re-issue `restore_consumers`: `InstalledKeyOf{grant}` (+ `SlotsOnly` for held slots), same path as the follower.
- Refusals (nothing created): `Fresh` with a `SHA256:` fingerprint (the old convention) → `binding_not_attached` /
  `public_key_mismatch`; `Fresh` without certificates → `no_certificates`; `SlotsOnly` without `environment_slots` →
  `empty_materialize_spec`.
- **For W (pipe forms):** the follower's and re-issued binding's locator is whatever the registry returned to
  `create_binding_endpoint` (`EndpointLayout::windows` → `\\.\pipe\…-b<tag>`), reported in
  `MaterializedFiles.endpoint` and named verbatim in the result; `EndpointRegistry::binding_endpoint(&binding)` returns
  the same `EndpointRef`. Tests to mirror: `live_tests::pipeline::{follower_names_exactly_the_endpoint_its_materialization_created,
  follower_refused_when_its_materialization_created_no_endpoint, materialize_refuses_a_spec_with_an_inconsistent_source}`
  (helpers `RecordingEffects`, `recording_process(w, drop_installed_endpoint)`, `decision_joined(p, pr, start, tag)`
  are private to `pipeline.rs`, which is `#[cfg(unix)]` via `live_tests`; ask under Requests if you need them `pub(super)`).

**§17.23 item 1 (R3A-Q2 (a)).** `heimdall_adapters::managed::advertised_enforcement()` (baseline +
`destination_scope: verified_server_principals`) is the managed descriptor's report; `baseline_enforcement()`
unchanged. A scope minimum now passes resolution for a managed pair and `prepare_from`'s per-pair evidence comparison
refuses it (`CAPABILITY_UNAVAILABLE`, `minimum_not_met`) when the evidence is invalid. No M01/M02 descriptor moves.

**§17.23 item 5 (R3C1-Q1 (a)).** The per-pair selection was already fed on every managed path (delegation included);
the gap was the commit's eligibility: `operations.rs` `fresh_pair`'s managed arm now restores the adapter's values
(interaction `none`, inferred, eligible) that `history_only` had reset, so a non-interactive managed request (every
`delegate`) with `exclusive` aliases commits; a non-`exclusive` pair is still refused `INTERACTION_REQUIRED`
(`fallback_identity_interaction`). Live harness (`managed_store.rs` `live_tests`): `Live.feed: Arc<LiveFeed>`
(`observe(alias, selection)`, `evidence_holds(pairs)`, `targets`, `client`), read through `Observed` +
`prepare::WithEvidenceFeed`; `Live::add_ca()`; new module `live_tests/selection.rs` (`mod selection;`).
`live_tests::cleanup::parent_with_second_reference` → `parent_with_child_delegation` (real `delegate`).
## X-B landed
**§17.23 item 3 (R3B-Q2 (a)).** Worklog `.m03-wave4-r3b-worklog-B.md` (incl. the U12 contract delta).
```rust
// heimdall_store::ext_m03 (new, pub): every recorded RegisterIssuer fact equal; store_locator and
// disclosures are not facts; anything but two registrations is false.
pub fn same_registration_facts(a: &DecisionKind, b: &DecisionKind) -> bool;
// Txn (signature changed; only caller issuer_m03.rs): `report` is the report as a RegisterIssuer with
// Some(store_locator). Fact mismatch / another locator / not pending → GenerationConflict, nothing written;
// same locator → Ok (no-op); no locator → document error.
pub fn attach_register_issuer_store_locator(&mut self, id: &DecisionId, report: &DecisionKind)
    -> Result<DecisionRecord>;
```
- `issuer.register` with `store_locator` for an **unregistered** CA: joins a live pending registration only
  if every fact is equal (attach once; same locator again answers the same decision); otherwise refused with
  no decision created or changed: `CONFIG_CONFLICT` (a registration of that CA pending with other facts, or a
  second different locator), `DECISION_STALE` (none pending). Registered-CA reports (restore CAS) unchanged.
  Reading R3BB-Q1 in the questions file.
## W landed
**W4-N01 (compiles on host, Windows clippy and Linux xcheck; Windows execution: the orchestrator's).** Worklog
`.m03-wave4-r3b-worklog-W.md` (per-test table, risks).
- `e2e_enroll_m03`: 45 of 66 tests run on Windows (`cfg(any(unix, windows))`), 21 stay `cfg(unix)` with a
  `// Unix only: <reason>` line (system form; a second sshd; the fence's local `Holder`; stopping the server).
  New Windows-only module `tests/e2e/enroll_m03/windows.rs` (`#[path]` from `enroll_m03.rs`; no `[[test]]`
  change): binding pipe lists/signs, decision-joined follower names its created pipe, re-issued binding pipe,
  `windows_client_trace_row_observation`.
- **New harness variables** (additive; `run-windows-local.ps1` + `remote-lib.sh`): `HM_FIXTURE_SSHD_REGISTRY`
  (Windows path) and `HM_FIXTURE_SSHD_REGISTRY_REMOTE` (WSL path) of the default WSL sshd's second
  `AuthorizedKeysFile` (`<wsl scratch>/registry/authorized_keys`, dir 0700, file 0600). `e2e_enroll_m03` runs
  with `--test-threads=1` there.
- testkit (additive): `LoopbackSshd::registry_remote_path()`; a seeded config on the default harness server
  writes its keys to that registry (keys file emptied).
- **Blocked on a recorded row:** the in-box Win32 client has no row in `heimdall_enroll::trace::RECORDED`, so 15
  Windows tests fail on `World::require_recorded_client` (by design) until the row is recorded from the
  observation test's `m03 observation: client_trace_row family=win32` lines.
## Requests
- **X-M → integrator (FYI, done by X-M; §17.23 item 5's gap):** one function outside the R3-C2 list in
  `crates/app/src/operations.rs`: `fresh_pair` (the `MANAGED_CERTIFICATE` arm only; called by
  `Facts::with_eligibility` from `stage_commit`). It realizes R2C-Q1 (a)'s "managed pairs keep the signer's facts"
  (the arm only moved the check time while `history_only` had reset the facts to `unknown`/not eligible). Revert
  proof r5a in `.m03-wave4-r3b-worklog-M.md`. Side effect on managed results: pairs now report `interaction: none`,
  eligible, and `credential_availability` follows (`current_only` observed for an undetermined-alias delegation).
- **X-M → integrator (FYI, done by X-M; §17.23 item 1's "no M01/M02 resolution changes"):** `operations.rs`
  `select_adapter`: for pairs resolved to **no** mechanism (M01 selection) the managed adapter's scope counts as
  `unknown` (its pre-change value); otherwise the descriptor move made a pending projection's scope-minimum request
  select the managed adapter (`projection_pending_refused_only_for_managed_only_minimums` failed). Revert proof r1b.
