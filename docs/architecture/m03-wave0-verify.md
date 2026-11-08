# M03 wave 0: design verified against the code (task M03-W0-verify)

**Status:** `implemented_unverified` (documentation only; no code changed).

**What this is.** ADR-0008 §17.14 item 3 opens wave 0 and says its code review re-checks the gate
protocol against the code. This note is the step before that: the design (m03-plan revision 6, ADR-0008
revision 6) read against the code at the wave-0 base. It covers the §0.4 assumptions M1–M20, U0b rows
1–28 ("Today" column, touch points, attach points), the preserve list, trip hazards for implementers,
and the contradictions or gaps that need a ruling. It is one verifier's reading, not the independent
review of wave 0's code. It decides nothing: every conflict is in §5 with options.

**Base.** Commit `410ec237` (branch `feat/m03-wave0-integration`). Every `file:line` below is at that
commit, read from `git archive 410ec237` (other agents edit the worktree concurrently, so the working
tree was not used). Wave 0 will move the lines. U0b's "Today" column is pinned at `1f5b8156`; the
§0.4 table at `7f6f1c05` (M02 code `491d8f5a`). Between `491d8f5a` and `410ec237` 17 files under
`crates/` and `tests/` changed (869 insertions, 126 deletions): `ipc/src/windows.rs` (pipe clients are
identified after their first write, ADR-0006 §13.21), `localenv/src/sys/quarantine.rs`, `launch`,
`testkit`, `heimdall/{cli,testcfg,tui}`, `app/src/holders.rs` (a Windows-safe executable constant) and
tests. None of them moves a line this note relies on, except as stated for M7 and M13.

**Sources read.** m03-plan revision 6 (§0.4, §1 U0 and U0b, §5 items 1–19 in full where they touch
wave 0), ADR-0008 revision 6 (D2 item 3a, D5 §6.4, §17.13, §17.14), `m02-wave0-verify.md` (the model),
and the code named below. Nothing in m03-plan.md or the ADR was edited.

## 1. §0.4 assumptions M1–M20

| # | Verdict | Evidence at `410ec237` |
|---|---|---|
| M1 | Holds | `CredentialAdapter` has `prepare`, `read_sources`, `prepare_from`, `renew`, `reconcile`, `revoke` and the drop contract (`app/src/ports.rs:255`–`:323`). `prepare` is still required (`:287`; the plan's list omits it). `read_sources` and `prepare_from` have no default body, and a source scan enforces that (`tests/model/operations.rs` `u02_adapters_prepare_from_reads_no_store_or_live_source`, N7) |
| M2 | Holds | `PrepareOutcome` (`ports.rs:199`), `ConsumerIntegration.pairs` (`contract/src/request.rs:380`–`:398`), `PreparedFacts` (`domain/src/catalog.rs:501`) have the shapes ADR-0006 §15.1 names |
| M3 | Holds, one delta | `paths::display_path` shows `/` on every platform (`localenv/src/paths.rs:87`–`:104`). `RenderPath::windows` still refuses verbatim paths (`sshconf/src/render.rs:211`); `progress.md:806` records the Git/ssh failures as test-side fixes |
| M4 | Holds | `ReplaceFileW` with a backup name (`localenv/src/sys/mod.rs:25`, `sys/quarantine.rs:18`); the quarantine pin and DACL fixes landed in `3fe6119f`, `5111a09f` |
| M5 | **Changed (shape)** | The variant is `BindForm::Launch(LaunchBinding)` with `LaunchBinding { executable, holder: Option<ProcessHolder> }` (`request.rs:532`, `:551`), not a struct variant. `run` registers its own PID (`heimdall/src/run_cmd.rs:220`–`:230`). Windows `run` spawns a child with no job object (`launch/src/windows.rs:5`, `:45`–`:79`). `connect` binds nothing (`connect_cmd.rs:38`). All three as the plan observed |
| M6 | Holds | `DestinationDefinition::Managed { hostname, port, account, identity }` (`domain/src/catalog.rs:35`–`:47`); `IdentitySource` has `NativeAgent{endpoint}`, `OnePassword{endpoint: Option}`, `PublicKeyFile{path}` (`:72`–`:93`), so no password-only account |
| M7 | Cannot verify | Needs the Windows host. The harness now records `fixture-sshd-account` as a fact (`tests/native/m02/run-windows.sh:338`–`:340`, `run-windows-local.ps1:625`); `progress.md:811`/`:817` lists the fix as a wave-6w unit; `410ec237`'s message reports the Windows artifact at exit 0 (1340 passed). Whether the mapping is fixed or only parameterized is not shown |
| M8 | Holds | `tests/native/m02/{m02-evidence.py,case-index.json,run-windows-local.ps1,required-inventory.json}` exist. `tests/native/m03` does not (U13) |
| M9 | Holds | `0001`–`0005_existing_access.sql` (`store/migrations/`); `SCHEMA_VERSION = 5` (`store/src/migrations.rs:17`); `MIGRATIONS` ends at `:52`–`:56` |
| M10 | Holds | `HostKeyObservation { key_type, fingerprint, origin_display, revoked }` (`localenv/src/known_hosts.rs:29`–`:38`): fingerprints only, no raw key |
| M11 | Holds | `Value::Undetermined(Vec<Value>)` (`sshconf/src/eval.rs:284`); module rules at `:5`–`:18` |
| M12 | Holds | Env-gated `testcfg` (`heimdall/src/testcfg.rs:11`–`:44`, `ALL_ENV` `:203`); `ScratchHome::isolation_args` (`testkit/src/home.rs:656`) |
| M13 | **Changed** | The Windows native fixes landed: `f0635b44`, `3fe6119f`, `5111a09f`, exit build `1e69263d` (Windows 1340 passed, 0 failed; `410ec237`). U7/U8/U11 no longer need to wait for them (the rebase rule is moot); `sys/quarantine.rs` and `ipc/src/windows.rs` changed under them |
| M14 | Holds | `JobObject::kill_on_close()`, `assign_child` (`localenv/src/sys/mod.rs:222`–`:240`); no breakaway (`:24`) |
| M15 | Holds | `TxnGate::assess` is private and read-only (`app/src/timegate.rs:150`); `TxnGate::check` writes the high-water mark and runtime anchor (`:183`–`:200`); `TimeGate::peek` runs a store transaction (`:393`). `assess_read_only` would be a new `pub(crate)` wrapper over `assess` |
| M16 | Holds | `Store::transaction` takes the `std::sync::Mutex` guard and holds it for the closure only (`store/src/lib.rs:369`–`:391`) |
| M17 | Holds | `SSH_AUTH_SOCK` set to the pairs' common endpoint (`launch/src/env.rs:3`, `:53`, `:87`) |
| M18 | Holds, refined | The holder is claimed in **two** transactions: the settling transaction of a new launch (`app/src/operations.rs:8590`–`:8595`) and the replay path `claim_replayed_launch` (`:8400`–`:8420`), both through `claim_launch_holder` (`:841`) |
| M19 | Holds | `IdentitySource` as M6; 1Password only through `IdentityAgent` references (`localenv/src/agents.rs:5`) |
| M20 | Holds | `CLIENT_FLOOR` is OpenSSH 9.5 (`localenv/src/doctor.rs:79`, used `:588`); ADR-0007 `:1605` |

## 2. U0b rows 1–28

Format: **Today** (verdict), **touch** (what changes, file:line), **attach** (phase-1 code, for rows
with phase 1). Phase 1 means wave 0.

**Row 1 (ipc signer).** Today matches, with deltas. `Signer { identities(), sign(key_blob, data, flags) }`
at `ipc/src/signing.rs:110`–`:115`; `NoIdentities` `:120`–`:131`; `serve` `:139`, `serve_with_idle`
`:159`–`:205`; the reply is built by `answer` (`:348`–`:366`), whose comment already marks `session-bind`
as "failure until the M03 signer" (`:363`); `write_all` + `flush` under `timeout(idle)` at `:181`–`:184`
(M-F33 holds). No `SigningSession`, `PermitGuard`, `ReleaseCheck`, outbound queue or writer task exists.
Callers to adapt: `runtime/src/service.rs:766`–`:801` (`serve_signing`; the spawn at `:799`–`:800` calls
`signing::serve(stream, s, stop)`); `ServiceOptions.signer: Arc<dyn Signer>` (`:166`, `:307`, `:769`);
`tests/adversarial/agent_frames.rs` (`ScriptedSigner` `:58`–`:74`, `serve_with_idle` `:120`, `:440`,
`:459`, `serve` `:479`, `:491`, `:507`); `tests/integration/ipc_unix.rs:764`. The peer available in the
accept loop is `PeerIdentity` (`ipc/src/endpoint.rs:104`), not `PeerInfo` (E5). The endpoint is known at
`serve_signing`'s caller: `endpoints.signing` (`service.rs:650`, `:696`) and `EndpointRef { kind, locator }`
(`contract/src/provider.rs:313`). On Windows the peer is known only after the first write
(`ipc/src/windows.rs`, W6), which `serve` must tolerate.

**Row 2 (issuance check).** Matches. `IssuanceCheck` literal sites: `app/src/operations.rs:10789`
(`run_issuance_check`, `:10696`–`:10816`) and `domain/src/issuance.rs:591` (tests). `permitted_extensions`
`operations.rs:10675`, called `:10788`; guarded by `tests/model/revocation.rs:1445`. The exhaustive match
on `IssuanceRefusal` is `OpError::from_issuance_refusal` (`app/src/error.rs:369`–`:409`): new variants
`UnknownCa`, `CaNotVerifiedForPair` need arms there. `IssuanceRefusal` is not `#[non_exhaustive]` and is
serde-tagged by `reason` (`domain/src/issuance.rs:76`). Attach: `enrolled_cas` is computed in
`run_issuance_check` after `ctx` (`:10751`) and passed in the literal at `:10789`.

**Row 3 (reserve selects the CA).** Matches. `Operations::reserve_issuance` `:10337`; `CertificateBounds`
literals at `:10366` and (publish re-reserve) `:10523`; `tests/integration/store.rs:323`; two domain-test
literals (`issuance.rs:418`, `:559`). `IssuanceRequest` (`:4893`) has no `ca_fingerprint` field today, so
the "request naming another CA" check needs a new optional field (5 `IssuanceRequest {` literals in
tests). `publish_issuance` `:10435`–`:10575`; store side `Txn::reserve_issuance` `store/src/ext.rs:1446`,
`publish_issuance` `:1518`, `void_issuance` `:1523`. Nothing outside tests calls these (the M03 issuer is
their first caller).

**Row 4 (verification issuance).** "—" confirmed (no `verification_issuance`, no `domain::verification`).
New: `Operations::{reserve,publish,void}_verification` beside `:10337`–`:10575`; store methods in the new
`ext_m03.rs` beside `ext.rs:1446`–`:1555`. `verification::check` has no owning unit for its body (E1).

**Row 5 (authorize_signature).** "—" confirmed. Time: `TimeGate::check` writes (M15); `assess_read_only`
must be built on `TxnGate::assess` (`timegate.rs:150`, `:183`). Natural home `app/src/managed.rs` (new)
for the gate and permit types; the two `Operations` entry points beside `reserve_issuance`. Note that
`Inner` (`operations.rs:404`, built once at `:4929`) is the only place a per-runtime `SigningGates` can
live without touching `OperationsConfig` (E6d).

**Row 6 (bounded_by_expiry).** Matches. Types: `RemoteObligation` (`domain/src/revocation.rs:213`),
`PendingRemoteRevocation` (`:115`), `RemotePendingReason` (`non_exhaustive`, `:385`), `RevocationCause`
(`non_exhaustive`, `:27`). The supervisor pass is `Supervisor::revocation_pass` (`runtime/src/supervisor.rs:666`
–`:797`), called by `scheduler_pass` (`:607`); the `bounded_by_expiry` transition belongs inside its
`for p in pending` loop (`:681`) before the `slot.at > now` test (`:731`), with no `retry_remote_revocation`
call (`operations.rs:9509`) and no attempt counted. Other readers of obligations to keep consistent:
`load_remote_record` (`operations.rs:2479`), `RemoteView` (`:2349`), `complete_round_in` (`:2814`),
`track_bounded_answers_in` (`:3158`), `rearm_or_add` (`:3036`), `obligation()` (`:2438`). The
`RevokeOutcome` literal sites (new `remote_effects`): `app/src/holders.rs:237`, `testkit/src/lib.rs:689`,
`adapters/src/integration.rs:808`, `tests/model/operations.rs:3806`. `RemoteObligation` literals outside
`revocation.rs`: `operations.rs:2439`, `:2495`, tests `:11427`, `:11538`, `:11550`, `:12166`;
`tests/integration/store.rs:3578`, `:4064`, `:4087`. `RevocationCause::SessionLocked`: matched only with
`==` (`operations.rs:9330`, `:9409`), so a new variant breaks nothing.

**Row 7 (QR17).** Matches. The "timed-out immediate call counts as made" site is the `_ =>` arm of
`process_cleanup_intent`: `operations.rs:6941`–`:6954` (`let _ = bounded_adapter_call(limit,
a.revoke(grant, now)).await;`), after which the intent is cleared (`:6958`–`:6969`, `clear_cleanup_intent`).
For a remote-effect adapter the intent must be kept there. `process_cleanup_intents` `:6828` has no
backoff today (every `revocation_pass` calls it, `supervisor.rs:672`); "bounded, jittered backoff" is new
(`retry_delay`, `supervisor.rs:247`). `AdapterInfo` (`operations.rs:3271`, filled by `adapter_infos`
`:5000`) is where `remote_credential_effect` is copied. `AdapterDescriptor` full literals: `app/src/holders.rs:344`,
`adapters/src/integration.rs:512`, `testkit/src/lib.rs:782`, `heimdall/src/testcfg.rs:440`,
`tests/integration/runtime.rs:994`, `tests/model/idempotency.rs:191`, `events.rs:203`, `revocation.rs:355`,
`operations.rs:169`; `operations.rs:9897` spreads `..descriptor()`.

**Row 8 (restart: lost and destroyed instances).** Today matches (no instance handling). Restart recovery
is `Operations::start` (`:4920`) → `recover_after_restart` (`:5160`). The one transaction is the first
`self.write` (`:5164`–`:5181`: `init_self_environment` `:5166`, the `runtime_lifecycle` "started" event
`:5175`), so `mark_lost_instances` attaches there, before `open_operations`/the drive loop (`:5220`–`:5228`).
"Before any listener binds" already holds: `Service::start_with` runs `Operations::start` at
`runtime/src/service.rs:412` and `bind_endpoints` after it (`:464`; module docs `:3`–`:9`). The supervisor
hook `managed_reissue_pass` goes in `Supervisor::run` beside the other passes (`supervisor.rs:532`–`:575`).
Production never writes a credential instance today (`insert_credential_instance` `store/src/ext.rs:1557`
has test callers only, `tests/integration/store.rs:2365`), so the wave-0 test must seed rows through the
store. `CredentialState` (`domain/src/issuance.rs:194`) has no `Lost` and is not `#[non_exhaustive]`.
`update_credential_instance` (`ext.rs:1595`) treats `Destroyed` as absorbing; a `lost` state needs its own
rule.

**Row 9 (mechanism per pair).** Matches. `select_adapter` `operations.rs:3286` (already has the
`unattended` arm `:3295`), `catalog_pairs` `:3305`, `catalog_mechanism` `:3343`, `mixed_mechanisms` `:3354`;
called from `resolve_in` `:3918`–`:3922` and the reconcile check `:6512`–`:6514`. `inspect --preview` uses
the same resolution (`preview` `:8186`). `EnsureRequest` is hashed with `extra: Value::Null`
(`:8262`–`:8274`), so `connection` enters through `extra` only when present. `EnsureRequest {` literals
(each needs `connection`): `holders.rs` 1, `heimdall/cli.rs` 3, `run_cmd.rs` 1, `tests/e2e/setup_dispatch.rs` 1,
`tests/integration/runtime.rs` 2, `tests/model/{events 1, idempotency 3, operations 11, revocation 6, setup 1}.rs`.

**Row 10 (GrantOrigin).** Matches. `GrantOrigin` (`domain/src/grant.rs:79`–`:114`). Full literals:
`operations.rs:944` (`origin_of`), `tests/integration/store.rs:3226`, `:3322`, `:3333`, `:3379`,
`store/src/lib.rs:2402`, `:2415` (its tests); `operations.rs:6533` and `ext.rs:1098` spread `..origin`.
Add-only rule: `Txn::set_grant_origin` (`ext.rs:1051`), `set_grant_covered` (`:1086`).

**Row 11 (policy).** Matches. `StandingPolicy` (`domain/src/policy.rs:62`); full literals outside the
domain: `app/src/holders.rs:327`, `heimdall/src/testcfg.rs:353` (and `:380`), `store/src/lib.rs:1592`
(tests), `tests/integration/{runtime.rs:1052, store.rs:190, :1970}`, `tests/model/{idempotency:155,
events:131, authority:220, :420, revocation:168, :1627, operations:211, :2719, :3266, :4529}.rs`,
`tests/e2e/{setup_dispatch:763, cli_m02:582, run_m02:2701}.rs`. `PolicyAction` exhaustive matches:
`operations.rs:9609`–`:9612` (id), `:9618`–`:9623` (widening), `:9624`–`:9629` (unchanged),
`:10841`–`:10844` and `:10852`–`:10855` (`apply_widening`); `:9663`–`:9665` has `_ => {}`. The request
predicate is `matches!` (`request.rs:916`). Merge: `merged_policy` `:648` (the strictest-of rule belongs
there), `continuing_policy` `:672`. `upsert_policy(.., true)` at `:9669` moves the generation
(`store/src/lib.rs:1119`). CLI constructors: `heimdall/src/cli.rs:1094`–`:1115`, `:2308`–`:2367`.

**Row 12 (DegradedReason).** Matches. Enum `non_exhaustive` (`grant.rs:116`–`:122`); stored as a meta
key (`ext.rs:73`, `set_grant_degradation` `:1153`). Uses: `operations.rs:734`, `:981` (`mechanism_refuses`),
`:2178`, `:2192`. The sign rule needs `mechanism_refuses` (`:974`) not to refuse `IssuerUnavailable` or
`PairUnenrolled`: today it refuses on equality with `MechanismUnavailable` only, so new variants already
do not refuse use (the use gates are `GrantState::permits_use`, which includes `Degraded`,
`contract/src/state.rs:110`).

**Row 13 (dispatch arms).** Mismatch in wording. The dispatch table is
`OperationsDispatcher::handle_as` (`runtime/src/dispatch.rs:175`): attended refusal `:181`, `Shutdown`
`:187`, `match request` arms `:192`–`:212`, then a wildcard that answers `USAGE_ERROR` "not supported"
(`:213`–`:216`). So the three requests are already "not dispatched"; the planned
`CAPABILITY_UNAVAILABLE`/`driver_unavailable` needs explicit arms (use `OpError::driver_unavailable`,
`app/src/error.rs:98`). `Setup`/`Catalog` are fully wired (`:211`–`:212`). Session gate: `ipc/src/session.rs:858`
(`required_capability`), `server_capabilities()` `:108`–`:118`, and the second capability literal in
`Operations::inspect` `operations.rs:7895`–`:7903`. `Request::required_capability()` is exhaustive without
a wildcard (`request.rs:879`–`:894`). The SetPreference path: `CatalogAction::from_request` ends with
`_ => return None` (`domain/src/catalog.rs:~410`), so a new `CatalogRequest` action reaches
`Operations::catalog` (`app/src/catalog.rs:296`) and answers `USAGE_ERROR` (`:309`–`:313`), not
`driver_unavailable`.

**Row 14 (decision dispatch).** Matches, with the code further along than the plan's phrase. `Operations::decide`
`operations.rs:9712`: pre-checks `:9713`–`:9740`; expiry arm `:9762`–`:9768` (an or-pattern, not exhaustive);
`let waiting = match &d.kind` `:9771`–`:9830`; widening re-check `:9834`; application
`match (&record.kind, verdict)` `:9889`–`:10027`. `DecisionKind` is not `#[non_exhaustive]`
(`domain/src/decision.rs:~25`); exhaustive sites: `events.rs:722` (`decision_kind_name`), `operations.rs:4813`
(`decision_view`), the two matches above. New kinds go in the `waiting` match as a refusal that returns before
`complete_decision` (record stays pending).

**Row 15 (store bodies).** `ext_m03.rs` does not exist; `store/src/lib.rs:40` is `pub mod ext;`, `Txn` is
`lib.rs:144`, and a child module may use `self.tx` (as `ext.rs` does). Needs: `REQUIRED_TABLES`
(`lib.rs:181`–`:210`), `MIGRATIONS` (`migrations.rs:32`–`:56`), `SCHEMA_VERSION` (`:17`), the SQL file.
Two M02 assertions pin 5: `tests/integration/store.rs:1324` and `:4197` (N8).

**Row 16 (testcfg gates).** Mismatch (E3). The release refusal exists only in `service run`
(`heimdall/src/service_cmd.rs:113`–`:118`, over `ALL_ENV`, a `[&str; 7]` at `testcfg.rs:203`) and in
`launch_hooks` (`testcfg.rs:150`–`:157`, over `LAUNCH_ENV`). `refusal()` `:234`, `AVAILABLE = cfg!(debug_assertions)`
`:217`. `main.rs` (`:15`–`:30`) has no early check. `ScratchSecretStore` selection etc. have no hook point yet
(`prepare`, `testcfg.rs:519`, wires only the adapter, ledger and clock).

**Row 17 (restart: M03 kinds unresolved).** Restart goes `lead` (`operations.rs:5248`) → `drive` (`:5365`).
`drive` is an exhaustive `match st.op.kind` (`:5367`–`:5401`); the three new kinds get an arm beside the
setup arm (`:5384`–`:5392`). The existing report is `local_driver_unavailable` (`:5419`–`:5447`): event
`runtime_lifecycle` with `reason: driver_unavailable`; row 17 wants `owner_reconcile` and `kind`, so it needs
a variant with a different reason (E8). `OperationKind::ALL` is `[_; 12]` (`domain/src/operation.rs:63`)
and is read by `operation.rs:1089`, `:1105`, `:1147`, `:1150`.

**Row 18 (uninstall).** `UninstallArgs` has `purge_state` only (`heimdall/src/cli.rs:479`–`:483`);
`--keep-remote-enrollments` is new. The refusal attaches before the typed confirmation (`uninstall_cmd.rs:410`–`:418`,
`confirm_purge`), reading the store like `read_counts` (`:272`, `Store::open_read_only`, `store/src/lib.rs:277`,
which never migrates). There is no `Txn` method for "non-final enrollments" in §5 item 18 (E13).

**Row 19 (holders and owned connections).** The plan's `holders::holder_pass` does not exist: the pass is
`Supervisor::holder_pass` (`supervisor.rs:440`) → `Operations::release_exited_holders` (`app/src/holders.rs:114`)
→ `release_if_held_by` (`operations.rs:8964`) → `release_checked` (`:8973`). The `BindForm::Launch`
transaction is the settling closure of `drive_bind` (`:8422`; holder claim `:8590`–`:8595`, after
`Facts::conservative(...)` (`:8583`), whose `integration.executables` carries the verified client's `path`)
and `claim_replayed_launch` (`:8400`). Store: `set_binding_holder` `ext.rs:2006`, `binding_holders` `:2033`.
The failed-exec clear is, by inference, the CLI's release after `launching` (`launch_flow.rs`, not read).

**Row 20 (narrowing paths).** The complete list in `crates/app/src/operations.rs`:

| # | Path | Where it commits | Gate set today |
|---|---|---|---|
| a | `Operations::revoke` (`:9038`) → `drive_revoke` (`:9117`) | phase-1 closure `:9139`–`:9179`: `tombstone` literal `:9148`, `insert_tombstone` `:9156`, `revoke_locally_in` `:9159`, `claim_first_round_in` `:9169`; `now` read outside at `:9125` | `all = root + tx.grant_descendants(root)` read **inside** the closure (`:9140`) |
| b | cascade | the same transaction (descendants in `all`, `Tombstone.cascade` `:9150`); `revoke_locally_in` `:2229` | as (a) |
| c | authority withdrawn at re-validation | `end_in` (`:2077`–`:2150`): `grant_end` (`:2013`) classifies, `Tombstone` literal `:2116`, `revoke_locally_in` `:2124`; completion `complete_withdrawals` (`:9261`), `complete_interrupted_withdrawals` (`:9365`) | inside the caller's transaction. Six callers: `stage_resolve` `:5675`, `drive_bind` `:8566`, `end_if_invalid` `:9568` (from `:6587`, `:7079`, `:7392`), `tick` `:10233`, `reserve_issuance` `:10388`, `publish_issuance` `:10536` |
| d | cutoff set or moved earlier | `Operations::policy` (`:9585`): narrowing branch `:9663`–`:9670` (`upsert_policy(&p, true)` `:9669`); widening test `:9618`–`:9623` (a first cutoff, `cutoff_at == None`, is narrowing) | grants under the policy's profile; not computed anywhere (E6c) |
| e | environment-permission removal | **no `operations.rs` path.** Only `Txn::upsert_environment` (`store/src/ext.rs:828`), called by tests, `testcfg.rs:401` and `holders.rs:305`; effect seen later through `grant_end` → `revalidate_chain_verdict` (`:1062`) → path (c) | n/a (E6a) |
| f | lock revocation (row 25) | new `on_session_lock` | new |
| g | enrollment hold or removal (U10) | new | new |

Not narrowing, no tombstone (so no gate by the plan's rule): `Expired` in `end_in` (`:2095`–`:2108`),
`expire_grant` (`:10284`), `release_checked` last reference (`:8995`–`:9010`), `cancel_local_in`
(`:1678`), `revoke_locally_in` of waiting grants. A pause (`:9663`) is not narrowing for continuing work
(`continuing_policy` `:672`). Structural fact for all of (c): the withdrawal is decided inside a blocking
`write` closure, where an async gate cannot be awaited (E6b). Attach point for the gate set and marks:
before each `self.write(...)` that carries a narrowing, in the async method; shared state in `Inner`
(`:404`, constructed `:4929`).

**Row 21 (IntegrationSnapshot.managed).** Matches. `IntegrationSnapshot` (`ports.rs:185`, `Default`); its only
struct literal is `adapters/src/integration.rs:209`; the runtime builds it in `read_prepare_sources`
(`operations.rs:326`) and the single bounded call is `adapter.prepare_from` (`:6611`). The scan
`u0b_every_adapter_call_is_bounded` pins this file (N7).

**Row 22 (SetPreference).** `CatalogRequest` (`contract/src/catalog.rs:133`, `non_exhaustive`) has 8
actions. Exhaustive matches inside the contract: `action()` `:231`, `request_id()` `:246`, `validate()`
`:261`–`:280`. `CatalogAction` (domain, `catalog.rs:~340`) is matched exhaustively in `app/src/catalog.rs:668`
(`match &intent.action`, arms `:669`–`:853`); `narrowing()` `:246`–`:251` is a `matches!`;
`check_request` `:205`–`:240` has `_ => {}`. `from_request` `domain/src/catalog.rs:375` returns `None` for
unknown actions.

**Row 23 (CA retirement at restart).** "—" confirmed (no `issuers` table). Attach in
`recover_after_restart`'s first transaction (`:5164`–`:5181`) or just after the drive loop (`:5233`).

**Row 24 (SigningGates).** "—" confirmed; `crates/app/src/managed.rs` and `issuance_ro.rs` do not exist;
`app/src/lib.rs:16`–`:29` lists the modules. Rows 5, 20 and 26 call it; the scan in N7 forbids putting adapter-like calls
in `operations.rs`.

**Row 25 (on_session_lock).** New. Finding the `revoke_on_lock` grants: `Txn::grants_due(Timestamp::MAX)`
(used by `tick`, `:10162`, `:10231`) returns live grants; filter on `Txn::grant_origin(..).lock_behavior` (row 10).

**Row 26 (register_owned_connection).** New. Checks to reuse: `activation_refusal` (`:1823`),
`gate.admission` (`timegate.rs:513`), `tx.denied_ancestor` (`ext.rs:881`), `validated_generation` (`operations.rs:996`).

**Row 27 (revocation timestamps).** Today matches, with a useful fact. `revoke` reads `now` at `:9039`,
before the hash, visibility check and `admit` (`:9041`–`:9100`), and `admit` stores it as
`OperationRecord.created_at` (`:7466`), so `requested_at` already exists as `created_at`
(inference: the plan's "stored in the operation's intent" could reuse it; adding a field to
`RecoveryIntent` touches about 20 of the 71 `StageReceipt`/`RecoveryIntent` literal sites, and
`intent_update_allowed` forbids changing `request`, `ext.rs:199`). `committed_at` is not read inside the
tombstone transaction today: `drive_revoke` takes a second `now` at `:9125`, outside, and writes it as
`Tombstone.revoked_at` (`:9152`); `end_in` uses `safe.wall()` assessed in the transaction (`:2120`). The only
`RevokeData` literal is `complete_revocation_in` (`:2303`–`:2307`, called from `complete_round_in` `:2869`).
Replay: `render_settled::<RevokeData>(&st.op)` (`:9114`) returns the stored result, so timestamps
placed in the settled value replay unchanged.

**Row 28 (procstat).** Matches, one semantic delta (E9). Linux `process_start_time`: `runtime/src/platform.rs:671`
–`:692` (module `os` for `linux`/`android` `:644`): cuts at `rfind(')')`, first token must not be `Z`/`X`,
`fields.nth(18)` is token 20, digits only, prefixed with the boot ID. Wrapper `:255`. It does not check
token 1 as a single letter, token 3, or the token count beyond `nth(18)`. Callers of
`process_start_time`: `instance.rs:84`, `:168`, `supervisor.rs:269`–`:272` (`PlatformLiveness`),
`service_cmd.rs:398`, `run_cmd.rs:221`; tests `tests/integration/runtime.rs:704`, `:824`, `:839`. `heimdall-domain`
has no `procstat.rs`; the runtime already depends on the domain, so the call direction is fine.

## 3. The preserve list

| Preserved path | Where it lives | Guarding suites (file: tests) |
|---|---|---|
| Idempotency | `admit` `operations.rs:7415` (order: `classify`, backpressure, insert, `Authenticate`), `domain/src/idempotency.rs:61`–`:89` | `tests/model/idempotency.rs` (`retries_converge_conflict_and_expire_under_interleavings_and_purges` `:453`, `caller_timeouts_never_cancel_…` `:531`); `tests/model/operations.rs` `u0b_admit_keeps_backpressure_order` `:10976` |
| Decision completion | `decide` `:9712`, `Txn::complete_decision` `ext.rs:480` | `idempotency.rs` `decisions_are_consumed_once_under_concurrent_decide` `:592`; `operations.rs` `u0b_decision_kind_must_match_its_waiting_intent` `:14393`, `u0b_apply_projection_decision_resumes_exact_waiting_operation` `:14209` |
| Recovery | `recover_after_restart` `:5160`; `drive` `:5365` | `operations.rs` `a06_*` `:1263`–`:1406`, `restart_never_changes_environment_identity_or_revives_a_pause` `:1894`, `u0b_restart_dispatches_every_operation_kind` (two copies, `:10612`, `:14464`), `u0b_restart_keeps_withdrawal_and_cleanup_intent_recovery` `:11326` |
| IPC permissions, framing | `ipc/src/{unix,windows,session,frame,signing}.rs` | `tests/integration/ipc_unix.rs` (`bind_refuses_a_permissive_or_symlinked_directory` `:495`, `foreign_owned_socket_is_never_probed_or_unlinked` `:606`, `same_user_peer_is_accepted_and_reported` `:697`); `tests/adversarial/{ipc_frames,agent_frames,agent_client_frames}.rs` |
| Exit codes | `contract/src/{code,exit}.rs` | `tests/contracts/code_table.rs` (`golden_file_matches_the_adr_table` `:94`, `every_code_matches_its_golden_row` `:101`, `exit_numbers_are_the_documented_wire_numbers` `:161`); `tests/e2e/cli_m01.rs` |
| Remote revocation (`claim_seq`, `effect_seq`, caps) | `domain/src/revocation.rs:277` (`current_claim_seq`), `:293` (`migrate_claim_seq`), `:400` (`cleared_by_claim`); `operations.rs:2627` (`claim_first_round_in`), `:2732`, `:2814`, `:3204` (`settle_effect_in`) | `operations.rs` unit tests `r1318_4_*` `:11628`, `r1319_1_*` `:11835`, `r1319_2_*` `:11974`; `tests/model/operations.rs` `r1312_1_*` `:6080`, `r1313_3_*` `:7104`, `r1317_*` `:7934`–`:7995`, `r1318_*` `:8329`–`:8511`, `r1319_*` `:8836`–`:9000`; `tests/integration/store.rs` migration `:4057` |
| Cleanup intents | `revocation.rs:350` (`CleanupIntent`); `ext.rs:83`–`:85`, `:1254`–`:1304`; `operations.rs:6828`–`:6975` | `tests/model/operations.rs` `r1320_1_a_pending_cleanup_intent_is_visible_until_its_call_is_made` `:9199`, `u0b_timed_out_preparation_cleanup_processed_by_supervisor_without_restart` `:11984` |
| Bounded adapter calls (M02) | `bounded_adapter_call` `:305`, `Limits.adapter_call_timeout` `:234`, `ports.rs:246`–`:253` | `operations.rs` `u0b_every_adapter_call_is_bounded` `:12832` (source scan, N7), `u0b_bounded_adapter_call_drops_the_call_at_the_bound` `:12714`, `u0b_revoke_timeout_counts_as_unconfirmed_in_rounds_and_bounded_cleanup` `:12419` |
| Setup admission (M02) | `admit(.., exclusive)` `:7415`, `Txn::insert_setup_operation` `ext.rs:2359`, `open_setup_operations` `:2282` | `tests/model/setup.rs` `second_setup_while_one_is_open_is_setup_in_progress` `:2268`, `setup_in_progress_persists_across_restart` `:2308`, `crash_during_setup_admission_leaves_no_blocker` `:2347`; `operations.rs` `u0b_setup_admission_goes_through_insert_setup_operation` `:14822` |
| Holders (M02) | `claim_launch_holder` `:841`, `holders.rs:114`, `ext.rs:2006`–`:2047` | `app/src/holders.rs` tests (`holder_exit_releases_reference_and_reused_pid_does_not_keep_it` `:462`, `holder_unknown_liveness_never_releases` `:501`, `t04_*` `:582`, `:647`); `tests/e2e/run_m02.rs` (`holder_pass_releases_the_binding_once_the_run_exits` `:1913`, `t04_overlapping_runs_…` `:1959`) |

## 4. Notes for wave-0 implementers

**N1. Match sites that fail to compile (or silently mishandle) when a variant is added.**

| Type | `#[non_exhaustive]`? | Sites (base) |
|---|---|---|
| `Request` | yes | exhaustive only inside `contract/src/request.rs`: `kind()` `:832`, `admission()` `:853`, `required_capability()` `:879`. Elsewhere a wildcard is mandatory: `dispatch.rs:213`. `is_effectful` derives from `admission()` (`:928`–`:930`) |
| `OperationKind` | **no** | `domain/src/operation.rs` `as_str` `:88`, `m02_effect_class` `:118`, `ALL` `:63` (length 12), `SETUP` `:80`; `app/src/operations.rs:5367` (`drive`). Equality tests only: `:1646`, `:8816`, `:11015`, `app/src/catalog.rs:264`, `:322`, `:331` |
| `DecisionKind` | **no** | `events.rs:722`, `operations.rs:4813` (`decision_view`), `:9771`, `:9889` |
| `InspectSubject` | **no** | `operations.rs:7893` (`match req.subject`, no wildcard, arms `:7895`–`:8156`); CLI/TUI only construct (`tui/worker.rs:497`–`:502`, `cli.rs:1008`, `:1034`, `:1038`) |
| `PolicyAction` | **no** | `operations.rs:9609`, `:9618`, `:9624`, `:10841`, `:10852` (N in Row 11) |
| `CatalogRequest` | yes | contract `catalog.rs:231`, `:246`, `:275`; app `catalog.rs:205`–`:240` has a wildcard |
| `EventType` | yes | no match site anywhere (constructions and `==` only), so new variants break nothing |
| `IssuanceRefusal` | **no** | `app/src/error.rs:369`–`:409` |
| `DegradedReason`, `RevocationCause`, `RemotePendingReason` | yes | `==` only |

**N2. Struct literals that the new fields break** (outside the defining module; "T" = test file, to be edited
mechanically, N8):

* `EnsureData`: one: `operations.rs:4702`. All other hits are return types.
* `RevokeData`: one: `operations.rs:2303`.
* `Enforcement`: `domain/src/evidence.rs:77`, `app/src/holders.rs:267`, `adapters/src/integration.rs:298`,
  `heimdall/src/testcfg.rs:428`, T `tests/integration/runtime.rs:969`, T `tests/model/operations.rs:157`.
* `IntegrationSnapshot`: one: `adapters/src/integration.rs:209`.
* `AdapterDescriptor`, `RevokeOutcome`, `StandingPolicy`, `GrantOrigin`, `CertificateBounds`,
  `RemoteObligation`, `EnsureRequest`: as listed in rows 7, 6, 11, 10, 3, 6, 9 above.
* `Tombstone`: `operations.rs:2116`, `:9148`, tests `:11451`, `:11568`, `:12054`; `store/src/lib.rs:1582`, `:1747`,
  `:2055`; T `tests/integration/store.rs:235`, `:236`, `:701`.
* `OperationsConfig`: `service.rs:412`, `supervisor.rs:1124`, `holders.rs:355` and about 37 test literals. Avoid
  adding a field to it (E6d).
* `Limits`: all test literals spread `..Limits::default()` or `..bounded_limits()`
  (`tests/model/operations.rs:1061`, `:12586`, `:13411` …), so new fields are safe. It is `Copy + Eq`
  (`operations.rs:233`), defaults `:264`.

**N3. Request kinds today** (`Request::admission`, `request.rs:853`–`:871`): journaled `ensure`, `delegate`,
`bind`, `revoke`, `setup.apply`, `setup.rollback`, `setup.repair`, `catalog`; synchronous `cancel`,
`release`, `policy`, `decide`, `confirm_time`; read-only `inspect`, `observe`, `shutdown`, `setup.preview`.
`journaled-kinds.golden.json` is hand-maintained JSON with five keys (`journaled`: variant → `as_str`;
`synchronous`, `read_only`: kind strings; `declared_never_constructed`; `reserved`). It is read by
`tests/contracts/m02.rs:159` (contract half) and `domain/src/operation.rs:1130` (domain half, which asserts
`journaled+never+reserved == OperationKind::ALL.len()`). The contract half asserts that
`one_of_every_request()` (`m02.rs:~90`–`:130`) covers exactly the `op` and `action` values of the generated
`request.schema.json`. So adding `Issuer`, `Enrollment` and `Connections` makes the **M02 test fail** until
its sample list is extended; the golden and that list must change together (N8).

**N4. The reason registry and its golden.** `contract::envelope::reason::ALL` (`envelope.rs:~245`–`:300`, 27
values) plus `ConflictKind`s and `setup::manual_reason::ALL` are compared **by equality** with a transcribed
M02 list in `tests/contracts/m02.rs:545`–`:628`. M03's reasons must therefore live in a **separate** list
(the plan's "separate golden", U0), not be appended to `reason::ALL`. `driver_unavailable` is already there.
The 30-row code table has three guards: the golden, a parse of ADR-0006 `## 5. Stable code table …
Placement decisions` (`tests/contracts/code_table.rs:45`–`:79`; it treats any `|`-row with an upper-case
first cell and ≥ 5 cells in that span as a code row), and `Code::all()`. When ADR-0006 revision 4 adds its
reasons table, it must sit **outside** that span.

**N5. The schema exporter.** `contract::schema::public_schemas()` (`schema.rs:27`–`:48`) is a hand-written
`vec![named::<T>("name"), …]`; `heimdall schema export` writes `schemas/public-api/<name>.schema.json`
plus `codes.json`; `check.sh`'s `schema_check` (`check.sh:114`–`:127`) regenerates twice and diffs. New public
types (`enrollment-plan`, `enrollment-result`) are added there, and every changed type (`Request`,
`EnsureData`, `RevokeData`, `Event`, …) regenerates its file. `inspect capabilities` lists these names too
(`operations.rs:7904`). Examples are listed in the const `EXAMPLES` table with a `Kind` enum
(`tests/contracts/examples.rs:30`–`:166`); new schema kinds need new `Kind` variants (the file is M01's).

**N6. Test hosting.** `tests/contracts/mod.rs:34`–`:42` declares the modules (`mod m02;`): add `mod m03;`.
`heimdall-domain` has **no** `[[test]]` target today (its `Cargo.toml` has none), so `model_managed_domain`
is new there; its dev-dependency on testkit (`default-features = false`) builds a second copy of
`heimdall-domain` through testkit, so the test must not pass domain values across that boundary. The other
targets are hosted as the brief says: `model_operations` and `integration_runtime` by `heimdall-runtime`
(`crates/runtime/Cargo.toml`), `integration_store` by `heimdall-testkit`, `e2e_cli_*` by `heimdall`.
`testkit` has features `store`, `app`, `fixtures` (default) and no `managed` yet (`testkit/Cargo.toml:13`–`:36`).

**N7. Source-scan guards that pin today's text.**
* `tests/model/operations.rs:12832` `u0b_every_adapter_call_is_bounded` reads the production part of
  `crates/app/src/operations.rs` and asserts **exactly** `.reconcile(` ×4, `.revoke(` ×3, `.prepare_from(` ×1,
  `.prepare(` ×0, 8 `bounded_adapter_call(` spans, one `.read_sources(`, and no `.transaction(`, `.write(`,
  `.observe(` or `projection` inside a span. Any new managed-port call in that file with those substrings
  breaks it. Put such code in `app/src/managed.rs`.
* `u02_adapters_prepare_from_reads_no_store_or_live_source` (`:12992`) requires the `impl CredentialAdapter
  for` files in `crates/adapters/src` to be exactly `native_agent.rs` and `onepassword.rs` (relevant to U6, not wave 0).
* `domain/src/operation.rs:1130` scans every `crates/*/src` file: `OperationKind::{Cancel,Release,Policy,Probe}`
  may appear only as match-pattern lines.
* `heimdall/src/cli.rs:1808` scans the M02 sources for the retired phrase (E4).

**N8. "The M01 and M02 suites run unchanged" cannot be literal** (as M02's E13). Mechanical edits are
unavoidable: the struct literals of N2; `tests/integration/store.rs:1324` and `:4197`
(`assert_eq!(SCHEMA_VERSION, 5)`, and the `.v4.backup` name); `tests/contracts/m02.rs` sample list (N3);
`ScriptedSigner` (`agent_frames.rs:58`) and the `serve` calls (row 1). Rule applied here: only added fields
at M01/M02-equivalent values, no assertion or scenario change, reviewed as such.

**N9. Restart event shape.** `runtime_lifecycle` "started" is one event with counts (`operations.rs:5175`);
the per-operation `unresolved` events come from `local_driver_unavailable` (`:5419`), payload `{phase,
operation_id, kind, state, reason}`. The M02 test helper that reads them is `m02_integration::unresolved_events`
(used at `tests/model/operations.rs:14510`).

**N10. Smaller facts.** `OpError::driver_unavailable` `error.rs:98`; `ErrorDetail.reason` exists
(`envelope.rs:184`–`:187`). `Operations::write` (`:5071`) is the only way to run a store transaction;
closures are `FnOnce(&mut Txn, &mut Emit)` on the blocking pool. `ipc::EndpointKind::Issuer` and its
path/size rules already exist (`endpoint.rs:17`, `:76`, `:86`, `:97`); `EndpointPaths` carries an `issuer`
path. `SETUP_V1`'s doc comment in `contract/src/ipc.rs:56`–`:59` still says "not offered" (stale; it is
offered since the M02 activation). Two tests named `u0b_restart_dispatches_every_operation_kind` exist, in different modules
(`tests/model/operations.rs:10612`, `:14464`); the first covers the M01 kinds, the second the setup and catalog kinds.

## 5. Escalations

None is resolved here. Each names the fail-closed reading wave 0 can build against.

* **E1. `domain::verification::check` is "signature only" in U0 (plan `:344`) but U0b row 4 (phase 1, `:494`)
  calls it and tests "one refusal per predicate".** No unit owns the body (the plan mentions the function only
  at those two lines; ADR-0008 D5 §6.5 item 2 and D3 `:701` define the predicates). *Options:* (a) U0b phase 1
  writes the body, as `issuance::check` is a pure function (recommended); (b) row 4 moves to phase 2 and its
  tests wait; (c) U0 ships a body that refuses everything (fail closed), and row 4's per-predicate tests
  are deferred. *Reading used:* (a). *Owner:* integrator.
* **E2. `enrollment_recovery_paths_each_tested` (plan `:424`, `:433`; ADR-0008 `:1147`, `:3250`) needs U5/U10
  tests that do not exist in wave 0, and its case index (`tests/native/m03/case-index.json`) is U13's.** *Options:*
  (a) wave 0 ships the structural half: every recovery path of D5 §6.4, §6.7–§6.9 has a stable ID in a table in
  `domain::enrollment`, each names a planned test string, and the existence check is `blocked` until U5/U10/U13
  land; (b) the test is `ignored` with the exact missing input recorded; (c) move it to U13. *Reading used:* (a),
  reported `blocked` for the existence half, per AGENTS.md. *Owner:* integrator.
* **E3. Row 16's "check.sh's release-gate step" does not exist, and the release refusal is narrower than
  described.** `check.sh` (steps `:91`–`:145`) builds nothing in release mode. "Refuses with exit 2, as M01 and
  M02 do" holds only for `service run` (`service_cmd.rs:113`–`:118`, over `ALL_ENV`) and `launch_hooks`
  (`testcfg.rs:150`). `release_build_ignores_m03_test_gates` never existed, so "renamed from" has no source.
  "Before anything else" has no code location (`main.rs:15`–`:30`). *Options:* (a) add the M03 variables to
  `ALL_ENV`, add an early check in `main` for every command, and a `check.sh` step that builds `-p heimdall
  --release` once and runs the binary with each variable (cost: one release build); (b) restrict the claim to
  `service run`; (c) test through `testcfg::refusal(false, true)` as a unit test and record the release build as
  `blocked`. *Reading used:* (c) now, (a) proposed. *Owner:* integrator (T owns `check.sh`).
* **E4. "M01's 'not available in this build' envelope" (U0, brief §2) is retired.** `cli.rs:12`–`:14` says it and its
  helpers are retired (ADR-0007 §12.30 item 4); `cli.rs:1808` fails if any M02 source line contains the phrase, and
  `tests/e2e/cli_m01.rs:1884`–`:1976` fails if any M02 command prints it. *Options:* (a) the M03 commands answer
  `CAPABILITY_UNAVAILABLE`, reason `driver_unavailable`, exit 4, with different wording (the M02 pattern for the runtime
  side); (b) reuse the phrase and amend both tests; (c) `USAGE_ERROR`, exit 2, as M02's wave 0 did. *Reading
  used:* (a) with wording that avoids the phrase. *Owner:* integrator (U0, U12).
* **E5. Row 1's `SigningSession { peer: PeerInfo, … }` names a type the signing endpoint does not have.** `PeerInfo` is the
  client software name/version of the control hello (`contract/src/ipc.rs:63`); the signing accept loop has
  `PeerIdentity` (`ipc/src/endpoint.rs:104`; uid/gid/pid or SID/pid). ADR-0008 never names `PeerInfo` in D2. *Options:*
  (a) `peer: PeerIdentity` (ipc already owns it); (b) a new ipc struct. *Reading used:* (a). *Owner:* integrator (row 1 wording).
* **E6. Row 20 cannot be built as worded in four respects.**
  (a) *Environment-permission removal has no `operations.rs` path* (table row e): permissions change only through
  `Txn::upsert_environment` from tests and seeding; the withdrawal is found later by re-validation (row c). ADR-0008 D2 item 3a
  lists it as a narrowing commit. *Options:* no new path now, covered by (c); or a new `Operations::set_environment_permissions`
  that gates (not in any unit). *Reading used:* covered by (c), with a test through the store.
  (b) *Withdrawal at re-validation commits inside a blocking transaction* (`end_in`, six callers). A gate is an async lock and
  cannot be awaited there. *Options:* a read-only detection pass, gate, then re-run `end_in` under the gates
  (round 0/1 as in D2 item 3a); or make `end_in` return the set and let the six callers loop. The plan's steps (1)–(3)
  assume the first. *Reading used:* detect, gate, re-run.
  (c) *The grant set of a cutoff narrowing is unspecified* (`policy`, `:9663`): which grants does a new earlier cutoff
  affect (those whose bound it shortens)? *Reading used:* active or degraded grants of the policy's profile whose bound
  drops below their current bound.
  (d) *Who owns `SigningGates`?* Rows 5, 20, 24, 26 and U10 all share one instance between `Operations` and the runtime's
  signer, but `OperationsConfig` (about 40 literals) and `Inner` are both candidates and the plan names neither. *Reading
  used:* `Inner`, with `Operations::signing_gates()`; no `OperationsConfig` field. *Owner:* integrator.
* **E7. `issuer_endpoint_kind_reserved_never_bound` (U0 tests) is false today as worded.** The constructors accept any
  kind: `ipc::unix::Listener::bind(path, kind)` (`unix.rs:66`) and `windows::Listener::bind(name, kind, sid)`
  (`windows.rs:163`) store `kind` and do not refuse `Issuer`. The runtime binds only Control and Signing
  (`service.rs:648`–`:650`, `:690`–`:698`). *Options:* (a) refuse `Issuer` in both constructors (a one-line change in
  two ipc files); (b) a source-scan test that only `Control` and `Signing` reach a bind call. *Reading used:* (b), (a)
  proposed. *Owner:* integrator (ipc).
* **E8. Row 17's reason `owner_reconcile` is new and cannot reuse `local_driver_unavailable`**, which writes
  `driver_unavailable` (`operations.rs:5428`). Also, M03's table (plan `:2688`) lists `driver_unavailable (exists)` among its
  new reasons, and the registry location is unstated (N4). *Reading used:* a second helper with reason `owner_reconcile` in a
  separate M03 reason list. *Owner:* integrator.
* **E9. Row 28's validation changes `process_start_time` for some PIDs.** The shared parser requires token 3 (process group)
  ≥ 1, but the Linux function today ignores the group and accepts a `/proc` line with group 0, which occurs for kernel threads
  (inference; also for processes outside the reader's PID namespace). `platform_start_time_uses_shared_parser_semantics_unchanged`
  and the new validation then disagree for such a line. `ProcStat` must also expose the state letter, for the `Z`/`X` rule.
  *Options:* (a) `process_start_time` calls a start-time-only entry of the shared module that does not require the group
  (keeps today's semantics); (b) accept the change and rewrite the "unchanged" test. *Reading used:* (a). *Owner:* integrator.
* **E10. No U0b row covers `Operations::cancel` for the three enrollment kinds.** `cancel` (`:8793`) handles setup and catalog
  specially (`:8816`) and settles anything else `cancelled`. Plan §5 item 11 and ADR-0008 §6.4 (`:1622`) say a cancel is refused
  with `CAPABILITY_UNAVAILABLE`/`remote_step_in_progress` once the E3 `Attempted` receipt exists, allowed before. A seeded
  `enrollment.apply` record would otherwise be cancelled by the M01 path. *Reading used:* in phase 1, refuse always (no receipt
  can exist yet), no state change. *Owner:* integrator (new row).
* **E11. "Run unchanged" versus compile-breaking fields** (N8). The preserve rule is stated as literal; the plan's own fields
  break roughly 100 test literals and two `SCHEMA_VERSION` assertions. *Reading used:* the mechanical-edit rule of N8.
  *Owner:* integrator.
* **E12. Row 18 needs a store read the plan does not list.** §5 item 18's `Txn` list has `enrollments_for_pair` and
  `verified_cas_for_pair` but nothing that lists all non-final enrollments, and `Store::open_read_only` never migrates, so a
  schema-5 file has no `enrollments` table. *Reading used:* a `Txn::open_enrollments()` in `ext_m03.rs` and a
  "table absent means none" rule in the uninstall read. *Owner:* integrator.
* **E13. Plan statements that do not match the code (corrections, no design change).** Row 19's `holders::holder_pass` is
  `Supervisor::holder_pass` → `Operations::release_exited_holders`. Row 16's `testcfg` gates are
  `service run`/`launch_hooks` only. M5's `BindForm::Launch { executable, holder }` is `Launch(LaunchBinding)`. M13 is landed.
  The SETUP_V1 doc comment is stale (N10). §0.4 and U0b still cite `7f6f1c05` and `1f5b8156`.
* **E14. `u0b_every_adapter_call_is_bounded` pins exact counts in `operations.rs`** (N7). Nothing in the plan says where the
  `ManagedEffects` calls (row 21, phase 2) go. *Reading used:* `app/src/managed.rs`. *Owner:* integrator.

## 6. Commands run

All read-only except this file and `.m03-wave0-questions-V.md`. The scratch export lived in `/tmp/v-base`, `/tmp/v-m03-plan.md`,
`/tmp/v-adr8.md` and was removed at the end.

* `git show 410ec237:docs/architecture/m03-plan.md`, `…:docs/decisions/0008-managed-credential-integration.md` to `/tmp`: exit 0.
* `git -C <worktree> archive 410ec237 crates tests tools schemas Cargo.toml | tar -x -C /tmp/v-base`: exit 0.
* `git diff --stat 491d8f5a 410ec237 -- crates tests/…`, `git diff --stat 1f5b8156 410ec237 -- crates`,
  `git log --oneline 7f6f1c05..410ec237`, `git merge-base --is-ancestor 1f5b8156 410ec237` (exit 0): no code changed by me.
* `grep`, `awk`, `sed -n` over `/tmp/v-base` for every claim above (all exit 0 or 1 by design; no failing command affected a
  result), and reads of the files named in each row.
* No `cargo`, no `check.sh`, no test was run. Nothing here was executed against a build; every statement is a reading of source
  or text. Statements marked "inference" were not checked by running anything.
