# M06 U0 handoff (contract revision 7)

**Status:** prepared 2026-11-23 and updated at the M06 exit (2026-11-24) by the M06 integrator, the contract owner of
revision 6.x, for the contract owner of revision 7 at U0. Docs only: nothing here is applied. Companion to
`docs/architecture/m07-u0-handoff.md`, which holds M07's questions (U0-Q1 to Q7) and M08's (U0-Q8 to Q10, added by M08 W2).
M06's questions are U0-Q11 to Q14 (§4).

## 1. The base: revision 6.x is closed at 6.6

- ADR-0013 §11 is written on revision 6.1. Main carries revisions 6.2 to 6.6 (ADR-0006 §18.6 to §18.10). **Revision 7
  re-bases onto 6.6**, not 6.1 and not 6.5.
- What 6.2 to 6.6 add (each additive, schema major `"1"`; the item tables in ADR-0006 are the authority):
  - 6.2 (§18.6, W2): the runner runtime offers `remote-control/1`; `ServerHello.remote_client`; `client.revoked` events;
    read-only owner-role views for a paired owner; `DecisionKind::RemoteWidening` (migration 0010); reason
    `mgmt_key_store_unavailable`; `EnsureData.residuals`.
  - 6.3 (§18.7, W3): client endpoint IDs (migration 0011, `Invite.iroh_admission`, `Join.iroh_endpoint`,
    `rotate_endpoint`); `ExposurePolicy.port`; the `controller_record.*` and `runner_local.*` forms (`trust_issuer`,
    `enroll_owner`); reasons `local_owner_required` and `resync_pending`; the prepare answer's policy ID;
    `environment status --json`'s remote fields; `Join.probe`; the bridge's self-check; the downgrade as an
    authority-bearing `meta` key and its attended lift.
  - 6.4 (§18.8, W4): `EnsureRequest.pair_issuers`; `AuthorityReport.pending_grants`; the pending `ACCEPTED` answer with
    `refresh_dependency: controller` and `remote_pending`; `environment resume-issuance`.
  - 6.5 (§18.9, W5): the serve policy's `sshd_port`; `access allow --profile P --environment RUNNER` (record source (b));
    the hidden `access ensure --issuer-ca`; the in-force flag on a delivered pause or cutoff; `rotate_endpoint` in the base
    capability; limited roles' product use; `environment remove` forgetting delivered state; local widening decisions
    (`origin`, `lifted_effects[]`); `route add --relay`; the unattended local widening's `INTERACTION_REQUIRED`;
    `route.record_health`; the `mgmt_agent_*` reasons (item 12) and the six `ssh_*` reasons (item 13).
  - 6.6 (§18.10, the M06 exit): `RouteFailureClass::driver_unavailable` (ADR-0015, ruling Q-B).
- Deferred by 6.5 to revision 7: the runner launch's provenance field (U0-Q4); a reason for the Windows probe refusal
  (U0-Q3); a reason for the unattended local widening `INTERACTION_REQUIRED` (§18.9 item 10).
- ADR-0015 (accepted; narrowed 2026-11-24 by the exit review's R03): release artifacts are built without `iroh`.
  Revision 7's command tree keeps the `transport` and Iroh route names. In a release build the `transport` forms answer
  `driver_unavailable`; route commands accept and record an Iroh leg, and using it is recorded `driver_unavailable` and
  failed over (6.6). Refusing the add itself is follow-up **M06-F7**, a live contract change for revision 7 (§5).

## 2. The files

| File | What U0 reads there |
|---|---|
| `docs/decisions/0006-public-contract-baseline.md` §18.4 to §18.10 | revisions 6.1 to 6.6, as ruled and as built |
| `docs/decisions/0012-environments-and-transport.md` | environments, roles, widening (§3.10), routes (§5), revocation and resync (§7.4) |
| `docs/decisions/0015-iroh-release-scope.md` | the Iroh preview scope, and what a build without `iroh` refuses (R03's amendment) |
| `docs/decisions/0005-managed-credential-recipe.md` §3.5 | remote reservations (conditions 1 to 10) |
| `docs/architecture/m06-plan.md` §2, §3 | the wave rulings and the exit mapping |
| `schemas/public-api/` | the generated schemas at 6.6 |
| `tests/contracts/golden/cli-help-m06/`, `tests/contracts/golden/rev6-5-decisions.golden.json` | M06's help goldens and decision documents |
| `crates/contract/src/{environment,route,request,managed}.rs` | the M06 types |
| `crates/remote/src/widening.rs`, `crates/store/migrations/0011*` to `0013*` | widening records and their replay |
| `tests/integration/remote_runtime_m06.rs` | D16's restart-replay coverage (pending, claimed, terminal, expired, local): `decision_backed_replay_after_a_store_restart_answers_each_record_state` |
| `docs/architecture/m06-exit.md` | the exit record: the records' build commit, the per-platform run commits and binaries' digests (§1.3's prior-version input), the limitations and the follow-ups |
| `tests/evidence/artifacts/review-m06/exit.md` | the exit review: R03 (route add of an Iroh leg without the driver) and R02 (route verification without the fill) |
| `tests/evidence/m06-*.json`, `tests/evidence/artifacts/m06/exit-runs.json` | the exit records and their configuration (`run_commit` per platform) |

## 3. Delta owners (ADR-0013's obligations on M06)

| Delta | M06 delivered | Remainder | Owner |
|---|---|---|---|
| **D3 / PC7, names and grammar** | The Q1 top-level names (`environment`, `device`, `route`, `transport`); per-command help goldens (16 files) | A command-tree golden; goldens for `environment recheck`, `transport enable/rotate/adopt-roost`, `route remove/prefer`, `remote *` beyond `init`; the help text's milestone and spec references (D14); whether the hidden endpoints `route connect`, `transport serve`, `remote serve` get declarative flags (ruling E8) | U0 |
| **D11, per-pair route status** | The inputs: stored routes and pins, `route.record_health` (in memory, per destination, untyped in `inspect destinations`) | The typed, persisted per-pair status (U0-Q12) | U0 (type), U3 (emitter) |
| **D16 / RC08, ratify revision 6; decision-backed replay** | Replay semantics in `remote::widening`; restart-replay coverage for every state, after a real store restart (M06 exit, `remote_runtime_m06.rs`) | The ratification itself; the keyspaces (U0-Q11) | U0 |
| **RC06, the paged `remote_pending` read** | Nothing (ADR-0013 names "M06's U7", which owned only the exit suite) | The count, the bounded projection and a page form (U0-Q13) | U0 (types), U3 (arm) |
| **§1.3, prior-version rows** | The M06 exit builds, their commits and their binaries' digests (`m06-exit.md` "Build identity"; `tests/evidence/artifacts/m06/exit-runs.json` and `digests.txt`) | The corpus from scratch stores written by that build | U0 |
| **The 6.x → 7 re-base** | 6.x closed at 6.6 (ADR-0006 §18.10) | ADR-0013 §11 re-based; at least D5, D8 and D16 change | U0 |
| **A07's runner residuals** | Runner residuals carry `new_authentication` only (a stated limitation of A07's runner rows) | The other components (U0-Q14) | U0 (types), U3 (emitter) |
| **M06-F7, an Iroh route added without the driver** | `route add --iroh` is accepted and recorded in any build, with its attended consent; the helper records the leg `driver_unavailable` and fails over (6.6) | Refuse the add in a build without the driver (`CAPABILITY_UNAVAILABLE`, `driver_unavailable`, the preview message) before any decision is recorded; keep the failover for rows a source build wrote | U0 (the refusal's place in the command tree), U3 (the code) |

## 4. Questions for U0

- **U0-Q1 to U0-Q7:** M07's, in `docs/architecture/m07-u0-handoff.md` §3. U0-Q3 (reasons under
  `CAPABILITY_UNAVAILABLE`) and U0-Q4 (launch provenance) cite M06 cases; M06 adds nothing to them beyond §1 above.
- **U0-Q8 to U0-Q10:** M08's, in `docs/architecture/m07-u0-handoff.md` §3 (added by M08 W2: repairing a damaged request
  ledger, case-insensitive catalog aliases, the `alias_collision` producers). M06 adds nothing to them.

### U0-Q11. The replay keyspaces for widening records
- **Observed:** ADR-0013 §7 keys decision-backed replay by `(client, kind, request_id)`. Revision 6.5 item 8 added
  `origin = local` records with no client, deduplicated by `(request_kind, delta_digest)`
  (`crates/store/migrations/0013_local_widening.sql`; `crates/remote/src/widening.rs`). A lapsed local record is
  replaced on resubmission, not answered `DECISION_STALE`. `request_id` is advisory for `runner_local.*` (§18.7).
- **Recommended:** §7 names three keyspaces, each with its own replay-table row: paired `(client, kind, request_id)`;
  local `(kind, delta digest)`, `request_id` advisory; `runner_local`, converging by result. D16's restart coverage
  already includes one local record.

### U0-Q12. What D11's per-pair route status is
- **Observed:** `route_health` is the latest attempt per destination, ignoring `account`
  (`crates/runtime/src/supervise_transport.rs`), memory-only (`crates/runtime/src/dispatch.rs`), and untyped JSON in
  `inspect destinations`, present only when a route transport is wired. ADR-0010 §10's gap (an unsatisfied route
  dependency shows only as a lost `destination_scope`) is still open.
- **Recommended:** a typed `route_status` per `(destination, account)` in D1's destination view, derived from stored
  routes and pins and persisted, with states `ready`, `undetermined` (a D21 reason) and `no_route`; `route_health`
  becomes an optional `last_attempt` documented "since runtime start"; the TUI reads only the typed field.

### U0-Q13. Who builds the complete `remote_pending` read (RC06)
- **Observed:** ADR-0013 §2 and §13 RC06 assign the paged environments arm to "M06's U7"; U7 owned only the exit suite
  (`m06-plan.md` §1). `EnvironmentView.remote_pending` is an unbounded `Vec` with no count
  (`crates/contract/src/environment.rs`), and `environment status --json` carries the same entries.
- **Recommended:** correct RC06's owner to U0 (`remote_pending_count`, a bounded first-16 projection, an
  `inspect environments` page form scoped to one environment) and U3 (the emitter); apply the same projection to
  `environment status --json` in the same change.

### U0-Q14. The runner's revocation residual components (A07)
- **Observed:** a runner's report carries `GrantResidual` with `new_authentication` only
  (`crates/app/src/remote_status.rs`). The other `RevocationResiduals` components (dedicated sessions, admissions, other
  live sessions, detached processes; `crates/contract/src/managed.rs`) are neither reported for a runner nor asserted by
  an A07 runner test. A07's runner rows state this as a limitation (ruling E4).
- **Recommended:** the runner report carries the full `RevocationResiduals` per grant, with the same counted-history rule
  as the local report; U3 emits it and A07's runner journey asserts each component.

## 5. Rulings already made that U0 carries

- ADR-0015: no support label for Iroh; the names stay in the command tree; `driver_unavailable` in release builds.
- E8: the hidden endpoints' flags are U0's decision under D3; M06 changes nothing.
- A Windows device is an owner controller only, not a limited client (ADR-0012 §2.6); the refusal's reason is U0-Q3.
- Every product launch of `ssh` inherits the user's environment unchanged or fills it from the OS (the M06 launches since
  `ca881f30`, without the caller's `SystemDrive` since `978c2be4`). Route verification and the jump leg inherit it, so a
  Windows process without `ProgramData` fails closed there, `HOST_PIN_DEFEATED`: `unreadable` (the exit review's R02;
  follow-up M06-F6, not a contract change).

## 6. The exit review's follow-ups, by whether they touch the contract

- **M06-F7 (contract, live):** see §3. The add-time refusal changes what `route.add` answers in a build without the
  driver; U3 implements it under revision 7.
- **Not contract changes:** M06-F5 (the guard requires a usable effective `ProgramData`; `windir` checked), M06-F6 (the
  fill for route verification and the jump leg), M06-F8 (a test-only marker in the Windows fill child test), and M06-F3
  (`HEIMDALL_TEST_*` as test configuration only; product hardening, likely M08 U1b).
