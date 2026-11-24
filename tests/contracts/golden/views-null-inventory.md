# Revision 7 typed views: per-field inventory (ADR-0013 D1, D9; PC2, PC3)

The types are in `crates/contract/src/views/` (`view_schemas()`). Each table below lists one
view. For each field it gives:

- the JSON type;
- its state **today**, read from the builder, with file and line (`ops` is
  `crates/app/src/operations.rs`; other paths are relative to `crates/`);
- its **revision-7** form under ADR-0006 §9;
- **PC3:** `yes` where the revision-7 form differs from today's. That is a U3 change, made
  together with its readers.

Today's states:

- **present:** always written.
- **omitted:** sometimes absent.
- **null:** sometimes `null`.
- **both:** sometimes absent and sometimes `null`.

Revision 7 has no required-nullable view field. Every PC3 change found is a `null` that
means "not applicable", which becomes an omitted key. No view removes, renames or re-types a
key. `tests/contracts/rev7_views.rs` checks each table: today's documents read, and
re-serializing drops exactly the `yes` rows.

`preview` is the result of `inspect --preview` (`PreviewView`). It is added to the data of
every subject except `export` (`ops:10144-10149`). It is omitted without `--preview`, both
today and in revision 7. Its rows are in the `inspect-bindings` table. The typed views
outside this directory carry it too, untyped (see the end).

Lines were read at `58fb4346`'s working tree. `heimdall/src/cli.rs` is being edited
concurrently, so its lines are approximate; its function names are exact.

## `inspect-capabilities` (`CapabilitiesView`)

| Field | JSON type | Today | Revision 7 | PC3 |
|---|---|---|---|---|
| `capabilities` | string[] | present (`ops:9644-9661`) | present | no |
| `schemas` | string[] | present (`ops:9662-9665`) | present | no |
| `codes[]` | `{code, exit_code, retryable, default_effect_status, default_next_action, success}` (`CodeRowView`) | present (`ops:9666`, `contract/src/schema.rs` `code_table`) | present | no |
| `schema_version` | string | present (`ops:9667`) | present | no |
| `lock` | `{behavior, disclosure, acknowledged_at?}` | omitted when the disclosure cannot be read (`app/src/operations/lock_connection_m03.rs:252-279`) | same | no |
| `lock.acknowledged_at` | timestamp | omitted when never acknowledged (`lock_connection_m03.rs:273-275`) | same | no |
| `login_start` | `LoginStartView` | omitted only if the observation task fails (`app/src/operations/login_entry_m04.rs:254-274`) | same | no |

## `inspect-environments.full` (`EnvironmentListView`)

The schema name is provisional. Today's public `inspect-environments`
(`environment::EnvironmentsView`) describes the owner's `items` only. This view adds M01's
keys, which every role gets.

| Field | JSON type | Today | Revision 7 | PC3 |
|---|---|---|---|---|
| `environment_id` | string | present (`ops:9678-9682`) | present | no |
| `enrolled` | bool | present | present | no |
| `environments[]` | `EnvironmentRecordView` (0 or 1 entries) | present | present | no |
| `environments[].id`, `.device`, `.kind`, `.permissions{automatic_activation, managed_signing, issuer_access}` | string, string, enum, object | present (domain `EnvironmentRecord`) | present | no |
| `environments[].label` | string | null when unset (domain `EnvironmentRecord.label`, no skip) | omitted when unset | **yes** |
| `items` | `EnvironmentView[]` | omitted for a role that is not the owner (`ops:9683-9693`). For a WSL row, `state` and `realization.helper` are rewritten after the transaction (`app/src/operations/wsl_m04.rs:348-410`) | same | no |

## `inspect-profiles` (`ProfileListView`)

| Field | JSON type | Today | Revision 7 | PC3 |
|---|---|---|---|---|
| `items[]` | `ProfileView` | present; `[]` for a role that is not the owner (`ops:9716-9738`) | present | no |
| `items[].profile_id`, `.revision`, `.pairs[]`, `.capabilities[]` | string, int, `{destination, account}`[], string[] | present (`ops:9725-9731`) | present | no |
| `items[].label` | string | null when unset (domain `ProfileDefinition.label`) | omitted when unset | **yes** |

## `inspect-destinations` (`DestinationListView`)

| Field | JSON type | Today | Revision 7 | PC3 |
|---|---|---|---|---|
| `items[]` | `DestinationView` | present; `[]` for a role that is not the owner (`ops:9706-9712`, `ops:10169-10207`) | present | no |
| `items[].destination_id`, `.alias`, `.revision`, `.updated_at`, `.definition` | string, string, int, timestamp, `managed`/`observed` | present (`ops:5720-5726`, `ops:5756`) | present | no |
| `items[].label` | string | null when unset (`ops:5724`) | omitted when unset | **yes** |
| `items[].hostname`, `.account`, `.identity_id` | string | omitted for `observed` (`ops:5736-5751`) | same | no |
| `items[].port` | int | null for `managed` without a port; omitted for `observed` (`ops:5740`, `ops:5747`); both | omitted unless set | **yes** |
| `items[].jump` | string | omitted without a jump (`ops:5738-5744`) | same | no |
| `items[].preference` | `{mechanism, projection{state, generation?}, connection_policy?}` | omitted without a stored pair row, and for `observed` (`ops:5760-5770`) | same | no |
| `items[].preference.connection_policy` | `ConnectionPolicyReport` | omitted unless a `managed_certificate` preference is covered and a wording source exists (`lock_connection_m03.rs:211-245`) | same | no |
| `items[].route_health` | `{result: RouteHealthPayload, reported_at}` | omitted without a report with at least one attempt. Added by the dispatcher (`runtime/src/dispatch.rs:216-256`, call `:810`) | same: the D11 per-pair status | no |
| `items[].host_pin_defeated` | `{setting, reported_at}` | omitted unless the report names a setting (`dispatch.rs:245-253`) | same (D11) | no |

## `inspect-bindings` (`BindingListView`)

| Field | JSON type | Today | Revision 7 | PC3 |
|---|---|---|---|---|
| `bindings[]` | `BindingView` | present (`ops:9739-9879`, wrap `ops:9875`) | present | no |
| `bindings[].binding_id`, `.grant_id`, `.work_id`, `.profile`, `.profile_revision`, `.state`, `.created_at` | string ×4, int, `active`/`released`, timestamp | present (`ops:9810-9818`) | present | no |
| `bindings[].request_id` | string | not emitted | **declared**: omitted except to the caller that created the binding | no (new) |
| `preview` | `PreviewView`, tagged by `outcome` | omitted without `--preview` (`ops:10144-10149`, built at `ops:10245-10273`) | same | no |
| `preview.snapshot.profile`, `.profile_revision`, `.requested{pairs, capabilities}`, `.deadline` | string, int, object, timestamp | present (`ops:10250-10256`) | present | no |
| `preview.snapshot.mechanism` | string | null without a resolved adapter (`ops:10249`, `ops:10255`) | omitted then | **yes** |
| `preview.effective` (`allowed`) | domain `EffectiveAuthority`, verbatim | present | present, verbatim | no |
| `preview.covered` (`approval_required`) | domain `EffectiveAuthority`, verbatim | null when nothing is covered (`ops:10261-10264`) | omitted then | **yes** |
| `preview.delta` (`approval_required`) | domain `AuthorityDelta`, verbatim; its inner `extra_window` is `null` without one | present | present, verbatim (see the open questions) | no |
| `preview.code`, `.message` (`denied`) | string | present (`ops:10247`, `ops:10267`) | present | no |

## `inspect-grants` (`GrantListView`)

| Field | JSON type | Today | Revision 7 | PC3 |
|---|---|---|---|---|
| `grants[]` | `GrantView` | present (`ops:9873`) | present | no |
| `grants[].grant_id`, `.state`, `.expires_at`, `.scope{pairs, capabilities}` | string, `GrantState`, timestamp, object | present (`ops:9822-9828`) | present | no |
| `grants[].parent` | string | null for a root grant (`ops:9826`) | omitted for a root grant | **yes** |
| `grants[].degraded_reason` | enum | omitted unless `degraded` with a recorded reason (`ops:9831-9838`) | same | no |
| `grants[].remote_pending` | `true` | omitted when false (`ops:9839-9843`) | same | no |
| `grants[].remote_pending_reasons` | enum[] | omitted when empty (`ops:9847-9852`) | same (D17) | no |
| `grants[].remote_retries` | `{attempts, last_attempt_at, stopped}` | present exactly with `remote_pending` (`ops:9853-9860`) | same | no |
| `grants[].cleanup_pending` | `true` | omitted when false (`ops:9862-9867`) | same | no |

## `inspect-operations` (`OperationListView`)

| Field | JSON type | Today | Revision 7 | PC3 |
|---|---|---|---|---|
| `operations[]` | `OperationView` (see `operation`) | present (`ops:9885-9890`) | present | (see `operation`) |
| `counts[]` | `{state, count}` | present: only states with a row, by state name, not filtered by visibility (`ops:9891-9894`, `store/src/lib.rs:1662`) | present (subject metadata, kept) | no |

## `inspect-decisions` (`DecisionListView`)

| Field | JSON type | Today | Revision 7 | PC3 |
|---|---|---|---|---|
| `decisions[]` | `DecisionView` | present; `[]` for a role that is not the owner (`ops:9933-9977`) | present | no |
| `decisions[].decision_id`, `.kind`, `.state`, `.created_at`, `.expires_at`, `.expired` | string, `DecisionKindName`, `DecisionStateView`, timestamps, bool | present (`ops:5870-5880`) | present | no |
| `decisions[].request` | object by `kind`, recorded content verbatim | present (`ops:5790-5869`) | present, verbatim: persisted content (D9) | no |
| `decisions[].reason` | string (`approval_lapsed`) | omitted unless a local widening lapsed at this read (`ops:5919-5925`) | same | no |
| `decisions[].policies` | `{policy_id, revision}`[] | present (possibly `[]`) exactly for a targeted `widen_policy` (`ops:9952-9956`, `app/src/operations/stop_m05.rs:1089-1108`) | same | no |
| `decisions[].lifted_effects` | `LiftedEffect[]` | omitted when it lifts none (`ops:9959-9963`, `stop_m05.rs:1059-1087`) | same | no |
| `decisions[].scope` | `DecisionScope` | omitted unless a `widen_policy` `create` has its basis and snapshot (`ops:9966-9970`) | same | no |

## `inspect-identities` (`IdentityListView`)

| Field | JSON type | Today | Revision 7 | PC3 |
|---|---|---|---|---|
| `identities[]` | `IdentityView` | present; `[]` for a role that is not the owner (`ops:9902-9915`) | present | no |
| `identities[].identity_id`, `.revision`, `.fingerprint`, `.key_type`, `.mechanism`, `.interaction`, `.interaction_basis`, `.noninteractive{eligible, reason?}`, `.eligibility_checked_at` | mixed | present (`ops:5686-5700`) | present | no |
| `identities[].endpoint` | `{kind, locator}` | null when the source names none (a public-key file) (`ops:5692`) | omitted then | **yes** |
| `identities[].label` | string | null when unset (`ops:5693`) | omitted when unset | **yes** |
| `identities[].declared_at` | timestamp | null without a live declaration relied on (`ops:5681-5685`, `ops:5696`) | omitted then | **yes** |
| `identities[].declaration` | `DeclarationRef` | null without a live declaration (`ops:5673-5680`, `ops:5697`) | omitted then | **yes** |

## `inspect-projections` (`ProjectionListView`)

| Field | JSON type | Today | Revision 7 | PC3 |
|---|---|---|---|---|
| `projections[]` | `ProjectionResourceView` (domain `ManagedResource`) | present; `[]` for a role that is not the owner (`ops:9918-9932`) | present | no |
| `projections[].id`, `.kind`, `.owner`, `.generation`, `.desired`, `.observed`, `.locator`, `.updated_at` | mixed | present | present | no |
| `projections[].last_operation` | string | null when none is recorded (domain `ManagedResource.last_operation`) | omitted then | **yes** |
| `record` | `ProjectionRecordView` | null until a projection is committed, and for a role that is not the owner (`ops:9920`, `ops:9924-9927`) | omitted then (subject metadata, kept) | **yes** |
| `record.environment` | string | present | present | no |
| `record.items` | object keyed by projection item | present (possibly `{}`) | present | no |
| `record.items.*.generation`, `.files[]`, `.aliases[]`, `.operation`, `.committed_at` | mixed (`files[]` verbatim domain `ProjectionLocator`) | present (domain `ItemRecord`) | present | no |
| `record.items.*.include_file` | string | omitted (domain skip) | same | no |

## `status` (`StatusView`)

| Field | JSON type | Today | Revision 7 | PC3 |
|---|---|---|---|---|
| `running` | `true` | present (`heimdall/src/cli.rs` `status`, ~1994-2000) | present | no |
| `environment_id` | string | present (from the hello) | present | no |
| `operation_counts` | `{state, count}`[] | present (`inspect operations`' `counts`) | present | no |
| `open_operations` | int | present | present | no |
| `pending_decisions` | int | present (expired-but-pending records included in `--json`) | present | no |
| `chores[]` | `{chore, command, message}` | omitted unless a chore is pending (`heimdall/src/doctor_cmd.rs:1296-1322`) | same | no |

## `service-status` (`ServiceStatusView`)

| Field | JSON type | Today | Revision 7 | PC3 |
|---|---|---|---|---|
| `running` | `true` | present (`heimdall/src/service_cmd.rs:457-466`) | present | no |
| `pid` | int | present (the advertisement's `InstanceInfo.pid`) | present (the verified peer's, equal to the advertisement's: D12) | no (source only) |
| `version` | string | present (the advertisement's `InstanceInfo.version`) | present (from the hello's `server.version`: D12) | no (source only) |
| `environment_id`, `capabilities`, `principal` | string, string[], `PrincipalInfo` | present (from the hello) | present | no |
| `time_sync_observation` | `{interface, reading, used_by_time_gate, max_error_us?, sta_unsync?, why?}` | present (`service_cmd.rs:663-691`) | present | no |
| `time_sync_observation.max_error_us`, `.sta_unsync` | int, bool | omitted unless `synchronized` or `not_synchronized` | same | no |
| `time_sync_observation.why` | string | omitted unless `unavailable` | same | no |
| `control_endpoint` | string | not emitted | **declared** (D12): the verified endpoint | no (new) |
| `protocol` | int | not emitted | **declared** (D12): from the hello | no (new) |

## `operation` (`OperationView`)

`operation show` and `operation wait` (`Observe::Operation`, `ops:10956-10998`;
`observed_view`, `ops:9345-9377`; `operation_view`, `ops:5775-5787`). `wait` adds nothing to
`data`.

| Field | JSON type | Today | Revision 7 | PC3 |
|---|---|---|---|---|
| `operation_id`, `kind`, `state`, `effect_status`, `created_at`, `updated_at` | string, `OperationKindView`, `OperationState`, `EffectStatus`, timestamps | present | present | no |
| `code` | `Code` | null until terminal (domain `OperationRecord.code`) | omitted until terminal | **yes** |
| `cancellation` | `{requested_at, may_have_external_effect}` | null unless a cancel was requested | omitted then | **yes** |
| `result` | any | null until terminal, and null where `observe` withholds a foreign binding's unreadable result (`ops:9364-9372`) | omitted in both cases (see the open questions) | **yes** |

## `subscription-head` (`SubscriptionHeadView`)

This is the `data` of the head line of `operation events --follow` (`heimdall/src/cli.rs`
`follow`, ~2821-2825). The envelope is `state: running`, `next: {action: observe, cursor}`.

| Field | JSON type | Today | Revision 7 | PC3 |
|---|---|---|---|---|
| `subscription` | int | present | present | no |
| `cursor` | string | present (the server's head boundary) | present | no |
| `snapshot` | `{data, cursor, taken_at}` | null when resuming from a usable cursor. Present when the client sent no cursor, or the server resnapshotted silently | omitted when resuming | **yes** |
| `snapshot.data` | today's untyped document (`app/src/events.rs:775-835`) | present | PC1's `event-snapshot` (outside this inventory) | (PC1) |
| `backlog` | int | not emitted | **declared** (D6): the exact backlog frame count | no (new) |
| `resync_reason` | `ResyncReason` | not emitted | **declared** (D6): why a cursor start became a snapshot | no (new) |

## `stream-line` (`StreamLine`)

| Variant | JSON type | Today | Revision 7 | PC3 |
|---|---|---|---|---|
| event | bare `Event` (`contract/src/event.rs`), not wrapped | every line after the head (`cli.rs` `follow`, `output::emit_line`). A `resync_required` with `payload.subscription_ended: true` is the last line | same | no |
| error | `Envelope<ErrorData>` | at most one, last: a `Goodbye` or a lost connection (`transport_failure_envelope`) | same | no |

## `environment-status` (`EnvironmentStatusView`)

`heimdall environment status --json` (`heimdall/src/m06_cmd.rs:3179-3229`;
`app/src/remote_env.rs:877-898` `StatusReport` and `EnvironmentStatus`;
`app/src/remote_status.rs:183-211` `RemoteStatus`, built by `status_of` at `:263`).

| Field | JSON type | Today | Revision 7 | PC3 |
|---|---|---|---|---|
| `management` | string | present (`available` or a refusal reason) | present | no |
| `environments[]` | `EnvironmentStatusEntry` | present, by environment ID | present | no |
| `environments[]` record keys (`environment`, `destination`, `route`, `client`, `role`, `key_fingerprint`, `pinned_at`) | `RemoteEnvironmentPin`, flattened | present | present | no |
| `environments[].label` | string | omitted when unset (contract skip) | same | no |
| remote keys (`connectivity`, `remote_pending`, `issuance`) | `Connectivity`, `RemotePending[]`, enum | all omitted when the controller's state cannot be read (`m06_cmd.rs:3479-3510`), else present | same | no |
| `environments[].last_seen_at` | timestamp | omitted when never seen | same | no |
| `environments[].remote_pending_count` | int | not emitted | **declared** (ADR-0013 §6.4): the full count; `remote_pending` then holds at most the first 16 | no (new) |
| `environments[].last_known_readiness`, `.residuals`, `.cutoffs_fired_early`, `.issuance_failures` | arrays | omitted when empty (`remote_status.rs:183-211`) | same | no |
| `environments[].runner_view` | `{read, view?, code?, message?, reason?}` | omitted unless the command names one limited-role record (`m06_cmd.rs:2964-2979`, `:3212-3227`) | same | no |
| `environments[].runner_view.view` | `EnvironmentListView` (the runner's `inspect environments`) | present exactly when `read` is true | same | no |

## `grant-residual` (`GrantResidual`)

This is one entry of `environment status`' `residuals` (`app/src/remote_status.rs:126-138`).

| Field | JSON type | Today | Revision 7 | PC3 |
|---|---|---|---|---|
| `grant`, `acknowledged`, `statement` | string, bool, string | present. The statement comes from `app/src/remote_status_barrier.rs:165-178` | present, wording unchanged | no |
| `new_authentication` | `AuthenticationResidual` `{latest_possible_credential_expiry?, destination_clock_error}` | omitted when nothing counted is outstanding | same | no |

## `inspect-workspace.full` (`WithPreview<trust::WorkspaceView>`)

The subject's own view, typed elsewhere and flattened (its fields and their forms are its own
schema's), with `preview` beside it (ruled 2026-11-24, D1 question 5).

| Field | JSON type | Today | Revision 7 | PC3 |
|---|---|---|---|---|
| the view's own keys | as `trust::WorkspaceView` | as that type | unchanged | no |
| `preview` | `PreviewView` | added by `ops:10144-10149` when the request carries `preview`; absent otherwise | omitted without a preview | no |

## `inspect-policies.full` (`WithPreview<trust::PoliciesView>`)

The subject's own view, typed elsewhere and flattened (its fields and their forms are its own
schema's), with `preview` beside it (ruled 2026-11-24, D1 question 5).

| Field | JSON type | Today | Revision 7 | PC3 |
|---|---|---|---|---|
| the view's own keys | as `trust::PoliciesView` | as that type | unchanged | no |
| `preview` | `PreviewView` | added by `ops:10144-10149` when the request carries `preview`; absent otherwise | omitted without a preview | no |

## `inspect-issuer` (`WithPreview<issuer::IssuerStatus>`)

The subject's own view, typed elsewhere and flattened (its fields and their forms are its own
schema's), with `preview` beside it (ruled 2026-11-24, D1 question 5).

| Field | JSON type | Today | Revision 7 | PC3 |
|---|---|---|---|---|
| the view's own keys | as `issuer::IssuerStatus` | as that type | unchanged | no |
| `preview` | `PreviewView` | added by `ops:10144-10149` when the request carries `preview`; absent otherwise | omitted without a preview | no |

## `inspect-enrollments` (`WithPreview<enrollment::EnrollmentsView>`)

The subject's own view, typed elsewhere and flattened (its fields and their forms are its own
schema's), with `preview` beside it (ruled 2026-11-24, D1 question 5).

| Field | JSON type | Today | Revision 7 | PC3 |
|---|---|---|---|---|
| the view's own keys | as `enrollment::EnrollmentsView` | as that type | unchanged | no |
| `preview` | `PreviewView` | added by `ops:10144-10149` when the request carries `preview`; absent otherwise | omitted without a preview | no |

## `inspect-connections` (`WithPreview<managed::ConnectionsView>`)

The subject's own view, typed elsewhere and flattened (its fields and their forms are its own
schema's), with `preview` beside it (ruled 2026-11-24, D1 question 5).

| Field | JSON type | Today | Revision 7 | PC3 |
|---|---|---|---|---|
| the view's own keys | as `managed::ConnectionsView` | as that type | unchanged | no |
| `preview` | `PreviewView` | added by `ops:10144-10149` when the request carries `preview`; absent otherwise | omitted without a preview | no |

## Typed elsewhere, and untyped keys on top of them

These subjects are already typed, so they are not repeated here:

- `workspace` (`trust::WorkspaceView`)
- `policies` (`trust::PoliciesView`)
- `issuer` (`issuer::IssuerStatus`)
- `enrollments` (`enrollment::EnrollmentsView`)
- `connections` (`managed::ConnectionsView`)
- `export` (`project::PortableBundle`)
- the `items` of `environments` (`environment::EnvironmentsView`)

Untyped keys added on top of them today:

- **`preview`** is added to all of them except `export` (`ops:10144-10149`). Their types do
  not declare it; `WithPreview<T>` does (the five tables above).
- **`inspect environments`:** its M01 keys are typed here (`inspect-environments.full`).
- **`EnvironmentView`** (the remote row of `items`) still needs the declared
  `remote_pending_count`, which `environment.rs` owns.
- **`inspect policies` for a role that is not the owner** answers `{"items": []}`
  (`ops:10110`). This still reads as `PoliciesView`, whose `default_profiles` defaults to
  empty.

## Open questions (for the contract owner)

1. **`operation.result` withheld.** `observe` writes `null` for a succeeded binding result it
   withholds. Under the strict reading this becomes omitted, the same as "not terminal
   yet". `state: succeeded` still tells the two apart. If "withheld" should stay visible,
   the alternatives are a required-nullable `result` or a separate flag.
2. **`inspect projections` `record`.** The view treats `null` ("no projection committed")
   as not applicable, so it becomes omitted. D1 keeps the key, not its `null`.
3. **Verbatim nested `null`s.** These are kept, because they are persisted content or
   verbatim domain records:
   - `preview.delta.extra_window` and `preview.effective.policy_revision`;
   - the `null`s inside decision `request` bodies, such as `approve_authority`'s
     `delta.extra_window`.

   They need a ruling if D9 should reach inside them.
4. **The `inspect-environments` schema name.** This view is registered as
   `inspect-environments.full`. Either it supersedes today's `inspect-environments`, or
   `EnvironmentsView` gains M01's keys.
