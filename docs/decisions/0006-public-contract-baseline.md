# ADR-0006 — Public contract baseline (G08, as far as M01 needs it)

**Status:** proposed — **baseline, not frozen.** Freezing happens at G08 only after
the reference callers (M01-T06 CLI, A19/A32 fixtures) pass (plan §3 G08, spec §11.1).
**Date:** 2026-10-31 · **Gate:** G08 · **Task:** M01-T00-design
**Affects:** R-AP-01…R-AP-08, R-RT-03, R-RT-06, R-SE-05, R-SE-06, R-AU-06.
**Executable form:** `crates/contract` (types, code table, limits, schemas),
`crates/domain::lifecycle` (state machines), `crates/ipc` (transport); `schemas/
public-api/*.json` are generated from them by `heimdall schema export`.

Every rule below cites the spec section it implements. Names are the v0.1
proposals of spec §11.1 and `docs/contracts/primitives-draft.md`; semantics are
normative.

## 1. Scope and what "baseline" means

This ADR fixes enough of the G08 deliverables (plan §3 G08) for M01 to build
against: IPC authentication and framing, the envelope, state machines, the code and
exit-code tables, idempotency identity and retention, events and cursors, and schema
versioning. Command names, the exact field set of `inspect` subjects, and the
consumer-binding strategy (G05) remain open until G08 closes. A change to anything
in §2–§9 before the freeze needs a new revision of this ADR and updated fixtures
(plan §7.3 "contract changes need a recorded decision").

## 2. Local IPC (spec §13.2, §11.7; plan §3 G08 "IPC authentication design")

### 2.1 Endpoints and authentication

Two endpoints, never one (spec §13.2 "Exposing one must not implicitly expose the
others"; R-RT-03):

| | Control | Signing |
|---|---|---|
| Purpose | policy, preparation, inspection, lifecycle, events | already-authorized credential operations only |
| Protocol | §2.2 framing + §2.3 hello + `Request`/`ServerMessage` | SSH agent wire protocol, bounded, allow-listed (§2.6) |
| Unix path | `<runtime_dir>/control.sock` | `<runtime_dir>/signing.sock` (per-binding endpoints under `<runtime_dir>/<binding>/` from M02) |
| Windows name | `\\.\pipe\heimdall-<token>-control` | `\\.\pipe\heimdall-<token>-signing` |
| Who may connect | the runtime's own OS user | the runtime's own OS user |

**Unix.** The runtime directory (`$XDG_RUNTIME_DIR/heimdall/` when set, else under
the state dir) is created `0700`, owned by the runtime uid, and verified by `fstat`
after open (not by path). Sockets are bound under umask `077` (`0600`). A dead
socket of ours (connect → `ECONNREFUSED`, same uid owner) is unlinked before rebind;
never by glob. Each accepted connection's peer credentials are read with
`UnixStream::peer_cred()` (`getpeereid` on macOS, `SO_PEERCRED` on Linux) and must
equal the runtime uid (`ipc::endpoint::verify_peer`). Clients verify the socket's
directory is `0700` and theirs before connecting. Loopback TCP is not an
alternative (spec §13.2).

**Windows.** Named pipes created with `PIPE_REJECT_REMOTE_CLIENTS`,
`FILE_FLAG_FIRST_PIPE_INSTANCE` on the first instance, and a protected owner-only
DACL `D:P(A;;GA;;;<owner SID>)` (g03 §3.1 N2; the prototype's test pipes used exactly
this, REPORT.md §16). Per connection the server impersonates at identification
level, reads the client token's user SID, reverts, and requires equality with the
owner SID. Clients open with `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` so a
rogue server cannot impersonate them, classify the path into the `\\.\pipe\` /
`\\?\pipe\` namespace after `GetFullPathNameW` normalization, and require
`FILE_TYPE_PIPE` on the handle before any data is written (REPORT.md §16 remedies).
Pipe names carry an unpredictable token and no labels (names are visible to other
users). Administrators and SYSTEM are not defended against (spec §14.1).

**What peer identity means.** The OS principal, not an application (spec §13.2,
§4.2). PID, image path, `agent_name`, cwd and environment variables are metadata.
The runtime reports what it authenticated back to the client in `ServerHello.
principal`. Owner-channel actions (approve, pause, cutoff, unenroll) are therefore
available to any same-user caller; this is the disclosed non-guarantee decided for
primitives-draft Q1 (ADR-0004 context; spec §14.2).

### 2.2 Framing (R-SE-05)

`u32` big-endian length, then exactly that many bytes of one UTF-8 JSON object.
Limits are checked before allocation; violations close the connection:

| Limit | Value | Constant |
|---|---|---|
| hello frame | 16 KiB | `ipc::MAX_HELLO_FRAME_BYTES` |
| control frame | 1 MiB | `ipc::MAX_CONTROL_FRAME_BYTES` |
| signing (agent) message | 256 KiB | `ipc::MAX_SIGNING_FRAME_BYTES` |
| time to first frame | 5 s | `ipc::HELLO_TIMEOUT_MS` |

`ipc::frame::{encode_frame, decode_frame}` are pure and shared by server, client and
tests; the async path uses `tokio_util::codec::LengthDelimitedCodec` with the same
limits.

### 2.3 Hello and capability negotiation (spec §11.2, §15.2 "version mismatch is
negotiated by capability")

First frame each way. `ClientHello { protocol, schema_version, client, capabilities,
required }` → `ServerHello { protocol, schema_version, server, capabilities
(intersection), principal, environment_id }` or `Reject(Envelope<ErrorData>)`
followed by close. Rejection codes: `SCHEMA_UNSUPPORTED` for a protocol or schema
major mismatch or a `required` capability the server lacks; `USAGE_ERROR` for a
malformed hello. `ipc::session::negotiate` is the pure rule.

### 2.4 Capability names

`operations/1` (the six primitives), `events/1` (subscriptions and cursors),
`owner-policy/1` (pause/resume/cutoff/clear), `schema-discovery/1` (`inspect
capabilities` returns schema names and the code table; R-AP-08). A remote paired
client (G07) negotiates a subset; its role is carried in the caller context, never
inferred from the capability list.

### 2.5 Per-connection and per-endpoint limits (spec §11.5)

16 in-flight requests, 4 subscriptions, 256 buffered events per subscription, 64
connections per endpoint (`ipc` constants; overview §4 table). Excess requests get
`BACKPRESSURE` with `retry_after_ms`; a lagging subscriber gets one `ResyncRequired`
event and its backlog is dropped.

### 2.6 Signing endpoint protocol

SSH agent protocol only. Accepted message types: `SSH_AGENTC_REQUEST_IDENTITIES`
(11), `SSH_AGENTC_SIGN_REQUEST` (13), `SSH_AGENTC_EXTENSION` (27) with
`session-bind@openssh.com` only (spec S03). Everything else — add, remove, lock,
unlock, smartcard, other extensions — is `SSH_AGENT_FAILURE` without further parsing
(`ipc::signing::classify`). At most 64 identities are listed; idle connections close
after 30 s. The signer behind the endpoint (M03) rechecks grant state, deadline,
pause, cutoff and authority generation on every signature (spec §6.1, R-SE-07). In
M01 the endpoint answers an empty identity list and failure to everything else;
that already exercises the boundary and the peer check.

## 3. Common envelope (spec §11.2; primitives-draft §1)

```json
{"schema_version":"1","operation_id":"op_…","state":"succeeded","code":"ACCESS_READY",
 "data":{…},"warnings":[{"code":"…","message":"…"}],"next":{"action":"use_binding","binding_id":"binding_…"}}
```

* `schema_version` is the major only (§9). `operation_id` is present for effectful
  or long-running work and omitted for pure reads. `state` is an operation state
  (§4.1); synchronous reads report `succeeded`/`failed`. `code` is from §5.
  `warnings` is always an array. `next` is always materialized (`null` when nothing
  is expected); `NextAction.action` names are stable strings (`observe`,
  `use_binding`, `interact`, `owner_decision`, `narrow_request`, `new_work`,
  `review_host_trust`, `retry_after`, `change_client`, `new_request_id`,
  `review_config`, `resync`, `reconcile`, `fix_request`, `report`, `none`), with
  optional `operation_id`, `binding_id`, `decision_ref`, `retry_after_ms`, `cursor`.
* Errors: `data.error = { code, effect_status ∈ none|applied|partial|unknown,
  retryable, resource {kind,id}, next, message }` (spec §11.6). `retryable` never
  authorizes replaying a remote mutation; `OUTCOME_UNKNOWN` is never `retryable`.
* No private keys, passphrases or reusable approval secrets in any field; IDs are
  opaque references (spec §11.2). Human strings never contain terminal escape
  sequences; the CLI additionally strips them before printing.
* Timestamps are RFC 3339 with explicit offset (UTC on the wire from the runtime).

## 4. State machines (executable in `heimdall_domain::lifecycle`)

### 4.1 Operations (spec §11.4; primitives-draft §3)

| From | Event | To |
|---|---|---|
| queued | Start | running |
| queued | ApprovalNeeded | awaiting_approval |
| queued | Cancel | cancelled |
| queued | Fail | failed |
| running | ApprovalNeeded | awaiting_approval |
| running | Succeed | succeeded |
| running | Fail | failed |
| running | Cancel | cancelled |
| running | EffectUncertain | outcome_unknown |
| awaiting_approval | Approved | running |
| awaiting_approval | DecisionDenied | failed |
| awaiting_approval | Cancel | cancelled |
| outcome_unknown | ReconciledApplied | succeeded |
| outcome_unknown | ReconciledNotApplied | failed |

A caller timeout is not an event (spec §11.4). `cancel` on a terminal operation is
idempotent at the application layer (returns the terminal record, including whether
an irreversible or uncertain step may have occurred) and is not a transition.

### 4.2 Grants (spec §6.3, verbatim rows)

| From | Event | To |
|---|---|---|
| requested | Authorized / ApprovalNeeded / DecisionDenied / Cancel | preparing / awaiting_approval / denied / cancelled |
| awaiting_approval | Approved / DecisionDenied / Cancel / DeadlineReached | preparing / denied / cancelled / expired |
| preparing | Prepared / Degrade / PreparationFailed / Cancel / RevokeLocal / DeadlineReached | active / degraded / failed / cancelled / revoked / expired |
| active | Degrade / DeadlineReached / RevokeLocal / LastReferenceReleased | degraded / expired / revoking / released |
| degraded | Repaired / PreparationFailed / DeadlineReached / RevokeLocal / LastReferenceReleased | active / failed / expired / revoking / released |
| revoking | RevokeComplete | revoked |
| revoking | DeadlineReached | revoking (stays pending with explicit evidence) |
| revoked, expired, released, denied, cancelled, failed | any | invalid (terminal; a new operation creates new work) |

`LastReferenceReleased` is only emitted when the store's ownership-aware reference
count for the grant reaches zero (spec §6.3); references never retain a grant past
its deadline.

## 5. Stable code table (spec §11.6; `contract::Code`; `schemas/public-api/codes.json`)

| Code | Exit | Retryable | Default effect | Default next | Source |
|---|---|---|---|---|---|
| OK | 0 | — | applied | none | baseline |
| ACCESS_READY | 0 | — | applied | use_binding | spec §11.3 |
| ACCEPTED | 0 (async only, else 5) | — | none | observe | spec §11.6 |
| APPROVAL_REQUIRED | 3 | no | none | observe | spec |
| INTERACTION_REQUIRED | 3 | no | none | interact | spec |
| PROVIDER_LOCKED | 3 | yes | none | interact | spec |
| CAPABILITY_UNAVAILABLE | 4 | no | none | narrow_request | spec |
| POLICY_PAUSED | 4 | no | none | owner_decision | spec |
| POLICY_CUTOFF | 4 | no | none | owner_decision | spec |
| CREDENTIAL_EXPIRED | 4 | no | none | new_work | spec |
| HOST_TRUST_CHANGED | 4 | no | none | review_host_trust | spec |
| DELEGATION_EXCEEDS_PARENT | 4 | no | none | narrow_request | primitives Q3 |
| OPERATION_CANCELLED | 4 | no | partial | none | baseline |
| DESTINATION_UNREACHABLE | 5 | yes | none | retry_after | spec |
| TIME_UNCERTAIN | 5 | yes | none | retry_after | spec |
| UNSUPPORTED_CLIENT | 5 | no | none | change_client | spec |
| SERVICE_UNAVAILABLE | 5 | yes | none | retry_after | baseline |
| STATE_UNAVAILABLE | 5 | yes | none | retry_after | baseline (spec §13.3, §15.2) |
| BACKPRESSURE | 5 | yes | none | retry_after | baseline (spec §11.5) |
| REQUEST_CONFLICT | 6 | no | none | new_request_id | spec |
| CONFIG_CONFLICT | 6 | no | none | review_config | spec |
| REQUEST_EXPIRED | 6 | no | none | new_request_id | baseline (spec §11.4 retention) |
| RESYNC_REQUIRED | 6 | no | none | resync | primitives Q3 |
| OUTCOME_UNKNOWN | 7 | no | unknown | reconcile | spec |
| USAGE_ERROR | 2 | no | none | fix_request | baseline |
| SCHEMA_UNSUPPORTED | 2 | no | none | fix_request | baseline (spec §11.2) |
| NOT_FOUND | 2 | no | none | fix_request | baseline |
| INTERNAL_ERROR | 1 | no | none | report | baseline |

Placement decisions worth recording: `CAPABILITY_UNAVAILABLE` is exit 4 (a refusal
that an unchanged retry cannot fix), not 5; `PROVIDER_LOCKED` is exit 3 and
retryable (a human unlock fixes it); `UNSUPPORTED_CLIENT` is exit 5 ("unavailable
dependency"); `HOST_TRUST_CHANGED` is exit 4 with next `review_host_trust` (spec
§9.1 forbids silent acceptance). `DELEGATION_EXCEEDS_PARENT` and `RESYNC_REQUIRED`
adopt primitives-draft Q3; the other baseline codes are additions permitted by the
spec's "stable codes include" wording and need the G08 spec amendment to be listed
there.

## 6. CLI exit codes (spec §11.6; `contract::ExitCode`)

0 success · 1 internal · 2 usage/schema · 3 required interaction · 4
denied/paused/cutoff · 5 unavailable/transient dependency · 6 conflict · 7 uncertain
external outcome. `ACCEPTED` exits 0 only with `--async`; after a synchronous
bounded wait a still-pending operation exits 5 with `next.observe`. clap usage
errors exit 2. `heimdall run` exits with the child's status after launch; pre-launch
failures use this table and the structured side channel (spec §10.4; M02).

## 7. Idempotency (spec §11.4; primitives-draft §5; `domain::idempotency`)

### 7.1 Identity

`IdempotencyKey = (CallerContext { principal (OS uid/SID), role }, operation kind,
request_id)`. Keys are namespaced by principal, so the same `request_id` from a
different owner is a different key (spec §14.3 "request-ID collision across
owners", A29). `request_id` and `work_id` are bounded tokens (`[A-Za-z0-9._:-]`,
≤ 128 bytes).

### 7.2 Canonical request hash

SHA-256 over canonical JSON (keys sorted bytewise, no whitespace, serde_json number
and string forms; independent of any `preserve_order` feature), domain-separated by
`"heimdall-request-hash/1\0" || kind || "\0"`. Hashed fields (`HashInput`):
environment ID (resolved), profile reference and explicit revision if given, scope
subset as submitted, **deadline intent verbatim** (so a retry of `--for 2h` matches
even though the resolved instant differs), `work_id`, required capabilities, parent
binding, and kind-specific extras (e.g. the grant ID for `revoke`). Excluded on
purpose: `interaction`, `wait` (delivery preferences), the resolved deadline.

### 7.3 Outcomes

Same key + same hash → the existing operation and its current result (`Replay`).
Same key + different hash → `REQUEST_CONFLICT` naming the existing operation. No
record → new operation. Record past `expires_at` → `REQUEST_EXPIRED`, never silently
new (R-AP-03). The idempotency row and the operation row are inserted in one
transaction, before any external step.

### 7.4 Retention

Records persist across restarts (SQLite). Retention is `config.retention.
operations` (default 7 days after terminal state, floor 24 hours, spec §13.6 draft
default). Purge never touches tombstones, policy cutoffs or environment identity.
The contract to callers: a retry within 24 hours is always deduplicated; a retry
after the configured retention is `REQUEST_EXPIRED`.

## 8. Events and cursors (spec §11.5, §11.2; `contract::event`, `app::events`)

* `Event { schema_version, event_id, type, environment_id, operation_id?, resource?,
  timestamp, cursor, payload }`; `payload` is redacted before persistence.
* Delivery is at least once; consumers deduplicate by `event_id`. Ordering is
  claimed only within one environment (per-environment monotonic `seq`).
* **Cursor** = opaque `base64url(version || reader_tag || environment || seq)`;
  `reader_tag` is a hash of the authenticated caller context, so cursors are scoped
  to the reader. A cursor from another reader, with an unknown version, or below the
  retained tail yields `RESYNC_REQUIRED` with `next.resync`.
* **Snapshot** = `{ data, cursor, taken_at }`; the cursor is the boundary after which
  events are not reflected in `data`, so a reconnecting observer resumes without
  silently missing state.
* `observe events` without a cursor returns a snapshot plus its cursor; with a cursor
  returns up to `limit` (≤ `Limits::max_event_page` = 500) events after it. Live
  subscriptions buffer 256 events; overflow emits `ResyncRequired` and drops the
  backlog (bounded memory, R-RT-06).
* Retention: `config.retention.events` (default 7 days) or a row cap; expiry of a
  cursor is a normal condition, not an error of the caller.

## 9. Schema versioning (spec §11.2, §13.3; plan §4.5)

* `schema_version` carries the **major** only (`"1"`). Additive changes (new
  optional fields, new enum variants on `#[non_exhaustive]` enums, new codes, new
  capabilities) do not bump it. Removing or re-typing a field, changing a code's
  meaning, or changing hashing inputs bumps it.
* Readers tolerate unknown non-critical fields (serde default: unknown fields are
  ignored on every wire type). Security-sensitive configuration rejects unknown keys
  (`config.toml` uses `deny_unknown_fields`; spec §13.4).
* An unsupported major (`SchemaVersion::is_supported`) or an unsatisfied `required`
  capability is rejected explicitly with `SCHEMA_UNSUPPORTED`; an older client never
  reads a newer store or stream as empty.
* **Omitted vs `null` vs `unknown`.** Optional fields omitted on the wire mean "not
  applicable / not provided"; `null` is emitted only where the schema makes the
  field required-nullable (`next`); `unknown` is an explicit enum value where a fact
  may be undetermined (`Enforcement.*::Unknown`, `EffectStatus::Unknown`,
  `ResourceState::Unknown`) and is never conflated with `false` or absence.
* Generated schemas (`schemas/public-api/`) are an output of the Rust model, not a
  second source; `check.sh` diffs them once M01-T06 enables the step (plan §7.4).

## 10. Time rules referenced by the contract (spec §6.2, §6.4)

Deadline intents are absolute RFC 3339 with offset or durations; both are kept
verbatim and resolved once; the effective instant is UTC and immutable per grant;
`TIME_UNCERTAIN` stops issuance when rollback or skew exceeds tolerance. Details and
tolerances: `docs/architecture/overview.md` §5.

## 11. Consequences

* M01 units implement against `crates/contract` and `crates/domain::lifecycle`
  as-is; changing a table here is a contract change (new ADR revision + fixtures).
* A29 fixtures (malformed/oversized IPC and agent frames, foreign cursors,
  cross-owner request IDs, signing/control confusion) are specified by §2 and §7.
* The spec §11.6 list gains the baseline codes above at G08 (spec amendment).
* Third-party wrappers need only `heimdall-contract` + the §2 transport; no private
  database or TUI dependency (R-AP-07, A32).

## 12. Reopen conditions

A reference caller cannot complete A19/A32 with the six primitives; a native
Windows test contradicts §2.1; G05 changes the caller-context model (bound contexts
beyond OS principal); G07 needs a different capability set for remote clients; the
owner revisits primitives Q1.

## 13. Open questions for the orchestrator (authority semantics only)

1. **Role of same-user callers on owner-channel actions.** Q1 was decided "accept
   and disclose", so `Policy(Pause|Resume|Cutoff|ClearCutoff)` and `Revoke` of any
   grant are available to every same-user control connection. Confirm that `Resume`
   and `ClearCutoff` (which *widen*) are also same-user, or whether they must be
   TUI/CLI-interactive only (still same user, but never non-interactive). Baseline
   assumption: allowed from any same-user caller, refused when `--non-interactive`
   is set, because an agent in non-interactive mode must not lift a human-set stop.
2. **Release semantics for the last reference under an active grant.** When the last
   binding releases a grant, the baseline transitions the grant to `released`
   (spec §6.3 row) and lets its credentials lapse at their own validity; it does
   **not** revoke them locally. Confirm that `release` ≠ `revoke` holds even when the
   releasing caller is the only consumer (the alternative, auto-revoke on last
   release, changes the residual window reported by B1).
3. **Exit class of `CAPABILITY_UNAVAILABLE`** (4 vs 5) and of `NOT_FOUND` (2 vs 4):
   both are baseline choices in §5 with reasons; a different ruling is a one-line
   table change before any caller depends on it.

### 13.1 Orchestrator rulings (2026-10-31)

1. **Widening owner-channel actions** (`Policy(Resume)`, `Policy(ClearCutoff)`, and approving
   an `awaiting_approval` operation) require an attended interactive confirmation: a CLI or
   TUI session on a terminal with an explicit confirmation step. They are refused with
   `INTERACTION_REQUIRED` when `--non-interactive` is set and on every non-interactive API
   path. Narrowing actions (`Pause`, `Cutoff`, `Revoke`, `Release`) stay available to any
   same-user control connection. Disclosure (spec §14.2): a same-user process that controls a
   terminal can imitate the owner; this is a convenience boundary, not isolation.
2. **Release is never revoke**, including for the last reference. The grant becomes
   `released`; ADR-0005 destroys its working key, so local signing ends; any issued
   certificate stays counted in `latest_possible_credential_expiry` until its own validity
   ends.
3. **Exit classes as baselined:** `CAPABILITY_UNAVAILABLE` exits 4 (the requested minimum
   cannot be met by this mechanism; not a transient dependency), `NOT_FOUND` exits 2.
