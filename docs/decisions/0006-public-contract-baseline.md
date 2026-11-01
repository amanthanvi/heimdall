# ADR-0006 — Public contract baseline (G08, as far as M01 needs it)

**Status:** proposed — **baseline, not frozen.** Freezing happens at G08 only after
the reference callers (M01-T06 CLI, A19/A32 fixtures) pass (plan §3 G08, spec §11.1).
**Date:** 2026-10-31 · **Gate:** G08 · **Task:** M01-T00-design
**Revision 2 (2026-10-31, task M01-T00-design-fix):** applies the adversarial design
review (`tests/evidence/artifacts/review-m01-design/review.md`, F01–F10) and the
wave-1 escalations under the orchestrator's rulings. Every changed rule is marked
**⟨rev2⟩**; §14 is the change log. Revision 1 text that is not marked is unchanged.
**Revision 2.1 (2026-10-31, task M01-T00-review2-fix):** applies the round-2 design
review (`tests/evidence/artifacts/review-m01-design/round2/review.md`, N01–N06) under
the orchestrator's rulings (§13.4). Rules changed by it are marked **⟨r2.1⟩**.
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
primitives-draft Q1 (ADR-0004 context; spec §14.2). **⟨rev2⟩ ⟨r2.1⟩** Widening actions
additionally need a server-issued decision record completed by `Decide` on an
*attended* session after an explicit, action-specific client confirmation (§3.1);
attendance alone never executes them. That is a usability boundary against
non-interactive agents, not a security boundary against same-user code.

**⟨rev2⟩ Third endpoint: issuer** (ADR-0005 §3.1, §12; review F06). `EndpointKind::
Issuer`, `<runtime_dir>/issuer.sock` / `\\.\pipe\heimdall-<token>-issuer`, same
owner-only transport as the control endpoint, control-size frames. It is reachable
only by the runtime's own supervisor process(es): never materialized into a binding,
container, worker or forwarded endpoint (spec §7.3 "private authority/CA keys ...
excluded from project-access endpoints"). Its protocol is the issuance request of
ADR-0005 §3.5 and arrives in M03; the kind, path and non-exposure rule are fixed now.

**⟨rev2⟩ Unix bind mechanics as implemented (wave-1 E13).** The socket is created,
then `chmod 0600`, inside a directory verified `0700` and owned by the runtime uid
by `fstat` on an opened handle; this pair is the umask-equivalent the baseline
requires. Wave 1's `ControlConnection::with_server_identity` builder stays: the
runtime (U8) sets the environment ID and server `PeerInfo` once per listener.

**⟨rev2⟩ Windows client-side server check (wave-1 E14).** Before sending the hello,
a client reads the pipe's owner SID (`GetSecurityInfo` with
`OWNER_SECURITY_INFORMATION` on the client handle) and refuses unless it equals the
current user's SID (`ServerOwner::CurrentUser`) or, for a documented elevated
runtime, the configured expected SID (`ServerOwner::Sid`). `connect_with_owner` is
the production entry; `connect` without the check is test-only. Native proof plan:
`tests/native/windows-ipc/README.md` (same-user accepted; foreign-user pipe refused
is `blocked` on the disposable second Windows account, ADR-0004 §3). U6w's
connection-level remote rejection (`GetNamedPipeClientComputerNameW ==
ERROR_PIPE_LOCAL` in addition to `PIPE_REJECT_REMOTE_CLIENTS`) is accepted.

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
required, interaction }` → `ServerHello { protocol, schema_version, server,
capabilities (intersection), principal, environment_id }` or
`Reject(Envelope<ErrorData>)` followed by close. Rejection codes:
`SCHEMA_UNSUPPORTED` for a protocol or schema major mismatch or a `required`
capability outside the **negotiated** set (**⟨rev2⟩** F10: `required ⊆ offer ∩
capabilities`, so a hello cannot require what it did not offer to speak);
`USAGE_ERROR` for a malformed hello. `ipc::session::negotiate` is the pure rule.

**⟨rev2⟩ Session interaction and attendance.** `interaction` (`interactive` |
`non_interactive`, default non-interactive when omitted) is a property of the
session. A session that declared `interactive` may later send `Attend`; the runtime
then marks it **attended** and answers `OK {attended: true}`; on a
`non_interactive` session `Attend` is refused with `INTERACTION_REQUIRED`. Two
predicates split the attended-only surface (**second round R5**):
`Request::requires_attended_session()` = `decide` and `confirm_time`, refused
**before dispatch** on any session that is not attended, with
`INTERACTION_REQUIRED` and no decision record; and
`Request::is_widening_policy_action()` = `resume` and `clear_cutoff`, which **are**
dispatched on every session so the application can create a `WidenPolicy` decision
record (§3.1; creating a pending record grants nothing, mirroring
`APPROVAL_REQUIRED`). **⟨r2.1⟩ N04:** the application **always** creates the record,
on attended sessions too, and never executes a widening action on dispatch: it
answers `APPROVAL_REQUIRED` with `next.decision_ref` on an attended session and
`INTERACTION_REQUIRED` with `next.decision_ref` on an unattended one. Execution
happens only through `Decide approve` (§3.1). The application layer checks
attendance again. Attendance is never a request field, and it is a property of the
session, not a confirmation of any particular action.

### 2.4 Capability names

`operations/1` (the six primitives), `events/1` (subscriptions and cursors),
`owner-policy/1` (pause/resume/cutoff/clear), `schema-discovery/1` (`inspect
capabilities` returns schema names and the code table; R-AP-08), `service-control/1`
(⟨r2.3⟩ `Request::Shutdown`, §13.6 item 8). Shutdown is accepted only from the owner
principal. Without the negotiated capability it is refused with `SCHEMA_UNSUPPORTED`;
from a non-owner role it is refused with `CAPABILITY_UNAVAILABLE`. A remote paired
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

### 3.1 ⟨rev2⟩ Attended confirmation and decision records (review F03; ruling 3)

Added authority (spec §5.3), the widening policy actions `resume`/`clear_cutoff`
(spec §6.1) and the owner's time confirmation (ADR-0005 §3.6) are decided through
**server-issued decision records**, never through request content (R-SE-02, A29):

* The runtime creates `DecisionRecord { id (dec_…), kind, generation, created_at,
  expires_at, state }` (`heimdall_domain::decision`). `kind` carries the **exact**
  delta (`ApproveAuthority { operation, delta }`), the verbatim action
  (`WidenPolicy { action }`), or the observed time (`ConfirmTime { boot_id,
  observed_wall }`). `generation` is the authority generation at issuance.
* **⟨r2.1⟩ N04: every** added-authority request, `resume` and `clear_cutoff`
  creates a server-issued decision record carrying the exact delta or the verbatim
  action, **whatever the session's attendance**. The requesting result carries the
  nonsecret reference in `next.decision_ref`: `APPROVAL_REQUIRED` on an attended
  session, `INTERACTION_REQUIRED` on an unattended one. Nothing is executed on
  dispatch; the former "attended session executes directly / the session is the
  confirmation" path (second round R5) is **withdrawn**. `decide` and
  `confirm_time` never reach the application unattended (§2.3).
* Completion is **only** `Request::Decide { decision_id, verdict }`, accepted **only
  on an attended session** (§2.3); otherwise `INTERACTION_REQUIRED`. It is
  consume-once and generation-checked (`heimdall_domain::decision::complete`): a
  record that is not `pending`, has expired (default lifetime 15 min), or was issued
  under an older generation is refused with `DECISION_STALE`, even for `deny`.
  Approval applies exactly the recorded delta or action and resumes the waiting
  operation; nothing wider.
* **⟨r2.1⟩ Client confirmation contract (N04; binding on the CLI, M01-U9, and the
  later TUI).** Before sending `Decide approve` or `ConfirmTime`, the client fetches
  and displays the **exact** recorded action or delta (for `ConfirmTime`, the
  runtime's observed time) and requires an affirmative typed confirmation: `y` or
  `yes` (case-insensitive, surrounding whitespace ignored), **default No**. EOF,
  Ctrl-C, a prompt timeout, a non-TTY stdin, `--non-interactive`, an explicit `n`,
  or any other input sends **nothing**: the decision stays `pending` until it
  expires, and the CLI exits 3 with code `INTERACTION_REQUIRED`, `next.decision_ref`
  and a "not confirmed" message. A conforming client sends `Attend` only on an
  interactive TTY session, before an owner-present request: `access ensure`,
  `resume`, either direction of `cutoff`, `decision approve|deny`, or `time
  confirm` (§13.6 item 7). It never sends `Attend` with `--non-interactive` or on a
  non-TTY stdin, and never for narrowing-only actions. Attendance authorizes nothing
  by itself. **Disclosure:** the server cannot verify that the client
  prompted; a same-user program can send `Attend` and `Decide` itself (same-user
  imitation, below). The prompt is the owner workflow the contract requires of
  conforming clients, not a server-enforced boundary.
* `Request::ConfirmTime { observed_wall }` creates and consumes a `ConfirmTime`
  decision in one step on an attended session; it accepts the runtime's own clock
  for this boot when the owner's value agrees within tolerance; it never moves a
  deadline or rebuilds a budget (ADR-0005 §3.6).
* **Disclosed limit:** within the same OS user a program can drive the interactive
  flow (open an interactive session and send `Attend`). Attendance is therefore a
  boundary against non-interactive agents and paired clients, consistent with Q1
  "accept and disclose" and spec §14.2; it is not isolation from same-user code.

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

A caller timeout is not an event (spec §11.4). `cancel` on a settled operation is
idempotent at the application layer (returns the settled record, including whether
an irreversible or uncertain step may have occurred) and is not a transition.

**⟨rev2⟩ State classes (review F07; ruling 7).** *Active*: `queued`, `running`,
`awaiting_approval`. *Settled* (final): `succeeded`, `failed`, `cancelled`.
*Unresolved* (quiescent, not final): `outcome_unknown`. `OperationState::is_settled`
and `is_quiescent` replace the ambiguous `is_terminal`. Restart recovery re-drives
active operations from their stage receipts and lists unresolved ones
(`Txn::unresolved_operations`) for reconciliation through the recorded adapter
identity and effect token; a caller waiting for "stopped" waits for quiescence, a
caller needing truth about the effect waits for settlement. Retention purges settled
operations only; an unresolved operation, its recovery intent, receipts and
issuance entries are never purged.

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
| DECISION_STALE | 6 | no | none | fix_request | baseline rev. 2 (§3.1) |
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
there. **⟨rev2⟩** `DECISION_STALE` (exit 6) is added for §3.1. **⟨rev2⟩ Reader
fallback (wave-1 E4):** a reader that meets a code it does not know parses it as
`Code::Unknown(<string>)`: never success, exit 1, effect `unknown`, next `report`.
Writers only emit the table above, which is what the generated `code` schema
enumerates; readers accept any bounded `SCREAMING_SNAKE_CASE` token.

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

### 7.3 Outcomes ⟨rev2⟩

Same key + same hash → the existing operation and its current result (`Replay`).
Same key + different hash → `REQUEST_CONFLICT` naming the existing operation. No
record and no marker → new operation. Record past `expires_at`, **or no record but
an expired-key marker inside its window** → `REQUEST_EXPIRED`, never silently new
(R-AP-03; review F02). The idempotency row and the operation row are inserted in
one transaction, before any external step (`heimdall_domain::idempotency::
classify(record, marker, hash, now)`).

### 7.4 Retention and expired-key markers ⟨rev2⟩ (ruling 2)

* **Pending keys never expire.** `IdempotencyRecord.expires_at` is `None` while the
  operation is active or unresolved (`outcome_unknown`); a long-pending operation's
  retry always replays.
* **Retention starts at settlement.** At `succeeded`/`failed`/`cancelled` the
  record gets `expires_at = terminal_at + config.retention.operations` (default 7
  days, floor 24 hours; `Txn::settle_idempotency`).
* **Purge leaves a marker.** `purge_operations_before(now)` deletes settled
  operations and results past `expires_at` and writes `ExpiredKeyMarker {
  key_hash = SHA-256(canonical key), expired_at, marker_until = expired_at + 30
  days }` (`MARKER_WINDOW`). While the marker lives, reuse of the key is
  `REQUEST_EXPIRED`; `purge_markers_before` removes markers past `marker_until`.
* **Beyond the marker window** (default 37 days after settlement) reuse of a
  request ID is documented caller error: callers must mint fresh IDs per logical
  request; the runtime cannot distinguish a 38-day-old retry from new work.
* Purge never touches tombstones, policies, decisions, issuance entries, grant
  anchors, environment identity, or any unresolved operation and its receipts.

## 8. Events and cursors (spec §11.5, §11.2; `contract::event`, `app::events`)

* `Event { schema_version, event_id, type, environment_id, operation_id?, resource?,
  timestamp, cursor, payload }`; `payload` is redacted before persistence.
* Delivery is at least once; consumers deduplicate by `event_id`. Ordering is
  claimed only within one environment (per-environment monotonic `seq`).
* **Cursor** = opaque `base64url(version || reader_tag || environment || seq)`;
  `reader_tag` is a hash of the authenticated caller context, so cursors are scoped
  to the reader. A cursor from another reader, with an unknown version, or below the
  retained tail yields `RESYNC_REQUIRED` with `next.resync`. **⟨rev2⟩** The store
  keeps **neutral** sequences only (`Txn::stored_events_after`, `StoredEvent { seq,
  event }`); reader-scoped cursors are built **at delivery** by the application
  (`heimdall_app::events::cursor`) and, for live events, by the session through the
  `cursor_for` closure the dispatcher hands it (review F08).
* **Snapshot** = `{ data, cursor, taken_at }`; the cursor is the boundary after which
  events are not reflected in `data`, so a reconnecting observer resumes without
  silently missing state.
* **⟨rev2⟩ Subscription handshake** (review F08; ruling 8). The server creates the
  live receiver **first**, then in one store transaction reads the head sequence
  and either the retained backlog after the client's cursor or, when there is no
  usable cursor, a snapshot consistent with that head (`Txn::snapshot_boundary`).
  `Subscribed { cursor, snapshot? }` is followed by the backlog events (already
  cursor-personalized), then live events strictly after the boundary (`seq >
  boundary_seq`). **⟨r2.2⟩** `Subscribed.cursor` is that **head boundary**: with a
  snapshot, the snapshot's cursor; when resuming from a cursor, the position
  **after** the backlog (never the client's own cursor), so a consumer resumes from
  the cursor of the last event it processed until the backlog is consumed (gap
  G18; contract doc of `ServerMessage::Subscribed`; model test
  `subscribed_cursor_is_the_head_boundary_not_the_clients_cursor`). Live events
  are fanned out in strictly increasing `seq` order (gap G06;
  `EventPublisher::announce` fills any gap from the store): overlap is deduplicated server-side, so a client may still
  deduplicate by `event_id` but need not. Lag beyond the 256-event buffer emits one
  `ResyncRequired` carrying the **last delivered cursor** (second round R8) and
  drops the backlog (bounded memory, R-RT-06). The client API is
  `ControlClient::{subscribe, next_event, unsubscribe}`.
* `observe events` without a cursor returns a snapshot plus its cursor; with a cursor
  returns up to `limit` (≤ `Limits::max_event_page` = 500) events after it.
* Retention: `config.retention.events` (default 7 days) or a row cap; expiry of a
  cursor is a normal condition, not an error of the caller.
* **⟨r2.1⟩ Oversized events (N03).** An event whose frame exceeds
  `MAX_CONTROL_FRAME_BYTES` is never delivered. The session's internal
  `send_event` reports `Delivered | Replaced`; on `Replaced`, in the backlog path
  and in the live path alike, the subscription's position stays at the **last event
  actually delivered**, the server sends one `ResyncRequired` event carrying that
  cursor (payload `{"reason": "event_too_large", "subscription_ended": true}`), and
  then **ends the subscription** (no further events for its handle; a later
  `Unsubscribe` of it answers `NOT_FOUND`). The documented recovery is a **fresh
  snapshot**: subscribe again **without** a cursor. Resubscribing *from* the
  carried cursor replays the backlog after it, meets the same oversized event and
  gets `ResyncRequired` again; the cursor is carried so the consumer knows exactly
  what it last saw, not as a resume point past the gap. A lag resync (above) still
  carries the last delivered cursor and keeps the subscription.

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
  second source; `check.sh` diffs them (plan §7.4).
* **⟨rev2⟩ Unknown codes (wave-1 E4).** A newer peer may emit a code this reader
  does not know. Readers parse it as `Code::Unknown`, never as success, and exit 1;
  the schema enumerates only what the writer emits (§5).
* **⟨rev2⟩ Required envelope fields (wave-1 E5).** `warnings` and `next` are
  `required` in the generated envelope schemas (always emitted; `next` is
  required-nullable). Readers stay lenient and accept their omission.
* **⟨rev2⟩ Hello `interaction`** defaults to `non_interactive` when omitted (older
  clients cannot accidentally become attendable).

## 10. Time rules referenced by the contract ⟨rev2⟩ (spec §6.2, §6.4; ADR-0005 §3.6; review F01; ruling 1)

ADR-0005 §3.6 revision 3 governs; this contract implements it in
`heimdall_domain::time` (pure) and `heimdall_app::TimeGate` (the one shared gate):

* **Deadlines** are absolute RFC 3339 with offset or durations, kept verbatim,
  resolved once (`resolve_deadline`), persisted as immutable UTC instants. Nothing
  moves them later.
* **Clocks:** wall; a **boot-scoped continuous clock** that counts sleep (Linux
  `CLOCK_BOOTTIME`, macOS `mach_continuous_time`, Windows `QueryInterruptTime`);
  a **boot ID** (Linux `/proc/sys/kernel/random/boot_id`, macOS
  `kern.bootsessionuuid`, Windows the Session Manager `BootId` counter [I]); a
  **synchronization report** (`TimeSync`, platform stubs return `Unknown` [I] until
  M03/M04 evidence; `Unknown` fails closed).
* **Per-grant anchors** `GrantAnchor { boot_id, continuous, wall, bound,
  budget_end }` are persisted at activation or first validation in a boot;
  `budget_end = continuous + (bound − wall)`; budgets only shorten (`shorten`);
  they are never rebuilt from the wall clock. **⟨r2.1⟩ N01:** `shorten(current,
  new_bound)` reduces the **existing** budget by the bound reduction,
  `budget_end = current.budget_end − (current.bound − new_bound)` (saturating at
  zero, never longer than `current`); it never recomputes the budget from the raw
  anchor, so a tolerance deduction made at anchoring (R4) is preserved. **Admission** fails once the wall
  clock reaches the bound **or** the continuous budget runs out; an anchor from
  another boot is `NeedsAnchor` (fail closed, not an expiry) until re-anchored from
  a `Safe` observation with the same persisted bound.
* **The gate** (`gate(GateInput)`), consulted before every admission, signature and
  issuance, returns `TIME_UNCERTAIN` when: **within a boot** (a same-boot runtime
  anchor or attended confirmation exists) the wall clock is below the persisted
  **high-water mark** (latest accepted wall time, never lowered) by more than the
  rollback tolerance; within a boot, the wall clock disagrees with the continuous-clock
  prediction from the last accepted anchor **in either direction** (an implausible
  forward jump included) or the continuous clock went backwards; after a reboot (or
  at first start) the wall clock is not **both** at/above the high-water mark and
  reported synchronized, unless an attended owner confirmation covers this boot.
  **⟨r2.1⟩ N05:** the rollback tolerance applies **only within a boot**; after a
  reboot or at first start any wall time below the mark is `TIME_UNCERTAIN`
  (`BelowHighWater`) until an attended confirmation for this boot applies, and
  `accepted_tolerance` therefore never contains a rollback share for an acceptance
  without a same-boot reference.
  On `Safe` the gate persists the high-water mark (`max(mark, accepted wall)`) and
  the runtime anchor chosen by `next_runtime_anchor` (**second round R2**: within a
  boot the anchor is re-based only when the platform reports synchronized time, or
  when an attended confirmation installed it; otherwise the previous reference is
  kept, so drift accumulates and a frozen or slowly wrong wall clock reaches
  `TIME_UNCERTAIN` even when checked every 60 s or less; with the M01 platform
  stubs reporting `Unknown`, a long uptime may therefore reach `TIME_UNCERTAIN` and
  an attended `ConfirmTime` resolves it — intended fail-closed behaviour). On
  `Uncertain` nothing is persisted and no issuance, signature or admission happens.
* **Confirmation as reference (second round R3).** An accepted attended
  `ConfirmTime` installs a new runtime anchor for this boot (boot ID, continuous
  reading, confirmed wall); the gate predicts from the later of the runtime anchor
  and the confirmation, so a same-boot skew is cleared by confirmation (ADR-0005
  §3.6). Confirmation never moves a deadline or rebuilds a budget.
* **Tolerance-aware re-anchoring (second round R4).** When a grant is re-anchored
  from an observation accepted within a tolerance (`accepted_tolerance`: the
  rollback tolerance when below the mark within a boot, plus the skew tolerance when
  accepted through a same-boot prediction or confirmation), `budget_end = continuous +
  (bound − (wall + tolerance))` (`anchor_grant_with_tolerance`): the grant may end
  up to the tolerance early, never late, and the result is `min()`'d with any
  existing same-boot budget.
* **Same-boot restart** resumes from the persisted anchors (continuous time is
  boot-scoped). **Reboot** voids anchors; new ones are created only from an accepted
  wall time. **Attended confirmation** (§3.1 `ConfirmTime`) accepts the current
  observation for this boot without moving any deadline or budget.
* Tolerances (`TimePolicy`): rollback 5 s, skew 60 s in M01; G09 sets the final
  values.

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

Resolved in revision 2: (1) widening owner actions need an attended session —
ruled and specified in §3.1; (3) exit classes stay as tabled (no contrary ruling).

1. **Release semantics for the last reference under an active grant** (unchanged
   question, now with ADR-0005 context). The baseline keeps `release ≠ revoke`: the
   last release moves the grant to `released`, and ADR-0005 §3.6 "at grant end
   (… release of the last reference) the signer destroys the grant's K_env" then
   destroys the working key locally, so no new signature is possible from this
   environment, while already-issued certificates stay counted in the residual
   until `valid_before`. Confirm this reading (release destroys the key but writes
   no tombstone and does not cascade to descendants) — or rule that the last
   release is a local revocation (tombstone + cascade), which changes A28 and the
   residual report.
2. **Attended confirmation by paired clients (G07).** §3.1 forbids `Attend` on
   non-interactive sessions and ADR-0005 §3.6 forbids time confirmation by "an agent
   or a paired client". Baseline: a paired remote client can never be attended, even
   if its user is at a terminal on the runner; only the runner's local CLI/TUI can.
   Confirm, or allow the controller's attended session to confirm time for a paired
   runner over the authenticated channel (would need G07 design).
3. **Decision lifetime and re-request.** Baseline: a pending decision expires after
   15 minutes; the waiting operation then fails with `APPROVAL_REQUIRED` state
   `failed`? — no: baseline keeps the operation `awaiting_approval` and issues a
   **new** decision record on the next retry of the same request (same idempotency
   key replays the operation; a fresh `decision_ref` is returned). Confirm that an
   expired decision does not fail the operation.

### 13.2 Second-round rulings (orchestrator, under the owner's delegation; applied)

(The first-round rulings are §13.1, at the end of this document.)

| # | Ruling | Applied where |
|---|---|---|
| R1 | Envelope schema: `warnings` and `next` are `required` via a container transform; `next` stays `NextAction \| null` (no `#[schemars(required)]`) | §9; `contract::envelope::require_warnings_and_next`; `schemas/public-api` re-exported |
| R2 | Within a boot a `Safe` pass re-bases the runtime anchor only on synchronized time or an attended confirmation; the high-water mark still advances every `Safe` pass; long unsynchronized uptime may reach `TIME_UNCERTAIN` (fail closed), resolved by attended `ConfirmTime` | §10; `domain::time::next_runtime_anchor`; `app::TimeGate` docs; model test `frozen_wall_checked_every_thirty_seconds_becomes_uncertain` |
| R3 | An accepted attended `ConfirmTime` installs a new runtime anchor for this boot; same-boot skew is cleared by confirmation; deadlines and budgets untouched | §10; `domain::time::gate` prediction reference (later of anchor and confirmation); model test `same_boot_skew_is_cleared_by_attended_confirmation_without_moving_anything` |
| R4 | A re-anchor from an observation accepted within a tolerance cuts the budget by that tolerance (early, never late), `min()`'d with any same-boot budget | §10; `domain::time::{accepted_tolerance, anchor_grant_with_tolerance}`; `app::SafeNow.tolerance_used`; model test `reanchor_accepted_within_tolerance_ends_early_never_late` and property `no_admission_after_true_bound_with_reboot_and_confirmation` |
| R5 | Split the attended predicate: `requires_attended_session` (decide, confirm_time; refused before dispatch, no record) vs `is_widening_policy_action` (resume, clear_cutoff; dispatched; app creates a `WidenPolicy` decision ~~or executes on an attended session~~). **⟨r2.1⟩ Superseded in part by N04 (§13.4):** the app always creates the record and never executes on dispatch; attended ⇒ `APPROVAL_REQUIRED`, unattended ⇒ `INTERACTION_REQUIRED` | §2.3, §3.1; `contract::request`; `ipc::session` gate and tests; U5 note in `m01-plan.md` |
| R6 | Pipe SDDL carries an explicit owner `O:<current user SID>` so `ServerOwner::CurrentUser` holds for elevated runtimes; `ServerOwner::Sid` kept; re-run natively on the Windows PC; cross-user case stays `blocked`. **Observed natively:** the first rerun (`…/u6w-native/r6-owner-sddl`, exit 101) showed Windows refuses any owner the creating process does not hold (`ERROR_INVALID_OWNER` 1307), so the descriptor's owner is always the creating process's own SID and the DACL grantee is a separate argument (`owner_only_sddl(owner, grantee)`); the second rerun (`…/u6w-native/r6-owner-sddl-2`) passed: `windows::` 14/14, all four test binaries exit 0, canary scan 0, run exit 0 | §2.1; `ipc::windows::{owner_only_sddl, create_instance}`; `tests/evidence/artifacts/m01/u6w-native/r6-owner-sddl{,-2}/` |
| R7 | Store semantic choices 1–8 accepted (NULL expiry for unsettled v1 keys; v1 time anchor dropped and its wall seeds the mark; first settlement wins; `NotOwner` checked first; snapshots immutable; recovery intent add-only; `Destroyed` terminal; FKs; `denied_ancestor` cycle ⇒ `Corrupt`); the application checks `marker_until`, `boot_id` and decision expiry itself | §14.3; U5 note in `m01-plan.md` |
| R8 | `handle_owner_sid` added to the unsafe inventory; `decision` added to the `ResourceRef` kinds; `ResyncRequired` carrying the last delivered cursor accepted | `overview.md` §9; §3 `ResourceRef`; §8 |

### 13.3 Third-round rulings on the §13 questions (orchestrator, 2026-10-31)

1. **Last-reference release (question 1):** already ruled in §13.1 item 2. Release is never
   revoke: no tombstone, no cascade. The working key is destroyed locally, and issued
   certificates stay in the residual until `valid_before`.
2. **Paired clients and attendance (question 2):** the baseline is confirmed for V1 M01–M05.
   A paired remote client is never attended, and only the runner's local CLI/TUI can
   attend or confirm time. G07 may propose controller-side attendance over the
   authenticated channel, but only in a new ADR that adds threat-model rows. Until then
   the fail-closed baseline stands.
3. **Decision expiry (question 3):** the baseline is confirmed. An expired decision is
   `DECISION_STALE` and does not fail the operation. The operation stays
   `awaiting_approval`, and a retry under the same idempotency key returns a fresh
   `decision_ref`. Spec §6.3 governs the grant: an `awaiting_approval` grant becomes
   `expired` when its absolute deadline passes. The waiting operation then fails with
   `CREDENTIAL_EXPIRED`, so nothing waits past its deadline (spec §11.3 "does not hang
   invisibly").
4. **Skew share on synchronized acceptances (R4 follow-up):** kept as implemented. When
   the platform reports synchronization, the time is accepted without a skew deduction.
   Unsynchronized acceptances and rollback acceptances deduct their tolerance.
   **⟨r2.1⟩ N05 (rewritten):** that a `Synchronized` report is truthful is an
   **ASSUMPTION**, not a property of the threat model. It needs native evidence per
   platform (M04, G09: which signal is trustworthy and how it fails), and ADR-0005's
   reopen condition for a signal that reports synchronized while wrong under
   accidental faults stands unchanged. Until that evidence exists, the M01 platform
   stubs report `Unknown` and fail closed.

### 13.4 ⟨r2.1⟩ Round-2 review rulings (orchestrator, under the owner's delegation; applied)

Source: `tests/evidence/artifacts/review-m01-design/round2/review.md`. The
orchestrator verified N01 and N05 against the code before ruling.

| # | Ruling | Applied where |
|---|---|---|
| N01 | `shorten(current, new_bound)` reduces the existing budget by the bound reduction (`budget_end − (bound − new_bound)`, saturating, never longer); never recomputed from the raw anchor | §10; `domain::time::shorten`; model test `shorten_preserves_tolerance_margin_reviewer_counterexample` and the true-bound property (now with `Cutoff` steps) in `tests/model/time.rs` |
| N02 | `issuance::check` enforces the whole ADR-0005 §3.5 refusal list plus the §3.6 deadline, at reserve **and** at publish: continuous admission (`IssuanceCheck.admission`; refusal `BudgetExpired`; `NeedsAnchor` ⇒ `TimeUncertain`); the exact principal `hm:<destination-id>:<account>` (`WrongPrincipal`; `issuance::principal_for`); extensions ⊆ the grant's permissions (`UnpermittedExtension`; `permit-X11-forwarding` never, `permit-agent-forwarding` only with the `agent-forwarding` capability); expected policy revision = current (`StalePolicyRevision`); recorded parent supplied and its chain complete (`AncestorMissing`); every ancestor issuable (`AncestorDenied`) and at the current generation (`StaleAncestor`); every earlier check | §14.2; `domain::issuance::{IssuanceCheck, IssuanceRefusal, check, principal_for}`; unit tests in `crates/domain/src/issuance.rs` (one refusal per predicate; reserve/publish interleavings through the production predicate); store-backed A07 interleavings remain U5's |
| N03 | `send_event` returns `Delivered \| Replaced`; on `Replaced` (backlog and live) the cursor stays at the last delivered event, the server sends `ResyncRequired` carrying it and ends the subscription; recovery is a fresh snapshot (subscribe without a cursor) | §8; `ipc::session::{send_event, start_subscription}` and the live loop; tests `oversized_*` in `tests/integration/ipc_unix.rs` |
| N04 | `resume`, `clear_cutoff` and added authority always create a server-issued decision record (attended ⇒ `APPROVAL_REQUIRED`, unattended ⇒ `INTERACTION_REQUIRED`, both with `next.decision_ref`); completion only by `Decide` on an attended session; the "session is the confirmation" path is withdrawn; client confirmation contract (typed `y`/`yes`, default No; EOF, Ctrl-C, timeout, non-TTY, `--non-interactive` or other input ⇒ nothing sent, exit 3 `INTERACTION_REQUIRED` "not confirmed"); the server cannot verify client prompting (disclosed) | §2.1, §2.3, §3.1; R5 row in §13.2 annotated; `ipc::session` docs and tests; `app::context` docs; `m01-plan.md` U5 and U9 |
| N05 | After a reboot or at first start (no same-boot reference) `gate` is `Safe` only if wall ≥ mark **and** `Synchronized`, unless an attended confirmation for this boot applies; the rollback tolerance applies only within a boot; `accepted_tolerance` has no rollback share without a same-boot reference; truthful `Synchronized` is an ASSUMPTION needing native evidence (M04/G09) and ADR-0005's reopen condition stands | §10, §13.3 item 4; `domain::time::{gate, accepted_tolerance}`; model test `reboot_synchronized_slightly_below_mark_is_uncertain_until_confirmed` (replaces the 4 s-below acceptance) |
| N06 | Exit evidence: U8 A17-local generation-N cleanup racing N+1 at the deletion boundary, and repeated unavailable-provider failures under one bounded supervisor; service-death A06 through a durable fake effect ledger (`FakeCredentialAdapter::with_ledger`), killing the service by exact PID and restarting it (U9/U10), with in-process reconstruction labelled as such; "kill the service while the caller waits; replace the socket" (U9/U10); U5 pending-approval deadline expiry (`CREDENTIAL_EXPIRED`) and expired decision (`DECISION_STALE`, operation stays `awaiting_approval`) | `m01-plan.md` U5, U8, U9, U10; `testkit::FakeCredentialAdapter::{with_ledger, ledger_entries}` and their unit tests |

### 13.5 ⟨r2.2⟩ Rulings on the N02 implementation questions (orchestrator, 2026-10-31)

1. **Ancestor states.** The fail-closed reading stands: every ancestor must be
   issuable (`preparing`, `active` or `degraded`). A `released` or `expired` parent
   ends issuance for its descendants. Delegated authority never outlives its parent's
   live authority (spec §6.2 intersection).

   Releasing a parent writes no tombstone and revokes nothing (§13.1 item 2), so a
   child stopping silently would surprise the owner. To prevent that, `delegate` takes
   an ownership-aware reference on the parent (spec §6.3 "reference counts are
   ownership-aware"), owned by the child grant. The reference is released when the
   child reaches a terminal state. Consumers releasing the parent therefore cannot
   move it to `released` while a live child depends on it, and the parent's deadline
   still bounds the child.
2. **Generation checks along the chain.** The authority generation is one global
   counter. The predicate therefore compares the generation at which each grant and
   ancestor was **last validated** with the current one.

   On a mismatch, the application re-validates automatically before reserving. It
   re-runs authority resolution against the current policy, cutoffs and tombstones,
   with unchanged scope and deadline, no widening and no prompt (spec §5.5 silent
   repair within saved authority). It then records the new validated generation, or
   denies. Reserve and publish must observe the same generation.

   An unrelated revoke therefore costs one re-validation and never fails healthy work.
   A revoke, or a cutoff that has passed, on the chain fails it. A pause on the chain
   blocks only new activations and new work bindings (§13.6 item 1, amending the
   earlier wording "a revoke, pause or cutoff"). Per-grant generations are a possible
   later optimisation, with no change of semantics.
3. **`permitted_extensions`.** The caller supplies it from the grant's resolved
   scope, its snapshot capabilities, and never from request fields. M03 replaces this
   source with the ADR-0005 §3.4 profile/route derivation.

### 13.6 ⟨r2.3⟩ Rulings on the wave-2 escalations (orchestrator, 2026-11-01)

Source: the wave-2 completeness critic (G01–G18) and gap-fix and integrator
escalations, workflow `wf_11ee3572-cd2` (summary in `progress.md`).

1. **Pause versus cutoff versus revoke for existing work** (corrects the gap-fix
   reading of §13.5 ruling 2). Spec §5.6 says "Pausing a saved policy prevents future
   automatic activations; it need not terminate existing work unless requested", and
   ADR-0005 §3.5 and §6.1 say "a pause blocks new activations only".
   * A pause refuses new grants and new work bindings under the paused policy with
     `POLICY_PAUSED` (exit 4). This includes fresh request or work identifiers
     (R-AU-02).
   * Running grants and their existing bindings continue until their deadlines:
     signing, and renewal or issuance within the existing grant (ADR-0005 §3.7).
     They stop only if the owner revokes or stops them.
   * A same-key replay of an existing binding returns its recorded result.
   * Re-validation (§13.5 ruling 2) under a pause therefore passes for continuing
     work. It never maps a pause to `CREDENTIAL_EXPIRED`.
   * A cutoff bounds every applicable grant at `min(deadline, cutoff)` (N01 shorten).
     Using an existing grant past that bound gives `CREDENTIAL_EXPIRED`. A new
     activation or new binding at or after the cutoff gives `POLICY_CUTOFF`.
   * A revoke on the chain denies, with the code-table mapping for revoked access.
2. **Pending decisions after an unrelated generation change.** Strict, as
   implemented. A decision issued under an older generation answers
   `DECISION_STALE`, and the waiting operation stays `awaiting_approval` after
   re-validation. A same-key retry returns a fresh `decision_ref` whose delta is
   recomputed against current policy. The rewritten
   `model_revocation::a07_a_pending_approval_cannot_complete_after_a_revoke` is
   accepted. The UX cost is revisited with evidence in M07.
3. **Child-owned parent reference** (amends §13.5 ruling 1). The reference is also
   released when the child enters `revoking`, which can only lead to `revoked`, so a
   dying child never keeps its parent alive.
4. **N06 evidence scope for M01.**
   * The supervisor's single cleanup executor is proven in-process with a fake
     `ResourceCleaner`. That meets the M01 exit ("no external side effects needed to
     verify core semantics", plan §5 M01). The real executor with a real adapter is
     M02 exit evidence.
   * A caller's operation whose `prepare` reports `Unavailable` is answered once
     with `SERVICE_UNAVAILABLE` (exit 5) and is not retried automatically: the
     caller retries with the same key.
   * Supervisor-owned repair and cleanup retries are bounded and **jittered**. Spec
     §13.5 says "bounded backoff and jitter". The jitter source is injectable and
     deterministic in tests.
5. **Several applicable policies.**
   * The fail-closed merge stays: the earliest cutoff and any pause across all
     policies that apply to the profile and environment. The store gets no
     one-policy-per-pair constraint, because separate workspace policy records are
     legitimate (spec §13.4).
   * Any change to an applicable policy (pause, cutoff, narrowing, revision) moves
     the authority generation, so re-validation runs.
   * Test: a pause or cutoff on a second applicable policy between reserve and
     publish voids the publish, and blocks new activations.
6. **Cutoff direction and time.**
   * Moving a cutoff **later**, or clearing it, is a widening action: decision
     record, attended `Decide` (§3.1, N04). An equal or earlier cutoff is narrowing.
     This amends the action list in §13.1 item 1.
   * Widening actions are refused with `TIME_UNCERTAIN` while time is uncertain.
   * Narrowing actions (pause, earlier cutoff, revoke, release) are never blocked by
     time.
7. **CLI attendance order (G15).** On an interactive TTY session about to run an
   owner-present action:
   * the CLI sends `Attend` **before** the request, so the server answers
     `APPROVAL_REQUIRED` with `next.decision_ref`;
   * the CLI then shows the exact recorded action or delta and asks for the typed
     confirmation;
   * on `y`/`yes` it sends `Decide`; on anything else it sends nothing more and
     exits 3.

   Attendance authorizes nothing by itself (N04). This matches m01-plan.md U9.
8. **Service stop on every platform (G09).** Add the owner-channel request
   `Request::Shutdown`, under the capability `service-control/1`:
   * accepted only from the owner principal on the control endpoint, never from a
     limited consumer, on any session;
   * idempotent, with a graceful drain;
   * `heimdall service stop` uses it on Unix and Windows; Unix signals remain the
     fallback.
   * Stopping the service is an availability action, not a widening of authority.
     A same-user process could end the process anyway (disclosed with §3.1).
   * The Windows variants of the runtime tests run natively on the Windows PC:
     second start, stale `instance.json`, the launcher's single child, and a control
     round trip over the named pipe.
9. **Linux host vps1-edge.** Tailscale SSH policy on the owner's tailnet refuses the
   configured user, so runs on that host are `blocked` on that owner setting. Changing
   access to a live server is outside the delegation (ADR-0004 §5). The Linux x86-64
   rows use the other host.
10. **Readings from the §13.6 fix round, confirmed** (2026-11-01):
    * A request still waiting for added authority counts as a new grant under a
      pause. A same-key retry answers `POLICY_PAUSED` (exit 4), the operation stays
      `awaiting_approval`, and no fresh decision record is issued until the pause is
      lifted. A cutoff that passes while it waits ends it with `CREDENTIAL_EXPIRED`.
    * `choose_policy` pins the first applicable policy by ID. Blocks come from the
      merged view of every applicable policy. Inserting a policy record also moves
      the generation.
11. **A publish voided only by an unrelated generation move** (the grant and its
    chain are still valid). Reporting `CREDENTIAL_EXPIRED` for it is misleading. The
    application re-validates and re-reserves automatically, at most 3 attempts within
    the same call. If the generation is still racing after that, the answer is
    `SERVICE_UNAVAILABLE` (exit 5, retryable) with a retry `next`. If re-validation
    fails, the answer is that denial's own code. The code table is unchanged.

## 14. ⟨rev2⟩ Change log and substrate added by revision 2

### 14.1 Recovery intent and stage receipts (review F05; ruling 5)

Before any external effect an operation persists `RecoveryIntent { request
(redacted original), resolved: ResolvedIntent { profile, profile_revision, scope,
deadline, policy_revision, generation, grant?, binding?, adapter } }`
(`Txn::set_recovery_intent`) and, as each `EnsureStage` durably completes, an
append-only `StageReceipt { stage, recorded_at, effect }` with `EffectReceipt ∈
{ NotAttempted, Attempted { adapter, effect_token }, Confirmed { adapter,
credential_ref }, Uncertain { adapter, effect_token } }`. The application mints the
`effect_token`, writes `Attempted`, then calls `CredentialAdapter::prepare(…,
effect_token)`; after a crash or lost reply it calls `reconcile(grant,
effect_token)` on the **same** adapter identity and never `prepare` again until the
outcome is `NotApplied`. **A request hash or a stage name is never an effect
receipt.** Retries and restarts resume from the persisted `ResolvedIntent` (same
snapshot, same deadline), never from re-resolution.

### 14.2 Issuance substrate (ADR-0005 §3.5, §12; review F06; ruling 6)

Pure records in `heimdall_domain::issuance`: `IssuanceEntry { id (iss_…), grant,
generation, pair, bounds: CertificateBounds { serial, key_id, principal,
valid_after, valid_before, extensions, subject_fingerprint }, state ∈ reserved |
published | voided, reserved_at, settled_at, void_reason }`, `CredentialInstance {
id (cred_…), grant, key_handle_ref, certificates, state }`, the refusal list
`IssuanceRefusal` and the predicate function `check(IssuanceCheck)` applied
identically at reserve and at publish (with the then-current store and the time
gate), and `residual(entries)` = latest `valid_before` over `reserved ∪ published`.
**⟨r2.1⟩ N02:** the caller builds `IssuanceCheck` inside the reserve and again inside
the publish transaction from current state: grant, recorded parent and the further
ancestor chain (`parent`, `ancestors`), applicable policy and the
`expected_policy_revision` pinned in the grant's `ResolvedIntent`, current
generation, tombstone flag, `permitted_extensions` for the pair (ADR-0005 §3.4
profile), and **time evidence**: the gate's `TimeStatus` plus
`admission = time::admission(&grant_anchor, &observation)` from the **same**
observation. `check` refuses with the first failing predicate; at publish a refusal
means `void_issuance(reason)`, never publication.
Transactional store methods: `reserve_issuance`, `publish_issuance` (CAS reserved →
published), `void_issuance` (CAS reserved → voided), `issuance_entries`,
`issuance_residual`, `insert/update/credential_instance`. Revocation, cutoff and
pause write their tombstone/generation in single transactions and therefore
serialize with reserve and publish. A `reserved` entry found after a restart stays
counted until its `valid_before` and is never published; recovery reserves afresh.
Cryptography and the issuer wire protocol are M03.

### 14.3 Store contract completed for the operations (review F04; ruling 4)

`heimdall_store::Txn` gains (all in `crates/store/src/ext.rs`): bindings with owner
principal and pinned profile revision (`insert_binding`, `binding`,
`bindings_for_work`, `release_binding` → `Released { remaining_references } |
AlreadyReleased | NotOwner`, `grant_references`); profiles and immutable snapshots
(`upsert_profile`, `profile`, `profile_snapshot`); environments
(`upsert_environment`, `environment`); applicable policies (`policies_for(profile,
environment)`); denial reads (`tombstone`, `denied_ancestor`); decisions
(`insert_decision`, `decision`, `complete_decision`, `pending_decisions`); time
(`high_water_mark`, `raise_high_water_mark`, `runtime_anchor`,
`set_runtime_anchor`, `grant_anchor`, `set_grant_anchor`, `time_confirmation`,
`set_time_confirmation`); idempotency (`settle_idempotency`, `expired_key_marker`,
`purge_markers_before`); recovery (`set_recovery_intent`, `recovery_intent`,
`append_stage_receipt`, `stage_receipts`); issuance (§14.2); `unresolved_operations`;
neutral events (`stored_events_after`, `snapshot_boundary`). Repeat release is
idempotent success; a foreign principal without the owner role gets `NotOwner`.

### 14.4 U2's fail-closed readings (wave-1 E7), confirmed

The authority resolver's documented readings (`crates/domain/src/authority.rs`,
`resolve_authority` doc) are confirmed as this baseline's interpretation of spec
§6.2: (a) pause/cutoff of the supplied policy denies before anything else, even
when the policy names another profile; (b) an unusable parent (not active/degraded,
stale generation, or past deadline) denies; (c) broader/longer delegation is denied,
never escalated; (d) caller minimums are checked against the requested scope and
known destination capability, and `Unknown` never satisfies a minimum; (e)
`covered` is empty when no policy names the profile, the environment is outside the
policy, or the environment lacks `automatic_activation`; (f) the delta is the exact
component-wise difference; (g) a `LimitedConsumer` with a non-empty delta is
`RoleForbidden`; (h) a requested deadline at or before `now` is never moved later —
revision 2 adds `Denial::DeadlinePassed` for it, mapped to `CREDENTIAL_EXPIRED`
(wave-1 E8). None contradicts spec §6.2 ("explicit deny and pause override allow";
"options may narrow or request authority; they cannot grant new authority").

### 14.5 Change log (file → rule)

| Ruling / escalation | Where |
|---|---|
| 1 time model | §10; `domain::time` (Clock/BootId/TimeAnchor/GateInput/gate/GrantAnchor/admission), `app::TimeGate`, `runtime::platform`, store time methods |
| 2 idempotency markers | §7.3–7.4; `domain::idempotency` (`expires_at: Option`, `ExpiredKeyMarker`, `MARKER_WINDOW`), store settle/marker methods |
| 3 attended confirmation | §2.3, §3.1; `contract::request::{Verdict, DecideRequest, ConfirmTimeRequest, Request::{Decide, ConfirmTime}, requires_attended_session}`, `contract::ipc::{ClientHello.interaction, ClientMessage::Attend}`, `Code::DecisionStale`, `domain::decision`, `app::context::{Caller, Attendance}`, `Operations::{attend, decide, confirm_time}` |
| 4 store completeness | §14.3; `domain::binding`, `store::ext` |
| 5 recovery | §14.1; `domain::operation::{RecoveryIntent, ResolvedIntent, StageReceipt, EffectReceipt, AdapterIdentity}`, `ports::CredentialAdapter::reconcile`, `PrepareRequest.effect_token` |
| 6 issuance substrate | §2.1 issuer endpoint, §14.2; `domain::issuance`, `ipc::EndpointKind::Issuer`, store issuance methods |
| 7 OutcomeUnknown | §4.1; `OperationState::{is_settled, is_quiescent, is_unresolved}`, `Txn::unresolved_operations`, purge rules |
| 8 events | §8; `app::events::{SequencedEvent, SubscriptionStart, CursorBuilder}`, `ipc::session::{SubscriptionStart, LiveEvent}`, `Subscribed.snapshot`, store neutral sequences |
| 9 harness | `m01-plan.md` §0 convention (`[[test]]` targets under root `tests/`), `OperationsConfig.stage_hook`, `check.sh` zero-test detection |
| 10 hello | §2.3 |
| E2 | `heimdall-testkit` features `store`/`app`; ipc dev-deps |
| E3 | `serde_json` `float_roundtrip` |
| E4 | §5, §9 `Code::Unknown` |
| E5 | §9 required envelope fields |
| E6 | example prefixes accepted as U1 chose them |
| E7 | §14.4 |
| E8 | `Denial::DeadlinePassed` → `CREDENTIAL_EXPIRED` |
| E9–E11 | ruling 1; `jiff` `tzdb-zoneinfo` |
| E12 | rulings 2 and 7 |
| E13 | §2.1 Unix bind mechanics; `with_server_identity` kept |
| E14 | §2.1 Windows server-owner check; native plan |
| E15 | every unit stays `implemented_unverified` until U10's records exist |
| ⟨r2.1⟩ N01 | §10; `domain::time::shorten` body (signature unchanged) |
| ⟨r2.1⟩ N02 | §14.2; **additive** fields `IssuanceCheck::{admission, permitted_extensions, expected_policy_revision, ancestors}`; **additive** `IssuanceRefusal::{BudgetExpired, WrongPrincipal, UnpermittedExtension, StalePolicyRevision, AncestorMissing, AncestorDenied, StaleAncestor}`; new `issuance::principal_for(&AccessPair) -> String`. `CriticalOption` now means critical options only |
| ⟨r2.1⟩ N03 | §8; `ipc::session` private `send_event -> Result<Delivery, FrameError>` (`Delivery::{Delivered, Replaced}`); `ResyncRequired` payload reason `event_too_large` + `subscription_ended: true` (payload only; no contract type change) |
| ⟨r2.1⟩ N04 | §2.1, §2.3, §3.1; no signature change (behaviour of `Operations::policy`/`ensure` for U5; client contract for U9) |
| ⟨r2.1⟩ N05 | §10, §13.3; `domain::time::{gate, accepted_tolerance}` bodies (signatures unchanged) |
| ⟨r2.1⟩ N06 | `m01-plan.md`; **additive** `testkit::FakeCredentialAdapter::{with_ledger(descriptor, script, path) -> io::Result<Arc<Self>>, ledger_entries(path)}`; `new` unchanged |
| ⟨r2.2⟩ §13.5 ruling 1 (gap G02) | `app::operations`: the delegate commit adds a reference on the parent keyed by the child's binding; `put_grant` drops it when the child reaches a terminal state and a parent left without references becomes `released` (no tombstone, no cascade) |
| ⟨r2.2⟩ §13.5 ruling 2 (gap G01) | **additive** `store::Txn::{grant_validation, record_grant_validation}` (meta rows, no migration); `app::operations::revalidate_chain` re-runs `resolve_authority` with the grant's unchanged scope and deadline before activation, bind, the awaiting-approval checks, delegation from the parent and reserve; publish voids (`StaleGeneration`) when the generation moved since its reservation |
| ⟨r2.2⟩ §13.5 ruling 3 (gap G07) | `IssuanceFacts.permitted_extensions` **removed** (app API, not a contract type); `app::operations::permitted_extensions(grant, pair)` derives them inside the reserve and publish transactions |
| gap G03/G04 (N06) | **additive** `app::ports::ResourceCleaner`, `app::reconcile::{CleanupPoint, CleanupHook, NoCleanupHook}`, `runtime::supervisor::{Supervisor::{with_cleaner, cleanup_pass}, CleanupReport}` |
| gap G06/G18 | §8 (live fan-out in `seq` order; `Subscribed.cursor` is the head boundary); `heimdall schema export --config-out` |
| ⟨r2.3⟩ §13.6 items 1, 3, 5, 6 (M01-rulings-13-6-F1) | No public signature change. Behaviour: `store::Txn::upsert_policy` bumps the generation on **every** accepted write (the `narrowing` argument no longer selects it); `domain::issuance::check` returns `CutoffPassed` only for `new_activation` (existing grants past the cutoff ⇒ `BoundPassed` ⇒ `CREDENTIAL_EXPIRED`); `app::operations` re-validation and continuing issuance ignore a pause (private `continuing_policy`), new grants/bindings check pause and cutoff before re-validation (`POLICY_PAUSED`/`POLICY_CUTOFF`), a waiting request under a pause answers `POLICY_PAUSED` and keeps waiting, the pinned applicable policy is the first by ID |
| ⟨r2.3⟩ §13.6 item 4 (M01-rulings-13-6-F2) | **additive** `runtime::supervisor::{Jitter, RandomJitter, FixedJitter(f64), retry_delay(&Backoff, attempt, &dyn Jitter) -> Duration, Supervisor::with_jitter(Arc<dyn Jitter>)}`; the cleanup executor's retry delays are `Backoff::jittered` from the injected source (default `RandomJitter`, CSPRNG; unit `1.0` if randomness fails), and a failed scheduler pass is retried after a jittered delay; tests `integration_runtime::u8b::cleanup_retries_use_bounded_backoff_with_injected_jitter`, property `jitter_props::jittered_retry_delays_stay_within_the_bounded_backoff`; verified (no code change): `u8b::unavailable_prepare_is_answered_once_and_never_retried_by_the_supervisor_or_a_restart`, e2e `unavailable_prepare_exits_5_once_and_the_same_key_replays_the_same_operation`. `model_operations::g04_*` asserts the unjittered schedule and needs `.with_jitter(Arc::new(FixedJitter(1.0)))` (escalated; outside F2's paths) |
| ⟨r2.3⟩ §13.6 item 7 (M01-rulings-13-6-F2) | No public signature change. CLI (`heimdall` bin): on an interactive TTY session `Attend` is sent **first** for `access ensure`, `access resume`, `access cutoff`, `decision approve|deny`, `time confirm` (never for `pause` or non-interactive/non-TTY invocations); the prompt shows the runtime's answer (`APPROVAL_REQUIRED`) and the exact recorded request; `Decide` only on `y`/`yes`. Crate-private test seam `cli::{Session, Prompter}`; unit tests `cli::tests::*attend*`, e2e pty cases (Unix) |
| ⟨r2.3⟩ §13.6 item 8 (M01-rulings-13-6-F2) | **additive** `contract::ipc::capability::SERVICE_CONTROL_V1 = "service-control/1"` (§2.4 list gains it; text of §2.4 left to the integrator), `contract::request::{ShutdownRequest {}, Request::Shutdown(ShutdownRequest)}` (wire `{"op":"shutdown"}`), `Request::required_capability() -> Option<&'static str>`; `Request::is_effectful` is `false` for `Shutdown` (no operation, no idempotency record). `ipc::session::server_capabilities()` offers `service-control/1`; a request whose capability was not negotiated is answered `SCHEMA_UNSUPPORTED` and never dispatched; **additive** `ipc::session::Dispatcher::replied(&self, &SessionInfo, &'static str, &Code)` (default no-op), called after the response frame is written. `runtime::dispatch::OperationsDispatcher::{with_service_control(CancellationToken), handle_as(&Caller, Request)}`: owner role only (`CAPABILITY_UNAVAILABLE` otherwise), any session, answer `OK {"stopping": true, "already_stopping": bool}`, drain started from `replied` (same graceful drain as a signal); `#[doc(hidden)] ServiceOptions.endpoint_prefix` (Windows test pipe prefix `hmtest-`). CLI `service stop` sends `Shutdown` on every platform (`data.via = "control"`), Unix SIGTERM fallback (`"signal"`) only when the endpoint is unusable (Windows has no fallback: it waits for an already-stopping runtime, `"exited"`, or reports the endpoint error). No code-table change. Schemas re-exported (`request`, `ipc.client-message`); examples `schemas/examples/{request.shutdown,ipc.client-message.request-shutdown,ipc.server-message.response-shutdown}.json`. Windows: **additive** `runtime::platform::disinherit_standard_handles()` (one new `unsafe` call, `SetHandleInformation(std handle, HANDLE_FLAG_INHERIT, 0)`, inside the existing `platform.rs` boundary; overview §9 inventory to be updated by the integrator), called by `launcher::spawn_detached` so the detached runtime never inherits the client's stdio pipes (native run 1 hung on exactly that). Runtime tests ported to Windows and run natively (`tests/evidence/artifacts/m01/rulings-13-6/windows/`) |
| ⟨r2.3⟩ §13.6 items 4, 8 (M01-rulings-13-6-integrate) | No public signature change. `app::operations` `inspect capabilities` lists `service-control/1`, so discovery equals `ipc::session::server_capabilities()` (asserted by `integration_runtime::u8b::dispatcher_rechecks_attendance_and_renders_application_results`); example `schemas/examples/envelope.success.read.json` and `tests/contracts/limits.rs` gain the name. `tests/model/operations.rs` `supervisor_with` pins `FixedJitter(1.0)` so the g03/g04 cases assert the unjittered schedule. overview §9 `unsafe` inventory lists `SetHandleInformation` and the process-identity reads. §2.4 text not edited (outside the integrator's grant) |

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
