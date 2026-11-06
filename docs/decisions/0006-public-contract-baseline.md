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
**Revision 3 (2026-11-01, task M02-W0-integrate):** the M02 wave-0 contract deltas of
`docs/architecture/m02-plan.md` §5 (revision 5) and ADR-0007 §10, as implemented at wave
0. Rules changed by it are marked **⟨rev3⟩**; §15 lists the deltas and the readings
applied where the design was silent.
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
| LAUNCH_FAILED | 127 (126 with reason `not_executable`) | no | none | fix_request | rev. 3 (ADR-0007 §8; `run` and `connect` only) |

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
failures use this table and the structured side channel (spec §10.4; M02). **⟨rev3⟩**
`LAUNCH_FAILED` exits 127, or 126 when its reason is `not_executable`; it occurs only
in `run` and `connect` (ADR-0007 §8). `contract::ExitCode` gains `NotExecutable` (126)
and `LaunchFailed` (127), and `Code::exit_code_for_reason` applies the 126 rule.

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
    ADR-0005 §3.5 records the matching issuer ordering: the issuer signs exactly the
    returned re-reservation, then publishes it.

### 13.7 ⟨r2.4⟩ Rulings on the code-review fix escalations (orchestrator, 2026-11-01)

Source: workflow `wf_886acd0c-ce2` (the fixes for review areas A, B and C).

1. **Approval basis.** Accepted as implemented. Approval re-bases an added-authority
   intent on the decision record's generation and applicable policy revision, through
   the add-only `ResolvedIntent.approval` field. Before preparation and at every later
   stage it requires needed delta ⊆ approved delta. The owner's decision is the
   authority for that delta (spec §5.3).
2. **Fully covered waiting request.** A waiting request whose recomputed delta is
   **empty** is now fully covered by the owner's saved standing policy. It proceeds as
   a standing-policy activation, through the normal resolution, time, pause and cutoff
   checks, and gets no decision record (spec §5.5: no prompt for authority the owner
   already saved). The empty-delta replacement record is withdrawn.
3. **Continuing use of an owner-approved grant.**
   * The approval basis is persisted **with the grant**: the approved delta, the
     decision ID, its generation and the policy revision. Operation retention cannot
     purge it.
   * Re-validation of an owner-approved grant requires its scope ⊆ (current
     applicable standing policy ∪ approved delta), together with every other
     re-validation predicate.
   * A narrowing that removes a part the approval did not cover ends the grant, with
     the denial's code.
   * The pause rule of §13.6 item 1 still applies: a pause does not end continuing
     work.
4. **Coalescing equivalent approvals (A07).**
   * Exact deadline equality is accepted as the coalescing key.
   * Cancelling the creating request must not fail the requests that joined it.
     Ownership of the shared grant and decision moves to the oldest remaining
     waiter, and the decision stays pending.
   * The shared grant ends only when every waiter has cancelled. Then it is
     cancelled and its decision withdrawn.
   * A deny settles every waiter.
5. **Environment changes move the generation.** `Txn::upsert_environment` advances the
   authority generation on every accepted write, as policy writes do (§13.6 item 5).
   A change in environment permissions therefore triggers re-validation.
6. **Evidence row status.** A row for a platform that ran on the current build, where
   an expected test did not run, is `in_progress` (an incomplete run). `blocked` is
   only for a platform or capability that is missing, as AGENTS.md says.
7. **The issuer ordering for item 11** is recorded in ADR-0005 §3.5.
8. **Service-stop fallback.** A missing test that must be added: an e2e case makes the
   control endpoint unusable while the advertisement stays valid. It then asserts that
   `heimdall service stop --json` reports `data.via == "signal"`, exits 0, and removes
   the advertisement.

### 13.8 ⟨r2.5⟩ Rulings on the round-2 code review and the §13.7 escalations (orchestrator, 2026-11-01)

Sources: `tests/evidence/artifacts/review-m01-code/round2.md` (R01–R09) and workflow
`wf_b2f9242d-155`.

1. **R01: the issuer signs before anything is published.** A publish that has to
   re-reserve (§13.6 item 11; ADR-0005 §3.5 amendment) returns the fresh reservation
   **unpublished** to the issuer, as `Rereserved { reservation }`. The issuer signs
   exactly those bounds and calls publish again. That final publish runs every
   predicate in its own transaction. The 3-attempt bound counts these round trips.
   The existing test that expects `Published` after an internal re-reservation is
   wrong and must be replaced. Its replacement records the order of signing and
   injects a revoke or an expiry between signing the replacement and publishing it.
2. **R02: one wait bound per request.** A `decide` that resumes several waiters
   applies one overall `max_wait` to the request. It resumes all waiters at once and
   returns the durable decision result when that bound is reached, with every
   waiter's operation still observable. Waiters never wait one after another.
3. **R03: retention never hides a gap.**
   * The catch-up read checks the retained tail against the delivery boundary in the
     same transaction.
   * If retention removed an event the subscriber has not received, the subscriber
     gets `ResyncRequired` carrying the last delivered cursor. Continuity is never
     claimed.
   * The event property gains retention steps. Each run must end in either complete
     delivery or an explicit resync.
4. **What "ends the grant" means (§13.7 items 3 and 5).** A grant must not look
   `active` once it can no longer be used. When re-validation of an active or
   degraded grant fails, the grant moves to a terminal state, either when the failure
   is detected at use or in the supervisor's scheduler pass:
   * a deadline or cutoff has passed: `expired`;
   * authority has been withdrawn (a revoke on the chain, a narrowing outside the
     approval, or a removed environment permission): `revoking`, with a tombstone
     whose cause is `authority_withdrawn`, then `revoked` once local denial is
     applied.

   The residual is reported as for any revocation (`latest_possible_credential_expiry`).
   A pause and uncertain time never end a grant.
5. **Cancelling the creator after approval (§13.7 item 4).**
   * If other waiters remain, the creator's operation settles `cancelled` from the
     caller's point of view. Because the shared preparation continues for the other
     waiters, its result reports `may_have_external_effect: true`.
   * The shared grant's preparation continues, using the creator's existing receipts
     and effect token, so nothing is handed over in the middle of an effect. The
     remaining waiters attach as normal, and the creator gets no binding.
   * When the last attached operation cancels, the grant is cancelled and cleaned up
     through the usual reconcile path.
6. **Confirmed as implemented:**
   * the oldest-waiter tie-break: `created_at`, then operation ID;
   * migration 0003 checks a v2 owner-approved grant with no basis left to backfill
     against the standing policy alone. This fails closed, and no released v2
     database exists;
   * the additive `DecisionState::Withdrawn`;
   * the evidence status rules (§13.7 item 6).
7. **File-descriptor hygiene for the detached runtime.** The intermittent hang in
   `eight_concurrent_clients_start_exactly_one_runtime` points at a descriptor
   leaking into the detached runtime.
   * The launcher must give the detached child only its three standard descriptors,
     and those must be null on every platform.
   * On Unix, the runtime closes or marks close-on-exec every inherited descriptor
     above 2 at startup. Any new unsafe call is added to overview §9.
   * Tests: a stress variant of the concurrent-start test, and a check that the
     runtime holds no inherited descriptors of its parent.

### 13.9 ⟨r2.6⟩ Rulings on the §13.8 escalations (orchestrator, 2026-11-01)

Source: workflow `wf_a33d445a-5c2`.

1. **Uncertain time and expiry.** §13.8 item 4 reads: *neither a `TIME_UNCERTAIN`
   state nor an untrusted wall reading ends a grant*.
   * While time is uncertain, `tick` expires a grant only when its boot-scoped
     continuous budget has run out (ADR-0005 §3.6). That clock counts sleep and is
     trusted in a boot, so a real sleep across a deadline still ends the grant.
   * A wall-clock bound that appears passed only because of an uncertain or
     forward-jumped wall reading ends nothing. Use is refused with
     `TIME_UNCERTAIN` until time is safe, and the grant is then judged.
   * Test: a forward wall jump under uncertainty leaves the grant non-terminal. A
     continuous budget running out under uncertainty expires it.
2. **The re-validation context comes from the grant, not from its consumers.**
   * Re-validation derives its context from the grant's own persisted record:
     snapshot, environment, profile revision, source, and the approval or covered
     basis. A consumer binding plays no part.
   * A parent kept alive only by its delegated child (§13.5 item 1) therefore
     re-validates like any other grant.
   * "Undetermined" (refuse the use, end nothing) is left only for a record that
     truly lacks the data.
   * Test: a parent with only a child reference, after an unrelated generation move,
     still serves the child's issuance and binds.
3. **Interrupted withdrawals complete.**
   * At startup and in every scheduler pass, the runtime idempotently completes any
     grant left in `revoking`: local denial, the `credential_lifecycle` event, the
     residual, and the move to `revoked` once nothing is pending remotely.
   * Test: a crash between the withdrawal tombstone and its completion, then a
     restart, gives one event and a correct residual.
4. **Item 5 ending from `active`.** Accepted: when the owner's continued preparation
   has activated the shared grant and every attached operation then cancels, the grant
   goes `active → released`. Release is never revoke (§13.1 item 2). This branch needs
   its own test.
5. **Confirmed:**
   * undetermined re-validation refuses the use but ends nothing (now rare, after
     item 2);
   * a continued preparation activates the shared grant without the owner's
     minimums, because each attached operation checks its own at its Commit;
   * a Linux zombie counts as not alive in `process_start_time`;
   * a retention gap forces a resync on every live subscriber (fail closed).
6. **Retention resync reason.** For M01, a retention gap is reported through the lag
   path with reason `subscriber_lagged`, which meets §13.8 item 3. A distinct
   `history_trimmed` reason is a contract-freeze item for M07.
7. **Windows handle inheritance.** For M01, the residual is accepted and disclosed:
   `std`'s `CreateProcess` still passes a non-standard handle that the client itself
   inherited as inheritable. M04, the Windows milestone, must close it with an
   explicit `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` spawn in `platform.rs` (a recorded
   unsafe call) and a native test. No hang was observed on Windows after
   `disinherit_standard_handles`.

### 13.10 ⟨r2.7⟩ Rulings on the §13.9 escalations and review round 3 (orchestrator, 2026-11-01)

Sources: workflow `wf_0b82e5b5-9e6`, task M01-review3-S04, and
`tests/evidence/artifacts/review-m01-code/round3.md`.

1. **The grant's origin is a schema column.** Accepted. Migration 0004 adds
   `grants.origin_json`, and `SCHEMA_VERSION` becomes 4. The backfill order is the
   recovery intent of the lowest operation that pins the grant, then the earliest
   binding that realizes it. Otherwise the origin stays NULL, which is undetermined and
   fails closed. An origin is a property of the grant, so it belongs in the grant row,
   not in a meta row.
2. **The scope of "undetermined".**
   * An unknown profile revision, or a grant pinned to an environment this runtime
     does not manage, stays undetermined: the use is refused and nothing ends.
   * A credential **mechanism that is no longer configured** also refuses the use and
     ends nothing. An owner's configuration change can be undone before the deadline,
     so ending the grant would be irreversible over a reversible cause.
   * To keep the state truthful, such a grant moves `active → degraded` with reason
     `mechanism_unavailable` (spec §6.3: some capability unavailable). It returns to
     `active` when the mechanism is configured again and re-validation passes.
3. **The revoke sweep.** Completing explicit revokes whose operation has already
   settled is accepted, without a second `authority_withdrawn` event. However, repeated
   adapter `revoke()` calls for a pending remote effect must follow the supervisor's
   bounded, jittered backoff (§13.6 item 4; spec §13.5): attempts are capped, and the
   grant then stays `revoking` with `remote_pending` visible. Spec §12.3 says "a
   pending remote revocation must remain visible without repeated nuisance
   notifications". Retrying on every pass is not allowed.
4. **S04 descriptor fallback.** Accepted as implemented in task M01-review3-S04:
   * scan up to the hard `RLIMIT_NOFILE` if it is finite and ≤ 1,048,576, otherwise
     error;
   * the launcher refuses to spawn (`SERVICE_UNAVAILABLE`), and `service run` refuses
     to start (exit 5);
   * the test lowers the soft limit through the seam, because a real `setrlimit` in a
     spawned child disturbed an unrelated lock test (17 failures in 150 runs).
5. **Case index.** The evidence run indexes every `r136_*`, `r137_*`, `r138_*` and
   `r139_*` test under its case group, plus the review regressions.

### 13.11 ⟨r2.8⟩ Confirmations on the §13.10 implementation (orchestrator, 2026-11-01)

Source: workflow `wf_e4d70f86-2c6`. All five readings are confirmed as implemented:

1. **Missing mechanism.** A use is refused with `CAPABILITY_UNAVAILABLE` (exit 4),
   matching spec §6.3's meaning of `degraded` and the existing Reconcile-stage refusal.
2. **Authority and capability are judged separately.** A degraded grant can still be
   withdrawn or expire. A waiting or approved request whose mechanism has gone fails
   at preparation with `CAPABILITY_UNAVAILABLE`, which is more accurate than the
   earlier `CREDENTIAL_EXPIRED`.
3. **Delegation and a degraded parent.** `degraded` concerns a capability, not
   authority. A child's credential is its own, so a delegated child of a degraded
   parent stays usable while its own mechanism is configured. Delegating **from** a
   degraded parent is refused.
4. **Re-arming remote revocation retries.** An authorized explicit `revoke` covering
   the root re-arms the bounded schedule. That is the owner or a binding holder,
   under the existing revoke authorization, and revoke is a narrowing action. A round
   that finds nothing pending clears the record. M01 has no adapter push channel.
5. **Visibility.** `degraded_reason`, `remote_pending` and `remote_retries` are
   additive fields in `inspect grants`. Rendering them in the human CLI and the TUI is
   an M02 task, needed for the spec §12.3 visibility claim. The `--json` output
   already carries them.

### 13.12 ⟨r2.9⟩ Rulings on code review round 4 (orchestrator, 2026-11-01)

Source: `tests/evidence/artifacts/review-m01-code/round4.md` (T01, T02).

1. **T01: claim a round before calling an adapter.**
   * A remote-revocation retry round is claimed durably, in its own committed
     transaction, before any adapter is called: the attempt count is incremented and
     `claimed_at` is recorded.
   * A round that was claimed but never completed counts as attempted, whether the
     process crashed or the completion transaction failed.
   * The cap counts claimed rounds, so no sequence of failures yields more adapter
     calls than the cap allows.
   * The pending obligation stays until completion is confirmed.
   * An authorized explicit revoke still re-arms the schedule (§13.11 item 4).
2. **T02: obligations are tracked per adapter.**
   * The pending record keeps the unresolved obligations per responsible adapter, by
     its `AdapterIdentity` from the recovery intent and receipts.
   * A retry calls the responsible adapter only. An obligation is cleared only when
     that adapter confirms completion.
   * If the responsible adapter is not configured, its obligation stays pending and
     visible: `remote_pending` with reason `adapter_unavailable`. The round consumes
     no attempt, because no call was made, but the schedule still backs off, so
     nothing spins.
   * When the adapter is configured again, rounds resume.
   * A grant leaves `revoking` only when every obligation has cleared.
   * Another adapter's answer, or an empty adapter list, never clears an obligation.
3. **Evidence.** The native evidence run at ca21d621 stands as evidence for that
   build. M01 exit evidence is regenerated at the commit that fixes T01 and T02.
4. **Decisions from the ca21d621 evidence run** (task M01-evidence-ca21d621):
   * **The hand-written A17-local Windows row is removed.** It claimed there was no
     native Windows test. This run contradicts it: service stop over the control
     endpoint, the single-child launcher and the A06 kill/restart tests passed
     natively on Windows.
   * **Eight `#[cfg(unix)]` tests are marked `platform_only` (macOS, Linux) in the
     case index**, with a stated rationale. Five are pseudo-terminal e2e tests. On
     Windows, the attendance and prompt order is covered by the CLI unit seams, and
     ConPTY tests are an M04 item. Three test POSIX modes and symlinks:
     `instance_insecure_files_are_refused`,
     `paths_tighten_existing_permissive_dirs_and_refuse_symlinks` and
     `instance_stale_records_are_ignored`. On Windows the state directory relies on
     the per-user `%LOCALAPPDATA%` ACL.
   * **M01 makes no Windows claim that the state directory is owner-only.** An
     explicit Windows ACL check, with a native test, is an M04 item.
   * **The rewritten limitation texts in `runs.json` are accepted.**
5. **Record validation.** `minischema.validate` returns a list of errors and does not
   raise, so earlier one-line validations could not fail. A new check.sh step,
   `evidence-records` (`tools/validation/validate-records.py`), validates every
   record in `tests/evidence/`, fails on any error, and self-checks that a bad record
   is rejected.

   Re-checked on 2026-11-01: 86 records, 0 invalid. No earlier claim of a valid record
   turned out to be false.

### 13.13 ⟨r2.10⟩ Rulings on the T01/T02 fix escalations (orchestrator, 2026-11-01)

Source: task M01-review4-T01-T02. The fix is applied in the main tree, and check.sh
exits 0 with 664 tests.

1. **The responsible adapter is persisted with the grant.**
   * `GrantOrigin` gains the full `AdapterIdentity` (mechanism and instance) of the
     adapter that prepared the grant. The field is additive and serde-default, so no
     migration is needed. It is written in the transaction that records the first
     `Attempted` receipt.
   * Operation retention therefore cannot remove it.
   * The mechanism-only fallback stays for grants written before the field existed,
     and only for those.
2. **Every pending answer is tracked.** When a responsible adapter reports a remote
   effect pending, that grant becomes an obligation, whatever its state, including
   grants that ended before activation. A one-off untracked call is not allowed.
3. **The cap applies per obligation.**
   * Attempts and the cap are counted for each (grant, adapter) obligation, not for
     the record as a whole.
   * One adapter's rounds never exhaust another adapter's obligation.
   * A returning adapter's obligation continues within its own cap.
   * The record stops only when every obligation has either cleared or reached its
     cap.
4. **Interrupted first rounds resume at once.** At startup, a claimed but uncompleted
   round is due **now**, not after a back-off delay. This covers an explicit revoke
   interrupted between its claim and its adapter call. The interrupted round still
   counts as attempted (T01).
5. **Report after a failed first completion.** Accepted as implemented: the sweep
   reports from the record and lists every unconfirmed grant as pending. A later
   confirmation emits only the grant's own state change, with no second report, and
   the residual stays truthful.
6. **Independent review.** A Codex round-5 check of these changes runs before the M01
   exit.

### 13.14 ⟨r2.11⟩ Rulings on the §13.13 implementation (orchestrator, 2026-11-01)

Source: task M01-rulings-13-13. Applied in the tree, where check.sh exits 0 with 675
tests from a clean build.

1. **Only the preparing adapter is responsible.** Confirmed. The adapter recorded in
   `GrantOrigin.adapter` is the one responsible adapter for a grant. It is not merged
   with intent or receipt adapters, because in M01 only the preparing adapter applies
   a credential effect: attached and joined operations attach a binding and never
   prepare (§13.7 item 4, §13.8 item 5). A later milestone that lets a second adapter
   apply an effect for the same grant must record its own obligation.
2. **Unknown remote state counts as pending.**
   * An adapter error counts as "not confirmed", so the obligation is kept. Confirmed.
   * A grant has an `Attempted`, `Uncertain` or `Applied` effect receipt and its
     responsible adapter is not configured when it is denied: it becomes an
     obligation with reason `adapter_unavailable`, even though no call was made and
     nothing was reported.
   * A grant with no effect receipt needs no obligation.
3. **Index the remaining tests.** The non-prefixed §13.12 and §13.13 store and domain
   tests are indexed under A07 and A17-local too.
4. **Build directory.** The orchestrator pruned `target/` when nothing was building
   (9.5G to 0, then 3.3G after a clean build).

### 13.15 ⟨r2.12⟩ Rulings on review round 5 and the §13.14 fix (orchestrator, 2026-11-01)

Sources: `tests/evidence/artifacts/review-m01-code/round5.md` (U01, U02) and task
M01-rulings-13-14.

1. **U02** is closed by §13.14 item 2. The regression must also cover the exact path
   the reviewer reproduced: an `Attempted` receipt and a partial result; restart
   without the preparing adapter; recovery moves the grant to `Failed`; then an
   explicit revoke. The expected result is an `adapter_unavailable` obligation that
   stays visible.
2. **U01: `inspect grants` combines every record that covers a grant.**
   * `stopped` holds only if every remaining obligation across those records is
     stopped.
   * `remote_pending_reason` lists every reason present.
   * `attempts` is the maximum across those obligations, and `last_attempt_at` the
     latest.
   * Add the overlapping-root regression from the review.
3. **One owner for revocation calls.** The best-effort `cleanup` path in recovery must
   not call `revoke` for a grant that has a pending remote revocation record. That
   record's rounds own those calls (§13.6 item 4, single supervisor-owned retries;
   §13.13 item 2, no untracked calls). Cleanup of a grant with no record is
   unchanged.
4. **Scope of "no effect receipt, no obligation".** Confirmed: it applies only when the
   responsible adapter is not configured. A configured adapter is still called, and its
   answer is tracked as before.
5. **The time property `props_rev2::no_admission_after_true_bound_with_reboot_and_confirmation`.**
   * Its shrunk failure has a synchronized reboot whose wall clock reads 1 unit behind
     true time, followed by a re-anchor, and is then admitted at the true bound. Under
     §13.3 item 4 as amended by N05, a `Synchronized` report is trusted as-is, and
     that trust is an explicit assumption (truthful platform time).
   * The generator therefore must not pair `sync: true` with a nonzero drift. A drift
     is drawn only with `sync: false`, where the tolerance deduction applies.
   * A separate named test documents the disclosed limitation: a clock that lies while
     reporting synchronized can admit up to its error past the true bound.
   * Native evidence that the synchronization signal is reliable is part of M04/G09.
   * The module also gets a fixed default seed, as m01-plan.md §0 requires, with
     `PROPTEST_RNG_SEED` still overriding it. The shrunk case stays as a committed
     regression with its corrected expectation.
   * Making every grant end early by a skew allowance was rejected. It does not help
     against a clock that lies, and it costs every honest clock.

### 13.16 ⟨r2.13⟩ Rulings on the §13.15 implementation (orchestrator, 2026-11-01)

Source: task M01-rulings-13-15. check.sh exited 0 on two consecutive runs, with 686
tests.

1. **`remote_pending_reasons` is always an array.** The `inspect grants` field is
   renamed from `remote_pending_reason` and always carries an array of the reasons
   present, so one stable shape holds whatever the count. The field is omitted when
   there is no reason. The contract is not frozen before M07, and no external reader
   uses the field.
2. **`cleanup()` skips any grant with a pending record.** Accepted on every path, not
   only in recovery: live refusal and cancellation too. This follows §13.13 item 2:
   no untracked calls, and one owner for revocation calls.
3. **Build directory.** The orchestrator prunes it when nothing is building.

### 13.17 ⟨r2.14⟩ Ruling on the automated security review of 6230acf9 (orchestrator, 2026-11-01)

Source: automated security review of the pushed commit 6230acf9, finding "fail-open
revocation (credential left active)" in `crates/app/src/operations.rs`. The finding
concerns the `cleanup()` guard of §13.15 item 3 / §13.16 item 2.

The current guard skips the immediate `revoke` whenever **any** pending remote record
lists the grant. Suppose a credential effect is applied late, for example a late
confirmation after the grant entered revocation, and the covering record is already
stopped (capped), or holds no live obligation for the adapter that applied the effect.
Then no further call is ever made, and the credential can stay live until its own
validity ends. That fails open. The ruling:

1. **Skip only when the call is still owned.** `cleanup()` skips the immediate call
   only when a covering record holds a **live** obligation for (this grant, the
   applying adapter): not stopped, and below its cap. Otherwise:
2. **A new effect re-arms or adds the obligation.** When a credential effect has been
   applied for a grant that a record covers:
   * if that record has a stopped or capped obligation for the applying adapter, it is
     re-armed, with attempts reset and `stopped` cleared;
   * if it has none for that adapter, one is added;
   * the change is written in one transaction with the cleanup decision, and the
     supervisor's rounds then own the call. This stays bounded: a grant under
     revocation gets no new preparations, only late arrivals from attempts already in
     flight, so re-arms are bounded by the recorded attempts.
3. **No record, unchanged.** If no record covers the grant, cleanup makes its
   immediate call as before.
4. **Tests.** Each case is red before the fix and green after:
   * a late-applied effect for a grant whose covering record is capped re-arms it and
     is called by the next round;
   * the same for a record with no obligation for the applying adapter;
   * a live obligation still means a skip and no extra call;
   * restart in each case;
   * a bound on re-arms.

### 13.18 ⟨r2.15⟩ Rulings on the §13.17 implementation (orchestrator, 2026-11-01)

Source: task M01-rulings-13-17 (commit 8d17ace9).

1. **The re-arm bound is keyed by (effect token, recorded state).** Accepted. An effect
   may re-arm once while it is only possibly applied (cancelled mid-`prepare`), and once
   more when it is confirmed. Keying by token alone would leave the confirmed credential
   with no call (`r1317_5`, mutation M8).
2. **Only a round claimed after an effect can clear it.** This fixes a fail-open race the
   implementer inferred:
   1. A round's call goes out.
   2. A credential is applied afterwards.
   3. Cleanup sees the obligation as live and skips.
   4. The round's completion clears the obligation.

   The new credential is then never revoked.

   The rule: when cleanup skips because of a live obligation, it records the effect on
   that obligation as the claimed-round count at that moment. A round's confirmation
   clears the obligation only if that round was claimed after the latest recorded
   effect. Otherwise the obligation stays, and the next round makes the call. This
   amends the clearing rule of §13.12 item 2. A confirmation means "revoked as of the
   call", never "revoked as of now".
3. **Each record carries its cap.** The record stores the cap in force when it was
   created or re-armed. Recovery and the supervisor then judge a record the same way,
   whatever the configured cap. If the configured cap is lower than the stored one, the
   lower value applies (fail closed).
4. **The automated security review of 8d17ace9.** It found three issues in
   `cleanup()`:
   * **[HIGH] A round in flight when a late effect lands.** This is item 2 above: only a
     round claimed after the effect may clear it.
   * **[MEDIUM] The re-arm bound key collides.** `RearmedEffect` is keyed by
     (grant, adapter, effect token, recorded state), and the bound is checked only
     against records for the same grant and adapter. An empty or unknown token is never
     treated as already re-armed. It re-arms, or cleanup makes the immediate call.
   * **[MEDIUM] The bound skips a real late effect.** The bound limits re-arms only; it
     never suppresses the call. When the bound is reached and no covering obligation for
     the applying adapter is live, cleanup makes the immediate best-effort call, and a
     pending answer is tracked as an obligation (§13.13 item 2).

   Rule: no outcome of `cleanup()` may leave an applied effect with neither a live
   owning obligation nor a call made after it.
5. **Readings from the §13.18 implementation, confirmed** (task M01-rulings-13-18).
   * Five readings are accepted:
     * a bounded effect whose adapter is not configured re-arms the obligation;
     * a bounded call that confirms leaves the stopped obligation in place, still
       visible;
     * a round superseded by an explicit revoke never clears an obligation that has a
       recorded effect;
     * an explicit re-arm resets the recorded effects to round 0;
     * only the restart cases are indexed under A17-local.
   * **The cap during recovery.** In M01 the production cap is not configurable.
     `Service` always builds the supervisor with `Backoff::default()` (8), and only test
     code calls `with_revocation_backoff`. So a record that recovery creates with
     `DEFAULT_ROUND_CAP` cannot fail open in production.
   * **Requirement for later:** once the cap becomes configurable (M08 tuning), the
     value must reach `Operations` through `OperationsConfig` before restart recovery
     runs, so that recovery and the supervisor judge with the same cap.

### 13.19 ⟨r2.16⟩ Rulings on code review round 7 (orchestrator, 2026-11-01)

Source: `tests/evidence/artifacts/review-m01-code/round7.md` (W01, W02, both HIGH and
reproduced).

1. **W01: each claim gets an identity that never resets.**
   * Every pending remote record carries a monotonically increasing `claim_seq`. It is
     persisted and never reset, not even by an explicit revoke's re-arm, which resets
     attempts only.
   * Each claim is identified by its `claim_seq`. The wall timestamp is informational
     only.
   * A recorded effect stores the `claim_seq` current when it was recorded.
   * A completion clears an obligation only when both hold:
     * its claim is still the record's current claim, by `claim_seq` equality;
     * that `claim_seq` is greater than the obligation's recorded effect sequence.
   * A superseded completion never clears an obligation that has a recorded effect.
2. **W02: the cleanup obligation is written with the effect.**
   * The transaction that persists a late `Confirmed` or `Uncertain` receipt for a
     grant that needs cleanup also registers or re-arms the owning obligation, under the
     §13.17 and §13.18 rules.
   * Where cleanup must instead run later, for example an immediate call for an
     uncovered grant, that same transaction persists a recoverable **cleanup intent**.
   * Restart recovery and the supervisor process every cleanup intent, even when the
     originating operation has already settled (cancelled, refused or failed). An intent
     is removed only when its call was made after the effect, or an obligation owns it.
   * The same discipline applies at every settlement boundary that can leave an applied
     effect: late confirmation, recheck and commit refusal, and cancellation.
3. **The property covers real transitions.** It must generate sequences over: claim,
   adapter call (held and released), late effect, explicit re-arm, completion,
   concurrent cleanup, restart at each durable point, and supervisor passes. It must
   execute the real calls and answer tracking. Its invariant: every applied effect ends
   with either a live owning obligation or an adapter call made after the effect.

   Both W01 and W02 become named regressions.

### 13.20 ⟨r2.17⟩ Rulings on the §13.19 implementation (orchestrator, 2026-11-01)

Source: task M01-rulings-13-19. check.sh exited 0 twice, with 734 tests. The property
runs 1,024 cases and found a record-removal ABA in the first fix, now fixed with a
store-wide claim counter.

1. **Pending cleanup is visible.** `inspect grants` lists every grant with a pending
   cleanup intent, ended or not, with `cleanup_pending: true`, as long as the intent
   exists (spec §12.3). This is an orchestrator change. Test:
   `r1320_1_a_pending_cleanup_intent_is_visible_until_its_call_is_made`, red without the
   field.
2. **The implementer's readings, confirmed:**
   * A superseded completion clears nothing, even an obligation with no recorded effect.
     This overrides §13.18 item 5's narrower readings; the base counterexample loses a
     pending obligation.
   * The claim sequence counter is store-wide, because records are removed and
     recreated for the same root.
   * An unanswered attempt always gets an intent at settlement.
   * An immediate-call intent whose adapter is not configured is kept, with no calls,
     until that adapter returns. Item 1 makes it visible.
   * A store failure inside a settling transaction fails that settlement, which fails
     closed.
   * The property runs 1,024 cases.
   * `RemoteObligation::cleared_by_round` is removed in favour of `cleared_by_claim`.
3. **A preparation that hangs after its effect.** In M01 its intent is processed only
   at restart, because the supervisor leaves an in-flight intent to the preparation's
   own return path. Requirement for M02 and M03, when real adapters land: adapter calls
   get a bounded timeout. After it, the preparation counts as `Uncertain`, and its intent
   is processed by the supervisor in the same process. M01 adapters are fakes, so no
   real adapter can hang.

### 13.21 Ruling on Windows client identification timing (orchestrator, 2026-11-06)

**Source:** wave 6w unit w6-ipc, native on the Windows 11 PC (ADR-0007 §12.43 item 6).

§2.1 says the Windows server identifies each client "per connection". It did not say when.

**What was observed natively.**
- `ConnectNamedPipe` completes when the client opens the pipe.
- A client opened without SQOS uses dynamic context tracking, so `ImpersonateNamedPipeClient` fails with `ERROR_CANNOT_IMPERSONATE` (1368) until data from that client has been read.
- A client opened with SQOS identification could be "verified" before it had sent anything.

**Ruling.** On Windows, the server identifies a client only after the client's first write has been read into the instance. Concretely:
- **No consumption:** identification waits for readability, and the client's bytes are delivered unchanged and in order.
- **Bounded wait:** the wait is bounded by `FIRST_WRITE_WAIT`, equal to the hello timeout (5 s). A client still silent at the bound is disconnected and refused, never returned as verified.
- **No head-of-line blocking:** each connection is identified in its own task. A silent client never delays another client.
- **Bounded concurrency:** at most `MAX_PENDING_IDENTIFICATIONS` connections (equal to `MAX_CONTROL_CONNECTIONS`) wait to be identified at once. While that many are pending, no new connection is taken, but the waiting instance stays listening.
- **Existing checks unchanged:** remote clients are refused, an owner SID mismatch is refused, and a failed `RevertToSelf` aborts.

Every Heimdall endpoint protocol is client-first: the control hello, the signing hello and the ssh-agent request. A future server-first protocol on Windows would need a different identification design, and this ruling must be reopened for it.

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
| review A05 (M01-review-fix-R1-events) | **additive** `app::events::EventPublisher::retry_held(&self) -> bool` (`true` when nothing is held back). Behaviour of `announce`: a failed catch-up read never advances the live stream past a gap; events read before the failure are fanned out, the announced event only if it is the next position, otherwise it is held back (no cursor beyond the gap) and retried from the retained position by the next `announce` or `retry_held`. Tests `model_events::{failed_catch_up_read_never_advances_the_live_stream_past_a_gap, held_back_events_are_delivered_in_order_once_the_store_is_readable}`, property `props_announce::live_stream_never_passes_a_gap_under_catch_up_faults` |
| review C01–C03 (M01-review-fix-R3-cli-evidence) | No public signature change. CLI (`heimdall` bin): a command-line parse failure with `--json` anywhere before a bare `--` renders exactly one `USAGE_ERROR` envelope on stdout (fixed value-free message, effect `none`, `next.action` `fix_request`), exit 2; help and version stay human text, exit 0; clap's diagnostic goes to stderr, sanitized (bin-internal `cli::{json_requested, parse_failure}`). Evidence generator: required tests come from the committed `tests/native/m01/required-inventory.json`, not run logs; nonzero required `exit_codes` prevent `verified`; intentionally failing probes go under `negative_probes` |
| review B02, B04, B05 (M01-review-fix-R2-runtime-harness) | **additive** in `runtime::supervisor`: field `SupervisorConfig.resume_check_interval: Duration` (default 2 s; exhaustive struct literals need it, none in the workspace), `SupervisorConfig::resume_bound(&self) -> Duration`, consts `MAX_RESUME_CHECK_INTERVAL` (5 s) and `MIN_RESUME_CHECK_INTERVAL` (10 ms): `Supervisor::run` bounds every wait by `resume_bound()` and then compares continuous with monotonic progress, so a resume is detected within at most 5 s of awake time (B04; native suspend/resume evidence is an M04 item). Behaviour: `Supervisor::cleanup_pass` drops retry entries that do not match a current cleanup candidate's generation before computing `next_due_in` (B02). `ipc::windows` (private) passes the UTF-16 capacity to `GetNamedPipeClientComputerNameW` (B05). Tests `integration_runtime::u8b::{cleanup_retries_are_pruned_when_the_resource_is_replaced_or_reconciled, supervisor_detects_a_sleep_across_a_deadline_within_the_resume_bound, supervisor_resume_check_interval_is_bounded}`, Windows unit test `heimdall_ipc::windows::tests::client_computer_name_capacity_counts_utf16_units`; harness self-test `tools/validation/native-harness-selftest.sh` (B01, B03) |
| review A01–A04, A06, A07; §13.6 item 11 (M01-review-fix-R1-operations) | **additive** `domain::operation::ResolvedIntent.approval: Option<ApprovalBasis>` (serde default, omitted when absent; struct literals need it) and `domain::operation::ApprovalBasis { decision, delta, generation, policy_revision }`; `store::Txn::set_recovery_intent` accepts it add-only (never replaced or cleared). Behaviour: the time gate runs inside the transaction that reserves, publishes, authorizes an effect attempt, rechecks, commits, binds, resolves, or creates or completes a decision (crate-private `app::timegate::TxnGate`; A01, A02); a fresh attempt waits for an adapter slot, then validates authority, deadline, cutoff and continuous admission before the `Attempted` receipt, and `PrepareRequest.grant` carries the deadline narrowed to the recorded bound (doc only; A03); `Commit` refuses prepared facts below a caller minimum (actual offline coverage, achieved destination-scope enforcement, capabilities) with `CAPABILITY_UNAVAILABLE` (A04); replacement decisions carry the delta recomputed against current policy, approval records an `ApprovalBasis` that preparation and activation re-validate (A06); equivalent waiting added-authority requests (same caller, kind, environment, work, parent, resolved authority, deadline, policy revision, generation, delta) share one record and grant, each with its own operation (A07); `Operations::publish_issuance` voided only by a generation move re-reserves (same bounds, fresh serial and ID) and publishes within the call, at most 3 attempts, then `SERVICE_UNAVAILABLE` with `next.retry_after`; the returned entry may be the re-reservation (item 11); issuance re-validation is deferred on uncertain time, which answers `TIME_UNCERTAIN`. Tests `model_revocation::review_*`, property `publication_answers_from_the_state_and_time_of_its_own_transaction`, `integration_store::recovery_intent_approval_basis_is_add_only` |
| review integration (M01-review-fix-integrate) | No public signature change. `runtime::supervisor::Supervisor::run` calls `EventPublisher::retry_held()` on every timed wake (bounded by `resume_bound()`), so an event held back behind a failed catch-up read reaches live subscribers without waiting for another commit (review A05 liveness). `tools/validation/check.sh` gains the `evidence-selftest` step (`tests/native/m01/test_m01_evidence.py`; reviews C02, C03). Test `integration_runtime::u8b::supervisor_delivers_held_back_events_without_a_new_commit` |
| ⟨r2.4⟩ §13.7 items 2–5, authority side (M01-rulings-13-7-G1) | **additive** `domain::decision::DecisionState::Withdrawn` (wire `"withdrawn"`; never completable); **additive** `domain::operation::CoveredBasis { generation, policy_revision }` and `domain::operation::ResolvedIntent.covered: Option<CoveredBasis>` (serde default, omitted when absent; struct literals need it; `Txn::set_recovery_intent` keeps it add-only); **additive** `store::Txn::{set_grant_approval(&GrantId, &ApprovalBasis) -> Result<()>` (written once; same basis is a no-op, another is `GenerationConflict`), `grant_approval(&GrantId) -> Result<Option<ApprovalBasis>>`, `transfer_waiting_grant(&GrantId, from: &OperationId, to: &OperationId) -> Result<()>` (CAS on a `requested`/`awaiting_approval` grant whose source is `OwnerDecision { from }`), `transfer_decision(&DecisionId, from: &OperationId, to: &OperationId) -> Result<DecisionRecord>` (CAS on a pending `ApproveAuthority { operation: from }`), `withdraw_decision(&DecisionId) -> Result<DecisionRecord>` (CAS pending → `withdrawn`, no `decided_at`)}`; migration `0003_grant_approval.sql` (`grants.approval_json`, backfilled from the recovery intents that pin the grant, lowest operation ID; transactional), `store::migrations::SCHEMA_VERSION = 3`, and opening refuses a v3 file without that column as `Corrupt`. Behaviour: item 5, `Txn::upsert_environment` advances the authority generation on every accepted write (signature unchanged). Item 2, a waiting request whose recomputed delta is empty proceeds on its same-key retry as a standing-policy activation with no decision record: every waiter on the shared grant records a `CoveredBasis` (current generation, applicable revision) and resumes (owner first), the grant moves `awaiting_approval → preparing` (the table's only edge, `Approved`), the waiters' pending records are withdrawn, and the attempt, `Recheck` and `Commit` run the normal time, pause, cutoff, generation, revision, bound and admission checks (activation re-bases on the covered basis as it does on an approval); the empty-delta replacement record is gone. Item 3, approval writes the `ApprovalBasis` with the shared grant in the deciding transaction; re-validation of an `OwnerDecision` grant past the decision stage needs what it requires beyond the current standing policy within the recorded delta (no recorded basis ⇒ the policy alone), so a narrowing that removes an uncovered part refuses every continuing use (bind, issuance, delegation from it) with `CREDENTIAL_EXPIRED` while a pause does not; the grant row is not moved to a terminal state (as for a standing-policy grant). Item 4, cancelling the owner of a shared waiting grant transfers the grant and its pending records to the oldest remaining waiter (creation time, then ID); with no waiter left the grant is cancelled and its records withdrawn; deny settles every waiter (unchanged). Cancelling the owner after approval (preparation under way) still ends the shared request (escalated). Tests `model_revocation::r137_*`, properties `continuing_use_is_allowed_exactly_within_policy_and_approved_delta`, `a_shared_decision_survives_any_cancel_order_until_its_last_waiter`; `integration_store::{upsert_environment_advances_the_authority_generation_on_every_write, grant_approval_is_written_once_and_survives_operation_purge, transfer_waiting_grant_is_a_cas_on_the_owner_while_waiting, decisions_transfer_and_withdraw_by_cas_on_pending, recovery_intent_covered_basis_is_add_only}`; `heimdall_store::tests::{migration_0003_preserves_a_populated_v2_database_and_backfills_the_basis, failing_0003_step_leaves_the_v2_database_untouched}` |
| ⟨r2.4⟩ §13.7 items 6, 8 (M01-rulings-13-7-G2) | No public signature change. Evidence generator (`tests/native/m01/m01-evidence.py`): a platform that ran on the current build but skipped an expected test is `in_progress` and lists the skipped tests under `incomplete_run`; `blocked` only through a per-platform `unavailable: <reason>` with no results (blocked_on = reason) or `missing_capabilities: {"<target>" \| "<target>::<test>": <reason>}` covering every absent test (blocked_on = the joined reasons; a capability-covered target is not a `missing_targets` entry); failures, failed commands or probes, missing targets and `predates_build` still outrank `blocked`; `unavailable` with results is `in_progress` (fails closed); the `blocked_reason` default is removed. Self-tests `test_m01_evidence.RowStatus137`. E2e `e2e_cli_m01::service_stop_falls_back_to_a_signal_when_the_control_endpoint_is_unusable` (Unix; Windows has no signal fallback by design, §13.6 item 8). Committed evidence records were not regenerated (the macOS A19 row and its dependent claim row become `in_progress` when they are). |
| ⟨r2.4⟩ §13.7 integration (M01-rulings-13-7-integrate) | No public signature change. G1 and G2 integrated without code changes; `bash tools/validation/check.sh` exit 0 on the combined tree. |
| ⟨r2.5⟩ §13.8 item 7 (M01-rulings-13-8-H3) | **additive** `runtime::platform::{disinherit_descriptors_above_stdio(), close_inherited_descriptors()}` (Unix; Windows no-ops; new `unsafe` calls `syscall(SYS_close_range)` on Linux x86_64/aarch64, `fcntl`, `close`, `getrlimit`, overview §9). Behaviour: `launcher::spawn_detached` marks every client descriptor above 2 close-on-exec before the spawn, so the detached runtime gets only the three null standard descriptors; `service run` closes every descriptor above 2 before it opens anything. Cause of the hang (observed, macOS): a client's stdout pipe leaked into a sibling client spawned concurrently by the test process, then into the runtime that sibling started. `platform::process_start_time` (signature unchanged): on Linux a zombie (`Z`/`X`) is not alive, as on macOS and Windows (otherwise `service stop` timed out natively on Linux whenever the parent had not reaped the runtime yet). Windows residual: a non-standard handle the client inherited as inheritable from its own parent still passes on (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST` needs the unstable `CommandExt::raw_attribute`). Tests: e2e `concurrent_start_stress_twenty_rounds_never_hang`, `on_demand_runtime_keeps_no_descriptor_inherited_through_its_client`, `runtime_closes_every_descriptor_inherited_at_startup` (Unix); `integration_runtime::{fd_hygiene::detached_child_receives_only_null_standard_descriptors, process_start_time_treats_an_unreaped_exited_child_as_gone}` (Unix) |
| ⟨r2.5⟩ §13.8 items 1, 2, 4, 5 (M01-rulings-13-8-H1) | **changed** `app::operations::Operations::publish_issuance(&self, &IssuanceId, &IssuanceFacts) -> Result<Publication, OpError>` (was `-> Result<IssuanceEntry, OpError>`) with **new** `app::operations::Publication { Published(IssuanceEntry), Rereserved { reservation: IssuanceEntry } }`; **additive** `domain::revocation::RevocationCause { Revoke, AuthorityWithdrawn }` (`#[non_exhaustive]`, wire `"revoke"`/`"authority_withdrawn"`) and `domain::revocation::Tombstone.cause: RevocationCause` (serde default `revoke`, so stored records without it read unchanged; struct literals need it; no migration: tombstones are stored as JSON). Behaviour: item 1, a publish voided only by a generation move re-reserves in its transaction and returns `Rereserved` unpublished; the issuer signs exactly those bounds and publishes again (every predicate re-run in that transaction); the 3-attempt bound counts round trips per reservation (`reserved_here` tracks the attempt), then `SERVICE_UNAVAILABLE`. Item 2, `decide` (and the covered-request resumption in `ensure`) drives every resumed waiter at once under one overall `Limits::max_wait` and returns the durable decision result when it is reached. Item 4, on detection at use (bind, issuance reserve/publish, delegation from it, an attached binding's `Recheck`/`Commit`, with the grant's ancestors) and in `Operations::tick` (the supervisor's scheduler pass; `runtime::supervisor` unchanged): an active/degraded grant past its bound or continuous budget ⇒ `expired`; withdrawn authority (tombstone on the chain, ended/missing ancestor, a re-resolution that denies or needs more than standing policy ∪ recorded approval) ⇒ tombstone `cause: authority_withdrawn` (descendants in its cascade), `revoking`, local denial through the adapters, then `revoked` unless remote effects are pending, and a `credential_lifecycle` event `{event: "authority_withdrawn", local_applied, remote_pending, latest_possible_credential_expiry, cascade}`; `revoked_locally` events gain `cause`. Only on safe time; a pause never ends a grant; a re-validation that cannot be determined (no context, unknown profile revision, mechanism not configured) refuses the use and ends nothing. Item 5, cancelling the owner of a shared owner-decision grant after approval while other operations remain attached settles it `cancelled` with `may_have_external_effect: true`; its preparation continues on its own receipts and effect token (activation gives it no binding; its caller minimums no longer apply); attached operations attach with facts reconciled through that token; the last attached operation's cancellation (or refusal) cancels the grant (`released` if already active with no reference) and cleans up its credential. Tests `model_revocation::r138_{1,2,5}_*` (replacing `review_13_6_11_an_unrelated_generation_move_rereserves_and_publishes`), `model_operations::r138_4_*`, updated properties `publication_answers_from_the_state_and_time_of_its_own_transaction` and `continuing_use_is_allowed_exactly_within_policy_and_approved_delta`, `integration_store::tombstone_cause_round_trips_and_the_first_record_is_kept`, `heimdall_domain::revocation::tests::a_record_without_a_cause_reads_as_an_explicit_revoke` |
| ⟨r2.5⟩ §13.8 item 3 (M01-rulings-13-8-H2) | No public signature change. Behaviour (`app::events`, private `CatchUp`, `force_resync`): each catch-up page is read with the existing `Txn::stored_events_after`, which returns the retained tail in the same transaction; a tail above the delivery boundary means retention removed an undelivered event, so nothing at or below the gap is fanned out, every live receiver is made to lag (the relay's existing mechanism; current-thread executor, overview §4) and each subscriber gets one `ResyncRequired` at its last delivered cursor (payload reason `subscriber_lagged`; a strict resume from it is refused); the stream then continues after the gap. A short page is no longer proof of continuity. Tests `model_events::{r03_retention_between_a_failed_catch_up_and_its_retry_requires_a_resync, r03_age_retention_before_an_announcement_requires_a_resync, r03_retention_gap_reaches_session_receivers_through_the_relay_as_a_lag, retention_of_delivered_history_needs_no_resync}`, property `props_announce::live_stream_never_passes_a_gap_under_catch_up_faults_and_retention` (retention steps; complete delivery or explicit resync) |
| ⟨r2.5⟩ §13.8 integration (M01-rulings-13-8-integrate) | No public signature change. H1, H2 and H3 integrated without code changes; `bash tools/validation/check.sh` exit 0 twice on the combined tree (620 passed, 0 failed, 2 ignored child-process entries). `tests/native/m01/required-inventory.json` regenerated with `m01-evidence.py --generate-inventory` (case index unchanged): the wildcard `model_events` target follows H2's property rename (`..._under_catch_up_faults_and_retention`) and gains the four H2 tests. The H1 and H3 tests are not yet in the case index (named targets; escalated). |
| review round 3 S04 (M01-review3-S04) | **changed** `runtime::platform::{disinherit_descriptors_above_stdio, close_inherited_descriptors}() -> std::io::Result<()>` (were `()`; Windows always `Ok`). Behaviour: when `close_range` and the descriptor listing both fail, the last-resort loop visits every number below the `RLIMIT_NOFILE` **hard** limit (was the soft limit, at most 65 536) if it is finite and at most 1 048 576; otherwise (unreadable, infinite, over the cap) a fixed `Unsupported` error and no partial scan. `launcher::spawn_detached` (signature unchanged) then spawns nothing and returns that error, which the CLI reports as `SERVICE_UNAVAILABLE` (exit 5, message `the runtime could not be started: unsupported`); `service run` refuses to start with a fixed stderr message and exit 5. Private injectable `platform::fds::Strategy` (production `SYSTEM`). Tests `heimdall_runtime::platform::fds::tests::{hard_limit_scan_reaches_a_descriptor_above_a_lowered_soft_limit, unbounded_or_over_cap_hard_limit_without_enumeration_is_an_error}` (`close_range`, listing and the `RLIMIT_NOFILE` read injected; a real descriptor above the lowered soft limit). New test-only `unsafe` calls `fcntl(F_DUPFD)`, `OwnedFd::from_raw_fd` (overview §9) |
| ⟨r2.6⟩ §13.9 items 1–4 (M01-rulings-13-9-J1) | **additive** `domain::time::budget_exhausted(&GrantAnchor, &TimeAnchor) -> bool` (the continuous branch of `admission` alone: same boot and `now.continuous >= budget_end`; another boot is never exhausted); **additive** `domain::grant::GrantOrigin { profile: ProfileId, profile_revision: u64, policy_revision: Option<PolicyRevision>, caller: CallerContext, mechanism: String, covered: Option<CoveredBasis> }` (`covered`: serde default, omitted when absent); **additive** `store::Txn::{set_grant_origin(&GrantId, &GrantOrigin) -> Result<()>` (written once; the same origin again is a no-op; only adding `covered` to a stored origin without one is accepted; anything else `GenerationConflict`; a missing grant `Sqlite(QueryReturnedNoRows)`), `set_grant_covered(&GrantId, &CoveredBasis) -> Result<bool>` (add-only; `false` when the grant records no origin), `grant_origin(&GrantId) -> Result<Option<GrantOrigin>>`, `record_withdrawal_report(&GrantId) -> Result<bool>` (meta row `withdrawal_reported:<root>`; `true` only the first time; needs the root's tombstone), `withdrawal_reported(&GrantId) -> Result<bool>}`; migration `0004_grant_origin.sql` (`grants.origin_json`, backfilled transactionally from the recovery intent of the lowest operation ID that pins the grant with its operation's caller, else from the earliest binding that realizes the grant, never a delegated child's binding; NULL otherwise), `store::migrations::SCHEMA_VERSION = 4`, and opening refuses a v4 file without that column as `Corrupt`. Crate-private: `app::timegate::{TxnGate, TimeGate}::{expired, budget_exhausted}`. No contract or code-table change; `runtime::{supervisor, service}` unchanged (the hooks are `Operations::start` and `Operations::tick`, which they already call). Behaviour: item 1, `Operations::tick` while time is uncertain expires a grant only when its persisted continuous budget has run out at a fresh reading in the anchor's boot (`budget_exhausted`); a wall bound that appears passed on an uncertain or forward-jumped reading ends nothing (waiting grants included); on safe time, `tick` and `grant_end` (every detection at use and in the pass) judge expiry on the accepted observation's wall time and the continuous budget only (`TxnGate::expired`), never on a later unassessed wall reading (`TxnGate::admission`, unchanged, still refuses a use on any reading). Item 2, `grant_context` derives the re-validation context from the grant's own record only: `GrantOrigin` (written in the transaction that creates the grant, at both creation sites; `proceed_covered` adds the covered basis), the snapshot's source and environment (re-resolution reads the grant's environment; a grant pinned to another environment is undetermined), and the approval basis persisted with it; the expected policy revision is the standing-policy source revision, else the approval basis's, else the covered basis's, else the origin's. No consumer binding and no operation record is consulted, so a parent kept alive only by its child's reference re-validates normally; undetermined (refuse the use, end nothing) remains for a grant without a recorded origin, an unknown profile revision, or a mechanism no longer configured. Item 3, at the end of restart recovery (`Operations::start`, after the open operations were driven) and in every `tick` (whatever the time status: narrowing), every grant left in `revoking` is completed idempotently, grouped by its tombstoned root (`denied_ancestor`; root plus the tombstone's cascade): local denial through every adapter, `revoking → revoked` for each grant with nothing pending remotely, and for a withdrawal (`cause: authority_withdrawn`) one `credential_lifecycle` `authority_withdrawn` event with `local_applied`, `remote_pending`, `latest_possible_credential_expiry` (issuance log ∪ adapters) and `cascade`, reported once per root (`record_withdrawal_report` in the completing transaction; the in-process completion after `end_in` shares the path). An explicit revoke whose operation is still open is left to that operation; one whose operation settled is completed without an event (its operation's result was the report). Item 4, no code change (H1 implemented `end_orphaned_in`'s `active → released` branch); the new test passed at the base and fails when that branch is removed. Tests `model_operations::{r139_1_a_forward_wall_jump_under_uncertainty_leaves_the_grant_non_terminal, r139_1_a_continuous_budget_running_out_under_uncertainty_expires_the_grant, r139_1_an_unassessed_wall_reading_after_the_gate_accepted_time_ends_nothing, r139_1_an_unassessed_wall_reading_never_turns_a_withdrawal_into_an_expiry, r139_2_a_parent_kept_alive_by_its_child_revalidates_after_an_unrelated_generation_move, r139_3_a_crash_between_the_withdrawal_tombstone_and_its_completion_completes_on_restart, r139_3_the_scheduler_pass_completes_an_interrupted_withdrawal_once, r139_3_a_pending_remote_effect_completes_in_a_later_pass_without_a_second_report}`, property `model_operations::r139_props::r139_1_under_uncertain_time_only_the_continuous_budget_ends_a_grant` (256 cases, fixed seed), `model_revocation::r139_4_an_activated_shared_grant_is_released_when_every_attached_operation_cancels`, `integration_store::{grant_origin_is_written_once_and_gains_only_a_covered_basis, withdrawal_report_is_recorded_once_per_tombstoned_root}`, `heimdall_store::tests::{migration_0004_preserves_a_populated_v3_database_and_backfills_the_origin, failing_0004_step_leaves_the_v3_database_untouched}`, `heimdall_domain::time::tests::budget_exhaustion_looks_at_the_continuous_clock_of_the_same_boot_only`; `model_operations::r138_4_an_undetermined_revalidation_ends_nothing` now uses a grant recorded without an origin (its former parent-only case re-validates under item 2); store tests that pinned schema version 3 updated to 4. Case index: A07, A08, A17-local gain the new test-target names; `required-inventory.json` regenerated (exactly those additions). |
| ⟨r2.7⟩ §13.10 items 2, 3, 5 (M01-rulings-13-10-K1) | **additive** `domain::grant::DegradedReason { MechanismUnavailable }` (`#[non_exhaustive]`, wire `"mechanism_unavailable"`); **additive** `domain::revocation::PendingRemoteRevocation { root: GrantId, grants: Vec<GrantId>, attempts: u32, last_attempt_at: Timestamp, stopped: bool }`; **additive** `domain::issuance::IssuanceRefusal::MechanismUnavailable` (wire `{"reason": "mechanism_unavailable"}`; `OpError::from_issuance_refusal` ⇒ `CAPABILITY_UNAVAILABLE`); **additive** `store::Txn::{set_grant_degradation(&GrantId, DegradedReason) -> Result<()>` (the grant must be `degraded`, else `GenerationConflict`; a missing grant `Sqlite(QueryReturnedNoRows)`), `grant_degradation(&GrantId) -> Result<Option<DegradedReason>>`, `set_remote_revocation(&PendingRemoteRevocation) -> Result<()>` (the root must carry a tombstone, else `Sqlite(QueryReturnedNoRows)`; an empty `grants` is `GenerationConflict`; replaces the root's earlier record), `remote_revocation(&GrantId) -> Result<Option<PendingRemoteRevocation>>`, `clear_remote_revocation(&GrantId) -> Result<()>` (idempotent), `remote_revocations() -> Result<Vec<PendingRemoteRevocation>>` (ordered by root)}` (meta rows `grant_degraded:<grant>` and `remote_revocation:<root>`, no migration, `SCHEMA_VERSION` stays 4); behaviour: `Txn::update_grant_state` (signature unchanged) removes the degradation reason in the same transaction whenever the written state is not `degraded`; **additive** `app::operations::Operations::{pending_remote_revocations(&self) -> Result<Vec<PendingRemoteRevocation>, OpError>, retry_remote_revocation(&self, root: &GrantId, max_attempts: u32) -> Result<Option<PendingRemoteRevocation>, OpError>}`; **additive** `runtime::supervisor::{Supervisor::{with_revocation_backoff(self, Backoff) -> Self, revocation_pass(&self) -> Result<RevocationReport, OpError>}, RevocationReport { scheduled: Vec<(GrantId, u32, Duration)>, retried: Vec<(GrantId, u32)>, completed: Vec<GrantId>, stopped: Vec<GrantId>, next_due_in: Option<Duration> }}`; `Supervisor::scheduler_pass` (signature unchanged) runs `revocation_pass` after `tick` and its returned wake also covers the earliest scheduled round (a failed revocation pass is logged, not propagated). No contract or code-table change. Behaviour, item 2: re-validation (`resolve_existing`) judges authority only; a mechanism that is not configured no longer makes it undetermined (the destination record then carries `Unknown` enforcement, which matters for no caller minimum there), so a withdrawal or an expiry is still found for such a grant. Every use refuses a grant whose recorded origin mechanism is not configured, after all authority checks, with `CAPABILITY_UNAVAILABLE` (exit 4) and ends nothing: bind, an attached binding's `Recheck`/`Commit` (`activation_refusal`; a new grant's own activation fails its preparation instead), issuance reserve and publish (`MechanismUnavailable`, the reservation voided at publish), delegation from it (after the authority decision). On safe time the use's transaction first and every `tick` (scheduler pass) move an `active` grant whose mechanism is not configured to `degraded` with reason `mechanism_unavailable` (`grant_state_changed` payload `{grant_id, state: "degraded", reason}`; `inspect grants` gains `degraded_reason`), and a grant `degraded` for that reason back to `active` once the mechanism is configured again and re-validation passes (the chain re-validates and the grant's own authority is re-resolved now whatever the generation; recorded); a grant that must end (`grant_end`) is left to ending, so a deadline, a cutoff, an exhausted budget or a withdrawal still ends a degraded grant as usual; a grant without a recorded origin stays undetermined; a grant still degraded for that reason is refused (fail closed). Item 3: the first local denial of a revocation (an explicit `revoke`'s phase 3, which always starts afresh, or a withdrawal's completion) records what it left pending (`attempts: 1`) in its completing transaction, or clears the record; the start-up and per-pass sweep (`complete_interrupted_withdrawals`) skips every root with a record; further adapter `revoke()` rounds come only from `retry_remote_revocation`, which the supervisor calls when due: round `n + 1` is due `retry_delay(backoff, n, jitter)` after the pass that saw round `n` (continuous clock, the injected `Jitter`, default `Backoff::default()`: 500 ms doubling to 60 s, 8 rounds), the first local denial counts, the count is durable (a restart never resets the cap) and the record is `stopped` at the cap; a stopped record gets no call and no report until an explicit `revoke` covering the root (a fresh record) or a round that finds nothing pending (record removed, grants `revoked`); a round emits no event except a grant's own `revoking → revoked`; `inspect grants` shows `remote_pending: true` and `remote_retries {attempts, last_attempt_at, stopped}` on each covered `revoking` grant. Item 5: case index (`tests/native/m01/case-index.json`) gains every `r136_*`–`r139_*` test not yet indexed, the new `r1310_*` tests and the review regressions named in `tests/evidence/artifacts/review-m01-code/*.md` that exist as Cargo tests (85 names under A06, A07, A08, A17-local, A19, A29; A17-local `platform_only` for the Unix-only `e2e_cli_m01::service_stop_falls_back_to_a_signal_when_the_control_endpoint_is_unusable`, and an in-process restart label); `required-inventory.json` regenerated with `m01-evidence.py --generate-inventory` (scratch first; additions only). Tests `model_operations::{r1310_2_a_use_with_the_mechanism_gone_is_refused_and_degrades_the_grant, r1310_2_the_scheduler_pass_degrades_a_grant_whose_mechanism_is_gone, r1310_2_a_use_repairs_a_degraded_grant_once_its_mechanism_is_configured_again, r1310_2_the_scheduler_pass_repairs_a_degraded_grant_once_its_mechanism_is_back, r1310_2_a_restart_while_degraded_keeps_the_grant_degraded_and_refused, r1310_2_a_deadline_passing_while_degraded_expires_the_grant, r1310_2_a_degraded_grant_returns_only_when_revalidation_passes, r1310_3_a_pending_remote_effect_is_retried_on_the_jittered_schedule_up_to_the_cap, r1310_3_a_pending_remote_effect_completes_when_the_adapter_later_reports_done, r1310_3_a_settled_explicit_revoke_left_pending_is_retried_only_when_due, r1310_3_the_revocation_backoff_is_injectable_and_caps_the_rounds}`, property `model_operations::r1310_props::r1310_3_rounds_follow_the_jittered_capped_schedule` (256 cases, fixed seed), `integration_store::{grant_degradation_exists_only_while_the_grant_is_degraded, remote_revocation_records_need_a_tombstone_and_round_trip}`, `heimdall_domain::grant::tests::degraded_reason_wire_form_is_snake_case`; `model_operations::r139_3_a_pending_remote_effect_completes_in_a_later_pass_without_a_second_report` now advances the clock to the due round (retrying in every pass is what §13.10 item 3 forbids). |
| ⟨r2.9⟩ §13.12 items 1, 2 (M01-review4-T01-T02; review round 4 T01, T02) | **additive** `domain::revocation::RemoteObligation { grant: GrantId, adapter: AdapterIdentity, reason: Option<RemotePendingReason> }` (`reason` serde default, omitted when absent) with `RemoteObligation::served_by(&self, &AdapterIdentity) -> bool` (the recorded identity exactly; an empty `instance` means any instance of the recorded mechanism, an empty identity any adapter); **additive** `domain::revocation::RemotePendingReason { AdapterUnavailable }` (`#[non_exhaustive]`, wire `"adapter_unavailable"`); **additive** fields `domain::revocation::PendingRemoteRevocation.{obligations: Vec<RemoteObligation>, claimed_at: Option<Timestamp>}` (serde default, omitted when empty, so a record written before them reads unchanged; struct literals need them; still the meta row `remote_revocation:<root>`, no migration, `SCHEMA_VERSION` stays 4); **additive** `store::Txn::grant_adapters(&GrantId) -> Result<Vec<AdapterIdentity>>` (the `resolved.adapter` of every recovery intent pinning the grant, then the adapter of every `Attempted`/`Confirmed`/`Uncertain` receipt of those operations, each once); behaviour: `Txn::set_remote_revocation` (signature unchanged) refuses a record whose non-empty `obligations` do not name exactly its `grants` (`GenerationConflict`); **additive** field `runtime::supervisor::RevocationReport.waiting: Vec<GrantId>`. `Operations::retry_remote_revocation` and `Supervisor::revocation_pass` keep their signatures. No contract or code-table change; `inspect grants` gains the additive field `remote_pending_reason: "adapter_unavailable"` on a `revoking` grant one of whose obligations has no responsible adapter configured. Behaviour, item 1: every adapter round of a pending remote revocation is claimed in a committed transaction before any `revoke()` call (`attempts + 1`, `claimed_at`, `last_attempt_at`): an explicit revoke's first local denial in its tombstone transaction (re-arming the count, §13.11 item 4), a withdrawal's first local denial in its own claim transaction (only when the root has no record yet), every supervisor retry in `retry_remote_revocation`'s claim transaction (at or past the cap it is `stopped` with no call). The completion transaction clears only confirmed obligations, completes its own claim (`claimed_at` cleared; `stopped` at the cap with something left) and moves every grant with no obligation left `revoking → revoked`; the record is removed when none is left. A failed completion or a crash after the call leaves the claimed attempt counted (the supervisor's next pass sees the durable count and stops at the cap without a call); a later drive of an explicit revoke (restart recovery, same-key retry) never calls the adapters again and settles from the record; the start-up and per-pass sweep never calls for a root with a record, and completes a withdrawal whose claimed round never completed from the record, emitting its one report. Item 2: the record keeps one obligation per `revoking` grant and responsible adapter (`grant_adapters`; when nothing is recorded any more, the grant origin's mechanism with an empty instance, else an empty identity); a round calls each obligation's responsible configured adapter only (a grant that already left usable states, e.g. `preparing → revoked`, gets one untracked local-denial call to its responsible adapter in the first round only); an obligation is cleared only when an adapter serving it confirmed (nothing pending, no error) and none serving it failed; another adapter's answer or an empty adapter list clears nothing. With no responsible adapter configured the obligation stays (reason `adapter_unavailable`), the round calls nothing and consumes no attempt, and the supervisor schedules the next one `retry_delay(backoff, n + k, jitter)` later after `k` such rounds in a row; once the adapter is configured again rounds resume. A pre-§13.12 record (grant list only) is read with each grant's responsible adapters. Tests `model_operations::{r1312_1_failed_completion_commits_never_allow_more_adapter_calls_than_the_cap, r1312_1_a_crash_between_the_adapter_call_and_its_completion_counts_the_round, r1312_1_an_interrupted_explicit_revoke_is_not_called_again_by_recovery, r1312_2_removing_the_original_adapter_never_completes_its_pending_revocation, r1312_2_an_empty_adapter_list_never_completes_a_pending_revocation, r1312_2_a_withdrawal_while_the_responsible_adapter_is_missing_waits_for_it, r1312_2_a_record_written_before_obligations_keeps_its_responsible_adapter}`, property `model_operations::r1312_props::r1312_calls_stay_within_the_cap_and_only_the_adapter_clears_its_obligation` (256 cases, fixed seed `0x1312_0001`; regression `tests/model/operations.proptest-regressions`), `integration_store::{remote_revocation_obligations_name_exactly_the_record_grants, grant_adapters_come_from_the_intents_and_receipts_that_pin_the_grant}`, `heimdall_domain::revocation::tests::{a_pending_record_without_obligations_reads_unchanged, only_the_responsible_adapter_serves_an_obligation}`; the first half of `model_operations::r1310_2_a_degraded_grant_returns_only_when_revalidation_passes` now expects the withdrawn grant to stay `revoking` (`adapter_unavailable`) until its own adapter is configured again and confirms (the former expectation, `revoked` at once on another mechanism's answer, was the T02 defect). |
| ⟨r2.10⟩ §13.13 items 1–4, case index (M01-rulings-13-13) | **additive** field `domain::grant::GrantOrigin.adapter: Option<AdapterIdentity>` (serde default, omitted when absent; struct literals need it; stored in `grants.origin_json`, no migration, `SCHEMA_VERSION` stays 4); **additive** fields `domain::revocation::RemoteObligation.{attempts: Option<u32>, stopped: bool}` (serde default, omitted when absent / `false`; struct literals need them; still the meta row `remote_revocation:<root>`) with **additive** `domain::revocation::PendingRemoteRevocation::{obligation_attempts(&self, &RemoteObligation) -> u32` (the obligation's own count, else the record's `attempts`), `obligation_capped(&self, &RemoteObligation, max_attempts: u32) -> bool`, `capped(&self, max_attempts: u32) -> bool}` (every obligation capped; a record without obligations by its own `attempts`); **additive** `app::operations::Operations::round_interrupted(&self, &PendingRemoteRevocation) -> bool`. `store::Txn::set_grant_origin` (signature unchanged) accepts adding `adapter` to a stored origin without one, add-only like `covered` (the same identity again is a no-op; another identity or clearing it is `GenerationConflict`). `Operations::{retry_remote_revocation, pending_remote_revocations}`, `Supervisor::revocation_pass` and `RevocationReport` keep their signatures. No contract or code-table change. Behaviour, item 1: the transaction that writes a grant's first `Attempted` receipt records the preparing adapter's full identity in the grant's origin (once; never replaced), and `responsible_adapters` uses it first, alone; without it (a grant written before the field existed, or one never attempted) the recovery intents and receipts, then the origin mechanism with an empty instance, as before. Item 2: a round's call for a grant that is not `revoking` (it ended before activation, e.g. `preparing → revoked`, or a denied waiting grant) to a configured responsible adapter is recorded as an obligation in the round's claim, before the call; only that adapter's confirmation clears it, any other answer (a pending remote effect or an error) keeps it, and the supervisor retries it on the bounded schedule; the untracked first-round call is gone. Retry rounds no longer drop obligations of grants that left `revoking` (only a pre-§13.12 record's derived obligations are limited to `revoking` grants, as before). `inspect grants` keeps listing a terminal grant while it has an obligation, with `remote_pending` and `remote_retries` (its bindings are not listed). Item 3: each obligation counts the claimed rounds that owed its adapter a call; a capped obligation (`max_attempts` reached) is `stopped` and gets no call while the others continue within their own caps; the record is `stopped` only when every obligation left is; the record's `attempts` counts the record's claimed rounds (the back-off and the claim identity); an explicit revoke re-arms every obligation (and supersedes an unfinished claim); a record whose obligations carry no count maps the record's `attempts` (and stop) onto each one; `inspect grants`' `remote_retries.attempts`/`stopped` are the grant's own obligations' (highest count; all stopped, or the record stopped). The supervisor stops a record without a call only when `capped(cap)`. Item 4: `Operations::start` records, before restart recovery, the roots whose record carries a claimed but uncompleted round (`claimed_at`); `round_interrupted` is true for such a record until this process claims its next round (the root is forgotten in that claim's transaction), so a round claimed by this process (in flight, or with a failed completion) is never one; `revocation_pass` runs a record first seen with an interrupted round at once instead of scheduling it (an explicit revoke interrupted between its claim and its call included); the interrupted round stays counted. Tests `model_operations::{r1313_1_the_preparing_adapter_stays_responsible_after_operation_retention, r1313_2_a_grant_revoked_while_preparing_is_tracked_until_its_adapter_confirms, r1313_3_one_adapters_rounds_never_exhaust_another_adapters_obligation, r1313_3_a_record_count_from_before_per_obligation_counts_still_caps_its_obligations, r1313_4_an_explicit_revoke_interrupted_before_its_call_is_due_at_once_after_restart, r1313_4_a_retry_round_interrupted_before_its_call_is_due_at_once_after_restart, r1313_4_a_round_in_flight_in_this_process_is_not_called_again_at_once, r1313_4_a_round_claimed_after_the_restart_follows_the_back_off_again}`; property `model_operations::r1312_props::r1312_calls_stay_within_the_cap_and_only_the_adapter_clears_its_obligation` extended (256 cases, fixed seed `0x1312_0001`): a withdrawn parent on adapter A and its delegated child on adapter B, steps that add and remove each adapter and interrupt a round before its call, a per-obligation cap, and a final phase in which every obligation clears or had reached its own cap (a shrunk case from the per-obligation mutation check is committed in `tests/model/operations.proptest-regressions`); `integration_store::grant_origin_gains_its_preparing_adapter_once`, `heimdall_domain::{grant::tests::an_origin_without_its_preparing_adapter_reads_unchanged, revocation::tests::obligation_attempts_map_a_record_count_conservatively_and_cap_per_obligation}`; `model_operations::r1312_1_an_interrupted_explicit_revoke_is_not_called_again_by_recovery` now expects the first supervisor pass after the restart to run the next round at once (it expected "only schedules", which item 4 replaces). Item 5 (case index): `tests/native/m01/case-index.json` marks the eight `#[cfg(unix)]` tests `platform_only` macOS/Linux with a `platform_only_rationale` (the §13.12 item 4 texts): `e2e_cli_m01::{non_interactive_with_a_pending_decision_exits_3_with_decision_ref_and_no_prompt, owner_prompt_on_a_pty_eof_and_no_keep_it_pending_yes_completes_exactly_once, interactive_ensure_on_a_pty_prompts_then_approves_and_replays_to_access_ready, widening_resume_needs_an_owner_decision_completed_on_a_pty}` (A19), `e2e_cli_m01::time_confirmation_on_a_pty_clears_time_uncertain_without_moving_deadlines` (A08), `integration_runtime::{instance_insecure_files_are_refused, paths_tighten_existing_permissive_dirs_and_refuse_symlinks}` (A29), `integration_runtime::instance_stale_records_are_ignored` (A17-local); it indexes every `r1312_*` test and this task's tests (A07: `r1312_1_failed_completion_commits_never_allow_more_adapter_calls_than_the_cap`, the §13.12 item 2 cases, the property, and the item 1–3 cases with the store and domain tests; A17-local, with the in-process restart label where a restart is involved: the two other §13.12 item 1 cases and the item 4 cases; every `r1310_*` test was indexed already); `required-inventory.json` regenerated with `m01-evidence.py --generate-inventory` (scratch config first; exactly those 19 additions, no removal). |
| ⟨r2.11⟩ §13.14 items 2, 3 (M01-rulings-13-14) | **additive** `store::Txn::grant_has_effect_receipt(&GrantId) -> Result<bool>` (true when a stage receipt of an operation whose recovery intent pins the grant records an `Attempted`, `Confirmed` or `Uncertain` effect; `false` for `NotAttempted` only, no receipt, or a grant nothing pins). No other signature, contract or code-table change; no migration. Behaviour, item 2: at the first local denial of a revoke or a withdrawal (`claim_first_round_in`), a grant that is not `revoking` (e.g. `preparing → revoked`) whose responsible adapter is not configured becomes an obligation when its remote state is unknown (its origin records the preparing adapter, written with the first `Attempted` receipt so it survives retention, or `grant_has_effect_receipt`): no call is made, the obligation carries reason `adapter_unavailable`, no attempt is consumed, retry rounds back off without a call, `inspect grants` keeps the terminal grant listed with `remote_pending`, `remote_pending_reason` and `remote_retries`, and the revoke result names it in `remote_pending`; once that adapter is configured again its confirmation clears it. A grant with no effect receipt still gets no obligation. Unchanged: a configured responsible adapter is called (and tracked) as before; a `revoking` grant is tracked as before. Tests `model_operations::{r1314_2_a_revoked_preparing_grant_with_an_effect_and_no_adapter_waits_for_it, r1314_2_a_revoked_preparing_grant_without_an_effect_receipt_owes_nothing}`, `integration_store::grant_has_effect_receipt_reads_only_the_effects_of_the_operations_pinning_it`. Item 3 (case index): A07 gains `integration_store::{remote_revocation_obligations_name_exactly_the_record_grants, grant_adapters_come_from_the_intents_and_receipts_that_pin_the_grant, grant_has_effect_receipt_reads_only_the_effects_of_the_operations_pinning_it}`, `heimdall_domain-unit::revocation::tests::{a_pending_record_without_obligations_reads_unchanged, only_the_responsible_adapter_serves_an_obligation}` and the two `r1314_2_*` cases; A17-local (durable state read back after a restart, upgrade or retention) gains `integration_store::{remote_revocation_obligations_name_exactly_the_record_grants, grant_adapters_come_from_the_intents_and_receipts_that_pin_the_grant, grant_origin_gains_its_preparing_adapter_once}` and `heimdall_domain-unit::{revocation::tests::a_pending_record_without_obligations_reads_unchanged, revocation::tests::obligation_attempts_map_a_record_count_conservatively_and_cap_per_obligation, grant::tests::an_origin_without_its_preparing_adapter_reads_unchanged}`; `required-inventory.json` regenerated with `m01-evidence.py --generate-inventory` (scratch config first; exactly those 13 additions, no removal). |
| ⟨r2.12⟩ §13.15 items 1–5 (M01-rulings-13-15; review round 5 U01, U02) | No public signature, code-table or schema change; no migration. Behaviour, item 1 (U02): regression only; the §13.14 item 2 rule already covers the reviewer's path (an `Attempted` receipt and a partial result leave the grant `preparing`; a restart with no adapter configured; recovery fails the grant; an explicit revoke records an `adapter_unavailable` obligation on the preparing adapter, named in the revoke's `remote_pending` and kept visible in `inspect grants`, with no call and no attempt consumed). Item 2 (U01): `inspect grants` combines every pending remote record that covers a grant (a delegated child is in its own root's record and in an ancestor's): `remote_retries.stopped` only if every remaining obligation across them is stopped (per record: the record stopped, or every one of the grant's obligations in it stopped), `remote_retries.attempts` the maximum and `remote_retries.last_attempt_at` the latest across them, and `remote_pending_reason` every reason present; with the one reason M01 defines (`adapter_unavailable`) the field keeps its scalar form, and several distinct reasons (none can arise in M01) would be listed as an array (escalated as a contract question; see the task return). Item 3: `Operations`' best-effort `cleanup` (recovery and the live refusal/cancellation paths alike) makes no adapter `revoke()` call for a grant that any pending remote record's `grants` covers; that record's supervisor-owned rounds own those calls. A grant no record covers is cleaned up as before, and so is one whose records cannot be read (best effort, logged). Item 4: confirmation only, no change (`had_effect` is consulted only for a responsible adapter that is not configured; a configured one is called and tracked as before). Item 5: test-only; `tests/model/time.rs` `props_rev2` pairs a nonzero reboot drift only with `sync: false` (a synchronized reboot has drift 0) and has a fixed default seed `0x4130_385f_5245_5632` (`PROPTEST_RNG_SEED` overrides it); no production time change. Tests `model_operations::{r1315_1_an_attempted_grant_failed_by_recovery_without_its_adapter_stays_pending_after_revoke, r1315_2_inspect_combines_every_pending_record_that_covers_a_grant, r1315_3_recovery_cleanup_never_calls_for_a_grant_with_a_pending_record, r1315_3_recovery_cleanup_still_calls_for_a_grant_without_a_record, r1315_3_recovery_cleanup_never_calls_for_a_child_covered_by_its_parents_record}`, `heimdall_app-unit::operations::tests::remote_views_combine_whatever_the_record_order`, `model_time::props_rev2::{regression_synchronized_reboot_at_the_true_bound_is_not_admitted, a_clock_lying_by_d_while_reporting_synchronized_admits_at_most_d_past_the_true_bound}` (the disclosed limitation: a clock reading `d` behind the truth while reported synchronized is admitted for less than `d` past the true bound, and never longer); `model_operations::r1314_2_a_revoked_preparing_grant_with_an_effect_and_no_adapter_waits_for_it` now expects no recovery cleanup call (item 3). Case index: A07 gains the five `r1315_*` cases and the app unit test; A17-local gains `r1315_1_*` and the three `r1315_3_*` cases with the in-process restart label; the two `model_time` tests are covered by A08's `"*"`; `required-inventory.json` regenerated with `m01-evidence.py --generate-inventory` (scratch config first; exactly those 12 additions, no removal). |
| ⟨r2.13⟩ §13.16 item 1 (orchestrator) | `inspect grants`: `remote_pending_reason` (scalar) renamed `remote_pending_reasons`, always an array of the reasons present, omitted when none; free-form inspect data, no schema or code-table change | `app::operations` inspect grants view; `tests/model/operations.rs` assertions |
| ⟨r2.14⟩ §13.17 items 1–4 (M01-rulings-13-17; automated security review of 6230acf9) | **additive** field `domain::revocation::PendingRemoteRevocation.rearmed_effects: Vec<RearmedEffect>` (serde default, omitted when empty, so a stored record without it reads unchanged; struct literals need it; still the meta row `remote_revocation:<root>`, no migration, `SCHEMA_VERSION` stays 4) and **new** `domain::revocation::RearmedEffect { effect_token: String, confirmed: bool }` (`confirmed` serde default, omitted when `false`); **additive** `app::operations::Operations::set_revocation_cap(&self, max_attempts: u32)` (the supervisor's per-obligation round cap; until it is set, `Backoff::default().max_attempts`, the production cap); `runtime::supervisor::Supervisor::{new, with_revocation_backoff}` (signatures unchanged) call it, and `Operations::retry_remote_revocation` (signature unchanged) records its `max_attempts` too. No contract, code-table or schema change. Behaviour: `Operations`' best-effort `cleanup` (late confirmation, `Recheck` and `Commit` refusal, cancellation) decides in **one** transaction. It reads the credential effect from the stage receipts of the operation that made it (an orphaned shared grant's owner, §13.8 item 5): the latest `Attempted`/`Uncertain` receipt's adapter (the applying adapter) and effect token, confirmed when a `Confirmed` receipt follows it; with no attempt on record, the grant's responsible adapters and an empty token. Item 1: when a pending record that lists the grant in `grants` and is not stopped holds an obligation of the grant served by each applying adapter, not stopped and below the cap, cleanup skips: nothing is written and nothing called. Item 2: otherwise the first covering record with such an obligation has it re-armed (attempts `0`, `stopped` cleared), or, with none, an obligation is added to the first covering record (root order); each changed record is no longer `stopped`, records the effect in `rearmed_effects` and is written in that transaction; no immediate call is made, and the supervisor schedules the record from its count and calls on its next round (a re-armed obligation gets its own cap again). Item 3: no covering record, so the immediate call to every configured adapter, as before (also when the records cannot be read). Item 4: an effect a covering record already lists re-arms nothing. An effect counts once per token and recorded state: possibly applied (no confirmation yet; e.g. the operation was cancelled while its preparation was in flight) and confirmed applied, because a late confirmation can follow rounds that the first state re-armed and that ran before the credential existed (escalated in the task return). Private: `end_orphaned_in` returns the owner operation; `Checked::Refused` carries it. Tests `model_operations::{r1317_1_a_late_effect_on_a_capped_record_rearms_it_for_the_next_round, r1317_1_a_restart_keeps_the_rearmed_obligation_and_schedules_it, r1317_2_a_late_effect_with_no_obligation_for_its_adapter_adds_one, r1317_2_a_restart_keeps_the_added_obligation_and_schedules_it, r1317_3_a_late_effect_with_a_live_obligation_is_skipped_without_an_extra_call, r1317_3_a_restart_keeps_the_live_obligation_and_schedules_it, r1317_4_an_obligation_at_its_cap_but_not_yet_stopped_is_rearmed, r1317_5_a_cancel_then_a_late_confirmation_each_rearm_once}` (the `PendingCounter` test adapter gains a held `prepare`), `heimdall_app-unit::operations::tests::{applied_effect_is_the_latest_attempt_and_whether_it_was_confirmed, an_applied_effect_rearms_a_covering_record_at_most_once_per_effect}` (the bound: a replay of one effect cannot be produced through the public operations, which settle the operation before cleanup), `heimdall_domain-unit::revocation::tests::rearmed_effects_round_trip_and_default_to_none`; `integration_store` record literals gain the field. Case index: A07 gains the eight `r1317_*` cases and the three unit tests; A17-local gains the six `r1317_1_*`–`r1317_3_*` cases (each restarts in process; in-process restart label) and the domain test; `required-inventory.json` regenerated with `m01-evidence.py --generate-inventory` (scratch config first; exactly those 18 additions, no removal). The r1312 property was not extended (not cheap; see the task return). |
| ⟨r2.15⟩ §13.18 items 2–4 (M01-rulings-13-18; automated security review of 8d17ace9) | **additive** fields `domain::revocation::RemoteObligation.effect_round: Option<u32>`, `PendingRemoteRevocation.cap: Option<u32>` and `RearmedEffect.{grant: Option<GrantId>, adapter: Option<AdapterIdentity>}` (each serde default and omitted when absent, so a record stored at 8d17ace9 or earlier reads unchanged; struct literals need them; still the meta row `remote_revocation:<root>`, no migration, `SCHEMA_VERSION` stays 4); **new** `domain::revocation::DEFAULT_ROUND_CAP: u32 = 8` (equal to `app::reconcile::Backoff::default().max_attempts`, asserted by a test), `PendingRemoteRevocation::round_cap(&self, configured: u32) -> u32` (the stored cap, or `DEFAULT_ROUND_CAP` without one, lowered to `configured`; `u32::MAX` means none configured) and `RemoteObligation::cleared_by_round(&self, round: Option<u32>) -> bool`. `Operations::set_revocation_cap` (signature unchanged): until the supervisor calls it no cap is configured (was: `Backoff::default().max_attempts`). No contract, code-table or schema change. Behaviour, item 2: when `cleanup` leaves the call to a covering obligation (a live skip, a re-arm, an added obligation, or a tracked pending answer), the obligation records the effect as `effect_round` = the record's claimed-round count then (the latest effect wins). `complete_round_in` (every confirming path: the explicit revoke's and the withdrawal's first round, and the supervisor's retries) clears an obligation with an effect recorded only when the round is still the record's current claim (`claimed_at` and `attempts` match) and its count is greater; otherwise it stays, the grant is reported pending, and the next round calls. An explicit revoke that re-arms a record (count restarted) sets each recorded `effect_round` to 0, so its own and later rounds can clear it while a round claimed before the re-arm cannot. Item 3: a record created, re-armed by an explicit revoke, or re-armed or extended by `cleanup` stores `cap`: the configured cap or, with none configured (restart recovery), its stored cap, or the default for a new record. Recovery, `cleanup`, `claim_retry_round_in`, `complete_round_in` and `Supervisor::revocation_pass` all judge a record by `round_cap(configured)`. Item 4: the re-arm bound key is (grant, applying adapter, effect token, recorded state), so a re-arm for one grant or adapter never bounds another. An entry written at 8d17ace9 (no grant, no adapter) matches nothing. An empty or unknown token (no attempt on record) is never bounded or recorded, and always re-arms. When the bound is reached and no covering obligation for the applying adapter is live, `cleanup` makes the immediate best-effort call to that adapter (exactly its identity) and tracks the answer (private `track_bounded_answers_in`). A confirmation changes nothing. A pending or failed answer keeps an existing obligation as it is, a stopped one included (no re-arm), or adds a live one. An adapter that is not configured, so no call was possible, has its obligation re-armed or added (fail closed; interpretation reported in the task return). Private: `own_applied_effect_in` delegates to the pure `decide_applied_effect`; `EffectOwner::Bounded(Vec<AdapterIdentity>)`; `claim_first_round_in` takes the configured cap. Tests `model_operations::{r1318_2_a_round_in_flight_when_a_late_effect_lands_does_not_clear_it, r1318_2_a_restart_after_the_racing_round_keeps_the_obligation_for_the_next_round, r1318_2_an_explicit_revokes_first_round_in_flight_does_not_clear_a_late_effect, r1318_2_a_round_claimed_after_the_late_effect_clears_it, r1318_2_an_explicit_revoke_after_a_recorded_effect_clears_it_with_its_own_round, r1318_2_a_round_superseded_by_an_explicit_revoke_does_not_clear_a_late_effect, r1318_3_restart_recovery_judges_a_record_by_the_lower_cap_it_was_created_with, r1318_3_the_supervisor_judges_a_record_by_the_lower_cap_it_was_created_with, r1318_3_a_withdrawals_record_keeps_the_cap_it_was_created_with, r1318_3_a_record_at_its_own_cap_after_a_failed_completion_is_stopped_without_a_call, r1318_4_a_bounded_late_effect_with_every_obligation_stopped_makes_one_immediate_call}` (the `PendingCounter` test adapter gains a held `revoke` answer), `heimdall_app-unit::operations::tests::{r1318_4_one_grants_rearm_never_bounds_another_grants_effect, r1318_4_an_unknown_or_empty_token_is_never_bounded, r1318_4_a_pending_answer_to_a_bounded_call_is_tracked, r1318_the_default_round_cap_is_the_default_backoffs, r1318_props::r1318_cleanup_never_leaves_an_applied_effect_unowned_and_uncalled}` (the invariant as a 256-case property over the decision, fixed seed), `heimdall_domain-unit::revocation::tests::{r1318_a_record_without_the_new_fields_reads_unchanged, r1318_a_record_is_judged_by_the_lower_of_its_cap_and_the_configured_one, r1318_only_a_round_claimed_after_the_effect_clears_it}`. Existing tests amended: `r1317_3_*` (a live skip now records the effect: "unchanged" becomes "unchanged but for `effect_round`") and `an_applied_effect_rearms_a_covering_record_at_most_once_per_effect` (the recorded round, scoped keys, the stored cap, and `Bounded` with its call); `integration_store` record literals gain the fields, and the obligations round-trip covers `cap` and `effect_round`. Case index: A07 gains the 11 `r1318_*` model cases, five app unit tests and three domain unit tests. A17-local gains the five in-process restart cases (in-process restart label) and the domain read-unchanged test. `required-inventory.json` is regenerated with `m01-evidence.py --generate-inventory`, to a scratch path first: exactly those 25 additions, nothing removed. |
| ⟨r2.16⟩ §13.19 items 1–3 (M01-rulings-13-19; code review round 7 W01, W02) | **additive** fields `domain::revocation::PendingRemoteRevocation.claim_seq: Option<u64>` and `RemoteObligation.effect_seq: Option<u64>` (each serde default and omitted when absent, so a record stored at 8263ee6c or earlier reads unchanged; struct literals need them; `RemoteObligation.effect_round` stays, read only from such records); **new** `PendingRemoteRevocation::{current_claim_seq(&self) -> u64, migrate_claim_seq(&mut self)}` and `RemoteObligation::cleared_by_claim(&self, current: Option<u64>) -> bool`, which **replaces** the removed `RemoteObligation::cleared_by_round(&self, Option<u32>) -> bool`; **new** `domain::revocation::CleanupIntent { grant: GrantId, operation: OperationId, adapter: Option<AdapterIdentity>, effect_token: String, confirmed: bool, in_flight: bool, version: u64, recorded_at: Timestamp }` (`adapter`, `effect_token`, `confirmed` and `in_flight` omitted when absent, empty or `false`); **additive** `store::Txn::{next_remote_claim_seq(&mut self, after: u64) -> Result<u64>, record_cleanup_intent(&mut self, &CleanupIntent) -> Result<CleanupIntent>, cleanup_intent(&mut self, &GrantId, &OperationId) -> Result<Option<CleanupIntent>>, clear_cleanup_intent(&mut self, &GrantId, &OperationId) -> Result<()>, cleanup_intents(&mut self) -> Result<Vec<CleanupIntent>>}` (meta rows `remote_revocation_claim_seq`, `cleanup_intent:<grant>:<operation>` and `cleanup_intent_version`; no migration, `SCHEMA_VERSION` stays 4); **additive** `app::operations::Operations::process_cleanup_intents(&self) -> Result<(), OpError>`. `runtime::supervisor::Supervisor::revocation_pass` (signature unchanged) calls it first in every pass, and restart recovery calls it after the open operations and interrupted withdrawals. No contract, code-table or schema change. Behaviour, item 1: every claim (an explicit revoke's or a withdrawal's first round, a supervisor round) takes a new sequence from the store counter: the next after both the greatest one assigned and the record's own. The counter outlives the record, so neither a re-arm (which restarts `attempts` only) nor a record's removal and re-creation for the same root makes a sequence reappear. `complete_round_in` treats a round as the record's current claim only while the record carries an open claim (`claimed_at` set) with the round's sequence; `claimed_at` is otherwise informational. A current round's confirmation clears an obligation unless the obligation's `effect_seq` is at or after the round's sequence. A superseded round's confirmations clear nothing, with or without a recorded effect (§13.18 item 5's reading "an explicit re-arm resets the recorded effects to round 0" is superseded). `cleanup`'s effect record (a live skip, a re-arm, an added obligation, a tracked pending answer) stores the record's latest claim sequence. `load_remote_record` migrates a record written before the field once: its sequence starts at its `attempts`, and an `effect_round` becomes an `effect_seq` at that sequence (conservative: only a claim made after the load clears it). Item 2: the late `Confirmed` receipt (`confirm`) and the late `Uncertain` receipt (`mark_uncertain`, for an operation that left `running` and that no attached operation continues), a `Recheck` or `Commit` refusal, and a cancellation decide the cleanup in their own transaction (private `settle_effect_in` over `own_applied_effect_in`). An owning obligation is registered or re-armed there. When the call is owed later (`Immediate`: no record covers the grant; `Bounded`) a `CleanupIntent` is written there. One is also written whenever the attempt has no answer yet (`Attempted` is its last receipt), even if an obligation owns the call: a call made before the effect lands could clear that obligation. The intent is processed after the commit (private `process_cleanup_intent`, replacing `cleanup` and `call_bounded`). If it is still the intent on record (its `version`), it re-decides. An owning obligation means the intent is removed. Otherwise the call is made: the immediate call to every configured adapter, only when the applying adapter is configured, otherwise the intent is kept; or the bounded calls, with their answers tracked. Then the intent is removed in that transaction, if it is still the same version. While this process still runs the attempt's preparation (private `Inner.preparing`, from before the `Attempted` receipt until `prepare` returns), only the originating path processes the intent, without removing it. The preparation's return path processes it again (private `process_cleanup_intent_of`), whatever its own step did. Restart recovery and every supervisor pass process the other intents, whatever the operation's state. A store failure in the settling transaction now fails that settlement (fail closed) instead of falling back to the immediate call. Item 3: `model_operations::r1319_props` (1024 cases, fixed seed `0x1319_0003`) drives the production `Operations` and `Supervisor` with a `PendingCounter` that logs calls and effects in order and can hold each answer. Its steps: explicit revokes and claimed rounds (held or not, pending or confirming), supervisor passes, the late effect, cancellation, held answers released in any order, `BeforeCommit` and `AfterCommit` store faults at one of the next commits, and in-process restarts. Checked after every step: no obligation disappears unless the latest call for its grant was a confirmation. Checked at the end, after a restart and supervisor passes: an applied effect of a grant not in use has a live owning obligation or a call after it, and a call follows it. Three shrunk cases are committed in `tests/model/operations.proptest-regressions`: at 8263ee6c; at the W01 fix alone; and the record-removal ABA, found against a first, per-record sequence. Tests `model_operations::{r1319_1_a_superseded_first_round_confirmation_never_erases_a_newer_pending_obligation, r1319_1_a_superseded_confirmation_never_erases_a_newer_pending_obligation_without_an_effect, r1319_1_a_claim_that_outlives_its_records_removal_never_erases_a_new_records_obligation, r1319_2_a_restart_after_the_late_confirmation_commit_keeps_the_capped_records_cleanup, r1319_2_a_restart_after_a_recheck_refusal_commit_keeps_the_capped_records_cleanup, r1319_2_a_restart_after_a_cancellation_commit_keeps_the_capped_records_cleanup, r1319_2_a_restart_after_a_commit_refusal_commit_makes_the_owed_immediate_call, r1319_2_the_supervisor_makes_the_immediate_call_a_failed_refusal_commit_owes, r1319_2_a_late_uncertain_receipt_after_a_cancellation_gets_a_call_after_the_effect, r1319_2_a_late_confirmation_that_fails_to_commit_still_gets_a_call_after_the_effect, r1319_2_a_restart_after_a_cancelled_preparation_applied_its_effect_makes_the_owed_call, r1319_props::r1319_every_applied_effect_ends_owned_or_called_and_no_pending_obligation_is_lost}` (each red at 8263ee6c; the `PendingCounter` test adapter gains an ordered call/effect log, per-call held answers and a hang after the effect), `heimdall_app-unit::operations::tests::{r1319_1_a_record_written_before_claim_seq_is_claimed_and_completed_by_sequence, r1319_1_an_explicit_revokes_rearm_never_resets_the_claim_sequence, r1319_2_the_settlement_records_who_makes_the_call_after_the_effect}`, `heimdall_domain-unit::revocation::tests::{r1319_a_record_without_claim_seq_reads_with_a_derived_sequence, r1319_a_cleanup_intent_round_trips}`, `integration_store::r1319_cleanup_intents_are_kept_per_grant_and_operation_with_increasing_versions`. Existing tests amended for the new fields, without renaming: `revocation::tests::r1318_only_a_round_claimed_after_the_effect_clears_it` now tests `cleared_by_claim`, and a superseded claim clears nothing; the `an_applied_effect_rearms_*`, `r1318_4_a_pending_answer_*` and `r1318_props` tests use `effect_seq` and `claim_seq`; the model helper `r1318_with_effect_at` writes `effect_seq`; the `integration_store` record literals gain the fields. Case index: A07 gains the 12 model cases, three app unit tests, two domain unit tests and the store test. A17-local gains the ten in-process restart cases (in-process restart label), the domain legacy-read test and the store test (it reopens a file store). `required-inventory.json` is regenerated with `m01-evidence.py --generate-inventory` to a scratch path first: exactly those 30 additions, nothing removed. |


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

## 15. ⟨rev3⟩ Revision 3 (M02 wave 0)

Revision 3 adds the contract that M02 needs (`docs/architecture/m02-plan.md` §5, revision 5;
ADR-0007 §10). Schema major stays `"1"` (§9): every change is additive except the two marked
**changed**. Every new enum is `#[non_exhaustive]` and `snake_case` on the wire. Wave 0 lands
the types and the fail-closed landing only; no Setup or Catalog request is served yet.

### 15.1 Deltas (m02-plan §5 item → where)

| Item | Delta | Where |
|---|---|---|
| 1 | `IdentityId`, prefix `idn` | `contract::ids` |
| 2 | `Request::Setup(SetupRequest)` (`preview`, `apply`, `rollback`, `repair`); `PreviewIntent` with `validate`; `PlanDigest`; `SetupPlan`, `SetupResult` and their parts; `ConflictKind`, `RepairResolution`; `kind()` `setup.preview` / `setup.apply` / `setup.rollback` / `setup.repair` | `contract::setup`, `contract::request` |
| 3 | `Request::Catalog(CatalogRequest)`, eight actions, with `validate`; `EndpointRef`; `WithdrawDeclarationData`; `kind()` `catalog` | `contract::catalog`, `contract::provider` |
| 4 | capability `setup/1`, **declared and not offered** (frozen fail-closed landing, ADR-0007 §12.5 item 7) | `contract::ipc::capability::SETUP_V1`; `ipc::session` |
| 5 | **changed** `BindForm::Launch(LaunchBinding { executable, holder })` with `validate`; `argv` and `MAX_ARGV_BYTES` removed (Q8) | `contract::request` |
| 6 | `RequiredCapabilities.unattended` (default `false`, omitted when `false`, so M01 hashes are unchanged) | `contract::request` |
| 7 | `EnsureData.{credential_availability, provider}` | `contract::request` |
| 8 | `ConsumerIntegration.{executables, overrides, pairs}` (default empty, omitted when empty) | `contract::request` |
| 9 | provider vocabulary (`ProviderKind`, `ProviderAvailability`, `InteractionKind`, `EvidenceBasis`, `ProbeLevel`, `ProviderStatus`, `CredentialAvailability`, `ProviderInteractionRef`, `IdentitySelection`, `IdentitySelectionReport`) | `contract::provider` |
| 10 | `NextAction.provider_interaction` | `contract::envelope` |
| 11 | `DoctorReport`, `ProbeRecord`, `Finding` and the finding codes | `contract::doctor`; schema `doctor-report.schema.json` |
| 12 | `RunRecord` and the pure reader `run_record::classify` (ADR-0007 §8) | `contract::run_record`; schema `run-record.schema.json` |
| 13 | code `LAUNCH_FAILED` (§5 row 30; §6); `ExitCode::{NotExecutable, LaunchFailed}` | `contract::code`, `contract::exit` |
| 14 | stable sub-reason `data.error.reason` (see 15.2 item 1) and its values | `contract::envelope::reason` |
| 15 | `InspectSubject::{Identities, Projections}`; the app ports (`ProjectionWriter`, `StageSink`, `ProviderProbe`, `ProcessLiveness`), `PrepareRequest.pairs`, `PrepareOutcome.{availability, provider, integration}`, the adapter drop contract (documentation) | `contract::request`, `app::ports` |
| 16 | hash inputs: `setup.*` = environment + `plan_digest`; `catalog` = action + canonical spec; bind launch = binding + `"launch"` + executable (holder excluded); bind materialize keeps the M01 input byte for byte | `app::operations` |
| 17, 17a | domain types (decisions, operation kinds, approvals, setup and catalog intents, `StepContent`, `FileIdentity`, `LocalReceipt`, catalog records, `eligibility`, `fallback_clearance`, holders, `PreparedFacts`) | `heimdall_domain::{decision, operation, projection, catalog, holder, resource}` |
| 18 | migration `0005_existing_access` (tables only, plus one index), `SCHEMA_VERSION` 5, the `Txn` methods, `Store::open_read_only` | `crates/store` |
| 19 | config `[clients]` and `[setup] declaration_validity_days` | **not landed in wave 0** (see 15.3) |

New public schemas: `setup-plan.schema.json`, `setup-result.schema.json`,
`doctor-report.schema.json` and `run-record.schema.json` (the exporter's file-name
convention; m02-plan §5 items 11 and 12 say `doctor-report.json` and `run-record.json`).
The code golden (`tests/contracts/golden/code-table.golden.json`) and this ADR's §5 table both
have 30 rows.

### 15.2 Readings applied where the design is silent (pending orchestrator confirmation)

1. **Sub-reason field (wave-0 E3).** m02-plan §5 item 14 and ADR-0007 §10 name
   `ErrorData.reason`; the error fields live in `ErrorDetail`, so the field is
   `ErrorDetail.reason: Option<String>`, wire `data.error.reason`, omitted when absent.
2. **Operation-kind wire names (E4).** The new `OperationKind` variants serialize with the
   dotted names `setup.apply`, `setup.rollback`, `setup.repair` (and `catalog`), so serde
   equals `as_str` for every kind; a test asserts it.
3. **Journaled-kind classifier (E5).** `Request::admission()` classifies every variant inside
   the contract crate without a wildcard; the domain half of
   `journaled_operation_kinds_match_their_request_kind` reads the shared golden
   `tests/contracts/golden/journaled-kinds.golden.json`.
4. **Held setup result.** A held operation's error envelope carries the `SetupResult` as
   `ErrorData.setup` (wire `data.setup`, omitted when absent).
5. **`credential_availability` is always written**; an M01 document without it reads as
   `unknown`.
6. **`runtime_lifecycle` per-operation report (E2).** At restart an open setup or catalog
   operation is left untouched and reported as `{phase: unresolved, operation_id, kind,
   state, reason: driver_unavailable}`. The event payload is free-form; no `EventType` is
   added.
7. **Cancel of a setup or catalog operation (E1)** is refused with `CAPABILITY_UNAVAILABLE`,
   reason `driver_unavailable`, and writes nothing, until a later revision defines it.
8. Shapes the design names without fixing (ClientObservation, BehaviorChange, OverrideSource,
   LaunchClassification and others) are as implemented in `crates/contract` and exported in
   `schemas/public-api`; they are part of this baseline, not frozen (§1).

### 15.3 Not in wave 0

* §5 item 19 (configuration): `[clients]` and `[setup] declaration_validity_days` are not
  yet in `runtime::config` or `schemas/configuration`. They land with the unit that reads
  them.
* `Limits.adapter_call_timeout` (U0b row 24) is phase 2.
* `setup/1` is offered only by the activation change set (m02-plan §2, wave 3).
