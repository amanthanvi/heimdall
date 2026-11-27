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
**Revision 4 (2026-11-08, task M03-W0-integrate):** the M03 wave-0 contract deltas of docs/architecture/m03-plan.md §5 (revision 6) and ADR-0008 (revision 6, rulings §17.1–§17.14), as implemented at wave 0. Rules changed by it are marked **⟨rev4⟩**; §16 lists the deltas and the readings applied.
**Revision 5 (2026-11-15, task M04-M05-W0-integrate; draft for the contract owner's approval):** the joint wave 0 of M04 and M05 (ADR-0010 §9 item 9, ADR-0011 §10 item 10): both tracks' additive deltas (`docs/architecture/m04-plan.md` §5, `docs/architecture/m05-plan.md` §4) as amended by the two rulings, the policy-resolution change of ADR-0011 §10 item 1 (replacing §13.6 item 5's first-by-ID choice) and the ensure-hash rule of ADR-0011 §10 item 5; it also carries one M03 follow-up, the reason `issuer_refused` (M03 exit suite, wave 6 question I-8(2)). Rules changed by it are marked **⟨rev5⟩**; §17 lists the deltas, the two rules, the readings applied and the questions put to the contract owner.
**Revision 6 (2026-11-20, task M06-W0-contract; draft for the orchestrator's approval):** ADR-0012 §9 items 1–11 (the M06 contract deltas; m06-plan U0), applied at M06 wave 0. Two semantic changes are implemented: the caller context gains the paired client (idempotency, ownership, visibility and cursors are keyed by it) and the hello negotiates `required ⊆ offer ∩ server ∩ role`. Everything else is declared and fails closed. Rules changed by it are marked **⟨rev6⟩**; §18 lists the deltas, the readings applied and what is not in wave 0.
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
**⟨rev6⟩** The rule becomes `required ⊆ offer ∩ server ∩ role` (ADR-0012 §6.2;
`ipc::session::negotiate_for_role`): a required capability the server lacks stays
`SCHEMA_UNSUPPORTED`; one the caller's role lacks is `CAPABILITY_UNAVAILABLE`, reason
`role_insufficient`. `ServerHello.role` reports the role of a role-negotiated session and is
omitted for the local same-user session (the owner). `ClientHello.remote_client` names a
paired client and is refused `SCHEMA_UNSUPPORTED` by a runtime that does not offer
`remote-control/1` (§18).

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
inferred from the capability list. **⟨rev6⟩** `remote-control/1`, `runner/1`, `routes/1` and
`transport-iroh/1` are declared and not offered; `capability::for_role` gives each role's set
(§18).

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
request_id)`. **⟨rev6⟩** The caller context is `{principal, role, remote_client}` (ADR-0012
§3.7): two paired clients' identical `request_id`s are different keys. `remote_client` is
omitted when absent, so every stored key and hash is unchanged (§18). Keys are namespaced by principal, so the same `request_id` from a
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
* ⟨2026-11-27, M08 W4 SEC-3b; the orchestrator's ruling of 2026-11-26, R1 to R4 and the
  override⟩ **Amended for a runner's authority history** (S2-05; ADR-0012 §7 item 4 has the
  same amendment). The retention pass (`Operations::tick`) also prunes a runner's history, on
  time the time gate accepted only (never under `TIME_UNCERTAIN`) and only on a runner's store
  (`Txn::prune_runner_history`); every other store is untouched, as above:
  - **R1, tombstones.** A known-grant tombstone goes only when its grant's row is `revoked`
    (terminal; `denied_ancestor` denies by that state, through every descendant), every
    descendant is terminal, `now ≥ max(the grant's deadline, the latest descendant's) +
    retention.operations`, and nothing live remains (no key or certificate in the runner's
    signer, no unreleased binding, grant reference, held slot, slot reference or open owned
    connection). The controller's `issuance_log` is never touched. A late redelivery of the
    revoke converges on the `revoked` row. A **bare tombstone** (a delivered `grant_revoke` for
    a grant ID the runner does not hold) goes at `revoked_at` + the contract's absolute maximum
    window + `retention.operations`. The contract states no absolute maximum
    (`session.max_window` is unbounded, and a runner's own configured window is not used), so
    the design's 30-day fallback applies (`GRANT_WINDOW_FALLBACK`).
  - **R2, policy revisions.** A revision in force is never pruned. A lifted one goes
    `retention.operations` after its producing controller confirmed the lift (a complete
    authority report served to that controller showed it lifted, and that controller's session
    then went on: its resynchronization records the lift in the same commit before its time
    sample; `heimdall_runtime::runner`, "Lift confirmation"), or after the later of the lift and
    the producer's revocation.
  - **R3, effect acknowledgements.** A `grant_revoke`'s goes `retention.operations` after it
    was applied, once its producer is revoked, or once its grant has no tombstone; a pause's or
    cutoff's never while the revision it names is in force, and goes with that revision or
    `retention.operations` after it was applied once the revision is lifted.
  - **R4, widening records.** A pending paired record past its deadline is settled `expired`
    by the pass (with its lapse answer, `DECISION_STALE` / `approval_lapsed`); before this it
    stayed `pending`. A settled record (approved with its result, denied, expired, stale,
    withdrawn) is purged `retention.operations` after its decision, side row then decision,
    leaving an expired-key marker of its caller-namespaced key until `marker_until`: a replay
    of the key is `REQUEST_EXPIRED` until then (`Txn::purge_settled_widening`,
    `widening::submit_bound`). An approved record with no result (`OUTCOME_UNKNOWN`) is never
    purged.
  - **The caps, and the override.** What has no authority effect on the runner is capped,
    with `BACKPRESSURE` and nothing recorded past a cap: bare tombstones (256 per producer, 1,024
    in total), in-force revisions whose scope matches nothing on the runner (256 per producer),
    and pending paired widening records (32 per client, 128 in total). **A narrowing with an
    authority effect is never refused**: a revoke of a grant the runner holds, and a pause or
    cutoff whose scope matches a runner object, always land; in-force revisions are coalesced
    per `(producer, scope_key, kind)` (one row, a cutoff only shortening it). A refused effect
    stays in the controller's outbox, so its issuer barrier stays closed (fail closed).

## 8. Events and cursors (spec §11.5, §11.2; `contract::event`, `app::events`)

* `Event { schema_version, event_id, type, environment_id, operation_id?, resource?,
  timestamp, cursor, payload }`; `payload` is redacted before persistence.
* Delivery is at least once; consumers deduplicate by `event_id`. Ordering is
  claimed only within one environment (per-environment monotonic `seq`).
* **Cursor** = opaque `base64url(version || reader_tag || environment || seq)`;
  `reader_tag` is a hash of the authenticated caller context, so cursors are scoped
  to the reader. A cursor from another reader, with an unknown version, or below the
  retained tail yields `RESYNC_REQUIRED` with `next.resync`. **⟨rev6⟩** The caller
  context includes `remote_client`, so cursors are scoped to the paired client too; a caller
  without one keeps its tag (§18). **⟨rev2⟩** The store
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
* **⟨2026-11-26, M08 U7b D01⟩** Heimdall 1.0 retires `session.strict_disconnect`
  and removes it from `schemas/configuration/config.schema.json`. A configuration
  that still sets the key fails at load with `USAGE_ERROR` and names
  `heimdall access ensure --strict` and
  `heimdall access connection-policy --policy <id> --existing strict`.
  A post-1.0 file default would be narrowing-only and OR'd into the effective
  strict flag derived from the request and policy.

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
5. **Several applicable policies.** ⟨rev5⟩ *Superseded by §17.3*: policies are
   selected by the request's context (personal or a matched workspace), never first by
   ID; the merge below now runs over the policies applicable in that context.
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
      the generation. ⟨rev5⟩ *The first two sentences are superseded by §17.3*
      (`choose_policy` is removed); the third stands.
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

## 16. ⟨rev4⟩ Revision 4 (M03 wave 0)

Revision 4 adds the contract that M03 needs (`docs/architecture/m03-plan.md` §5, revision 6;
ADR-0008 revision 6 and its rulings §17.1–§17.14, which win where the plan differs). Schema
major stays `"1"` (§9): every change is additive. Every new field is `#[serde(default)]`
(and omitted when it carries no value, so M01 and M02 documents, stored grants and request
hashes are byte-identical); every new enum is `#[non_exhaustive]` and `snake_case` on the
wire. The code table stays at **30 rows** (§5; golden `code-table.golden.json`): M03 adds
sub-reasons (`data.error.reason`, §15.2 item 1), never codes. Wave 0 lands the types and the
fail-closed landing; **no Issuer, Enrollment or Connections request is served**. Those
requests answer `CAPABILITY_UNAVAILABLE` with reason `driver_unavailable` before any record
is written (after an owner-role refusal for `step`, `step_result`, `reconcile`, `close` and
`register`); the new decision kinds are refused, not consumed; an M03 operation kind is never
driven at restart (it stays unresolved and untouched, reported once with reason
`owner_reconcile`); the ports return an `Unavailable`-style error. The M03 behaviour that rides
on M01 and M02 requests (the per-pair mechanism of `ensure`, `SetPreference`, the two policy
actions, signature authorization, the narrowing protocol and the `revoke` timestamps) is
implemented. The capabilities `issuer/1`, `enrollment/1`, `managed-credentials/1` and
`connections/1` are **declared and not offered**.

### 16.1 Deltas (m03-plan §5 item → what landed → where)

| Item | What landed | Where |
|---|---|---|
| 1 | `EnrollmentId` (`enr`); `CaFingerprint` (`SHA256:` plus 43 base64 characters, validated on decode, `CaFingerprintError`); also `ConnectionId` (`conn`) and `ForeignRemovalId` (`frm`) | `contract::ids` |
| 2 | `Request::Issuer(IssuerRequest)`: `status`, `register`, `unlock`, `retire`, `bundle` (kinds `issuer.status` … `issuer.bundle`; `status` and `bundle` read-only, the others synchronous; `unlock` needs an attended session); `StoreKind` (four product kinds, no test variant: a test asserts its absence, F23); `IssuerState`, `CaState`, `CaStatus`, `EnrollmentCounts`, `OrphanStoreItem`, `IssuerStatus`; capability `issuer/1` | `contract::issuer`, `contract::request` |
| 3 | `Request::Enrollment(EnrollmentRequest)`: `preview` (read-only), `apply`, `verify`, `remove` (journaled `enrollment.apply` / `.verify` / `.remove`), `reconcile`, `abandon`, `step`, `step_result` (synchronous); `EnrollmentSpec`, `RemovalTarget`, `ForeignRemovalTarget`, `RegistryRef`, `RegistryCanonical`, `RemoteStage`, `RemoteStep`, `StepPins` and its four pin groups, `ApprovedTarget`, `EnrollmentPlan` and its parts, `EnrollmentEvidenceView`, `EnrollmentResult` (with `EnrollmentNext`, `EnrollmentNote`), `EnrollmentView`, `EnrollmentsView`, `EnrollmentState` (20 states, `ALL`), `EnrollmentForm`, `VerifyMode`, `RemovalPurpose`, `DisclosureKind`; capability `enrollment/1` | `contract::enrollment`, `contract::request` |
| 4 | `InspectSubject::{Enrollments, Issuer, Connections}`; `ConnectionsView`, `ConnectionEntry`, `ConnectionState`; no PID is exposed | `contract::request`, `contract::managed` |
| 4a | `Request::Connections(ConnectionsRequest)`: `close { connection_id }` (kind `connections.close`), `register { binding_id, pid, created_at, image }` (kind `connections.register`); synchronous, owner role only (the runtime refuses any other role before `driver_unavailable`); capability `connections/1` | `contract::managed`, `contract::request`, `runtime::dispatch` |
| 4b | `CatalogRequest::SetPreference { destination, account, mechanism, request_id }` (the ninth action), `PreferredMechanism`; domain `CatalogAction::SetPreference`; local only: `managed_certificate` without a verified enrollment for the pair is `CAPABILITY_UNAVAILABLE` / `pair_not_enrolled`, a changed preference is stored with projection `pending`; `Operations::{add_issuing_ca, remove_issuing_ca}` maintain `issuing_cas` | `contract::catalog`, `contract::managed`, `domain::catalog`, `app::catalog` |
| 5 | `EnsureRequest.connection: Option<ConnectionRequest { existing }>` (default, omitted when absent); `graceful` is `USAGE_ERROR` before anything is written; enters the canonical hash only when present (`{"connection": …}` in the hash's `extra`; `domain::idempotency::HashInput` is unchanged) | `contract::request`, `contract::managed`, `app::operations::pair_mechanism_m03` |
| 6 | `PolicyAction::{SetLockBehavior, SetConnectionPolicy}` and `PolicyAction::is_widening()` (`continue`, `graceful`, `owned_masters` widen; the rest narrow); `StandingPolicy.{lock_behavior, connection}` (defaults `continue`, graceful and disabled); `strictest_lock_behavior`, `strictest_connection_policy`, `merge_lock_and_connection` (called by `app`'s merged policy); `LockBehavior`, `ConnectionPolicy`, `ExistingConnectionsMode`, `MultiplexingMode` | `contract::request`, `contract::managed`, `domain::policy`, `app::operations::lock_connection_m03` |
| 7 | `EnsureData.{lock_continuity, conditions, refresh_condition, revocation, evidence, connection_policy}` with `LockContinuityReport`, `ReadinessCondition`, `RefreshCondition`, `RevocationSemantics`, `EvidenceEntry`, `ConnectionPolicyReport`; example `schemas/examples/ensure-data.managed.json` | `contract::request`, `contract::managed` |
| 8 | `Enforcement.{identity_selection, new_signing_expiry, owned_multiplexing, remote_processes, unmanaged_connections, issuer_isolation}` (each reads `unknown` when absent); `ExistingConnectionsPolicy::NotControlled` | `contract::request`, `contract::managed` |
| 9 | `RevokeData.{remote_effects, owned_connections, notes, requested_at, committed_at}` with `RemoteEffectReport`, `ResidualStatus`, `OwnedConnectionReport`, `RevokeNote`; `RecoveryBundle` (`schema` `heimdall-recovery-bundle/1`, `RECOVERY_BUNDLE_SCHEMA`), `BundleCa`, `BundleEnrollment`, `BundleLateWrite`; example `schemas/examples/revoke-data.managed.json` | `contract::request`, `contract::managed`, `contract::issuer`; `app::operations::narrowing` (timestamps) |
| 10 | `DecisionKind::{RegisterIssuer, RetireIssuer, EnrollAccount, EnrollSystemForm, RemoveEnrollment, ApproveTargetChange}`, `DecisionKind::is_m03()`, `EnrollmentPlanSummary`, `SystemFormLines`, `RemovalTargetRef` (an alias of `RemovalTarget`), `DisclosureKind` (re-exported); each is refused, not consumed, until U10 | `domain::decision`, `app::operations` |
| 11 | `OperationKind::{EnrollmentApply, EnrollmentVerify, EnrollmentRemove}` (`ALL` is 15; serde equals `as_str`), `ENROLLMENT`, `is_enrollment`, `m03_effect_class`, `enrollment_stage::*`, `enrollment_cancel_allowed`, `CancelRefusal`; never driven at restart; a cancel writes nothing: `driver_unavailable` before an `Attempted` receipt exists, `remote_step_in_progress` (next `reconcile`) after | `domain::operation`, `app::operations::enrollment_cancel_m03` |
| 12 | `ensure` hash input as in item 5 (landed). The `enrollment.apply`, `enrollment.verify` and `enrollment.remove` hash inputs are **not in the code at wave 0**: no enrollment request is journaled yet (see 16.4) | `app::operations::pair_mechanism_m03` |
| 13 | `EventType::{Enrollment, Connection, SessionLock}`; payload types `EnrollmentEventPayload`, `ConnectionEventPayload` (`ConnectionEventKind`, `CloseReason`), `SessionLockEventPayload` (`SessionLockState`); `CredentialLifecycleEvent` (M03 values `lost` and `reissued`, M01's values kept). Types only; no M03 event is emitted at wave 0 | `contract::event`, `contract::managed` |
| 14 | `reason::M03` (62 `(reason, Code)` pairs at wave 0; ⟨wave 4⟩ 64 with `issuer_store_locator_unrecorded` and `descriptor_mismatch`, both `CAPABILITY_UNAVAILABLE` (exit 4); ⟨wave 5⟩ 65 with `registry_path_invalid`, `USAGE_ERROR` (exit 2); table order, kept **separate** from M02's `reason::ALL`, which is unchanged), each reason a `pub const` in `contract::envelope::reason`; `m03_warning::{…, ALL}` (4; ⟨wave 5, round 2⟩ plus `m03_warning::REASONS` (1), the `Warning.reason` values: 16.5) and `doctor::finding::M03` (4; ⟨wave 5⟩ 5 with `managed_dir_unsafe`); `driver_unavailable` already exists; goldens `tests/contracts/golden/m03-reasons.golden.json` (reasons, warnings, findings; ⟨wave 5, round 2⟩ `warning_reasons`) and `journaled-kinds.golden.json` (extended with the M03 kinds) | `contract::envelope`, `contract::doctor` |
| 15 | `ISSUER_V1`, `ENROLLMENT_V1`, `MANAGED_CREDENTIALS_V1`, `CONNECTIONS_V1`, `M03_DECLARED`; `Request::required_capability` names them; `ipc::session` offers none | `contract::ipc::capability`, `contract::request`, `ipc::session` |
| 16 | Enrollment: `transition`, `foreign_transition`, `target_change_outcome`, `EnrollmentEvent`, `EnrollmentRecord`, `EnrollmentHold`, `RemovalOrigin`, `LateWrite`, `PairPreference`, `ProjectionStatus`, `ForeignRemovalRecord`, `FOREIGN_SUBSET`, `TargetEvaluation`, `CatalogView`. Verification: `VerificationEntry`, `VerificationCheck`, `VerificationRefusal`, `TraceEvents`, `check`, `classify` (wave 0: always inconclusive). Issuance: `CertificateBounds.ca_fingerprint`, `IssuanceRefusal::{UnknownCa, CaNotVerifiedForPair, CaRetiring}`, `CredentialState::Lost`, `extension_profile`, `CaEvent`, `ca_transition`. Grant: `DegradedReason::{CredentialReissuePending, IssuerUnavailable, PairUnenrolled}`, `sign_rule`, `GrantOrigin.{lock_behavior, connection}`. Revocation: `RevocationCause::SessionLocked`, `RemoteObligation.kind: ObligationKind`, `residual_step`, `RESIDUAL_DRIFT_PPM`. `ResourceKind::{MaterializedFile, Connection}`; slots, `OwnedConnection`, `LockEpoch`; connection close rules; the shared `/proc/<pid>/stat` parser; the claim table (`CLAIMS` empty, `CUSTODY_FIELDS`) | `domain::{enrollment, verification, issuance, grant, revocation, policy, resource, managed, connection, procstat, claims}` |
| 17 | Every limit of the item-17 table, in `Limits` (compound values split into fields: step timeouts, not-after allowance and hard-deadline margin, skew lag and lead, stderr cap and excerpt); `signing_gate_max_wait` is 10 s; the narrowing limits are targets and budgets, never refusals | `app::operations::Limits` |
| 18 | Migration `0006_managed_credentials`, `SCHEMA_VERSION` 6, tables only: `issuers`, `enrollments`, `foreign_removals` (no foreign key to `issuers`), `verification_issuance`, `pair_preferences`, `managed_slots`, `owned_connections`; the `Txn` methods of item 18 plus `open_enrollments` (a missing table means none), `enrollment_by_marker`, `enrollments_for_ca`, `foreign_removal`, `foreign_removals_by_marker`, `owned_connection`, `owned_connections_for_binding`, `slot`, `slot_files_removed`, `acknowledged_lock_epoch` and the test-only `seed_enrollment`; the uniqueness index is the one ruled in 16.3 | `crates/store/migrations/0006_managed_credentials.sql`, `store::ext_m03`, `store::migrations` |
| 19 | Ports `SignatureAuthority`, `IssuerPort`, `VerificationRunner`, `VerificationEndpoints`, `VerificationSession`, `TargetEvaluator`, `ManagedEffects`, `SessionLockSource`, `ConnectionControl`, with `SignatureRequestFacts`, `SignRefusal`, `IssuanceRef`, `IssuerRefusal`, `IssuerError`, `IssuerStatusSnapshot`, `ManagedSources`; `AdapterDescriptor.remote_credential_effect`, `RevokeOutcome.remote_effects`, `IntegrationSnapshot.managed`. Signing gates and permits (`SigningGates`, `SignPermit`, `drive_preparation`) are in `app::managed`. In `ipc::signing`: `ReleaseCheck` (`may_release`, `expires_at`), `PermitGuard`, `SignOutcome.permit`, `SigningSession`, `Signer`, `ServeLimits` | `app::ports`, `app::managed`, `ipc::signing` |
| 20 | `heimdall-issuer/1`: `Request` / `Response` messages including `unload` / `unloaded`, 64 KiB frames, the `IssuerRefusal` wire form (own reasons by name; `issuance.<reason>`, `verification.<reason>`, `issuance.grant_not_issuable.<state>`), golden `tests/contracts/golden/issuer-protocol.json`. Not a public schema | `crates/issuer/src/protocol.rs` |
| 21 | The HM1 grammar and exit codes are frozen (26 keys, 14 exit codes, the ready line, the 512 KiB, 64 KiB and 4 KiB caps, token sets); the signatures of `classify_step`, `plan::build`, `plan::plan_digest`, `line::expected_line`, `SshStepRunner::run` fail closed. **The scripts and `tests/contracts/golden/enroll-scripts/*.sh` are not in wave 0** (that directory holds a README) | `heimdall_registry::{hm1, classify, plan, line, script, step, fence, post_image}`, `heimdall_enroll::remote` |
| 22 | `lock_behavior` and `registry_path` are refused under `[x]` (`FORBIDDEN_UNDER_X`); no new key | `runtime::config` |
| 23 | New public schemas `enrollment-plan.schema.json`, `enrollment-result.schema.json`, `issuer-status.schema.json`, `recovery-bundle.schema.json` (the exporter's file-name convention); `envelope.ensure`, `envelope.revoke`, `event`, `request` and the two `ipc` message schemas regenerated, additively. Examples under `schemas/examples/` (`request.issuer.*`, `request.enrollment.*`, `enrollment-plan`, `enrollment-result`, `inspect.{enrollments,issuer,connections}`, the two managed data examples) round-trip. Goldens: `tests/model/golden/enrollment-transitions.golden.json` (88 rows) and `enrollment-recovery-paths.json` (54 planned paths), `tests/contracts/golden/issuer-protocol.json`, `m03-reasons.golden.json`, `journaled-kinds.golden.json` | `contract::schema`, `schemas/public-api`, `schemas/examples`, `tests/contracts/m03.rs`, `tests/model/managed_domain.rs` |
| 24 | The command tree of the table (`issuer`, `enroll`, `connections`, `destination prefer`, `access lock-behavior`, `access connection-policy`, `access ensure --strict`, hidden `internal issuer` and `internal session-lock-state`, the `uninstall` additions); every handler answers M01's "not available in this build" envelope (see 16.2); `uninstall --purge-state` refuses while enrollments remain; a release build refuses the M03 test-configuration variables (U0b row 16; `release-gate.sh` probes them, `enroll` included) | `heimdall::cli`, `heimdall::{m03_cmd, issuer_cmd, enroll_cmd, connections_cmd}`, `tools/validation/release-gate.sh` |

### 16.2 Readings applied where the design is silent (pending orchestrator confirmation)

Question IDs are those of the wave-0 escalation index (`.m03-wave0-questions.md`).

1. **Optional new fields (A1-Q1).** `Enforcement`'s six and `EnsureData`'s six new fields are `Option` on the type (serde default, omitted when `None`) with getters that read `unknown` (`lock_continuity()` reads `not_verified`), and `Enforcement::new(..)` takes the five M01 fields. A bare field, always serialized, would change every stored grant and M02 result.
2. **`IssuanceCheck.enrolled_cas` is `Option<EnrolledCas>` (A1-Q2).** `None` is the M01 input; refusals follow `WrongPrincipal` as `UnknownCa`, `CaRetiring`, `CaNotVerifiedForPair`. `CertificateBounds.ca_fingerprint` is `Option<CaFingerprint>` (A1-Q3).
3. **`Connections::Register` carries `image` (A1-Q5, X-Q7).** The plan text omits it; ADR-0008 D8 and the `ConnectionControl::register` port have it.
4. **`DestinationClock` (A1-Q12, X-D3).** Externally tagged on the wire (`{"measured": {…}}`, `"unmeasured"`) with a hand-written deserializer that ignores unknown sibling keys (spec §11.2); its schema carries no `additionalProperties`.
5. **M03 reasons are a separate list (A1-Q6, V-E8).** `reason::ALL` (M02) is unchanged, so the M02 list-equality test holds; `reason::M03` carries the rest. `owner_reconcile` is a `runtime_lifecycle` payload value, not an error reason (R6): `app::operations::OWNER_RECONCILE`.
6. **The wave-0 CLI envelope (C-Q1, V-E4).** "Not available in this build" is M01's envelope: `USAGE_ERROR`, exit 2, effect `none`, next `fix_request`, message ending "(planned for M03)". It is built at run time in `heimdall::m03_cmd`, outside the M02 sources the M02 guard scans. The uninstall refusal while enrollments remain is `CONFIG_CONFLICT` (exit 6) with `data.enrollments`; `--keep-remote-enrollments` without `--bundle` is `CAPABILITY_UNAVAILABLE` / `bundle_required` (C-Q2).
7. **Peer type of the signing session (B2-Q1, V-E5).** `SigningSession.peer` is `heimdall_ipc::endpoint::PeerIdentity` (the transport principal), not the control hello's `PeerInfo`. A permit-less signature frame is sent as is, so M01 fixture signers work (B2-Q3); the production signer always attaches a permit.
8. **Revoke timestamps (G-Q2).** `requested_at` is the operation's stored creation time, read before the hash, the visibility check and any gate wait; `committed_at` is read inside the tombstone transaction and stored as `Tombstone.revoked_at`; a replay returns the stored values.
9. **Narrowing diagnostics (G-Q6).** `narrowing_over_target` and `narrowing_set_grew` have no wire value: they are logged and kept in `Operations::narrowing_reports`; `RevokeNote` has `ordinary_connections_not_closed` only.
10. **Issuer refusals (N1, A2-Q2).** `IssuerRefusal` lives in `app::ports` and is frozen with `heimdall-issuer/1`'s one-string wire form (N1). The wave-0 read-only assessment answers `EntryNotReserved`: nothing is confirmed, nothing is signed.
11. **CA refusals (O-Q2).** `CaRetiring` is `ca_retiring`, `CaNotVerifiedForPair` is `pair_not_enrolled`, `UnknownCa` carries no reason; a `pending` CA signs no grant certificate (`UnknownCa`, X-D2).
12. **Mechanism resolution (O-Q1, O-Q3, O-Q7).** An issuance is on the M03 path when it names a CA or the grant's recorded mechanism is `managed_certificate`; a pending projection returns `next: setup_apply` with the binding kept and the warning `managed_projection_pending`; `unattended` keeps M02's rule for existing-access adapters (production ones never report `Verified`).
13. **Policy recording (O-Q5, O-Q10).** A `SetConnectionPolicy` that widens either field is widening as a whole; a default lock behaviour or connection policy is recorded in a grant origin as absent, so M01 and M02 origins stay byte-identical.
14. **Foreign removal state and cancel (A1-Q9, A1-Q10, X-D1).** A foreign record's states are the `FOREIGN_SUBSET`, checked by the same `transition`; a manual-removal cancel of a foreign record returns to its persisted `planned`, `held` or `abandoned` origin (after a `ca_not_held` result: `manual_removal_pending`, or `held` for a held origin); the bootstrap receipt does not block a cancel.
15. **Procfs parsing (R2).** `domain::procstat::parse_start_time` reads the state letter and start time without requiring a process group, so `process_start_time` keeps accepting group 0.
16. **Config key (R3).** The M01 key `[session] lock_behavior` is untouched; whether it still means anything beside `StandingPolicy.lock_behavior` is open.
17. **HM1 tokens (N4).** Booleans `yes` / `no`; modes as the ten-character `ls -ldn` text; `remote_now` decimal remote epoch seconds; `fence_signals` `""`, `TERM` or `TERM,KILL`.
18. **`plan_digest` is bare 64-character hex (X-Q4)**, not `sha256:…`; `consumer.pairs` of a managed result has no shape yet and the managed example omits it (X-Q5); no schema file is published for the inspect views (X-Q6).

### 16.3 Ruled during wave 0

1. **Enrollment uniqueness (S1; orchestrator).** The partial unique index on (`destination_id`, `account`, `ca_fingerprint`) covers only the enrollment-path states (`planned`, `applying`, `outcome_unknown`, `applied_unverified`, `manual_pending`, `verifying`, `verified`, `reverifying`, `held`), excluding every removal and rollback state, `abandoned` and every final state, so an abandoned line can be removed beside a new live enrollment. `manual_pending` is inside the index. A cancel of a removal returns the row to its persisted `removal_origin`; a cancel (or absence result) naming another origin is refused and writes nothing. A `held` row with `removal_origin` set is a residual outside the index; the store keeps `removal_origin_set` as a column, checked against the stored document on every read (`StoreError::Corrupt` on disagreement), and a caller that does not set `removal_origin` when moving into removal gets a `held` that counts as live (fail closed).
2. **Zero-gate narrowing (G-Q1; orchestrator, accepted with a condition).** A narrowing whose affected grants have no signing gate commits in one transaction without pending marks. The moment any affected grant has a gate, the full protocol (ADR-0008 D2 item 3a) applies to the whole set, gated or not: marks on every member, ordered acquisition, rounds, key destruction under the gates, release, then cleanup.
3. **`interaction_required` (O-Q4; orchestrator).** No `interaction_required` reason in wave 0 (nothing produces it); the first unit that does adds it to `reason::M03` and `m03-reasons.golden.json`.

### 16.4 Not in wave 0

* The four capabilities are offered in phase 2 (U0b row 13); no Issuer, Enrollment or Connections request is served before it.
* Bodies owned by U1–U13 that fail closed now: the signer, the managed vault and issuance (`issuance_ro::assess`, `TimeGate::assess_read_only`, `verification::classify`); the issuer child, its client, the CA ceremonies and stores (`heimdall_issuer`); the registry plan builder, scripts and classification (`heimdall_registry`) and the CLI-side runner (`heimdall_enroll`); the session-lock source and connection control; the CLI handlers (item 24).
* Decision kinds completed: `RegisterIssuer`, `RetireIssuer`, `EnrollAccount`, `EnrollSystemForm`, `RemoveEnrollment`, `ApproveTargetChange` are refused, not consumed, until U10.
* The managed adapter is not registered; no driver runs an enrollment, a verification, a materialization or an owned connection; the `enrollment.*` hash inputs (item 12) and the enrollment stage events land with them.
* The scripts and their goldens (`tests/contracts/golden/enroll-scripts/`); `claims` entries (`CLAIMS` is empty, so every claim-gated field reads `unknown`); the bodies of the K_ca stores, the D5 backup and the recovery-bundle writer (their types and signatures are frozen).
* Open for ADR-0008: the standing meaning of the M01 `[session] lock_behavior` key (16.2 item 16).

### 16.5 ⟨wave 5, round 2⟩ Additive deltas authorized by ADR-0008 §17.25

Each row is additive (§9: schema major stays `"1"`): a new field is `#[serde(default)]` and omitted
when absent, so every earlier document, stored record and golden is byte-identical; the new request
is a new `action` of `Request::Issuer`. Landed as seams (types, wire form, fail-closed handling);
the values are filled by the wave-5 round-2 workers. The inspect and policy views of items 19, 21
and 22 have no contract type (16.2 item 18): their keys are recorded here and in
`.m03-wave5-r2-api.md` R0, and no type was added. Round 1's `managed_dir_unsafe` (§17.25 item 14)
and `registry_path_invalid` (§17.20 item 13) are recorded in 16.1 row 14.

| Item | What landed | Where |
|---|---|---|
| §17.25 item 4 (§5 item 3) | `EnrollmentView.hold: Option<EnrollmentHoldView { reason: String, next: Vec<String> }>`, key `hold` (`{"reason": <HoldReason wire name>, "next": [<command>, …]}`, `next` omitted when empty); computed by the app from `EnrollmentRecord.hold`; absent for a record that is not `held` | `contract::enrollment`, `app::operations::enrollment_m03` |
| §17.25 item 8 (§5 item 2) | `IssuerRequest::BundleWritten { created_at: Timestamp, sha256: String }`, kind `issuer.bundle_written`, synchronous, capability `issuer/1`, not attended-only; the CLI sends it after the bundle file is written and fsynced; the runtime records `last_bundle_at` and the digest, never lowered, and never the path. Until its handler lands it answers `CAPABILITY_UNAVAILABLE` / `driver_unavailable` and records nothing. Store: `meta` rows `issuer_bundle_sha256:<hex>` (`Txn::record_bundle_digest`, `bundle_digest_recorded_at`; no migration). Example `schemas/examples/request.issuer.bundle-written.json`; golden `journaled-kinds.golden.json` (synchronous) | `contract::issuer`, `contract::request`, `app::operations::issuer_m03`, `store::ext_m03` |
| §17.25 item 15 (§5 item 14) | `Warning.reason: Option<String>`, key `reason`; `m03_warning::TIME_CONFIRMATION_AFTER_REBOOT` (`time_confirmation_after_reboot`) refining `TIME_UNCERTAIN` when the cause is no time reference for this boot; `m03_warning::REASONS` (reason, warning code); golden `m03-reasons.golden.json` `warning_reasons` | `contract::envelope` |
| §17.25 item 18 (§5 item 19; m03-plan §0.4 M2) | `app::ports::PrepareOutcome.managed: Option<ManagedResultFacts>` (`lock_continuity`, `conditions`, `refresh_condition`, `revocation`, `evidence`, `connection_policy`, the `EnsureData` fields' contract types); `None` for every M01/M02 adapter; carried in memory only (not in `PreparedFacts`), so after a restart the six `EnsureData` fields stay absent. No wire change: `EnsureData` already has the six fields (16.1 row 7) | `app::ports`, `app::operations` |
| §17.25 item 19 (§5 item 4b) | `inspect destinations`: an item's `preference` object gains `connection_policy` (the `ConnectionPolicyReport` form `{"existing", "multiplexing", "wording"}`, `wording` the runtime's D8 sentence(s)); absent when the runtime cannot compute it | `app::operations::destination_view` (untyped) |
| §17.25 item 21 (§5 item 15) | `inspect capabilities` data gains `lock` (`{"behavior": <LockBehavior>, "disclosure": <text>, "acknowledged_at": <Timestamp>}`, `acknowledged_at` omitted until acknowledged), from `Operations::lock_disclosure`; read-only | `app::operations::inspect` (untyped) |
| §17.25 item 22 (§5 item 6) | The `set_lock_behavior` and `set_connection_policy` policy results gain `lock_behavior` (`<LockBehavior>`) and `connection` (`{"existing": <ExistingConnectionsMode>, "multiplexing": <MultiplexingMode>}`); every M01 policy action's result is unchanged | `app::operations::policy_view` (untyped) |

### 16.6 ⟨wave 5, round 3⟩ Additive deltas authorized by ADR-0008 §17.27 items 1 and 2

Each row is additive (§9: schema major stays `"1"`). The new field is `#[serde(default)]` and
omitted when empty, so every earlier bundle decodes and re-encodes byte-identically; the new request
is a new top-level `op` under the existing `service-control/1` capability; the two reasons are new
rows of `envelope::reason::M03` with existing codes (no code is added).

| Item | What landed | Where |
|---|---|---|
| §17.27 item 1 (W5-R01; RecoveryBundle) | `RecoveryBundle.foreign_removals: Vec<BundleForeignRemoval>`, key `foreign_removals`, omitted when empty: every foreign removal that is not final (an abandoned system-form one, still `pending_until_line_removed`, included) by its **public removal descriptor** only (`marker`, `local_alias`, `bundle_destination_id`, `hostname`/`port` unless redacted, `account`, `ca_public_key`, `line_sha256`, `registry`, `form`) and its `state`; never foreign bytes (W4-S02). Built by `bundle::export_with_foreign` (`export` is unchanged and exports none) from `Txn::outstanding_obligations`; a bundle with any adds one removal instruction. Schema `recovery-bundle.schema.json` | `contract::issuer`, `app::issuer::bundle`, `app::operations::issuer_m03`, `store::ext_m03` |
| §17.27 item 2 (W5-S01; Request) | `Request::UninstallFence(UninstallFenceRequest)`, wire `{"op":"uninstall_fence","action":"acquire"\|"release"}`, kinds `uninstall_fence.acquire` / `.release`, `Admission::Synchronous` (no operation row, no idempotency record), capability `service-control/1`, owner role only, not attended-only. Answer `OK {"fence": "held"\|"released"}`. Held by the acquiring **connection**; released by `release` on it, when it ends for any reason, and with the runtime. ⟨§17.28 item 1⟩ While held, every request from a connection other than the holder that can start or advance remote or CA work is refused `SERVICE_UNAVAILABLE` / `uninstall_in_progress` by the dispatcher: `enrollment` `apply`, `verify`, `remove` (own and foreign), `reconcile`, `abandon`, `step`; `issuer` `register` (rotation and restore included), `unlock`, `retire` (with or without `deleted_locator`); `decide` with `approve`, whatever the kind; and the application refuses every certificate reservation outside the holder's requests. Not refused: read-only requests, `decide` with `deny`, `enrollment.step_result` (a step dispatched before the fence records its result), `issuer.bundle_written`, and the holder's own requests. `acquire` from another connection is refused the same way; `acquire` waits (≤ 20 s) for fenced requests already past their check. Golden `journaled-kinds.golden.json` (synchronous); schemas `request.schema.json`, `ipc.client-message.schema.json` | `contract::request`, `runtime::dispatch`, `app::operations::uninstall_fence_m03` |
| §17.27 item 2 (reasons, §5 item 14) | `uninstall_in_progress` → `SERVICE_UNAVAILABLE` (exit 5); `uninstall_inventory_changed` → `CAPABILITY_UNAVAILABLE` (exit 4: §5's exit-4 class is "denied / not possible as asked"; CAPABILITY_UNAVAILABLE is the code `bundle_required` already uses for uninstall's other "cannot purge as confirmed" refusal, and the other exit-4 codes name policy, credential, host-trust, delegation or cancellation states that do not apply). Its error data lists the inventory as it is now and `next_command: "heimdall uninstall"`; `next.action` stays the code's default. Golden `m03-reasons.golden.json` | `contract::envelope`, `heimdall::uninstall_cmd` |
| §17.28 item 1 (reason, §5 item 14) | `uninstall_remote_step_unresolved` → `CAPABILITY_UNAVAILABLE` (exit 4): under the fence a `--purge-state` finds an enrollment operation whose journal has a dispatched step without its result, or an uncertain mutation (remote effect unknown); it refuses, lifts the fence and deletes nothing. A reason of its own, not `uninstall_inventory_changed`: the inventory did not change since the confirmation, and the remedy differs (let the step finish or reconcile it, then run `heimdall uninstall` again). Error data lists `unresolved_steps` (operation IDs) and `next_command`. Golden `m03-reasons.golden.json` | `contract::envelope`, `app::operations::unresolved_remote_steps`, `heimdall::uninstall_cmd` |
| §17.31 items 1 and 6 (reason, §5 item 14) | `uninstall_shutdown_unconfirmed` → `SERVICE_UNAVAILABLE` (exit 5, retryable): a `--purge-state` whose runtime stop was not confirmed (the shutdown request failed, was refused, or its connection was lost), or whose instance lock a replacement runtime holds after the stop (Q-I-R8-1), reads and deletes nothing; the message names which case it was ("the runtime did not confirm its shutdown" / "a runtime started again while uninstall was running"); a lock I/O failure stays reasonless; effect `partial` (the rollback and the stop attempt happened). Error data carries `next_command` `heimdall service stop` and `next_step` "stop the runtime (`heimdall service stop`) or wait for it to stop, then run `heimdall uninstall` again". Golden `m03-reasons.golden.json` | `contract::envelope`, `heimdall::uninstall_cmd` |
| §17.33 items 1 and 9 (reason, §5 item 14) | `uninstall_fence_release_stuck` → `SERVICE_UNAVAILABLE` (exit 5, retryable): while an uninstall's fence is releasing past its bound (`RELEASE_WAIT`, 20 s) because work the uninstall started has not ended, every request the fence refuses gets this reason instead of `uninstall_in_progress` (before the bound, and for a fence that is simply held, it stays `uninstall_in_progress`); nothing is admitted or written; effect `none`. The message and error data name the way out: `next_command` `heimdall service stop` and `next_step` "stop the runtime (`heimdall service stop`), then start it again (`heimdall service run --detach`)" (the fence is never stored, so a restarted runtime has none). The named residual `uninstall_fence_release_stuck_until_holder_work_ends` (`heimdall_domain::claims::RESIDUALS`). Golden `m03-reasons.golden.json` | `contract::envelope`, `app::operations::uninstall_fence_m03`, `runtime::dispatch` |
| §17.35 item 7 (reason, §5 item 14; audit D1, D2) | `uninstall_quarantine_present` → `SERVICE_UNAVAILABLE` (exit 5): runtime start-up, after the instance lock and before it creates or opens the state database, finds in `<state>` an interrupted uninstall's quarantine (any `.hm-purge-*` entry) or a `-wal`, `-shm` or `-journal` without `state.db`, and refuses: no store is opened or created, so a log holding the only copy of commits is never discarded by a new database; effect `none`. The message names the exact paths (`display_path`) and the next step, `heimdall uninstall`, which first restores the quarantined database family under ADR-0008 §17.35 item 1's rule (or refuses, naming what it cannot restore). No residual. Golden `m03-reasons.golden.json` | `contract::envelope`, `runtime::service`, `heimdall::uninstall_cmd`, `heimdall::purge_sweep` |
| §17.36 item 1 (W5-H01, H02; no contract change) | **Removed:** `heimdall_store::Checkpointer` (ADR-0008 §17.35 items 2 and 6: the purge's read-write `PRAGMA wal_checkpoint(TRUNCATE)` on the quarantined family), which a hot rollback journal could make SQLite replay into the owner's pages. Nothing else used it. The purge never opens the original family read-write: its final read is read-only, and its recovery copy is `heimdall_store::Store::vacuum_into` (`VACUUM INTO` from that read-only connection, an additive workspace API). `uninstall_quarantine_present` (the row above) also covers a quarantine directory holding a recovery copy. No reason, code or schema changes | `store`, `heimdall::purge_sweep`, `heimdall::uninstall_cmd` |
| §17.28 item 5 (reason, §5 item 14) | `issuer_executable_changed` → `SERVICE_UNAVAILABLE` (exit 5, retryable): an owner-present ceremony refuses to write a CA key store item when the running executable no longer matches the identity the item's access list would trust (its file was replaced: an update or a rebuild); nothing is stored. The message names the next step, "finish installing or updating Heimdall, then run the command again"; `next.action` stays the code's default. Golden `m03-reasons.golden.json` | `contract::envelope`, `issuer::store::StoreError::refusal_reason`, `issuer::ceremony` |
| §17.28 item 6 (reason, §5 item 14) | `issuer_store_access_denied` → `CAPABILITY_UNAVAILABLE` (exit 4, not retryable): the store is unlocked but its access list denies this executable a read of K_ca (macOS: `errSecAuthFailed` while the keychain's status reads unlocked; an ad-hoc-signed build after an update). The code of the other issuer store reasons: waiting does not help and the owner must act. Never `issuer_store_locked`, which stays the reason for a locked keychain or `errSecInteractionNotAllowed`. Reported by the issuer child's load (`issuer.status` `reason`), `issuer.unlock`, a refused activation, and the CLI's own store reads; the CLI's error data adds `next_command: "heimdall issuer restore --backup <file>"`. ⟨§17.28 item 7⟩ That restore writes the key to a **new** item with a distinct locator (macOS: same service, account `<environment>#r<n>`, the lowest free `n` ≤ 99, never overwriting), recorded through the attended `RegisterIssuer` with `expected_store_locator` the old one (the existing log-intact new-locator path); the old item stays in `orphan_store_items` (its locator names its service and account) for the owner to delete in Keychain Access, and Heimdall never deletes it. No wire change: `SecretStore` gains two defaulted methods (`get_item`, `put_new_item`), and the issuer child reads a CA's recorded item. Additive wire value `access_denied` of the `heimdall-issuer/1` `store_unavailable` reason (golden `issuer-protocol.json`; child and runtime are the same executable). Windows DPAPI and Linux Secret Service have no per-executable access list and do not report it. Golden `m03-reasons.golden.json` | `contract::envelope`, `issuer::store::{StoreAvailability, macos}`, `app::issuer::unlock_guidance`, `app::operations::issuer_m03`, `app::managed::driver`, `heimdall::issuer_cmd` |
| §17.28 item 6 (doctor finding, §5 item 14) | `finding::ISSUER_STORE_ACCESS_DENIED` (`issuer_store_access_denied`, severity `problem`, level `static`, subject kind `issuer`, `reason` the same, `next.action` `owner_decision`): added when a CA is registered and an already-running runtime's `issuer.status` reports `issuer_store_access_denied`. The doctor never starts the runtime and never reads K_ca, so with no runtime running it reports nothing. `finding::M03` gains it; golden `m03-reasons.golden.json` `doctor_findings` | `contract::doctor`, `heimdall::doctor_cmd` |
| §17.32 item 7 (Q-I-R10-1; Request) | `UninstallFenceRequest::RetryRemoteRevocations`, wire `{"op":"uninstall_fence","action":"retry_remote_revocations"}`, kind `uninstall_fence.retry_remote_revocations`, `Admission::Synchronous` (no operation row; each record's round is claimed and completed in that record, as the supervisor's are), capability `service-control/1`, owner role. **Holder only:** refused `SERVICE_UNAVAILABLE` (exit 5), effect `none`, nothing attempted, unless the connection holds the fence: reason `uninstall_in_progress` while another connection holds it (the fence's own non-holder answer), none when nobody does (no uninstall is in progress, so that reason would be false; no reason is added). Under the held fence, before the shutdown, it makes **exactly one** ordinary `retry_remote_revocation` round per pending remote revocation record with the supervisor's configured cap: an attempt is claimed (`attempts + 1`) only when an adapter call is owed; a stopped record is answered unchanged; a record at its cap is stopped with no call; it never re-arms (no count reset, no lifted stop). Answer `OK {"remote_revocations": [{"root_grant", "outcome": "completed"\|"attempted_still_pending"\|"not_attempted"\|"failed", "attempts_before", "attempts_after", "stopped", "pending", "record"}]}`; ⟨§17.33 item 3 (W5-E01)⟩ additive `record`: the complete `PendingRemoteRevocation` as stored right after the round (`null` once gone), which uninstall's final locked check admits byte for byte in the store's form and nothing else. `heimdall uninstall` sends it on its own session after `acquire`, lists what is still pending in the purge confirmation and the report (`pending_remote_revocations`, `remote_revocation_retries`), covered by the typed confirmation, and refuses a purge only when the request itself failed. Golden `journaled-kinds.golden.json` (synchronous); schemas `request.schema.json`, `ipc.client-message.schema.json` | `contract::request`, `runtime::dispatch`, `app::operations::uninstall_fence_m03`, `heimdall::uninstall_cmd` |
| §17.29 item 2 (reason, §5 item 14) | `late_write_present` → `CONFIG_CONFLICT` (exit 6, not retryable): an attended `enroll verify <enrollment> --absence` run after the `late_write` residual's not-after (on the destination's clock), with no lock of the uncertain step and a readable registry, observed the enrollment's marker line **present**: the uncertain append landed and trust of ours remains, whatever the record's state. A definite result, not `verification_inconclusive` (which stays the reason of an inconclusive or failed check). The code of the other "the destination's registry holds a line the owner must have removed" reasons (`registry_line_damaged`, `registry_not_rewritable`, `already_enrolled`): retrying the check cannot change it, a removal can; `CAPABILITY_UNAVAILABLE` is the verification classes' code, for what the check could not establish. The residual is kept; nothing remote changes. The message names, and the CLI's error data adds, `next_command: "heimdall enroll remove <enrollment>"`; `next.action` stays the code's default. Golden `m03-reasons.golden.json` | `contract::envelope`, `app::operations::enrollment_m03::verify`, `heimdall::enroll_cmd` |

## 17. ⟨rev5⟩ Revision 5 (joint wave 0 of M04 and M05)

Revision 5 is **one** revision carrying both tracks' wave-0 contract deltas (ADR-0010 §9
item 9, ADR-0011 §10 items 5 and 10): `docs/architecture/m04-plan.md` §5 and
`docs/architecture/m05-plan.md` §4, as amended by the two rulings, which win where a plan
differs. The orchestrator owns it (ADR-0009 §2.6); this text is the integrator's draft for
that approval, and §17.6 lists what is put to the owner rather than decided here.

Schema major stays `"1"` (§9): every change is additive. Every new field is
`#[serde(default)]` and omitted when it carries no value, so every M01–M03 document,
stored record, request hash and golden is byte-identical (§17.4). The code table stays at
**30 rows**: the tracks add reasons (`reason::M04`, `reason::M05`, and M03's follow-up
`reason::M03_REV5`), never codes. Wave 0
lands types, wire forms and the fail-closed landing only:

* the capabilities `environments/1` and `trusted-work/1` are **declared and not offered**
  (`capability::REVISION_5_DECLARED`; `ipc::session` and `inspect capabilities` list
  neither), and each revision-5 request form names its capability in
  `Request::required_capability`, so a session that did not negotiate it gets
  `SCHEMA_UNSUPPORTED` and a runtime that does not know a form refuses it instead of
  ignoring an unknown field;
* every revision-5 request form reached in process answers `CAPABILITY_UNAVAILABLE` with
  reason `driver_unavailable` **before any record is written**, a decision record
  included (after an owner-role refusal for `Request::Environment`);
* the two new decision kinds, and a `WidenPolicy` carrying a revision-5 action, are
  refused and not consumed;
* the CLI's new commands and flags answer M01's "not available in this build" envelope
  (16.2 item 6) with "(planned for M04)" or "(planned for M05)".

The two semantic changes of the revision **are** implemented: the managed-environment
seam (§17.2) and policy resolution by context (§17.3).

### 17.1 Deltas (plan item → what landed → where)

**M04** (`m04-plan.md` §5, ADR-0010 §9):

| Item | What landed | Where |
|---|---|---|
| 1 | capability `environments/1` (`ENVIRONMENTS_V1`), declared, not offered | `contract::ipc::capability` |
| 2 | `Request::Environment(EnvironmentRequest)`: `wsl_enable {distribution_guid, account, mode_a, mode_b}`, `wsl_disable {distribution_guid, start}` (`start`: ADR-0010 §9 item 2's explicit authorized start), `container_add {label}`, `container_remove {environment_id}`; kinds `environment.*`; `Admission::Synchronous` (decision-recorded or setup-confirmed, no operation row, no request ID: the `issuer.register` pattern); capability `environments/1`; `DistributionGuid` (canonical `8-4-4-4-12` lowercase hex, validated on decode). The dispatcher refuses a non-owner, then `driver_unavailable` | `contract::environment`, `contract::request`, `runtime::dispatch` |
| 3 | setup items `ProjectionItem::{LoginEntry, DistributionGit, DistributionProjection}`; `PreviewIntent::Apply.{items, distribution}` and `PreviewIntent::Rollback.distribution` (omitted when empty: every M02/M03 intent and plan digest unchanged); a preview naming one is refused `driver_unavailable` | `contract::setup`, `app::setup` |
| 4 | `EnvironmentsView {items: [EnvironmentView {environment_id, kind, label, state, realization}]}`, `EnvironmentKindView`, `EnvironmentState` (`active`, `not_running`, `removed`, `gone`), `RealizationView` (`native`, `wsl {name, guid, account, modes, helper}`, `container {label, directory, in_container_path}`), `WslMode`, `HelperState`; schema `inspect-environments`. Types only: `inspect environments` keeps its M01 answer until M04 fills it | `contract::environment`, `schemas/public-api` |
| 5 | `ConsumerIntegration.realization: RealizationDescriptor {environment_kind, endpoint, config, mount: MountSpec {source, target, read_only}, environment}` | `contract::request`, `contract::environment` |
| 6 | `PairIntegration.{route: RouteView {jump, jump_alias, jump_access: managed \| existing}, agent_forwarding}` (omitted when absent/false); `DestinationDefinitionSpec::Managed.jump` and the domain `DestinationDefinition::Managed.jump` (serde default `None`); a catalog upsert naming a jump is refused `driver_unavailable` | `contract::request`, `contract::catalog`, `domain::catalog`, `app::catalog` |
| 7 | `ReadinessCondition::{WslDistributionRunning, RouteDependency}`; `LoginStartView {kind: run_value \| launch_agent \| systemd_user \| none, installed}` (type; `inspect capabilities` unchanged until M04 U1) | `contract::managed`, `contract::environment` |
| 8 | `reason::M04`: 12 reasons with codes (§17.6 R5-Q4); golden `tests/contracts/golden/rev5-reasons.golden.json` | `contract::envelope` |
| 9 | Schema version: major `"1"`, no bump. Only the major is carried (§9), so the plan's "minor bump" has no carrier | `contract::version` |
| domain, store | `EnvironmentRealization` (`wsl {guid, name, account}`, `container {label, dir_tag}`), `ManagedState`, `ManagedEnvironment {environment, controller, realization, state, ...}`, `admit_environment`, `EnvironmentAdmission`, `WslDistributionRecord`, `ResourceKind::LoginEntry`; migration `0007_platform_realization` (`managed_environments`, `wsl_distributions`), `SCHEMA_VERSION` 7, `store::ext_m04`; app port `SignerEndpoint::ManagedEnvironment(EnvironmentId)` | `domain::{environment, resource}`, `store`, `app::ports` |
| I-9 (M04 wave 1 review-fix round; the contract owner's ruling of 2026-11-18) | `doctor::finding::M04` = `git_client_cannot_reach_pipe` (doctor, `info`; also the reason of that name, R5-Q4) and `login_entry` (the login entry's setup-plan finding); `finding::M04_REASONS` = the `login_entry` finding's sub-reasons `on_demand` and `login_entry_conflict`; [`finding::ALL`] and `finding::M03` unchanged; golden `rev5-reasons.golden.json` keys `m04_doctor_findings` and `m04_finding_reasons` (`contracts::rev5::rev5_reason_golden`). Additive: no code, schema or earlier finding changes | `contract::doctor`, `localenv::doctor`, `app::operations::login_entry_m04` |

**M03** (the M03 exit suite, wave 6 question I-8(2); additive, carried by this revision):

| Item | What landed | Where |
|---|---|---|
| I-8(2) | Reason `issuer_refused` → `CAPABILITY_UNAVAILABLE` (exit 4, not retryable), in a list of its own, `reason::M03_REV5` (`reason::M03` and its golden stay M03's record); golden `rev5-reasons.golden.json` key `m03`. `run_verification` maps the issuer's answer when it does not sign a verification certificate (`sign_error`): a **refusal** by a running issuer (`ceiling_exceeded`, `subject_mismatch`, `entry_stale`, `entry_not_reserved`, `ca_not_loaded`, a predicate) is `issuer_refused`, naming the refusal in the message; `rate_limited` is the existing `issuer_rate_limited` (`BACKPRESSURE`, retryable); an issuer that is not running, locked, restarting, silent or garbled stays `issuer_unavailable`. Before, every one of these was `issuer_unavailable`. The voided entry's recorded reason is unchanged (`operation_not_verifying`), and what a run that never reached a login records (`unclassified`) is M03 wave 6's. Regression: `issuer_refusal_of_a_verification_certificate_is_not_issuer_unavailable` | `contract::envelope`, `app::operations::enrollment_m03::verify` |

**M05** (`m05-plan.md` §4, ADR-0011 §10):

| Item | What landed | Where |
|---|---|---|
| 1 | `EnsureRequest.{profile: Option, context: Option<WorkContext {cwd}>, covered_only}`: `profile` may be absent only with `context`; `WorkContext` (absolute, ≤ 4 KiB, no NUL); `EnsureRequest::uses_m05_form`; the hash rule of §17.4 | `contract::request`, `contract::trust`, `app::operations` |
| 2 | `PolicyAction`: `pause`, `resume`, `cutoff`, `clear_cutoff` take `policy_id` **or** `target: PolicyTarget` (`policy`, `profile`, `workspace`, `all`), exactly one (`selector_ok`; otherwise `USAGE_ERROR`); new `create {profile, environments, max_window, default}`, `extend_scope {policy_id, pairs, capabilities, environments, background_work}`, `narrow_scope {policy_id, pairs}`, `set_max_window {policy_id, max_window}`, `remove {policy_id}`, `trust_workspace {cwd, access_digest, proposal: TrustProposal}`, `reconcile_workspace {workspace, cwd}`, `stop {target}`; `is_widening` extended (the new widening ones, and `set_max_window`, which the request alone cannot classify); `is_m05`, `policy_id()` | `contract::request`, `contract::trust`, `app::operations` |
| 3 | `RevokeRequest.{grant_id: Option, target: Option<RevokeTarget::Work {environment, work_id}>}`, exactly one | `contract::request`, `contract::trust` |
| 4 | `CatalogRequest::ApplyImport {bundle: PortableBundle, request_id}` (action `apply_import`, journaled `catalog`, owner only, no decision) | `contract::catalog`, `contract::project` |
| 5 | `InspectSubject::{Workspace, Policies, Export}` with `InspectRequest.{cwd, redact}` (the subjects stay strings on the wire; §17.6 R5-Q6); schemas `inspect-workspace`, `inspect-policies` | `contract::request`, `contract::trust` |
| 6 | `DecisionKind::{TrustWorkspace {action, project_label, lock_disclosure}, ReconcileWorkspace {action, why}}`, `DecisionKind::is_m05`; `WidenPolicy` carries the new widening actions | `domain::decision` |
| 7 | `EnsureData.{context: ContextReport {kind, workspace_id, policy_id, policy_revision, provenance}, uncovered}`; `Enforcement.{ordinary_aliases, owner_functions}` (read `unknown` when absent); `GrantOrigin.{workspace, policy_id}` and `ResolvedIntent.workspace` (stored; absent: personal); `bindings.context_json` (`BindingContext`); `WorkspaceView`, `PoliciesView` | `contract::{request, trust}`, `domain::{grant, operation, workspace}`, `store::ext_m05` |
| 8 | `EventType::Activation`, payload `ActivationEventPayload {kind: activated \| blocked \| not_covered, environment_id, policy_id, workspace_id, reason}`; not emitted in wave 0 | `contract::event`, `contract::trust` |
| 9 | `reason::M05`: 10 reasons, 13 rows (a reason the plan gives two codes by attendance has one row per code); `m05_warning::SLOT_SHARED`; `NextAction.groups: [MechanismGroup {mechanism, pairs}]` for `mixed_mechanisms` | `contract::envelope` |
| 10 | capability `trusted-work/1` (`TRUSTED_WORK_V1`), declared, not offered; required by every revision-5 request form | `contract::ipc::capability`, `contract::request` |
| 11 | `schemas/project/manifest.schema.json` (`contract::project::Manifest`: closed, `deny_unknown_fields`) and `schemas/project/portable.schema.json` (`PortableBundle`), written by `heimdall schema export --project-out` and diffed by `check.sh`; outside the public API's unknown-field tolerance and keyword check, because the manifest is a closed file format, not a wire message | `contract::{project, schema}`, `heimdall::cli`, `tools/validation/check.sh` |
| 12 | migration `0008_trusted_work` (`workspaces`, `policy_history`, `decision_cooldowns`, `work_stops`, `slot_references`, `bindings.context_json`), `SCHEMA_VERSION` 8, `store::ext_m05` (accessors in full); domain `workspace` (`WorkspaceRecord`, `WorkspaceMatch`, `AmbiguityReason`, `PolicyHistoryEntry`, `DecisionCooldown`, `WorkStop`, `SlotReference`, `BindingContext`) | `store`, `domain::workspace` |

Examples (each round-trips and validates; `tests/contracts/rev5.rs`):
`request.environment.{wsl-enable,wsl-disable,container-add,container-remove}`,
`request.catalog.apply-import`, `request.ensure.context`, `request.revoke.work`,
`request.policy.{pause-target,trust-workspace}`, `request.inspect.workspace`,
`inspect.{environments,workspace,policies}`, `project-manifest`. Goldens:
`rev5-reasons.golden.json`, `journaled-kinds.golden.json` (the four `environment.*`
kinds synchronous), the CLI help goldens the new commands change.

### 17.2 The managed-environment seam (ADR-0010 §9 item 1)

1. **The set.** A runtime manages its own environment (`OperationsConfig.environment`,
   the store's `self_environment`) and every `managed_environments` row whose
   `controller` is that environment and whose state is `active` or `not_running`. A row
   is never re-added; `removed` and `gone` rows stay as removed identities.
2. **Admission replaces equality.** Every M01–M03 `target == own` check is replaced by
   one admission (`domain::environment::admit_environment`, read in the caller's
   transaction through `app::environments::admit`), never deleted: `ensure`, resolution,
   `LoadAuthority`, re-validation, `activation_refusal`, the issuance check (the
   issuer's independent check runs the same predicate), restart recovery, `bind`,
   `delegate` (whose child is pinned to its parent binding's environment), signature
   authorization, owned-connection registration and the event snapshot. An unmanaged
   target is `NOT_FOUND` (M01's message, no reason); a removed one is `NOT_FOUND` with
   reason `environment_removed`. Nothing is written for either.
3. **Controller and execution environment stay distinct.** The caller's principal never
   names an environment; a work operation is recorded in its **target** environment
   (`operations.environment`), as are its grant and binding. Setup admissions stay in
   the runtime's own environment.
4. **Per environment.** Policies, the environment record and work deadlines are read
   for the target or the grant's own environment. Slot rows were already keyed by
   environment; slot files now live under each environment's own root
   (`ManagedEffectsImpl::with_slot_root`) and the signer keeps one listing per
   environment (`SignerEndpoint::ManagedEnvironment`); the native environment endpoint
   never lists another environment's slot. A slot write takes the binding's environment
   from its stored row (`SlotStore::binding_environment`), a clear takes the slot row's.
   Recovery and cleanup iterate the managed set.
5. **Leaving the set.** `Operations::retire_managed_environment(env, removed | gone)`
   moves the row (and the authority generation); re-validation then classifies the
   environment's grants as **withdrawn**, so they end through the existing withdrawal
   path and each grant's own cleanup (endpoints, files and slots of that environment,
   by generation) runs. An environment this runtime never managed stays undetermined
   (refused, ends nothing), as in M01.
6. **The issuance key ID** keeps naming the issuing runtime's environment
   (`heimdall:<own environment>:<grant>:<serial>`), which the issuer child's ceiling
   check compares with its store's environment; the grant's own environment is checked
   by the issuance predicate (item 2).

### 17.3 Policy resolution by context (ADR-0011 §10 item 1; replaces §13.6 item 5)

A resolution names a **context**: `PolicyContext::Personal`, or
`PolicyContext::Workspace(id)` for an observation the project crate matched as `Trusted`
or `Member` of that workspace (`PolicyContext::of_match`; `Untrusted` and `Ambiguous`,
including a re-clone at the same path, are personal). The applicable policies are
(`domain::policy::applicable_policies`):

* in `Personal`: the personal policies (`workspace: None`) only;
* in `Workspace(id)`: that workspace's policies first, then the personal ones; with no
  policy of that workspace for the profile, the personal ones alone.

Scope, window and revision come from the first applicable policy (several policies of
one context, which production never creates, keep §13.6's first-by-ID among
themselves); any pause, the earliest cutoff and the strictest lock behaviour and
connection policy are merged fail closed over every applicable policy
(`resolve_policy`). So a workspace policy never supplies personal scope or reaches
another workspace; a personal pause or cutoff stops that profile's workspace work; a
workspace's pause, cutoff, scope or lock behaviour never reaches personal work. With no
applicable policy the request needs an owner decision, never another context's policy.

Every path resolves in its own context: `ensure` and `run` from the request (personal
until M05 U4 resolves `context`), re-validation, renewal and issuance from the grant's
recorded context (`GrantOrigin.workspace`), `activation_refusal` from the intent's
(`ResolvedIntent.workspace`), delegation from its parent grant's, the lock and
connection terms from the grant's, and pair-level rendering of ordinary aliases
(environment-level, ADR-0011 §5.2) from the personal context, as ordinary `ssh` and the
shell hook will. The narrowing set of a policy action contains only the grants that
policy applies to. §13.6 item 5's other rules stand: any change to an applicable policy
moves the generation; the store keeps no one-policy-per-pair constraint.

### 17.4 The ensure hash (ADR-0011 §10 item 5)

The revision-5 extras (`context`, `covered_only`, the resolved workspace and access
digest) enter the canonical `ensure` hash's `extra` **only when `context` is present**
(`app::operations::pair_mechanism_m03::ensure_hash_extra`). A request without `context`
hashes exactly as in M03 (`null`, or `{"connection": …}`), so an in-flight M01–M03
request replays and every recorded hash stands. Proven against the existing vectors:
the byte-identity goldens `tests/contracts/golden/m02-existing-access-ensure/`
(`request-hash.txt`, `intent.json`, `result.json`, `envelope.json`; `e2e_consumer_m03`),
`model_operations_m03::connection_absent_hash_unchanged_from_m02` and
`strict_request_hash_differs`, and the pure rule's unit test
(`revision_5_extras_enter_the_ensure_hash_only_with_context`). With `context`, the same
request ID with a different resolved workspace or digest is `REQUEST_CONFLICT` (M05 U2
extends the idempotency property, ADR-0011 §10 item 7).

### 17.5 Readings applied where the design is silent (pending the owner's confirmation)

1. **Inspect parameters on the request.** `workspace` and `export` are unit subjects;
   their parameters are `InspectRequest.{cwd, redact}`, so subjects stay strings and the
   request stays tolerant of unknown fields (a data-carrying subject variant would be an
   object the public schema closes).
2. **Optional `policy_id` and `grant_id`.** The targeted forms make `policy_id` (four
   policy actions) and `grant_id` (`revoke`) optional on the type, with "exactly one"
   checked by the application before anything is written; every M01–M03 wire form is
   unchanged.
3. **Environment requests carry no request ID** (the `issuer.register` pattern: one
   pending decision per action, coalesced).
4. **Context records.** The context a grant, an intent and a binding pin is recorded as
   `GrantOrigin.workspace`, `ResolvedIntent.workspace` and `bindings.context_json`; the
   grant origin's `policy_id` is declared and left for M05 (U2/U6) to fill, so every
   stored M01–M03 origin and intent is unchanged.
5. **The personal default** (`create {default}`) has no `StandingPolicy` field yet:
   where "at most one per environment" is recorded is M05 U5's.
6. **Removed versus unmanaged.** A removed environment's grants are withdrawn (§17.2
   item 5); an environment never managed stays undetermined, as in M01.
7. **Recovery classes** (ADR-0008 §17.32): `managed_environments`, `wsl_distributions`
   and `workspaces` are `Rows`; `policy_history`, `decision_cooldowns`, `work_stops` and
   `slot_references` are `Discarded`; the two new decision kinds are excluded from the
   purge snapshot (local trust decisions).

### 17.6 The contract owner's rulings (2026-11-16)

The orchestrator owns revision 5 (ADR-0010 §9 item 9, ADR-0011 §10 item 10). These rulings settle wave 0's questions, and the readings in §17.5 stand as confirmed.

1. **R5-Q1, option (a): `covered_only` requires `context`,** and a request without it gets `USAGE_ERROR`. That keeps a `covered_only` request from ever sharing a hash with a request that doesn't carry it. Ordinary-`ssh` activation (M05 U5) uses an internal path, not a client `EnsureRequest`. M05 U2 implements the refusal.
2. **R5-Q2:** the draft's encoding is accepted. That is three `ProjectionItem` unit variants (`login_entry`, `distribution_git`, `distribution_projection`), `PreviewIntent::Apply.items`, and `distribution` on `Apply` and `Rollback`, each left out when empty, so every M02/M03 intent and plan digest is unchanged. A change the M04 track needs while building on it comes back to the contract owner.
3. **R5-Q3:** the draft's `PolicyAction` shapes are accepted:
   - `create.max_window` is a duration string;
   - `extend_scope` is `{pairs, capabilities, environments, background_work}`, and `narrow_scope` is `{pairs}`;
   - `trust_workspace.proposal` is a `TrustProposal`, fixed when the decision is created;
   - the request-only predicate treats `set_max_window` as a widening;
   - `stop` takes `{target}`.
4. **R5-Q4:** the draft's codes for the M04 reasons are accepted. `git_client_cannot_reach_pipe` is also a doctor finding (ADR-0010 §1 item 5), which M04 U2 adds.
5. **R5-Q5:** `inspect-environments`, `inspect-workspace` and `inspect-policies` are published in `schemas/public-api/`. They are new typed results, and publishing them lets a caller validate without knowing the implementation.
6. **R5-Q6:** subjects stay strings, and `cwd` and `redact` sit on `InspectRequest`, keeping §9's closed-schema tolerance rule.
7. **R5-Q7:** confirmed. Each revision-5 form requires its capability (`trusted-work/1`, `environments/1`), so a runtime that doesn't offer one answers `SCHEMA_UNSUPPORTED` rather than ignoring a field it doesn't know.
8. **R5-Q8:** confirmed. `Ambiguous` and `Untrusted` resolve to the personal context. The old workspace scope is out of reach, and the rest gets a `ReconcileWorkspace` decision (M05 U4).
9. **R5-Q9:** confirmed, failing closed. A personal policy's stricter lock behaviour and connection policy apply to that profile's workspace work. A workspace's never reach personal work or another workspace. This is consistent with ADR-0011 §10 item 1 (a personal pause or cutoff applies to workspace work) and item 2 (activation uses the recorded lock behaviour, never the manifest's).
10. **R5-Q10:** the draft is kept. Within one context, the first policy by ID gives the scope, and blocks are merged across all of them. Both policies were created by the owner, so no scope beyond the owner's approval is reachable. Production creates only one.
11. **R5-Q11:** confirmed. `operations.environment` is the target environment. Events and setup admissions stay with the runtime's own environment.
12. **R5-Q12:** confirmed. The key ID keeps the issuing runtime's environment (`heimdall:<own>:<grant>:<serial>`), and the issuance predicate checks the grant's environment.
13. **R5-Q13:** confirmed. `retire_managed_environment` withdraws that environment's grants (a tombstone, `revoking`, then `revoked`) and runs its per-environment cleanup. M04's `container remove` and `wsl disable` call it.
14. **The CLI shapes of `access allow` and `access stop`** are provisional. M05 U2 and U3 set their final syntax and add the help goldens when the commands become available.
15. **An issuer's `rate_limited` refusal** of a verification certificate maps to the existing `issuer_rate_limited`, not to `issuer_refused`.
16. **S-Q2 (M05 U0b):** the 2 s budget stands on macOS and Linux, which both waited 65 s for a delayed identities answer. Windows is decided by the PC run (S-Q1).
17. **ST-Q1 and ST-Q2:** confirmed. A workspace record goes only from `active` to `stale`, and a reconcile writes a new record. `set_binding_context` is set-once and idempotent.

### 17.7 Proofs

* **The seam (§17.2):** `managed_store::live_tests::pipeline::two_environments_ensure_issue_bind_sign_restart_unmanaged_refused_cleanup_isolated`
  (heimdall-runtime), extending the existing re-issue-after-restart test: the real
  ensure → issue → bind → sign (system `ssh` against a loopback `sshd`) → restart →
  re-issue path in two environments, an unmanaged environment refused with nothing
  written, and one environment's cleanup leaving the other usable; plus
  `integration_store_m04_m05::managed_environment_admission_terminal_states_and_generation`.
* **Resolution (§17.3):** `model_authority::two_policy_trace_resolution_is_by_context_never_by_id`
  (ADR-0011 §10 item 1's two-policy trace, 512 cases) and, through the application,
  `model_operations::personal_resolution_ignores_a_workspace_policy_that_sorts_first`.
* **Revert proofs** (the test fails with the change reverted, passes restored; outputs in
  `tests/evidence/artifacts/m04m05-w0/`): resolution reverted to first-by-ID (both
  resolution tests fail); the environment check deleted without its replacement, and slot
  cleanup reverted to one namespace (the live test fails each time).
* **I-8(2):** `heimdall-app` unit test
  `operations::enrollment_m03::verify::tests::issuer_refusal_of_a_verification_certificate_is_not_issuer_unavailable`
  (every issuer answer to a verification certificate → its code and reason).
* **The landing:** `integration_runtime_m03::w0_revision_5_requests_fail_closed_before_any_record`
  (every revision-5 request form, one table) and `e2e_cli_m04_m05` (every new command
  and flag, one table).
* **The wave's independent review** (`tests/evidence/artifacts/review-m04m05/w0.md`) and its
  fixes, each with a regression in `model_operations` unless named:
  1. **W0-R01 (blocking):** a new grant's origin records the lock behaviour of the
     policies of **its own context** only, as its connection policy already did (R5-Q9):
     `w0_r01_workspace_lock_behavior_never_reaches_a_personal_grant`, with a revert proof
     (`tests/evidence/artifacts/m04m05-w0/revert-w0-r01-lock-origin.json`).
  2. **W0-R02:** the lock disclosure and `inspect capabilities` describe the runtime's
     general lock behaviour from the personal policies only:
     `w0_r02_lock_disclosure_reads_only_personal_policies`.
  3. **W0-R03:** `delegate` admits its parent binding's environment before anything is
     written, and its hash and work spec name that environment, so equal delegations in a
     managed environment coalesce (`own` for every M01–M03 delegation, whose hashes are
     unchanged): `w0_r03a_delegate_in_a_removed_environment_writes_nothing`,
     `w0_r03b_equal_delegations_in_a_managed_environment_coalesce`.
  4. **W0-R04:** `Request::required_capability` also names `trusted-work/1` for
     `apply_import` and for `cwd` or `redact` on any inspect subject, and
     `environments/1` for a destination with a `jump` and a setup preview of an M04 item
     or distribution (`contracts::rev5::rev5_capabilities_declared_not_offered_and_required`);
     in process, `inspect` refuses `cwd` and `redact` on an M01–M03 subject
     `driver_unavailable` instead of ignoring them (two rows of the landing table).

### 17.8 Not in wave 0

* Serving any revision-5 request form; offering `environments/1` or `trusted-work/1`.
* The realizations: WSL discovery, the helper and its channel (`heimdall-wsl/1`, whose
  file-operation protocol ADR-0010 §9 item 2 governs), Mode A and B, container
  directories and endpoints, routes and forwarding, login entries, time sync (M04 U1–U6).
* Workspace discovery, observation and matching, manifests and bundles (`heimdall-project`,
  M05 U1), trust and policy actions, coalescing and cooldowns, stop and targets, context
  activation and the shell hook, ordinary-`ssh` activation, slot references, export and
  import, delegation labels (M05 U2–U9).

### 17.9 Revision 5.1 (M05 wave 2)

*Approved by the contract owner on 2026-11-18, with M05 wave 2 (orchestrator ruling I-6; M05
U7; the "revision 5.1" delta items `dry_run`, the closed bundle, C1 and C2). Additive on revision 5, gated on
`trusted-work/1`: every revision-5 document, stored record, request hash and golden is
byte-identical (see "Byte identity" below), the code table stays at 30 rows, and the schema
major stays `"1"` (§9).*

| Item | What landed | Where |
|---|---|---|
| 13 | `CatalogRequest::SetDefaultProfile {environment?, profile, request_id}` (action `set_default_profile`): sets or clears an environment's **default-profile preference** (ADR-0011 §5.1). `environment` is omitted when absent (the runtime's own); `profile` is always written, `null` clears (a missing `profile` reads as `null`). Owner only, no decision, journaled under kind `catalog` (idempotent by `request_id`; the action is in the idempotency extras), `Admission::Journaled("catalog")`, capability `trusted-work/1` (`Request::required_capability`). Not widening: `is_widening_policy_action` is false | `contract::{catalog, request}`, `domain::catalog` (`CatalogAction::SetDefaultProfile`), `app::catalog` |
| 14 | `PoliciesView.default_profiles: [DefaultProfileView {environment_id, profile_id}]`, ordered by environment ID, one per managed environment that has a preference; omitted when empty, so `inspect policies` is byte-identical until one is set. Schema `inspect-policies` regenerated | `contract::trust`, `schemas/public-api` |
| 15 | `apply_import` and `inspect export` are served (no wire change): the shapes below | `app::operations::portable_m05` |
| 16 | `CatalogRequest::ApplyImport.dry_run: bool` (default false, omitted when false): validates the bundle exactly as a real import does, computes the plan and answers it **marked as a dry run, writing nothing**. A read: no catalog row, operation, idempotency, event or journal record (the request ID is not consulted, so the same ID can then import for real). Owner only (`CAPABILITY_UNAVAILABLE` otherwise) and gated on `trusted-work/1` through the same `Request::required_capability` arm as a real import; a real import's result and hash are unchanged | `contract::catalog`, `app::catalog` (`Operations::catalog`), `app::operations::portable_m05::dry_run` |
| 17 | **The portable bundle is closed:** `#[serde(deny_unknown_fields)]` on `PortableBundle`, `PortableDestination`, `PortableIdentity` and `PortableProfile`. A request that carries a bundle with an unknown or authority-bearing key at any level (`policies`, `trust`, `grants`, `policy`, ...) no longer decodes, as the file path (`heimdall_project::parse_bundle`) already refused it. A request that fails to decode is answered by the session as a malformed frame: a `USAGE_ERROR` goodbye, the connection closed, before any handler runs, so nothing is written (and the refusal text never echoes the peer's bytes: `heimdall_ipc::session::parse_frame`). `schemas/project/portable.schema.json` is now closed (`additionalProperties: false` on the four types), and `request` and `ipc.client-message` carry the same four closed definitions | `contract::project`, `schemas/project`, `schemas/public-api` |
| 18 | **C1, the decision view of a targeted widening lists its policies.** A pending `WidenPolicy` record created by a targeted `resume`, `clear_cutoff` or a later `cutoff` with a `target` (U3) carries `policies: [PolicyRevisionRef {policy_id, revision}]` in its `inspect decisions` view, read from its decision basis (`DecisionBasis::Targeted`, fixed at creation, ADR-0011 I5): exactly the policies approval will apply, each at the revision it must still be at. Omitted for every other record (the key is absent, so every existing decision view is byte-identical). The decision view is an untyped JSON value with no published schema, so `PolicyRevisionRef` is the type and no schema changes | `contract::trust`, `app::operations` (`decision_view` call site in `inspect`), `app::operations::stop_m05::listed_policies` |
| 19 | **C2, a typed result for the targeted policy actions** (`pause`, `resume`, `cutoff`, `clear_cutoff` with a `target`, and `stop`): `PolicyTargetResult {target: PolicyTarget, changed, policies: [PolicyTargetEntry {policy_id, revision, paused, cutoff_at, changed}], revoked?}`. It is exactly what U3 returned as untyped JSON: `cutoff_at` is always written (`null` when none), `revoked` (the grants a `stop` revoked, cascade included) only for `stop`. U3's result is built through the type, so its JSON is byte-identical. Schema `policy-target-result` published in `schemas/public-api/`. The M01 single-policy result (`policy_id`) is unchanged | `contract::{trust, schema}`, `app::operations::stop_m05::targeted_view` |
| 20 | **Deferred to M07 (I-12, ruled 2026-11-18): the exported host-key fingerprint as a first-connect hint.** The fingerprint I-11.3 means is each destination's SSH **host key** fingerprint (algorithm and SHA-256) as the exporting installation knew it: not the destination ID, the CA fingerprint or a user key. Revision 5 already carries it (`PortableDestination.host_key_fingerprints`), and the `dry_run` plan (item 16) shows it for comparison; import then discards it, so an imported destination stays *observed* and no host key is ever trusted by an import (I4). The rest of the ruling — keeping the fingerprint as a hint, turning the owner's later attended host-trust confirmation into a one-step "matches what was exported", and refusing a mismatch at first connect — needs the export to read host keys from enrollment records (the catalog holds none) and the attended host-trust and known-hosts flows (`app/src/operations/enrollment_m03/*`, `localenv/src/known_hosts.rs`), which are M03's and M04's. It is not small, so under the ruling's own fallback it is **deferred to M07**, and no wire form changes for it in 5.1 | none |

Examples (each round-trips and validates; `tests/contracts/rev5.rs`):
`request.catalog.set-default-profile`, `request.catalog.apply-import.dry-run`,
`inspect.policies.default-profile`, `policy-target-result`. Golden:
`tests/contracts/golden/rev5-1.golden.json` (the four `set_default_profile` request forms,
the capability, the kind, the view; the `dry_run` forms; the unknown key at each level of
the bundle; the three shapes of `PolicyTargetResult`; the C1 policy list). Schemas
regenerated by `heimdall schema export` (`request`, `ipc.client-message`,
`inspect-policies`, `portable`; new: `policy-target-result`).

**Capability gating.** Nothing here adds a capability. `dry_run` rides on `apply_import`,
which `Request::required_capability` already names `trusted-work/1`; the closed bundle is
the same request; C1 is a field of `inspect decisions`, which an owner already reads; C2 is
the result of `policy` actions whose targeted forms already require `trusted-work/1`. A
session that did not negotiate `trusted-work/1` gets `SCHEMA_UNSUPPORTED` for the request
forms exactly as before, and the capability stays declared and not offered until the wave's
gate.

**Byte identity.** Every new field is `#[serde(default, skip_serializing_if = ...)]`
(`dry_run` when false, `revoked` when `None`, the decision view's `policies` when the record
has no targeted basis); `PolicyTargetEntry.cutoff_at` is the one field written as `null`
because U3's result always wrote it. Therefore every revision-5 request, hash, example,
golden and stored record is unchanged: the contract suite (`rev5_m01_m03_forms_unchanged`,
`rev5_examples_round_trip_and_validate`, the `schema` check of `tools/validation/check.sh`)
passes with no existing example or golden changed (U7's own `rev5-1.golden.json` gains
keys, nothing is removed), `apply_import` re-encodes without
`dry_run`, and the existing U3 journeys (`e2e_stop_m05`, `model_precedence_m05`) pass
unchanged on the typed result. The only schema text that changes is the regenerated
`request`, `ipc.client-message`, `inspect-policies` and `portable` documents, which gain
the new fields and the four closed definitions, and the new `policy-target-result`. The
contract suite's own validators change with the closure: the in-tree validator
(`tests/contracts/jsonschema_lite.rs`) supports `additionalProperties: false` (it used to
reject the keyword outright, as the tolerance rule), and the keyword check moves the
tolerance rule to an explicit allowlist (below).

**Why the bundle is closed although public requests tolerate unknown fields (§9).** §9's
tolerance exists so that an older reader accepts a newer writer's additive fields. The
portable bundle is not a wire message of that kind: it is a **file format** (ADR-0011 I4)
that is written once, carried between installations and read by an importer that never
trusts its contents, and the manifest is closed for the same reason (item 11). An unknown
key in it is either a future field the importer cannot apply, which it must say so rather
than drop, or an authority claim it must refuse, so the bundle fails whole on both paths:
the file path already did, and `deny_unknown_fields` makes the request path do the same
instead of silently ignoring a key (question 2 of the first draft). The closure is the
four named definitions only: the public-API keyword check
(`schema_export::public_schemas_tolerate_unknown_fields_except_the_closed_bundle_types`)
allows `additionalProperties: false` at exactly those definitions of `request` and
`ipc.client-message`, and nowhere else, and the in-tree validator checks it there.

**Proofs.** Contract: `rev5::rev5_1_dry_run_closed_bundle_and_typed_results` (`dry_run`
omitted when false and written when true, both gated on `trusted-work/1`; an unknown key
at each of the four bundle levels makes the request undecodable and the `portable` schema is
closed at each; `PolicyTargetResult` and the C1 list round-trip and the result validates
against its schema), `rev5::rev5_examples_round_trip_and_validate` (the two new examples),
`schema_export::public_schemas_tolerate_unknown_fields_except_the_closed_bundle_types`,
`schema_export::checked_in_public_api_matches_the_model_exactly` and
`checked_in_project_schemas_match_the_model_exactly` (the regenerated schemas).
Application (`integration_portable`): `dry_run_writes_nothing_and_shows_the_plan` (every
table's row count, the catalog and the authority tables identical before and after; the plan
lists adds, an alias and a content conflict, the identity needing a local adoption and every
exported host-key fingerprint; a following real import under the same request ID applies
exactly that plan; a bad bundle and a non-owner are refused) and
`a_bundle_with_an_authority_section_is_refused_on_the_request_path` (six hostile bundles:
the session's decode refuses each and nothing is written). Journeys (`e2e_stop_m05`):
`a_targeted_widenings_decision_view_lists_its_policies` (C1; a single-policy `resume` has no
`policies` key) and `targeted_results_decode_into_the_typed_result` (C2: `pause`, `cutoff`
and `stop` results decode into the type and re-encode to the same bytes, and only `stop`
carries `revoked`); U3's targeted journeys pass unchanged.

**Semantics (no ruling needed; stated for the record).**

1. **Set.** The profile must exist in the catalog (`NOT_FOUND` otherwise) and the
   environment must be in the runtime's managed set (§17.2: `NOT_FOUND`, reason
   `environment_removed` for a removed one); a refusal settles the operation `failed`,
   effect `none`, and writes nothing. Success answers `{environment_id, profile_id}`
   (`profile_id` null when cleared). One transaction with the operation's settlement; no
   authority generation moves; a binding or grant pinned at activation never reads the
   preference (R-AU-03). Unlike a widening action it needs no safe time (it is classified
   with the narrowing catalog actions).
2. **`inspect export`** (`InspectRequest.redact`; `cwd` and `preview` are refused on this
   subject) answers a `PortableBundle` of the local catalog, owner role only
   (`CAPABILITY_UNAVAILABLE` for another role: an empty bundle would read as a real one).
   `identities[].provider` is `native_agent`, `onepassword` or `unknown` (a public-key file
   is no agent). `host_key_fingerprints` is empty: the catalog holds no host-key record, and
   a host key lives with an enrollment, which never travels.
3. **`catalog apply_import`** answers `{applied: {added, unchanged, conflicts,
   needs_local}, plan: [{kind, id, status, reason?, host_key_fingerprints?}], reestablish}`
   (an untyped result, like every catalog action's): `kind` is `destination`, `identity`
   (its fingerprint) or `profile`; `status` is `add` (written), `unchanged`, `conflict`
   (`reason`: `differs_locally`, `alias_collision`, `duplicate_in_bundle`, `invalid`; never
   applied) or `needs_local` (an identity reference with no adopted key here; nothing can be
   written for a fingerprint alone). A destination is added as an **observed** destination
   named by its alias (a bundle carries no link from a destination to an identity, which a
   managed one needs); a profile is added with the bundle's pairs and `ssh-authentication`.
   An existing record is never changed, so no profile, grant, binding or policy widens
   (spec §6.2). `reestablish` is the importer's fixed list, never the bundle's text. The
   bundle is validated like a file's bytes before admission (`USAGE_ERROR`, nothing
   written); exported host-key fingerprints are shown in the plan and trusted nowhere.
   With `dry_run` (item 16) the same validation and the same plan are answered as
   `{dry_run: true, would_apply: {added, unchanged, conflicts, needs_local}, plan, reestablish}`
   (the counts are `would_apply`, never `applied`, so a dry run cannot be mistaken for an
   applied import), with no operation ID, and nothing is written.

**Questions for the contract owner** (none blocks the draft; each is a possible later
revision):

1. **The host-key hint (item 20): settled, deferred to M07.** I-12 ruled that I-11.3 means the
   destination's SSH host-key fingerprint. Revision 5's `host_key_fingerprints` already carries
   it and the `dry_run` plan shows it. Keeping it as a first-connect hint touches M03's and M04's
   host-trust flows, so it waits for M07. An import still records an observed destination: the
   bundle has no link to a local identity.
2. **Authority sections over the wire: settled by item 17.** The first draft left the
   typed bundle open on the request path (serde ignored an unknown key) and offered
   `deny_unknown_fields` as the fix; the orchestrator accepted it.
3. **Import preview: settled by item 16.** `dry_run` is the read the CLI's preview (wave 3)
   uses; no new `inspect` subject.
4. **Default-profile reads for an unmanaged environment** are refused like every other
   request naming one; `default_profiles` lists the managed set only.

### 17.10 Revision 5.2 (M05 wave 3)

*Approved by the contract owner on 2026-11-18, with M05 wave 3 (orchestrator ruling I-14;
M05 U9a); item 22 ruled by the contract owner on 2026-11-18 with the wave's fix round (review
M05-W3-R01). Additive on revisions 5 and 5.1, gated on `trusted-work/1`: every revision-5 and
5.1 document, stored record, request hash and golden is byte-identical (see "Byte identity"
below), the code table stays at 30 rows, and the schema major stays `"1"` (§9).*

| Item | What landed | Where |
|---|---|---|
| 21 | **The server-built trust proposal in `inspect workspace`.** `WorkspaceView.proposal: Option<TrustProposal>` (`#[serde(default, skip_serializing_if = "Option::is_none")]`): the proposal the **runtime** builds for the working directory, the manifest's request ∩ the profile's latest snapshot, its pair, environment and capability tokens resolved against the local catalog, exactly what `policy trust_workspace` computes and compares a request's `proposal` and `access_digest` with (ADR-0011 I5). It is built by the same code (`trust_m05::manifest_proposal`, shared by the decision builder and by `inspect workspace`). Owner only, like `access_digest`. Omitted when there is none: no workspace root, no manifest, a manifest that names a profile this catalog does not have, or a request that resolves to nothing (`manifest_invalid`); a request built without a proposal then reaches the decision builder, which refuses it with its stable reason. Gated on `trusted-work/1` like the rest of `inspect workspace` (`Request::required_capability`, unchanged) | `contract::trust`, `app::operations::{context_m05, trust_m05}` (`manifest_proposal_view`), `schemas/public-api/inspect-workspace.schema.json` |
| 22 | **The scope of a `create` decision in `inspect decisions`.** A pending `WidenPolicy{create}` record's view gains `scope: DecisionScope {profile_id, profile_revision, pairs: [AccessPairRef], environments: [EnvironmentId], capabilities: [Capability], lock_behavior}`, read from its decision basis fixed at creation (`DecisionBasis::Create`, ADR-0011 I5; the stored basis, never a fresh catalog read): the profile revision the record pinned, that revision's snapshot (its pairs and capabilities; snapshots are immutable), the record's environments and the lock behaviour approval gives the new policy. It is exactly what approval applies (`trust_m05::apply_widening` reads the same basis and snapshot). Every list is always written, so an empty one means none. **Omitted for every other record**, and for a `create` whose basis or snapshot is gone (approval refuses that one as stale). No other `WidenPolicy` kind pins a profile revision, so none carries it: `set_max_window`, the targeted `resume`, `clear_cutoff` and later `cutoff` (revision 5.1 C1's `policies`) and the M01 single-policy forms change no scope. The rule: **present for `create` (and a targeted `WidenPolicy`, if it pins a profile revision); absent for `extend_scope`, whose recorded action is the added authority** (ruling I-14's normalization; a `scope` it cannot fill honestly would be worse). Like C1, a typed struct placed inside the untyped decision view: **no schema change**. Gated on `trusted-work/1` like the `create` request that raises the record | `contract::trust` (`DecisionScope`), `app::operations` (`decision_scope`, at the `decision_view` call site in `inspect`) |

**Why (ADR-0011 §2.2).** The runtime reads the manifest and the client never does. Revisions 5
and 5.1 gave the client no way to learn the proposal before a decision record exists, so
the CLI's `project trust` and `access allow --workspace` ran the runtime's observer
(`workspace_observe::RealWorkspaceProbe`) in process and recomputed the intersection to build
the request. With item 21 they take the proposal and the access digest from `inspect
workspace` and send them back unchanged; they run no observer and read no manifest. The
runtime's refusal of any difference (I5) is unchanged and is still the only check that
matters: the client's copy is a convenience, not an authority.

Example: `inspect.workspace.proposal` (round-trips and validates;
`tests/contracts/rev5.rs`). Golden: `tests/contracts/golden/rev5-2.golden.json` (a view with
a proposal, the smallest proposal, and the two views that carry none: a manifest-less root
and a non-workspace directory). Schema regenerated by `heimdall schema export`:
`inspect-workspace` only (the other public schemas, `configuration` and `project` are
unchanged).

**Byte identity.** The field is skipped when `None`, so a view without a proposal, every
revision-5 and 5.1 `inspect workspace` document, example (`inspect.workspace`) and golden is
unchanged; a client built before this revision ignores the added key (§9). The only schema
text that changes is `inspect-workspace`, which gains the optional `proposal` property and
the `TrustProposal`, `AccessPairRef`, `AccountName`, `Capability`, `DestinationId`,
`EnvironmentId` and `ProfileId` definitions it references.

**Proofs.** Contract: `rev5::rev5_2_workspace_proposal` (the golden: each view round-trips
exactly and validates against `inspect-workspace`, the key is written exactly when there is a
proposal, the field is optional in the schema, `inspect workspace` still needs
`trusted-work/1`), `rev5::rev5_examples_round_trip_and_validate` (the new example; the
revision-5 example has no proposal), `schema_export::checked_in_public_api_matches_the_model_exactly`
and the `schema` check of `tools/validation/check.sh`. Runtime
(`e2e_context_m05`): `the_inspected_proposal_is_what_trust_workspace_accepts` (a request
built only from `inspect workspace` raises the trust decision, whose recorded action is
that proposal; one built from an answer the manifest outran is refused `USAGE_ERROR` with
the store's row counts unchanged; a manifest-less root, an unknown profile and a
non-workspace directory carry no proposal). CLI (`e2e_cli_m05`): the `project trust` journey,
which now goes through `inspect workspace`; and `crates/heimdall/src/` names neither
`RealWorkspaceProbe` nor `workspace_observe`.

**Item 22: why (review M05-W3-R01).** The setup offer built its personal-default disclosure
from its own `inspect profiles` read, while the runtime pinned the profile revision current
when the `create` arrived. An ordinary owner catalog edit between the two (profile `review`
gaining `h2` and `h3`) gave a prompt listing only `h1` and an approval that created a
standing default covering `h3`: a consent mismatch caused by the owner's own action
(ADR-0009 §2.1, blocking). Revisions 5 and 5.1 gave no consent surface the pinned scope of a
`create` record: its view held only the action (profile, environments, window, default).
With item 22 the setup offer, the CLI's `create` review (`access allow --profile` for a
profile without a policy, and `heimdall decide approve`) and the TUI's `create` view render
the disclosure **from the record's `scope`**, read with the record itself, and never from a
client read; a `create` record without a well-formed `scope` is refused before anything is
asked (`setup_cmd::SCOPE_NOT_RECORDED`; fail closed). This is the public consumer ruling I-3
waited for: the basis stays an internal store row, and the view exposes what it fixes.

Golden: `tests/contracts/golden/rev5-2.golden.json` `decision_scope` (two pinned `create`
views, one with an empty capability list, and two records without a scope: an
`extend_scope` and a targeted `resume`).

**Byte identity (item 22).** The key is inserted only for a pinned `create`, so every other
decision view, every revision-5 and 5.1 document, example and golden is unchanged; the
published schemas are unchanged (no schema names `DecisionScope`); a client built before
this revision ignores the added key (§9).

**Proofs (item 22).** Contract: `rev5::rev5_2_decision_scope` (the golden: the scope
round-trips exactly through `DecisionScope` with every list written, a missing list is
refused rather than read as empty, the key is present exactly for the `create` forms, and no
public schema names the type). CLI, the reviewer's probe inverted, against the production
`Service` in process with the debug test configuration and a real `Client`
(`setup_cmd::tests::personal_default_offer_shows_the_scope_recorded_after_a_catalog_edit`):
a production `UpsertProfile` committed between the offer's profile read and its `create`
is in the prompt (the destination line is exactly the recorded scope, `h3` included), the
default approval creates has exactly that scope, and the `extend_scope` record raised after
it has no `scope` key; reverting the offer to its own read makes it fail (exit 101), restored
it passes. Fail closed: `setup_cmd::tests::personal_default_offer_without_a_recorded_scope_approves_nothing`,
`m05_cmd::tests::a_create_review_shows_the_recorded_scope_or_refuses` and
`tui::m05::tests::a_create_shows_its_recorded_scope_or_offers_no_approval`.

**Ruled (item 22, `extend_scope`; the contract owner, 2026-11-18).** `scope` is absent for an
`extend_scope` record. That kind pins no profile revision: its creation checks the request
against the profile's latest definition and stores no revision, and its approval leaves the
lock behaviour unchanged when the recorded `background_work` is absent, so `profile_revision`
and `lock_behavior` would have no fixed value. Its recorded action is already exactly the
authority it adds (ruling I-14), and the CLI and TUI show that action.

### 17.11 Revision 5.3 (M05 wave 4)

*Ruled by the contract owner on 2026-11-20, with M05 wave 4's final candidate (the portable
bundle dropped a route's jump; item 24 with the final review's fix round, ruling I-27).
Additive on revisions 5, 5.1 and 5.2, gated on `trusted-work/1` like the bundle it extends: every
earlier document, stored record, request hash and golden is byte-identical, the code table stays
at 30 rows, and the schema major stays `"1"` (§9).*

| Item | What landed | Where |
|---|---|---|
| 23 | **A route's jump in the portable bundle.** `PortableDestination.jump: Option<DestinationId>` (`#[serde(default, skip_serializing_if = "Option::is_none")]`): the jump destination of a managed destination reached through a single-hop jump (its route's `jump`, revision 5's ADR-0010 §5 item 1), as a reference to that destination's ID; omitted for a direct or observed destination. **Export** writes it (plain and redacted: it is an ID, never a host name). **Import** resolves it against the bundle (a destination there with no jump of its own) or the local catalog (a managed destination with no jump of its own); otherwise it refuses that destination with the finding `jump_unresolved` (a `conflict` entry; nothing is written for it), and a chain is unresolved too (`route_chain_unsupported`). An import entry shows the `jump` it names, and a local managed destination matches a bundle's only when their jumps are equal (a direct and a routed destination are `differs_locally`, never `unchanged`). A jump route is never imported as a direct one: import still writes only observed destinations (§17.9), now with the route shown in the plan. The bundle schema's closed `PortableDestination` gains the optional `jump` property | `contract::project` (`PortableDestination`), `project::portable` (the closed key list; a destination is never its own jump), `app::operations::portable_m05` (export, plan), `schemas/project/portable.schema.json`, `schemas/public-api/{request,ipc.client-message}.schema.json` (the bundle `apply_import` carries) |
| 24 | **A routed destination is skipped on import** (ruling I-27, with review M05-W4F-R01 and R03). Import never writes a destination whose bundle entry names a `jump`, unless this catalog already has that destination with the same route (a managed destination through the same jump, compared as item 23 compares): then the entry is `unchanged` and nothing is written. Otherwise it is **`skipped`**, a new plan status (`status: skipped`, `reason: route_required`), its entry naming the `jump` and a `setup` command, `heimdall destination add <alias> --id <id> --hostname <host> --account <account> --identity <identity> --jump <jump>` (the alias, ID and jump are the bundle's checked tokens; the rest is the owner's to fill in), and the counts gain `skipped` (`applied` and `would_apply`). Nothing of it is stored (no row, no marker), so no listing, TUI view, edit, `connect`, `ensure` or `run` can reach it by its bare alias: they answer it as an unknown destination. A new profile in the bundle with a pair on a skipped destination is `skipped` too (`route_required`, nothing written): `ensure` answers a pair on a destination outside the catalog as existing access, so the profile would otherwise be a request path to the destination through the owner's ordinary SSH configuration; a re-import after the owner has set the route up adds it. The route comes only from the owner's own definition, with ADR-0010 §5's pins and checks. A jump that does not resolve stays `jump_unresolved` (item 23). A jump resolves against the import's reconciled result (review M05-W4F-R03): a bundled hop that is itself refused, or named twice, leaves its routed destination `jump_unresolved`; a hop the bundle omits resolves to this catalog's managed direct destination. **Every** row whose destination ID the bundle repeats is refused (`duplicate_in_bundle`), the first one too, before any alias is claimed. Export is item 23's (a managed destination's jump travels) | `app::operations::portable_m05` (plan, counts), `heimdall::portable_cmd` (the plan's human form) |

**Why.** A bastion destination exported without its jump read, on import and in the plan, as a
destination reached directly: the owner could re-create it as direct, bypassing the bastion, and
a direct local destination compared `unchanged` with a routed one.

**Proofs.** `integration_portable::a_bastion_destination_round_trips_with_its_jump` (the export
names the jump; a second installation's plan adds both destinations and shows the jump; a
re-import into the exporter is a no-op; a bundle routing the direct destination through the
bastion is `differs_locally`) and `an_unresolved_jump_refuses_its_destination_on_import` (an
unknown jump and a two-hop chain are `jump_unresolved`, nothing is written for them, the rest
applies); `schema_export::checked_in_public_api_matches_the_model_exactly` and the `schema` check.
Item 24: `e2e_cli_m05::an_imported_routed_destination_is_never_launched_by_its_bare_alias` (a
scratch home with a disposable direct `Host lab-inner` and a stub launcher recording its argv:
the import skips `lab-inner`, `route_required` with the jump and the setup command, and the
profile `inner` with its pair; the destination list has no such row; `connect lab-inner` and
`run --profile inner` are refused `NOT_FOUND` and nothing is launched; the direct bastion still connects; revert proof
`tests/evidence/artifacts/m05-w4/revert-r01-routed-import-skipped.json`),
`heimdall::tui::model::tests::a_destination_an_import_skipped_is_never_connectable_from_the_tui`,
`integration_portable::a_bastion_destination_round_trips_with_its_jump` (a receiver without the
route skips it and writes nothing for it; the exporter, which has the matching route, is
`unchanged`), `a_jump_resolves_against_the_reconciled_hop` and
`every_row_of_a_repeated_destination_id_is_refused`.

## 18. ⟨rev6⟩ Revision 6 (M06 wave 0)

Revision 6 is ADR-0012 §9 (items 1–11) applied at M06 wave 0 (m06-plan U0). The orchestrator
owns it as the contract owner (m06-plan §0 rule 1). This text is the wave-0 worker's draft for
that approval; §18.2 lists the readings put to the orchestrator rather than decided here.

Schema major stays `"1"` (§9): every change is additive. Every new field is
`#[serde(default)]` and omitted when it carries no value, so every M01–M05 document, stored
record, request hash, cursor and golden is byte-identical. The code table stays at **30 rows**
and no exit code changes: revision 6 adds reasons (`reason::M06`), never codes.

**Implemented** (the two semantic changes):

* **The caller context** gains `remote_client` (ADR-0012 §9 items 1–2). Idempotency keys,
  operation ownership and visibility, binding ownership and event cursors are keyed by it.
  Nothing sets it in wave 0: the runtime builds every caller with `remote_client: None`, and
  no request field can set it.
* **Negotiation** is `required ⊆ offer ∩ server ∩ role` with both refusal codes (item 4). Every
  local caller is the owner, so nothing changes for it, and its server hello is byte-identical.
  A hello carrying `remote_client` is refused `SCHEMA_UNSUPPORTED` by every wave-0 runtime.

**Declared and failing closed** (everything else):

* the capabilities `remote-control/1`, `runner/1`, `routes/1` and `transport-iroh/1` are
  declared and **not offered** (`capability::REVISION_6_DECLARED`; `ipc::session` and
  `inspect capabilities` list none of them);
* each revision-6 request form names its capability in `Request::required_capability`, so a
  session that did not negotiate it gets `SCHEMA_UNSUPPORTED` before dispatch;
* every revision-6 form reached in process answers `CAPABILITY_UNAVAILABLE` with reason
  `driver_unavailable` **before any record is written**, whatever the caller's role
  (`Operations::revision_6_request`);
* the CLI's new commands answer M01's "not available in this build" envelope with "(planned for
  M06)" (§16.2 item 6);
* the views, events, routes, readiness residuals and store tables are types and schema only.

### 18.1 Deltas (ADR-0012 §9 item → what landed → where)

| Item | What landed | Where |
|---|---|---|
| 1 (§2.1 caller identity) | `CallerContext.remote_client: Option<ClientId>` (serde default, omitted when `None`); `CallerContext::local(principal, role)` and `same_caller` (same principal **and** same client); `ClientId` (`cl_<hex>`, a prefixed ID validated like the others). `runtime::dispatch::caller_for` builds `remote_client: None` | `contract::ids`, `domain::principal`, `runtime::dispatch` |
| 2 (§7.1 idempotency; §4.1 ownership and visibility; §8 cursors) | The key is `(CallerContext{principal, role, remote_client}, kind, request_id)`; with no client the key document, its hash and the stored `caller_json` are unchanged (explicit bytes in the test). `app::events::visible_to`, `domain::binding::may_act_on` and `revoke`'s grant visibility compare `same_caller` instead of the principal alone; the cursor's reader tag hashes the whole context. The closing of a revoked client's sessions and subscriptions (the terminal `client_revoked` event) is U1's | `domain::idempotency`, `domain::binding`, `app::events`, `app::operations` |
| 3 (§2.3, §3.1, §13.3 item 2 attendance) | Unchanged, as ADR-0012 states. No `RemoteDecide` form exists; no revision-6 form is attended-only or a widening policy action, and a widening one creates a pending record when its unit lands | `contract::request` |
| 4 (§2.3 negotiation) | `ipc::session::negotiate_for_role(hello, principal, role, …)`: server lacks a required capability → `SCHEMA_UNSUPPORTED`; the role lacks it → `CAPABILITY_UNAVAILABLE` / `role_insufficient`; optional capabilities are cut to the role's set. `negotiate` is the local owner (`role: None`, not reported). `ServerHello.role: Option<Role>` and `ClientHello.remote_client: Option<ClientId>`, both omitted when absent. A hello with `remote_client` is `SCHEMA_UNSUPPORTED` unless the runtime offers `remote-control/1`. `remote::Role {owner, requester, viewer}`, `remote::Permission` (the seven of ADR-0012 §3.8), `Role::permissions`; `capability::for_role` (owner: `capability::ALL`; requester: `operations/1`, `events/1`, `schema-discovery/1`, `managed-credentials/1` (⟨rev7, §19.3 H13⟩ and `request-epoch/1`); viewer: `operations/1`, `events/1`, `schema-discovery/1`); the four capabilities, `REVISION_6_DECLARED`, not offered | `contract::ipc`, `contract::remote`, `ipc::session` |
| 5 (environment view) | `EnvironmentKindView::RemoteRunner`; `RealizationView::RemoteRunner {destination, account}`; `EnvironmentView.{connectivity, last_seen_at, runner_lifetime, remote_pending[], pinned_host_key, management_policy}`, each omitted when absent. `remote::Connectivity` (`connected`, `disconnected{last_seen_at}`, `unreachable{reason}`), `RunnerLifetime` (`user_service`, `session_scope`, `unknown`), `ManagementPolicy` (`verified`, `owner_only`), `RemotePending` (`effect{effect, target, reason?}`, `client_revocation{client, reason?}`); `EnvironmentView::new` for local views. Schema `inspect-environments` regenerated | `contract::environment`, `contract::remote`, `app::operations::{container_m04, wsl_m04}` |
| 6 (new requests) | `Request::RemoteEnvironment` (op `remote_environment`, actions `add`, `invite`, `join`, `revoke_client`, `remove`, `update`, `status`) and `Request::Device` (`retire`), capability `remote-control/1`; `Request::Route` (`add`, `remove`, `prefer`, `resolve_binding` = `ResolveRouteBinding`), `routes/1`; `Request::Transport` (`enable`, `disable`, `adopt_roost`), `transport-iroh/1`; `Request::Runner` (`prepare_remote_grant`, `install_certificate`, `time_challenge`, `time_response`, `deliver_effect`, `authority_report`), `runner/1`. Kinds `<op>.<action>`. Admission: `status`, `resolve_binding` and `authority_report` read-only, every other form synchronous (no operation row, no new `OperationKind`). `remote::EffectTarget` is typed: `grant_revoke{grant, grant_generation}`, `policy_pause{policy, revision}`, `policy_cutoff{scope: PolicyTarget, revision}`. No `RemoteDecide`; no serve-child lease or suspend message. `Request::is_revision_6`; `app::operations::revision_6_refusal`; the runtime routes the five ops to `Operations::revision_6_request` | `contract::{request, remote, route}`, `app::operations::remote_m06`, `runtime::dispatch` |
| 7 (reasons) | `reason::M06`: 23 reasons, each `CAPABILITY_UNAVAILABLE` (exit 4, not retryable); `route_dependency_out_of_scope` stays M04's. `reason::IROH_ADMISSION_CLOSING` in `reason::M06_PENDING`, a `remote_pending` reason with no code. Golden `tests/contracts/golden/rev6-reasons.golden.json` | `contract::envelope` |
| 8 (events) | `EventType::{Environment, Client, Device, RemoteEffect, Route}`, declared and not emitted. Payloads: `remote::EnvironmentEventPayload {kind: connectivity_changed, environment, connectivity}`, `ClientEventPayload {kind: enrolled \| revoked, environment, client, role?}`, `DeviceEventPayload {kind: retired, revoked_on[]}`, `RemoteEffectEventPayload {kind: pending \| acknowledged, environment, producer, effect, target}`; `route::RouteHealthPayload {kind: health \| failed_over, destination, account, attempts: [{route, failure?}], final_route?}` with `RouteFailureClass` (`refused`, `timeout`, `identification_timeout`, `admission_refused`, `terminal_after_forwarding`) | `contract::{event, remote, route}` |
| 9 (destinations) | Types only: `route::RouteSpec` (`direct{host, port?}`, `jump{via}`, `iroh{endpoint, external_roost}`), `ExposurePolicy {bind, infrastructure, direct_fallback}` (default: the minimal policy), `BindScope`, `InfrastructureProfile` (`none`, `custom{relays}`, `n0_public`), `DestinationRoute {id, route, exposure?, consents[], identification_timeout_ms?}`, `HostKeyPin {public_key, fingerprint}`, `DestinationRoutes {destination, routes[], host_keys[]}`; IDs `RouteId` (`route_`), `ConsentId` (`cns_`), `KeyFingerprint`, `IrohEndpointId` (64 lowercase hex). Not wired into the catalog or the domain | `contract::{route, ids}` |
| 10 (readiness) | `ReadinessCondition::{RunnerLifetime, RunnerTimeBounded, RunnerProcessNotRestarted}`; `managed::RevocationResiduals {new_authentication?, owned_dedicated_sessions?, owned_admissions?, other_live_sessions?, detached_remote_processes?}`, `AuthenticationResidual {latest_possible_credential_expiry?, destination_clock_error}` (`destination_clock_error` is the existing `DestinationClock`: `{"measured": {behind_upper_ms, …}}` or `"unmeasured"`), `ComponentResidual` (`closed`, `not_ended`, `unknown`); every field omitted when absent. Not attached to `EnsureData` in wave 0 (§18.2 item 14) | `contract::managed` |
| 11 (store) | Migration `0009_remote` (`SCHEMA_VERSION` 9), tables only: `remote_clients` (the role table and client tombstones), `remote_invitations` (generation, wall deadline, boot ID, elapsed bound), `remote_effect_outbox` and `remote_effect_acks` (keyed by producer, effect ID, typed target and target generation), `remote_policy_revisions`, `remote_environment_pins`, `remote_grant_issuers`, `destination_routes`, `route_consents`, `remote_authority_generation`, `transport_keys` (references only). Runner-local decisions use the existing `decisions` table. In `REQUIRED_TABLES`; classified in `TABLE_RECOVERY` (§18.2 item 16). No store API | `store::migrations`, `store`, `store::ext_m03` |
| CLI | `env`, `device`, `route`, `transport`, `roost`: registered, arguments accepted and ignored, each answered by `m06_cmd::refuse` with `USAGE_ERROR` (exit 2, effect `none`, `fix_request`) "(planned for M06)" before any runtime contact or home creation; a `--json` after the command still selects the envelope. Golden `tests/contracts/golden/cli-help/top-level.txt` | `heimdall::{cli, m06_cmd}` |
| Schemas | `schemas/public-api/` regenerated with the real binary (`heimdall schema export`): `request`, `ipc.client-message`, `ipc.server-message`, `event`, `inspect-environments` and `envelope.ensure` (the readiness conditions) changed; no file added | `schemas/public-api` |

**Proofs.**
* **Contract** (`cargo test -p heimdall-contract`): `contracts::rev6::{rev6_reason_golden, rev6_request_forms, rev6_capabilities_declared_and_roles, rev6_earlier_forms_unchanged, rev6_additive_documents}`; the journaled-kind and capability tables of `contracts::m02` cover every revision-6 form (`golden/journaled-kinds.golden.json`, `golden/rev6-requests.golden.json`); `schema_export::checked_in_public_api_matches_the_model_exactly`; unit tests `ids::tests::m06_ids_validate`, `remote::tests::{roles_hold_their_permissions, effect_targets_are_typed}`, `route::tests::default_exposure_is_minimal`.
* **Idempotency, ownership, cursors**: `heimdall_domain::idempotency::tests::remote_client_namespaces_the_key_and_none_keeps_the_old_encoding` (two callers differing only in their client get different keys; no client is the revision-5 byte string and hash), `heimdall_domain::binding::tests::foreign_limited_caller_may_not_act`, `heimdall_app::events::tests::remote_client_scopes_cursors_and_visibility`.
* **Negotiation**: `heimdall_ipc::session::tests::{the_revision_6_capabilities_are_declared_not_offered, negotiation_intersects_the_role_with_both_refusal_codes, a_hello_naming_a_remote_client_is_refused_without_remote_control}`.
* **The landing**: `heimdall_runtime::dispatch::tests::w0_revision_6_requests_fail_closed_before_any_record` (every form of the golden, as owner and as a limited caller: `driver_unavailable`, effect `none`, no operation, decision, event or generation change); `heimdall_app::operations::remote_m06::tests::only_revision_6_forms_are_refused`; `heimdall::m06_cmd::tests::m06_commands_refuse_as_planned_for_m06`.
* **Store**: `heimdall_store::migrations::tests::remote_step_applies_on_the_previous_version_and_rolls_back_whole` (0009 on a version-8 database, earlier rows kept; a broken step leaves version 8 and none of its tables), with the existing `failing_step_rolls_back_whole_step_and_version`; `heimdall::uninstall_cmd::tests::recovery_snapshot_classifies_every_table` covers the new tables.

### 18.2 Readings applied where the design is silent (ruled 2026-11-21: confirmed, or amended in §18.5)

1. ⟨amended: §18.5⟩ **A hello naming `remote_client`** is refused `SCHEMA_UNSUPPORTED` by any runtime that does
   not offer `remote-control/1`; in wave 0 that is every runtime (the integrator's reading).
2. ⟨amended: §18.5⟩ **Route types are contract-only.** The destination object keeps its single route and jump
   fields; `DestinationRoutes` is not attached to the catalog or the domain (U5a's work; the
   integrator's reading).
3. **The store is forward-only.** m06-plan U0's "migration up and down" is read as: 0009 applies
   on a version-8 database, a failure inside it rolls the whole step back, and no down
   migration exists (the integrator's reading). A later change is a new step.
4. **`ServerHello.role`** is reported only for a role-negotiated session
   (`negotiate_for_role(.., Some(role), ..)`). The local same-user session is the owner (§2.1)
   and its hello stays byte-identical.
5. ⟨amended: §18.5; §19.3, H13⟩ **The role capability sets** (`capability::for_role`): owner every capability; requester the
   primitives, events, schema discovery, managed-credential results and (revision 7, H13)
   `request-epoch/1` where the runtime offers it; viewer the
   primitives, events and schema discovery. Neither limited role gets `remote-control/1` or
   another revision-6 capability. A negotiated capability never authorizes: each request is
   still checked against the role (U1).
6. **Request names.** `env` is the op `remote_environment` (distinct from revision 5's local
   `environment`). `ResolveRouteBinding` is `route.resolve_binding` under `routes/1`, because
   the helper runs wherever a routed alias is rendered. `roost adopt` is
   `transport.adopt_roost` under `transport-iroh/1`, because the route it creates is an Iroh
   route.
7. ⟨amended: §18.5, M06-W0-R08⟩ **Request IDs and admission.** The forms that can widen authority or exposure carry a
   required `request_id`, so a replay after the runner-local decision returns the recorded
   terminal result (ADR-0012 §3.10 T-RA3). Those forms are `invite`, `route add`,
   `route prefer`, `transport enable` and `adopt_roost`. Narrowing, compare-and-set and local
   forms carry none, as revision 5's environment requests. No form gets an operation row.
8. **The producer of an effect is never a request field.** `deliver_effect` carries the effect
   ID and the typed target. The producing controller is the session's authenticated client
   (ADR-0012 §7.2 "authenticated producing controller").
9. ⟨superseded: §18.5, M06-W0-R02⟩ **`policy_cutoff` carries no instant.** A delivered cutoff takes effect when applied, the
   narrowest reading of "ends every affected grant like expiry" (DONE question W0C-Q2).
10. **Time samples** are two requests: `time_challenge` asks the runner for a nonce, and
    `time_response {nonce, controller_time}` answers it (T_c). The runner cannot originate a
    request on the management channel.
11. **Event families.** Each ADR-0012 name `family.kind` is `EventType::<Family>`, with the
    payload's `kind` naming the event, as revision 5's `activation` event does. The
    `route.failed_over` subtype is `kind: failed_over` with the same attempt result as
    `route.health`.
12. **The target generation** rides inside the typed target (`grant_generation`, `revision`), not
    in a separate field beside it (`EffectTarget::generation`).
13. **A remote runner's realization** is `RealizationView::RemoteRunner {destination, account}`:
    the catalog destination and runner account that reach it. `EnvironmentView.realization` is
    required.
14. ⟨amended: §18.5, M06-W0-R09⟩ **The residuals are not attached in wave 0.** ADR-0012 §9 item 10 puts them beside
    `EnsureData`'s readiness fields. Attaching an optional field there breaks every
    `EnsureData` struct literal, and most of them are in test files outside wave 0's write
    scope. The types are complete and serialize as specified, and U3/U4 attach them (or the
    integrator does, with the literal edit).
15. **The wave-0 refusal is uniform.** Every revision-6 form answers `driver_unavailable`
    whatever the role, so it tells a limited caller nothing beyond the capability list. The
    role checks (`role_insufficient`) are U1's.
16. ⟨amended: §18.5⟩ **Store details.**
    * Runner-local decisions reuse `decisions`.
    * The outbox (controller) and the acknowledgements (runner) are separate tables, both keyed
      by the four §7.2 parts.
    * The admission authority generation is a one-row table of its own, so the serve lease never
      moves with grant or policy changes; whether it should be the existing
      `meta.authority_generation` is DONE question W0C-Q4.
    * No uniqueness is imposed on key fingerprints, since re-inviting a revoked key is U1's
      decision.
    * All eleven tables are `Discarded` in the recovery snapshot while no writer exists. Each
      unit reclassifies its table before its writer lands (DONE question W0C-Q3).
17. ⟨amended: §18.5, M06-W0-R03⟩ **Ownership and visibility** compare the same principal **and** the same client; the owner
    role still sees and acts on everything (ADR-0012 §3.7 "plus the environment-level views
    its role permits").
18. **IDs.** The new prefixes are `cl_`, `inv_`, `route_`, `eff_` and `cns_`. `KeyFingerprint`
    has the `CaFingerprint` form (`SHA256:` and 43 base64 characters). `IrohEndpointId` is the
    64-hex form observed in G06.

### 18.3 Not in wave 0

* Serving any revision-6 form; offering any revision-6 capability; setting `remote_client`
  (the bridge, U1); attaching `RevocationResiduals` to `EnsureData`.
* The role table, invitations, the effect outbox, pins, routes and transport keys as store
  APIs (U1–U5), and their recovery classes.
* Emitting the revision-6 events; closing a revoked client's sessions and subscriptions; the
  route-health result; the remote environment view's values.
* Routes in the catalog and the domain, the helper and failover (U5a, U5b); the transport and
  its serve child (the `heimdall-transport-iroh` crate); K_mgmt and K_iroh custody.
* The argument trees of `env`, `device`, `route`, `transport` and `roost` and their help goldens
  (U2, U5).

### 18.4 Revision 6.1 (M06 wave 1)

Four additive corrections the wave-1 units (U1, U5a, U6a) needed; the integrator applied them
as contract owner. Schema major stays `"1"`; every revision-6 form keeps its capability,
admission and fail-closed landing.

| Item | What landed | Where | Raised by |
|---|---|---|---|
| 1 | `RemoteEnvironmentRequest::Invite.public_key` (one OpenSSH public key line, public text), required: the runner writes the management line from it and refuses it unless its fingerprint equals `key_fingerprint` (ADR-0012 §3.9 item 1) | `contract::remote` | U1 (the fingerprint alone cannot write a line) |
| 2 | `RemoteEnvironmentRequest::ActivationProbe {environment, nonce}`, kind `remote_environment.activation_probe`, `remote-control/1`, admitted like `join`: the wire form of ADR-0012 §3.2's confirming probe and one of the two forms a pending client may send (§3.9 item 3) | `contract::remote`, `contract::request` | U1 (no wire form existed) |
| 3 | `RouteSpec::Iroh.direct_addresses` (`ip:port` strings, omitted when empty): direct paths go only to these unless the exposure policy consents to direct fallback (ADR-0012 §2.1) | `contract::route` | U6a (Q2) |
| 4 | `RouteFailureClass::AuthenticationOrTrust`: a jump leg that fails host-key verification or authentication at the jump host before identification; terminal, never failed over (ADR-0012 §5.5 item 3) | `contract::route`; used by `app::routes_failover` | U5a (such failures were recorded as `refused`) |

Goldens: `rev6-requests.golden.json` (the invite row gains `public_key`; a probe row),
`journaled-kinds.golden.json` (the probe kind beside `join`), `contracts::rev6` (22 forms).
Schemas regenerated (`request`, `ipc.client-message`).

### 18.5 Orchestrator rulings on the W0 review (2026-11-21)

The independent review of `ce5b0dc2..a2576a51` (archived redacted at
`tests/evidence/artifacts/review-m06/w0.md`; FIX FIRST: M06-W0-R01–R03 blocking) and the
orchestrator's rulings, applied in M06 wave 1. Readings 3, 4, 6, 8, 10–13, 15 and 18 are
**confirmed** as the reviewer marked them. The others are amended:

| Reading | Ruling | Finding | Where it lands |
|---|---|---|---|
| 1 | W0's unconditional refusal stays. U1 accepts a client ID only from a runner session with a resolved bridge identity and role; a capability advertisement alone never establishes identity | — | U1 (W1), runtime acceptance W2 |
| 2 | Explicit deferral: U5a attached the route list on the domain side (W1); attaching routes and pins to the **public** destination object (schema) is U56's, with the pin-source ruling | M06-W0-R09 | m06-plan U0, U56 |
| 5 | Ordinary role intersection stays; a pending session gets a pending-only path (activation probe and `join`, with the invitation and identity checks ahead of any recorded result) without opening `join`'s capability to limited sessions; primitives and event delivery are gated by permission and scope | M06-W0-R06 | U1 before W2's exit (dispatch is wired in W2) |
| 7 | Per-action replay mapping: a preference among consented routes needs no decision (`route prefer` request ID optional, idempotency only); bootstrap owner enrollment and device retirement are locally attended confirmations, separate from T-RA3; every widening request a paired client can submit carries a required `request_id` with terminal replay — always on `invite`, `route add`, `transport enable` and `transport adopt_roost` (not computed from the consent delta) | M06-W0-R08 | contract (rev 6.1: `Prefer.request_id` optional), `remote::widening` |
| 9 | **Superseded.** A delivered cutoff carries the owner's instant `at` (`EffectTarget::PolicyCutoff.at`). The runner's effective cutoff is `min(existing, delivered)`: a delivered or replayed cutoff only shortens it; moving it later is a widening (runner-local). An `at` at or before trusted now applies at the durable apply, no signature after that commit; a future `at` is persisted and enforced at `at` by the supervisor wake (I-26 wakes for `cutoff_at`); under uncertain time it fires as soon as `at` may have passed (the upper bound of now) | M06-W0-R02 | contract (rev 6.1), enforcement U4 (tests: early, late, replay under uncertainty) |
| 14 | Explicit deferral: U3 attaches the residuals to `EnsureData`, with the literal edit, in the same commit | M06-W0-R09 | m06-plan U0, U3 |
| 16 | Key-fingerprint uniqueness is scoped per runner and role table; policy-revision identity is producer-scoped `(scope_key, producer, revision)` with a runner-side order (`runner_seq`) and composing narrowing effects — migration 0009 amended in place before any writer (unmerged, unreleased); recovery and purge cases before writers, transport writers included (ruling 3: `placeholder_discarded_tables_have_no_writer`) | M06-W0-R05 | 0009, U4, store |
| 17 | The local owner keeps its global bypass. A paired caller, owner role included, gets client-scoped ownership (principal and client) plus only its role-permitted environment views and the named cross-controller narrowing powers (ADR-0012 §7.2, §8); no blanket bypass for observe, cancel or binding ownership; visibility on every delivery path (event pages, resumed and live subscriptions) | M06-W0-R03 | app, domain, ipc (W1) |

**⟨amended 2026-11-26, M08 W4 SEC-3a (S2-01); the orchestrator's ruling⟩ Ruling 7's `route prefer`
is local-only.**
- Ruling 7 itself is unchanged on the local endpoint: a preference among consented routes needs no
  decision, and its request ID is optional.
- A **paired** session's `route.prefer` is refused before the request fence with
  `INTERACTION_REQUIRED` / `local_owner_required`, as all runner-local configuration is (ADR-0012
  §3.10, amended the same day), and nothing is written.
  - No shipped client sends it over a paired session.
  - The old paired path could leave a pending record with no executor, which fails open.
- The test is `tests/integration/request_epoch.rs`
  `s2_01_paired_owner_cannot_run_runner_local_configuration_and_writes_nothing`, where
  `route.prefer` is one of the excluded kinds.
- **Post-1.0:** a route preference set from the controller would come as a delivered effect with
  its own executor, never as a pending record.

### 18.6 Revision 6.2 (M06 wave 2)

Additive changes the wave-2 units (the paired runtime, U2, U3, U56) needed; the integrator
records them as contract owner, pending the orchestrator's approval with the W2 review. Schema
major stays `"1"`; every earlier document, stored record and golden is byte-identical.

| Item | What landed | Where | Source |
|---|---|---|---|
| 1 | A runner runtime (its own environment of kind `remote_runner`, written by `heimdall remote init` → `runtime::paired::init_runner`) **offers** `remote-control/1` and the role-intersected subset; every other runtime keeps W0's refusal. A hello's `remote_client` is accepted only when the runner's role table resolves it (`remote::resolve_session`), and the session takes the table's role (§18.5 reading 1) | `runtime::paired`, `ipc::session` | ADR-0012 §3.6 |
| 2 | `ServerHello.remote_client` (omitted when none): a runner reports the paired client of the session | `contract::ipc` | U2 (W2) |
| 3 | `client.revoked` events are emitted: revoking a client closes each of its subscriptions with that terminal event, then the session | `runtime::paired` | §9 item 2, ADR-0012 §3.7 |
| 4 | Decision and resource events reach a paired owner as read-only owner-role environment views with every decision handle stripped (no decision or resource ID usable for approval: live events, resumed backlogs, snapshots, event pages, `inspect decisions`); requester and viewer receive none (their view sets name none) | `app::events`, `runtime::paired` | orchestrator ruling of 2026-11-21 |
| 5 | `DecisionKind::RemoteWidening` (domain) with migration `0010_remote_widening.sql` (schema 10; recovery class `Rows`, with recovery cases): runner-local widening records are durable decision records; approval and execution re-check the exact request (hash, kind, request ID, invite key and role, transport exposure delta) | `domain`, `store`, `app::operations` | ADR-0012 §3.10; M06-W0-R07/R08 |
| 6 | Reason `mgmt_key_store_unavailable` (`CAPABILITY_UNAVAILABLE`): a missing, not locked, K_mgmt store | `contract::envelope` (`reason::M06`) | U2 (W2), ADR-0012 §3.4 |
| 7 | `EnsureData.residuals` (optional, omitted when absent): the per-component residuals of ADR-0012 §7.3 with `latest_possible_credential_expiry` and `destination_clock_error: measured{bound} \| unmeasured` | `contract::request` / readiness types | §18.5 reading 14 (U3) |

**Readings applied in wave 2 (pending the orchestrator's confirmation):**
- The refresh dependency of a runner's managed binding is the existing contract value `controller` (ADR-0012 §4.5 calls it `controller_issuer`; the value already means the controller's issuer).
- `issuer_trust` and the time-source designation persist as `meta` keys (classified for the recovery snapshot) until a unit needs a table.
- The runner's authorized_keys writer (`runtime::paired_lines`) re-implements ADR-0005 §3.3's steps (append-only add, compare-then-rename rewrite and remove, symlink and hard-link refusal, re-read after every write) because the registry helpers fit only enrollment lines; it reads every `AuthorizedKeysFile` and writes only the account's own `authorized_keys`.


### 18.7 Revision 6.3 (M06 wave 3)

The orchestrator's rulings of 2026-11-21 on the W2 questions (m06-plan §2 "W3 rulings"; ADR-0012's
⟨2026-11-21⟩ amendments). Additive: schema major stays `"1"`; every earlier document, stored record
and golden is byte-identical; each new field is omitted when empty or false.

| Item | What lands | Where | Source |
|---|---|---|---|
| 1 | Migration `0011` (schema 11): table `remote_client_endpoints (client_id TEXT PRIMARY KEY REFERENCES remote_clients, endpoint_id TEXT NOT NULL UNIQUE, recorded_at TEXT NOT NULL)`, recovery class `Rows`, with recovery cases; column `remote_invitations.iroh_admission INTEGER NOT NULL DEFAULT 0` | `store` | ruling 4 (Q2) |
| 2 | `Invite.iroh_admission: bool` (omitted when false): the invited client may reach this runner over Iroh. It is part of the invitation's exact request, so the runner-local widening decision confirms it | `contract::remote` | ruling 4 |
| 3 | `Join.iroh_endpoint: Option<IrohEndpointId>` (omitted when none): the client's own endpoint ID, sent over its K_mgmt session. The runner records it in the join's commit transaction only when the invitation has `iroh_admission`; otherwise the join is refused (`USAGE_ERROR`, `fix_request`, effect `none`; corrected 2026-11-21: the code table has no `INVALID_REQUEST`). The owner never types endpoint IDs | `contract::remote`, `remote`, `store` | ruling 4 |
| 4 | `RemoteEnvironmentRequest::RotateEndpoint { environment, endpoint }`, kind `remote_environment.rotate_endpoint` (capability `remote-control/1`, any role, the session's own client only). It sets or atomically replaces that client's `remote_client_endpoints` row, only when its consumed invitation had `iroh_admission`. A replacement bumps `remote_authority_generation` in the same transaction; the same endpoint again is a no-op. The controller's `heimdall transport rotate` rotates this device's K_iroh and sends it to each recorded runner. Revocation deletes the client's row in the tombstone's transaction | `contract::remote`, `remote`, `runtime::paired`, `app` | ruling 4 (answers U56-Q7 for client endpoints) |
| 5 | `ExposurePolicy.port: Option<u16>` (omitted when none; `0` refused): the serve port. `heimdall transport enable --port <n>`. Without it the first successful bind's port is recorded durably and reused. An unbindable port fails closed (`CAPABILITY_UNAVAILABLE`, reason `transport_unavailable`) with a doctor finding naming the port; changing it is `disable` then `enable` | `contract::route`, `runtime::supervise_transport`, `heimdall` | ruling 5 (Q5) |
| 6 | `Request::ControllerRecord(ControllerRecordRequest)`: `put_environment { record: RemoteEnvironmentPin }` and `remove_environment { environment }` (kinds `controller_record.put_environment`, `controller_record.remove_environment`). `RemoteEnvironmentPin` and `ManagementRoute` move from `app::remote_env` into the contract unchanged. Local owner only; a paired session is refused. The CLI keeps the TTY confirmations and the ssh bootstrap, sends the form when a runtime answers, and writes directly under the instance lock when none does, so `environment add/join/remove` and `device retire` no longer answer `SERVICE_UNAVAILABLE` while a runtime runs | `contract`, `runtime`, `heimdall`, `app::remote_env` | ruling 6 (W-Q1) |
| 7 | `Request::RunnerLocal(RunnerLocalRequest)`: `trust_issuer { controller, ca_public_key, request_id }` (the paired owner client whose issuer holds the CA; the runner computes the fingerprint) and `designate_time_source { client, request_id }` (widening: a local owner in an attended session only, after the CLI's typed confirmation), `distrust_issuer { ca_fingerprint }` and `clear_time_source` (narrowing: a local owner). Kinds `runner_local.*`. A paired session is refused. Hidden CLI `heimdall remote issuer-trust add <file> \| remove <fingerprint> \| list` and `heimdall remote time-source set <client> \| clear \| show`, run at the runner (an interactive ssh TTY counts); `environment add`'s bootstrap may run them in its TTY session | `contract`, `runtime::runner*`, `heimdall` | ruling 8 (b); U3-Q7 |

**Readings confirmed by the rulings (2026-11-21), subject to the W2 review:**
- §18.6 items 1–7 are approved.
- (a) The refresh dependency of a runner's managed binding is the contract value `controller` (ADR-0012 §4.5 names it).
- (b) `issuer_trust` and the time-source designation stay `meta` keys. Recovery treats them as authority-bearing: they are in the snapshot and compared, and never silently restored to a different value. Their writers are runner-local and attended (item 7).
- (c) The re-implemented authorized_keys writer stands for W2. In W3 the shared safety steps (link refusal, compare-then-rename, append-only add, the re-read check) move into one module that both the enrollment writer and `runtime::paired_lines` use, with both callers' tests passing.
- Several `authorizedkeysfile` entries verify only as sshd's default pair; any other list leaves the runner owner-only (ADR-0012 §3.2).

**The orchestrator's confirmation of the items 2, 4 and 7 readings (2026-11-21), with conditions:**
- **Item 2:** `iroh_admission` is part of the exact request bound into the `RemoteWidening` decision: its hash, and the exposure delta the owner confirmed runner-locally.
- **Item 4:** a first set is insert-if-absent, as one compare-and-set.
  - Two concurrent first sets cannot both win, and a first set never overwrites an existing row.
  - It is allowed only for a live, unrevoked client whose invitation carried `iroh_admission`, after the per-request role check and the revocation recheck.
  - Only a replacement bumps `remote_authority_generation`. A first set reaches the serve child through the documented child replacement (U56-Q10), not through a bump.
  - A race test is added only if the existing compare-and-set tests do not already cover two writers.
- **Item 7:** paired sessions are refused outright, never left pending: these forms have no remote decision path. The `meta` keys stay authority-bearing in recovery.

**The orchestrator's rulings on the W3 runner unit's questions (2026-11-21):**
- **Q1:** item 3's refusal is `USAGE_ERROR`, `fix_request`, effect `none`. The code table has no `INVALID_REQUEST` (a doc correction).
- **Q2, the bootstrap owner and Iroh (item 8 below).**
- **Q5, local-only forms from a paired session:** `INTERACTION_REQUIRED` with the new additive reason `local_owner_required` (item 9 below).
- **Q3:** a runner with its runtime offers `runner/1` to owner sessions only. This holds while ADR-0012's role table makes every `runner.*` form owner-only; a form that belongs to another role is gated per request instead. The per-request role check applies to every form either way.
- **Q4:** `RunnerLocal` sits under `remote-control/1`. The capability only gates availability; authority is checked per request.
- **Q12:** `remote issuer-trust add --controller <cid>` defaults to the only active owner and must be named when there are several. It stays hidden. The attended confirmation shows the controller's client ID and its K_mgmt fingerprint.

| Item | What lands | Where | Source |
|---|---|---|---|
| 8 | **Iroh admission is an attribute of the client**, as well as of the invitation. Invited clients and the bootstrap owner follow one rule.<br>- **Join:** copies the invitation's `iroh_admission` to the client.<br>- **First set:** `RotateEndpoint`'s first set reads the client's admission.<br>- **The bootstrap owner:** `remote init --iroh-endpoint <id>`, validated by the Iroh library's own parser (anything else is refused). The runner-local TTY confirmation shows the endpoint ID next to the owner key's fingerprint. The admission and the endpoint row are recorded in the owner enrollment's transaction.<br>- **A later opt-in:** `remote init`'s idempotent repair path (same key, same client), with the same confirmation. It only adds admission and a first endpoint, and never replaces an existing endpoint (that is `RotateEndpoint`'s job). | `store` (migration 0011), `remote`, `runtime::paired`, `heimdall` (`remote init`), `app::remote_env_ssh` | orchestrator ruling Q2 |
| 9 | **Reason `local_owner_required`** (`INTERACTION_REQUIRED`), for a local-only form sent from a paired session: `runner_local.*`, `controller_record.*`, and a paired `decide`, which had no reason before. Without a reason a wrapper cannot tell this from "ask the user and retry", and a retry from the paired session can never succeed. Adding a reason where there was none is additive; the goldens that change are listed at integration | `contract::envelope` (`reason::M06`), `runtime::paired`, `remote::roles` | orchestrator ruling Q5 |
| 10 | **`TransportRequest::Rotate`** (kind `transport.rotate`; a rotation, not a widening): rotates this device's K_iroh through the runtime, so `transport rotate` no longer answers `SERVICE_UNAVAILABLE` while a runtime runs. Local owner only; a paired session gets `INTERACTION_REQUIRED` / `local_owner_required`.<br>- **Retry-safe, as `device retire`:** the new key is stored as a new item and the old key is never overwritten.<br>- **Per runner:** each recorded runner gets `RotateEndpoint`; a runner that fails stays recorded as pending.<br>- **A re-run** finishes the pending runners and mints no further key.<br>- **The old K_iroh** is destroyed only after every recorded runner has acknowledged or been forgotten.<br>- **Output:** names the runners still pending. | `contract::route`, `runtime`, `app::transport`, `credential`, `heimdall` | orchestrator ruling (surface Q1), 2026-11-21 |

**Also ruled (surface Q2, 2026-11-21):** on an Iroh leg the client-line window applies once per connect, not once per route: the line is held and replayed, so later routes wait only for the server's identification (ADR-0012 §5.5 item 5).

**The orchestrator's rulings on the U4 unit's questions (2026-11-21):**

| Item | What lands | Where | Source |
|---|---|---|---|
| 11 | **Reason `resync_pending`** (`CAPABILITY_UNAVAILABLE`): issuance refused until the authority report and resynchronization are complete. The controller's barrier answers it, and so does a **per-session gate on the runner**: the runner refuses prepare and install from any session that has not completed the report and resync, whatever the controller does | `contract::envelope`, `app::remote_status`, `runtime::runner*` | U4 Q1, Q2 |
| 12 | The prepare answer carries an optional **policy ID** (omitted when none), so the controller's barrier can refuse a paused or cut-off scope earlier. The runner's install check stays authoritative | `contract`, `runtime::runner_issuance`, `app::remote_status` | U4 Q6 |
| 13 | `environment status --json`: the remote fields (connectivity, last-known readiness, pending effects, residuals) sit in each environment's entry. There is no separate `remote_status` array | `app::remote_env`, `heimdall` | U4 Q8 |

**Semantics ruled with them (recorded in ADR-0012 §7):** a cutoff that fired under uncertain time stays fired; a runner-local attended `resume` or `clear_cutoff` lifts a delivered pause or cutoff; a cutoff covers the policies that exist at delivery; a revoke is never defeated by a stale generation.
| 14 | `RunnerLocalRequest::EnrollOwner { client, public_key, iroh_endpoint, request_id }`, kind `runner_local.enroll_owner`: `remote init`'s repair path when a runtime already runs (M06-W2-R02). Attended, local owner only, with the same TTY confirmation as `remote init`; it adds admission and a first endpoint and never replaces one (item 8). Approved (2026-11-21): idempotent per `request_id` and for the same key and client; a paired session gets `local_owner_required` | `contract::remote`, `runtime::paired`, `heimdall` | follow-ups A (W2-R02) |
| 15 | `local_owner_required` also on the remaining attended-only forms sent from a paired session: `confirm_time`, issuer unlock, `device retire` and attend. One rule everywhere; the goldens that change are listed at integration | `runtime`, `ipc`, `remote::roles` | orchestrator ruling, 2026-11-21 |

**Also ruled (2026-11-21):**
- `remote init` may create a missing `~/.ssh` (0700) after the TTY confirmation: only if absent, never changing an existing directory's mode or owner, refusing a symlink or a directory the account does not own, and writing `authorized_keys` 0600 through the shared module. A home directory that would fail sshd's `StrictModes` is reported in the output and in `doctor`, not fixed.
- A debug-only variable `HEIMDALL_TEST_RUNNER_SSHD_CONFIG` (an absolute path, used only as the `sshd -T` check's configuration path) is read under `cfg(debug_assertions)` and is in `testcfg`'s refused set for release builds.
- A first `remote init` while a non-runner runtime runs answers `driver_unavailable`, and its message says to stop the local runtime first.

**The orchestrator's ruling on the probe-mismatch trigger (2026-11-21):**

| Item | What lands | Where | Source |
|---|---|---|---|
| 16 | `Join.probe: Option<ProbeObservation>` (omitted when none): what the joining device's four probes observed (PTY, `-W` forward, agent forwarding with a disposable agent, `SetEnv` canary). The runner runs the policy check before the join's commit. A disagreeing join is refused (`management_sshd_unsupported`) and the runner goes owner-only, permanently. A limited-role join without an observation is refused; owner joins are exempt | `contract::remote`, `remote`, `runtime::paired`, `app::remote_env` | ruling on follow-ups C Q3 |
| 17 | **The bridge checks its own session at start.** If sshd allocated a PTY (`SSH_TTY` set) or forwarded an agent (`SSH_AUTH_SOCK` set), it refuses the session, and the runner goes owner-only, permanently, with a doctor finding. No contract type | `heimdall` (`remote serve`), `runtime::paired` | same ruling |

- `request_id` is **advisory** for `runner_local.*`: those forms are idempotent by convergence, and each is attended, so a reused ID with a different body gets its own confirmation. Wrappers must not rely on detecting a mismatched reuse for them.
- A refused `~/.ssh` answers `CONFIG_CONFLICT` before the confirmation. New output names: `strict_modes` (`remote init`) and the doctor finding `runner_ssh_strict_modes`.

**The orchestrator's ruling on storing and lifting the owner-only downgrade (2026-11-21):**

| Item | What lands | Where | Source |
|---|---|---|---|
| 18 | **The downgrade is an authority-bearing `meta` key**, not a marker file: in the recovery snapshot, compared, and never silently restored to a different value (a restore that would clear it keeps it set). The uninstall inventory lists it | `store`, `runtime::paired`, `heimdall` | ruling on follow-ups D Q1–Q2 |
| 19 | **Lifting it is a local, attended widening that needs fresh evidence from the real path**; `sshd -T` alone never lifts it.<br>- **On the owner's controller:** `heimdall environment recheck <env>` (owner only) runs the four probes over a real management session and sends `RemoteEnvironmentRequest::RunnerPolicyRecheck { environment, probe }` (kind `remote_environment.runner_policy_recheck`, owner only). The runner records the result only when `sshd -T` verifies now and the probe agrees; otherwise it refuses with the reason.<br>- **On the runner:** `heimdall remote policy recheck` (hidden; `RunnerLocalRequest::PolicyRecheck { request_id }` when a runtime runs; `local_owner_required` from a paired session) shows that evidence, with its time and the probing controller, and clears the downgrade only after the TTY confirmation.<br>- **Refused:** evidence older than 15 minutes, or from before a later downgrade. | `contract::remote`, `remote`, `runtime::paired`, `app::remote_env`, `heimdall` | same ruling |

- An inconclusive probe means no limited-role join; the controller's message says the probe was inconclusive, so only an owner join is possible.

### 18.8 Revision 6.4 (M06 wave 4)

Additive; schema major stays `"1"`; every new field is omitted when empty. Rulings of 2026-11-21 (m06-plan §2).

| Item | What lands | Where | Source |
|---|---|---|---|
| 1 | `EnsureRequest.pair_issuers` (omitted when empty): per pair, the fingerprint of the CA the controller will issue from. Set by the forwarding controller, or by the runner's local owner for a CA already in the runner's `issuer_trust` (a pending grant only). The runner resolves a pair to a managed certificate only when that CA is trusted for the naming party; otherwise `issuer_untrusted` | `contract::request`, `app::operations::runner_m06` | W4 `grant-e2e` |
| 2 | `AuthorityReport.pending_grants` (omitted when empty): the runner's grants awaiting their issuer, for record source (b) | `contract::remote`, `runtime::runner*` | W4 `grant-e2e` |
| 3 | The pending answer (`ACCEPTED`, no reason) carries `refresh_dependency: controller` and `remote_pending` (grant IDs) in its data | `contract::envelope` | W4 `grant-e2e` |
| 4 | `heimdall environment resume-issuance <env>` and its local-owner, attended form: the controller-side acknowledgement of a lift. Issuance after a delivered pause or cutoff resumes only when the runner's report shows the lift and this acknowledgement is recorded. The form is `controller_record.resume_issuance` (it writes the controller's own record, on the local-owner path of §18.7 item 6; confirmed 2026-11-21). The acknowledgement names the specific delivered effect and releases only that one; it never pre-acknowledges a later cutoff. The form carries `effects` (required, nonempty): the effect IDs the owner was shown before the confirmation. An empty list is `USAGE_ERROR`; an unknown ID, another environment's, or one not delivered is `NOT_FOUND`; either way nothing is written for any ID. The acknowledgement row is migration `0012_remote_lift_acks` (schema 12), recovery class `Rows` | `contract::controller_record`, `store`, `app::remote_status*`, `heimdall` | ruling on M06-W3-R02 |

### 18.9 Revision 6.5 (M06 wave 5)

Additive; schema major stays `"1"`; every new field is omitted when empty or default. Accepted by the orchestrator as contract owner, 2026-11-22.

| Item | What lands | Where | Source |
|---|---|---|---|
| 1 | The serve policy's `sshd_port` (omitted when 22): `heimdall transport enable --serve --sshd-port <n>`, validated 1–65535. The target host stays `127.0.0.1` and is never configurable. Changing the port of an enabled serving endpoint is `transport disable`, then `transport enable --serve --sshd-port <n>` (a new attended serve decision); `transport enable` with any other configuration is refused `CONFIG_CONFLICT` and changes nothing (corrected 2026-11-23, M06-W5-R03) | `contract::route`, `runtime::supervise_transport`, `heimdall` | ruling on W5 `w5d` Q2 (ADR-0012 §2.3) |
| 2 | `access allow --profile <P> --environment <RUNNER>`: a controller-held standing policy naming exactly one recorded runner (record source (b), ADR-0005 §3.5 condition 8). No new form: the existing policy request, with the managed-set refusal lifted for exactly this case | `app::operations`, `heimdall` | ruling of 2026-11-22 |
| 3 | The hidden `access ensure --issuer-ca <fingerprint>` on a runner sets `pair_issuers` (§18.8 item 1); the runtime refuses it from an unattended local owner | `heimdall`, `app::operations::runner_m06` | ruling of 2026-11-22 |

| 4 | The runner's authority report states, per delivered pause or cutoff revision, whether that effect is **still in force** (an additive field; only a runner-local lift clears it). ⟨M06-W5-RC01, 2026-11-23⟩ A delivered effect stays in force until a lift that names it is approved; removing or narrowing a policy never lifts it, and the report only reads the flag. A lift counts only when the runner reports that specific effect no longer in force **and** the owner has acknowledged it (§18.8 item 4). This replaces reading "nothing in scope is in force", which left a policy-less runner with one effective key | `contract::remote`, `runtime::runner_effects`, `app::remote_status_barrier` | ruling on W5 `w5e` Q5 |
| 5 | `remote_environment.rotate_endpoint` moves to the base capability, for the session's own client only, with the per-request check unchanged (§18.7 item 4 says "any role") | `contract::request`, `remote::roles`, `runtime::paired` | ruling on `w5e` Q6 |
| 6 | **Limited roles' product use.** A viewer's `environment status <env>` opens a session and shows the runner's own view through read-only forms. A requester's `access ensure --environment <env>` submits the request with no record and no CA named; the runner admits it under its own policy or a runner-local decision, and it stays pending until an owner controller's record covers it. Nothing is signed on a requester's word. A limited role's owner command is refused `role_insufficient` on the controller. A limited record is forgotten locally by `environment remove` without the revoke; the output says an owner must still revoke that client on the runner | `app::remote_env`, `runtime::controller_host`, `heimdall` | ruling on `w5e` Q1–Q3 |
| 7 | `environment remove` also forgets, in its transaction, the runner's delivered grants, undelivered effects, outbox and acknowledgement rows, and the contact record (last report, held state) | `store`, `app::remote_env` | W4-R03 and the ruling on `w5e` |

| 8 | **Local widening decisions.** The widening decision record gains `origin` (`local` \| `paired`; an additive field on the decision document). `client_id` is null only when `origin = local`, enforced by a CHECK constraint in the migration. Only a non-paired, attended session the runtime has authenticated as the installation's local owner may submit `origin = local`; a paired session never can. Approval is bound to the exact delta and executes only on an attended local approve. A local submission is idempotent by (`origin = local`, request kind, delta digest). The executor exists on every installation: serve on a runner; `adopt-roost` and a widening `route add` on a controller (ADR-0012 §3.10 item 4) | `contract`, `domain`, `store` (migration), `app`, `runtime`, `heimdall` | ruling on W5 `w5k` item 9 |

| 9 | **`route add --relay <URL>`** (repeatable; a frozen-surface addition, accepted 2026-11-22): the relay consent of ADR-0012 §2.1, so `route add` can be a widening. The URL is validated before any record is written: only the schemes the relay transport accepts; userinfo, a query string carrying credentials, and a fragment are refused, so no secret can arrive through it. It is normalised first, so the delta digest and the retry dedup see one spelling. Each flag's URL is named in the delta. It is in the CLI contract, the help text, the frozen-surface ledger and the release gate's surface list | `contract::route`, `app::routes_ops`, `heimdall` | ruling on W5 `w5m` Q1 |
| 10 | An **unattended local widening** answers `INTERACTION_REQUIRED` (not `exposure_unconsented`), with the detail naming the widening and the exposure-consent reason where the envelope has a reason field | `app`, `runtime` | ruling on `w5m` Q2 |

| 11 | **`route.record_health`:** the route helper reports each attempt to the runtime. Only the caller holding the binding for that pair's slot may report, for that binding's routes; the report is typed (a route ID from the stored set, an outcome code, a bounded duration); it can only reorder among stored, owner-approved, pinned routes; reports are bounded per binding and kept **in memory only**. Two keys in `inspect destinations` show the latest result | `contract::route`, `runtime`, `app::routes*`, `heimdall` | ruling on W5 `w5n` Q1 |

**Deferred to the next contract revision (M07's U0 list):** a contract field for the runner launch's provenance report, which is a stderr line today; and a reason token for the Windows probe refusal (`CAPABILITY_UNAVAILABLE`, no reason today).

**Additions recorded at the W5 candidate (2026-11-23):**
- **Item 8, the document:** in `inspect decisions`, a `remote_widening` decision's `request` carries `origin` (omitted when `paired`); `client` is absent exactly when `origin` is `local`. A lift also carries `lifted_effects[]` (scope, kind, the delivering controller, revision, effect ID, delivered time). The four example documents are `tests/contracts/golden/rev6-5-decisions.golden.json`. A lapsed local record reads as expired with a `reason` key; the lapse is settled at the next decision read, resubmission or approval attempt (nothing sweeps on a timer).
- **Item 9, as built:** `https` and `http` only (the schemes the relay transport accepts); userinfo, **any** query string, a fragment and a malformed URL are each refused, and no refusal quotes the URL. The relay set is normalised, sorted and deduplicated, so the delta names each URL once, sorted, not in flag order. No frozen-surface ledger exists yet; the flag is recorded in the `route-add.txt` help golden.
- **Item 10:** the `INTERACTION_REQUIRED` answer carries no reason: the reason table binds `exposure_unconsented` to `CAPABILITY_UNAVAILABLE`, and `local_owner_required` means a paired session. A reason for it waits for the next revision.
- **Item 11, as built:** the form carries a required `endpoint` (the caller's binding endpoint, by which the runtime finds the binding that holds the slot) and each attempt an optional `duration_ms`.
- **`setup apply --allow-config-commands`** (new flag): without it `setup apply` uses the static pin check only and never runs `ssh -G`; an alias whose pin the static check cannot decide is reported undetermined, with the finding `routes_not_used_by_ordinary_ssh` for existing-access aliases with several routes.

**Added at the W5 fix commit (2026-11-23; rulings on the W5 `w5q` diagnosis):**

| Item | What lands | Where | Source |
|---|---|---|---|
| 12 | **The controller's management key agent:** four additive reasons, split by whether an unchanged retry can help (the code table's placement rule: a refusal that an unchanged retry cannot fix belongs under `CAPABILITY_UNAVAILABLE`). `mgmt_agent_path_too_long` and `mgmt_agent_permission_denied` are under `CAPABILITY_UNAVAILABLE` (exit 4, not retryable; the message names the fix: a shorter runtime or temporary directory, or that directory's ownership or permissions). `mgmt_agent_address_in_use` (only after three fresh random names were all taken) and `mgmt_agent_unavailable` are under `STATE_UNAVAILABLE` (retryable). The message names this controller's agent and why, never a path. Every other failure of the session opener on this controller names this controller, never the runner's runtime; the session directory and its file writes answer `CAPABILITY_UNAVAILABLE` for a permission or read-only failure and `STATE_UNAVAILABLE` otherwise. On Unix the agent's and the probes' sockets live in `<owner-only $XDG_RUNTIME_DIR, else /tmp>/heimdall-mgmt-<16 hex>/`, created exclusively with mode 0700 (the endpoint directory checks of `ipc::unix`), refused before anything is created when the path would pass the platform's socket-path limit, and removed at session end; a crash's leftover is removed only when its name, owner, mode, contents (its own dead sockets only) and a 60 s quiet period all match. Windows pipes are unchanged apart from the reason | `contract::envelope`, `ipc::unix`, `credential::mgmt::agent`, `app::remote_env`, `heimdall` | rulings on the `w5q` findings |
- **Item 9, relay URLs and credentials (M06-W5-R05, 2026-11-23):** a relay URL must not carry a credential anywhere, its path included. It is stored and consented as given, and every answer, error, decision view, `inspect` and event shows it only as its scheme, host and port with `(sha256:<first 12 hex of the SHA-256 of the full URL>)`.
- **M06-W5-R01 (2026-11-23):** every lift that a `resume` or `clear-cutoff` approval would cause is listed in `lifted_effects`, whatever the delivered effect's scope; `access resume --policy P` on a runner holding P takes the targeted path; an approval whose re-check finds a lift its decision does not name (the state changed after issuance) is refused `DECISION_STALE` (ADR-0006 §3.1; `next: fix_request`: get a fresh decision), and nothing is lifted; `decision_binding_mismatch` keeps its meaning (a decision used for another action or parameters). A paired session's request that would lift a delivered effect is refused at request time, `CAPABILITY_UNAVAILABLE` / `role_insufficient`, with no decision record. (Rulings of 2026-11-23.)
- **M06-W5-R02 (2026-11-23):** `route add` for an approved Iroh endpoint with a different relay set answers `CONFIG_CONFLICT` (remove the route and add it again), never `already_present`.

**Item 13 (2026-11-23; M06-W5-RC04): why a runner could not be reached, and the Windows `ProgramData` refusal.** Six additive reasons, from what the controller's `ssh` actually did (no path or address in any message), split by the code table's placement rule:

| Reason | Code | When |
|---|---|---|
| `ssh_client_not_started` | `CAPABILITY_UNAVAILABLE` | the controller's OpenSSH client could not be spawned, or ended with a status outside 0–255 and said nothing |
| `ssh_client_config_rejected` | `CAPABILITY_UNAVAILABLE` | the client refused its own options or configuration before connecting (bad option, an unopenable config file or `-E` log, bad owner or permissions, usage text) |
| `ssh_connection_refused` | `DESTINATION_UNREACHABLE` | "Connection refused" |
| `ssh_connection_timed_out` | `DESTINATION_UNREACHABLE` | "Connection timed out", "Operation timed out" (including the banner exchange), or the preflight's own timeout |
| `ssh_name_not_resolved` | `DESTINATION_UNREACHABLE` | "Could not resolve host…" |
| `ssh_unreachable_other` | `DESTINATION_UNREACHABLE` | any other unreached outcome, or nothing said (keeps the old message) |

- **Placement rule:** a cause the controller's own client made (`ssh_client_*`), which an unchanged retry cannot fix, is `CAPABILITY_UNAVAILABLE`; what happened on the way to the runner (refused, timed out, name not resolved, other) stays `DESTINATION_UNREACHABLE`.
- **RC03 row:** the management session's `ssh_client_*` errors are flagged as this controller's (§18.9 item 12).
- **The Windows `ProgramData` refusal:** on Windows, a missing `ProgramData` is refused before any preflight, bootstrap or management-session `ssh` starts (`CAPABILITY_UNAVAILABLE`, `ssh_client_not_started`, naming the variable): Win32-OpenSSH reads it before its error output exists and would exit 255 with nothing said (PC jobs 42 and 44; fixed and verified by PC job 45).
- **The recorded deviation, closed at the M06 exit (2026-11-23):** the M06 launches of `ssh` (the preflight, the bootstrap session, the management session and the confirming probes) now fill `ProgramData` and the related variables from the operating system, like every other product launch of `ssh`. The fill is injected as a function parameter (`heimdall_app::remote_env::ssh::OpensshEnvFill`: a field of `BootstrapSsh`, a parameter of `spawn_management`, `run_probe` and `run_probes`), and the `heimdall` binary wires `heimdall_localenv::sys::openssh_env::fill_openssh_environment` (`m06_cmd::OPENSSH_FILL`), so `heimdall-app` still does not depend on `heimdall-localenv`. Each launch applies the fill, then the guard (`prepare_client_environment`), which stays as the backstop: if the fill cannot supply `ProgramData`, the refusal above still fires. Tests: `remote_env::ssh::tests::the_fill_supplies_what_the_parent_environment_lacks`, `…::without_the_fills_source_the_guard_still_refuses`, `…::every_m06_launch_carries_the_fill` (Unix, each launch site) and `heimdall`'s `m06_cmd::tests::the_os_fill_reaches_an_m06_launch_without_program_data` (the real fill; on Windows it supplies the variables, elsewhere the guard refuses). Windows verification is pending the exit PC run.
- **The fill without the caller's `SystemDrive` (PC job 53, 2026-11-24):** job 53 found that `SHGetKnownFolderPath(FOLDERID_ProgramData)` expands from Heimdall's **own** environment and fails (`0x80070003`) when that environment has no `SystemDrive`, so a Heimdall started from a cleared environment could not fill `ProgramData` and the guard refused (the `-WithoutProgramData` journey, 0 of 10). Fixed in the shared fill, `heimdall_localenv::sys::openssh_env::fill_openssh_environment`, so it is fixed across every Windows launch of `ssh` that uses it: `connect`, `run`, the WSL helper and the M06 launches, not as an M06-only item. When the known folder fails and Heimdall has no `SystemDrive`, `ProgramData` and `ALLUSERSPROFILE` are the documented default `<drive>\ProgramData` and `SystemDrive` is that drive, derived from the Windows directory (`FOLDERID_Windows`); Heimdall's own environment is never changed, and the guard stays as the backstop. Sources: Microsoft Learn, *KNOWNFOLDERID* (the default path of `FOLDERID_ProgramData`, `%ALLUSERSPROFILE%` = `%SystemDrive%\ProgramData`; https://learn.microsoft.com/en-us/windows/win32/shell/knownfolderid) and *SHGetKnownFolderPath function* (it takes no environment: `hToken` selects only a user; https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetknownfolderpath). Test: `heimdall-localenv`'s `sys::openssh_env::tests::the_fill_supplies_system_drive_and_program_data_without_the_callers_system_drive` (Windows: a child process with the driver's cleared environment) and `…::the_system_drive_and_default_program_data_derive_from_the_windows_directory` (any platform). **Stated limits:** (1) the drive comes from `FOLDERID_Windows`, which relies on the caller's `windir`: with neither `SystemDrive` nor `windir` present, the guard refuses; (2) in that fallback a relocated `ProgramData` is not followed: the documented default `<drive>\ProgramData` is used.
- **The WSL helper:** `wsl_command` now fills `ProgramData` and related variables from the operating system. PC job 45's probe showed that WSL interop hands `wsl.exe`'s environment to the Windows process it starts (`without=programdata=unset`, `with=programdata=set`), so this closed a real-user defect on the WSL preview path.


### 18.10 Revision 6.6 (the M06 exit; the last revision of 6.x)

Additive; schema major stays `"1"`. Accepted by the orchestrator as contract owner, 2026-11-23 (ruling Q-B, with ADR-0015).

| Item | What lands | Where | Source |
|---|---|---|---|
| 1 | `RouteFailureClass` gains `driver_unavailable`: an attempt on a leg whose driver is not in this build (an Iroh leg in a build without the `iroh` feature). The leg is never dialed and is failed over, so the route's direct and jump legs are still tried. A route whose legs are all of that kind refuses `CAPABILITY_UNAVAILABLE` with the existing reason `driver_unavailable`, after its attempts are recorded, and its message names the Iroh transport preview and how to build it (ADR-0015). A build with `iroh` but no verified key store is unchanged (`refused`) | `contract::route`, `app::routes`, `app::routes_failover`; `schemas/public-api/` regenerated | ADR-0015; the orchestrator's ruling Q-B, 2026-11-23 |

**Revision 6.x is closed with this revision** (the M06 exit). Revision 7 (ADR-0013 §11) is re-based from 6.1 onto 6.6 by the contract owner at U0.

## 19. ⟨rev7⟩ Revision 7, provisional (the preparatory part: M07 U0 and M08 U0)

Revision 7 is ADR-0013 §11 (D1–D21) and ADR-0014 §7 (H1–H15), **layered on revision 6.6**
(§18.10), under the contract owner's rulings of 2026-11-24 on U0-Q1 to Q14 and on the U0 plan
(`docs/architecture/u0-plan.md`). It is **provisional** until G08 is ratified (ADR-0013 §1.2): the
native A19 and A32 rows of M07 U9. Schema major stays `"1"`.

### 19.1 What lands now, and what does not

**The bound (ADR-0013 §1.3).** This part lands only what no live path emits: types, schemas
and reason constants as unused additions; the command-tree golden, the help lint, the
primitive index and the reason table; the replay corpus; store migration 0014 (H9); the
case-insensitive alias check at write (U0-Q9); and the skeletons of the new commands. Every
live wire-shape change is a later change (U3, U2b), one per correction, with its emitters,
every in-tree reader and its goldens.

**Standalone types (the ruling on S0).** No field is attached to an existing wire struct here:
each extension is a standalone type with its own schema under `schemas/public-api/declared/`
(`schema::declared_schemas`; answered by `schema show <name>`, not listed by `inspect
capabilities`). The change that attaches it, with its emitters and readers, moves its schema to
`schemas/public-api/`. **Every published schema of a live document is byte-identical** to
revision 6.6's, and so is every live answer except the additions below.

**What a client can observe change now:**
- `schema show primitives` (D7) and `schema show reasons` (D8), also exported as
  `schemas/public-api/primitives.json` and `reasons.json`;
- `schema show <declared name>`;
- the new commands `support bundle`, `state status|restore|reset|repair`, `service stop
  --preview` and `inspect request <REQUEST_ID>`: each answers `USAGE_ERROR` (exit 2, effect
  `none`, next `fix_request`), "this command is not available in this build", whatever flags it
  is given (the ruling on ASK-H3), before any runtime contact, home creation or file read. "Whatever
  flags" means any valid invocation: a malformed one (a missing required argument, an unknown
  flag) is clap's usage refusal, also exit 2 (review U0-R07, ruled);
- `inspect <subject> <ID>` for a subject other than `request` is `USAGE_ERROR`;
- help text names no milestone, ADR, section or test-only wording (D14), and `activate --hook`
  is hidden from help (an integration endpoint, §2.3 of ADR-0013);
- a catalog write that creates a destination, or renames one, into a case-variant of another
  destination's alias is refused `CONFIG_CONFLICT` / `alias_collision` (U0-Q9);
- the store migrates to schema version 14 (an older build then refuses it, as for every
  migration).

**Not in this part:** the version string (`1.0.0-rc.1` is set once at the M08 candidate commit
with U8's claims update; the ruling on ASK-VERSION: every claim entry pins its signer build, so
the bump makes every claimed field read `unknown` until then); `REQUEST_STALE` in the code table
(the ruling on ASK-CODE: declared in the reason table only, it joins `Code` with its emitter and
both harnesses' tables); any flag that would refuse (ASK-FLAGS: `--request-epoch` and `access
release --request-id` arrive with their checks); H11 (M08 U3c), H12 and H15 (U2b).

### 19.2 ADR-0013's deltas

| # | This part | Where | Later |
|---|---|---|---|
| D1 | Typed views for every untyped read: `inspect` subjects, `status`, `service-status`, `operation`, the subscription head, the stream line, `environment status` and `GrantResidual` (Q14); keys kept, subject metadata kept | `contract::views`; `tests/contracts/rev7_views.rs` | U3 builders (PC2) |
| D2 | `pages/1` declared, not offered; `PageRequest`, `Select`, `Page`, `Selection`, `PageToken`; the limits | `contract::page`, `ipc::capability::PAGES_V1` | U3 |
| D3 | The command-tree golden; M06's names are in. **E8 (ruled 2026-11-24):** revision 7 gives the hidden endpoints no declarative flags; `route connect`, `transport serve` and `remote serve` stay hidden, frozen integration endpoints that take trailing arguments as today. Human help text is not frozen: the golden pins paths and flags, the help lint the text rules | `heimdall::cli_tree_tests`, `golden/command-tree.golden.txt` | — |
| D4 | `EventSnapshot` and its caps | `contract::event` | U3 (PC1) |
| D5 | `EventPayload`, every key as emitted; the emission-site registry | `contract::event_payload`; `tests/contracts/rev7_events.rs`, `golden/event-emission-sites.json` | — |
| D6 | `ResyncReason`; the resync reasons | `contract::event`, `envelope::reason` | U3 (PC5, PC6, PC9, PC10) |
| D7 | The primitive index (six groups) | `contract::primitives` | — |
| D8 | The reason table: every error reason with every code it is emitted under; pending, resync and warning reasons apart; `declared_codes` | `contract::reasons` | — |
| D9 | The per-field inventory | `golden/views-null-inventory.md` | U3 (PC3) |
| D10 | — (the views carry no new field yet) | — | U3 |
| D11 | Ruled (Q12): M06's `route_health` and `host_pin_defeated` on each `inspect destinations` item are D11, omitted when there is no report; typed in the destinations view. `route_health` is the latest report per destination, ignoring `account`, held in memory since the runtime started, and omitted when there is no report (D9). ADR-0010 §10's per-pair dependency status is `deferred_with_decision` past 1.0 (the consumer has `route_dependency_out_of_scope` and `route_undetermined`) | `contract::views::catalog` | U3 (a test of the emitted `route` event) |
| D12 | The `service-status` view; `runtime_not_running`, `runtime_unreachable` (H14), `endpoint_untrusted` | `contract::views::status`, `envelope::reason::REV7` | U3 |
| D13 | `destination_has_live_access`; `LiveAccessRefusal` | `contract::envelope` | U3 with U8b |
| D14 | The help lint, with no exemption left; `cli.rs` help rewritten, and `m06_cmd.rs`'s `remote` help strings once M06's exit was on this branch (review R08(f)) | `heimdall::cli_tree_tests` | — |
| D15 | The spec text below (§19.7), for the contract owner to apply | — | the orchestrator |
| D16–D18 | §19.6 | — | ratification |
| D19 | `response_too_large`; `ResponseTooLarge` | `contract::envelope` | U3 (PC4) |
| D20 | The bounds (§19.5) and `item_too_large` | `contract::bounds` | U3 (PC11) |
| D21 | `page_token_invalid`, `selector_invalid`; `route_undetermined` exists | `envelope::reason` | U3 |

### 19.3 ADR-0014's deltas

| # | This part | Where | Later |
|---|---|---|---|
| H1 | `support bundle` skeleton; `SupportBundleManifest` | `heimdall::rev7_cmd`, `contract::lifecycle` | U6b |
| H2 | `service stop --preview` skeleton; `StopPreview` | same | U2b |
| H3, Q8 | `state status|restore|reset|repair` skeletons; `StateStatus`, `RestoreReport`, `ResetReport`, `RepairReport`; §19.4's authority rule | same | U2b |
| H4, H10 | `state_corrupt`, `state_newer_than_build`, `state_restored_authority_ended`, `client_quarantined_after_restore`, `invitation_void_after_restore`, `exposure_disabled_after_restore`; one event type `state_restored` (declared by name; `EventType` gains it with its emitter) with `StateRestoredPayload` | `envelope::reason::REV7`, `contract::lifecycle` | U2b |
| H5 | `executable_moved` (a name) | `contract::lifecycle` | U2b |
| H6 | `migration_backup`, `earlier_store_generation`, `previous_binary`, `git_block_moved` (names; `RemainingArtifactKind` gains them with their emitters) | `contract::lifecycle::residue_kind` | U2b |
| H7 | `BuildProvenance` | `contract::lifecycle` | U3 |
| H8 | — (§19.1) | — | M08 candidate |
| H9 | Migration 0014 | `crates/store/migrations/0014_restore_epoch.sql` | U2b writers |
| H13 | `request-epoch/1` declared, not offered; `RestoreEpoch`; the frame field's name; `REQUEST_STALE` declared with `restore_epoch_stale` and `restored_before_completion` | `contract::lifecycle`, `ipc::capability::REQUEST_EPOCH_V1` | one change: U2b with U3's readers |
| H11, H12, H14, H15 | — (H14's reason is in D12) | — | U3c, U2b, U3, U2b |

**H13, as ruled.** One optional `request_epoch` per request frame (`ClientMessage::Request`),
outside every canonical request hash; the hello reports `restore_epoch`. A mutating request
whose epoch is not current is refused `REQUEST_STALE` / `restore_epoch_stale` before any store
write or effect, attended or not; one with no epoch is bound to the current epoch at receipt,
and a fence for its key answers `REQUEST_STALE` / `restored_before_completion`. A client holding
a kept epoch refuses (`SCHEMA_UNSUPPORTED`) instead of sending to a runtime that does not offer
`request-epoch/1`; a fresh request with no kept epoch is sent without one. `REQUEST_STALE` is
exit class 6, not retryable, effect `none`, next `new_request_id` (U0-Q6). The residual: a
caller that re-stamps an old request ID with a new epoch is outside the contract. The server
check, the envelope's `request_epoch`, the CLI's `--request-epoch` and every consumer (the CLI
retry path, the TUI, the wrapper, H1, H2) land as one change.

**H13's role sets (orchestrator ruling, 2026-11-25, M08 W3 U2b-2 follow-up A).** `request-epoch/1`
is in the owner's and the **requester's** capability sets, not the viewer's (§18.2 reading 5 and
§18.1 row 4 amended): agents retry across a restore through the wrapper, and a requester's stale
retry must be refused, not bound at receipt. The role checks and the uninstall-fence admission
come before the epoch check and the request ledger, so a frame refused for its role or its
admission appends nothing, and a frame refused for its role gets the role refusal (stamped with
its frame epoch) even when that epoch is stale.

**H13's ledger is bounded (orchestrator ruling, 2026-11-26; M08 W4 U2b-3a, U2b-3a-F).** The
request ledger keeps ADR-0014 §3.6 step 4's retention: it drops an entry only after its settled
key's marker window (a key's settlement is kept by the ledger's digest once its operation is
purged), and never one whose settlement is unknown. Within the window nothing can be dropped, so a
new request key is refused before any append, `BACKPRESSURE` (retryable, effect `none`, next
`retry_after` with `retry_after_ms`), at a hard cap on live entries:
- **262,144 live entries** (`LEDGER_LIMIT`, about 12 MiB), whoever asks;
- **the last 65,536 reserved for owner-role callers** (`LEDGER_OWNER_RESERVE`), counted from the
  ledger's length: a caller without the owner role is refused once the ledger holds 196,608, so
  the last 65,536 entries are the owner role's (the local owner and paired owner clients)
  whatever another principal has sent. Because the count is the ledger's own, this holds across
  restarts;
- **32,768 per non-owner caller per runtime lifetime** (`LEDGER_CLIENT_SHARE`), counted in memory
  and keyed by the caller identity the session carries (principal plus client), covering every
  non-owner caller — local requester principals included — as well as paired clients other than
  the local owner (so one requester's flood refuses only that caller, until the reserve line);
  - **⟨ruling, 2026-11-27⟩ Who the share limits:** **the local owner is exempt, and every caller
    with a `remote_client` is share-limited, owner role included.** A paired owner is a remote
    principal; ADR-0012's T-RA5 counts a compromised owner controller among its threats.
    - The reserve exists so that no remote party can lock the local owner out.
    - A share of 32,768 is below the reserve of 65,536, so no paired owner can use up the
      reserve within one runtime lifetime.
- **the residual:** because the ledger holds no identifier, the share is counted in memory and
  resets at a restart, so a principal that floods across restarts can exceed its share, but never
  the owner's reserve. Since S2-01, a paired client cannot restart the runtime remotely.

A retry of a key already in the ledger is deduplicated (no append) and still answered at the
cap. Nothing is evicted to make room. The forms with no request ID (a policy's pause, cutoff or
stop, a client's revocation) append nothing and are never refused by the cap. With the default retention
(7 days, then the 30-day marker) the limit allows about 7,000 new request keys a day in the
steady state.

**H13's unrecorded decision references after a restore (orchestrator ruling, 2026-11-26; M08 W4
U2b-3a-F, option A).** Once the restore epoch is above 0, a `dec_` reference with no recorded
decision answers `DECISION_STALE` / `restore_epoch_stale` (effect `none`, next `fix_request`),
never `NOT_FOUND`, and writes nothing. Every decision minted under the current epoch is recorded
in the current generation and decision records are never purged (§7.4), so an unrecorded
reference cannot be current. A recorded decision keeps its existing answers, and at epoch 0 an
unrecorded reference keeps `NOT_FOUND`. The post-1.0 alternative (option B) is to carry the
restore epoch in the `dec_` ID format.

**H13's `access release` request IDs (orchestrator ruling, 2026-11-26; M08 W4 U2b-3a,
U2b-3a-F).** `access release` is idempotent by effect, not journaled: a reused `--request-id`
that names another binding releases that binding, with no `REQUEST_CONFLICT` (a repeated release
of an already-released binding answers `already_released`). The CLI mints no request ID when
`--request-id` is not given. Journaling `access release` is post-1.0, if it is ever wanted.

**`credential_lifecycle.cause` values for cutoffs (contract-owner ruling, 2026-11-26; M08 W4
SEC-5, SEC-5F).** `policy_cutoff` and `cutoff_fired_while_time_uncertain` are approved additive
values of `CredentialLifecycle.cause` (an existing optional `Option<String>` key on
`credential_lifecycle`, D5), emitted on `expired` events when a grant ends at a policy cutoff or
at a cutoff that fired under uncertain time. `crates/contract/src/event_payload.rs` and
`schemas/public-api/declared/event-payload.schema.json` document them; no published live schema
changes.

**Fail-closed `profile:` and `workspace:` cutoffs from another controller (orchestrator ruling,
2026-11-26; M08 W4 SEC-5, SEC-5F).** An in-force `profile:`- or `workspace:`-scoped cutoff
delivered by another controller (including one fired under uncertain time) blocks all of the
runner's remote issuance on this controller — for every policy, including policies created after
the cutoff fired — until the attended lift at the runner, because `ReportedPolicy` carries no
profile or workspace membership in 1.0. Carrying `ReportedPolicy` membership to narrow the block
to covered policies is the post-1.0 path.

### 19.4 The restore rule is an authority rule of this contract (H3)

ADR-0014 §3.6 is adopted as written, as part of this contract: a restore recovers identity and
configuration and **no authority**; what it keeps, ends, quarantines and voids (its table); the
carry-forward of the more restrictive state and of later terminal records; the restore epoch and
the replay fence (steps 1–7); identity binding and the refusals of the restore protocol; reset's
inventory-unavailable disclosure; "never, by any path". Recovery from `state_corrupt` in 1.0 is
`state restore --backup <file>` or `state reset`, both attended, with no automatic generation
picking; a damaged request ledger is repaired only by the attended `state repair` (U0-Q8: carry
every decodable record after the damage into the store as fence records, raise the restore
epoch, truncate at the first damaged record; the stated residual is that a request among the
dropped records retried without its epoch could run again).

### 19.5 Rulings applied (U0-Q1 to Q14)

- **Q1:** `APPROVAL_REQUIRED` for a session that can attend, `INTERACTION_REQUIRED` with the same
  `next.decision_ref` for one that cannot; every reader takes `decision_ref` under either code.
- **Q2:** no binding reference on `run`; a request ID names exactly one request; adoption of the
  `ensure` binding through a shared request ID is removed in U3 (a changing request under a used
  request ID is `REQUEST_CONFLICT`, next `new_request_id`).
- **Q3:** reasons under `CAPABILITY_UNAVAILABLE`: `mechanism_minimum_unmet`, `decision_denied`,
  `route_undetermined` (exists), and `probes_unavailable` (the refused confirming probe, named from
  its emission site `heimdall_app::remote_env::probes_unavailable`). Emitters are U3.
- **Q4:** `LaunchProvenance` with M06's four values (`runner_managed`, `independently_managed`,
  `controller_dependency`, `unknown`); the unattended refusal already carries its reasons
  (`controller_dependency`, `dependency_provenance_unknown`). Attachment to the run record is U3.
- **Q5, Q6:** §19.3.
- **Q7:** `inspect request <REQUEST_ID>` (`RequestView`: `state` `in_progress` | `completed` |
  `not_found`, `operation_id?`, `code?`, `request_epoch`), scoped to the caller's own namespace;
  `access release --request-id` and the repeated-release statement (`already_released`, no other
  effect); `inspect bindings`' `request_id` for its own caller only. U3.
- **Q8:** §19.4. **Q9:** catalog alias uniqueness is case-insensitive at write
  (`CONFIG_CONFLICT` / `alias_collision`); a write that keeps a destination's own stored alias
  byte for byte is allowed; existing pairs are reported by `doctor` (U1b, reading
  `Txn::destination_alias_case_collisions`), never rewritten. **Q10:** U1b.
- **Q11:** §19.6. **Q12:** D11 above. **Q13:** M07 U3 builds RC06 for both `inspect environments`
  (its remote row) and `environment status`: a capped `remote_pending` (at most 16 entries) with
  `remote_pending_count`, from a bounded store read; one change moves the CLI renderer, the four
  test files and the TUI reader. **Q14:** `GrantResidual` is A07's report, typed with a public
  schema and its statement unchanged; `EnsureData.residuals`, `attach_runner_readiness` and the
  hard-coded `runner_residuals` are removed in U3 as a pre-release correction; a per-component
  report is out of 1.0, stated as a limitation.
- **D20's numbers (ruled 2026-11-24; the 64 KiB item bound stays):** 200 profile pairs, 64
  identity declarations, 8 routes per destination, 8 relays per route and 16 per destination
  (relay URLs stay at 2,048 bytes), 4 consents and 3 direct addresses per route, 8 host-key pins
  per destination of at most 1,536 bytes each (an RSA-8192 pin is about 1.4 KB), 16 listed
  `remote_pending` entries. Each maximal-record test fills every field of its item at its bound
  at once, at its worst-case escaping (a label of `"`), and leaves 4 KiB (at most 61,440 bytes):
  a maximal profile is 58,381 bytes; a maximal destination with its routes (each with
  `external_roost`), its pair preference (`graceful`) and connection policy, the route-health view
  of the largest report `record_health` accepts and the longest host-pin setting is 58,569 bytes
  (view 6,208, routes 52,361; review U0-RC01; addresses with their zones). **`route_health` lists
  at most the 32 most recent attempts of its report, newest first, with `attempts_dropped`** (how
  many older attempts are not listed, omitted when none, the form of `resync_required`'s
  `dropped`; `ROUTE_HEALTH_VIEW_ATTEMPTS_MAX`, `RouteHealthView::from_report`): the diagnostic
  report is cut, not a user capacity. Before the cut the true worst case was 61,517 bytes, 77 over
  the line. **Address strings (ruled 2026-11-24):** each `direct_addresses` entry and each
  `BindScope::Interface.address` is at most `MAX_ADDRESS_BYTES` = 64 bytes (IPv6 with a zone ID).
  At write time (U3, PC11) each is parsed as an IP address with an optional zone and stored in its
  canonical text form; an unparseable entry or one over the bound is refused with `USAGE_ERROR`
  (`item_too_large` over the bound, next `fix_request` for an unparseable entry); a stored value
  that does not parse or exceeds the bound is reported, never rewritten. The maximal test fills
  each with the canonical IPv6 maximum and a 15-byte zone. Each bound, of bytes or of entries,
  refuses at write with `USAGE_ERROR` / `item_too_large` (`ItemTooLarge` names the field and the
  bound); a store that already exceeds one is reported, never truncated.
- **Next actions in the reason table (ruled 2026-11-24):** every row is one (reason, code)
  answer with the `next.action` it carries, so a well-behaved agent stops instead of looping:
  `state_corrupt` and `ledger_damaged` carry `owner_decision` (the attended repair or restore),
  `state_newer_than_build` carries `change_client`, and three M03 answers carry what their
  emission sites send today (`projection_pending`: `setup_apply`; `remote_step_in_progress`:
  `reconcile`; `managed_slot_held`: `release_binding`). The review's overrides (U0-R04):
  `response_too_large` under `USAGE_ERROR` carries `narrow_request` (a read refused before
  anything is sent), with one exception: a reply that does not fit after dispatch keeps its
  operation's true effect and reference and carries `observe`; `decision_denied` under
  `CAPABILITY_UNAVAILABLE` carries `none` (the person said no: stop, do not ask again); and
  `client_quarantined_after_restore`, `invitation_void_after_restore` and
  `exposure_disabled_after_restore` under `CAPABILITY_UNAVAILABLE` carry `owner_decision`
  (only the owner's reauthorization or a new local decision reopens). `retryable` is always
  the code's.
  `restore_epoch_stale` is an answer under both `REQUEST_STALE` (a request) and
  `DECISION_STALE` (`fix_request`; a decision reference minted under an older epoch).
- **The D1 views (ruled 2026-11-24):** a terminal operation with no `result` reads as
  withheld (PC3; `state` says it is terminal); `inspect projections`' `record` is omitted when
  nothing is committed; explicit `null`s inside verbatim persisted content are kept; one public
  schema per subject: U3 swaps each `<name>.full` declared view in for its public `<name>` by a
  rename (`inspect-environments.full`, `inspect-workspace.full`, `inspect-policies.full`); a
  subject whose view is typed elsewhere carries `preview` through `WithPreview<T>` (the view
  flattened, one flat object, `preview` omitted without a preview).
- **Q3's sites (ruled):** `--require-unattended` keeps `lock_continuity_unverified`;
  `mechanism_minimum_unmet` goes to the reason-less minimum refusals,
  `heimdall_app::error`'s `Denial::CapabilityUnavailable` and `operations::unmet_minimum`;
  `decision_denied` to the denial settlements (`operations.rs` `ApproveAuthority`,
  `ApplyProjection`, `DeclareInteraction`; `context_m05`'s cooldown; the enrollment and foreign
  removal denials; `remote::widening`'s runner-local denial); `probes_unavailable` to
  `remote_env::probes_unavailable` (`remote_env.rs:1413`, `:1568`), and the new
  `probe_inconclusive` (`DESTINATION_UNREACHABLE`) to the inconclusive probe (`:1435`, `:1571`).
  Carrying the managed adapter's reasons through the port is a
  live change, listed for U3.
- **M06's handoff (`docs/architecture/m06-u0-handoff.md`; ruled 2026-11-24):**
  - **M06-F7:** `route add` with an Iroh leg in a build without the driver is refused
    `CAPABILITY_UNAVAILABLE` / `driver_unavailable`, with the preview message, before any
    decision is recorded. The command tree is unchanged; rows a source build wrote keep the
    failover (6.6). U3 implements it.
  - **§18.9 item 10's reason:** an unattended local widening's `INTERACTION_REQUIRED` carries
    `local_widening_needs_attended_owner` (`reason::REV7`, next `interact`). Declared, not
    emitted; U3 adds the emitter.

### 19.6 Provisional ratifications (D16–D18) and decision-backed replay

- Revision 3's §15.2 items 1–7, revision 4's §16.2 items 1–18, revision 6 as ruled in §18.5 and the
  M06 W2–W3 readings; ADR-0006 §7.4's retention unchanged, with no ceiling.
- **Decision-backed replay (ADR-0013 §7) has two keyspaces (the ruling on Q11, option A):**
  - **paired:** `(client, kind, request_id)` bound to the canonical hash, with §7's five answers;
  - **local** (`origin = local`, ADR-0006 §18.9 item 8): keyed by the digest of the request without
    its ID and the exact delta; one pending record per digest; a terminal, claimed or expired
    record is never replayed, and a repeat is evaluated afresh against the current state (a still
    widening request gets a new decision; otherwise it runs, e.g. `already_present`).
  - The `runner_local.*` forms (§18.7's `trust_issuer`, `enroll_owner`) are **not**
    decision-backed replay (ruled 2026-11-24): `request_id` is advisory and a repeat converges by
    result.
  - `route add`, `transport enable` and `transport adopt-roost` are owner commands with no
    `--request-id`: each run is a new request, idempotent in effect. ADR-0013 §7's "agents always
    pass `--request-id`" covers the agent primitives only. Their frames carry the frame-level epoch,
    bound at send. After a restore a re-run needs a fresh local decision, because the restore
    closes pending decisions.
  - D16's precondition: M06's restart-replay coverage (`tests/integration/remote_runtime_m06.rs`,
    `decision_backed_replay_after_a_store_restart_answers_each_record_state`) covers the paired
    pending, claimed, terminal and expired records and the local pending one. U3 adds one test: a
    local widening retried after a restart from a terminal record is evaluated afresh.
- `remote_pending_reasons` (grants) stays distinct from revision 6's environment
  `remote_pending[].reason` (D17); coexistence, selection and removal as ADR-0013 §3.3 (D18).

### 19.7 Proposed text for spec §11.6 (D15; the contract owner applies it)

> Stable codes are `OK`, `ACCESS_READY`, `ACCEPTED`, `APPROVAL_REQUIRED`, `INTERACTION_REQUIRED`,
> `PROVIDER_LOCKED`, `CAPABILITY_UNAVAILABLE`, `POLICY_PAUSED`, `POLICY_CUTOFF`,
> `CREDENTIAL_EXPIRED`, `HOST_TRUST_CHANGED`, `DELEGATION_EXCEEDS_PARENT`, `OPERATION_CANCELLED`,
> `DESTINATION_UNREACHABLE`, `TIME_UNCERTAIN`, `UNSUPPORTED_CLIENT`, `SERVICE_UNAVAILABLE`,
> `STATE_UNAVAILABLE`, `BACKPRESSURE`, `REQUEST_CONFLICT`, `CONFIG_CONFLICT`, `REQUEST_EXPIRED`,
> `RESYNC_REQUIRED`, `DECISION_STALE`, `OUTCOME_UNKNOWN`, `USAGE_ERROR`, `SCHEMA_UNSUPPORTED`,
> `NOT_FOUND`, `INTERNAL_ERROR` and `LAUNCH_FAILED`.
>
> For non-child CLI commands the exit codes are 0 success (`OK`, `ACCESS_READY`; `ACCEPTED` with
> `--async` only), 1 internal failure or an unknown code, 2 usage or schema error, 3 required
> interaction, 4 denied, paused or cut off, 5 unavailable or transient (including `ACCEPTED`
> without `--async`), 6 conflict, 7 uncertain external outcome, and 126 or 127 when `run` or
> `connect` could not launch its program. After a launch, `run` and `connect` exit with the
> child's status. `operation wait` exits 5 while the operation is active, 7 for an uncertain
> outcome and otherwise its recorded code's class.
>
> `operation events --follow` writes NDJSON. When the subscription succeeds, its first line is the
> head envelope (`subscription`, `cursor`, and either the backlog count or a whole snapshot with
> its `resync_reason`); each later line is an event, or one terminal error envelope after which the
> stream ends. When the subscription is refused, the only line is the error envelope. It exits 0 at
> `--max-events` or on interrupt, 6 after a terminal event (a `resync_required` event, which every
> gap is, or a paired client's revocation), and otherwise with its terminal error's class; a
> disconnect after the head is a terminal `SERVICE_UNAVAILABLE` envelope (exit 5).

### 19.8 Proofs

- `cargo test -p heimdall-contract`: `contracts::rev7::{primitive_index_names_six_groups_with_known_schemas_codes_and_capabilities, reason_table_lists_every_answer_with_its_code_and_next_action, revision_7_capabilities_are_declared_not_offered}`; `contracts::rev7_events::{event_payload_schema_covers_every_emission_site, emission_scan_self_check}`; `contracts::rev7_views` (every view reads today's documents; re-serialization drops only PC3 fields); `contracts::schema_export::{checked_in_public_api_matches_the_model_exactly, declared_schemas_are_disjoint_from_the_public_ones}` and the keyword and tolerance checks over the declared schemas; unit tests in `page`, `primitives`, `event_payload`, `lifecycle`, `request_state`, and `views::catalog::tests::route_health_lists_the_most_recent_attempts_newest_first` (U0-RC01).
- `cargo test -p heimdall --bin heimdall`: `cli::tree_tests::{command_tree_matches_its_golden, help_text_names_no_milestone_adr_or_section, help_lint_self_check}`; `rev7_cmd::tests::{every_declared_command_answers_not_available_and_touches_nothing, only_inspect_request_takes_an_id}`.
- `cargo test -p heimdall-store`: `migrations::tests::restore_epoch_step_keeps_the_seeded_rows_at_epoch_zero_and_rolls_back_whole`; `tests::{catalog_aliases_are_unique_without_case_at_write, a_lost_restore_epoch_is_damage_never_epoch_zero, the_restore_epoch_is_canonical_decimal_only}` (the stored epoch is canonical decimal only: no sign, no leading zero but `0`, no whitespace; anything else is `state_corrupt`, U0-RC04).
- `cargo test -p heimdall-app --lib`: `catalog::tests::a_store_alias_conflict_in_the_driver_settles_terminal_and_leaves_nothing_open` (the driver's own defence, U0-RC03; a test-build seam makes the store refuse the write after the catalog's check passed).
- `cargo test -p heimdall-store --test contracts_replay`: `stored_samples_replay_through_revision_7_readers` (§19.9); the driver's self-test `tests/contracts/test_replay_journey.py` (the `check.sh` step `replay-driver-selftest`).

### 19.9 The replay corpus

Real prior-version rows (ADR-0013 §1.3): scratch stores written by the M02 (`e4f43f84`), M03
(`2b79aac1`), M04/M05 (`50dbc86b`) and M06 (`9399e768`) exit builds running one short fixed
journey, kept as SQL text dumps under `tests/contracts/golden/replay/`, migrated forward by the
production migrations and read back, every row of every table of the migrated schema, through its
reader (the store's public readers, revision 7's typed payloads for events and controller pins;
rows read must equal rows stored, U0-RC02), plus hand-authored rows (`hand/`) for the historical
shapes no journey produces. The tables and `meta` keys with no reader are listed in the corpus
README ("Stored, not read"). Each build's genuineness (its `heimdall` build graph equals the
crates cargo compiled; every binary's SHA-256 differs) is recorded in
`tests/contracts/golden/replay/README.md`. The recipe is `docs/architecture/u0-plan.md` §5.
