# Local control protocol

Draft for protocol 1 and schema major `"1"`. Use the wire names and request
fields in the [client message schema][client-schema], [server message schema][server-schema]
and [request schema][request-schema]. The [Python reference wrapper][wrapper]
implements the client against the current protocol, over Unix sockets and
Windows named pipes. This document marks future wire behavior as
**planned (ADR-0013, provisional)**.

## Endpoint and authentication

Pass the local **control endpoint and expected environment ID** to the client
together. On Unix the control socket is `control.sock` in the runtime directory.
On Windows the control pipe uses a local name of the form
`\\.\pipe\heimdall-<token>-control`. A harness that starts its own runtime can
supply its socket path and read `data.environment_id` from
`heimdall --json service status`. A pipe name carries an unpredictable token,
so a Windows client learns it only from the planned `data.control_endpoint`
described below. Keep the runtime advertisement private.
The control protocol has no TCP transport. Use a signing endpoint only from
a binding's `consumer` descriptor, for that binding's child. The signing protocol
is SSH agent IPC. The issuer endpoint is private to the supervisor.

Before sending any data, a client MUST perform the checks for its platform.

- **Unix.** Use `lstat` for the endpoint's containing directory and the socket
  itself. The directory must be a directory and the socket must be a socket.
  Both must be owned by the client's effective UID and have
  `mode & 0o077 == 0`. Reject symlinks at either entry. After connecting, verify
  the connected peer's UID equals the client's effective UID, using
  `getsockopt(SOL_SOCKET, SO_PEERCRED)` on Linux or `getpeereid` (or
  `LOCAL_PEERCRED`) on macOS. Close on an unavailable or mismatched credential.
- **Windows.** Perform these steps in order. Close the handle on any failure,
  including a call that fails.
  1. Normalize the path with `GetFullPathNameW` and verify the `\\.\pipe\` or
     `\\?\pipe\` namespace. The pipe name MUST start with `heimdall-`, as
     defence in depth. It MUST also end in `-control`, because a control client
     never opens a signing or issuer pipe. Refuse any other path without
     opening it. [ADR-0013 §8][freeze] gains both name rules as MUSTs at
     revision 7.
  2. Open the normalized path with `CreateFileW`, using
     `GENERIC_READ | GENERIC_WRITE`, `OPEN_EXISTING` and
     `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`. The server can then
     identify the client and cannot act as it.
  3. Verify that `GetFileType` reports `FILE_TYPE_PIPE`.
  4. Verify that the pipe's owner SID equals the caller's user SID. Read the
     owner with `GetSecurityInfo` and `OWNER_SECURITY_INFORMATION` on the
     handle. Read the caller's SID from its process token.
  5. Verify that the server process runs as the caller's user SID. Take its
     process ID from `GetNamedPipeServerProcessId`. Read its SID with
     `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`, `OpenProcessToken` and
     `GetTokenInformation(TokenUser)`. This step is
     **planned (ADR-0013, provisional)**, and a client implementing the
     ADR-0013 checks MUST perform it.

  Compare SIDs as SIDs, with `EqualSid` or in `S-1-…` string form. Never
  compare account names. The reference wrapper performs all five steps,
  including both name rules. It also requires the name to be a single
  component. It has no option for another expected owner SID, so it refuses
  a pipe with any other owner, including an elevated runtime's default
  owner. A pipe handle has no socket timeout. The wrapper uses
  overlapped reads and writes. At its timeout it cancels the transfer with
  `CancelIoEx`, waits for the cancellation to settle and closes the
  connection.
- **Both.** Verify the server hello's `environment_id` equals the expected ID
  before sending a request. Close on mismatch. The server independently
  authenticates the client against the runtime owner's UID or SID.

**Planned (ADR-0013, provisional).** `service status --json` exposes
`data.control_endpoint` as the endpoint it verified. The environment ID,
protocol, capabilities, principal and version come from its verified hello,
and the verified peer PID must match the advertised PID. It reports
`SERVICE_UNAVAILABLE` with reason `runtime_not_running` or `endpoint_untrusted`
as appropriate. A consumer still verifies the endpoint, peer and environment
on its own connection. See [ADR-0013 §8][freeze].

Peer credentials identify an OS principal. A process running as the same user
can reach the owner channel. Attended confirmation is a usability boundary
for non-interactive clients. Administrators and SYSTEM are outside this threat
model.

## Framing and hello

Write a four-byte unsigned big-endian length followed by exactly that many
bytes of one UTF-8 JSON object. The length is the byte count of the body. Read
the prefix completely, reject zero or over-limit lengths and close before
allocating or reading the body. A read can return a fragment of a prefix or
body. EOF mid-frame is a disconnect. Apply the same cap to writes.

| Phase | Maximum body bytes |
| --- | ---: |
| First frame in each direction, including a rejection | 16,384 |
| Further control frames after an accepted hello | 1,048,576 |

The runtime's default time to the first frame is five seconds.
Baseline connection limits are 16 requests in flight and four subscriptions
per connection, 256 buffered live events per subscription, and 64 connections
per endpoint. Excess work can return `BACKPRESSURE`. See [ADR-0006 §2][baseline].

This is the first frame from a non-interactive client.

```json
{"type":"hello","protocol":1,"schema_version":"1","client":{"name":"example","version":"0.1"},"capabilities":["operations/1","events/1","schema-discovery/1"],"required":["events/1"],"interaction":"non_interactive"}
```

An accepted hello is an object with `type: "hello"`, `protocol`, `schema_version`,
`server: {name, version}`, negotiated `capabilities`, authenticated client
`principal` and `environment_id`. Check the protocol and schema major before
proceeding. Negotiated capabilities are the intersection of the client and
server offers. Require only what the client needs, put every required
capability in its offer, and check all required capabilities were negotiated.
An optionally offered unknown capability can be left out of the intersection.
A missing required capability or unsupported version is `SCHEMA_UNSUPPORTED`.
After the hello, a request or subscription that needs a capability the session
did not negotiate is refused `SCHEMA_UNSUPPORTED` with effect `none` and never
runs. `inspect capabilities` needs `schema-discovery/1`. `subscribe` and
`observe` of `events` need `events/1`. The `pause`, `resume`, `cutoff` and
`clear_cutoff` policy actions need `owner-policy/1`. Offer each capability your
client uses. A paired session whose role cannot hold the capability gets
`CAPABILITY_UNAVAILABLE` with reason `role_insufficient` (`invitation_pending`
while its invitation is pending) instead. See
[ADR-0006 §2.4 and §19.10][baseline].
A malformed hello can receive `USAGE_ERROR`. A rejected hello has
`type: "reject"` and the error envelope fields **at the top level**, followed by
connection closure. A `goodbye` frame has `code` and `message` and ends the
connection.

Use `interaction: "non_interactive"` for automation. It also defaults to that
value when omitted. `attend` is a sequenced top-level frame, for example
`{"type":"attend","seq":1}`. The runtime answers a non-interactive session
with a correlated `response` carrying `INTERACTION_REQUIRED`. It accepts
attendance on an interactive session. Owner approval is a separate action.
The wrapper leaves owner decisions and time confirmation to an attended owner
client.

## Requests and results

Send a `request` frame with a unique unsigned 64-bit `seq` for this connection.
The request object uses `op` as its discriminator.

```json
{"type":"request","seq":1,"request":{"op":"inspect","subject":"destinations"}}
```

The runtime sends a `response` with `in_reply_to: 1` and an `envelope` object.
Correlate replies by sequence. Event frames carry a subscription handle
instead, and can be interleaved with replies. A synchronous client may keep
one request outstanding and use a separate connection for streaming.

These requests are available now. Consult the request schema for optional
fields and the shape of every referenced object.

| Intent | Key fields inside `request` |
| --- | --- |
| Read a whole inspect subject | `{"op":"inspect","subject":"destinations"}`. The destinations list is `data.items`. The `capabilities` subject returns `data.capabilities`, `data.schemas` and `data.codes`. Use the hello for the capabilities of this session. |
| Prepare access | `op: "ensure"`, `profile`, `work_id`, `request_id`. Optional fields include `scope`, `environment`, `until`, `required_capabilities` and `wait`. Set `interaction: "non_interactive"` for automation. |
| Materialize a binding | `{"op":"bind","binding_id":"…","request_id":"…","form":{"form":"materialize"}}` |
| Delegate to a child | `op: "delegate"`, `parent_binding_id`, `scope`, `work_id`, `request_id`. A child is constrained by the parent's scope and effective deadline. |
| Show or wait for an operation | `{"op":"observe","kind":"operation","operation_id":"…"}`. Add positive `wait_ms` for a bounded wait. Expiration of a wait does not cancel the operation. |
| Read a snapshot or event page | `{"op":"observe","kind":"events","filter":{}}`. Supply `cursor` to request an event page, and optionally `limit`. |
| Cancel an operation | `{"op":"cancel","operation_id":"…"}` |
| Drop a consumer reference | `{"op":"release","binding_id":"…"}` |
| Revoke a grant and its descendants | `{"op":"revoke","grant_id":"…","request_id":"…"}`. Read local application and pending remote effects from the result. |

The [envelope schema][envelope-schema] carries `schema_version`, optional
`operation_id`, `state`, `code`, `data`, `warnings` and `next`.
`warnings` is an array and `next` is an action object or `null`. Errors carry
`data.error` with `code`, `effect_status` (`none`, `applied`, `partial` or
`unknown`), `retryable`, `resource`, `next` and `message`, and optionally
`reason`. Use the typed code and effect fields for decisions. For example,
a successful `observe` lookup can return `OK` and describe a still-active
or failed operation. Read that operation's state and recorded outcome to decide
what to do next. Validate `data` against the request's expected shape before
reading it. In a successful `inspect destinations` response, `data` is an object
and `data.items` is an array.

When an `ensure` needs additional owner approval, the current runtime returns
`state: "awaiting_approval"` and `next.decision_ref`. An unattended caller
receives `INTERACTION_REQUIRED`. An attended caller using interactive mode
receives `APPROVAL_REQUIRED`. Hand the decision reference to the owner to
review and approve in an attended client. Use the original request ID with
the same parameters to retrieve its recorded result.

Use the [code table][codes] for code defaults. Exit classes are a CLI
convention. IPC sends envelopes.

| Exit | Class |
| --- | --- |
| 0 | Success, including `ACCEPTED` only when requested asynchronously |
| 1 | Internal error or unknown code |
| 2 | Usage, schema or lookup failure |
| 3 | Interaction required |
| 4 | Refusal, including policy denial or cancellation |
| 5 | Unavailable, backpressure or still pending after a bounded synchronous wait |
| 6 | Conflict, expired request or resync required |
| 7 | Unknown external outcome |
| 126 | `LAUNCH_FAILED` with `data.error.reason` equal to `not_executable` |
| 127 | Other `LAUNCH_FAILED` results |

**Planned (ADR-0013, provisional).** Response overflow is
`USAGE_ERROR` / `response_too_large`. A refused read has effect `none` and
next `narrow_request`. After dispatch the error will preserve the actual
effect, operation ID and next `observe`. Earlier runtimes can return
`INTERNAL_ERROR` for overflow; a failed response does not establish that a
mutation had no effect.

**Planned (ADR-0013, provisional).** `pages/1` adds `select: {ids?, aliases?}`
or `page: {limit?, token?}` to inspect. A whole read is complete or receives
a typed refusal. Select takes 1–64 entries and reports missing entries.
Paged results carry `items`, `more` and a `next_page_token` when more is true.
The default limit is 200, the maximum is 1,000 and the byte budget is 768 KiB.
Use the token with the same query, reader and environment. The traversal
ends on `more: false`, including an empty terminal page. Select and page
are mutually exclusive. These are catalog pages, distinct from the
currently supported `observe` event pages. See [ADR-0013 §6.1–6.2][paging].

### Idempotency and observation

Mint a fresh `request_id` for each logical request that takes one. It is a
token of 1–128 ASCII characters from `[A-Za-z0-9._:-]`. Reuse it when retrying
the **same** logical request under the same principal, role and operation
kind. Keep the request's authority inputs unchanged, including the deadline
intent, work ID, scope and capability requirements. Delivery preferences
such as wait and interaction do not change the hash. The runtime owns the
canonical hash and settles a journaled request under the original key.

The same key and parameters return the existing operation or recorded
result. Changed parameters give `REQUEST_CONFLICT`. An expired key or retained
expiry marker gives `REQUEST_EXPIRED`. Pending and unresolved keys stay
retained. Settled results default to seven days of retention with a 24-hour
floor, followed by a 30-day expiry marker window. After that window an old ID
can be admitted as new work. Observe an interrupted operation and reconcile
`OUTCOME_UNKNOWN` before considering new work. The `retryable` field does
not authorize a replay of a remote mutation. See [ADR-0006 §7][idempotency].

## Events, snapshots and subscriptions

An [event][event-schema] has `schema_version`, `event_id`, `type`,
`environment_id`, `timestamp`, `cursor` and a redacted `payload`, with
optional `operation_id` and `resource`. Delivery can repeat. Deduplicate by
`event_id`. Ordering is defined within one environment. Treat cursor strings
as opaque and scoped to the authenticated reader and environment. A cursor
on an event is the position after that event.

A [snapshot][snapshot-schema] has `data`, `cursor` and `taken_at`. Its cursor
is the boundary of the state it contains. To request just a snapshot,
send `observe` with `kind: "events"` and omit the cursor. Read
`data.snapshot` from the result. To page events, send a cursor and reuse
the same filter. A page returns `data.events`, `data.cursor` and
`data.more`. The limit is 500 events. Apply every frame in the page before
saving its page cursor. Treat `more: true` as continuation, including when
all page events are skipped by the reader. For a refused cursor
(`RESYNC_REQUIRED`), request a fresh snapshot and apply it before saving
its cursor.

To follow live events, send a sequenced `subscribe` message. The filter
can contain `operation_id` and `types`; omit both for an unfiltered stream.

```json
{"type":"subscribe","seq":2,"filter":{"types":["operation_state_changed"]}}
```

Add `from_cursor` to resume. Success is `type: "subscribed"`, `in_reply_to`,
`subscription` (an unsigned 64-bit handle), `cursor`, and a `snapshot`
when the server starts from one. A refused subscription instead returns a
sequenced `response` containing an error envelope. Omit the cursor for a
fresh snapshot. The current server can substitute a snapshot for an unusable
cursor or backlog beyond 500 events. The head's cursor marks the boundary
after the snapshot or retained backlog. Backlog frames come first, then
live frames after the boundary. Each arrives as
`{"type":"event","subscription":1,"event":{…}}`.

Send `{"type":"unsubscribe","seq":3,"subscription":1}` to stop the handle.
The runtime responds with a correlated envelope, `OK` if it removed the
handle or `NOT_FOUND` if the handle is already gone. Discard any in-flight
events for the handle once you stop applying them. A client with a dedicated
subscription connection can close the connection instead.

**Checkpoint rule.** Persist a cursor only after applying its full snapshot or
every event through that cursor. Skipping an unknown event type is a deliberate
no-op for that reader. Until a usable snapshot or explicit backlog count proves
the head applied, checkpoint each applied event's cursor. When a count is
available, the head is eligible only after all counted frames were processed,
including duplicates and unknown event types. On any `resync_required`
event, terminal `client` event with `payload.kind: "revoked"`, disconnect
or early stop, freeze the checkpoint. Close the old stream and apply nothing
more from it. Then open a new subscription with the same filter and last
applied cursor. Apply a replacement snapshot whole before changing the
checkpoint. Coordinate application state and checkpoint persistence so
a crash can safely replay.

An older server can keep streaming after a lag or retention gap. Close it
as soon as the gap arrives. On the baseline, an oversized backlog event can
be encountered again when replaying from the same checkpoint. If the
resubscription still cannot deliver that event, explicitly obtain a fresh
snapshot without a cursor and save only the cursor of the snapshot you apply.
See [ADR-0006 §8][events] and [ADR-0013 §5][checkpoint].

**Planned (ADR-0013, provisional).** Every gap ends the stream. The typed reasons
are `subscriber_lagged`, `history_trimmed` and `event_too_large`. Paired-client
revocation sends one terminal `client` / `revoked` event and closes its
connection. A resumed subscription head can include exact `backlog` (visible
filter-matching event frames) or a fresh snapshot with `resync_reason`. The
runtime chooses a snapshot if replay includes an undeliverable event.
Snapshots become typed, filter-matched and whole-or-refused. Their limits
are 1,000 operations, 256 pending decisions and 768 KiB serialized.
Standalone event pages gain a 768 KiB budget and typed gap reasons without a
replacement cursor. An event above the page budget that fits a frame can
be returned on its own. See [ADR-0013 §5][checkpoint].

## Reader obligations

Ignore unknown fields. Use `unknown` for unrecognized values of enums that
define it. Skip unknown event types. For an unfamiliar reason, fall back to
its code's defaults for classification and preserve actual effect information
for reconciliation. An unknown code is failure (exit class 1, default effect
`unknown`, next `report`); a success-looking state does not override it.
Reject an unsupported schema major explicitly. Require only the fields and
capabilities needed for the action. Preserve distinctions among an omitted
value, a documented explicit `null`, and `unknown`. See
[ADR-0006 §9][versioning] and [ADR-0013 §3.2][readers].

## Documentation gaps found

These details of the currently served protocol had to be recovered from
implementation source. The schemas describe the constituent message or
envelope shapes.

- A refused subscribe uses a normal correlated `response` envelope on IPC.
  The proposed ADR specifies the CLI's first-line error behavior, and the
  IPC schema only describes a successful `subscribed` reply under the
  request. `ipc::session` emits the error frame, including for an oversized
  head.
- `unsubscribe` success is a `response` with `OK` and
  `data: {subscription, unsubscribed: true}`; an absent handle is
  `NOT_FOUND`. The message schema describes the request without this reply
  detail. The current behavior comes from `ipc::session`.
- `observe events` currently wraps a snapshot under `data.snapshot` and
  returns pages as `data.{events,cursor,more}`. In `app::operations::observe`,
  `more` means the returned events filled the requested limit, so a
  following page can be empty. A short page can advance its cursor to the
  read head. A refused cursor may still carry a `next.cursor` hint. It takes
  a snapshot application to checkpoint that boundary. There is no typed
  current response schema for these cases.
- The snapshot schema leaves `data` open. Current `app::events::snapshot_data`
  emits `environment_id`, `authority_generation`, `boundary_seq`,
  `operations`, `operation` (nullable) and `pending_decisions`. Current
  sections can be present even when a type filter excludes their events.
  Keep the opaque cursor as the checkpoint. The proposed snapshot shape
  changes these rules.
- The generic envelope schema leaves inspect payloads open. The code table
  returned by `inspect capabilities` is under `data.codes`. The destination
  listing described in ADR-0007 §12.24 uses `data.items`, including an empty
  array for an empty catalog. These field names come from
  `app::operations::inspect`.
- The runtime currently clamps `observe`'s `wait_ms` to its configured
  maximum (300 seconds by default) and returns an `OK` lookup envelope with
  the operation's own `state`. Read the recorded operation result for the
  work's outcome. The request schema describes the wait field but leaves this
  response behavior to `app::operations::observe`.
- Current oversized control responses can be replaced by a correlated
  `INTERNAL_ERROR` from `ipc::session::send_or_internal`. The proposed typed
  refusal and preservation of a dispatched operation's effect are future
  behavior.

[client-schema]: ../../schemas/public-api/ipc.client-message.schema.json
[server-schema]: ../../schemas/public-api/ipc.server-message.schema.json
[request-schema]: ../../schemas/public-api/request.schema.json
[envelope-schema]: ../../schemas/public-api/envelope.schema.json
[codes]: ../../schemas/public-api/codes.json
[event-schema]: ../../schemas/public-api/event.schema.json
[snapshot-schema]: ../../schemas/public-api/snapshot.schema.json
[wrapper]: ../../examples/reference-wrapper/
[baseline]: ../decisions/0006-public-contract-baseline.md#2-local-ipc-spec-132-117-plan-3-g08-ipc-authentication-design
[idempotency]: ../decisions/0006-public-contract-baseline.md#7-idempotency-spec-114-primitives-draft-5-domainidempotency
[events]: ../decisions/0006-public-contract-baseline.md#8-events-and-cursors-spec-115-112-contractevent-appevents
[versioning]: ../decisions/0006-public-contract-baseline.md#9-schema-versioning-spec-112-133-plan-45
[freeze]: ../decisions/0013-public-contract-freeze.md#8-ipc-authentication-design-r07
[readers]: ../decisions/0013-public-contract-freeze.md#32-after-the-freeze
[checkpoint]: ../decisions/0013-public-contract-freeze.md#5-events-and-cursors
[paging]: ../decisions/0013-public-contract-freeze.md#61-whole-reads-select-and-pages-d2
