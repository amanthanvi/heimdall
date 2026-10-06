# Public primitive draft (M00-T06)

**Status:** proposed draft. It becomes binding for M01 only after G08's
reference callers pass. Names are not frozen (spec §11.1). This draft is
language-neutral; M01 models it as typed domain operations **before** the CLI
surface grows.
**Sources:** spec §4, §6, §11, §13.2; plan §3 G08, §4.2.

## 1. Common envelope (spec §11.2)

Every final result:

| Field | Type | Notes |
|---|---|---|
| `schema_version` | string | major version; unsupported major → explicit rejection |
| `operation_id` | opaque string, optional | present for effectful or long-running work |
| `state` | enum | operation state (§3) or `succeeded`/`failed` for synchronous reads |
| `code` | stable semantic code | never localized |
| `data` | object | per primitive |
| `warnings` | array of `{code, message}` | |
| `next` | object or null | machine next action, e.g. `{"action":"observe","operation_id":…}` |

Errors carry `data.error = {code, effect_status, retryable, resource, next}`
where `effect_status` ∈ `none | applied | partial | unknown` and `retryable`
never means "replay an arbitrary remote mutation" (spec §11.6).

Readers tolerate unknown non-critical fields; `null`, omitted, `unknown`, and
`false` are distinct; timestamps are RFC 3339 with offset; IDs are opaque
references, never bearer credentials; no private keys, passphrases, or reusable
approval secrets appear in any result or event.

## 2. Caller context (authentication is not caller-supplied data)

| Context element | Source | Authority? |
|---|---|---|
| OS principal | local IPC peer credentials / pipe ACL (G08) | identifies the user, not the application |
| Environment ID | runtime's own enrolled environment | yes, pinned per binding |
| Bound context | binding established by `bind`/integration (G05) | narrows; never widens |
| `agent_name`, PID, cwd, env vars | caller-supplied | **metadata only** (spec §4.2, §13.2) |
| Remote paired client role | G07 pairing | only the role's permitted subset |

Approval of new authority is **not** a primitive. It happens on an owner channel
(TUI/CLI decision flow, G05). See open question Q1.

## 3. Operation and grant states

Operation: `queued → running → {succeeded | failed | cancelled | outcome_unknown}`,
with `awaiting_approval` reachable from `queued`/`running`. A caller timeout
never changes state. Grant states and transitions: spec §6.3 table (executable
and tested in M01-T02).

## 4. The six primitives

### 4.1 `inspect` (read; no effects)

- **Purpose:** what is installed, available, active, and what would an ensure
  need. Includes capability/schema discovery for agents (R-AP-08).
- **Input:** `subject` ∈ `capabilities | environments | profiles | destinations |
  bindings | grants | operations | decisions`, optional filters, optional
  `preview: {profile, environment, until, required_capabilities}`.
- **Output:** snapshot with freshness/provenance per value; `preview` returns the
  resolved snapshot and the **authority delta** (what is already authorized vs
  what would need approval), with no side effects.
- **Passivity:** never contacts agents, network, or executes config (spec §10.2).
  Active probes are a separate effectful request: `inspect` with
  `probe_level` ∈ `agent_contact | network | host_verification | authentication`
  creates an operation (it can trigger provider behavior) and is never default.

### 4.2 `ensure` (effectful, idempotent preparation)

- **Purpose:** one intent-level call that produces usable access under existing
  authority, or a precise pending/denied state (R-AP-01, plan §4.2 pipeline).
- **Input:** `profile` (or destination/account subset), `environment` (default:
  caller's), `work_id`, `until` (absolute or duration — converted to UTC once at
  creation; original intent retained), `required_capabilities` (minimums, e.g.
  `destination_scope >= verified_server_principals`, `offline_until >= T`),
  `request_id`, `interaction` ∈ `interactive | non_interactive`,
  `wait` ∈ `sync(timeout) | async`.
- **Success data:** `binding_id`, `environment_id`, `profile_revision`,
  `grant_id`, `expires_at`, `usable_until`, `offline_until`,
  `refresh_dependency`, `credential_mechanism`, `enforcement{…}` (spec §4.3
  fields), consumer integration descriptor (no secrets).
- **Codes:** `ACCESS_READY`; `APPROVAL_REQUIRED` (state `awaiting_approval`,
  nonsecret decision reference + minimal delta); `CAPABILITY_UNAVAILABLE`;
  `POLICY_PAUSED`; `POLICY_CUTOFF`; `PROVIDER_LOCKED`; `INTERACTION_REQUIRED`;
  `TIME_UNCERTAIN`; `REQUEST_CONFLICT`; `OUTCOME_UNKNOWN`.
- **Non-interactive:** never opens browser/dialog/terminal prompts (R-AP-06).
- **Never:** extends an existing grant's deadline, widens a pinned snapshot, or
  selects a weaker mechanism than `required_capabilities`.

### 4.3 `bind` (associate a running context with a binding)

- **Forms:** (a) `launch`: `argv` after `--`, no shell, process contract of
  spec §10.4 (child status is the exit status; Heimdall pre-launch failures and
  child launch metadata via the operation result / side channel); (b)
  `materialize`: produce a bound consumer configuration (generated ssh_config
  fragment, endpoint, Git `core.sshCommand` guidance) for a consumer that cannot
  be launched by Heimdall.
- **Composition:** `run` = `ensure` + `bind(launch)` in one call, because they
  are invariably sequential (spec §11.1, S24).
- **Pinning:** binds environment ID, profile revision, resolved scope,
  mechanism, and grant; later default changes do not redirect it (R-AU-03).

### 4.4 `delegate` (narrower child binding)

- **Input:** `parent_binding_id`, scope subset, `until` (≤ parent), `work_id`,
  `request_id`, `required_enforcement`.
- **Rules:** child scope ⊆ parent ∩ policy ∩ capability; child deadline ≤
  parent; parent expiry/revocation/cutoff cascade; a child never receives
  approve/issue/policy authority (R-AU-07). The result's `enforcement` says
  whether narrowing is enforced (named mechanism) or same-user convenience.
- **Denials:** a broader/longer request is denied, not escalated to approval —
  proposed code `DELEGATION_EXCEEDS_PARENT` (see Q3); a minimum enforcement
  the mechanism cannot meet → `CAPABILITY_UNAVAILABLE`.

### 4.5 `observe` (status, events, resumption)

- **Get:** operation by ID; optional bounded `wait(timeout)` returning current
  state on timeout (timeout ≠ cancel).
- **Stream:** NDJSON events `{schema_version, event_id, operation/resource ref,
  environment, timestamp, type, cursor, payload(redacted)}`, at-least-once,
  consumer dedupes by `event_id`, no cross-environment ordering (spec §11.5).
- **Resync:** snapshot includes its cursor boundary; an expired cursor returns a
  resync instruction (proposed code `RESYNC_REQUIRED`, Q3). Cursors are scoped to
  the authenticated reader. Bounded buffers emit backpressure, not unbounded
  growth.

### 4.6 `release` / `revoke` (stop family)

| Action | Effect | Who |
|---|---|---|
| `cancel(operation_id)` | explicit, idempotent; reports whether an irreversible/uncertain step may have occurred | caller that owns the operation, owner |
| `release(binding_id)` | drops this consumer reference; does not revoke a shared grant others use; ref counts never outlive expiry | binding holder, owner |
| `revoke(grant_id)` | local denial persisted (tombstone + generation) **before** acknowledgment; cascades to descendants; returns `local_applied`, `remote_pending[]`, `latest_possible_credential_expiry` | grant holder for its own grant (narrowing is always allowed), owner for any |
| `pause(policy)` / `cutoff(policy, at)` | blocks future automatic activation, including fresh work/request IDs (R-AU-02) | owner channel only |
| `unenroll(destination/account)` | remote removal of Heimdall-owned records via enrollment transaction | owner channel only |

## 5. Idempotency (spec §11.4)

- Key: `(authenticated caller context, operation kind, request_id)`.
- Canonical request hash covers the request **as submitted** after
  normalization: environment, profile reference (and explicit revision if
  given), scope subset, **deadline intent as given** (absolute timestamp or
  duration string — not the resolved instant, so a retry of `--for 2h` matches),
  `work_id`, required capabilities, parent binding. The operation stores the
  resolved snapshot and resolved deadline once.
- Same key + same hash → same operation/result. Same key + different hash →
  `REQUEST_CONFLICT`. Records survive restart; retention is documented and an
  expired key is reported, never silently treated as new (R-AP-03).
- These definitions are serialized orchestrator decisions; changes need an ADR.

## 6. Exit codes for non-child commands (spec §11.6, proposed)

0 success · 2 usage/schema · 3 interaction required · 4 denied/paused/cutoff ·
5 unavailable/transient dependency · 6 conflict · 7 uncertain external outcome ·
1 internal. Async accepted/pending exits 0 only when the caller chose async.

## 7. Open questions (owner/G05/G08)

- **Q1 — What distinguishes the owner approval channel from a same-user agent?**
  An agent running as the owner's OS user can drive the same CLI/TUI. Options:
  (a) accept and disclose this non-guarantee (spec §14.2 already lists a
  compromised owner session as out of scope); (b) require OS user-presence
  verification (e.g. platform biometric/password prompt) for approvals;
  (c) a separate approval process/UI not reachable through the agent's IPC.
  Needs a G05 decision with evidence; recommendation pending experiments.
  **Decided 2026-10-06 (owner): option (a).** Accept the non-guarantee and
  disclose it: an agent running as the owner's OS user can drive the
  approval CLI/TUI. This is consistent with spec §14.2, which puts a
  compromised owner session out of scope. Setup and documentation state it
  plainly.
- **Q2 — Delegated-worker authentication.** Same-user IPC cannot tell a worker
  from its parent (spec §13.2). The V1 narrower-binding demo must rely on a
  signer/principal mechanism or a validated isolated context (spec §8.7); the
  primitive reports which.
- **Q3 — New stable codes.** `DELEGATION_EXCEEDS_PARENT` and `RESYNC_REQUIRED`
  are proposed additions to the spec §11.6 list (which says "include", so not
  closed). They need a spec amendment at G08 if adopted.
