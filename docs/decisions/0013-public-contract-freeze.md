# ADR-0013: Public contract freeze (G08, final)

**Status:** proposed, revision 3 · **Date:** 2026-11-21 · **Gate:** G08 (final contract freeze) · **Milestone:** M07 (T03, T04, T05)
**Decided by:** nothing yet. This is the M07 design unit's proposal to the contract owner (the orchestrator, ADR-0009 §2.6).
**Acceptance:** this ADR is accepted, and G08 ratified, only after the native A19 and A32 rows pass (§1.2; M07 plan U9). Until then, revision 7 is **provisional**.

**Revision 3 (2026-11-21):**
- **What it applies:** the scoped re-check (Codex, FIX FIRST, M07-RC-R01–R11; `/tmp/hm-tools/m07-design-recheck-out/report.md`), under the orchestrator's simplification rulings S1–S4 and the rulings on RC02 and RC05–RC11.
- **What it removes from revision 2:** the partial snapshot and its rebuild, the oversized-item stub, and traversal for internal resolution.
- **What ADR-0009 allows next:** no further independent re-check. The orchestrator reviews this revision's diff against revision 2.
- **Where to find the changes:** `target/m07-notes/DONE-r3` maps each finding to its change.

**Revision 2 (2026-11-21):** the design review (FIX FIRST, M07-D-R01–R14) and the rulings Q1–Q12.

**Applies to the contract:** nothing until the M07 plan's trigger (§3 there), when M06 closes revision 6.x. The deltas in §11 are a **proposed ADR-0006 revision 7**, layered on revision 6.1. This document applies none of them.
**Basis:**
- ADR-0006 revision 5 on `main` at `b2bb8507`;
- revisions 6 and 6.1 (§18, §18.4, §18.5) on `m06/w1` at `82158dee`;
- the design probes in `tests/evidence/m07-probe-tui-and-lists.json`.
**Plan:** `docs/architecture/m07-plan.md`.
**Requirements:** R-AP-01, R-AP-02, R-AP-03, R-AP-04, R-AP-05, R-AP-07, R-AP-08, R-RT-06 and R-UX-07.
**Acceptance cases:** A19 and A32 (G08's named fixtures); A20 and A27 for the CLI and run-record parts.

## 1. Context, and what the freeze means

ADR-0006 was a baseline "as far as M01 needs it". Plan §3 G08 asks for seven deliverables:
- the API and CLI naming freeze (§2);
- a schema versioning policy (§3);
- an exit-code table (§4);
- an event and cursor specification (§5);
- an idempotency namespace and retention contract (§7);
- an IPC authentication design (§8);
- the A19 and A32 fixtures (M07 plan §6).

It prefers a small conventional protocol. Spec §11.1 freezes names at G08 "before public compatibility promises".

### 1.1 What is frozen

| Surface | Frozen items |
|---|---|
| Local IPC | protocol `1`; framing and limits (ADR-0006 §2.2, §2.5); the hello (§2.3); capability names and versions; the authentication design (§8) |
| Documents | schema major `"1"`; the envelope (ADR-0006 §3); every request kind; every published view, page and snapshot shape (§5, §6); the code table (ADR-0006 §5); the error-reason table (D8); next-action names; ID prefixes |
| Events | event types, payloads as emitted, cursors, snapshots, checkpoints, gap endings (§5) |
| Idempotency | the key namespace, hash inputs, outcomes and retention, including decision-backed replay (§7) |
| CLI | command paths and flags (the command-tree golden, D3); exit codes and the NDJSON line grammar (§4); every `--json` document; the run record; the integration endpoints that installed or rendered artifacts call (`activate --hook`, the route helper) |
| Files | the manifest, the portable bundle (`heimdall-portable/1`) and the `config.toml` keys |
| Discovery | `schema show` names; the primitive index (D7) |

**Not frozen:** human-mode text, the TUI's layout and keys, the store schema, `instance.json` and other runtime files, logs, and `internal` subcommands.

### 1.2 Provisional until the native consumers pass (R01, RC10)

M07's W1 lands only harmless, preparatory parts of revision 7 (§1.3). The rest lands in W2, still provisional.

**Ratification** marks this ADR accepted, G08 closed, and revision 7 final. It requires every **A19 and A32 native row** in U9 to pass on macOS, the devbox and Windows, with the reference wrapper and both harnesses. Only these rows are excused:
- rows blocked **solely** on named owner inputs: the foreign-owner endpoint rows, on B2 (Windows), B3 (macOS) and B8 (devbox);
- A32's LLM-harness metrics, deferred by plan §5 to M09-T02.

Everything learned before ratification amends revision 7 under §1.3. After ratification, ADR-0006's additive rule (§3.2) binds.

### 1.3 Before the freeze: pre-release corrections, landing, persisted data, self-describing answers

- **Pre-release corrections are allowed** inside schema major `"1"`, before ratification (the orchestrator's ruling). No release has shipped. §12 lists each one with its reason.
- **One change per live wire shape** (RC09). Each live wire-shape change lands in **one change**, together with:
  - its emitters;
  - every in-tree reader (CLI, TUI, wrapper, harnesses, skill);
  - its goldens.

  W1 adds only types, constants and goldens that no live path emits yet. Shape changes start in W2.
- **Persisted data keeps replaying.** Event rows, operation rows, idempotency records and decision records written by revisions 1–6.x must replay, or be migrated by an explicit, tested migration. **The replay corpus** (U0) holds:
  - real prior-version rows, from scratch stores written by the M02, M03, M04/M05 and M06 exit builds running a short fixed journey, then migrated forward through the production migrations;
  - hand-authored rows for every historical shape in the emission inventory that no build journey produces.

  A test reads every row back through the revision-7 readers.
- **Answers describe themselves.**
  - A page says whether more remains (`more`, `next_page_token`). Its content is always complete: there are no stubs (§6).
  - A whole read and a snapshot are complete, or refused with a typed reason (§5.5, §6.1).

## 2. Naming freeze

### 2.1 Wire names

| Kind | Rule | Examples |
|---|---|---|
| Field names | `snake_case`. Instants are RFC 3339 with an explicit offset, named `*_at`, `*_until` or `valid_before`. Durations `*_ms`. Collections are plural arrays. Existing names are frozen; the rule governs new fields | `expires_at`, `offline_until` |
| Codes | `SCREAMING_SNAKE_CASE`, never localized | `ACCESS_READY` |
| Error reasons | `data.error.reason`, `snake_case`, stable. An unknown reason reads as its code's defaults | `route_undetermined` |
| Pending-state reasons | `snake_case`, with no code. `remote_pending_reasons` on grants (D17) stays distinct from revision 6's environment `remote_pending[].reason` | `adapter_unavailable` |
| Request kinds | `<op>.<action>`. Primitives keep bare names | `ensure`, `remote_environment.add` |
| Event types | `snake_case`, with the family subtype in `payload.kind` | `operation_state_changed`, `client` + `kind: revoked` |
| Next actions | `snake_case`, ADR-0006 §3's set | `use_binding`, `observe`, `narrow_request` |
| Capabilities | `kebab-case/N` | `operations/1`, `pages/1` |
| IDs | `<prefix>_<32 lowercase hex>` for runtime-generated IDs; opaque | `op_…`, `cl_…` |
| Opaque tokens | Cursors and page tokens: ≤ 256 bytes, base64url, never parsed. Page tokens are integrity-protected (§6.2) | — |

### 2.2 The primitives and their names

| Group | CLI | Wire request | Capability |
|---|---|---|---|
| inspect | `heimdall --json inspect <subject> [--preview <profile> …] [--id I … \| --limit N [--page-token T]]` | `inspect` (`select` **or** `page`) | `operations/1`; `pages/1` for `select` and `page` |
| ensure | `heimdall --json --non-interactive access ensure --profile P --work-id W --request-id R [--pair D:A …] [--environment E] [--until T \| --for D] [--async] [--timeout-ms N] [--require-* …]` | `ensure` | `operations/1` |
| bind | launch: `heimdall run [--profile P] [--request-id R] [--meta-fd N \| --meta-file F] -- <argv>`; materialize: wire only | `bind` | `operations/1` |
| delegate | `heimdall --json access delegate --parent B --work-id W --request-id R [--pair D:A …] [--until T]`; `run --parent-binding B` | `delegate` | `operations/1` |
| observe, including cancel | `heimdall --json operation show\|wait\|events [--operation O] [--cursor C] [--limit N] [--follow] [--max-events N]`; `operation cancel` | `observe`, subscriptions, `cancel` | `operations/1`, `events/1` |
| release / revoke | `heimdall --json access release <binding>`; `access revoke <grant> --request-id R` | `release`, `revoke` | `operations/1` |

### 2.3 The CLI command tree

The command-tree golden (D3) records every path and flag.

- **Everyday:** `setup`, `connect`, `run`, `status`, `doctor`, `tui`.
- **Advanced:** `access`, `operation`, `decision`, `time`, `service`, `schema`, `inspect`, `destination`, `identity`, `profile`, `project`, `shell`, `export`, `import`, `issuer`, `enroll`, `connections`, `wsl`, `container`, `uninstall`.
- **M06's names (Q1, ruled, implemented by M06 W2):**
  - `env` → `environment`, with no alias;
  - `roost adopt` → `transport adopt-roost`;
  - `route` and `device` stay.
  Revision 7 records the grammar once, when M06's argument trees settle.
- **Integration endpoints, frozen and hidden from help:**
  - `activate --hook`;
  - the route helper, the ProxyCommand leg.
  An update keeps them working, or re-renders whatever calls them (M08-T02).
- **Help text** carries no milestone, ADR or section references and no test-only wording. A lint enforces this (D14).
- **Flags:**
  - `--json`, `--non-interactive` and `--home` are global;
  - `--request-id` and `--work-id` are bounded tokens;
  - `--until` or `--for`, never both;
  - `--id` (repeatable) or `--limit`/`--page-token`/`--all`, never both;
  - `--async`;
  - `--yes` on `import` only.

## 3. Schema versioning policy

### 3.1 Axes

| Axis | Carried in | Changes when |
|---|---|---|
| IPC protocol | `protocol` in the hello (u16, `1`) | framing or the hello changes (never in V1) |
| Schema major | `schema_version` (`"1"`) | a shared rule breaks after the freeze; needs its own ADR |
| Capability version | `name/N` | a capability's requests or views change incompatibly after the freeze |
| File formats | `heimdall-portable/1`, manifest, `config.toml` | as the capability rule |
| Run record | `run-record` | as the capability rule |
| Store | private `SCHEMA_VERSION` | freely, keeping §1.3's replay guarantee |

### 3.2 After the freeze

- **Additive:** a new optional field; a new variant of a `#[non_exhaustive]` enum; a new error reason, event type or next action; a new capability, or a request form behind one; a new failure code in an existing exit class.
- **Breaking, so a new capability version:** removing or retyping a field; changing a code's meaning, exit class, retryability or default effect; changing request-hash inputs or a default; making an optional field required.
- **Readers must:**
  - ignore unknown fields;
  - read an unknown enum variant as `unknown` where the type has one;
  - skip unknown event types;
  - read an unknown error reason as its code's defaults;
  - read an unknown code as a failure (exit 1);
  - reject an unsupported major explicitly;
  - require only what they cannot work without;
  - **treat a page with `more: true` as not the end of the list**.

  A whole read is complete or refused, and a session without `pages/1` never receives a page.
- **Writers must:**
  - apply ADR-0006 §9's omitted-versus-`null` rule in typed views (D9). An explicit `null` stays where documented or where it means "cleared", and in every persisted event payload;
  - make every `--json` document, error and stream line validate against its published schema (the schema-to-emitter checklist).

### 3.3 Coexistence, selection and removal (D18, Q5)

- **Coexistence.** After `name/N+1` is introduced, `name/N` stays offered for at least two minor releases **and** 90 days. The release notes in between name the removal release.
- **Selection.** Negotiation picks, per session and per capability, the highest version both sides offer. The server serializes everything for that session in the selected version's shapes. A form that exists only in `name/N+1` is refused as `SCHEMA_UNSUPPORTED` on a session that selected `name/N`.
- **Removal.** Only in a release that satisfies both bounds, and only as a capability change: a client that requires `name/N` then gets `SCHEMA_UNSUPPORTED` at hello.

**Rejected:** minor numbers in documents, per-request version fields, and a generated-client framework.

## 4. Final exit-code table

**Non-child commands** (ADR-0006 §6; classes unchanged):

| Exit | Class | Codes |
|---|---|---|
| 0 | success | `OK`, `ACCESS_READY`; `ACCEPTED` with `--async` only |
| 1 | internal, or an unknown code | `INTERNAL_ERROR`; any `Code::Unknown` |
| 2 | usage or schema | `USAGE_ERROR` (with reasons `response_too_large`, `page_token_invalid` and `selector_invalid`), `SCHEMA_UNSUPPORTED`, `NOT_FOUND`; clap usage errors |
| 3 | interaction required | `APPROVAL_REQUIRED`, `INTERACTION_REQUIRED`, `PROVIDER_LOCKED` |
| 4 | denied, paused, cut off | `CAPABILITY_UNAVAILABLE` (including `route_undetermined`), `POLICY_PAUSED`, `POLICY_CUTOFF`, `CREDENTIAL_EXPIRED`, `HOST_TRUST_CHANGED`, `DELEGATION_EXCEEDS_PARENT`, `OPERATION_CANCELLED` |
| 5 | unavailable or transient | `DESTINATION_UNREACHABLE`, `TIME_UNCERTAIN`, `UNSUPPORTED_CLIENT`, `SERVICE_UNAVAILABLE` (with `runtime_not_running` and `endpoint_untrusted`), `STATE_UNAVAILABLE`, `BACKPRESSURE`; `ACCEPTED` without `--async` |
| 6 | conflict | `REQUEST_CONFLICT`, `CONFIG_CONFLICT` (with `destination_has_live_access`), `REQUEST_EXPIRED`, `RESYNC_REQUIRED`, `DECISION_STALE` |
| 7 | uncertain external outcome | `OUTCOME_UNKNOWN` |
| 126 / 127 | launch failed (`run`, `connect`) | `LAUNCH_FAILED` |

Retryability, default effect and default next action stay ADR-0006 §5's 30 rows. Revision 7 adds no code, only the reasons named above.

**A response too large for one frame (D19; RC07):**
- It is never `INTERNAL_ERROR`, and never an empty or silently partial list.
- **Reads are refused before anything is sent.** Whole lists, `select` and snapshots are sized before serialization from bounded store reads (§6.4). An over-limit answer is `USAGE_ERROR`/`response_too_large`, with `effect_status: none`, next `narrow_request`, and `data.error.limit_bytes`, the section or item, and the narrowing to use.
- **A reply after dispatch** (an operation's result that turns out not to fit) is also `USAGE_ERROR`/`response_too_large`, but it **keeps the truth**:
  - the operation's actual `effect_status` (`applied`, `partial` or `unknown`);
  - its `operation_id`;
  - next `observe`, with that operation.

  A committed or uncertain effect is never reported as `none`. `ipc::session::send_or_internal` builds this reply from the operation reference it was sending.

**Command-specific rules:**
- **`run`, `connect`:** after a launch, the exit is the child's status. Pre-launch failures use this table and the run-record side channel.
- **`operation wait`:** 5 while active, 7 for `outcome_unknown`, otherwise the class of the recorded code.
- **`operation events --follow`** (the NDJSON grammar):
  - **When the subscribe succeeds,** the first line is the head, an envelope with `data.{subscription, cursor, backlog?, snapshot?, resync_reason?}` (§5.3). Each later line is an **event** (an object with `event_id`) or **one terminal error envelope** (`code`, `state: "failed"`, `data.error`), after which the stream ends.
  - **When the subscribe is refused** (`response_too_large`, `SCHEMA_UNSUPPORTED`, a transport failure before the head), the **only line is the error envelope**. There is no head.
  - **Exits:**
    - 0 at `--max-events` or on Ctrl-C;
    - **6 after a terminal event**: a `resync_required` event (every gap ends the stream, §5.4) or the terminal `client` event with `kind: revoked`;
    - otherwise the terminal error envelope's class;
    - a disconnect after the head is a terminal error envelope (`SERVICE_UNAVAILABLE`, exit 5).
- **The TUI:** 0, 129, 130, 143; 2 for refusals before the terminal is touched.
- **`--help`, `--version`:** 0.
- **An interrupted synchronous wait** does not cancel. The same `--request-id` reaches the operation again.

**The spec amendment** (D15; applied by the orchestrator at U0, Q12): spec §11.6 gains the 16 codes missing from its list (`OK`, `ACCESS_READY`, `ACCEPTED`, `DELEGATION_EXCEEDS_PARENT`, `OPERATION_CANCELLED`, `SERVICE_UNAVAILABLE`, `STATE_UNAVAILABLE`, `BACKPRESSURE`, `REQUEST_EXPIRED`, `RESYNC_REQUIRED`, `DECISION_STALE`, `USAGE_ERROR`, `SCHEMA_UNSUPPORTED`, `NOT_FOUND`, `INTERNAL_ERROR`, `LAUNCH_FAILED`), and this exit table with the stream grammar.

## 5. Events and cursors

### 5.1 Envelope and payloads (D5)

- **The envelope:** `{schema_version, event_id, type, environment_id, operation_id?, resource?, timestamp, cursor, payload}`. Payloads are redacted before persistence.
- **Payloads are typed as emitted.** U0 derives the discriminated schema from **every emission site and the replay corpus** (§1.3), keeping every key and every nullable key. The inventory test fails on an emission site the schema does not cover.

  | Type | Payload keys as emitted (`?` optional; `\|null` nullable) |
  |---|---|
  | `operation_state_changed` | `kind`, `state`, `code\|null`, `effect_status\|null` |
  | `grant_state_changed` | `grant_id`, `state`, `reason?\|null` |
  | `decision` | `decision_id`, `kind`, `state`, `expires_at` |
  | `policy_changed` | `policy_id`, `revision`, `paused`, `cutoff_at\|null` |
  | `credential_lifecycle` | `grant_id`, `event`, `cause?`, `cascade?`, `local_applied?`, `remote_pending?`, `latest_possible_credential_expiry?`, `issuance_id?`, `credential_instance_id?` |
  | `resource_changed` | `change`, with `declaration_revision?`, `item?`, `generation?`, and the supervisor's keys (inventoried by U0) |
  | `runtime_lifecycle` | `phase`, `open_operations?`, `unresolved_operations?`, and the per-operation report keys |
  | `resync_required` | `reason` (§5.4), `dropped?`, `subscription_ended` |
  | `enrollment`, `connection`, `session_lock`, `activation` | their existing typed payloads |
  | `environment`, `client`, `device`, `remote_effect`, `route` | revision 6's typed payloads |

- **Delivery and order:** at least once, so deduplicate by `event_id`. Order is claimed only within one `environment_id`.

### 5.2 Scope and visibility

- **A cursor is scoped** to its reader tag (principal, role, `remote_client`) and its environment.
- **Visibility on every path** (pages, backlog, live) follows revision 6's ruling 17 (§18.5).
- **A revoked paired client** receives **one** terminal `client` event, `kind: revoked`, after which its subscriptions end and its connection closes. The CLI exits 6 on it.

### 5.3 Subscribing, and cursors by mode

The wire subscription is non-strict. `strict` stays an in-process test seam.

| Cursor given | Subscribe | Observe page (`operation events --cursor`) |
|---|---|---|
| none | whole snapshot start (§5.5) | whole snapshot (§5.5) |
| valid, the missed backlog ≤ 500 visible events, each deliverable in one frame | backlog start, `backlog: n` | up to `limit` events after it (§5.6) |
| valid, but more than 500 behind, or an undeliverable event in the backlog | whole snapshot start, `resync_reason: backlog_too_long` or `event_too_large` | up to `limit` events (pages catch up), or §5.6's refusal |
| below the retained tail | whole snapshot start, `resync_reason: history_trimmed` | `RESYNC_REQUIRED`, reason `history_trimmed` |
| beyond the head, malformed, unknown version, another reader or another environment | whole snapshot start, `resync_reason: cursor_invalid` | `RESYNC_REQUIRED`, reason `cursor_invalid` |

- **`backlog: n`** is exactly the number of event frames that follow `Subscribed` before live delivery begins: visible, filter-matching events only, with no control frames counted. The server reads the backlog in the subscribe transaction, checks each event's visibility and frame size, and counts what it will send.
- **A snapshot start whose whole snapshot exceeds its caps** refuses the subscribe (§5.5).
- **Page-mode `RESYNC_REQUIRED`** carries **no cursor** (PC10). The recovery is a fresh whole snapshot (`operation events` without `--cursor`), and only that snapshot's cursor is used.

### 5.4 Gaps, endings and checkpoints

**Every gap ends the stream** (PC9). The runtime sends one `resync_required` event with `subscription_ended: true`, and nothing after it. Its `reason` is one of:
- `subscriber_lagged` (the 256-event buffer overran);
- `history_trimmed` (retention removed events a live subscriber had not received; D6);
- `event_too_large` (an event that does not fit one frame).

The reasons differ on the wire. U3 asserts lag versus trim at the wire, reusing the existing retention paths.

**Endings:**
- the gap event above;
- the terminal `client`/`revoked` event;
- the connection closing;
- `Unsubscribe`. `Unsubscribe` of an ended subscription answers `NOT_FOUND`.

**The checkpoint rule** (S1, RC02). A reader persists a cursor only after it has applied either:
- the whole snapshot that cursor came from; or
- every event up to and including that cursor.

`Subscribed.cursor` counts as applied only after the snapshot, or after all `backlog: n` events.

**After a gap, a disconnect or an early stop:**
1. **The checkpoint freezes** at the last applied cursor.
2. The reader **closes the old stream**. It unsubscribes, or drops the connection, and applies nothing more from it.
3. It **resubscribes with the same filter** from the last applied cursor.
4. The runtime answers with the lossless backlog when it can deliver every missed event whole. Otherwise it answers with a **fresh whole snapshot** and its `resync_reason` (§5.3).

So recovery never builds state from a partial snapshot, and never skips an event that was not applied. An undeliverable event can never loop: a backlog that holds one becomes a snapshot start.

### 5.5 Snapshots: whole or refused (S1; D4)

**A snapshot is read in one store transaction** at the head boundary: `{data, cursor, taken_at}`.

**Its data is a typed `event-snapshot`:**
- `environment_id`;
- `authority_generation`;
- `operations`: the open and unresolved operations the reader may see;
- `operation`: the one the filter names;
- `pending_decisions`: the owner role only.

**Each section matches what the stream delivers.**
- `operations` and `operation` hold exactly the operations whose events this subscription's log and visibility predicate deliver: the same environment set, the same reader scope.
- **A section the filter cannot maintain is omitted.** `operations` appears only if the filter admits `operation_state_changed`, and `pending_decisions` only if it admits `decision`. With `filter.operation_id`, only `operation` appears.

So every item a snapshot holds receives its next change through that stream.

**Caps, which real single-user use does not reach:**
- `operations` ≤ 1,000 items;
- `pending_decisions` ≤ 256 items;
- the serialized document ≤ 768 KiB.

Compare: at most 32 operations run at once (`Limits::max_running_operations`), decisions are coalesced and expire after 15 minutes, and items are a few hundred bytes. Each section is read with `LIMIT cap + 1`, and its row lengths are summed in SQL before any row is materialized.

**Exceeding any cap refuses the subscribe**, and the cursorless `observe events`, with `USAGE_ERROR`/`response_too_large`. `data.error.section` names the section, and `data.error.narrow` names the filter to use (`filter.operation_id`, or `filter.types` without that section's event type). There is no partial snapshot, rebuild or partial marker. **`boundary_seq` is removed** (Q11's condition holds: no published schema names it, and no documented API or in-tree reader uses it).

### 5.6 Event pages

- **A page** (`operation events --cursor`) holds up to `limit` (≤ 500) events and up to a 768 KiB budget. It always includes its first event if that event fits one frame: an event over the budget but within the frame is returned alone, as a **singleton page**. It carries `more` and the cursor after its last event.
- **An event that does not fit one frame is undeliverable.** If it is the first event after the cursor, the page answers `RESYNC_REQUIRED`, reason `event_too_large`, with no cursor. The history gap is explicit, and the reader recovers from a fresh whole snapshot.
- **This standalone path is otherwise unchanged:** pages with a cursor, no live stream.

## 6. Lists and pages

### 6.1 Whole reads, `select` and pages (D2)

- **`pages/1`** is offered on **every read role's** session: owner, requester and viewer (an addition to revision 6's `capability::for_role` sets). It adds two request forms to `inspect`. **Subject authorization and visibility are unchanged:** a role pages only what it could already read. A request with `select` or `page` on a session without `pages/1` gets `SCHEMA_UNSUPPORTED`, so an old runtime refuses rather than ignores them.
- **A whole read** (neither `select` nor `page`) answers the complete list, or `USAGE_ERROR`/`response_too_large` sized before anything is sent (§4).
- **`select: {ids?, aliases?}`** holds 1–64 entries, subject-scoped. It answers exactly those items, plus `missing: [...]` for the ones that do not exist or are not visible. An empty selector is `USAGE_ERROR`/`selector_invalid`.
- **`page: {limit?, token?}`** answers `{items, more, next_page_token?}`. `next_page_token` is present exactly when `more` is true.
  - The default limit is 200, the maximum 1000, and the budget 768 KiB.
  - Content is always complete: there are no stubs.
  - **The traversal ends at the first page with `more: false`.** That page may be empty: an empty list, or a previous page that ended exactly at the last item.
- **`select` together with `page`** is refused (`USAGE_ERROR`/`selector_invalid`). Each form has one result shape.

### 6.2 Page tokens (RC05)

A page token is base64url and holds:
- a version;
- the **scoped tuple**: the reader tag (principal, role, `remote_client`), the environment, and the canonical query (subject, `cwd`, `preview`, `redact`, sort);
- the **position**: the last item's immutable unique ID, the subject's sort key;
- **an HMAC-SHA256 over all of the above**, under a 32-byte runtime-local key. The key is generated once into the store's metadata, never exported, printed or logged.

On each page the runtime recomputes the tuple from the current session and request, and verifies the MAC. **A tampered token, or one whose reader, environment, query or sort differs,** answers `USAGE_ERROR`/`page_token_invalid`. **A token carries a position, never authority:** every page re-applies the reader's visibility and role.

No snapshot consistency across pages is promised. A stable item is never repeated or skipped, because the keyset order is strict.

### 6.3 Resolution uses point lookups only (S3; RC04)

- **Internal resolution reads exactly the records it needs, by `select`.** That covers routes, hops, aliases, profiles, identities and projections, wherever `connect`, `ManagedConnect`, `run`, enrollment, catalog commands and setup decide something. Traversal serves enumeration only: list output and the TUI's lists.
- **A route dependency that is absent, malformed or unreadable is `CAPABILITY_UNAVAILABLE`/`route_undetermined`** (D21). Unreadable means the lookup failed, or the record is refused for size. It never falls back to the no-route or projection path. Today `connect_cmd::route_of` reads a missing hop as "no route".
- **M06's same-grant check** (ADR-0012 §5.4) stays on every selected or attempted jump.
- **Other resolution keeps its existing codes** (`NOT_FOUND` for an absent named item) and never falls back to a broader path.

### 6.4 Bounded items and bounded store reads (S2; RC06)

- **Every list item is bounded at write time,** at every ingress: CLI and IPC catalog writes, `import` (`portable_m05`), setup adoption, enrollment and runtime-created records. Its serialized form is ≤ **64 KiB**. The bounds are per field: labels, aliases and host names (existing), public keys (`MAX_PUBLIC_KEY_BYTES`), a profile's pairs (≤ 256), an identity's declarations (≤ 64), and M06's route and host-key counts. Runtime records inherit their bounds from these. U0 confirms the numbers against current validation (D20).
- **A legacy row over the limit** stays stored and readable by ID. A page or point `inspect` that meets it answers `USAGE_ERROR`/`response_too_large`, naming the item in `data.error.resource`, with remediation: edit or remove it by ID through the existing catalog command.
- **Store reads are bounded before rows are materialized.** Keyset pages read `limit + 1` rows. Whole reads, `select`, snapshot sections and backlogs read `LIMIT cap + 1` and sum `length(document)` in SQL first. Rows over the item limit are refused without deserializing them.
- **`remote_pending` (RC06).**
  - The environment view projects it as `remote_pending_count`, plus the first 16 entries.
  - The complete set is readable through a paged inspect path added in the environments arm, which M06's U7 owns.
  - **A view cap never refuses, drops or acknowledges a durable effect.** The effects themselves are not capped.

## 7. Idempotency namespace and retention

- **Key, hash and outcomes:** ADR-0006 §7.1–§7.3, with revision 6's `remote_client` in the key.
- **Retention:** ADR-0006 §7.4, **unchanged, with no ceiling** (R05):
  - active and `outcome_unknown` keys never expire;
  - a settled key is kept `retention.operations` (default 7 days, floor 24 hours);
  - then a 30-day marker.
  Recorded expiry instants and markers keep their written values.
- **Decision-backed replay adopts M06 W1's semantics** (RC08; `remote::widening::replay_answer`; §18.5 ruling 7). These are revision 6's synchronous widening forms with a required `request_id`: `invite`, `route add`, `transport enable` and `transport adopt_roost`. `route prefer`'s is optional. For the key `(client, kind, request_id)` bound to the canonical hash:

  | Record | A replay answers |
  |---|---|
  | a terminal result recorded | that result |
  | pending, not yet expired | the pending answer (`APPROVAL_REQUIRED`, the same `decision_ref`) |
  | approved (claimed), no result | `OUTCOME_UNKNOWN`. Never re-executed, never expired while unresolved |
  | expired, stale or otherwise unresolved | `DECISION_STALE`. The key is spent, and a new attempt uses a new `request_id` |
  | same key, another hash | `REQUEST_CONFLICT` |

  There is no replacement transaction. **Ratifying D16 requires M06's store-backed implementation to supply restart-replay coverage for pending, claimed, terminal and expired records.** Retention of terminal records follows that implementation.
- **The CLI mints a request ID when none is given.** Agents always pass `--request-id`.
- **Forms without a request ID** (revision 5's environment forms; revision 6's narrowing and compare-and-set forms) are not deduplicated by key. None is a primitive.

## 8. IPC authentication design (R07)

ADR-0006 §2.1, as amended through revision 6, is adopted as G08's IPC authentication design. The protocol document publishes the client half as MUSTs.

- **Three endpoints, never merged:**
  - **control;**
  - **signing:** per binding;
  - **issuer:** supervisor only, never published.

  The namespace is local only:
  - **Unix:** a runtime directory owned by the runtime's uid, with no group or other bits. Sockets are owned by that uid and have no group or other bits (`mode & 0o077 == 0`, which the runtime creates as `0600`). There is no TCP.
  - **Windows:** pipes with `PIPE_REJECT_REMOTE_CLIENTS`, a protected owner-only DACL, `FILE_FLAG_FIRST_PIPE_INSTANCE`, and a connection-level local check.
- **The server checks the client:** Unix peer credentials, or a Windows identification-level impersonation SID, must equal the owner's.
- **The client checks the server, before any data:**
  - **Unix**, mirroring `ipc::unix::connect`:
    - **the directory** is a directory owned by the caller, with `mode & 0o077 == 0` (`check_private_dir`), checked with `lstat`;
    - **the socket** is a socket owned by the caller, with `mode & 0o077 == 0` (`check_own_socket`);
    - **after connecting,** the peer credential's uid equals the caller's (Linux `SO_PEERCRED`; macOS `getpeereid` or `LOCAL_PEERCRED`).
  - **Windows:**
    - the path is in the `\\.\pipe\` namespace after normalization;
    - `CreateFileW` with `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`;
    - `FILE_TYPE_PIPE`;
    - the pipe owner's SID equals the caller's;
    - the server process (`GetNamedPipeServerProcessId`) runs as the caller's SID.
  - **Both:** after the hello, `ServerHello.environment_id` equals the **expected environment ID**. That ID is an input that comes with the endpoint: from discovery, or, with an explicit endpoint, from the caller.
- **Discovery (D12; RC11).** `service status --json` connects, verifies, and completes the hello. **Every field it reports comes from that verified connection or is checked against it:**
  - `control_endpoint`: the endpoint it connected to;
  - `environment_id`, `protocol`, `capabilities`, `principal` and the server version: from `ServerHello`;
  - `pid`: from the verified peer (Linux `SO_PEERCRED`, macOS `LOCAL_PEERPID`, Windows `GetNamedPipeServerProcessId`), which must equal the advertisement's `pid`.

  A mismatch is `SERVICE_UNAVAILABLE`/`endpoint_untrusted`. No runtime is `SERVICE_UNAVAILABLE`/`runtime_not_running`. Signing endpoints come only from a binding's `consumer`. The issuer endpoint is never published.
- **The same-user residual:** peer identity is the OS principal. Every same-user process can reach the owner channel, and attended confirmation is a usability boundary, not a security boundary (primitives-draft Q1, decided). Administrators and SYSTEM are out of scope.
- **Not yet run natively:** the foreign-owner rows. They stay `blocked` on B2, B3 and B8 until executed.

## 9. The compact primitive set exposed to agents

`heimdall --json schema show primitives` (D7) prints exactly six groups, offline, generated from the contract types. Each entry gives the CLI and wire forms, response schemas, codes and next actions, whether `request_id` is taken, and the roles allowed:

| Group | Forms | Who may call |
|---|---|---|
| inspect | `inspect` (whole, `select`, `page`) | every role, within its visibility |
| ensure | `ensure` | owner, requester |
| bind | `bind` (launch through `run`; materialize) | the binding's holder; the owner |
| delegate | `delegate` | the parent binding's holder |
| observe | `observe` (show, wait, events, subscribe); `cancel` is a form of observe | the operation's caller; the local owner |
| release / revoke | `release`, `revoke` | release: the holder; revoke: the grant's holder, own grant only, or the owner |

**Excluded:** pause, resume, cutoff, broader `access stop`, `access allow`, decisions, time confirmation, setup, enrollment, the issuer and uninstall. Consent never comes from the agent surface.

## 10. Consequences

- **Third parties need no Rust crate.** The wrapper proves the IPC surface; H1 and H2 prove the CLI surface in two composition styles.
- **No answer can be mistaken for a whole list.** No internal decision reads a page or a traversal.
- **Snapshots are whole or refused, and every gap ends the stream.** A reader recovers by one resubscribe from its last applied cursor.
- **Costs:**
  - a filter is needed in the (unreached) case of oversized snapshot sections;
  - write-time item bounds at every ingress;
  - the in-tree resolution callers migrate to point lookups.

## 11. Proposed ADR-0006 revision 7 (layered on revision 6.1; nothing applied)

**Classes:**
- **A:** additive.
- **C:** a pre-release correction (§12).
- **B:** a behaviour change before the freeze.
- **R:** a ratification.

| # | Delta | Class | Owner and tests |
|---|---|---|---|
| D1 | **Typed views with published schemas** for every list and read subject, `status`, `service-status`, `operation`, the subscription head, and the error and stream variants. Types are inventoried from today's shapes and callers. **Keys are kept, including subject metadata** (`inspect operations`' `counts`, `inspect projections`' `record`) | C | U0 types, U3 builders; the schema-to-emitter checklist |
| D2 | **`pages/1` on every read role; whole, `select` or `page`, one at a time; `{items, more, next_page_token?}`; HMAC-protected tokens** (§6) | A | U0, U3. Tests: limited roles; tampered token; changed scope or sort; `select` with `page`; empty selector; final-row reachability and count |
| D3 | **Names:** the command-tree golden; Q1's names; hidden integration endpoints | C | U0, M06 |
| D4 | **Whole-or-refuse snapshots** with section caps, filter-matched sections and `boundary_seq` removed (§5.5) | C | U3. Tests: the over-cap refusal; filtered and paired subscriptions deliver every snapshot item's next change |
| D5 | **Typed event payloads as emitted,** from the emission sites and the replay corpus | A | U0. Tests: the inventory; the replay corpus |
| D6 | **Gap endings:** `history_trimmed`; every gap ends the stream; `Subscribed.backlog` as an exact frame count; `Subscribed.resync_reason`; reasons in page-mode `RESYNC_REQUIRED`, which carries no cursor | A + C | U3. Tests: lag versus trim at the wire; a disconnect at the head; an early stop; a gap followed by a later event (nothing after the gap is applied, and the resume delivers it) |
| D7 | **`schema show primitives`:** six groups, roles and schemas | A | U0; golden |
| D8 | **`schema show reasons`:** error reasons with their codes, including the route pair (`route_undetermined` / `CAPABILITY_UNAVAILABLE`). Pending-state reasons are listed separately | A | U0; golden |
| D9 | **Omitted versus `null` in typed views,** after a per-field inventory. Persisted payloads are unchanged | C | U3; corpus |
| D10 | `EnsureData.uncovered_lock_behavior`, `PolicyView.scope` (optional) | A | U0, U3 |
| D11 | **A per-pair route status** on M06's route semantics | A | U0 with M06 |
| D12 | **`service status`:** every field from, or checked against, the verified connection (§8); `runtime_not_running`, `endpoint_untrusted` | A | U3. Test: a restart between the read and the hello, checking `control_endpoint`, `environment_id`, `pid` and version |
| D13 | **`destination remove`** refuses live or unresolved access inside the removal transaction: `CONFIG_CONFLICT`/`destination_has_live_access`. `data.error.live` lists up to 32 entries plus `total`. **`data.error.remediation` names `heimdall access stop --work <work_id>` only for entries with an actual work reference**; the other entries are listed without a command. This closes M05-F1 | B | U8b. Tests: the refusal; a grant created after a preflight is refused |
| D14 | **The help-text rule** and its lint | A | U0, U2b |
| D15 | **The spec §11.6 list and the exit table with the stream grammar** (§4) | R | the orchestrator |
| D16 | **Ratify:** revision 3's §15.2 items 1–7; revision 4's §16.2 items 1–18; revision 6 as ruled in §18.5; any M06 W2–W3 readings; §7.4 retention unchanged; decision-backed replay as §7, **with M06's restart-replay coverage as a precondition** | R | U0, M06 |
| D17 | **Confirm `remote_pending_reasons`,** distinct from revision 6's `remote_pending` | R | — |
| D18 | **Coexistence, selection and removal** (§3.3) | R | — |
| D19 | **`response_too_large`:** reads refused before sending (`effect_status: none`, next `narrow_request`); a reply after dispatch keeps its truthful `effect_status`, `operation_id` and next `observe` (§4). Generated error schemas, the CLI and the wrapper migrate together | C | U3. Tests: a list over budget; a snapshot over a cap; a settled mutation's reply that does not fit (`applied`, operation reference); an uncertain one (`unknown`); the CLI exits 2 |
| D20 | **Write-time item bounds** at every ingress, import included; legacy rows readable by ID and refused for size in lists (§6.4) | B (new validation; listed as PC11) | U0, U3. Tests: a maximal record fits a page; a legacy over-limit row is refused from a page and from a point `inspect`, naming its ID; an over-limit import is refused |
| D21 | **`page_token_invalid`, `selector_invalid`, and `route_undetermined` for an absent, malformed or unreadable route dependency** | A + B | U3. Tests: a deleted hop and a failed hop lookup, through the CLI and the route helper; M06's same-grant check still enforced |

**Unchanged:** the IPC protocol and framing; the schema major; the codes and their exit classes; every existing request hash; the attended-confirmation rules; revision 6's role negotiation, except the `pages/1` addition; **every persisted row**.

## 12. Pre-release corrections (before ratification only)

Each lands as one change, with its emitters, every in-tree reader and its goldens (§1.3).

| # | Correction | Why | Emitters and readers in the same change |
|---|---|---|---|
| PC1 | Snapshot `data` → typed, whole-or-refused `event-snapshot`; filter-matched sections; `boundary_seq` removed | S1, Q11 | `app::events::snapshot_data`, `observe events`; CLI `--follow` head, TUI worker, wrapper, H1, H2, `integration_ipc_unix`/`model_events` goldens |
| PC2 | Untyped `inspect` views → typed, same keys, metadata kept | R06 | `app/operations.rs` inspect arms; CLI renderers, TUI `data.rs`/`m03.rs`/`m05.rs`, wrapper, harnesses, goldens |
| PC3 | `null` dropped from typed views where it means "not applicable" | ADR-0006 §9 | the view builders; TUI readers, goldens |
| PC4 | An oversized response: `INTERNAL_ERROR` → `response_too_large`, with truthful effects | Q4, RC07 | `ipc::session::send_or_internal`, the view builders; CLI exit tests, wrapper, generated error schema |
| PC5 | An undeliverable first event in a page → `RESYNC_REQUIRED`/`event_too_large`; singleton pages | RC02 | `app/operations.rs` `observe events`; CLI page reader, wrapper, H1 |
| PC6 | A retention gap → `history_trimmed` | ADR-0006 §13.9 item 6 | the publisher's `force_resync`, `ipc::session` relay; CLI `--follow`, wrapper, harnesses, `model_events` |
| PC7 | M06's CLI names | Q1 | M06's registration, help, any rendered caller |
| PC8 | `destination remove` refuses while access is live | Q6 | `app::catalog`; `catalog_cmd`, goldens |
| PC9 | **Every gap ends the stream** (`subscriber_lagged` used to keep it) | S1 | `ipc::session` relay; CLI `--follow` (exit 6), TUI worker, wrapper, harnesses |
| PC10 | **Page-mode `RESYNC_REQUIRED` carries no cursor** | RC02 | `Operations::resync`; CLI, wrapper, H1 |
| PC11 | **Write-time item bounds** (D20) | S2, RC06 | catalog writes, import, setup, enrollment; the CLI's refusals, goldens; legacy-row tests |

## 13. Rulings recorded

**Revision 2's rulings stand:**
- **Q1–Q12;**
- **the typed refusal:** `USAGE_ERROR`;
- **pre-freeze breaks.** Q9 cites spec §9.1 and A18.

**Revision 3 applies these rulings:**
- **S1:** no partial snapshots; every gap ends the stream; the checkpoint rule.
- **S2:** no stubs; write-time bounds; legacy refusals by ID; `more` separate from content.
- **S3:** resolution by point lookups only; `route_undetermined`; M06's same-grant check.
- **S4:** H2 independent, over `heimdall --json`, goal-directed; the operation-level capability-refusal fixture (M07 plan §5a).
- **RC02:** one revocation ending; an error-only first line.
- **RC05:** `pages/1` on every read role; HMAC tokens; one form at a time.
- **RC06:** `remote_pending` projected; ingress bounds; bounded reads; M06's U7 owns the environments arm.
- **RC07:** truthful effects after dispatch.
- **RC08:** M06's replay semantics.
- **RC09:** one change per live shape; real prior-version rows.
- **RC10:** the ratification exceptions; A30 stated once, in the plan's controlling exit section.
- **RC11:** the reviewer's fix.

## 14. Reopen conditions

- The wrapper or a harness cannot complete A32 from the protocol document and schemas alone.
- A native platform contradicts §8.
- M06 needs a contract change after revision 6.x is closed.
- Real use reaches a snapshot cap.
- The replay corpus finds a row the revision-7 readers cannot read.
- The owner revisits primitives-draft Q1.
