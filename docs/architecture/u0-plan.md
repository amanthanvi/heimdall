# U0 plan: revision 7's preparatory part and the M08 contract skeleton

**Status:** draft 1 (2026-11-23), by the U0 implementer for the contract owner. Nothing here is a
ruling. Items marked **[ASK]** wait for the contract owner; everything else proceeds as written.
**Branch:** `u0/rev7` = `main` `e9bdb96c` + `origin/m06/exit` `a10eec63` (local merge `58fb4346`,
no conflicts). Revision 7 is layered on revision 6.6 (ADR-0006 §18.10).
**Sources:** ADR-0013 rev 3 (§1.3, §11–§13, D1–D21); ADR-0014 §3.6 and §7 (H1–H15); m07-plan U0
and §3; m08-plan U0 and rule 2; `m07-u0-handoff.md` (main's copy plus Q8–Q10 from
`origin/m08/w2`); the contract owner's rulings on U0-Q1 to Q10 (2026-11-24).
**Merge trigger:** M06's exit on `main` and the contract owner's explicit handoff. U0 drafts now.

## Rulings on draft 1 (the contract owner, 2026-11-24), applied below where they change the plan

- **S0:** standalone types and schemas; U3 or U2b attaches each with its emitters and readers;
  published schemas of live documents stay byte-identical in U0.
- **ASK-CODE (b):** `REQUEST_STALE` is declared in the reason table only; `Code::RequestStale`
  joins `Code::all()`, `schema show codes` and `codes.json` with its emitter and both harnesses.
- **ASK-VERSION (b):** `1.0.0-rc.1` is set once at the M08 candidate commit, with U8's claims
  update. **Not in U0.**
- **H13:** one optional `request_epoch` per request frame, outside every hash; `request-epoch/1`
  declared, not offered. A client holding a kept epoch refuses (`SCHEMA_UNSUPPORTED`) against a
  runtime that does not offer it; a fresh request with no kept epoch is sent without one. The
  server check, the envelope field, the CLI flag and every consumer land as one change (U2b with
  U3's readers).
- **ASK-FLAGS:** no refusing flags; `--request-epoch` and `access release --request-id` arrive with
  their checks.
- **Q11 A** (a local-widening row in ADR-0013 §7; §7's "agents always pass `--request-id`" covers
  agent primitives only); **Q12 A + D** (`route_health`, `host_pin_defeated` are D11; ADR-0010 §10's
  dependency status `deferred_with_decision` past 1.0); **Q13 B** (M07 U3; both `inspect
  environments` and `environment status` carry a capped `remote_pending` and
  `remote_pending_count`; the cap is a D20 number: **16**, ADR-0013 §6.4's "first 16"); **Q14 A**
  (`GrantResidual` typed with a public schema; `EnsureData.residuals`, `attach_runner_readiness`
  and the hard-coded `runner_residuals` removed in U3 as a pre-release correction).
- **ASK-H3:** every skeleton answers "not available in this build" whatever flags it gets.
- **ASK-H10:** one `EventType::StateRestored`; its payload names what ended (quarantined clients,
  voided invitations, disabled exposure, closed decisions).
- **ASK-Q9:** approved as built. **ASK-D20:** 256 profile pairs, 64 identity declarations, 16 routes
  per destination, 8 relays per route, plus the `remote_pending` cap.
- **Help lint:** U0 may edit `m06_cmd.rs`'s doc comments and help strings only, once M06's exit is
  on `main`; until then the lint's pending list names those paths.
- **§6 items 9–14** as proposed. **Migration 0014** stays in U0; H12's adoption treats version 14
  as a flat-layout store.

## Rulings of 2026-11-24 on D20 and the readings, applied

- **D20:** the 64 KiB item bound stays; 200 profile pairs (a maximal profile is 58,125 bytes);
  8 routes, 8 relays per route, 16 relays per destination, relay URLs at 2,048 bytes, 4 consents
  and 4 direct addresses per route, 8 host-key pins of 1,536 bytes (a maximal destination with
  its routes is 61,105 bytes). Each maximal-record test (`contracts::rev7::maximal_*`) fills
  every field at once and leaves 4 KiB.
- **Readings confirmed:** `state_restored_authority_ended` (`CREDENTIAL_EXPIRED`), `item_too_large`
  (`USAGE_ERROR`, byte and count bounds; `ItemTooLarge` names the field and the bound),
  `ledger_damaged` and `state_corrupt` (`STATE_UNAVAILABLE`, next `owner_decision`),
  `state_newer_than_build` (next `change_client`), `probes_unavailable`, `restore_epoch_stale`
  under `REQUEST_STALE` and `DECISION_STALE`. The reason table's rows are (reason, code) answers
  with their next action. Q4's four values; Q3's sites (ADR-0006 §19.5).
- **D1 questions:** withheld `result` omitted (documented); `record` omitted until committed;
  nested `null`s in persisted content kept; `.full` views swapped in by rename in U3;
  `WithPreview<T>` flattens the typed-elsewhere views (checked flat: `with_preview_is_one_flat_object`).
- **Out-of-scope touches accepted:** `main.rs`'s `mod rev7_cmd;`; the four `SCHEMA_VERSION`
  assertions. The TUI `noninteractive` finding went to M07; `schemas/examples/` stay for U3.

## 0. The bound, and one structural finding

ADR-0013 §1.3: U0 lands only what no live path emits yet. Every live wire-shape change is U3's
(or U2b's), one change per correction, with its emitters, every in-tree reader and its goldens.

**Finding S0 (shapes the whole plan): U0 cannot attach a field to an existing wire struct.**
The structs revision 7 extends are built with struct literals outside U0's write scope, so adding
even an `Option` field breaks compilation there:

| Struct | Literal construction sites outside U0's scope (files) |
|---|---|
| `InspectRequest` (D2 `select`/`page`) | `tests/model/operations.rs` (10), `tests/integration/{runtime_m03,portable}.rs`, `heimdall/src/m05_cmd.rs`, `runtime/src/dispatch.rs`, `wsl_cmd.rs`, `tests/e2e/*`, … |
| `ServerHello` (H13 `restore_epoch`) | `ipc/src/session.rs`, `remote/src/bridge.rs`, `heimdall/src/client.rs` |
| `ErrorDetail` (D13, D19 fields) | `app/src/error.rs`, `ipc/src/session.rs`, `app/src/remote_env_tests.rs`, `tests/integration/ipc_unix.rs` |
| `EnsureData` (D10, A07 residuals) | `app/src/operations.rs`, `tests/model/*` (15+), `tests/integration/*` |
| `ReleaseRequest` (Q7 `request_id`) | `tests/model/*`, `runtime/src/managed_store/live_tests/*`, `app/src/holders.rs` |
| `PeerInfo` (H7 provenance) | `ipc/src/session.rs`, `tests/*` (20+) |

So U0 defines **standalone types** (and their schemas) for each extension, plus reason and code
constants, and the attachment of a field to a live struct is the live change, made by U3 or U2b
with its emitters and readers. That is ADR-0013 §1.3's rule applied literally, and it keeps every
published schema of a live document byte-identical in U0. The alternative, widening U0's scope to
mechanical `field: None` edits in those files, would change published schemas of live documents
with no emitter behind them. **[ASK-S0]** Confirm standalone types, or widen the scope.

Two other enums revision 7 extends are not `#[non_exhaustive]` and are matched exhaustively
outside U0's scope: `InspectSubject` (`inspect request`) and the CLI-independent request forms in
`Request`. U0 adds no variant to either; `inspect request` is a CLI skeleton (§2, Q7) and its wire
form lands with U3. Enums that are `#[non_exhaustive]` (`Code`, `EventType`,
`RemainingArtifactKind`) take new variants in U0 where §3 says so.

## 1. Each item's U0 part

Files: `contract/` = `crates/contract/src/`; goldens under `tests/contracts/golden/`; schemas under
`schemas/public-api/`. "Standalone" = a new type, exported as its own schema, attached by the unit
named.

### 1.1 ADR-0013 D1–D21

| # | U0 part | Files | Later (unit) |
|---|---|---|---|
| D1 typed views | Standalone view types for every list and read subject (the 11 of 16 `inspect` subjects with no published schema, plus `status`, `service-status`, `operation`, the subscription head, the error and stream-line variants), keys inventoried from today's builders and callers, subject metadata kept (`inspect operations`' `counts`, `inspect projections`' `record`). Each field's omitted-versus-`null` form follows the D9 inventory (the revision-7 form, so it may differ from today's bytes where PC3 applies; that difference is listed per field). Schemas `inspect-<subject>`, `status`, `service-status`, `operation`, `subscription-head`, `stream-line` | `contract/views/*.rs` (new), `contract/schema.rs`, schemas, `tests/contracts/rev7.rs` | U3: builders (PC2, PC3) |
| D2 `pages/1` | `capability::PAGES_V1` in a new `REVISION_7_DECLARED`, **not offered**. Standalone `PageRequest {limit?, token?}`, `Select {ids?, aliases?}`, `Page<T> {items, more, next_page_token?}`, `Selection<T> {items, missing}`, `PageToken` (opaque, ≤ 256 bytes, base64url, never parsed). Constants: default limit 200, max 1000, budget 768 KiB, select 1–64 entries. Reasons `page_token_invalid`, `selector_invalid` (`USAGE_ERROR`) | `contract/page.rs` (new), `contract/ipc.rs`, reasons | U3: the `InspectRequest` fields, `for_role` sets, HMAC tokens, server and client |
| D3 names | The command-tree golden (every path, flag, positional and hidden marker, from clap's `Command` tree); M06's names are already in (`environment`, `transport adopt-roost`, no `roost`; checked by the golden). Hidden integration endpoints `activate --hook` and `route connect` recorded as hidden | `cli.rs` test module, `golden/command-tree.golden.txt` | — |
| D4 snapshots | Standalone `EventSnapshot {environment_id, authority_generation, operations?, operation?, pending_decisions?}`; caps (1,000 operations, 256 decisions, 768 KiB) as constants; schema `event-snapshot` | `contract/event.rs` | U3: PC1, `boundary_seq` removal |
| D5 payloads | A discriminated `EventPayload` type (one variant per type and `kind`, every key as emitted, nullable keys kept), its schema, and **`event_payload_schema_covers_every_emission_site`** (a source scan of the emission choke points; §4) plus the replay corpus (§5). `Event.payload` stays `Value` | `contract/event_payload.rs` (new), `tests/contracts/rev7_events.rs` | — |
| D6 gaps | Reasons `subscriber_lagged`, `history_trimmed`, `event_too_large`, `backlog_too_long`, `cursor_invalid`; a `ResyncReason` enum; standalone `SubscribedRev7 {subscription, cursor, backlog?, snapshot?, resync_reason?}` documentation type; the `resync_required` payload's `subscription_ended` in the D5 type | `contract/event.rs`, reasons | U3: PC5, PC6, PC9, PC10 |
| D7 primitives | `schema show primitives`: six groups generated from contract types (CLI and wire forms, response schemas, codes and next actions, `request_id`, roles); golden `primitives.golden.json` | `contract/primitives.rs` (new), `cli.rs` (`schema show` name), golden | — |
| D8 reasons | `schema show reasons`: one table of every error reason with its code(s), from every group (`reason::ALL` with its codes made explicit, `M03`, `M03_REV5`, `M04`, `M05`, `M06`, the conflict kinds, manual reasons, `m03_warning::REASONS`) plus revision 7's (§3); pending-state reasons listed separately (`M06_PENDING`, `remote_pending_reasons`); golden `reasons.golden.json`. Q3's tokens and Q4's reason are rows here (§3) | `contract/envelope.rs` (`reason::table()`), `cli.rs`, golden | U3: emitters |
| D9 null | The per-field inventory, as a table in `tests/contracts/golden/views-null-inventory.md` read by the D1 tests (each field: today omitted / `null` / always present; revision 7 form; PC3 change yes/no) | golden | U3: PC3 |
| D10 | Standalone `UncoveredLockBehavior` (the value `EnsureData.uncovered` cannot name, ADR-0011 I-7) and `PolicyScope` (I-14), schemas | `contract/request.rs`, `contract/trust.rs` | U3: attach to `EnsureData` and `PolicyView` |
| D11 per-pair route status | **Waits for Q12** (§7) | — | — |
| D12, H14 | Standalone `ServiceStatus` view (every field from or checked against the verified connection: `control_endpoint`, `environment_id`, `protocol`, `capabilities`, `principal`, `server`, `pid`); reasons `runtime_not_running`, `endpoint_untrusted`, `runtime_unreachable` (`SERVICE_UNAVAILABLE`) | `contract/views/service.rs`, reasons | U3: the three-state read |
| D13 | Reason `destination_has_live_access` (`CONFIG_CONFLICT`); standalone `LiveAccessRefusal {live (≤ 32), total, remediation?}` | reasons, `contract/catalog.rs` | U3 with U8b |
| D14 | The help lint over the rendered help of every command (no `M0n`, `ADR-`, `§`, no test-only wording); the help strings in `cli.rs` rewritten to pass. **m06_cmd.rs's help strings are outside U0's scope** (§6) | `cli.rs`, help goldens | U2b for any remainder |
| D15 | The proposed spec §11.6 text (16 codes plus the exit table and stream grammar), drafted in ADR-0006 §19 for the contract owner to apply | ADR-0006 §19 | the orchestrator |
| D16–D18 | Recorded in §19 as provisional ratifications: §15.2 items 1–7, §16.2 items 1–18, revision 6 as ruled in §18.5, the M06 W2–W3 readings, §7.4 retention unchanged, decision-backed replay **with D16's precondition met by `6f2cc7eb`'s restart-replay coverage** (to be confirmed under Q11), `remote_pending_reasons` distinct, coexistence and removal | ADR-0006 §19 | — |
| D19 | Reason `response_too_large` (`USAGE_ERROR`); standalone `ResponseTooLarge {limit_bytes, section?, narrow?, resource?}` | reasons, `contract/envelope.rs` | U3: PC4 |
| D20 | The bounds as constants with the numbers confirmed against current validation (§1.4), and a contract test that a maximal record of each contract-typed kind serializes ≤ 64 KiB | `contract/bounds.rs` (new), `tests/contracts/rev7.rs` | U3: PC11 enforcement at every ingress |
| D21 | `page_token_invalid`, `selector_invalid` (D2); `route_undetermined` exists (M03 table) | reasons | U3 |

### 1.2 ADR-0014 H1–H15 and the rulings Q1–Q10

| # | U0 part | Files | Later |
|---|---|---|---|
| H1 | `heimdall support bundle [--preview] --out <file> [--include-identifiers]`: skeleton answering the "not available in this build" envelope; a contract type for the manifest mirroring `crates/support`'s (format `heimdall-support-bundle/1`), schema `support-bundle-manifest` | `cli.rs`, `contract/support.rs` (new) | U6b |
| H2 | `service stop --preview`: skeleton; standalone `StopPreview` type, schema `service-stop-preview` | `cli.rs`, `contract/views/service.rs` | U2b |
| H3, Q8 | `state status`, `state restore --backup <file>`, `state reset`, `state repair` (ledger scope): attended skeletons (refused under `--non-interactive` with `INTERACTION_REQUIRED` before the not-available answer? see **[ASK-H3]**); report types `StateStatus`, `RestoreReport`, `ResetReport`, `RepairReport`; ADR-0014 §3.6 recorded in §19 as an authority rule of the contract | `cli.rs`, `contract/state_cmd.rs` (new), ADR-0006 §19 | U2b |
| H4 | Reasons `state_corrupt`, `state_newer_than_build` (`STATE_UNAVAILABLE`), `state_restored_authority_ended` | reasons | U2b |
| H5 | Doctor finding constant `executable_moved` (declared, not produced) | `contract/doctor.rs` | U2b |
| H6 | `RemainingArtifactKind::{MigrationBackup, EarlierStoreGeneration, PreviousBinary, GitBlockMoved}` (the enum is `#[non_exhaustive]`; `setup-result` schema regenerated) | `contract/setup.rs` | U2b |
| H7 | Standalone `BuildProvenance {commit, target, profile, features}` | `contract/version.rs` | U3/M08: attach to `PeerInfo`/`inspect capabilities` |
| H8 | `1.0.0-rc.1` in the root manifest, set once. **Consequence found: every claim entry reads `unknown`** (§6 item 2) | `Cargo.toml`, `Cargo.lock` | — |
| H9 | Migration `0014_restore_epoch.sql` (§4) | `crates/store/migrations/`, store | U2b: writers |
| H10 | Reasons `client_quarantined_after_restore`, `invitation_void_after_restore`, `exposure_disabled_after_restore`; `EventType::StateRestored` declared, not emitted, with its payload type (H4's event and H10's `restore` event read as one; **[ASK-H10]**) | reasons, `contract/event.rs` | U2b |
| H11 | None (M08 U3c, a manifest feature) | — | U3c |
| H12 | None: built in U2b per ADR-0014 H12 (m08-plan U0 lists "the storage layout of H12"; §6 item 9) | — | U2b |
| H13, Q5, Q6 | §3: `REQUEST_STALE` (class 6, `new_request_id`), reasons `restore_epoch_stale`, `restored_before_completion`; standalone epoch types; the design | `contract/code.rs`, reasons, `contract/epoch.rs` (new) | U2b and U3 |
| H15 | None (U2b) | — | U2b |
| Q1 | Recorded in §19 (both codes carry `next.decision_ref`); no code change | ADR-0006 §19 | U4b skill |
| Q2 | Recorded in §19; no type | ADR-0006 §19 | U3 (removal of adoption) |
| Q3 | Reasons under `CAPABILITY_UNAVAILABLE`: `mechanism_minimum_unmet`, `decision_denied`, `route_undetermined` (exists), and the refused confirming probe's token, named from M06's emission site (§7, inventory) | reasons | U3 |
| Q4 | Standalone `LaunchProvenance` (`controller_dependency`, `unknown`, and M06's clean value, named from its emission site) and the unattended refusal's reason row in D8's table | `contract/run_record.rs`, reasons | U3: attach to the run record |
| Q7 | `inspect request <REQUEST_ID>` CLI skeleton; standalone `RequestView {state, operation_id?, code?, request_epoch}` (`state`: `in_progress`, `completed`, `not_found`); standalone `BindingRequestRef` for `inspect bindings`' `request_id`; `access release --request-id/--request-epoch` **[ASK-FLAGS]** | `cli.rs`, `contract/views/request.rs` | U3 |
| Q9 | The store side: a case-insensitive alias lookup used by the catalog's write path, `CONFIG_CONFLICT`/`alias_collision` at write; an index on `alias COLLATE NOCASE` (non-unique: existing case-variant pairs stay); a store query listing existing case-variant pairs for `doctor` | `crates/store/src/ext.rs`, migration 0014, `crates/app/src/catalog.rs` | U1b: the `doctor` finding (Q10 owner) |
| Q10 | None (U1b) | — | U1b |

### 1.3 Version, ADR and handoff

- `1.0.0-rc.1` is the last commit (§6 item 2).
- ADR-0006 §19 (revision 7, provisional), layered on 6.6: every delta and H item with its U0 part and its later unit, the rulings Q1–Q10 (and Q11–Q14 when ruled), the S0 rule, D16–D18's provisional ratifications, the spec §11.6 proposal, ADR-0014 §3.6 as an authority rule.
- `m07-u0-handoff.md`: main's copy merged with `origin/m08/w2`'s Q8–Q10 and the rulings marked.

### 1.4 D20's numbers against current validation (observed in source)

| Field | ADR-0013 §6.4 | Today | Where |
|---|---|---|---|
| alias | existing | 255 bytes | `app/src/catalog.rs:117` |
| host name | existing | 255 bytes | `app/src/catalog.rs:120` |
| label | existing | 256 bytes (environment 64, remote 64, project 128) | `contract/catalog.rs:21`, `environment.rs:14`, `remote.rs:119`, `domain/workspace.rs:198` |
| public key | `MAX_PUBLIC_KEY_BYTES` | 16 KiB | `contract/catalog.rs:19` |
| profile pairs | ≤ 256 | **no bound** on a profile; a request scope is ≤ 1,024 (`MAX_SCOPE_PAIRS`), a manifest ≤ 256 | `contract/request.rs:40`, `project.rs:23` |
| identity declarations | ≤ 64 | **no bound found** | — |
| host keys (M06) | M06's | 16 per runner | `app/src/remote_env.rs:75` |
| routes per destination, relays per route (M06) | M06's | **no count bound found**; a relay URL ≤ 2,048 bytes | `contract/route.rs:190` |

U0 records 256 pairs and 64 declarations as revision 7's bounds; the route and relay counts need a
number **[ASK-D20]** (proposed: 16 routes per destination, 8 relays per route, from the 64 KiB
item budget). Enforcement at every ingress is PC11 (U3).

## 2. The CLI skeletons

Each new command answers the "not available in this build" envelope (`USAGE_ERROR`, exit 2,
effect `none`, next `fix_request`) before any runtime contact, home creation or file read, with
`--json` honoured after the command. The message is "this command is not available in this
build" with no milestone (help lint; the M02/M03 source guards scan for the unassembled text, so
it is assembled at run time as `wsl_cmd::refusal_message` does). New: `support bundle`, `state
status|restore|reset|repair`, `service stop --preview`, `inspect request <REQUEST_ID>`. Each is in
the command-tree golden. None is an agent primitive (D7), and the skill lint's allow-list keeps
refusing them (handoff §2).

## 3. H13: the epoch design under Q5 and Q6

**Proposed** (U0 lands the types and constants; U2b the server check, the store writes and the CLI;
U3 the envelope; the wrapper and harnesses follow in the same change):

1. **Hello:** `ServerHello.restore_epoch: u64`, attached by U2b; a reader treats it absent as 0.
2. **On the wire, one field per request frame, not per form:** `ClientMessage::Request {seq,
   request, request_epoch?}`. Every mutating request carries it; reads ignore it. It is outside
   every canonical request hash, so every existing hash stays byte-identical, and a retry with the
   same epoch matches. **Alternative:** a field beside each form's `request_id` (12+ forms, and
   none for the mutating forms with no request ID, which H13 also covers). **[ASK-H13a]**
3. **A capability** gates it, so a runtime that would ignore the field refuses instead:
   `request-epoch/1`, declared not offered in U0. A client that sends `request_epoch` without it
   gets `SCHEMA_UNSUPPORTED` at hello. **[ASK-H13b]** (ADR-0014 names no capability; without one
   an older runtime ignores the epoch and the fence fails open.)
4. **The server's check, before any store write or effect:** present and not current →
   `REQUEST_STALE`/`restore_epoch_stale`. Absent → bound to the current epoch at receipt. Then a
   fence record for the request's ledger digest (H9) answers `REQUEST_STALE`/
   `restored_before_completion`. Attended or not.
5. **The CLI:** `--request-epoch <N>` on every command that takes `--request-id` (**[ASK-FLAGS]**:
   added in U0 as a flag that refuses with "not available in this build" when given, or added by
   U2b with its check). Absent, the CLI binds the hello's epoch at send. The mutating answer
   reports `request_epoch` beside the request ID it used: `Envelope` gains no field in U0 (S0);
   U3 adds it where the envelope names the request.
6. **Codes:** `REQUEST_STALE`: exit 6, not retryable, effect `none`, next `new_request_id` (Q6).
   **Live consequence** (§6 item 1): `schema show codes` and `codes.json` grow to 31 rows, and H2's
   real-binary smoke asserts its frozen copy equals the installed table.
7. **Stored (H9):** `restore_epoch` in the store's metadata (default 0); `request_epoch` on
   idempotency records, `restore_epoch` on operations and decisions (every existing row 0, so every
   reference minted before is epoch 0); a fence table keyed by the ledger digest (SHA-256 over the
   canonical full idempotency key: principal, caller role, `remote_client`, kind, request ID;
   `stategen::ledger::key_digest`), with its stored answer and ADR-0006 §7.4 lifetimes (settled
   instant, expiry, the 30-day marker); the backup's environment binding (`backup_environment_id`
   in the store metadata); a quarantine state for `remote_clients` and a void state for
   `remote_invitations` where 0009–0013 lack them (checked at implementation).
8. **The residual,** as H13 states it: a caller that re-stamps an old request ID with a new epoch
   is outside the contract; the ledger and fence still catch it when either survives.

## 4. Tests named by the plans, and the order of work

**Named tests (U0):** the regenerated schema goldens; the command-tree golden; the help lint; the
primitive-index and reason-table goldens; `event_payload_schema_covers_every_emission_site`;
`stored_samples_replay_through_revision_7_readers`;
`schema_export::checked_in_public_api_matches_the_model_exactly`, extended; migration up (0014 on a
version-13 store, earlier rows kept; a broken step leaves 13); every new command answers its "not
available in this build" envelope. **Added by this plan:** the Q9 refusal (`Alpha` beside `alpha`
refused at write through the catalog; a stored legacy pair stays readable and listed by the store
query); a maximal-record size test (D20); the code-table goldens at 31 rows when `REQUEST_STALE`
lands.

**Order** (each a commit, gate green first; dependent items last):

| # | Commit | Depends on |
|---|---|---|
| 1 | `docs/architecture/u0-plan.md` (this file) | — |
| 2 | Reasons and the D8 table: revision 7's reason constants, `reason::table()`, `schema show reasons`, its golden | — (Q3's probe token and Q4's clean value from the inventory) |
| 3 | D7: `schema show primitives` and its golden | — |
| 4 | D3/D14: the command-tree golden, the help lint, `cli.rs` help text, help goldens regenerated | m06_cmd.rs's strings (§6 item 3) |
| 5 | The skeletons: `support bundle`, `state *`, `service stop --preview`, `inspect request` | [ASK-H3] |
| 6 | Standalone types and schemas: D2, D4, D6, D10, D12, D13, D19, D20, H1, H2, H3, H7, Q4, Q7, H6, H5, H10 | [ASK-S0] |
| 7 | D1 typed views and the D9 inventory | 6 |
| 8 | D5 typed payloads, the emission-site inventory test | 6 |
| 9 | H9 migration 0014 and Q9 (store, catalog) | — |
| 10 | The replay corpus (M02, M03, M04/M05; then M06 when its SHA arrives) and the replay test | 8, 9 |
| 11 | `REQUEST_STALE` and H13's types | [ASK-CODE] |
| 12 | ADR-0006 §19 and the handoff doc | all |
| 13 | `1.0.0-rc.1` | [ASK-VERSION] |

`check.sh` gains no step: the new goldens run inside the `contracts` and `heimdall` test targets,
and the replay test is a new `[[test]]` in `crates/store/Cargo.toml` (a shared line U0 adds).

## 5. The replay corpus recipe

**Facts (read at each SHA; nothing run yet):**

| Build | SHA | Store `SCHEMA_VERSION` | Toolchain | Redirects it honours (debug) |
|---|---|---|---|---|
| M02 exit | `e4f43f84` | 5 | 1.99.1 (= HEAD) | `HEIMDALL_TEST_SSH_HOME` only; **no** secret-store redirect, **no** dev-home guard |
| M03 exit (E9) | `2b79aac1` | 6 | 1.99.1 | + `HEIMDALL_TEST_SECRET_STORE`; no dev-home guard |
| M04/M05 exit | `50dbc86b` (contains M05's `85e67bfe`) | 8 | 1.99.1 | + dev-home guard |
| M06 exit | the SHA the contract owner sends (`a10eec63`'s tree today; only `connect_cmd.rs` and `testcfg.rs` differ from HEAD) | 13 | 1.99.1 | + `HEIMDALL_TEST_MGMT_STORE`, `HEIMDALL_TEST_IROH_KEY_STORE` |

The four tables' SQL has not changed since migration 0002; migration files 0001–0008 are
byte-identical at every SHA that has them; HEAD's `Store::open` migrates any older version forward
after its backup (no version floor). What changes is the JSON in the rows (`CallerContext`'s
optional `remote_client`; `PolicyAction`'s optional `policy_id` plus `target`; `DecisionKind` and
`OperationKind` variants). One replay hazard to test explicitly: `idempotency_record` looks rows
up by the re-encoded caller document, so a byte change in that encoding would make old rows
unfindable.

**Builds.** Debug only (a release build refuses every `HEIMDALL_TEST_*`). Each old SHA is exported
with `git archive <sha> | tar -x -C /tmp/u0-replay/src-<m>` (no checkout, no worktree) and built
with `cargo build --locked -p heimdall` under `heavy-gate.sh`, with `CARGO_TARGET_DIR` set to this
worktree's `target/` (the one target directory: registry crates are shared, path crates get their
own hashes); the binary is copied to `/tmp/u0-replay/bin/<m>/heimdall` at once, and the export is
removed when the step ends, pass or fail. HEAD's binary is rebuilt afterwards. No `iroh` feature.

**The journey** (one scratch root per build, every process under `env -i` with `PATH`, scratch
`HOME`, `HEIMDALL_HOME`, `HEIMDALL_TEST_SSH_HOME`, `HEIMDALL_TEST_SECRET_STORE=scratch`,
`HEIMDALL_TEST_MGMT_STORE=fixture-file:<scratch>`, `HEIMDALL_TEST_IROH_KEY_STORE=<scratch>`,
`HEIMDALL_TEST_ADAPTER=prepare`, `HEIMDALL_TEST_LEDGER`, `HEIMDALL_TEST_TIME_SYNC=synchronized`,
`HEIMDALL_TEST_SESSION_LOCK`, `GIT_CONFIG_NOSYSTEM=1`; a build ignores the variables it does not
know; the driver checks all three homes are inside its root before it spawns anything, as
m07-plan rule 4 says), the same commands at every build (the flags are identical at all four;
template `tests/e2e/cli_m01.rs` `every_exit_class_0_to_7_is_observed_through_the_real_binary`):
1. `service run` (test configuration seeds profile `dev`, policy `pol`); wait for `service status`.
2. `access ensure --profile dev --work-id w1 --request-id r1 --pair h1:deploy` → `ACCESS_READY`;
   the same again (replay); the same ID with another work ID (`REQUEST_CONFLICT`).
3. `access ensure … --request-id r2 --pair h3:deploy --non-interactive` → `INTERACTION_REQUIRED`
   with a pending `approve_authority` decision (left pending).
4. r3 then `decision deny` on a pty with a typed `yes` (denied); r4 then `decision approve` (approved).
5. `access pause pol`; `access resume pol` (pending `widen_policy`), then attended (approved);
   `access cutoff pol --at 2099-01-01T00:00:00Z`; `access cutoff pol --clear` (pending).
6. `access release <binding>`; `access revoke <grant> --request-id rv1`.
7. A second home with `HEIMDALL_TEST_SLOW_PREPARE_MS` for `--async` then `operation cancel`; a
   third with `lose_reply` for `OUTCOME_UNKNOWN` and its same-key retry. (A stage-failure home
   was dropped: it only replayed an injected `INTERNAL_ERROR`; the denied approval gives the
   failed operation.)
8. Per build: M03+ `access lock-behavior` and `access connection-policy`, a `session_lock` event
   from the lock file; M04/M05+ `access stop --work`, `access default-profile`, `access allow`;
   M06 a local widening (`route add --iroh … --relay …` on a pty, writes a record, dials nothing).
9. `service stop`; copy `state/state.db` (after the stop, so no WAL is left).

Attended steps use `script(1)` with a typed `yes`, as the old harnesses do. Never run: `setup`,
`doctor`, `run`, `connect`, `uninstall`, a bare `heimdall`, `identity adopt --from-agent`,
`access delegate`, `enroll`, `issuer`, `connections`, `container`, `wsl`, `service autostart`,
`transport`, `environment`.

**Migration and readback.** The corpus keeps each build's store as a SQL text dump
(`tests/contracts/golden/replay/<m>/state.sql`, from Python's `sqlite3` `iterdump`, so it is
reviewable and scannable before a push to the public repository: no home path, user name or
secret; generated IDs and the seeded test profile only), plus a `manifest.json` (build SHA, the
store's `user_version`, the journey's steps with their real exit codes, row counts per table). The
test rebuilds each database from its dump at its recorded `user_version`, then
`stored_samples_replay_through_revision_7_readers` (a new `[[test]]` of `heimdall-store`, source
`tests/contracts/replay.rs`) opens it with
`Store::open` (backup, then every production migration to 14), enumerates the rows by raw SQL and
reads each through the store's readers (`operation`, `idempotency_record` by its re-encoded key,
`decision`, `events_after`, `expired_key_marker`) and then through the revision-7 decoders (D5's
`EventPayload`, the D1 operation view, the decision document types). Every row must decode; the
test also checks row counts are unchanged by the migration.

**Hand-authored rows** (`tests/contracts/golden/replay/hand/*.json`, one document per historical
shape, inserted into a migrated store by the test): `idempotency_markers` (the 24 h floor would
purge the journey's own rows); `credential_lifecycle` `authority_withdrawn` and the issuance and
instance forms; `runtime_lifecycle` `unresolved`; every `resource_changed` form (identity,
projection, supervisor); `enrollment`, `connection`, `route` and `client` events; decision kinds
other than `approve_authority`, `widen_policy` and `confirm_time`; a lapsed `pending` decision with
a past `expires_at` (no build before M06 writes `expired`); and every shape D5's emission
inventory finds that no journey produces.

**As built:** each export is touched after `git archive` (its commit-time mtimes would let cargo
reuse another SHA's artifacts with the same unit hash), and the worktree's sources are touched
before HEAD is rebuilt. Each build's genuineness is recorded in
`tests/contracts/golden/replay/README.md`: the workspace crates of its `heimdall` build graph
equal the crates cargo compiled, and every binary's SHA-256 differs.

**Order:** M02, M03 and M04/M05 now; M06 when the contract owner sends its SHA.

## 6. What looks live rather than preparatory

1. **`REQUEST_STALE` in the code table** **[ASK-CODE]**. It changes `schema show codes`,
   `codes.json` and the `code` schema (31 rows). H2's real-binary smoke
   (`examples/harnesses/goal-loop/tests/test_harness.py:4669`, run by `check.sh`) asserts
   `EXIT_CLASSES == installed_codes`, so the `harness-h2-tests` step fails until H2's frozen copy
   gains the row; the wrapper's `CODE_DEFAULTS` reads an unknown code as exit 1 (safe, not
   failing). Options: (a) U0 adds the row and the contract owner lands H2's one-line table edit
   with it (outside U0's scope; owner M07 U5h); (b) U0 declares the code's row in the reason table
   only, and `Code::RequestStale` joins `Code::all()` in U2b with its emitter and both harnesses.
2. **The version string** **[ASK-VERSION]**. `heimdall_domain::claims::SIGNER_BUILD` is
   `CARGO_PKG_VERSION`, and every `CLAIMS` entry pins `signer_builds` to `0.1.0-m01`
   (`crates/domain/src/claims.rs`; `claims_table.py` requires the bound to equal the workspace
   version at the record's commit). At `1.0.0-rc.1` no entry matches the running build, so every
   claimed field reads `unknown` in every `ensure` answer, `docs/user/adapters.md`'s rows name a
   build that no longer exists, and tests that expect a claimed value from the current build may
   fail. It is also carried in the hello (`PeerInfo.version`). Options: (a) bump in U0 and accept
   `unknown` claims until M08 U8's claim audit re-verifies at the candidate; (b) bump at the
   candidate commit (M08 W3), still "set once"; (c) bump in U0 with a reviewed claims-table update
   (needs new native records; not U0's). Recommended: (b), or (a) if the owner wants the string in
   the hello now.
3. **Help text** (D14). Human help is not frozen, but the lint must pass in `check.sh`. The help
   strings of `environment`, `device`, `route` and `transport` live in `m06_cmd.rs` (outside U0's
   scope). Options: the lint carries an explicit, shrinking allow-list of those paths until U2b;
   or the contract owner grants `m06_cmd.rs`'s doc comments to U0.
4. **Q9's alias check** is new behaviour at write (ruled for U0): `destination add`, a rename,
   `import` and setup adoption refuse a case-variant of an existing alias with
   `CONFIG_CONFLICT`/`alias_collision`. Reading applied: a write that keeps a destination's own
   stored alias byte-for-byte is not refused, so a legacy pair stays editable (relabel) and is
   reported by `doctor` (U1b); **[ASK-Q9]** if a legacy pair should block every write to either.
5. **Migration 0014** raises the store's schema version: an older build refuses the migrated store
   (the existing `NewerSchema` refusal), and the existing pre-migration backup is written. This is
   the normal migration path, but it is one-way for users of earlier builds; H12's adoption fence
   (U2b) must treat version 14 as a flat-layout store it may adopt.
6. **`schema show primitives` and `schema show reasons`** are new names on a live command. Nothing
   reads them yet. Preparatory.
7. **New capability names** (`pages/1`, `request-epoch/1`) declared, not offered: `inspect
   capabilities` and the hello list only offered ones, so no output changes.
8. **New CLI commands** answer refusals, never act. The top-level help gains `support` and `state`.

**Where the plans disagree on U0 or later (for the contract owner):**
9. **H12:** m08-plan U0 lists "the storage layout of H12" as U0's; ADR-0014 H12 says it is built in
   U2b after the handoff; the U0 bound lists only H9. This plan: U2b.
10. **H13:** m08-plan U0 lists "the epoch in the hello and on every mutating request, with the
    stale-request refusal", which the CLI, the TUI, the wrapper and the harnesses follow "in the
    same change": live. This plan: types and constants in U0, the rest U2b/U3.
11. **D14:** m07-plan U2 says "U2b: the help text, in U0's `cli.rs` pass"; the U0 scope includes
    `cli.rs`'s help strings. This plan: U0 rewrites `cli.rs`'s; U2b any remainder.
12. **D15:** m07-plan U0 owns "the proposed spec text"; ADR-0013 D15 says the orchestrator. This
    plan: U0 drafts it in §19, the orchestrator applies it.
13. **D10, D11, D20:** "U0, U3" and "U0 with M06": U0 = types and numbers; attachment U3.
14. **H3:** m08-plan U0 says "the state commands with §3.6's restore rule as an authority rule of
    the contract": U0 records the rule in §19 and lands skeletons; the commands are U2b's.

## 7. Q11–Q14: evidence for the contract owner (M06 exit tree; read in code, nothing run)

Gathered by a read-only investigator and checked at the cited lines where it decides an option.
"Favours" is inference, not a recommendation of a ruling.

### Q11. Replay keyspaces for local widening

- **Paired (live):** `remote::widening::submit_bound` (`crates/remote/src/widening.rs:567`) keys
  `(Submitter::Paired(client), kind, request_id)` (`store/src/ext_m06.rs:953`); another hash is
  `REQUEST_CONFLICT`; otherwise `replay_answer` (`widening.rs:519`) gives ADR-0013 §7's table
  (terminal → result; pending, live → `APPROVAL_REQUIRED` same ref; approved → `OUTCOME_UNKNOWN`;
  else `DECISION_STALE`). Pending replay checks expiry, not the generation.
- **Local (live):** `submit_local` (`widening.rs:676`, from `runtime/src/local_widening.rs:186`,
  for `route add` and `transport enable|adopt-roost`). The request carries a `request_id` that is
  stored but **not a key**. Lookup is `pending_local(kind, local_digest)` (`ext_m06.rs:968`,
  pending rows only); `local_digest` (`widening.rs:621`) hashes the request without its ID, with
  the delta. A lapsed or other-generation pending record is settled `expired`/`stale` and replaced.
  `replay_answer` is never called. Migration 0013's `UNIQUE(client_id, request_kind, request_id)`
  does not constrain local rows (NULL client); one pending row per digest is enforced in code.
- **So the five answers differ:** local terminal, claimed and expired records are never replayed
  (the request is evaluated afresh: a still-widening request gets a new decision, otherwise it
  runs, e.g. `already_present`); no local `REQUEST_CONFLICT`.
- **CLI:** `route add`, `transport enable` and `transport adopt-roost` have **no `--request-id`**
  (`m06_cmd.rs:250`, `:315`, `:331`) and mint one each run (`:612`, `:692`, `:701`); only
  `environment invite` takes one. ADR-0013 §7's "agents always pass `--request-id`" is not true
  for them, and Q5's "every command that takes `--request-id` also takes `--request-epoch`" does
  not reach them.
- **Tests:** `tests/integration/remote_runtime_m06.rs:919` (restart) covers paired pending,
  claimed, terminal and expired; for local, only a **pending** retry; no restart `REQUEST_CONFLICT`.
  Unit `widening.rs:1160` covers local lapse and stale replacement.
- **Ledger (ADR-0014 §3.6 step 4):** the digest is over the request ID, which the CLI re-mints
  per run for local widenings, so a fence for one run can never match a CLI retry; local widenings
  have no operation row, so "a terminal record in the staged generation" is undefined for them.
- **Options:** (A) §7 gains a local key row ratifying what is live (no reader moves), plus the
  `--request-id` wording fix; (B) key local records by `request_id` first with §7's five answers,
  then the digest (needs `--request-id` on three commands, a unique partial index, tests; a
  same-ID retry after a terminal record then returns the recorded result); (C) all five answers
  by digest alone (a later identical widening replays a stale result); (D) scope §7 to paired
  records only. **Favours A**, and D16's "restart-replay coverage" is then complete for paired and
  pending-only for local.

### Q12. D11's per-pair route status

- **What M04 asked:** ADR-0010 §10 (`0010-platform-realization.md:608–610`): a routed pair's
  unsatisfied route *dependency* shows only as a lost `destination_scope`, not as a status with a
  reason; "a per-pair route-status field is deferred to M07-T03". The consumer is the `ensure`
  result (`Enforcement.destination_scope`, `request.rs:189`; reason
  `route_dependency_out_of_scope` from `app/operations.rs:3961`).
- **M07's re-scope:** m07-plan:150 "on M06's route-health semantics"; the handoff names its reader
  as the TUI's route health (U7).
- **Live today:** two untyped keys on each `inspect destinations` item, added by
  `runtime/src/dispatch.rs:216–256` (`add_route_health`) when the runtime serves routes:
  `route_health: {result: RouteHealthPayload, reported_at}` (present only after attempts) and
  `host_pin_defeated: {setting, reported_at}`; the source is `route.record_health`, in memory, per
  binding (8 per binding, 256 bindings), read per destination. A managed destination has one
  account, so one destination is one pair; existing-access destinations get no report. The
  `route` event is published at `dispatch.rs:1008–1027`; no test asserts the emitted event.
  Readers: `tests/e2e/exit_m06/{routes,iroh_alias}.rs` and a dispatch unit test only.
- **Options:** (A) ratify the two keys as D11 and type them in D1's destination view (health, not
  dependency); (B) a per-pair dependency status in `EnsureData` (M04's intent; overlaps D21);
  (C) both; (D) defer B past 1.0, with D21's `route_undetermined` plus A. **Favours A** (one
  named reader); A does not close ADR-0010 §10's gap as worded.

### Q13. RC06: the environments arm and `remote_pending`

- **Declared only:** `EnvironmentView.remote_pending` (`contract/src/environment.rs:265`). The
  `inspect environments` arm (`app/operations.rs:9669` → `container_m04::environments_view`)
  never builds a `RemoteRunner` row, so it never emits `remote_pending`.
- **Live:** `environment status --json` (`app/remote_status.rs:183`, `:263–279`) always emits
  `remote_pending`, read from the **whole** effect outbox (`store/src/ext_effects.rs:603`, no
  LIMIT, filtered in Rust): no cap, count or page. It is a CLI read without a session
  (`m06_cmd.rs:3179–3200`), not an IPC inspect arm. `remote_pending_count` exists nowhere.
- **Ownership on paper:** m06-plan U7 owns only `tests/native/m06/**` and the exit evidence;
  m07-plan U3 defers the arm to "M06's U7"; M07's U7 renders `remote_pending` (`tui/m06.rs`).
- **Readers of the live shape:** the CLI's human renderer (`m06_cmd.rs:3527`, `:3534`);
  `tests/e2e/exit_m06/{a07,t06}.rs`, `environment_runner_m06.rs`, `controller_driver_m06.rs`; the
  TUI has fixtures only; no wrapper or harness.
- **Options:** (A) an M06 follow-up (reopens an exited track); (B) M07 U3 with the other inspect
  arms (a remote row in `inspect environments` is new emission; capping the live `environment
  status` list is a live change moving the CLI renderer, four test files and U7's TUI together);
  (C) M07 U7 (needs a grant into U3's files). Also to rule: whether RC06's "environment view" is
  `inspect environments` only, or `environment status` too. **Favours B**, with U7 as reader.

### Q14. The report shape of A07's runner residual components

- **Declared, attached, never emitted:** `RevocationResiduals` (`contract/src/managed.rs:357`) is
  `EnsureData.residuals` (`request.rs:603–608`; §18.6 item 7) and in `envelope.ensure.schema.json`;
  `grant_ensure_data` sets it `None` (`app/operations.rs:5643`); `attach_runner_readiness` and
  `Runner::readiness` are called only from tests; `runner_residuals` hard-codes closed, closed,
  unknown, not_ended.
- **Live A07 shape:** `environment status --json`, per entry `residuals[]` of `GrantResidual`
  (`app/remote_status.rs:126`, built at `:283–305` from `grant_revoke` outbox rows):
  `{grant, acknowledged, new_authentication?: {latest_possible_credential_expiry?,
  destination_clock_error}, statement}`; the clock is always `unmeasured`; no per-component
  fields; no public schema. `access revoke` of a runner grant answers `RevokeData {local_applied:
  false, remote_pending: [grant], latest_possible_credential_expiry?, …}`.
- **Asserted by:** `exit_m06/a07.rs:100–160` (grant, `acknowledged`, statement naming the
  destination-clock error), `t06.rs`, `environment_runner_m06.rs`, `controller_driver_m06.rs`.
  Reader: the CLI's `remote_lines` (`m06_cmd.rs:3534`).
- **Options:** (A) ratify `GrantResidual` as A07's report, typed under D1, and keep or remove
  `EnsureData.residuals` (removal is a pre-release correction with a schema regeneration);
  (B1) wire `attach_runner_readiness` (the hard-coded component values become live claims needing
  evidence); (B2) add per-component fields to `GrantResidual` (live change: CLI renderer, four
  test files, goldens); (C) keep both and state their relation (they share
  `AuthenticationResidual`). **Favours A or C.**

## 8. Estimate

13 commits (§4), about 6–9k lines, most of it types, schemas and goldens. The D1 views and the
D5 payload inventory are the largest (about a third). The replay corpus needs three old builds
(§5) plus the M06 one.

## 9. Lines outside U0's scope (with owners)

| Change | Owner |
|---|---|
| H2's frozen code table row for `REQUEST_STALE` (`examples/harnesses/goal-loop/harness.py`), if §6 item 1 (a) | M07 U5h |
| `m06_cmd.rs` help strings, for the lint | M06 / U2b |
| The `doctor` finding for existing case-variant catalog aliases (reads the store query) | M08 U1b (with Q10) |
| Attaching each standalone type (S0) | U3, U2b |
