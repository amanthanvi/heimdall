# M07 U0 handoff list

**Status:** prepared 2026-11-22 by the M07 integrator for the contract owner, to be ruled on together
when M06's contract closes. Docs only: nothing here is applied. Sources: ADR-0013 (revision 3) §11 to
§13, ADR-0014 §7 (H1 to H13), `docs/architecture/m07-plan.md`, and what the M07 W3 and W4 real-binary
journeys observed on main `6a087fbb` (macOS and the devbox; Windows where stated).

## 1. What U0 lands, and what waits for U3

U0 lands only what no live path emits yet (ADR-0013 §1.3). Every live shape change is one change per
correction in U3, with its emitters, every in-tree reader and its goldens.

| Delta | In U0 | In U3 or later | M07 readers that move with it |
|---|---|---|---|
| D1 typed views | the types and schemas, unused | the inspect arms (PC2, PC3) | CLI renderers, the TUI's `data.rs`, `m03.rs`, `m05.rs`, the wrapper, H1, H2 |
| D2 `pages/1`, `select`, HMAC tokens | types, the capability name | the server and the client traversal | wrapper (`inspect` with `page`), the TUI worker's paged loading (U6) |
| D3 names | the command-tree golden; M06's names (PC7) | — | the skill (U4b), both harnesses' call tables, `skill_lint.py` |
| D4 whole-or-refuse snapshots | types | PC1 | CLI `--follow` head, the TUI worker, wrapper, H1, H2 |
| D5 typed event payloads | the inventory and the replay corpus | — | wrapper (skips unknown event types today) |
| D6 gap endings | the reasons | PC5, PC6, PC9, PC10 | CLI `--follow` (exit 6), the TUI worker, wrapper, H1 |
| D7 `schema show primitives` | the index and its golden | — | H2's `load_call_set` (a marked seam today), the skill |
| D8 `schema show reasons` | the tables and their golden | — | both harnesses, the wrapper's reader rule for unknown reasons |
| D9 omitted versus `null` | the per-field inventory | PC3 | the TUI readers |
| D10 `uncovered_lock_behavior`, `PolicyView.scope` | types | emitters | the TUI overview and `status` (already worded for both) |
| D11 per-pair route status | with M06 | — | the TUI's route health (U7) |
| D12 verified-hello `service status` | — | U3 | the wrapper's discovery on every platform; **the wrapper's Windows journey is blocked on it** |
| D13 `destination remove` guard | the reason | U3 with U8b | `catalog_cmd`, the TUI's remove path |
| D14 help-text rule and lint | U0 and U2b | — | — |
| D15 to D18 ratifications | the contract owner | — | — |
| D19 `response_too_large` | the reason | PC4 | CLI exit tests, the wrapper |
| D20 write-time item bounds | the bounds | PC11 | CLI refusals |
| D21 `page_token_invalid`, `selector_invalid`, `route_undetermined` | the reasons | U3 | the wrapper, both harnesses |

## 2. M08's deltas that touch M07's consumers (ADR-0014 §7)

| Delta | What changes for a consumer | Where M07 carries it |
|---|---|---|
| **H13, the epoch on requests** | The hello reports `restore_epoch`. Every mutating request carries the epoch its request ID was minted under, bound at mint time and reused on retry. A non-current epoch is refused `REQUEST_STALE` (`restored_before_completion`, `restore_epoch_stale`). | **Wrapper:** it keeps a request ID for replay in its journey driver; keep it as a pair with the session's epoch, sent on the request. **H1 and H2:** they speak the CLI, so the CLI must accept and print the epoch for a kept request ID (a flag or a paired token; see U0-Q5). **TUI and CLI:** any retry path. `REQUEST_STALE` is a new code: exit class, `next.action`, and both harnesses' tables. |
| **H9, the epoch in server-minted references** | Operation, decision and idempotency records carry the epoch. | Readers ignore unknown fields today; the typed views (D1) must name the field. |
| **H7, build provenance** | New fields in the version output and `inspect capabilities`: commit, target, profile, feature set. | Additive. The wrapper and both harnesses read `inspect capabilities` and ignore unknown fields; the typed view (D1) and the adapter page's build check can use them. See U0-Q4. |
| **H8, the version string** | Carried in the hello. | The wrapper's skew test compares against the build under test, not a literal. |
| **H4, H10 reasons; `REQUEST_STALE`** | New reasons under existing codes and one new code. | D8's reason tables; the skill's "any code you do not recognize is a failure" rule already covers an older consumer. |
| **H1, H2, H3 commands** | `support bundle`, `service stop --preview`, `state status|restore|reset`. | D3's command-tree golden and D7's primitive index: none is an agent primitive; the skill lint's allow-list must keep refusing them. |
| H5, H6, H11, H12 | Doctor finding, residue kinds, a cargo feature, the storage layout. | No M07 consumer reads them. H12 moves the state path every M07 test launcher points at through `HEIMDALL_HOME`; no launcher names a path inside it. |

## 3. Questions for U0

Each has what today's build does (observed, with where), and a recommendation.

### U0-Q1. The code for missing access asked for without a person
- **Observed:** a non-interactive `ensure` that needs approval answers `INTERACTION_REQUIRED`, state
  `awaiting_approval`, with a `next.decision_ref` (`e2e_wrapper_m07`, `e2e_harness_m07`, both
  harnesses; macOS and the devbox). The skill and the plan's journeys pair `decision_ref` with
  `APPROVAL_REQUIRED` only.
- **Recommended:** freeze what the build serves: `APPROVAL_REQUIRED` for a session that can attend,
  `INTERACTION_REQUIRED` with the same `decision_ref` for one that cannot. Every reader takes
  `decision_ref` under either code. U4b aligns the skill.

### U0-Q2. A binding adopted through a shared request ID
- **Observed:** a `run` that reuses the request ID of the `ensure` for the same work is accepted (exit
  0, no conflict) and binds the binding `ensure` prepared. With a new request ID it makes a second
  binding on the same grant (ADR-0011 §10 item 12, I-1); the `ensure` binding stays active until
  `access release`.
- **Recommended (the contract owner's):** a binding is reused only by explicit reference, never
  through a shared request ID. That needs a way to name the prepared binding on `run` (today `run`
  takes a profile and a work ID). If none is added, the skill says to release the `ensure` binding,
  or to skip `ensure` when `run` alone is enough (ruled for U4b).

### U0-Q3. Reasons under `CAPABILITY_UNAVAILABLE`
- **Observed:** three different situations answer the same code with nothing typed to tell them
  apart: an `ensure` whose minimum the mechanism cannot meet (`--require-unattended` on existing
  access; effect `none`); an operation whose approval the person **denied** (`operation wait` then
  shows `data.code` `CAPABILITY_UNAVAILABLE`, exit 4); and the route pair D8 already names
  (`route_undetermined`). A harness can only report "not allowed".
- **Recommended:** D8's table gives each a reason token (for example `mechanism_minimum_unmet`,
  `decision_denied`, `route_undetermined`), so a consumer can tell "the person said no" (stop, do
  not ask again) from "ask for less". No new code.
- **Note:** this item was named by the contract owner; the three cases above are what M07's
  journeys saw, and may not be the whole list.

### U0-Q4. The provenance fields (H7)
- **Question:** where the commit, target, profile and feature set appear (`--version`, `inspect
  capabilities`, the hello), under which keys, and whether a debug or test-store build says so in
  a typed field.
- **Recommended:** one `build` object in `inspect capabilities` and in the hello, the same keys in
  both; `profile` and a boolean for test configuration present, so the wrapper and the harnesses
  can record exactly what they ran against in the A32 evidence, and the claims table's
  release-profile rule can be checked from the binary's own answer.

### U0-Q5. How a CLI caller carries the request epoch (H13)
- **Question:** H13 binds the epoch at mint time. A CLI caller that passes `--request-id` and
  retries later has no session to read the epoch from.
- **Recommended:** the CLI prints the epoch with the request ID it used (in the envelope), and
  accepts it back on retry (`--request-epoch`, or one opaque token that holds both). Agents keep
  the pair; the skill says so. Decide before U4b freezes the command forms.

### U0-Q6. The exit class of the new code `REQUEST_STALE`
- **Question:** H13 names the code and its reasons, not its exit class or `next.action`.
- **Recommended:** class 6 (conflict) with `next.action` `new_request_id`, so H2's
  `invalid_retries` definition counts it and no table needs a seventh class.

## 4. Rulings already made that U0 or U4b must carry

- `invalid_retries` counts answers whose `next.action` is `fix_request` or `new_request_id`.
- Every changing request gets its own request ID; the idempotency key is never a continuation
  token.
- After `OUTCOME_UNKNOWN` a consumer never resends; it observes the named operation until it is
  terminal, within its bound, and reports the operation ID if it is still unfinished.
- A consumer releases every binding it was given; a refused release is recorded, the rest are still
  released, and the attempt counts as failed.
- The pipe-name MUSTs for ADR-0013 §8 (a `heimdall-` prefix, a `-control` suffix, a non-empty
  token; no owner-SID option), approved for revision 7.
- Follow-up M07-F1 (a runtime is found only under the spelling of its home) belongs to M08's path
  and authority unit.

## 5. Not covered by any real-binary run today

A live trim gap, a live lag gap, an oversized event, paired-client revocation, `OUTCOME_UNKNOWN`,
`APPROVAL_REQUIRED` and a provider wait in a harness, the M06-exit-build skew run, and the
wrapper's journey on Windows. U3's tests (ADR-0013 §11) and the U5b and U5h remainders close them.
