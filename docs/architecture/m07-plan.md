# M07 plan: finish the everyday experience and public building blocks

**Status:** draft, revision 3 (2026-11-21), from the M07 design unit. ADR-0009 allows no further independent re-check: the orchestrator reviews this revision's diff against revision 2, then commits the design. No production code was written for it.

**Revision 3:**
- **What it applies:** the scoped re-check (Codex, FIX FIRST, M07-RC-R01–R11; `/tmp/hm-tools/m07-design-recheck-out/report.md`), under the orchestrator's simplification rulings S1–S4 and the rulings on RC02 and RC05–RC11.
- **What it removes from revision 2:** the partial snapshot and its rebuild, the oversized-item stub, the use of traversal for internal resolution, and harness H2's dependency on the wrapper.
- **Where to find the changes:** `target/m07-notes/DONE-r3` maps each finding to its change.

**Revision 2:**
- **What it applies:** the independent design review (Codex, FIX FIRST, M07-D-R01–R14; `/tmp/hm-tools/m07-design-review-out/report.md`), and the orchestrator's rulings of 2026-11-21. Those rulings cover Q1–Q12, pre-freeze breaks (ADR-0013 §1.3), the typed limit refusal (`USAGE_ERROR`/`response_too_large`), and a reviewer fix for each nonblocking finding.
- **Where to find the changes:** `target/m07-notes/DONE-r2` maps each finding to its change.

**Design ADR:** ADR-0013 (proposed, revision 2): the G08 freeze, written as a proposed ADR-0006 revision 7 layered on revision 6.1. The contract owner lands revision 7 as **provisional** after M06's contract work settles (§3). It is ratified only after U9's native A19 and A32 runs pass (ADR-0013 §1.2).
**Basis:**
- `main` at `b2bb8507`: `c10810af`, the M01–M05 exits and the accepted M06 design, plus the AGENTS.md static-pass rule;
- M06 wave 1 at `82158dee` on `m06/w1`: revision 6.1, and the W0 rulings in ADR-0006 §18.5.
**Delivery rules:** ADR-0009.

**Inputs:**
- plan §5 M07 (T01–T06 and the exit evidence), §3 G08, §6, §7.2, §8 and §10;
- spec §5, §9.1, §11, §12, §15.1 and §15.4;
- the six requirements M07 owns: R-UX-05, R-UX-07, R-AP-05, R-AP-07, R-AP-08 and R-RT-06. It also supports R-AP-01, R-AP-02, R-AP-04, R-RT-05, R-SS-04, R-UX-03, R-UX-08, R-QU-05 and R-QU-06;
- the items handed to M07 (§1.4).

**Exit evidence:** plan §5 M07 asks for:
- A19, A20, A27, A30 and A32;
- the CLI and the TUI each usable on their own;
- normal preparation in one intent-level request;
- recovery and uncertainty handled through public contracts.

**§6.1 is the controlling exit section.** It states what M07 closes, the one ruled exception, and what G08 ratification requires.

**Declared versions** (new in M07):

| Component | Version |
|---|---|
| Ratatui / crossterm | `=0.30.2` / `=0.29.0` (unchanged workspace pins) |
| Python for the wrapper and harness H2 | 3.9 or later, standard library only. On the Windows PC: the pinned python.org embeddable package (Q2's conditions, §4) |
| PowerShell for the context integration | Windows PowerShell 5.1 and PowerShell 7.x |

## 0a. The orchestrator's rulings (2026-11-21), folded

| Ruling | Where it lands |
|---|---|
| **Q1:** `env` → `environment` (no alias); `roost adopt` → `transport adopt-roost`; `route` and `device` stay; the ProxyCommand leg hidden and frozen. Already sent to M06 for W2 | ADR-0013 §2.3, D3; M06 implements |
| **Q2:** the wrapper in Python 3.9+, standard library, at `examples/reference-wrapper/`, over the control endpoint. The PC download is authorized: a pinned python.org embeddable package, its version and SHA-256 fixed in the harness and verified before use, kept in the run's scratch root, no installer, no PATH or registry change, removed with the root | §4, U5 |
| **Q3:** `service status --json` gains `control_endpoint`; `service run --detach` is the documented start; `instance.json` stays private | ADR-0013 §8, D12; §4 |
| **Q4, with its addition:** exceeding the frame is never `INTERNAL_ERROR` and never an empty list; the TUI shows an error state; one test for each | ADR-0013 §4, §6, D2, D19; U1, U3 |
| **Q5:** at least two minor releases **and** 90 days | ADR-0013 §3.3 |
| **Q6:** `CONFIG_CONFLICT`/`destination_has_live_access`, listing the live access. This closes M05-F1 | ADR-0013 D13; U8b |
| **Q7:** the six primitives only | ADR-0013 §9 |
| **Q8:** the Git residuals re-deferred to M08-T02 | §9 |
| **Q9:** the host-key hint is a post-V1 candidate. No requirement mandates it: spec §9.1 needs an intentional trust flow and treats an unauthenticated observation as a candidate, and A18 names no host key | §9; U8c removed |
| **Q10:** add B14 (one person unfamiliar with Heimdall); A30's session runs inside M09-T01's normal-week study | §6.1 (the only statement of A30's exit status), §11 |
| **Q11:** remove `boundary_seq` only if no published schema requires it and nothing documented depends on it. Checked: true | ADR-0013 §5.5 |
| **Q12:** the orchestrator applies the spec §11.6 list and the §11.1 names at U0, when ADR-0013 is accepted | ADR-0013 D15 |
| **Pre-freeze breaks:** allowed in major `"1"`, each listed with its consumers migrated; persisted rows keep replaying, tested on stored samples; responses describe their completeness | ADR-0013 §1.3, §12; U0's replay corpus |
| **The typed refusal:** `USAGE_ERROR` (exit 2), reason `response_too_large`, next `narrow_request` | ADR-0013 D19 |
| **U8a:** its branch carries the two `cli.rs` lines and the match arm together; the orchestrator approves them at merge | U8a |
| **Shared manifests and `check.sh` steps:** merged by the integrator who owns them | rule 7 |
| **S1 (revision 3):** no partial snapshots: whole or refused per section cap; every gap ends the stream with `RESYNC_REQUIRED`; the checkpoint rule; `Subscribed.backlog` only as an exact count of visible, filtered event frames | ADR-0013 §5.3–5.5; U3, U5 |
| **S2:** no stubs: item size bounded at write time at every ingress, import included; a legacy over-limit item refused by ID from a page and from a point `inspect`; pages carry `more` and the token apart from content, which is always complete; the empty terminal page defined | ADR-0013 §6.1, §6.4; U3 |
| **S3:** internal resolution by point lookups only, never traversal; an absent, malformed or unavailable required route fact is `route_undetermined`, never a fallback; M06's same-grant check stays on each jump; a failed-lookup test beside the deleted-hop test | ADR-0013 §6.3; U3 |
| **S4:** H2 stays, implementing its own calls over `heimdall --json`, independent of the wrapper, with an explicit goal and typed state; the native operation-level capability-refusal fixture | §5a; U5h |
| **RC02:** one revocation ending (the terminal `client.revoked` event, exit 6); an error-only first line when a subscribe fails; tests for a disconnect at the head, an early stop, and a gap followed by a later event | ADR-0013 §4, §5.2, §5.4; U3 |
| **RC05:** `pages/1` on every read role, with subject authorization unchanged; HMAC page tokens under a runtime-local key; `page` with `select` refused; an empty selector refused | ADR-0013 §6.1–6.2; U3 |
| **RC06:** `remote_pending` projected as a count, the first N and an inspect path, with no durable effect refused, dropped or acknowledged because of a cap; byte bounds at every ingress; store reads bounded before rows are materialized; M06's U7 owns the environments arm | ADR-0013 §6.4; U3, M06 |
| **RC07:** preflight where possible; an overflow after dispatch keeps its truthful `effect_status` and the operation reference | ADR-0013 §4, D19; U3 |
| **RC08:** adopt M06 W1's replay semantics (an expired pending record → `DECISION_STALE`; approved without a result → `OUTCOME_UNKNOWN`); no replacement transaction; ratification needs M06's restart-replay coverage | ADR-0013 §7, D16 |
| **RC09:** each live wire-shape change is one change with its emitters, every in-tree reader and its goldens; W1 is preparatory; the replay corpus holds real prior-version rows or migrated fixture stores | ADR-0013 §1.3, §12; U0, U3, §3 |
| **RC10:** G08 ratification requires every A19 and A32 native row, except rows blocked solely on B2, B3 or B8 (and the deferred LLM metrics); A30's exit status is stated once, in §6.1 | §6.1 |
| **RC11:** the reviewer's fix: the expected environment is an input with an explicit endpoint; every `service status` field comes from, or is checked against, the verified connection; the restart test checks them all; the Unix predicates match `ipc::unix` | ADR-0013 §8, D12; §4 |

## 0. Rules

1. **One contract owner.** The integrator holds ADR-0006 and lands revision 7 (ADR-0013 §11) only after the §3 trigger, as provisional. Until then no M07 unit edits:
   - `crates/contract/**`, `schemas/**` or `tests/contracts/**`;
   - the CLI subcommand table in `cli.rs`;
   - `runtime/src/dispatch.rs` or `ipc/src/session.rs`;
   - the dispatch arms of `app/src/operations.rs`, or `app/src/events.rs`;
   - the store.

   A unit that finds it needs a contract change records it as an ADR-0013 delta and stops.
2. **Parallel-safe now** means both of these hold:
   - **The write set is outside M06's.** That means m06-plan §1, plus what `82158dee` changed: the app's events, operations, routes and `stop_m05`; the contract's event, remote, request and route modules; `domain::{binding, catalog, principal, routes}`; `enroll`, `registry` and `sshconf`; `ipc::session`; `runtime::dispatch`; `heimdall::uninstall_cmd` and the `heimdall` crate's `Cargo.toml`; the store; `transport-iroh`; `remote`; and `check.sh`.
   - **The unit uses only current requests, fields and actions.** Nothing from revision 6 or 7.

   Everything else is **after M06 contract**.
3. **Fixtures only.** Per-run keys, the loopback fixture sshd, disposable agents, and the AGENTS.md option set on every fixture `ssh`. No owner keys, agents, keychains or real repositories.
4. **One harness-owned scratch launch environment** (R14; AGENTS.md at `b2bb8507`):
   - **What it contains:** every debug `heimdall` child a harness starts (setup, each `service status`, the detached runtime, the TUI, `doctor`, the CLI calls of H1) gets the same launch environment. That is scratch `HOME`, scratch `HEIMDALL_HOME`, and scratch `HEIMDALL_TEST_SSH_HOME` with its `etc-ssh`, plus only the test variables the case names.
   - **The check:** the harness verifies all three point inside its own scratch root **before** it spawns anything. A missing or foreign one is a harness failure, and nothing is launched.
   - **Release builds** have no redirect, so their TUI, `doctor`, `setup` and runtime run only in a disposable account, container or VM.
5. **Gates and native runs** (ADR-0009 §2.2–§2.4):
   - focused crate tests while iterating;
   - `check.sh`, `linux-xcheck --workspace` and the umask-002 targets once per commit to a branch;
   - Windows and the devbox once per merge candidate;
   - one combined exit suite at the end.
6. **No blanket reruns.** M01's A19 groups, M02's and M04's A27 groups and the M02/M03/M05 TUI tests are reused by reference. The existing 17th-request, resubscribe and oversized-event tests already cover their Rust boundaries; the wrapper adds evidence only for client behaviour it exercises independently.
7. **Shared files:** root and per-crate `[[test]]` lists, crate manifests and `check.sh` steps. A W0 unit does not edit them: it hands its lines to the integrator who owns them. That is M06's integrator while M06 owns them, then M07's.
8. **Statuses.** Every unit stays `implemented_unverified` until U9's records exist.

## 1. Gap audit

### 1.1 Headline

- **The terminal mechanics of A20 already exist:** restoration after panic, signal, hang-up, the ssh handoff, Ctrl-Z and the Windows console; 40×12 and 120×40 snapshots; `NO_COLOR` markers; tiny sizes; resize. Missing are four of spec §12.1's seven views, an overview that answers spec §5.1's four questions, the selected environment and active work on the overview, and provenance and freshness in the new detail panels.
- **The isolated probes (§8) found three problems** (debug build):
  - **Per-key work grows with the catalog.** Key-to-first-byte P95 was 15–19 ms at 100 destinations, 84 ms at 1000, 306 ms at 3000 and 402 ms at 3500. The first byte can come from an unrelated redraw (R11), so A20 measures completed frames (U1).
  - **A failed listing reads as an empty catalog.** Past about 7,000 destinations the listing exceeds the frame, the CLI exits 1 with `INTERNAL_ERROR`, and the TUI shows "No catalog destinations."
  - **The overview lists diagnostics by raw code, one row per destination,** under a correct "Ready".
- **T03 is the largest gap.**
  - 11 of the 16 `inspect` subjects have no published schema, 9 of them untyped `json!`.
  - Nothing outside the event log is paginated.
  - **About 50 in-tree callers read whole lists and decide from them** (§1.2 T03; R02). One of them, `connect_cmd::route_of`, silently treats a hop missing from its listing as "no route".
  - The subscription snapshot and the event page are bounded by count only, not bytes, and the snapshot's operations and decisions sections are unbounded.
  - A retention gap is reported as `subscriber_lagged`.
- **T04 and T05 have not started.** The control endpoint's Windows name is advertised only in the private `instance.json`.

### 1.2 Tasks

| Task | Exists now | Missing → unit |
|---|---|---|
| **T01** TUI IA, keyboard, narrow and no-color, restoration | `crates/heimdall/src/tui/`: tabs Overview, Destinations, Profiles and Activity (`tui/model.rs:46`); `w`, `h`, `s`, `?`; the typed-`yes` decision modal. Restoration: `e2e_tui_m02::pty::{panic_restores_terminal, connect_handoff_restores_terminal_after_exit_and_after_child_signal, tui_handoff_ctrl_z_stops_and_fg_resumes_as_one_job, hangup_watchdog_exits, no_cursor_position_query_emitted}`, `e2e_tui_m03::pty::tui_restores_terminal_after_enroll_decision`, Windows `e2e_tui_m03::windows_console::windows_tui_restores_the_console_after_quitting`. Sizes: 47 snapshot files (`tui/snapshots/`); 9×3 to 40×8 in `view.rs`; "terminal too small" below 10×3 (`tui/view.rs:138`). Color: `no_color_carries_no_color_and_every_state_has_a_text_marker`. Latency: `first_frame_latency_measured_and_recorded` (debug, not gated). **No A20 record** | The environments, identities, projects and settings views. The overview's four questions, with the selected environment and active work. Provenance and freshness in the new detail panels. Grouped findings. Per-key work independent of the catalog. An error state instead of an empty list. Search recomputed when the query changes, not per frame. Relative times that do not repaint every poll. Keyboard-completeness and TUI-equals-CLI request checks. A TUI access-and-stop journey. Completed-frame latency under load (U1; staged page loading is U6) |
| **T02** Ordinary-user wording | The verbatim first-trust text and the four-action stop menu (`tui/m05.rs`); wording never retyped (`tui/m03.rs`); `output::sanitize_for_terminal`; ruling I-21 | Help with milestone and ADR references (`cli-help/top-level.txt`; `--non-interactive`'s "(spec §11.3)") (U2b, with U0). A vocabulary rule for the default surfaces. The `DECISION_STALE` retry path (ADR-0006 §13.6 item 2). The enrollment-then-projection sequence (m03-plan §8). Human-only lost-device guidance (ADR-0008 D4 item 5). A CLI access-and-stop journey (U2a) |
| **T03** Stable JSON, NDJSON, cursors, snapshots, pagination, limits, codes, exits | The envelope, code and exit tables (ADR-0006 §3, §5, §6); events, cursors, snapshots and backpressure (§8); `--follow` NDJSON (`cli.rs:2440`–2495, exit 6 after a terminal resync); run records; A19 verified at M01 (`m01-a19-operations.json`); `e2e_cli_m01::{every_exit_class_0_to_7_is_observed_through_the_real_binary, operation_events_follow_resumes_from_cursor}` | Typed views (D1). **The migration of the whole-list callers** (`catalog_cmd`, `connect_cmd`, `enroll_cmd`, `launch_flow`, `setup_cmd`, `m03_cmd`, `m05_cmd`, `container_cmd`, `wsl_cmd`, `connections_cmd`, `issuer_cmd/session`, `uninstall_cmd`, `cli.rs`, `tui/worker.rs`): internal resolution to point lookups only, enumeration to the shared traversal (D2). `route_undetermined` for an absent, malformed or unreadable hop (D21). Whole-or-refuse snapshots and byte-bounded pages (D4; ADR §5.5–5.6). Every gap ending the stream, `history_trimmed`, an exact `backlog` and `resync_reason` (D6). Write-time item bounds (D20). Typed event payloads with replay (D5). `response_too_large` (D19). The schema-to-emitter checklist (U3) |
| **T04** Installed help and schema discovery, the skill, the primitive set | `schema export`, `schema show <name>`, `schema show codes`; `inspect capabilities` (`app/operations.rs:9505`); 24 help goldens | The primitive index with six groups and roles (D7); the error-reason table (D8); the command-tree golden (D3); the skill (U4) |
| **T05** Independent wrapper; version skew | Only Rust clients; `docs/contracts/primitives-draft.md`; the IPC schemas. ADR-0006 §11 sends third parties to `heimdall-contract` | The protocol document with the client's checks in both directions (ADR-0013 §8). Verified-hello discovery (D12). The wrapper, the two harnesses, the skew runs (U5, U5h) |
| **T06** Duplicate frontend logic, notifications, unexplained waiting, adapter capabilities | The TUI is a client and authorizes nothing; the stop menu sends the CLI's requests; decision modals open only on the user's action (`tui/model.rs:1017`: no storm; audited); `matrix.md`; `CLAIMS` and `RESIDUALS` | The TUI's own tolerant view copies (`tui/data.rs`, `m03.rs`, `m05.rs`) replaced by typed views, with staged page loading (U6). Human-mode waits that print nothing (U6). A user-facing adapter page from the claims table (U6) |

### 1.3 Exit cases

| Case | Exists now | Missing |
|---|---|---|
| **A19** | `m01-a19-operations.json` (`verified` at `b89743ae`, 11 groups) | A run on the provisional revision 7; byte-bounded lists, snapshots and pages; distinct resync reasons; the schema-to-emitter checklist; independent non-Rust callers |
| **A20** | The T01 tests; no record | T01's gaps |
| **A27** | `m02-a27-child-integrity.json` (blocked only on B5); `m04-a27-byte-integrity.json` (`verified`); M03 U13's ConPTY rows | The rendered route helper as a ProxyCommand subprocess with stock `ssh`, `scp`, `sftp` and `git` consumers (M06 W1 covers the helper core and Iroh echo, not this); PowerShell hook startup; a run at the exit build |
| **A30** | Nothing executed. M02's and M03's walkthrough rows are blocked on B7 | The deterministic surface checks (U2a). The participant session: §6.1 |
| **A32** | The CLI JSON surface; `m05-g05-agent-context.json` | The wrapper, two independent harnesses with metrics, the primitive index and the skill |

### 1.4 Carried into M07

| Item | Source | Disposition |
|---|---|---|
| Final TUI information architecture | m02-plan §8, m02-exit §7 | U1 (W0 scope), U6, U7 |
| PowerShell context integration | m05-plan Q6 | U8a |
| Exported host-key hint at first connect | ADR-0011 I-12; ADR-0006 §17.9 item 20 | **Post-V1 candidate (Q9).** No requirement mandates it |
| `EnsureData.uncovered_lock_behavior`, `PolicyView.scope` | ADR-0011 I-7, I-14 | D10 |
| A per-pair route status | ADR-0010 §10; m04-exit-draft | D11, on M06's route-health semantics |
| `history_trimmed` | ADR-0006 §13.9 item 6 | D6 |
| `remote_pending_reasons` | ADR-0006 §13.16 item 1 | D17 (kept distinct from revision 6's `remote_pending`) |
| The `DECISION_STALE` experience | ADR-0006 §13.6 item 2 | U2a |
| The guided lost-device flow | ADR-0008 D4 item 5; m03-plan §8 | U2a, human-only in W0; any new `next` field is a later delta |
| One sequence for enrollment and projection | ADR-0008 §16; m03-plan §8 | U2a: two records, two confirmations |
| The three Git residuals | ADR-0007 §12.41; ADR-0008 §18 | M08-T02 (Q8) |
| M05-F1 | `progress.md`; m05-exit §5 | U8b (Q6; closes it) |
| Machine-local remapping of manifest references | m05-plan §7 | Deferred (§9) |

## 2. Units

Each unit lists its marking, owner role, owned paths, dependencies, what it builds, its tests and its native runs. Models follow ADR-0009 §2.6.

### U0: Revision 7's preparatory part, provisional (the integrator, as contract owner) — after M06 contract

- **Owns:**
  - `crates/contract/**`, `schemas/**`, `tests/contracts/**`;
  - ADR-0006 §19 (revision 7, provisional);
  - the CLI subcommand table and help strings in `cli.rs`;
  - the reason tables;
  - the replay corpus (`tests/contracts/golden/replay/`);
  - the proposed spec text.
- **Depends:** the §3 trigger; the rulings above.
- **Builds, in W1, only what no live path emits yet** (ADR-0013 §1.3):
  - the types and schemas of D1–D21 as unused additions;
  - reason constants;
  - the command-tree golden, the help lint and the replay corpus.

  **Every live shape change of ADR-0013 §12 lands later, in W2,** as one change per correction owned by U3, with its emitters, every in-tree reader and its goldens.
- **The replay corpus:**
  - scratch stores written by the **M02, M03, M04/M05 and M06 exit builds**, each running a short fixed journey, then migrated forward through the production migrations;
  - hand-authored rows for every historical shape in the emission inventory that no journey produces;
  - stored event, operation, idempotency and decision rows.

  It is read back through the revision-7 readers.
- **Tests:**
  - the regenerated schema goldens;
  - the command-tree golden and the help lint (no `M0n`, `ADR-` or `§`);
  - the primitive-index and reason-table goldens;
  - **`event_payload_schema_covers_every_emission_site`:** an inventory over the emission sites;
  - **`stored_samples_replay_through_revision_7_readers`;**
  - `schema_export::checked_in_public_api_matches_the_model_exactly`, extended.
- **Native:** Windows and the devbox at the merge candidate.

### U1: TUI information architecture and responsiveness (T01) — parallel-safe now (W0 scope)

- **Owner:** the TUI implementer (fast model), reviewed by the integrator.
- **Owns:**
  - `crates/heimdall/src/tui/**`, **except the shared decision-modal dispatch**, which stays as it is so M06 can add `tui/m06.rs` with one line;
  - snapshots `tui/snapshots/m07_*`;
  - `tests/e2e/tui_m07.rs`, whose `[[test]]` line goes to the integrator.
- **Depends:** current requests, fields and actions only.
- **Builds:**
  - **Views, with what current views carry:**
    - Overview, Destinations, Identities (`inspect identities`), Projects (the workspace and policy screens; `w` and `h` keep working), Environments (`inspect environments` as published today, rendering only today's fields), Activity and Settings, plus Profiles;
    - **Settings** shows what current views carry (lock behaviour and connection policy per policy, the default profile, the saved window), and changes them only through existing requests;
    - **M06's fields and decision kinds render in U7;**
    - narrow screens show `n/8 Name`.
  - **The overview:** what is available; **the selected environment and its active work**; what needs attention (actionable problems only, grouped by finding with a count, in plain words, linked to the destination detail); how to pause or stop (`s`, in the header).
  - **Detail panels of the new views** show each value's provenance and freshness, as the destination detail does today.
  - **Per-key work independent of the catalog:**
    - derived lists are computed once per worker update, never per key or frame;
    - a map from destination ID to alias replaces `finding_alias`'s linear search (`tui/model.rs:865`);
    - `health()` reads the cached items;
    - search filters are recomputed only when the query changes;
    - list views render only the visible window.
  - **An explicit error state:** a failed listing shows its code, message and the last good data marked stale, never "No catalog destinations." Paged loading off the input thread is U6's, after U3.
  - **Relative times** change at minute granularity; a poll that changes nothing draws nothing.
- **Tests:**
  - **Snapshots** of the new views at 120×40 and 40×12. The existing `no_color_…_text_marker` loop is extended to them, and restoration checks are extended only for changed paths.
  - `every_footer_and_help_key_is_bound` (unit).
  - `tui_actions_send_the_cli_requests` (unit), extending the `StopAction::request` precedent to every action.
  - `overview_groups_findings_and_keeps_rows_distinct` (unit).
  - **`listing_failure_is_shown_not_empty`** (unit; Q4's test for the TUI).
  - **`tui_standalone_access_and_stop`** (pty; the M02 TUI world with a fixture alias, the loopback sshd and a disposable agent). It opens a destination, connects through the handoff, returns, and stops the work from the stop menu, with no CLI in between and the terminal restored.
  - **`a20_keyboard_walkthrough`** (pty; debug build; a slow fixture operation through `HEIMDALL_TEST_SLOW_PREPARE_MS`). It covers every view, search, a detail and back, the stop menu, an operation cancelled with `x`, `?` and quit. It resizes 120×40 → 40×12 → 120×40 and, **at each size, asserts the selected row is still selected and visible, the footer's key hints are readable, and the search results are shown.**
  - **`a20_key_latency`** (pty; debug build; **5000 loaded rows and a live slow operation**). For each of Tab, PageDown and a search keystroke, it times **the completed frame that shows that key's effect** (read from the frame dump), not the first byte. A sample that times out at 2 s is counted as 2 s and listed. It reports P50, P95, the sample count (≥ 40 per key) and the host. The A20 bar is §6.
  - **The Windows walkthrough** through `heimdall_testkit::console::TerminalCommand`: views, a resize, a key after the resize answered within the bar, and quit, with the console mode restored.
- **Native:** macOS and the devbox (pty), Windows (ConPTY), at the merge candidate.

### U2: Ordinary-user wording and the CLI journey (T02) — U2a parallel-safe now; U2b after M06 contract

- **Owner:** the TUI implementer (fast model). The wording is reviewed against spec §5.1 and §12.3.
- **U2a owns:**
  - human-mode strings in `output.rs` and in the M02–M05 command modules (not `uninstall_cmd.rs` or `m06_cmd.rs`);
  - `enroll_cmd.rs` and `issuer_cmd.rs` for the guided sequences;
  - `tests/e2e/cli_m07.rs`, whose `[[test]]` line goes to the integrator.
  The TUI's strings land in U1's files, by the same implementer.
- **U2b:** the help text, in U0's `cli.rs` pass.
- **Builds:**
  - **The vocabulary rule (spec §5.1)** for the default surfaces: `status`, the overview, first trust, the stop menu and the doctor summary.
  - **`DECISION_STALE` on the attended path:** the CLI and the TUI retry the original request with the **same request ID**, which yields a fresh `decision_ref` with its delta recomputed. They show the fresh delta and **reset the typed confirmation** (an earlier `yes` never carries over). The machine code `DECISION_STALE` is unchanged.
  - **Enrollment, then projection:** after the enrollment's confirmation, the projection decision follows as **a second confirmation**, with its own scope shown and its own typed `yes`. These stay two records.
  - **Lost device, human-only in W0:** the human output of `issuer status` and `enroll status` explains the restore and foreign-removal steps in plain words. New `next` fields, if any, are a later delta.
- **Tests:**
  - `default_surfaces_use_everyday_vocabulary`;
  - `decision_stale_retries_with_the_same_key_and_resets_the_confirmation` (TUI unit, plus one CLI pty case);
  - `enroll_then_projection_needs_two_confirmations` (CLI pty, M03's fixtures);
  - `a30_surfaces_answer_the_three_questions`;
  - **`cli_standalone_access_and_stop`**: the M02 CLI fixtures (scratch setup, an observed destination with an adopted identity, the loopback sshd and a disposable agent). It runs `heimdall run` through to a fixture login, then `heimdall access stop --work <work_id>`, then a refused retry, with no TUI involved.
- **Native:** at the merge candidate.

### U3: Machine contract, server and client (T03) — after M06 contract

- **Owner:** the API implementer (strongest model).
- **Owns:**
  - new `crates/app/src/views_m07/*.rs` and `crates/store/src/ext_m07.rs` (bounded keyset and length-summed reads);
  - the `inspect` arms of `app/operations.rs`, each reduced to one call;
  - the snapshot, page and gap code in `app/events.rs` and `ipc/session.rs`;
  - **the point lookups and the enumeration traversal in `heimdall::client`, and the migration of every whole-list caller** (§1.2 T03);
  - `service status`;
  - **for each correction it lands, the readers of that shape in the CLI, the TUI (U1's files), the wrapper, the harnesses and the skill,** in the same change (rule 1 of ADR-0013 §1.3).
- **Depends:** U0. The environments arm, and its `remote_pending` inspect path, are M06's U7's (RC06).
- **Builds, in this order:**
  1. **Point lookups for every internal resolution** (S3): routes, hops, aliases, profiles, identities and projections, in `connect`, `ManagedConnect`, `run`, enrollment, the catalog commands and setup. **Traversal is used only for enumeration:** list output and TUI lists.
  2. **Fail-closed route facts:** `route_undetermined` for an absent, malformed or unreadable route dependency. M06's same-grant check stays on every selected or attempted jump.
  3. **Write-time item bounds at every ingress, import included,** with legacy rows readable by ID (D20, PC11).
  4. **Then the corrections and additions,** one change each:
     - typed views (PC2, PC3);
     - `pages/1` with HMAC tokens (D2);
     - whole-or-refuse snapshots (PC1);
     - gap endings and exact `backlog` (D6, PC6, PC9, PC10);
     - byte-bounded and singleton pages (PC5);
     - `response_too_large` with truthful effects (PC4);
     - verified-hello status (D12), **with a three-state read** (ADR-0014 §7 H14, from M08's installer review; lands with M08 W0): nothing advertised (`runtime_not_running`), advertised and verified, and advertised but not connectable (`runtime_unreachable`, a new reason). Today `service status` answers "no runtime is running" for both the first and the third, so an installer or a wrapper cannot tell them apart.
  5. **D13's transactional guard,** with U8b.
- **Tests:**
  - **Lists and pages:**
    - the pagination proptest (fixed seed, concurrent inserts and deletes; a stable item is never repeated or skipped);
    - **`last_row_reachable_with_the_right_count`** (20,000 destinations seeded through the testkit store), ending at an empty terminal page;
    - **`limited_roles_page_their_visible_subjects`** (requester and viewer sessions);
    - **`page_token_tampered_or_rescoped_is_refused`** (a flipped byte; another sort, reader or environment; `page_token_invalid`);
    - **`select_with_page_and_empty_selector_are_refused`** (`selector_invalid`).
  - **Resolution:**
    - **`managed_hop_on_a_later_page_than_its_destination`**;
    - **`deleted_hop_fails_closed`** and **`failed_hop_lookup_fails_closed`**: both `route_undetermined`, through the CLI and the route helper; the same-grant check still enforced;
    - **`no_internal_resolution_traverses`**: a source check that every resolution call uses `select`.
  - **Bounds and refusals:**
    - **`maximal_record_fits_a_page`**;
    - **`legacy_over_limit_row_refused_by_id_from_page_and_point_inspect`**;
    - **`over_limit_import_is_refused`**;
    - **`over_budget_whole_list_is_response_too_large`** and **`cli_exits_2_not_1`** (Q4's list test);
    - **`overflowing_reply_after_dispatch_keeps_its_effect`**: a settled mutation reports `applied` with its operation reference; an uncertain one reports `unknown`.
  - **Snapshots and streams:**
    - **`snapshot_over_a_cap_refuses_naming_section_and_filter`** (subscribe and cursorless `observe events`);
    - **`filtered_and_paired_subscriptions_deliver_every_snapshot_items_next_change`**;
    - **`subscribe_refused_prints_one_error_line`**;
    - **`disconnect_at_the_head`**, **`early_stop_resumes_from_last_applied`**, and **`gap_then_later_event_is_never_applied_and_resume_delivers_it`**, all reusing `integration_ipc_unix`'s head and backlog fixture;
    - **`backlog_count_is_exact_under_filter_and_visibility`**;
    - **`event_page_singleton_and_undeliverable_event`**;
    - **`lag_and_trim_are_distinct_on_the_wire`**: the existing retention paths, with the expectation changed;
    - **`client_revoked_is_the_one_revocation_ending`**: CLI exit 6.
  - **Status:** **`status_fields_come_from_the_verified_connection`**: a restart between the read and the hello checks `control_endpoint`, `environment_id`, `pid` and version.
  - **The schema-to-emitter checklist** (`tests/contracts/emitters.md` plus one test per row), covering:
    - success, pending and error documents;
    - both follow heads, and the error-only first line;
    - event lines;
    - terminal behaviour: exit 0, exit 6 after a gap or a revocation, exit 5 after a disconnect.
- **Native:** Windows and the devbox at the merge candidate.

### U4: Discovery and the skill (T04) — U4a parallel-safe now; U4b after M06 contract

- **Owner:** the integrator writes the skill text (strongest model). The lint is a fast-model task.
- **Owns:**
  - `skills/heimdall/SKILL.md` and `tools/validation/skill_lint.py`. The `check.sh` line goes to the integrator.
- **Builds:** §5.
  - **U4a:** the draft and the lint, on today's names.
  - **U4b:** the final text, on the frozen names and the primitive index.
- **Tests:** the lint and its self-check against a known-bad fixture.

### U5: The reference wrapper (T05) — U5a parallel-safe now; U5b after U3 and U4b

- **Owner:** the wrapper implementer (fast model). The integrator reviews the endpoint and peer checks.
- **Owns:**
  - `examples/reference-wrapper/**`;
  - `docs/api/local-protocol.md`;
  - `tests/e2e/wrapper_m07.rs`: the Rust harness that sets up fixtures and runs the wrapper. The wrapper imports nothing from Rust.
- **Builds:** §4.
  - **U5a:** the protocol layer; the Unix transport with the endpoint and peer checks; an explicit endpoint argument; the fake-server unit tests; the protocol document draft.
  - **U5b, gated on U3 and U4b:** verified-hello discovery; the Windows transport; the journeys; the skew runs.
- **Native:** macOS, the devbox and Windows.

### U5h: The two independent harnesses (A32) — after U3 and U4b

- **Owner:** a different implementer from U5's, so the harnesses are written independently of the wrapper (fast model).
- **Owns:** `examples/harnesses/cli/` (H1), `examples/harnesses/goal-loop/` (H2), and `tests/e2e/harness_m07.rs`, which runs both under the rule 4 environment. Neither imports the wrapper.
- **Builds:** §5a.
- **Native:** macOS, the devbox and Windows.

### U6: Frontend consolidation (T06) — after U3

- **Owner:** the TUI implementer (fast model).
- **Owns:**
  - the TUI's models (`tui/data.rs`, `m03.rs`, `m05.rs`) and `tui/worker.rs`'s loading;
  - the CLI's synchronous wait paths;
  - `docs/user/adapters.md`, with its check script.
- **Builds:**
  - **Typed views in the TUI.**
  - **Paged loading in the worker, off the input thread,** for enumeration only. A list shows "loading" until a page with `more: false` arrives. A later page that fails keeps the loaded part, marked stale or unavailable with the error, and never shows it as the whole list.
  - **Typed views for the shapes no correction changed.** Each changed shape's TUI reader moved in U3's change.
  - **Explained waits:** a human-mode synchronous wait longer than 1 s prints one stderr line naming what it waits for and the operation ID, and saying that Ctrl-C stops waiting but not the request.
  - **The adapter page,** derived from `CLAIMS`, `RESIDUALS` and the matrix labels.
- **Tests:**
  - `tui_later_page_failure_shows_stale_not_whole`;
  - `cli_sync_wait_explains_itself`;
  - `adapter_page_claims_within_the_claims_table`;
  - the existing snapshots guard the typed refactor.
- **Native:** at the merge candidate.

### U7: M06 consolidation — after the M06 exit candidate

- **Owner:** the integrator.
- **Owns:** `tui/m06.rs` (or M06's equivalent), the M06 command wording, and the A27 helper rows.
- **Builds:**
  - **The TUI's rendering of M06's decision kinds,** environment fields (connectivity, last seen, `remote_pending`) and route health.
  - **Plain-word help for M06's commands.**
  - **`a27_rendered_route_helper_with_stock_consumers`:** raw binary over `scp` and `sftp`, a `git` clone and fetch, and an interactive `ssh` with resize and Ctrl-C. All of it runs through the **rendered** ProxyCommand helper subprocess, on the direct and jump legs, and on the Iroh leg where M06 qualifies it. These are helper and console integration rows, distinct from M06's protocol-level byte tests, which they do not duplicate.
- **Also in U7, once M06 no longer needs the shared decision-modal dispatch frozen** (ruled 2026-11-21, from W1's audit): the decision, authorization and repair modals accept a confirmation only when the latest frame drew it and every row has been shown, not only the last row. This is the rule Settings and the stop menu already follow (`model::Seen`).
- **Native:** macOS, the devbox, and Windows where M06 qualifies the path.

### U8: Carried items

- **U8a, the PowerShell context integration (parallel-safe now).**
  - **Owner and owned paths:** a Windows implementer (fast model) owns `activate_cmd.rs`'s PowerShell script and `tests/e2e/m07_powershell_hook.rs`.
  - **The branch carries, together:**
    - the `ShellCommand::Init` doc line in `cli.rs` (`/// Print the shell integration script for \`zsh\`, \`bash\` or \`powershell\`.`);
    - the `ShellArg` variant (`/// PowerShell (Windows PowerShell 5.1 and PowerShell 7).` then `Powershell,`);
    - the match arm in `activate_cmd.rs` (`ShellArg::Powershell => ("powershell", POWERSHELL_SCRIPT)`).

    The orchestrator approves the `cli.rs` lines at merge.
  - **What it builds:** a hook that mirrors M05's. It sends no `Attend`, never prompts or decides, keeps a 1 s budget and fails silently. It warms the personal default, which closes I-13 on native Windows.
  - **Tests:** the activation and warming journey on PowerShell 5.1 and 7; **startup cases** (a profile that loads the hook with no runtime, with an unreachable runtime, and inside a non-interactive host); and an A27 check that the hook writes nothing to the shell's stdout.
  - **Native:** Windows.
- **U8b, M05-F1 (after M06 contract).** D13: the check runs inside the removal transaction, with bounded, scoped remediation.
  - **Tests:** `destination_remove_with_live_access_refuses_and_lists_them`, and `a_grant_created_after_a_preflight_is_still_refused`. The second runs the check inside the transaction, so a grant created after a preflight read cannot slip through.
- **U8c:** removed. The host-key hint is a post-V1 candidate (Q9).

### U1c: keys typed ahead of the screen (W2; ruled 2026-11-21)

W1's audit found that a batched key sequence can still trigger some actions before any frame shows them.
- **Behind the reading guard in W2:** operation cancel (`x`), which stops someone's running work, and the network probe, which opens an outbound TCP connection. Each is accepted only when the latest frame drew its target.
- **Left as they are, by ruling:** connect (`c`, a plain `ssh`) and starting the runtime (`S`).
- **Tests:** a batched sequence triggers neither cancel nor the network probe unseen, each with a revert proof.
- **Named limit (ruled 2026-11-22):** a resize away and back whose signals are both still undelivered when the worker settle completes is not counted, a kernel signal-latency window that no pending-signal mechanism closes; the live size read at action time is the backstop for every resize whose size still differs.
- **Refusals under load (ruled 2026-11-22):** a loaded machine may refuse one more answer at a drawn frame; the refusal says the screen changed and asks for the answer again, which is the fail-closed behaviour for durable and outbound actions.

### U9: Exit suite, evidence and ratification (the integrator)

- **Owns:**
  - `tests/native/m07/**`, `tests/evidence/m07-*.json`;
  - `docs/architecture/m07-exit.md`;
  - the M07 matrix and `progress.md` sections.
- **Builds:**
  - the case index, reusing earlier groups by reference;
  - the combined native runs;
  - the records;
  - **then, if §6.1's ratification condition holds, ADR-0013's acceptance and revision 7's ratification,** proposed to the contract owner.

## 3. Waves, and staying mergeable while M06 lands

```text
W0  (now, beside M06 W2)            U1 TUI │ U2a wording + CLI journey │ U4a skill draft + lint │ U5a wrapper core │ U8a PowerShell
W1  (trigger: M06 contract closed)   U0 preparatory: unused types, constants, goldens, replay corpus
W2                                   U3 point lookups and bounds, then one change per correction (emitters + every reader + goldens) │ U4b skill final │ U2b help text │ U8b
W3  (after U3 and U4b; M06 exit)     U5b wrapper journeys + skew │ U5h harnesses │ U6 consolidation │ U7 M06 consolidation
W4                                   U9 exit suite, native runs, records; ratification under §6.1
```

**The trigger:** the contract owner declares revision 6.x closed, once everything M06 W2–W3 needs is on `main`. U0 may draft earlier, but merges only after the trigger.

**How a W0 unit stays mergeable:**
- **It writes only its own paths.** `crates/heimdall/src/tui/**` (not the shared modal dispatch), new test files, `examples/reference-wrapper/**`, `docs/api/**`, `skills/**`, `tools/validation/skill_lint.py`, and `activate_cmd.rs`'s script. U8a's `cli.rs` lines ride its branch for the orchestrator's approval.
- **It hands shared lines to the integrator who owns them** (rule 7).
- **It consumes only current requests, fields and actions.** Revision 6 and 7 shapes wait for U0, U6 and U7.
- **It rebases at the actual integration points:** each M06 merge to `main`, and the U0 merge. Q1's names are already decided, so no generated caller uses an old name.

**Reviews:** one review and one scoped re-check per wave. The plan §6.7 security review covers:
- **W0:** U5a's endpoint and peer checks, and U8a;
- **W2:** the HMAC page tokens, the fail-closed route resolution, the ingress bounds, and D13's transaction.

## 4. The reference wrapper (T05)

**Choice (Q2, accepted):**
- **Language:** Python 3.9+, standard library only.
- **Location:** `examples/reference-wrapper/`, outside the Cargo workspace; never published.
- **API:** the control-endpoint protocol (ADR-0006 §2), directly.
- **Rejected:** a CLI-only wrapper (it becomes harness H1's style), Go, Node, and a Rust example.

**Endpoint and peer checks** (ADR-0013 §8; MUSTs in `docs/api/local-protocol.md`):
- **Unix:**
  - the directory is a directory, owned by the caller, mode `& 077 == 0`, checked with `lstat`;
  - the socket is a socket, owned by the caller, mode `& 077 == 0`;
  - after connecting, **the peer credential's uid equals the caller's**: Linux `getsockopt(SO_PEERCRED)`; macOS `getpeereid` through `ctypes`, or `LOCAL_PEERCRED`.
- **Windows** (through `ctypes`):
  - the `\\.\pipe\` namespace after `GetFullPathNameW`;
  - `CreateFileW` with `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`;
  - `FILE_TYPE_PIPE`;
  - the pipe owner's SID equals the caller's;
  - **`GetNamedPipeServerProcessId`'s process runs as the caller's SID.**
- **After the hello,** `ServerHello.environment_id` equals the **expected environment ID**, which always comes with the endpoint: from discovery, or from the caller beside an explicit endpoint. Any mismatch closes the connection before a request is sent.
- **Only the control endpoint is discovered.** Signing endpoints come from a binding's `consumer` and are used only for the binding's own child; the issuer endpoint is never reachable.
- **Frame caps:** 16 KiB for the hello, 1 MiB after it, checked before allocating.

**Discovery and startup:**
- **The wrapper takes the absolute path of the `heimdall` executable** from its caller; it never looks it up on PATH.
- **Discovery:** `heimdall --json service status` → `control_endpoint`, `environment_id`, `protocol` (D12, the verified hello).
  - `runtime_not_running` → the wrapper reports "not running" to its caller.
  - `endpoint_untrusted` → it reports a refusal, and never retries elsewhere.
- **Startup stays owner-driven.** The wrapper never spawns the runtime. In tests, the Rust harness starts `heimdall service run --detach` under the rule 4 environment:
  - **Unix:** null stdio and its own process group;
  - **Windows:** `DETACHED_PROCESS`, `CREATE_NEW_PROCESS_GROUP`, and an explicit handle list holding only the three `NUL` handles, through the testkit's spawn helper (as `runtime::launcher` does);
  - the harness polls `service status` with bounded backoff up to 10 s, then stops the runtime with `service stop` and, if needed, its exact PID.
- **An older build without D12** (the M06 exit build) gets the endpoint **and the expected environment ID** through the wrapper's explicit arguments. The harness supplies both: the socket or pipe path of its own scratch runtime, and the `environment_id` that build's own `service status` reported from its verified hello.

**What it implements** (target ≈ 450 lines):
- connect, the checks, and the hello;
- `inspect`: a whole list, `select`, or pages, never `select` with pages;
- `ensure`, `bind(materialize)`, `delegate`;
- `observe` and a bounded wait;
- `subscribe` under ADR-0013 §5.4's rule:
  - it persists a cursor only after applying its snapshot, or every event up to it;
  - it freezes the checkpoint on a gap or a disconnect;
  - it closes the old stream;
  - it resubscribes with the same filter from the last applied cursor;
  - it deduplicates by `event_id`;
- `cancel`, `release`, `revoke`.

It validates only the fields it reads, and ignores unknown fields, event types and reasons. An unknown code is a failure.

**Tests:**
- **Unit tests** (`python3 -m unittest`, an in-process fake server):
  - frame caps;
  - a refused schema major;
  - unknown fields, codes and event types;
  - every gap ending (lag, trim, oversize, revocation) and the checkpoint rule;
  - a page with `more: true` is never treated as the end; an empty terminal page ends the traversal;
  - a peer-credential mismatch is refused;
  - an environment mismatch is refused.
- **`a32_wrapper_journey`** (the real binary; rule 4's environment; the M02 loopback sshd and a disposable agent):
  1. discover;
  2. `ensure` a covered profile, reaching `ACCESS_READY` in **one** request (counted);
  3. `ensure` a wider scope: `APPROVAL_REQUIRED` with a `decision_ref`, handed to the harness's human step, which approves on a pty;
  4. **a non-interactive denial:** the wrapper's session cannot attend, an `Attend` sent on it is refused `INTERACTION_REQUIRED`, and nothing is applied;
  5. replay with the same key returns the same operation; **the same key with other parameters gets `REQUEST_CONFLICT`**;
  6. subscribe, checkpoint, disconnect, and resume from the last applied cursor; force each gap (lag, trim with `retention.events` of seconds, oversize) and recover by one resubscribe;
  7. `bind(materialize)`, then launch `ssh` itself from the consumer descriptor with the AGENTS.md option set;
  8. `release`, then `cancel` of a held operation; a bounded wait that times out leaves the operation running;
  9. `OUTCOME_UNKNOWN` through the fixture adapter's `lose_reply`, reconciled and never replayed;
  10. `BACKPRESSURE` at the 17th in-flight request, as client behaviour (the Rust boundary is already tested);
  11. **the operation-level capability refusal** (S4), after a successful hello in both cases:
      - an `inspect` with `page` on a session that did not negotiate `pages/1` is `SCHEMA_UNSUPPORTED`;
      - an `ensure` whose minimum the mechanism cannot meet (`required_capabilities.unattended` on an existing-access profile) is `CAPABILITY_UNAVAILABLE`, with effect `none` and nothing applied.
- **`a32_wrapper_version_skew`:**
  - **Against the M07 build:**
    - a hello with major 2 gets `SCHEMA_UNSUPPORTED`;
    - requiring an unknown capability gets `SCHEMA_UNSUPPORTED`;
    - offering it optionally negotiates it away.
  - **Against the M06 exit build as the older runtime,** with the explicit endpoint and expected-environment arguments:
    - **one successful exchange** (hello, `inspect capabilities`, a whole-list `inspect`);
    - **one real required-feature refusal:** requiring `pages/1`, which the old build does not offer, gets `SCHEMA_UNSUPPORTED`;
    - the wrapper then falls back to whole lists.
  - **For each build,** the schema elements the wrapper requires are checked as a **subset** of `heimdall schema show`'s output, never as equality, so additive skew passes.
- **Independence checks:**
  - **a static check** that the wrapper imports only standard-library modules and names no state path, database or `instance.json`;
  - **in the journey,** every `heimdall` child the wrapper starts inherits the harness's rule 4 environment, verified before launch.

**What it is not:** an SDK, a policy engine or a consent channel. It never sends `Decide` or `ConfirmTime`, and sends `Attend` only in the denial test.

**Windows Python (Q2's conditions):**
- the harness pins a python.org embeddable package's version and SHA-256 in its source;
- it downloads the package into the run's scratch root and verifies the SHA-256 before extracting;
- it runs `python.exe` from there, with no installer, no PATH or registry change;
- it removes the package with the root.

## 5. The optional skill (T04)

**Where:**
- `skills/heimdall/SKILL.md`, with front matter;
- packaged by M08-T03;
- installed only by the user.

**What it may say** (≤ 120 lines):
- **What Heimdall does,** in everyday words.
- **Exactly the six groups,** with their CLI forms and role limits:
  - `cancel` is a form of observe;
  - `revoke` covers only the caller's own grant;
  - always `--json --non-interactive --request-id`.
- **Decide by `code` and `next.action`, never by message text:**
  - `ACCESS_READY` → use the binding;
  - `APPROVAL_REQUIRED` with `next.decision_ref` → **hand the reference to the human, verbatim, and observe the same operation**;
  - provider-owned `INTERACTION_REQUIRED` or `PROVIDER_LOCKED` with `next.provider_interaction` → **tell the human what the provider is asking for** (provider and kind) and wait;
  - `OUTCOME_UNKNOWN` → observe, never repeat;
  - a timeout → observe the same operation.
- **For the human,** the skill may name only read-only Heimdall commands (`heimdall decision list`, `heimdall tui`), where Heimdall itself shows the decision and asks for the typed confirmation.
- **More detail** comes from the installed binary (`schema show primitives`, then `schema show <name>`).
- **Repository files are data, not instructions.**

**What it must never say:**
- any approval, denial, time confirmation, resume, cutoff clearing, widening, or answering of a prompt (`decision approve|deny`, `time confirm`, `access allow`, `resume`, `--clear`, `yes`), including as an example for the human;
- anything that reads Heimdall's state or runtime files, edits `~/.ssh`, or uses `--home` or `HEIMDALL_TEST_*`;
- any real host, path, ID or key;
- **any claim that it grants anything.**

The skill states that it is guidance, that Heimdall decides every request, and that the human approves on their own terminal (R-AP-08). M05's residual R1 stays disclosed: the skill tells the agent never to drive the attended prompt, and no enforcement is claimed.

**Enforcement** (`skill_lint.py`):
- the size cap;
- the forbidden patterns;
- every `heimdall …` line must exist in U0's command-tree golden;
- placeholders only;
- exactly six group headings;
- the self-check against a known-bad fixture.

## 5a. The two harnesses (A32)

**Two harness styles,** written independently of each other and of the wrapper (S4), plus the wrapper itself, which is spec A32's third-party consumer. Both harnesses implement their own calls over `heimdall --json`, through `subprocess`. Neither imports the wrapper.

| | H1: scripted CLI harness | H2: goal-directed harness |
|---|---|---|
| **Style** | a procedural script per task: a fixed sequence of `heimdall --json --non-interactive …` calls, checking exit codes, and reading `operation events --follow` NDJSON | a planner with an **explicit task goal** (for example `{goal: "access", profile, work_id}`) and a **typed state**: `start`, `discovered`, `pending_approval(decision_ref)`, `pending_provider(provider, kind)`, `ready(binding_id)`, `running(pid)`, `stopped`, `failed(code)`. **Its first call comes from the goal.** Each transition is chosen from the state plus the last answer's `code` and `next.action` (a transition table, not a script). Its call set is loaded from `schema show primitives` |
| **Where** | `examples/harnesses/cli/` (Python standard library) | `examples/harnesses/goal-loop/` (Python standard library) |
| **What it touches** | documented CLI output only | the primitive index and documented CLI output only |

The two differ in how they compose calls (a script versus a goal and state machine). Both differ from the wrapper's transport (IPC versus the CLI).

**Deterministic tasks,** the same set for both:
1. discover;
2. use an already-trusted profile;
3. request only missing access, handing off the approval;
4. recover from a caller timeout by observing;
5. bind work and run a child;
6. stop it;
7. **meet the operation-level capability refusal** (S4): an `ensure` with `--require-unattended` on an existing-access profile. It gets `CAPABILITY_UNAVAILABLE`, effect `none`, and the harness records the refusal and stops cleanly.

**Recorded per task and harness:**
- success;
- calls and round trips;
- human handoffs;
- invalid retries (target 0);
- wall time, excluding the human step;
- discovery bytes read.

The records go to `m07-a32-composition.json`. M09-T02's LLM evaluations stay separate.

**Amendments from W3 (ruled 2026-11-22):**
- **H2's states as built:** the list above plus `observing(operation_id)`, for an accepted operation that is neither an approval nor a provider wait. Also `reconciling(operation_id)` (the operation of an uncertain outcome, while it is observed), `releasing` (one per extra binding, on the way to `stopped`) `unresolved(code, operation_id)` (the bound ran out while reconciling) and `inconsistent(code, exit_code)` (an answer whose exit class does not fit its code). Also `observing_release(binding_id, operation_id)` and `inspecting_release(binding_id)`: a binding whose release was answered `OUTCOME_UNKNOWN`, observed by the operation that answer named, or by its own state in `inspect bindings` where it named none. Two payloads carry more than shown: `pending_approval(decision_ref, operation_id)` and `running(pid, binding_id)`. With a new request ID for `run`, today's build makes a second binding for the same work on the one grant (ADR-0011 §10 item 12, I-1: a separate reference), so H2 keeps every binding it was given and its stop passes through `releasing` once per extra binding before `stopped`.
- **`invalid_retries`** counts the answers whose `next.action` is `fix_request` or `new_request_id`. The same definition goes into the A32 evidence record.
- **Request IDs:** every changing request gets its own ID, `run` after `access` included. The idempotency key is never a continuation token.
- **`OUTCOME_UNKNOWN`:** a harness never sends the request again. It observes the named operation until it reaches a terminal state, within the task's existing bound; `ACCESS_READY` seen there counts as the goal met. Still unfinished at the bound (the request plus at most five observations of up to 20 s each), it reports `OUTCOME_UNKNOWN` with the operation ID, and the A32 metrics count that task as a failed attempt. `failed(OUTCOME_UNKNOWN)` carries the operation ID too whenever one is known.
- **Cleanup (W3 review, M07-W3-R01):** H2 releases every binding it holds from any state that holds one, a failed goal and `close()` included; bounded cleanup is resumable; each journey ends with zero active bindings. A release Heimdall refuses is recorded and the rest are still released; the harness exits 1 and the A32 record counts that attempt as failed (ruled 2026-11-22). A goal's record lists each refused release as `{binding_id, code, exit_code}`, and `failed` may carry `binding_id` and `exit_code`. A release whose exit class does not fit its code is recorded the same way with `inconsistent: true` and a `detail` that names it as a probable product defect; the stop goes on (ruled 2026-11-22). A release answered `OUTCOME_UNKNOWN` is recorded apart, in `outcome_unknown`, with the binding, the request ID (`null`: today's `access release` takes none) and the operation ID when the answer names one. H2 never sends it again while its outcome is unknown. The stop or close that receives the uncertain answer does not observe it itself, so a single close receiving `OUTCOME_UNKNOWN` ends with the binding held and exit 1. A later stop, or the close, observes it first. **Where the answer named an operation,** H2 waits on it, bounded, and acts on its result: one new release only when that result says the first did not happen. **Where it named none,** H2 reads the binding's state in `inspect bindings`: an `active` binding alone is not evidence that the release never ran, so H2 sends nothing, reports `still_unknown`, keeps the binding held and exits 1; a binding missing from the list is recorded `not_listed` (not held), never `released`, because absence could also be expiry or revocation. That reading comes from the contract's binding list, not from an observed run. A goal's record carries both readings as lists, `still_unknown` and `not_listed`, apart from `outcome_unknown`, which names only a release that was itself answered `OUTCOME_UNKNOWN`. The bounded wait is one `operation wait` per stop; a later stop or the close waits again. `inspect bindings` is the one call H2 uses that the skill does not list yet (U4b adds it). The close is always a stop of its own, with its own recorded attempt. `access release` takes no request ID today (ADR-0013 handoff, U0-Q7): H2 changes once U0 rules. **From the W5 review (M07-W5-R01 to R03):** a call about a release that gets no answer (a timeout, an unreadable answer) is a recorded attempt, `unanswered`, and is uncertain like `OUTCOME_UNKNOWN`: it is observed before any other release of that binding, and a complete `OUTCOME_UNKNOWN` line received before the timeout keeps its operation ID. A CLI that could not be started is `not_sent`, not uncertain. Every held binding gets its bounded attempt in a stop and in the close, whatever happened to the others. An operation view is read by its typed `state`: only `succeeded` is evidence of a release, and only `failed` or `cancelled` with effect `none` says it did not happen; any other state stays unknown, and an answer that says otherwise by its envelope is `inconsistent`. Every published code has its exit class checked (the installed table after discovery, the frozen table otherwise). Three readings, accepted by ruling (2026-11-22): a release that printed `OK` and then timed out is uncertain, not released; an `OK` that names another binding is uncertain; an operation in a state the table does not know is unfinished. **Requests follow the same rule (ruled 2026-11-22):** an `access ensure` or `run` that timed out or came back unreadable is remembered as uncertain with its request ID and whatever it printed (a binding it named is held at once; an operation it named is kept), and is never sent again. A later stop or the close observes it once, before any binding: by its operation, or, since today's CLI cannot observe by request ID, by the binding list for that work, where an `active` binding H2 does not hold is held and released. Unsettled, it is `still_unknown` and the run exits 1; a CLI that never started is `not_sent`. The record carries `requests_unanswered`, `requests_not_sent` and `requests_still_unknown`, and the summary `request_attempts` keyed by request ID. A request with no operation and nothing new in the list never settles; only observation by request ID (a U0 matter, with U0-Q7) can close that. **W6.3 (ruled 2026-11-23):** H2 never releases a binding it cannot tie to its own request. Through `inspect bindings`, a candidate must be `active`, match the request's `work_id` and `profile`, have a `created_at` later than the moment H2 sent the request, and never have been given to H2 before; with no candidate, or more than one, H2 releases nothing, reports `still_unknown`, and the run exits 1. The attempt records `listed` and `candidates`. The binding view has no field naming a caller or a request (`grant_id` and `profile_revision` tie it to neither), so a caller with access to other callers' bindings could still match one made by another caller after its request; closing that needs a contract field (with U0-Q7). An observation that names a binding in the wrong exit class still gets that binding held and released, `inconsistent: true`, and the request stays uncertain. Two answered requests are remembered the same way as one that got no answer, never resent and observed by a later stop or the close before any binding: an `access ensure` or `run` answered `OUTCOME_UNKNOWN` whose operation is still unfinished at the bound (`outcome_unknown`, in `requests_outcome_unknown`), and one answered `ACCEPTED` whose `operation wait` timed out, was unreadable or could not be started (the goal ends `failed(OUTCOME_UNKNOWN, request_id, operation_id)`). The harness README lists every record field in one table; they are example-harness output, not product contract. **Held on Windows, by ruling (2026-11-23):** A32 task 5's login through the binding's own signing endpoint is proven on Unix only; on Windows the run child is the in-box `ssh.exe` with `IdentityAgent=none`, and the composition record lists the held item. This is a held row, not a gap closed; the M07 case index (U9) records it. **W7a (M07-W6-R01 to R03, the ACCEPTED remainder and the four known-open cases; ruled 2026-11-23):** Nothing uncertain is a success. A goal never counts `OUTCOME_UNKNOWN` as an expected refusal, whatever effect it reports. A refusal a goal expected counts only when its request is not left uncertain. Whatever the goals' own results, the run exits 1 while any request or release is still uncertain. A request answered `OUTCOME_UNKNOWN` whose goal ends at that answer is remembered as `outcome_unknown`, in `requests_outcome_unknown`. Examples: its `next` names no operation, or its exit class does not fit. It is kept with the operation it named, if any (`next.operation_id`, else the envelope's own), and is otherwise observed through the binding list. A goal that ends while it waits on the operation of its own answered request (`observing`, `pending_approval`, `reconciling`) leaves the request uncertain, unless its last answer says how the operation ended. That answer is read by the same table as a later observation: a binding found, or a terminal failure with effect `none`. The request is then remembered with its operation, and the attempt is `still_unknown` with that answer's code and exit status, in `requests_still_unknown`. The cases this covers: the step limit in `observing` or `pending_approval`, which ends in `failed(OUTCOME_UNKNOWN, request_id, operation_id)`; a wait refused for now (for example `SERVICE_UNAVAILABLE`); a wait with no answer in any of the three states; an in-goal wait in the wrong exit class (`inconsistent`, and a binding it named is held); an operation whose own code is `OUTCOME_UNKNOWN`; an approval handoff the person abandons. Remembered requests that named an operation are observed first. Those observed through the binding list that share a work and profile are observed together in one read, newest first, and each binding is credited to one request at most. Two bindings both made after the newest request was sent stay unattributed (`still_unknown`, nothing released): only a request field (U0-Q7) can settle that. On Windows, H2 reads a launch as `launching` (Heimdall's own PID) followed by `spawned`, re-reading the run-record file for up to 5 s. It keeps that file until the child has ended. H1 and H2 accept the in-box `%SystemRoot%\System32\OpenSSH\ssh.exe` as the `run` child, and nothing else outside the scratch root. A32 tasks 5 and 6 run on Windows with that client as the child: `-F <scratch config>` and the isolated option set are on its own command line, and the driver checks exactly one isolated login with the generated key. The login through the binding's signing endpoint is proven on Unix only. On Windows nothing between `run` and `ssh.exe` can check that `SSH_AUTH_SOCK` names the disposable agent, and the isolated set requires `IdentityAgent=none`. H2's `main` parses its arguments and calls `run(args, command)`. The whole-run tests call `run` on Windows, so its exit-code paths are checked there. Covered by H2's stub only, except the Windows journey, which awaits the PC. A goal's record gains the lists `unanswered` and `not_sent`; an attempt may carry `fault`, and its `exit_code` may be `null`. The summary's `release_attempts` is keyed by binding, with each binding's attempts in order (the stop, then the close). A stop that fails does not end its child; the close does. No real-binary run produces any of these answers today: they are covered by H2's stub only.
- **Exit classes (M07-W3-R03):** H2 checks the documented exit class together with the envelope on every call.
- **The login oracle (M07-W3-R02):** each journey proves an authentication through the binding's own signing endpoint, beside the isolated fixture-key login.
- **The binding `ensure` prepared:** with a new request ID for `run`, it stays active after the child ends, until `access release`. U4b's skill says to release it when the work no longer needs it, or to skip `ensure` when `run` alone is enough. Observed today and recorded in the A32 evidence: a `run` that reuses `ensure`'s request ID is accepted and adopts `ensure`'s binding (ADR-0013 §13, U0-Q2).
- **Two fixture worlds, accepted for A32:** tasks 1, 2, 5, 6 and 7 run on existing access (the loopback sshd, a disposable agent, a saved profile); tasks 3 and 4 run on the fixture adapter, because today's build offers a partly covered profile and a slow prepare only there. The record states this with the reason.
- **Windows:** both real-binary journeys are Unix-only as first written. That is fixture plumbing, not inherent, and W4 plans the Windows coverage (see `progress.md`).

## 6. Exit mapping

Records live in `tests/evidence/m07-*.json`. The lowest-row rule applies. "All" means macOS arm64, the Linux devbox and Windows 11. §6.1 controls the exit and ratification.

| Case | Proven by | Platforms | Fixtures | Passing means | Rows not run natively |
|---|---|---|---|---|---|
| **A19** (R-AP-01, R-AP-02, R-AP-04, R-AP-05, R-RT-05, R-RT-06, R-UX-07) | M01's groups (by reference); U3's tests and the schema-to-emitter checklist; the wrapper journey; H1 and H2 as independent non-interactive callers | All | The fixture adapter with its ledger (`HEIMDALL_TEST_ADAPTER`, `_LEDGER`, `_SLOW_PREPARE_MS`); 20,000 seeded destinations; `retention.events` of seconds | Every indexed test passes; every emitter on the checklist validates; no response exceeds the frame, and none is `INTERNAL_ERROR` for size; whole reads and snapshots are complete or refused; no internal resolution traverses; an overflow after dispatch keeps its effect; timeout is not cancellation; an uncertain outcome is never replayed; every gap ends the stream and one resubscribe recovers it | None |
| **A20** (R-UX-05, R-UX-07) | The M02/M03/M05 TUI tests (by reference); U1's tests; U6's stale-page test | macOS and the devbox (pty); Windows 11 (ConPTY) | Rule 4's environment; `HEIMDALL_TEST_SLOW_PREPARE_MS`; 5000 destinations from two `import` bundles; `NO_COLOR` | The walkthrough completes keyboard-only, with focus, controls and results asserted at each size; the terminal is restored; text markers in every view; an idle poll draws nothing; **for Tab, PageDown and a search key, the completed-frame P95 is ≤ 100 ms at 5000 loaded rows with a live slow operation, on the debug build on macOS** (a targeted A20 check; M08-T05 owns spec §15.1's table); timeouts are counted; Windows answers a key after a resize within the bar | None. An optional release-build figure is taken only in a disposable account, container or VM |
| **A27** (R-SS-04, R-RT-05) | M02's and M04's groups and M03's ConPTY rows (by reference); U7's rendered-helper rows; U8a's startup and stdout rows; the frozen run record | All, plus M04's WSL rows | M02's byte fixtures, the loopback sshd, disposable distributions | The groups pass; no stdout contamination through the rendered helper or the hook; protocol and integration rows are reported separately | B5 |
| **A30** (R-UX-03, R-UX-08, R-QU-06) | U2a's vocabulary and three-questions checks (the deterministic part) | All | Scratch runtime in each state | The default surfaces answer the three questions in everyday words | B14, B7 (§6.1) |
| **A32** (R-AP-07, R-AP-08, R-UX-04, R-QU-05) | H1 and H2 (§5a), each running the seven tasks; the wrapper's journey and skew runs; U4's index and skill lint | All | As A19, plus the M06 exit binary for skew | Both harnesses and the wrapper complete the tasks; `ACCESS_READY` in one intent-level request; the operation-level capability refusal is handled; zero invalid retries; no private file, database or TUI is read; no LLM; the skill passes its lint; the metrics are recorded | Foreign-owner endpoint rows: B2, B3, B8. LLM metrics: `deferred_with_decision` to M09-T02 |
| **CLI standalone** | `cli_standalone_access_and_stop` (U2a) | All | M02's CLI fixtures | Access and stop through the CLI only | None |
| **TUI standalone** | `tui_standalone_access_and_stop` (U1) | macOS and the devbox (pty); Windows (ConPTY variant) | M02's TUI world | Access and stop through the TUI only | None |
| All | `tests/native/m07/case-index.json` | — | — | — | `m07-exit-claims.json` |

### 6.1 The exit rule and G08 ratification (controlling)

**M07 exits** when every record is `verified`, except:
- rows blocked solely on named owner inputs;
- rows deferred by decision.

That is the M01 and M03 rule. **The one ruled exception to plan §5 M07's list is A30.** It stays `blocked` on B14 (one person unfamiliar with Heimdall) and B7 (the baseline worksheet). Its participant session runs inside M09-T01's normal-week study, so the owner is asked once (Q10). M07's exit record reports A30 as blocked, never as passing.

**The other rows that may stay open at exit:**
- A27's Windows console row (B5);
- the foreign-owner endpoint rows (B2, B3, B8);
- A32's LLM metrics, deferred to M09-T02.

**G08 ratification** (ADR-0013 §1.2) requires every A19 and A32 native row to be `verified` on macOS, the devbox and Windows. The only rows excused are:
- rows blocked **solely** on B2, B3 or B8, which are the foreign-owner endpoint rows;
- the deferred LLM metrics.

Until then, revision 7 stays provisional, and M07 does not claim G08.

## 7. Contract deltas

ADR-0013 §11 lists D1–D21, and §12 the pre-release corrections PC1–PC8, with their consumers. In brief:
- **Views and lists:**
  - typed views (D1);
  - opt-in pages and point lookups (D2);
  - names (D3);
  - whole-or-refuse snapshots (D4).
- **Events:**
  - typed payloads as emitted (D5);
  - resync completed (D6).
- **Discovery:**
  - the primitive index (D7);
  - error reasons (D8).
- **Fields and refusals:**
  - `null` handling (D9);
  - handed-on fields (D10, D11);
  - verified discovery (D12);
  - M05-F1 (D13).
- **Ratifications:**
  - the help rule (D14);
  - the spec list and stream grammar (D15);
  - pending readings and retention without a ceiling (D16);
  - `remote_pending_reasons` (D17);
  - deprecation (D18).
- **New in revision 2, completed in revision 3:**
  - `response_too_large` with truthful effects (D19);
  - write-time item bounds at every ingress (D20);
  - `page_token_invalid`, `selector_invalid` and the fail-closed route facts (D21).
- **Pre-release corrections:** PC1–PC11, each landing as one change with its readers. PC9 (every gap ends the stream), PC10 (no cursor in page-mode resync) and PC11 (item bounds) are new in revision 3.

## 8. Probes run in this design unit

**Where the outputs are:**
- **Record:** `tests/evidence/m07-probe-tui-and-lists.json`.
- **Raw output:** `tests/evidence/artifacts/m07/probe/`.
- **Drivers:** `prototypes/m07-probe/`.

**Setup:** the debug build of `c10810af`, on the build host, with the static pass redirected to a scratch account home.

**A discarded first run:** it left out `HEIMDALL_TEST_SSH_HOME`, so the passive static pass read the owner's configuration tree. It was read-only, and the orchestrator confirmed nothing was written. Its results were replaced. The record keeps the incident, and rule 4 comes from it. **The retained artifacts are debug mechanism evidence.**

| Probe | Question | Observed (isolated) | What it changed |
|---|---|---|---|
| P1 | Does an idle TUI keep repainting? | About 1.5 KB per minute, one burst about every 1.5 s (relative times; the 3 s poll) | U1: minute granularity; idle polls draw nothing |
| P2 | Is key handling responsive at catalog scale? | Key-to-**first-byte** P95 of 15–19 ms at 100 destinations, 84 ms at 1000, 306 ms at 3000 and 402 ms at 3500, roughly in proportion to the catalog. The first byte can come from an unrelated redraw, so this is a baseline only (R11) | U1: per-update derivation, windowed rendering, completed-frame timing under load |
| P3 / P3b | When does a listing stop fitting one frame, and what do clients show? | 6000 destinations: 864,100 bytes, exit 0. 8500: `INTERNAL_ERROR`, exit 1, from both the JSON and human list. **The TUI showed "0 total · No catalog destinations."** One import bundle is capped at 1 MiB | D2, D19, U1 and U6 error states, R02's caller migration |
| P4 | What does a fresh catalog's overview say? | "[OK] Ready", then one raw-code finding row per destination (35 visible rows at 120×40 with 100 destinations; rows truncate to identical text at 40×12) | U1 and U2a grouping and wording |

## 9. Deferred, each with a reason

| Item | Reason |
|---|---|
| LLM agent evaluations | M09-T02 (plan §5) |
| The A30 participant session and the baseline comparison | M09-T01; B14 and B7 |
| Spec §15.1's full table on release builds | M08-T05 (A34) |
| MCP adapter, SDKs | Later candidates (plan §11.2) |
| The three Git residuals | M08-T02 (Q8) |
| The exported host-key hint | Post-V1 candidate (Q9): no requirement mandates it |
| Machine-local remapping of manifest references | No case or requirement needs it |
| Export and import above the 1 MiB bundle cap | M08, if a user needs chunked bundles |
| A real screen-reader trial | Not in A20's pass condition; M09-T01 if the owner wants one |

## 10. Questions

**One is open, for U0** (2026-11-22; ADR-0013 §13, U0-Q1): which code a non-interactive `ensure` that needs approval answers. Today's build serves `INTERACTION_REQUIRED` with a `next.decision_ref`; the journeys below and the skill say `APPROVAL_REQUIRED`. Until U0 decides, the wrapper and both harnesses accept `decision_ref` under either code.

Q1–Q12 are ruled, and revision 3 applies the orchestrator's rulings S1–S4 and those on RC02 and RC05–RC11 (§0a). **The choices revision 3 makes within those rulings:**
- the snapshot caps (1,000 operations, 256 pending decisions, 768 KiB);
- the 64 KiB item bound and its per-field caps (U0 confirms the numbers against current validation);
- `remote_pending`'s first 16 entries;
- HMAC-SHA256 tokens under a key stored in the store's metadata.

## 11. Owner inputs and handoffs

**Owner inputs:**
- **B14 (new):** one person unfamiliar with Heimdall, for A30 inside M09-T01's normal-week study;
- **B7:** the baseline worksheet (carried);
- **B5:** A27's Windows console row (carried);
- **B2, B3, B8:** the foreign-owner endpoint rows (carried);
- **B9:** the arm64 rows (carried);
- **for the optional release-build latency figure,** a disposable account (B3, B8) or a VM.

The PC's Python download is authorized (Q2).

**Handed on:**

| Item | Where |
|---|---|
| LLM agent evaluations; the A30 session | M09-T02, M09-T01 |
| Spec §15.1's table; catalogs above the bundle cap | M08-T05; M08 |
| The Git residuals | M08-T02 |
| The recovery runbook behind U2a's lost-device guidance | M08-T06 |
| Packaging the skill, the wrapper and the harnesses as examples | M08-T03 |
| The decision-backed replay store and its retention | M06 (ADR-0013 §7), ratified at U0 |
