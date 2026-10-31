# Heimdall production architecture (M01-T00)

**Status:** design baseline for M01, `implemented_unverified` skeleton (compiles;
fmt/clippy/tests pass; unit bodies are `todo!()` and owned by the M01 tasks in
`m01-plan.md`). **Sources of truth:** `spec.md` and `plan.md`; this document maps
them onto Cargo crates and records decisions, it does not add obligations.
**Decided inputs (not reopened here):** Rust + Ratatui (ADR-0002 §10, ADR-0004 §1);
managed recipe B1 (ADR-0004 §2, ADR-0005 in progress); SQLite starting candidate
(spec P08); TOML config with generated JSON Schema (spec P10); public primitive
draft (`docs/contracts/primitives-draft.md`); release contract (ADR-0001).
**Companion:** ADR-0006 (`docs/decisions/0006-public-contract-baseline.md`) holds
the public contract; `dependencies.md` holds every third-party choice.

## 1. Layering (plan §4.1) → crates

```text
                 crates/heimdall  (binary: CLI, TUI entry, `service run`)        interfaces
                        |                     |
                 crates/runtime  (service loop, supervisor, instance lock,     runtime /
                        |         scheduler, time guard, on-demand start)      reconciler
            +-----------+-----------+
            |                       |
      crates/ipc              crates/app  (six primitives, authz checks,       application
  (endpoints, framing,         ensure pipeline, single-flight, reconciler      operations
   hello, signing framer)      planning, event publication, adapter ports)
            |                       |
            |                 crates/store  (SQLite journal, idempotency,      persistence
            |                       |        grants, tombstones, events)
            +-----------+-----------+
                        |
                 crates/domain  (IDs, scopes, policy intersection, snapshots,   domain /
                        |        state machines, time model, idempotency,       contracts
                        |        evidence, resource generations)
                 crates/contract (envelope, codes, exit codes, states, events,
                                  requests, IPC messages, canonical JSON, schemas)

                 crates/testkit  (dev-only: virtual clock, scripted faults,
                                  fake adapter, proptest strategies, canary assert)
```

Dependencies point inward only (plan §7.1). `domain` and `contract` import no
terminal, transport, storage or provider code. `app` knows adapters only through
its own port traits. `ipc` does not know `app` (the runtime supplies a
`Dispatcher`). The binary is the only crate that links everything.

Plan §4.1 rows not given a crate in M01, and why: *credential adapters* (M02/M03:
the `CredentialAdapter` port lives in `app::ports`; the only M01 implementation is
`testkit::FakeCredentialAdapter`), *route adapters* (M04/M06), *environment/consumer
adapters* beyond OS IPC (M02 `run`/projections, M04 WSL/containers). The "two
callers" rule (plan §4.1) is applied: the store has one implementation (SQLite, with
`:memory:` for tests) and no trait; the adapter port exists because the fake and the
M02 adapters are both known callers; no plugin framework exists.

## 2. Crate contracts

| Crate (lib name) | Responsibility | Must not own | Depends on | Public surface (skeleton) |
|---|---|---|---|---|
| `heimdall-contract` | Wire contract: `Envelope<T>`, `Code` table with exit/retry/effect/next, `ExitCode`, `OperationState`/`GrantState`, typed IDs, `Event`/`Cursor`/`Snapshot`, six-primitive request/response types, IPC message set + hard limits, canonical JSON + `RequestHash`, JSON Schema generator | Semantics (transitions, authority, hashing *inputs*), I/O | serde, serde_json, schemars, jiff, sha2 | `code::Code`, `exit::ExitCode`, `envelope::*`, `state::*`, `ids::*`, `event::*`, `request::*`, `ipc::*`, `canonical::{canonical_json, request_hash}`, `schema::{public_schemas, code_table}`, `version::*` |
| `heimdall-domain` | Pure functions and data: `Scope` algebra, `StandingPolicy` (pause/cutoff, revision, `AuthorityGeneration`), `ProfileSnapshot`, `EnvironmentRecord`, `resolve_authority`, `GrantSnapshot`, `OperationRecord`, `grant_transition`/`operation_transition`, `Clock` + `Deadline` + `TimeAnchor`/`assess_time`, `IdempotencyKey`/`compute_hash`/`classify`, `EnforcementEvidence`, `ManagedResource`/`may_cleanup`, `Tombstone`/`generation_still_valid` | Provider SDK calls, UI, hidden I/O, retry loops (plan §4.1) | contract, jiff, serde | module per concept; every function `pub` and pure |
| `heimdall-store` | SQLite state (`Store`, `Txn`), versioned migrations with backup, WAL + `synchronous=FULL`, fault points (`FaultHook`, `FaultPoint`), per-environment event sequence, retention purge that never touches tombstones/policies | Secrets in plaintext (references only, spec §13.3), authorization, wire rendering | domain, contract, rusqlite | `Store::{open, open_in_memory, transaction, schema_version}`, `Txn` repository methods, `migrations::{MIGRATIONS, SCHEMA_VERSION, apply}` |
| `heimdall-app` | `Operations` (inspect/ensure/bind/delegate/observe/cancel/release/revoke/policy/tick), `ensure::EnsureStage` pipeline + `StageHook`, `SingleFlight`, `reconcile::{plan, Backoff, should_retry, guard_cleanup}`, `EventPublisher` + reader-scoped cursors, `OpError`/`Completed` → envelope, `ports::{CredentialAdapter, DecisionChannel}`, `ids` (CSPRNG) | Shell-string construction, per-frontend retry loops, SQL, framing, rendering | domain, contract, store, tokio (sync/time), async-trait, getrandom, base64ct | as listed; everything returns `OpResult<T>` |
| `heimdall-ipc` | Control endpoint transport (Unix socket dir + `peer_cred`; Windows named pipe + DACL + client SID), length-prefixed JSON framing, hello negotiation, per-connection limits, `Dispatcher` trait, `ControlClient`, bounded SSH-agent framer for the signing endpoint with an exact allow-list and `Signer` trait | Authorization, operation logic, storage | contract, tokio (net/io), tokio-util codec, ssh-agent-lib (proto only), windows-sys (Windows) | `endpoint::*`, `frame::*`, `session::{negotiate, ControlConnection, ControlClient, Dispatcher}`, `signing::{classify, serve, Signer}`, `unix::*`/`windows::*` |
| `heimdall-runtime` | `Config`/`Paths` (TOML + schema), `InstanceLock` (`File::try_lock`), `InstanceInfo`, `Service::{start, run}`, `Supervisor` (resource owners, deadline scheduler, time guard), `launcher::ensure_running` (on-demand start), `telemetry::{init, redact}` | Authority semantics, operation logic, wire formats, rendering | app, ipc, store, domain, contract, tokio, toml, schemars, etcetera, tracing | as listed |
| `heimdall` (bin) | clap command tree (spec §11.1), envelope rendering and exit mapping (`output`), `service run` entry, `tui` entry (M02-T05), `schema export|show` (implemented) | Any authorization or lifecycle implementation (plan §4.1 "Interfaces") | runtime, app, ipc, contract, clap | `heimdall` executable |
| `heimdall-testkit` (dev) | `VirtualClock`, `ScriptedFaults`, `FakeCredentialAdapter` with side-effect counters, proptest strategies, `assert_no_canary` | Shipping in a binary (dev-dependency only) | app, store, domain, contract, proptest | as listed |

## 3. Process model (spec §13.1, §13.2, P01)

One executable, three modes:

1. **Client mode** (every command except `service run` and `tui`): parse, build the
   request, connect to the control endpoint, hello, send, map the envelope to an exit
   code (ADR-0006 §6). Pure inspection and help never start the service
   (spec §13.1); effectful commands call `runtime::launcher::ensure_running`.
2. **TUI mode** (`heimdall` on a TTY, `heimdall tui`; M02-T05): the ratatui loop on
   the main thread; IPC on a worker thread running a current-thread tokio runtime;
   the TUI is a client like the CLI and authorizes nothing itself (R-UX-05).
3. **Service mode** (`heimdall service run [--detach]`): the per-user runtime.
   Start-up order (R-RT-07): instance lock → open/migrate store → time anchor check →
   `Operations::start` (restart recovery; no deadline reset, no pause revival, no
   identity change) → bind control and signing endpoints → write `instance.json` →
   supervisor. Shutdown drains in-flight operations to a durable stage, closes
   endpoints, removes `instance.json`, releases the lock last.

**Single instance.** `InstanceLock` is an exclusive advisory lock on
`<state_dir>/service.lock` (kernel-released on crash, so a stale PID can never keep a
dead instance "running"); `instance.json` carries pid + OS start time and is
validated by clients, never trusted blindly (spec §13.3, §4.2 PID reuse).

**On-demand start.** A client that finds no live endpoint takes `start.lock`, spawns
its own executable path with `service run --detach` (no `PATH` lookup, no shell),
and polls with bounded backoff (`launcher::LauncherConfig`); concurrent clients start
at most one service and never a new broad agent per invocation.

**Endpoints.** Control and signing are distinct listeners with distinct paths,
permissions and protocols (ADR-0006 §2). Containers, forwarded agents and workers
receive only a signing endpoint (spec §8.5 "do not expose the control/approval
interface alongside the signing endpoint"). The issuer (recipe B1, M03) is a third
endpoint reachable only by the runtime itself.

**Elevation.** None in routine operation; service registration is a setup action
(spec §13.1, R-DI-02) and is M04/M08 work.

## 4. Threading and async (decision)

**Decision: tokio, current-thread flavour, in every process; blocking work on
`spawn_blocking`; the domain layer is synchronous and pure.**

Why tokio at all: the runtime multiplexes many connections on two endpoints, timers
at persisted deadlines, event fan-out, graceful shutdown, and (M06) Iroh, which is
tokio-native (ADR-0002 §8). tokio also supplies the two platform primitives the IPC
design needs without `unsafe` on Unix: `UnixStream::peer_cred()` (`getpeereid` /
`SO_PEERCRED`) and `named_pipe::ServerOptions` with `reject_remote_clients`,
`first_pipe_instance` and raw security attributes on Windows.

Why current-thread: deterministic task ordering for model tests, single-flight and
generation checks without cross-thread races, the lowest idle cost against the
spec §15.1 idle budgets (< 0.5 % CPU, ≤ 150 MiB), and `tokio::time::pause` for
timer tests. CPU/blocking work (SQLite, signing in M03, process launch in M02) goes to
the blocking pool, which is bounded (`max_blocking_threads`) in `Service::runtime`
once M01-T05 sets it. Switching to the multi-thread flavour later is a configuration
change, not a redesign: the ports are `Send + Sync`.

**Bounded queues (spec §11.5, R-RT-06).** Every queue has a limit and a defined
overflow behaviour:

| Queue | Bound (constant) | On overflow |
|---|---|---|
| Control connections per endpoint | `ipc::MAX_CONTROL_CONNECTIONS` = 64 | accept, send `Goodbye(BACKPRESSURE)`, close |
| Signing connections per endpoint | `ipc::MAX_SIGNING_CONNECTIONS` = 64 | close without reading |
| In-flight requests per connection | `MAX_INFLIGHT_REQUESTS_PER_CONNECTION` = 16 | `Response(BACKPRESSURE)` for the excess request |
| Subscriptions per connection | `MAX_SUBSCRIPTIONS_PER_CONNECTION` = 4 | `Response(BACKPRESSURE)` |
| Live events per subscriber | `EVENT_BUFFER_PER_SUBSCRIPTION` = 256 (`broadcast` capacity) | `Lagged` → one `ResyncRequired` event, backlog dropped, consumer snapshots |
| Running operations | `app::Limits::max_running_operations` = 32 | `BACKPRESSURE` with `retry_after_ms` |
| Concurrent adapter calls | `Limits::max_concurrent_adapter_calls` = 4 (semaphore) | queued inside the operation, bounded by the operation's wait |
| Single-flight keys | `SingleFlight::with_bound(256)` | `BACKPRESSURE` |
| Retries per resource | `reconcile::Backoff::max_attempts` = 8, cap 60 s, jitter | resource `failed`, durable next step, no prompt storm |
| Frame sizes | 1 MiB control, 16 KiB hello, 256 KiB signing | reject before allocation, close |

## 5. Time model (spec §6.2, §6.4; ADR-0006 §10)

* `domain::time::Clock` (`wall()` → `jiff::Timestamp` UTC, `monotonic()` →
  `Duration`) is injected everywhere time is read: `Operations`, `Supervisor`,
  adapters receive `now` as a value. `SystemClock` in production,
  `testkit::VirtualClock` in tests (advance, monotonic-only advance, wall rollback,
  restart). Virtual-clock tests therefore drive the real `Operations`, `Supervisor::
  scheduler_pass` and `time_guard_pass` code, not copies.
* Deadlines are resolved **once** at creation (`resolve_deadline`): the caller's
  intent (absolute RFC 3339 with offset, or a duration) is kept verbatim in
  `Deadline.intent`, the enforced instant in `Deadline.effective` (UTC); both are
  persisted in the immutable grant columns. Enforcement is always
  `now >= effective` against the persisted instant (`is_expired`), after restart,
  wake or clock change alike. Ambiguous local times are rejected at the human input
  boundary (`DeadlineError::Ambiguous`, jiff disambiguation); machine requests must
  be unambiguous.
* Monotonic time is used for in-process intervals only (backoff, renewal cadence,
  skew detection). It is never persisted across processes except inside a
  `TimeAnchor` tagged with a `process_generation`.
* **Rollback detection.** The time guard persists `TimeAnchor { wall, monotonic,
  process_generation }` every `anchor_interval` and after wake. `assess_time`
  returns `Uncertain(Rollback)` when wall < previous anchor − `max_tolerated_rollback`
  (default 5 s), and `Uncertain(Skew)` when, within one process, wall progress and
  monotonic progress differ by more than `max_tolerated_skew` (60 s). Forward jumps
  are plausible (sleep) and only make deadlines expire sooner. On `Uncertain`,
  issuance and activation stop with `TIME_UNCERTAIN`; passive reads continue with a
  warning; expiry checks still run (they can only deny). Server clock errors are a
  separate diagnosis (M03).

## 6. Storage model (spec §13.3, P08; plan §4.3)

SQLite via `rusqlite` with the bundled engine: WAL, `synchronous=FULL`, foreign
keys, `STRICT` tables, `integrity_check` at open. One connection behind a mutex in
the service process (current-thread runtime; all store calls run on the blocking
pool). Schema in `crates/store/migrations/NNNN_*.sql`, applied transactionally after a
file backup; a newer `user_version` than `migrations::SCHEMA_VERSION` is
`StoreError::NewerSchema` (older clients never read a newer store as empty).

Transaction boundaries follow plan §4.3: *journal intent* (operation row + stage) →
*perform the scoped action* outside the transaction → *record outcome* → *reconcile
ambiguity* (`OutcomeUnknown` until a later transaction resolves it). Fault points
(`FaultPoint::{BeforeTransaction, BeforeCommit, AfterCommit, ...}`) are consulted
through `FaultHook` so plan §6.4 "interrupt before and after each durable write" is
testable in-process; `FaultAction::Crash` aborts the process for child-process
crash tests.

Retention (spec §13.6 draft defaults, tunable in `config.toml`): operations and
idempotency records 7 days after terminal state (floor 24 h); event log 7 days or
a row cap; tombstones, policies, environment identity and grants' immutable
columns are never purged by retention.

## 7. Error model (spec §11.6; ADR-0006 §3, §5, §6)

`app::OpError { code, effect_status, resource, next, message, operation_id }` is the
single error type crossing the application boundary. `OpError::into_envelope`
produces `Envelope<ErrorData>` with `state` derived from the code (`OutcomeUnknown`,
`Cancelled`, `AwaitingApproval`, else `Failed`), `data.error.retryable` from the code
table, and `next` populated. Store errors map to `STATE_UNAVAILABLE`; randomness
failure to `INTERNAL_ERROR`; adapter errors map by variant (`ProviderLocked` →
`PROVIDER_LOCKED`, `InteractionRequired` → `INTERACTION_REQUIRED`, `Unavailable` →
`DESTINATION_UNREACHABLE`/`SERVICE_UNAVAILABLE` by resource, `CapabilityUnavailable`
→ `CAPABILITY_UNAVAILABLE`, `OutcomeUnknown` → `OUTCOME_UNKNOWN`, `Protocol` →
`UNSUPPORTED_CLIENT`). The CLI maps `Code::exit_code()` with one override:
`ACCEPTED` exits 0 only when the caller chose `--async` (`output::exit_code_for`).
`run` exits with the child's status after launch (spec §10.4; M02).

## 8. Mapping to spec §13.1 and plan §7.1

| spec §13.1 box | crate |
|---|---|
| Human CLI / TUI / agent callers | `heimdall` (bin), third-party wrappers over `heimdall-ipc` + `heimdall-contract` |
| versioned application operations | `heimdall-app` (`Operations`), exposed by `heimdall-ipc` sessions |
| policy resolution + lifecycle supervisor | `heimdall-domain::authority` + `heimdall-runtime::supervisor` |
| credential / environment / route adapters | `heimdall-app::ports` (M01), adapter crates from M02 |
| owned resources + transactional state | `heimdall-domain::resource` + `heimdall-store` |

plan §7.1 `<source-root>/{domain,application,runtime,adapters,interfaces,persistence}`
becomes `crates/{domain+contract, app, runtime+ipc, (M02+), heimdall, store}`.
`schemas/public-api/` is generated by `heimdall schema export`; `schemas/
configuration/` by M01-T05 (`Config::json_schema`). `tests/{model,contracts,
integration,adversarial}` hold cross-crate tests as `m01-plan.md` assigns them.

## 9. `unsafe` inventory

`unsafe_code = "deny"` at workspace level. Exactly one module may opt in:
`crates/ipc/src/windows.rs` (`#![allow(unsafe_code)]`) for `CreateNamedPipeW`
security attributes (`create_with_security_attributes_raw`), SDDL conversion, and
the client-token query (`ImpersonateNamedPipeClient` → `OpenThreadToken` →
`GetTokenInformation(TokenUser)` → `RevertToSelf`). Each call is wrapped in a safe
function with its invariants documented; no `unsafe` leaves the module. Unix needs
none (tokio provides `peer_cred`; std provides file locks and permission bits).
Dependencies' internal `unsafe` is not audited by this document (REPORT.md §8
lesson); `cargo-deny`/`cargo auditable`/OSV scanning are M08 obligations
(ADR-0002 §11).

## 10. Lints, build hygiene, validation

* Workspace lints: `unsafe_code = deny`, `missing_docs = warn`, `unused_must_use =
  deny`; clippy `all`, `unwrap_used`, `expect_used`, `dbg_macro`, `print_stdout`,
  `print_stderr`, `unimplemented` as warnings; CI runs clippy with `-D warnings`, so
  they are errors in practice. `clippy::todo` is allowed only while the skeleton
  exists (re-enable as `deny` when M01 closes). `clippy.toml` raises
  `large-error-threshold` to 1024 for `OpError`.
* One target dir, `./target` (gitignored); never `CARGO_TARGET_DIR` overrides
  (AGENTS.md). Toolchain pinned in `rust-toolchain.toml` (1.99.1, edition 2024,
  resolver 3). `Cargo.lock` committed; CI uses `--locked`.
* `tools/validation/check.sh`: `cargo fmt --all --check`, `cargo clippy --workspace
  --all-targets --locked -- -D warnings`, `cargo test --workspace --locked`; prints
  each real exit code; the schema-consistency diff is enabled by M01-T06.
* Lessons carried from `prototypes/rust/REPORT.md` into this design: classify a
  Windows path before opening it and check `FILE_TYPE_PIPE`/`FILE_TYPE_DISK` on the
  handle (§16); crossterm 0.29 hangs on terminal hang-up and `Terminal::clear()`
  queries the cursor (§5) — the TUI unit (M02-T05) must keep the watchdog and avoid
  the query; no C compiled at build time except SQLite (bundled), which the
  cross-build recipe (zig) already handles.

## 11. Open items

Authority-semantics questions for the orchestrator are in ADR-0006 §13. Everything
else here is decided; reopen through an ADR when evidence contradicts it (plan
§11.3).
