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

**M02 crates** (m02-plan U0; ADR-0007). Four crates join the workspace. They sit
beside the layers above and depend inward only:

```text
   crates/heimdall (bin) ──► launch ──► localenv ──► app (ports), sshconf, domain, contract
                         └─► adapters ─► localenv, app (ports), ipc, domain, contract
   localenv ──► sshconf ──► domain, contract        (sshconf is pure: no I/O but its
                                                      ConfigSource port, never executes)
```

* `crates/sshconf` (`heimdall-sshconf`): OpenSSH and Git configuration text (U1, U2).
* `crates/localenv` (`heimdall-localenv`): discovery, the passive doctor, explicit
  probes, Git observation (U3); the projection file transaction behind the
  `ProjectionWriter` port and the projection `ResourceCleaner` (U4). Holds the third
  `unsafe` module (§9).
* `crates/adapters` (`heimdall-adapters`): the native-agent and 1Password
  existing-access adapters behind `CredentialAdapter` and `ProviderProbe` (U6).
* `crates/launch` (`heimdall-launch`): the process contract for `run`, `connect` and
  the TUI handoff (U8).

`app` never depends on these crates: it names them only through its ports, and the
recovery and fingerprint types a held step carries live in
`heimdall_domain::projection` (wave-0 verifier E8). The runtime wires the real
implementations only in the activation change set (m02-plan §2, wave 3); until then
no request, CLI command or restart reaches them.

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
| `heimdall-domain` | Pure functions and data: `Scope` algebra, `StandingPolicy` (pause/cutoff, revision, `AuthorityGeneration`), `ProfileSnapshot`, `EnvironmentRecord`, `resolve_authority` (+`Denial::DeadlinePassed`), `GrantSnapshot`, `BindingRecord`/`may_act_on`, `OperationRecord` + `RecoveryIntent`/`StageReceipt`/`EffectReceipt`, `grant_transition`/`operation_transition`, time (`Clock`/`BootId`/`TimeSync`/`TimeAnchor`/`gate`/`GrantAnchor`/`admission`), `IdempotencyKey`/`compute_hash`/`classify` + `ExpiredKeyMarker`, `DecisionRecord`/`complete`, issuance records + `check`/`residual`, `EnforcementEvidence`, `ManagedResource`/`may_cleanup`, `Tombstone`/`generation_still_valid` | Provider SDK calls, UI, hidden I/O, retry loops, platform clock syscalls (plan §4.1) | contract, jiff, serde | module per concept; every function `pub` and pure |
| `heimdall-store` | SQLite state (`Store`, `Txn`), versioned migrations with backup (0001 init, 0002 design-fix tables), WAL + `synchronous=FULL`, fault points (`FaultHook`, `FaultPoint`), neutral per-environment event sequences, retention purge that leaves expired-key markers and never touches tombstones, policies, decisions, issuance entries, grant anchors or unresolved operations | Secrets in plaintext (references only, spec §13.3), authorization, wire rendering, reader-scoped cursors | domain, contract, rusqlite | `Store::{open, open_in_memory, transaction, schema_version}`, `Txn` repository methods in `lib.rs` (wave 1) and `ext.rs` (bindings, profiles/snapshots, environments, policies_for, tombstone/denied_ancestor, decisions, time anchors/high-water/confirmation, idempotency settlement/markers, recovery intent/receipts, issuance reserve/publish/void/residual, unresolved_operations, stored_events_after/snapshot_boundary), `migrations::{MIGRATIONS, SCHEMA_VERSION, apply}` |
| `heimdall-app` | `Operations` (inspect/ensure/bind/delegate/observe/cancel/release/revoke/policy/tick + `attend`/`decide`/`confirm_time`) over `context::Caller { context, attendance, interaction }`, `OperationsConfig { store, clock, time_sync, time_policy, environment, adapters, stage_hook, limits, default_window }`, `TimeGate` (the one shared gate; `SafeNow`), `ensure::EnsureStage` pipeline + `StageHook` (injected in production), `SingleFlight`, `reconcile::{plan, Backoff, should_retry, guard_cleanup}`, `EventPublisher` + `SubscriptionStart`/`SequencedEvent` + reader-scoped cursors built at delivery, `OpError`/`Completed` → envelope, `ports::CredentialAdapter` (prepare/renew/**reconcile**/revoke with `effect_token`), `ports::ResourceCleaner` (generation-bound delete, called only by the supervisor's cleanup executor), `reconcile::CleanupHook`, `ids` (CSPRNG) | Shell-string construction, per-frontend retry loops, SQL, framing, rendering, owner decisions as a port (they are store records) | domain, contract, store, tokio (sync/time), async-trait, getrandom, base64ct | as listed; everything returns `OpResult<T>` |
| `heimdall-ipc` | Control endpoint transport (Unix socket dir + `peer_cred`; Windows named pipe + DACL + client SID), length-prefixed JSON framing, hello negotiation, per-connection limits, `Dispatcher` trait, `ControlClient`, bounded SSH-agent framer for the signing endpoint with an exact allow-list and `Signer` trait | Authorization, operation logic, storage | contract, tokio (net/io), tokio-util codec, ssh-agent-lib (proto only), windows-sys (Windows) | `endpoint::*`, `frame::*`, `session::{negotiate, ControlConnection, ControlClient, Dispatcher}`, `signing::{classify, serve, Signer}`, `unix::*`/`windows::*` |
| `heimdall-runtime` | `Config`/`Paths` (TOML + schema), `InstanceLock` (`File::try_lock`), `InstanceInfo`, `Service::{start, run}`, `Supervisor` (resource owners incl. the single cleanup executor with bounded retries, deadline scheduler, time guard), `launcher::ensure_running` (on-demand start), `telemetry::{init, redact}` | Authority semantics, operation logic, wire formats, rendering | app, ipc, store, domain, contract, tokio, toml, schemars, etcetera, tracing | as listed |
| `heimdall` (bin) | clap command tree (spec §11.1), envelope rendering and exit mapping (`output`), `service run` entry, `tui` entry (M02-T05), `schema export|show` (implemented) | Any authorization or lifecycle implementation (plan §4.1 "Interfaces") | runtime, app, ipc, contract, clap | `heimdall` executable |
| `heimdall-sshconf` (M02) | OpenSSH and Git configuration text: lexer, parser, directive table, include loader, static evaluator (`Undetermined` where it cannot know), relevant behaviour and its digest, identity selection, renderer, block editors, Git text scan, consent classification (m02-plan U1, U2) | Any I/O except its `ConfigSource` port, executing anything, private key files | domain, contract | `lex`, `parse`, `directive`, `include::{ConfigSource, ConfigSet, Roots}`, `limits`, `eval`, `relevant`, `render`, `edit`, `gitedit`, `consent` |
| `heimdall-localenv` (M02) | Discovery (paths, clients, agents, known hosts), local queries, Git observation, the passive doctor and explicit probes (U3); the projection file transaction behind `ProjectionWriter`, the projection `ResourceCleaner`, public-key files (U4); the environment snapshot shared with `launch`; the third `unsafe` module (§9) | Authority decisions, store access, wire rendering, removing any name outside its quarantine | app (ports), sshconf, domain, contract, glob, rustix (Unix), windows-sys (Windows) | `env`, `paths`, `fs`, `clients`, `agents`, `known_hosts`, `local_query`, `git`, `doctor`, `probe::*`, `projection::{LocalProjection, replace, content, recovery, git, cleaner}`, `materialize`, `sys` |
| `heimdall-adapters` (M02) | The native-agent and 1Password existing-access adapters (`CredentialAdapter` + `ProviderProbe`), passive detection, interaction states through the domain rule, consumer integration (U6) | Signing, adding, removing or locking keys; hardcoded 1Password paths (no pinned excerpt, `docs/sources/excerpts/notes.md`) | app (ports), localenv, ipc, domain, contract | `native_agent`, `onepassword`, `detect`, `state`, `integration` |
| `heimdall-launch` (M02) | The process contract: program resolution without a shell, the environment delta, side-channel run records, Unix `exec`, Windows spawn-and-wait, TUI handoff, the pre-launch eligibility check (U8) | Sending or recording `argv`, job objects for the launched child, authorization | localenv, domain, contract, tokio | `resolve`, `env`, `meta`, `unix`/`windows`, `handoff`, `eligibility`, `MAX_ARGV_BYTES` |
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
| Live events per subscriber | `EVENT_BUFFER_PER_SUBSCRIPTION` = 256 (`broadcast` capacity) | `Lagged` → one `ResyncRequired` event, backlog dropped, consumer snapshots; an event over the frame limit → `ResyncRequired` at the last delivered cursor and the subscription ends (ADR-0006 §8 ⟨r2.1⟩ N03) |
| Running operations | `app::Limits::max_running_operations` = 32 | `BACKPRESSURE` with `retry_after_ms` |
| Concurrent adapter calls | `Limits::max_concurrent_adapter_calls` = 4 (semaphore) | queued inside the operation, bounded by the operation's wait |
| Single-flight keys | `SingleFlight::with_bound(256)` | `BACKPRESSURE` |
| Retries per resource | `reconcile::Backoff::max_attempts` = 8, cap 60 s, jitter | resource `failed`, durable next step, no prompt storm |
| Frame sizes | 1 MiB control, 16 KiB hello, 256 KiB signing | reject before allocation, close |

## 5. Time model (spec §6.2, §6.4; ADR-0005 §3.6 revision 3; ADR-0006 §10) — revised by the design-fix round

* **Three injected sources.** `domain::time::Clock` gives `wall()` (UTC
  `Timestamp`), `continuous()` (boot-scoped, counts sleep: Linux `CLOCK_BOOTTIME`,
  macOS `mach_continuous_time`, Windows `QueryInterruptTime`) and `boot_id()`
  (Linux `/proc/sys/kernel/random/boot_id`, macOS `kern.bootsessionuuid`, Windows
  the Session Manager `BootId` counter [I], evidenced in M04); `domain::time::
  TimeSync` reports whether the OS says its clock is synchronized (platform stubs
  return `Unknown` until M03/M04 evidence; `Unknown` fails closed). Production
  sources live in `runtime::platform` (`SystemClock`, `SystemTimeSync`); tests use
  `testkit::VirtualClock` (advance, continuous-only advance, wall step, reboot) and
  `testkit::ScriptedTimeSync`, so virtual-clock tests drive the real gate, the real
  `Operations` and the real `Supervisor` passes.
* **Deadlines** are resolved once (`resolve_deadline`), intent kept verbatim,
  effective instant persisted in the immutable grant columns; nothing moves them.
  Ambiguous local times are refused at the human input boundary.
* **Per-grant anchors.** At activation, or at first validation in a boot, the
  runtime persists `GrantAnchor { boot_id, continuous, wall, bound, budget_end =
  continuous + (bound − wall) }`. `admission(grant_anchor, now)` is `Expired` once
  the wall clock reaches the bound **or** the continuous budget runs out, and
  `NeedsAnchor` (fail closed, not an expiry) when the anchor belongs to another
  boot. Budgets only shorten (`shorten` reduces the existing budget by the bound
  reduction, keeping any tolerance deduction; ADR-0006 §13.4 N01); they are never
  rebuilt from the wall clock; a same-boot process restart resumes from the
  persisted anchor.
* **One shared gate.** `app::TimeGate::check` (over `domain::time::gate`) runs before
  every admission, signature and issuance, in `Operations`, the signer (M03) and the
  issuer (M03) alike; there is no supervisor-private flag. It returns `Safe` and
  persists the new runtime anchor and **high-water mark** (latest accepted wall
  time, never lowered), or `Uncertain` → `TIME_UNCERTAIN` and persists nothing, when:
  within a boot the wall clock is below the high-water mark by more than
  `max_tolerated_rollback` (5 s); within a boot it disagrees with the continuous-clock prediction from the
  last accepted anchor by more than `max_tolerated_skew` (60 s) **in either
  direction** (frozen wall, step back, implausible forward jump) or the continuous
  clock went backwards; after a reboot or at first start it is not both at/above the
  mark (no rollback tolerance; ADR-0006 §13.4 N05) **and** reported synchronized, unless an attended owner confirmation covers
  this boot (`Operations::confirm_time`, attended sessions only; it never moves a
  deadline or budget). Passive reads continue with a warning while uncertain; the
  wall-bound expiry still applies (it can only deny). Tolerances are M01 defaults;
  G09 sets the final values. Server clock errors are a separate diagnosis (M03).

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

Design-fix additions: `Denial::DeadlinePassed` → `CREDENTIAL_EXPIRED`; a decision
that is consumed, expired or issued under an older generation → `DECISION_STALE`
(exit 6); a widening action or added authority always creates a decision record:
on an unattended session → `INTERACTION_REQUIRED` with `next.decision_ref`, on an
attended one → `APPROVAL_REQUIRED` with `next.decision_ref`, completed only by an
explicitly confirmed `Decide` (ADR-0006 §3.1 ⟨r2.1⟩ N04); a code unknown to the reader → `Code::Unknown(String)`,
never success, exit 1, effect `unknown` (ADR-0006 §9). `Code` is `Clone`, not
`Copy`, because of the reader fallback.

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

`unsafe_code = "deny"` at workspace level. Exactly three modules may opt in (the
third since M02, ADR-0007 §13):

1. `crates/ipc/src/windows.rs` (`#![allow(unsafe_code)]`): `CreateNamedPipeW`
   security attributes (`create_with_security_attributes_raw`), SDDL conversion,
   the client-token query (`ImpersonateNamedPipeClient` → `OpenThreadToken` →
   `GetTokenInformation(TokenUser)` → `RevertToSelf`), the remote-client check
   (`GetNamedPipeClientComputerNameW`), and the client-side server-owner check
   `handle_owner_sid` (`GetSecurityInfo(OWNER_SECURITY_INFORMATION)` on the client
   handle, `ConvertSidToStringSidW`, the returned descriptor and string released
   with `LocalFree` exactly once; design-fix second round R8). The server's SDDL
   sets an explicit owner `O:<sid>` (R6) so the check holds for elevated runtimes.
2. `crates/runtime/src/platform.rs` (`#![allow(unsafe_code)]`): the boot-scoped
   continuous clock and boot ID syscalls (`clock_gettime(CLOCK_BOOTTIME)`,
   `mach_continuous_time`/`mach_timebase_info`, `sysctlbyname`,
   `QueryInterruptTime`, the `BootId` registry read), the process-identity reads
   (`proc_pidinfo`; `OpenProcess`/`GetProcessTimes`/`GetExitCodeProcess`/
   `CloseHandle`), and, on Windows, `SetHandleInformation(std handle,
   HANDLE_FLAG_INHERIT, 0)` in `disinherit_standard_handles` so the detached runtime
   never inherits the client's stdio pipes (ADR-0006 §13.6 item 8), and, on Unix,
   the descriptor hygiene of ADR-0006 §13.8 item 7: `syscall(SYS_close_range, 3,
   ~0, flags)` (Linux x86_64/aarch64), `fcntl(F_GETFD/F_SETFD, FD_CLOEXEC)`,
   `close` and `getrlimit(RLIMIT_NOFILE)` in `disinherit_descriptors_above_stdio`
   (the launcher, before the spawn: every descriptor above 2 close-on-exec) and
   `close_inherited_descriptors` (`service run`, before it opens anything: every
   descriptor above 2 closed). Without `close_range` and descriptor listing, the
   last-resort loop runs up to the `getrlimit` **hard** limit only when it is
   finite and at most 1 048 576; otherwise both functions return an error (the
   launcher spawns nothing, `service run` refuses to start) instead of claiming a
   partial scan (review round 3, S04). Unit tests only (`platform::fds::tests`,
   never in a release build): `fcntl(F_DUPFD)` and `OwnedFd::from_raw_fd` for the
   S04 fallback test's descriptor. The module's own table lists each call with
   its invariant.

3. `crates/localenv/src/sys.rs` (`#![allow(unsafe_code)]`; M02, m02-plan U0, U3, U4).
   Wave 0 declares the module and its safe wrappers with no `unsafe` block yet; U3
   and U4 write the bodies. The calls: the account home from the account database
   (`getpwuid_r(getuid())`, never `$HOME`, ADR-0007 F19; Windows
   `SHGetKnownFolderPath(FOLDERID_Profile)` with `CoTaskMemFree` exactly once); a
   probe's process group (`killpg`, only a group this process created); kill-on-close
   job objects without breakaway (`CreateJobObjectW`,
   `SetInformationJobObject(KILL_ON_JOB_CLOSE)`, `AssignProcessToJobObject`,
   `CloseHandle` once); `ReplaceFileW` with a backup name; handle identity
   (`GetFileInformationByHandleEx(FileIdInfo)`); the adoption of `run --meta-fd`
   (`fcntl(F_GETFD)`, `fstat`, `OwnedFd::from_raw_fd`, `FD_CLOEXEC`); and **the only
   removal in the crate**, `QuarantineDir::remove_verified` (Unix `openat`/`fstat`
   then `unlinkat` relative to the validated `.hm-quarantine` directory handle;
   Windows `SetFileInformationByHandle(FileDispositionInfoEx)` on a handle whose
   identity was checked), which removes an entry only when its identity and digest
   equal the expected ones at removal (ADR-0007 §5.3). The atomic exchange and the
   no-replace rename on Unix are **not** here: they go through rustix's safe
   `fs::renameat_with` (m02-plan §6 P5; `dependencies.md`). The module's own table
   lists each call with its invariant.

Each call is wrapped in a safe function with its invariants documented; no `unsafe`
leaves any of these modules. Unix IPC needs none (tokio provides `peer_cred`; std
provides file locks and permission bits).
Dependencies' internal `unsafe` is not audited by this document (REPORT.md §8
lesson); `cargo-deny`/`cargo auditable`/OSV scanning are M08 obligations
(ADR-0002 §11).

## 10. Lints, build hygiene, validation

* Workspace lints: `unsafe_code = deny`, `missing_docs = warn`, `unused_must_use =
  deny`; clippy `all`, `unwrap_used`, `expect_used`, `dbg_macro`, `print_stdout`,
  `print_stderr`, `unimplemented` as warnings; CI runs clippy with `-D warnings`, so
  they are errors in practice. `clippy::todo` is allowed only while a skeleton
  exists: M01 left none, and the M02 skeleton (m02-plan U0) uses it only where no
  request, CLI command, restart recovery or store method can reach (re-enable as
  `deny` when M02 closes). `clippy.toml` raises
  `large-error-threshold` to 1024 for `OpError`.
* One target dir, `./target` (gitignored); never `CARGO_TARGET_DIR` overrides
  (AGENTS.md). Toolchain pinned in `rust-toolchain.toml` (1.99.1, edition 2024,
  resolver 3). `Cargo.lock` committed; CI uses `--locked`.
* `tools/validation/check.sh`: `cargo fmt --all --check`, `cargo clippy --workspace
  --all-targets --locked -- -D warnings`, `cargo test --workspace --locked`, the
  generated-schema diff (two exports must match each other and
  `schemas/public-api/`), and a zero-test guard: any non-doctest test target that
  reports `running 0 tests` fails the run (review F09). Each step prints its real
  exit code.
* **Test-target convention (review F09).** Every planned suite is a real Cargo
  `[[test]]` target whose source lives under the repository `tests/{model,
  contracts,integration,adversarial,e2e}/` tree (plan §7.1 layout), declared with
  `path = "../../tests/..."` in the crate that already has the needed dependency
  edges (`heimdall-testkit` hosts the model and store suites, `heimdall-contract`
  the contracts suite, `heimdall-ipc` its integration/adversarial suites). No
  `#[path]` inclusion into unit-test modules; items a suite needs are `pub`
  (`#[doc(hidden)]` when not part of the public surface). Pipeline faults are
  injected through production code (`OperationsConfig.stage_hook`,
  `Store::open*(faults)`), never through test-only code paths.
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
