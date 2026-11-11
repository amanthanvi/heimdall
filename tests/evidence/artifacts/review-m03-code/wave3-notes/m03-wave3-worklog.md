# M03 wave 3: worklog (untracked; integrator + units)

## Integrator
- Goal: U6 (managed adapter) + U7 (connection control) to m03-plan §1 and ADR-0008 (rev 6, §17
  rulings win), one integrated uncommitted change set + report. Base `1b5c1758`.
- 2026-11-11: read plan §0–§5, §7; ADR D6–D8, D10, D12, §17.3/§17.4/§17.17–§17.19; wave-2 API notes.
- Scaffolding landed (see `.m03-wave3-api.md` §0). `cargo check -p heimdall-adapters -p heimdall-runtime --tests` → 0.
  `Cargo.lock` delta: only heimdall-adapters' dependency array (+issuer, +store, +proptest, +tempfile); no package.
- Readings R1–R9 written; W3-Q1 recorded.
- Next: spawn U6 and U7 agents (Opus), in parallel; U6 lands its declared `files`/`report` names first.

## U6
- Goal: m03-plan §1 U6 (managed adapter) under ADR-0008 D6/D7/D10/D12 + §17.3/§17.4/§17.17–§17.19; owner paths
  `crates/adapters/src/managed/*`, `tests/integration/managed_adapter.rs`.
- 2026-11-11: read brief, api (R1–R9), plan §0/§1 U6/§3/§5 items 7–9 + 19, ADR-0008 D6/D7/D10/D12, §17.3/§17.4/§17.17–19,
  ADR-0005 §3.4/§3.7/§7.2, wave-2 api notes; code: app::ports, app::managed, credential::{table,endpoints,vault,cert},
  localenv content/sys, connect_cmd::binding_files, run_cmd::ManagedSlots, store ext_m03 slot API.
- Step 1 landed: `files` (paths, atomic generation-marked writes/clears) + `report::{owned_connection_reports,
  revoke_notes, owned_multiplexing}`; `cargo check -p heimdall-adapters` → 0. Signatures appended to the api file.
- Decision: generation marker `.generation` = `<g> <binding-id>`, written first, removed last; a clear of g leaves
  any other generation untouched; one process lock serializes writes and clears.
- Request filed: `ssh-key = { workspace = true }` in adapters `[dependencies]` (install needs `ssh_key::Certificate`;
  no parser in heimdall-credential). U6-Q1.

- U6-Q1 resolved without a manifest change (`line.parse()` infers `ssh_key::Certificate`); request withdrawn.
- Step 2 landed: `prepare` (source trait `ManagedSourceRead`, outcome computation), `reissue` (pure §3.7),
  `report::compute` + residual/removal functions, `effects::ManagedEffectsImpl` + `ManagedSlotTable`/`SlotStore`,
  `ManagedCertificateAdapter` (mod.rs). Questions U6-Q2…Q6 written (fail-closed choices taken).
- Decisions: `owned_multiplexing` `disabled` on every platform when the policy disables masters (the §5 golden is
  a Windows result), `unavailable` only for `owned_masters` on Windows; the revoke result moves no residual status
  on the caller's `now` (`REVOKE_MOVES_NO_RESIDUAL` comment; the cleanup-intent path passes a raw wall read);
  D6 item 7 uses the claim's presence (`lock_claim_verified`) so `revoke_on_lock` gives `lock_revokes_chosen`.
- Tests: `tests/integration/managed_adapter.rs`, 37 tests + the no-op issuer-child entry; fixture driver
  (`World::drive`), fixture install view, fixture endpoints, narrowing hook calling the real adapter's revoke.
- Commands (2026-11-11, macOS arm64): `cargo check -p heimdall-adapters --tests` → 0;
  `cargo test -p heimdall-adapters --test integration_managed_adapter` → 0 (38 passed);
  `cargo test -p heimdall-adapters --lib` → 0 (18 passed); `cargo clippy -p heimdall-adapters --all-targets -- -D warnings` → 0;
  Windows clippy (script via `bash -c`, see Requests) → 0; `bash tools/validation/linux-xcheck.sh -p heimdall-adapters` → 0;
  `rustfmt --check --edition 2024` on U6 files → 0 (`cargo fmt --all --check` → 1, only `tests/integration/connections.rs`, U7's).
- `du -sh target` → 11G (shared by U6/U7/integrator; not pruned: the brief forbids deleting `target/`).

## U7
- Goal: m03-plan §1 U7 (connection control) under ADR-0008 D8, D7 item 2 steps 4/6, D10 items 2–5, §17.3 item 1,
  §17.4 items 7/8, §17.19 item 4; readings R4, R8, R9. Owner paths only.
- Landed: `crates/localenv/src/sys/mod.rs` (`JobObject::{spawn_suspended, contains_pid}`, `SuspendedChild`,
  `ContainedChild`, `ProcessPin`, `VerifiedProcess`, `ProcessSignal`; module table + overview §9 item 3 rows);
  `crates/launch/src/windows.rs` (`launch_uses_kill_on_close_job`, `spawn_contained_and_wait`, `Registration`,
  `ContainedFailure`); `crates/heimdall/src/run_cmd.rs` (R9: the Windows refusal replaced by the contained path with
  the production `Connections::Register` registrar, which fails closed until U10); `crates/runtime/src/connections.rs`
  (`ConnectionSupervisor` + passes); tests `tests/integration/connections.rs`, `tests/e2e/deadline_m03.rs`.
- Decisions: (1) start tokens compared only against their writer's source (Unix `platform::process_start_time`,
  Windows `created_at.to_string()` read on the pinned handle), so `sys` exposes no Unix start-time reader; (2) a
  matching token with another image is `Pending` (not signalled, row `closing`, retried), a different token at the
  PID is `Unverified`; (3) masters are std children (a dropped supervisor leaves them running for the restart
  pass) behind a kill-on-drop guard while starting (drop contract); (4) each master has a `ManagedResource`
  (`process`, owner binding, id `res_<conn suffix>`, locator = JSON `MasterLocator` with alias and socket inode),
  which is also the index for the replacement generation and the restart pass (U7-Q4); (5) a socket at the slot
  path that no verified master owns refuses the start (`mux_path_occupied`), never removed; (6) Windows dedicated
  rows are cleared by `reap_pass` (U7-Q2).
- Blocked: U7-Q1 (runtime → sshconf edge). Messaged the integrator. Until it is applied, `heimdall-runtime` (and so
  `heimdall`) does not compile in this tree. Development runs use `/tmp/u7-tools/stubcheck.sh`, which, for the
  duration of one command, replaces only the sshconf call in `master_argv` by a stand-in producing the same
  CertificateAsIdentityFile options and `OWNED_LAUNCH_PINS[0..2]`, and drops the one test that renders P
  (`enabling_masters_needs_decision_and_setup_apply`); it restores both files byte for byte afterwards. Those runs
  are development evidence only, not the product argv.
- Commands (exit codes, all from this worktree):
  - `cargo check -p heimdall-localenv --tests` → 0; `bash /tmp/u7-tools/xwin.sh -p heimdall-localenv --all-targets`
    → 0; `bash tools/validation/linux-xcheck.sh -p heimdall-localenv` → 0 (sys primitives, before any stub).
  - stubbed: `cargo check -p heimdall-runtime -p heimdall-localenv -p heimdall-launch -p heimdall --tests` → 0;
    `cargo clippy -p heimdall-localenv -p heimdall-launch -p heimdall-runtime -p heimdall --all-targets -- -D warnings`
    → 0; Windows clippy (same four, `--all-targets`) → 0; `linux-xcheck.sh -p heimdall-localenv -p heimdall-runtime`
    → 0; `cargo test -p heimdall-localenv -p heimdall-launch -p heimdall-runtime --lib` → 0;
    `cargo test -p heimdall --bin heimdall run_cmd` → 0 (3 passed); `cargo test -p heimdall --test e2e_deadline_m03`
    → 0 (1 passed; the `windows_*` tests are `cfg(windows)`).
  - stubbed (sshconf call returning no identity options): `cargo test -p heimdall-runtime --test
    integration_connections` → 101, 25 passed, 2 failed (`owned_master_pins_fork_after_authentication_no`,
    `master_start_failure_retried_bounded_jittered_and_clients_connect_directly`: both need the identity options
    the stub omitted). With the stand-in identity options (`TMPDIR=/tmp`, `--test-threads=4`): → 0, 27 passed
    (every plan test of this target except `enabling_masters_needs_decision_and_setup_apply`, which the stub
    removes because it renders P through sshconf). Observations (OpenSSH_10.5p1, LibreSSL 3.3.6): `-O stop` exit 0,
    master alive, pre-accepted session alive, control socket removed, a new session connects directly (new auth),
    a later `-O exit` exit 255 (U7-Q5); `-O exit` exit 0, master gone, pre-accepted session ended, socket removed;
    remote `sleep` alive after the close; a forward through the master gets no forwarded channel.
  - `cargo fmt --all --check` → 0 (after `rustfmt` of U7's files only).
  - `du -sh target` → 11G (shared by U6, U7 and the integrator; holds `x86_64-pc-windows-gnu` and
    `x86_64-unknown-linux-gnu` from the cross-checks). Not pruned by U7 (brief: do not delete `target/`).
  - `/tmp/u7-tools` (xwin copy, stubcheck) and U7's `/tmp/u7-*.log` removed at the end.
- After U7-Q1 is applied, the evidence runs are: `cargo check -p heimdall-runtime -p heimdall-localenv -p
  heimdall-launch -p heimdall --tests`; `TMPDIR=/tmp cargo test -p heimdall-runtime --test integration_connections`;
  `cargo test -p heimdall --test e2e_deadline_m03`; clippy host and Windows on the four packages; linux-xcheck on
  localenv and runtime.
- U7 note (2026-11-11): `.m03-wave3-xcheck-windows.sh` lives at the worktree root but keeps
  `cd "$(dirname "$0")/../.."` from `tools/validation/`, so run as documented it exits 101
  ("could not find `Cargo.toml` in `<home>/.t3/worktrees`"). U7 runs an identical
  copy (`/tmp/u7-tools/xwin.sh`, removed at the end) whose only difference is
  `cd <this worktree>`.

## Integrator (after the units)
- U6 and U7 agents returned (Opus). U7-Q1 applied: `crates/runtime/Cargo.toml` `heimdall-sshconf = { workspace = true }`
  (production edge; sshconf already in runtime's graph through localenv; Cargo.lock: only runtime's array). The helper
  `.m03-wave3-xcheck-windows.sh` `cd` fixed (it kept clippy-windows.sh's `../..`; both units ran a corrected copy).
- `cargo check -p heimdall-runtime -p heimdall --tests` → 0. `TMPDIR=/tmp cargo test -p heimdall-runtime --test
  integration_connections` → 0, 28 passed (first run of U7's suite on the real code; the units' runs used a stub).
- Integrator review fix (`connections.rs` `terminate_verified`): macOS pins nothing, so the identity is re-verified
  right before the SIGKILL that follows the 5 s grace (Linux/Windows keep their pin).
- `TMPDIR=/tmp bash tools/validation/check.sh` → **exit 0**, every step 0 (fmt, clippy, clippy-windows, crate-graph,
  claims-table, test, test-discovery, schema, release-gate, native-harness-selftest 316/0, evidence-selftest,
  evidence-records): 2556 passed, 0 failed, 188 ignored over 97 targets.
- `bash tools/validation/linux-xcheck.sh --workspace` → 0.
- Scan of every changed/new file: no `HEIMDALL_CANARY_*` value, home path or private key; no Docker image left.
