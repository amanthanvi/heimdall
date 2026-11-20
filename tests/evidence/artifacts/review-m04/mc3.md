FIX FIRST (M04-MC3-R01)

Candidate `0cea2ad307a56535527744754649038edba2e9f8`. Reviewed the first-parent range after `37cb179b` and compared the merge against `31aadbea` and `2b79aac1`. The M04 merge edits are the listed-spawn flags and the issuer client merge resolution that preserves its separate listed and ordinary spawn paths.

## M04-MC3-R01 — A replacement helper can make `ensure` return an untrusted config path

**High. Blocking under ADR-0009 §2.1.** An ordinary helper crash and runtime-directory turnover can make Heimdall vouch for an SSH configuration under another account’s control. The configuration governs remote trust.

- `crates/wsl/src/bridge/linux.rs:157` chooses a run base for each helper session. `crates/credential/src/endpoints/wsl.rs:277` stores the first helper’s socket path. `crates/adapters/src/managed/effects.rs:1180` renders the config using that path. `crates/runtime/src/wsl_bridge.rs:466` discards the realization’s returned paths after `crates/wsl/src/bridge/session.rs:327` checks them against the **current** helper’s base. `crates/app/src/operations/container_m04.rs:848` derives the returned `ssh_config` path from the stored endpoint.
- Suppose `ensure` records an endpoint under a private XDG runtime directory. Its helper dies before realization, and the volatile XDG directory disappears. The same request can start a replacement helper, which selects the home fallback and successfully realizes the tag there. The request returns `ACCESS_READY` with the old XDG socket and config paths. This also affects the replay of live bindings on helper respawn. If the old base is now replaceable by another account, the emitted `ssh -F` path can point to a configuration outside the owner’s control. If the old base is simply absent, the returned endpoint is unusable.
- Smallest fix. Bind each endpoint generation and replay entry to the run base used to render it. If a replacement advertises a different base, refuse realization or replay of that generation and invalidate the stale endpoint. Publish a new locator only after rendering and realization agree on the new base.
- Test. Extend the existing fake-bridge harness to return two distinct run bases, losing the first helper between endpoint creation and realization. Assert that an `ensure` cannot return the old paths as ready and that respawn cannot silently replay a binding at a different locator. The existing owner-start test loses the helper before endpoint creation and gives both helpers the same path.

## M04-MC3-R02 — The fallback writes through ancestors before checking them

**Medium. Nonblocking under ADR-0009 §2.1.** The deterministic failure leaves empty directories and can misreport the refusal. The checked path refuses before writing binding material or returning a usable endpoint.

- `crates/wsl/src/bridge/linux.rs:407` creates the anchor and `run` before calling `secure_chain` at line 423. `crates/wsl/src/helper/mod.rs:191` creates missing ancestors with a path-based recursive `DirBuilder`. That can traverse existing symlinks before the chain walk rejects them. For example, if the configured state base is a missing child of the rejected world-writable XDG directory, realization creates `state/heimdall/run` there, then refuses. An unsafe anchor already present can also return `wsl_helper_state_unsafe` before reaching the combined diagnostic.
- Smallest fix. Check existing ancestors first and create missing components relative to validated directory handles. Validate the created or racing-existing entry before descending. Keep the existing root-owned symlink rule and use the combined refusal for an unsafe fallback when XDG was rejected.
- Test. Strengthen `mode_b_refusal_names_both_when_xdg_runtime_dir_and_the_home_base_are_unsafe` at `crates/wsl/src/channel_tests.rs:929` to assert that `state` itself was never created. It currently checks that `run/b` was never created. A symlink fixture can also assert that the target remains untouched.

## M04-MC3-R03 — The issuer pipe diagnostics are active in release

**Low. Nonblocking under ADR-0009 §2.1.** The new runtime entries record operational metadata only, with no authority or owner-data impact.

- `crates/issuer/src/client.rs:270` and `:310` emit first-read and first-write byte counts and a write-success bit through ordinary `tracing::info!` calls. A detached release runtime installs an INFO-level file sink by default (`crates/heimdall/src/service_cmd.rs:217`, `crates/runtime/src/telemetry.rs:112`), so these calls can record entries during normal issuer startup. The child’s separate phase file is inert in release (`crates/heimdall/src/m03_cmd.rs:357`). Its fields are PID, fixed phase names and times. The pump entries carry counts and a boolean. The earlier startup entries carry timings, fixed outcomes and an exit code. I found no frame contents, nonce, key material, or secret values in those fields.
- Smallest fix. If the pipe entries are intended to be test-only as specified in the review brief, use the debug test gate at the pump call sites. The child phase file already has the release guard.
- Test. The existing release gate checks refusal of test configuration. An isolated release startup would need to assert that ordinary runtime logs omit the two pump entries.

## M04-MC3-R04 — The debug phase recorder opens before the scratch-home guard

**Low. Nonblocking under ADR-0009 §2.1.** The direct debug entry point can leave a diagnostic file in the installed state directory. The new write contains fixed phase metadata and leaves existing credential and recovery records intact in the ordinary case.

- `crates/heimdall/src/m03_cmd.rs:405` opens and appends the phase file before reading the database or validating the test store at line 421. `crates/heimdall/src/cli.rs:1483` dispatches `internal issuer` directly. A debug invocation with piped stdin and a test variable but no explicit Heimdall home can append a phase to an existing default state directory, even if the requested test store is later refused. The `service run` scratch-home guard at `crates/heimdall/src/service_cmd.rs:195` never runs on this entry point.
- Smallest fix. Apply the existing `testcfg::home_refusal` during the issuer child’s early test gate, before resolving paths or opening the log.
- Test. Add a debug issuer-entry regression for a requested test configuration with no explicit Heimdall home. Resolve the default state path inside a disposable fixture and assert refusal before the phase file is opened. The existing Windows timing test supplies an explicit home.

## Other reviewed paths

- Owner start. New activation gets its own operation kind through the effect token. An attached follower derives authority from its own operation, and both endpoint creation and realization forward it. Delegation, reissue and slot materialization use `Forbidden`; the shared bridge boundary then performs background admission when it needs a helper. The runtime’s startup recovery runs before Mode B bridge wiring is installed. The existing fake-bridge test exercises loss after the initial owner start and before endpoint creation. R01 covers the later loss window.
- Filesystem and socket bounds. `ManagedDir` pins the owner-controlled anchor and opens children relative to it. Mode B checks the binding directory’s device and inode before file writes and again after binding the socket. The same lexical chain walk is used for the chosen base, subject to R02’s creation order. `check_realize` measures the complete socket path in bytes on both sides and refuses paths over 103 bytes before the helper writes. The existing long-path regression exercises the runtime-side refusal.
- Windows handle inheritance. The detached launcher supplies three fresh `NUL` handles. The same three handles occupy `STARTUPINFOEXW`’s standard streams and the explicit inheritance list. Owned handles and the attribute list unwind on partial failure, and launch failure propagates out of the readiness loop. The positive-control test checks caller-pipe EOF and that the runtime stays alive. `98f13db9` adds evidence for this path, whose implementation predates the range.
- Windows console flags. The production listed issuer, verification `ssh -G`, WSL helper, and bounded `wsl.exe` commands all supply `CREATE_NO_WINDOW` via `ListedSpawn`. The detached runtime uses `DETACHED_PROCESS`. Foreground launch uses the existing console-aware path. The E9 console test is designed to check a live issuer. Direct evidence for the short-lived WSL and verification children and console attachment for interactive launches requires Windows.

## Checks and exit codes

- `git fetch origin m04/w2 m03/wave6` → 0. `git rev-parse` pinned `origin/m04/w2` to the target. `git merge-base --is-ancestor 2b79aac1 origin/m03/wave6` → 0. The fetched M03 ref is newer than the actual second parent.
- `git log --first-parent 37cb179b..0cea2ad3` and `git diff` against the pre-merge head and both merge parents → 0. `git show --remerge-diff 0cea2ad3 -- crates` → 0.
- `git diff --check` for `37cb179b` to `31aadbea` and for each parent to the merge, restricted to `crates/` → 0 for each comparison.
- Candidate Git-object reads and call-site searches, plus a `python3` check of the candidate’s create-before-check ordering and per-session path checks → 0 for the check. The Python check also used a disposable macOS directory fixture to confirm the directory-creation premise of R02. It did not execute Heimdall or simulate a Windows/WSL run.
- `git status --porcelain=v1` → 0, clean. No Cargo build or product test was run. The checkout belongs to a different head, so the review used the requested candidate’s Git objects. Windows and WSL conclusions are from source. No SSH, runtime or remote host was used.
