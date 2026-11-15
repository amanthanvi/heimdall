# M03 wave 5 round 3 — worker K3 (issuer ceremonies) worklog

Scope: §17.27 items 5, 6, 7, 8, 10, issuer half of 4 (+ §17.26 item 6), item 3 for ceremonies.
Owner files: crates/issuer/src/** (not bundle*), crates/heimdall/src/issuer_cmd{.rs,/**},
tests/e2e/cli_m03/issuer.rs, tests/e2e/issuer_ceremony.rs, issuer_store.rs RegisterDecision ctor,
new release-gate integration test (Cargo.toml [[test]] entry = integrator request).

## Decisions
- Tty trait: additive `read_answer(hidden) -> io::Result<TtyRead>` (Line/Eof/Cancelled/TimedOut)
  with a default impl over read_line/read_hidden, so issuer_store.rs's ScriptedTty is unchanged.
- ControllingTerminal::open(prompt_timeout): the CLI passes `prompt::PROMPT_TIMEOUT` (no second
  constant). Bounded read = reader thread on a cloned fd + recv_timeout; timed-out terminal is
  spent (every later read = TimedOut, a late `yes` is never honoured).
- Sanitizing: CLI wraps the controlling terminal (`SanitizedTerminal`): every write_text goes
  through `output::sanitize_for_terminal` (zeroizing buffer); clear_lines (the ceremony's own
  secret-display clearing) passes raw. Covers paths, runtime strings, lock text, locators.
- lock text: WireSession::register fetches `inspect capabilities` when the decision carries
  lock_continuity_once → D3 helper → RegisterDecision.lock_text; ceremony refuses
  (LockDisclosureUnavailable, exit 3) when needed text missing/blank.
- Retire's typed confirmation = ordinary `setup_cmd::confirm_and_decide` (stdin, ask_within,
  ctx.interactive checked) → not a ceremony read; unchanged.

## Progress
- [x] issuer crate; retire (item 10) + release gate; CLI; tests; reverts; umask 002; clippy host,
      windows (0), linux-xcheck -p heimdall-issuer -p heimdall (0). Temp copy removed.
- Open: K3-R1 ([[test]] entry), K3-R2 (target size), K3-Q1 (Windows Ctrl-C, U13).

## Commands (exit codes)
- issuer crate + retire + release-gate file + CLI session: implemented, build 0.
- cargo test -p heimdall-issuer --lib: 0 (18). --release --lib: 0 (17).
- release gate via TEMP copy crates/issuer/tests/k3_tmp_release_gate.rs (DELETE before finishing;
  real file tests/integration/issuer_release_gate.rs, [[test]] = K3-R1): --release 0 (3), debug 0 (3).
- Revert A (TEST_STORE_DELETION=true): release gate 101 (2 failed); restored 0, sha same.
- Revert B (old inline const assert): release --lib compile 101 (E0080); restored 0, sha same.
- e2e_issuer_ceremony: 0 (8 + 2 ignored) incl. 4 new.
- Revert R1 (recv() unbounded): e2e_issuer_ceremony times_out 101 (2 failed, 31 s); restored.
- Revert R2 (Eof/Cancelled → wrong answer): at_written_cancels 101 (2 failed); unit written_retries 101.
- Revert R3 (generic lock text, no refusal): unit register_decision_needs_the_runtime_lock_text 101.
- ceremony.rs sha 7f92ebd5… before/after each revert; restored lib 0 (18), e2e 0 (8).
- e2e_cli_m03 issuer::: 0 (15) x5 runs (2 at umask 002); 1 run of 6 had 3 product-store tests
  fail with issuer_store_locked at the store step (IS2's r2 notes saw the same once; pre-existing
  keychain flake under parallel tests). Keychain search list/default digests equal before/after.
- CLI reverts (session.rs sha 45ee077c…, ceremony.rs 7f92ebd5… restored each): C1 no interactive
  check 101; C2 raw writes 101; C3 lock text None 101 (2); C4 cancel=wrong answer 101; C5 generic
  lock text 101 (2).
- issuer_store.rs: + `foreign_removals: Vec::new()` (U3 request); integration_issuer_store 0 (30).
- clippy host: issuer --all-targets 0; heimdall bin + e2e_cli_m03 + e2e_issuer_ceremony 0; bin
  --profile test 0. clippy-windows.sh 0 (after cfg(unix) on exits_within). linux-xcheck 0.
- full e2e_cli_m03: 0 (54 + 3 ignored). heimdall bin `issuer` unit filter 0 (5).

## Follow-up: issuer_store_locked flake (orchestrator task)
- Cause: on-disk binary replaced by concurrent cargo builds (shared target) → item ACL trusts new
  file → CLI read-back errSecAuthFailed (-25293) → issuer_store_locked + orphan item. Repro (copy
  binary, swap a re-signed copy at `written`): 5/5 exit 4 issuer_store_locked, probe code -25293.
- Probe: keychain stays unlocked ≥ 40 s in-process and cross-process (settings: no timeout/sleep lock).
- Fix: sys.rs running_code_satisfies before SecKeychainItemCreateFromContent; StoreError::
  ExecutableChanged → SERVICE_UNAVAILABLE. Revert: regression 3/3 exit 101 (issuer_store_locked);
  restored 3/3 exit 0; sys.rs sha 20bcc885… same.
- Fixture: Rig::program snapshot. 20/20 consecutive issuer:: runs pass (threads=4, fixed binary);
  with a swapper replacing the program every 0.4 s: fixed fixture 10/10 pass (5 at umask 002);
  snapshot reverted: 5/5 runs fail (2–6 tests each; executable-replaced and issuer_store_locked).
- clippy host issuer/heimdall 0; windows 0; linux-xcheck 0; issuer lib/store/release-gate 0;
  e2e_issuer_ceremony 0. Keychain digests unchanged. Temp probe files removed.
