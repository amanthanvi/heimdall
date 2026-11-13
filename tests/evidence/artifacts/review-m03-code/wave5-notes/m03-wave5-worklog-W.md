# M03 wave 5 -- worker W (integrator-owned test rewrites) worklog

Scope: tests/e2e/cli_m03.rs (parent), m03_cmd.rs `mod tests` + stale docs + internal_issuer_envelope,
cli.rs doc comments, guard test no_m03_source_contains_the_wave_0_text. Not R's `internal session-lock-state` arm.

## Probe (real binary, cleared env, scratch home that does not exist, stdin /dev/null, --json --non-interactive)
- issuer init/rotate begin/restore/unlock (all forms): exit 3 INTERACTION_REQUIRED, effect none
- issuer status, issuer bundle (both): exit 5 SERVICE_UNAVAILABLE; issuer retire SHA256:abc: exit 2 (invalid CA fingerprint)
- enroll lab (bare): STARTS a detached runtime -> dropped. enroll lab ... --ca fp: exit 2 (invalid CA fingerprint)
- enroll status: exit 5; verify/remove ID/reconcile/abandon with enr-1/op-1: exit 2 (invalid ID); remove --from-bundle f: exit 2
- destination prefer lab managed|existing: STARTS a runtime (NOT_FOUND exit 2 after contact) -> dropped (covered by access.rs)
- access ensure --strict / lock-behavior / connection-policy with valid IDs: START a runtime; with an invalid ID ("BAD ID") they
  answer USAGE_ERROR exit 2 before contact -> use the invalid-ID form; connection-policy w/o flags: exit 2 (usage)
- connections: exit 5; connections close conn-1: exit 2 (invalid connection ID)
- internal session-lock-state: wave-0 text still (R's arm); internal issuer: exit 5, stdout empty
- My probe started 8 runtimes in /tmp/w-probe homes (destination prefer x3 incl. one "BAD ID", ensure, policy lines);
  each stopped via `heimdall service stop` against that exact home (pids reported in the stop answer), none remain.

## Edits (done)
- tests/e2e/cli_m03.rs: header (wave 5, submodules); `w0_m03_cli_commands_report_not_available_and_never_panic` ->
  `m03_cli_commands_answer_without_a_runtime_and_never_panic` (table ANSWERS_WITHOUT_A_RUNTIME: line, exit, code);
  gates test: debug abs-dir case asserts exit 2 + HEIMDALL_TEST_SCRIPT_PAUSE_DIR; uninstall --bundle case asserts exit 4
  CAPABILITY_UNAVAILABLE bundle_required, enrollments len 1, db unchanged, no run/ (plain uninstall has no case in that test);
  new `no_m03_source_contains_the_wave_0_text` (word-sequence scan + the "not_available" / "(planned for M03)" halves).
- m03_cmd.rs: header docs; `internal_issuer_envelope(false)` is a plain usage error ("internal issuer runs only as the
  runtime's child"); tests: `the_wave_0_envelope_is_m01s` -> `m03_internal_issuer_envelopes_carry_no_wave_0_text`;
  `internal_issuer_refuses_tty_stdin` kept (asserts the pipe message); `m03_lines_answer_without_touching_the_home` uses the
  real exit class per line (table ANSWERS_WITHOUT_A_RUNTIME, `BAD ID` forms), no run/ dir.
- cli.rs: module doc, `AccessEnsureArgs.strict` doc (it is `--help` text: golden access-ensure.txt line updated by hand),
  a test comment. No code change.
- Waiting on R: `internal session-lock-state` arm still returns the wave-0 envelope -> the e2e table test (its
  session-lock-state check) and the guard fail with that reason until R lands.

## Final (R's arm landed)
- Removed m03_cmd::{not_available_message, not_available_envelope} (no callers). e2e session-lock-state check: exit 0, OK,
  data.source platform, state in the four wire names, no home/run.
- Guard revert proofs (shasum-verified): probe file in tui/ with the text -> guard exit 101, removed -> 0; wave-0 text in
  internal_issuer_envelope -> unit tests 101 + guard 101, restored (sha identical afc77655...) -> 0/0.
- Final: e2e_cli_m03 31 passed, 2 ignored (umask 022 and 002); bin m03_cmd 11 passed (both umasks); clippy host exit 0.
- /tmp/w-probe scratch removed; no runtime left (8 probe runtimes stopped with `service stop` on their exact homes).
- Note: one full-suite run overlapped R's own revert proof of the session-lock-state arm (m03_cmd.rs transiently
  "reverted: wave-0 refusal"): 2 failures then, both gone on rerun.
