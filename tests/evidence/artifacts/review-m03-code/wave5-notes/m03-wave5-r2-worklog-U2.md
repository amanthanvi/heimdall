# M03 wave 5 round 2 — worker U2 worklog (uninstall, doctor, chores)

Owner files: `crates/heimdall/src/{uninstall_cmd,doctor_cmd}.rs`, `crates/localenv/src/doctor.rs`,
`tests/e2e/cli_m03/uninstall_doctor.rs`, `crates/heimdall/src/cli.rs` `UninstallArgs` only.

## State
- [x] Read brief, api.md, §17.25, round-1 U worklog, Q-U1..Q-U5.
- [x] Item 8 uninstall digest match (BUNDLE_WRITE_RECORD_REQUIRED removed) — code + unit test
- [x] Item 9 inline retire via IS2's in-flight `issuer_cmd::retire_to_retired` — code + unit test
- [x] Item 11 plain-uninstall ack via --keep-remote-enrollments (cli.rs UninstallArgs); PLAIN_UNINSTALL_ACK_REQUIRED removed
- [x] Item 12 chore = TimeGate::assess_read_only_in → Unsynchronized && CA registered — code + unit test
- [x] Item 13 three doctor findings — code + unit test (client trace)
- [x] e2e tests: 10/10 uninstall_doctor pass (umask 002)
- [x] revert proofs R1–R8 (each exit 101, restored sha match)
- [x] clippy host (localenv, heimdall all-targets) 0; clippy-windows 0; linux-xcheck blocked by IS2's
      `issuer/src/store/test_product.rs:162` dead code (retrying)

## Decisions
- Item 8: content check also requires every registered CA listed in its current state (CA state
  changes carry no timestamp; "no earlier than the last CA change" read fail-closed). Last CA
  change = max(created_at, backup_created_at, retired_at). Digest = sha256_hex of exact bytes.
- Item 8 test seeds the digest through `Txn::record_bundle_digest` (the real `issuer bundle` path
  needs a runtime; never started here).
- Item 9: inline retire only on an interactive terminal; otherwise nothing is sent (no pending
  RetireIssuer decision left behind), item stays `deletion_offered` + `retire.ran=false`.
- Item 11: `--bundle` now `requires_all = [keep_remote_enrollments, purge_state]`.
- Item 12: "registered" CA = state not deleted/retired. TimePolicy::default() (the runtime's default).
- Item 13: enrollment facts: stale = verified && (no evidence || fresh_until <= now);
  inconclusive = last two enrollment events reverifying→verified by one op X and evidence.operation != X;
  reason from op X's error (when still stored). client_trace finding gated on a CA registered (Q-U2-1).

## Commands (exit codes)
- `cargo check -p heimdall-localenv -p heimdall --tests` exit 0 (after R2's transient app error)
- `umask 002; cargo test -p heimdall --bin heimdall -- uninstall_cmd doctor_cmd` exit 0: 20 passed
- e2e_cli_m03 full: 40 passed, 2 failed (integrator's m03_cli_commands_... at :380 — expected, item 11;
  IS2's issuer_init_prints_passphrase_only_to_tty — not mine)
- e2e_cli_m02 uninstall 0 (8 passed), doctor 0 (2 passed)
- localenv integration_doctor 101: 4 failed (a21_* x3, home_resolution_matches_ssh_g) — same 4 fail with
  HEAD's localenv/src/doctor.rs swapped in (exit 101), so not from U2's change (host ssh behaviour)
- revert proofs via /tmp/u2-revert/revert.py (removed after)
- linux-xcheck -p heimdall-localenv -p heimdall: 101 x12 (IS2 test_product.rs:162 dead code); not confirmed
- clippy-windows.sh 0; removed target/x86_64-pc-windows-gnu afterwards
- rustfmt --edition 2024 applied to my three owned .rs files (localenv doctor.rs and cli.rs already clean)
