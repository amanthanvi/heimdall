# M03 wave 5, round 2 — worker IS2 (issuer) worklog

Scope (R1 row IS2): §17.25 items 7 (b)+(d), 8, 9, 10. No commits. Status: **done** (see api.md
"### IS2", Requests IS2-R1..R4, questions Q-IS2-1..5).

## Decisions
- Selector `HEIMDALL_TEST_SECRET_STORE=product-file:<abs path>`; macOS file keychain, Windows DPAPI
  dir, Linux refused at parse. Checks in `heimdall_issuer::store::test_product::refusal` (debug-only
  module); selection `testcfg::test_store` → `TestStore`; `m03_cmd::issuer_store(.., &TestStore)`.
- "Created by this test" = marker `<path>.heimdall-test-store` made first (O_EXCL, 0600, names the
  store) + birth-time order + same uid as the home (Q-IS2-1). Scratch home = explicit HEIMDALL_HOME,
  not the account home or an ancestor.
- Runtime selection: inherited env of `internal issuer` → same selector; no service.rs edit.
- 7 (d): `retire::TEST_STORE_DELETION = cfg!(debug_assertions)`; S3 switch + mirror removed.
- 8: `record_bundle_written` (refuses non-hex / future created_at); CLI confirms unredacted only,
  after sync_all (+ dir fsync best effort); refusal = runtime envelope, file kept.
- 10: `disclosure_text(kind, &DisclosureContext{alias, lock}) -> String`, `UNKNOWN_DISCLOSURE`.
- Ceremony reads: ISIG off + VEOL=ETX so Ctrl-C = NotConfirmed exit 3 (Q-IS2-2).

## Progress (all done)
- [x] items 7b, 7d, 8, 9, 10; release-gate probes; testkit docs; tests; reverts R1–R8.

## Commands (exit codes, final state)
- cargo test -p heimdall-issuer --lib: 0 (15). heimdall-app --lib: 0 (57). testkit --lib: 0.
- cargo test -p heimdall --bin heimdall -- testcfg issuer_cmd: 0 (11); --release -- testcfg: 0 (9).
- cargo test -p heimdall --test e2e_cli_m03: 0 (42 + 2 ignored); issuer:: 0 (10) x9 runs at umask
  022 and x3 at umask 002, plus one early run with 2 failures (issuer_store_locked at a ceremony's
  store step, and the restore test) not reproduced since.
- cargo test -p heimdall --test e2e_issuer_ceremony: 0 (4). heimdall-runtime integration_issuer_m03: 0 (21).
- cargo test -p heimdall-issuer --test integration_issuer_store: 101 (2 expected, IS2-R4).
- release-gate.sh: 0 (25 probes, 3 new product-file probes PASS).
- clippy host (issuer/app/testkit all-targets; heimdall bin+2 tests, test profile; heimdall bin
  --release): 0. Windows clippy (same sets): 0. linux-xcheck -p heimdall-issuer -p heimdall: 0.
- Reverts (reverted → restored, sha same): R1 test-store deletion 101/0 (unit + e2e); R2 birth
  order 101/0; R3 Keychains 101/0; R4 CLI BundleWritten 101/0; R5 disclosure coverage 101/0; R6
  Ctrl-C mode 101/0; R7 redacted not confirmed 101/0; R8 future created_at 101/0.
- Keychain search list + default keychain digests equal before/after all runs.
