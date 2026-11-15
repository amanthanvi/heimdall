# Worklog C (contract and port seams), M03 wave 5 round 2

Goal: land additive seams for §17.25 items 4, 8, 15, 18, 19, 21, 22 (+ ADR-0006 rows, schemas, goldens,
api notes R0). No behaviour change. No commits.

## Progress
- [ ] read sources
- [x] read sources (brief, §17.25, ADR-0006 §16, round-1 Qs)
- [x] seams landed: EnrollmentView.hold, Warning.reason + m03_warning::REASONS, IssuerRequest::BundleWritten
      (+ app arm driver_unavailable), store record_bundle_digest/bundle_digest_recorded_at,
      PrepareOutcome.managed + ports::ManagedResultFacts, Facts.managed (allow(dead_code))
- [x] mechanical literal fills outside the explicit grant (compile-only): Warning{reason:None} x7,
      EnrollmentView{hold:None} x3 — recorded in api notes and questions
- [x] example request.issuer.bundle-written.json; contracts tests (examples, m02 list, m03 caps, golden
      journaled-kinds synchronous, m03-reasons warning_reasons); schemas regenerated (7 files, + only)
- cmds: cargo build --workspace exit 0; contracts test exit 0 (90 passed); store unit exit 0;
  clippy host all-targets exit 0 (after fixing operations_m03.rs literal the script skipped)
- [x] docs: ADR-0006 §16.5 (7 rows) + row 14 inline; m03-plan §0.4 M2 amendment, §5 item 14 warning reason
- [x] .m03-wave5-r2-api.md R0 written; questions C-Q1..C-Q5
- cmds (final): cargo build --workspace 0; contracts 0 (90 passed); store lib 0 (21); domain operation 0;
  heimdall bin m03_cmd 0 (11), tui 0 (52); e2e_cli_m03 0 (32 passed, 2 ignored pty-child helpers);
  clippy host all-targets 0; clippy-windows 0; schema_check logic alone rc=0; fmt --check 0 (after rustfmt
  of ext_m03.rs and tests/contracts/m03.rs); revert run: golden row changed -> contract_reason_golden 101,
  restored (shasum equal) -> 0.
- ./target is 24G (shared with other workers; not cleaned per the brief). Scratch /tmp script removed.
## Status: done (implemented_unverified on Windows/Linux natively; host-only runs)
