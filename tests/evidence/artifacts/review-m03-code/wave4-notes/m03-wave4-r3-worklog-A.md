# M03 wave 4, round 3 — worker R3-A (enrollment + evidence) worklog

## Goal
ADR-0008 §17.22 items 1 (W4-S01), 2 (W4-S02), 7 (W4-R04 + R2A-Q1).

## Decisions
- R3A-D1 (item 1). `admit::same_foreign_descriptor` = full `ForeignRemovalTarget` equality (alias,
  destination ID, host, port, account, marker, CA, line hash, registry, form). Admission of a foreign
  removal that finds a held record of the marker refuses a different descriptor **before** `insert_op`
  (nothing written: no operation, no decision, the record unchanged). The `RemoveEnrollment` precheck
  re-checks it against the decision's shown target (`DECISION_STALE` otherwise). Reason: `descriptor_mismatch`
  is not registered (R3A-Q1) → `CAPABILITY_UNAVAILABLE` + `bundle_host_mismatch` meanwhile (switch
  `admit::DESCRIPTOR_MISMATCH`).
- R3A-D2 (item 2). `registry::classify::Inspection::marker_facts(marker, line)` (counts of exact canonical
  lines / other marker lines, SHA-256 over the others, `MarkerClass`); `without_foreign_lines` removed.
  `StoredReading` stores `marker`, `own_entries`, `own_entry_hex` (the canonical line, only when one
  matched), `other_marker_lines`, `other_marker_sha256`, `marker_class`; `marker_entries_hex` gone. The
  minimized reading's content is rebuilt (`classify::minimized_content`): the canonical entry × count plus
  one stand-in comment line carrying the marker per other line, so `line_state`, `post_image_without`
  (damage check) and `late_write_cleared` classify exactly as on the full reading; inconsistent facts →
  `None` (re-inspect / unavailable, fail closed). `inspect_fact` takes `line_of(ctx)`.
- R3A-D3 (item 7, comparison). `app::enrollment::evidence_holds(record, eval, client)`: the alias's
  evaluation is exactly the approved target (`route_matches`) and the evidence names the current client
  (`evidence_client_current`, per-word `version_token`); no evaluation / no client → invalid. The managed
  adapter's `prepare::snapshot` runs it at read time (`invalidate_evidence`) and drops the snapshot copy's
  evidence when it fails (nothing written; `pair_enrolled` reads the state only, so the refusal is
  `minimum_not_met`, scope `unknown`). `ManagedSourceRead` gained `evaluate_target` / `client_version`
  (defaults `None`: fail closed), plus `EvidenceFeed`, `TargetAndClient`, `WithEvidenceFeed`.
  `pair_evidence(managed, pairs, prepared)` takes only evidence of the prepared certificate's CA.
  No change to `app::ports` (ManagedSources unchanged).
- R3A-D4 (item 7, runtime feed). `service.rs` `mod sources`: `LateEvidenceFeed`, `Observing` reads it;
  `read(s, writer, feed)`. Outside `mod sources` (R3-D's region; three mechanical lines, recorded under
  Requests as done by R3-A): the `ManagedParts.evidence` field + its init, `adapter()` passing it, and
  `start()` binding `TargetAndClient { target, host }` next to `set_enrollment_host`. Without them the feed
  was dead code (clippy -D warnings) and production would always report `unknown`.
- R3A-D5 (item 7, host-key change). `HOST_KEY_CHANGE_PROMPT_REVERIFY` and its prompt-delay gate removed.
  The pass marks a host-key change due at once; `verify_operation` records a `Reverify` without a
  proposed target whose alias evaluates to a host-key change as `HostKeyMismatch` **from the evaluation
  alone** (`host_key_mismatch_outcome`, before `run_verification`: no `enroll.verify.started`, no session,
  no certificate, no login) → the standard `ReverificationResult` → `held(host_key_changed)`, grants
  degraded. `ApproveTargetChange` (proposed target) runs the attended verification as before.
  `Limits::reverify_prompt_delay` is now unused (operations.rs, not mine; left).
- R3A-D6 (item 7, client). The pass's "changed client" uses the same `evidence_client_current`. An
  inconclusive re-verification leaves the record's old evidence, which the comparison keeps invalid.

## Progress
- [x] item 1  - [x] item 2  - [x] item 7

## Commands (exit codes)
- `cargo test -p heimdall --test e2e_enroll_m03 foreign_removal_held_reuse`: 0 (1 passed).
- `cargo test -p heimdall-registry --lib marker_facts`: 0.
- `cargo test -p heimdall --test e2e_enroll_m03 journal_never_stores`: 0 (2 passed).
- `cargo test -p heimdall-adapters --test integration_managed_adapter`: 101 — only
  `expired_grant_never_reissued` (line 2545 `w.table().public_key(&gid).unwrap()`: K_env destroyed at
  expiry, R3-C1's item 4; not an evidence case). 45 others passed.
- `cargo test -p heimdall-adapters --test integration_managed_adapter -- evidence_invalidated_at_the_comparison pair_evidence_is_for`: 0 (2 passed).

- `cargo test -p heimdall --test e2e_enroll_m03`: 0 (66 passed).
- `cargo test -p heimdall-registry`: 0 (lib 24, model_registry_pure 17, doc 0).
- `cargo test -p heimdall-runtime --test model_operations_m03`: 0 (37 passed).
- `cargo test -p heimdall-app --lib`: 0 (50 passed).
- `cargo test -p heimdall-adapters --test integration_managed_adapter`: 101 — 47 passed, only
  `expired_grant_never_reissued` (R3-C1's item 4; request filed).
- clippy (5 packages, `--all-targets -D warnings`): 101, blocked only by others' in-progress files
  (`issuer_m03.rs:229` type_complexity, R3-B; `managed_store.rs:1476`, R3-C1/C2; `store/ext_m03.rs:483/485`
  unused, R3-B). No diagnostic in an R3-A file. Retried below.
- `bash tools/validation/linux-xcheck.sh -p heimdall-app`: 101, only `issuer_m03.rs:229` (R3-B). Retried below.
- `rustfmt --edition 2024 --check` on my files: clean (formatted e2e/managed_adapter tests and passes.rs).

## Revert proofs (revert in place with `/tmp/r3a-scratch/revert.py` → run → restore, byte-identical → run)
| # | Fix reverted | Regression | Reverted | Restored |
|---|---|---|---|---|
| A1 | admission reuses a held record for any descriptor (`&& false`) | `foreign_removal_held_reuse_needs_the_exact_descriptor` | 101 (line 6082: admitted) | 0 |
| A2 | precheck accepts any shown descriptor (`shown.is_some()`) | same | 101 (line 6124: forged B approved) | 0 |
| A3 | `StoredReading::of` stores every marker line's bytes (hex) | `journal_never_stores_marker_bearing_foreign_lines` | 101 (scan, line 6187) | 0 |
| A4 | `snapshot` skips the comparison (`invalidate_evidence` not called) | e2e `ensure_scope_minimum_refused_before_any_pass`, `inconclusive_reverification_after_client_change_keeps_scope_unknown` | 101 (both, line 6448: scope still verified) | 0 |
| A5 | same | adapter `evidence_invalidated_at_the_comparison_before_any_pass` | 101 (line 4981: minimum met) | 0 |
| A6 | `pair_evidence` ignores the prepared certificate's CA | adapter `pair_evidence_is_for_the_prepared_certificates_ca` | 101 (line 5045) | 0 |
| A7 | same | e2e `ensure_scope_minimum_refused_before_any_pass` (CA case) | 101 (line 6550) | 0 |
| A8 | `verify_operation` without the host-key pre-check (`&& false`) | e2e `evidence_invalidated_on_host_key_or_client_change` | 101 (line 6042: a verification session was created) | 0 |

## Final checks
- clippy, 5 packages, `--all-targets -- -D warnings`: 101, the only diagnostic `crates/app/src/operations/issuer_m03.rs:229`
  (type_complexity, R3-B's in-progress file). Diagnostic run with `-A clippy::type_complexity` added: 0 (nothing in
  any other file, mine included). Not an acceptance substitute; rerun once R3-B lands.
- `bash tools/validation/linux-xcheck.sh -p heimdall-app`: 101, the same single R3-B diagnostic.
- rustfmt `--edition 2024 --check` on every R3-A file: clean.
- Scratch `/tmp/r3a-scratch` (revert helper, patches, logs) removed.
