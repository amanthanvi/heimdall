# M03 wave 5, round 6 — questions for the orchestrator

## Integrator (I)
## L5

**Q-L5-9 (item 4 reading; built): what "differs" means for `OwnerReverify { hold }`.** The event
carries a `HoldKind`, not the stored `EnrollmentHold { reason, evidence_based }`, so exact equality
is impossible. The store compares kinds: `stored.hold.map(EnrollmentHold::kind) == Some(hold)`, and
a stored record with no hold never agrees. The refusal is the existing inner `Err(InvalidTransition)`
of `transition_enrollment`, the same one `removal_origin_kept` and the table use; it is not a
`StoreError`. Confirm.

**Q-L5-10 (open; not built): the other hold-carrying payloads.** `TargetChangeApproved { hold }` and
`ManualRecoveryLine{Present,Absent} { hold, purpose }` also restate the stored hold's kind. The
ruling names only `OwnerReverify`. Recommendation: the same check for both (the app already derives
them from the stored record).

**Q-L5-11 (item 5; built, no migration, so no escalation): the cause was the missing origin, not the
index.** `enrollments_open_pair_ca` already excludes `held` rows with `removal_origin_set = 1` (the S1
follow-up). The account-form removal path never set `removal_origin`. Fix in
`Txn::transition_enrollment`: a removal admitted from `withdrawn` (`WithdrawnRemovalApproved`) or
`abandoned` (`RemoveEnrollmentApproved`) records origin `{state, evidence, hold}` when the caller's
record omits it, and an account-form record keeps its stored origin through every later transition
whose `updated` omits it. Account-form records never clear an origin (only the system form's cancel
and absence paths do). Confirm.

**Q-L5-12 (inform): round 5's `enroll.remove.late_write` receipt is gone.** Residual clearing
(items 2-3) now keys on the persisted removal origin (`withdrawn` or `abandoned`). That also covers a
re-removal from `held` of the same removal, because the origin is kept. Test support only:
`RawDocuments` gains `Enrollments` and `Events`.

## Integrator (round-6 records)
- **Q-L5-9 (`OwnerReverify { hold }` compared by kind): ANSWERED (orchestrator, 2026-11-13; to be
  ADR-0008 §17.30 item 6): confirmed.** The store compares by kind, because the event carries only
  the kind; a mismatched kind is refused and nothing changes.
