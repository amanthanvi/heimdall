# M03 wave 5, round 5 — questions for the orchestrator

## Integrator (I)
## L5 (late_write present, withdrawn removal)

**Q-L5-1 (inform; built): `late_write_present` is `CONFIG_CONFLICT` (exit 6).** It belongs with the
reasons for "the destination's registry holds a line the owner must have removed"
(`registry_line_damaged`, `registry_not_rewritable`, `already_enrolled`, `managed_slot_held`): a
retry of the check cannot change it, only a removal can. `CAPABILITY_UNAVAILABLE` is the code of the
verification classes (`verification_inconclusive`/`_failed`), for what a check could not establish.
Option B: `CAPABILITY_UNAVAILABLE`. Recommendation: A (built). ADR-0006 §16.6 row added.

**Q-L5-2 (ADR text, for the orchestrator): proposed D5 §6.2 amendment.** For the `withdrawn` row's
"next" column, instead of "none" (the row is shared with `verification_failed`, `removed`,
`failed_unwritten`, so split `withdrawn` out or add a note):
> ⟨§17.29 item 2⟩ `withdrawn`: none, **except** a record that carries the `late_write` residual:
> `removing` (account form: a new attended `RemoveEnrollment` of the exact line by marker, as from
> `abandoned`). On success it ends `removed`, and the residual clears in the same transaction once
> the removal's own inspect reads past `not_after_remote` with no lock of the uncertain step;
> otherwise it ends `removed` with the residual kept, for the absence check to clear.

Domain: the new event `WithdrawnRemovalApproved { late_write: bool }`, and only `late_write: true`
leaves `withdrawn` (own account form). `RemoveEnrollmentApproved` is unchanged. One new golden row.

**Q-L5-3 (semantics; built fail-closed): when the removal clears the residual.** The ruling says
"on success … the residual cleared". I clear it only if the removal's own reading (the inspect the
remove step, or its reconcile, ran on) is past `not_after_remote` on the destination clock, the
registry was readable, and no lock with the residual's token (or an unreadable or foreign lock)
was present: D5 §6.7's condition, with the line removed. A removal before the not-after ends
`removed` with the residual kept (the absence check still clears it later). Option B: clear on any
confirmed removal. Recommendation: A (built). Only a removal admitted from `withdrawn` clears it.
That is tracked by an `enroll.remove.late_write` stage receipt (`NotAttempted`) on the operation.

**Q-L5-4 (open): `abandoned` with `late_write`.** Unchanged: `abandoned → removing → removed`
keeps the residual (§17.28 item 3: only the absence check clears it), so the record stays an
outstanding obligation until `enroll verify --absence`. Recommendation: apply Q-L5-3's condition to
it too. Not built (needs a ruling).

**Q-L5-5 (inform; built, affects `abandoned` too): the issuing set on removal.** **ANSWERED (orchestrator, 2026-11-13; to be ADR-0008 §17.29 item 9): accepted.** A confirmed removal (any origin) drops the CA from the pair's issuing set only when no other verified enrollment of that pair still trusts it; own regressions required (old abandoned or residual-carrying withdrawn + newer verified under the same CA: removing the old line keeps the CA and the newer can still issue; removing the last enrollment under a CA drops it), each failing when reverted. A confirmed
removal took the CA out of the pair's issuing set unconditionally. A `withdrawn` (or `abandoned`)
record sits outside the uniqueness index, so a later verified enrollment of the same pair can use
the same CA. Removing the old record's line then dropped the live enrollment's CA. Now the CA is
removed only if no other record of the pair under it is `verified` or `reverifying`. The regression
asserts it (revert R6).

**Q-L5-6 (request, store owner; not mine): cross-check the event payload.** `transition_enrollment`
trusts the caller's `WithdrawnRemovalApproved { late_write }`, as it already trusts
`OwnerReverify { hold }`. The app derives the payload from the stored record in the same
transaction. Recommendation: the store refuses the event when `late_write` differs from
`stored.late_write.is_some()`.

**Q-L5-7 (inference, not run): `removing → held` beside a live (pair, CA).** If the removal of a
withdrawn or abandoned record is held (`registry_changed` ×3, not rewritable, damaged) while another
live enrollment holds the same (pair, CA), `held` (no `removal_origin`) falls in
`enrollments_open_pair_ca`. The transition would then fail as a store conflict, and the step
result's transaction would roll back. This already happens for `abandoned` today, and the new path
inherits it. Recommendation: a ruling on whether such a held removal should keep a marker that
excludes it from the index.

**Q-L5-8 (built; for confirmation): `reverifying` counts as still trusting the CA in the issuing-set rule (§17.29 item 9), so a CA is dropped only when no other enrollment of the pair under it is `verified` or `reverifying`.**

## Integrator (round-5 records)
- **`late_write_present` code: ANSWERED (orchestrator, 2026-11-13; to be ADR-0008 §17.29 item 8):**
  `CONFIG_CONFLICT` (exit 6) accepted: the recorded `withdrawn` state conflicts with the observed remote.
- **Q-L5-8 (`reverifying` counts as trusting the CA): ANSWERED (orchestrator, 2026-11-13; to be
  ADR-0008 §17.29 item 10): confirmed.** An enrollment that is `verified` or `reverifying` still trusts
  its CA for the issuing-set rule: a record being re-verified keeps its trust line until the check
  concludes; a failed re-verification follows its own transition, and the issuing set is recomputed then.
