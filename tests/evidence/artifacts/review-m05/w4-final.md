FIX FIRST (M05-W4F-R01, M05-W4F-R02)

Reviewed candidate `959936c4`. Scope was the first-parent changes after `d81abda6`
and the conflict resolution in `08a9746b`. Findings are from source inspection.

## Findings

### M05-W4F-R01 — Blocking. A routed import creates a connectable alias with no route.

`crates/app/src/operations/portable_m05.rs:328` and `:393`;
`crates/heimdall/src/connect_cmd.rs:149`, `:177` and `:651`.

Import shows the jump in its result but persists the target as unqualified
`Observed`. Suppose the receiving installation already has an ordinary SSH
alias for the target that connects directly and that alias is absent from its
Heimdall catalog. Before import, `heimdall connect` refuses the unknown alias.
After a successful import, attended `connect` recognizes it and hands the bare
alias to SSH. The local direct route wins. A subsequent export also loses the
jump because the route was never stored. An ordinary import and connect can
therefore bypass the route the owner intended and create a lasting catalog
entry that misrepresents it. This meets ADR-0009 §2.1's consent criterion.

Smallest fix is to report the routed destination as requiring local setup
and withhold the connectable alias until a matching local route exists. If an
observed placeholder is required, it needs to keep the jump intent and refuse
launch until the route is established. The current round-trip test checks the
plan's `jump` and expects `add`. It would miss the downgrade. Test import
followed by `connect` with a disposable direct alias and a stub launcher.

### M05-W4F-R02 — Blocking. An accepted wall-clock advance leaves the old timer in place.

`crates/runtime/src/supervisor.rs:651`, `:677`, `:687` and `:722`;
`crates/domain/src/time.rs:265` and `:471`.

With a strict connection, a cutoff and its continuous budget both 90 s away,
advance wall time by 30 s while the machine stays awake. The default time gate
accepts that skew. The cutoff is reached after 60 s of elapsed time, but
`next_pass` still targets 90 s if there are no new events. The resume poll
compares continuous time with the monotonic timer only. The guard can see
`Safe` again without scheduling a pass, and the periodic connection sweep sees
the grant as active. The already-authenticated strict connection can stay up
30 s beyond the owner's explicit cutoff. That bypasses the owner's cutoff
under ADR-0009 §2.1 even if fresh admissions refuse on time.

Smallest fix is to check wall progress against elapsed progress at the
existing bounded resume poll and make a clock adjustment that advances the
due instant trigger a scheduler pass. Keep the tick's safe-time and
continuous-budget checks. The current cutoff test advances both clocks and
invokes `scheduler_pass` directly. It would miss this. Drive the actual timed
loop with injected wall and monotonic clocks and no intervening events.

### M05-W4F-R03 — Nonblocking. A refused bastion can still resolve its dependents.

`crates/app/src/operations/portable_m05.rs:293` and `:312`.

The dependency lookup treats a bundled ID with no jump as resolved before
reconciliation. If its alias collides with a different local ID, the bastion
gets `alias_collision` while a target referring to that missing bastion can
still get `add`. Duplicate IDs also make the lookup use the last definition
while reconciliation keeps the first. The OR with a local direct record can
mask a bundled chain. The dependency check itself writes no remote trust or
pins. R01 covers the separate launch consequence under ADR-0009 §2.1.

Resolve against the destination reconciliation result. Propagate conflicts or
ambiguity in the referenced ID and use the local direct managed definition
when the bundle omits the hop. Existing tests cover a missing hop and a chain
with an empty catalog. They would miss a refused or ambiguous hop. Cover a
partial bundle with a valid local hop, a colliding hop, and a duplicate ID.

### M05-W4F-R04 — Nonblocking. A preparing grant can still miss its deadline wake.

`crates/runtime/src/supervisor.rs:1333`;
`crates/app/src/operations.rs:12541` and `:12565`;
`crates/domain/src/lifecycle.rs:93`.

If a pass runs just before a `Preparing` grant's own deadline and the
next-wake read runs just after it, `permits_use()` is false and the wake is
dropped. The grant can remain pending until another event or the 300 s idle
pass even though the tick would expire it. `AwaitingApproval` has the same
state mismatch. New admission and issuance retain their own checks, so the
stale state alone fails ADR-0009 §2.1's blocking threshold.

Base the passed-bound retry on states that accept `DeadlineReached`, leaving
revocation to its own retry. The current helper and active-grant cutoff tests
would miss this. Cross the bound between the tick and wake reads with a
preparing grant and assert a retry and terminal transition.

### M05-W4F-R05 — Nonblocking. A slow pass can consume the entire retry delay.

`crates/runtime/src/supervisor.rs:666`, `:722` and `:2055`.

A passed wall bound may remain due while time is uncertain and the continuous
budget is still live. `wake_for` adds one second at the end of the pass, but
the loop adds the resulting delay to its earlier `Instant` sample. If the
pass takes more than a second, the timer is already due and passes can run
back to back. Shutdown and other due work are checked each iteration. The
extra polling has no demonstrated lasting trust, recovery, data or consent
effect under ADR-0009 §2.1.

Use a fresh monotonic sample when applying the computed delay. The helper
test checks timestamp arithmetic only. A timed-loop test with a slow pass
and persistent uncertain time would catch the missing delay.

## Other reviewed behavior

- The scheduler takes the minimum across future bounds. Pause preserves
  existing work and does not remove its cutoff. After a successful expiry
  tick, the same pass sweeps ended grants, closes owned masters and strict
  dedicated connections, preserves graceful dedicated connections, and
  attempts slot cleanup. Failures are retried by the periodic managed sweep.
- Self references fail validation. A cycle entirely in the bundle fails the
  dependency check with an empty catalog. Export adds a destination ID in
  both redaction modes and does not read enrollment pins or private material.
  Supplied host-key hints are displayed and discarded, leaving local pins
  intact. First-connect comparison against exporter's pins is deferred to M07.
- Revision 5.3 adds an optional field under the existing v1 schema and
  `trusted-work/1`. Omitting the field preserves old serialization. Older
  closed readers reject a bundle containing `jump` instead of discarding it.
- The merge's sole conflict was in the native harness. Both parents' test
  blocks and exit accounting survive. There were no product conflicts.

## Checks and scope limits

- `git fetch origin m05/w4 main` — 0. Ref and first-parent assertions using
  `git rev-parse` and `git rev-list` — 0.
- `git show --remerge-diff` and `git show --cc` for `08a9746b` — 0.
  `git diff --check` for both product commits and the merge script against both
  parents — 0.
- `bash -n` on the merged script and Python byte comparisons of both parents'
  harness blocks — 0. Python structural comparison of all three published
  schemas against the parent — 0.
- `git status --porcelain=v1 --untracked-files=all` — 0, empty. The checkout
  is at `8baf2e1b`. Candidate blobs were read directly and no build target or
  scratch files were created. Focused Rust tests, the live harness and native
  Windows/WSL tests were unrun. The committed revert record was inspected as
  prior evidence only.
