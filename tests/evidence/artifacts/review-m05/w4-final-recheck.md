FIX FIRST — M05-W4F-R01, M05-W4F-R02, M05-W4F-RC-R01 to R03

Reviewed `056a1692` against its parent `959936c4`. Locations below refer to the fix commit.
ADR-0009 §2.1 blocks the route and cutoff findings because ordinary owner actions can bypass
an accepted bastion requirement or a strict cutoff.

| Finding | Status | Location | Residual |
| --- | --- | --- | --- |
| M05-W4F-R01 | Partly resolved | `crates/app/src/operations/portable_m05.rs:124,442–455`, `crates/heimdall/src/connect_cmd.rs:159–187`, `crates/app/src/operations/pair_mechanism_m03.rs:98–108`, `crates/app/src/catalog.rs:848–889` | Import and export retain the jump. Fresh admission and CLI connect refuse before SSH launch. TUI connect, local edits that clear the marker, and old successful requests leave the scenarios below. |
| M05-W4F-R02 | Partly resolved | `crates/runtime/src/supervisor.rs:257,649–701,796–805`, `crates/app/src/operations.rs:12554–12620` | The original large step triggers the pass and tick still uses safe wall time and the continuous budget. Each poll discards progress below the 2 s step threshold. Five 1.5 s advances on separate polls can move a strict cutoff 7.5 s ahead of the old timer without triggering any pass. The time gate accepts this skew and the managed sweep closes only grants already marked ended. Compare the scheduled wall wake with current wall time on each poll and bring a due pass forward, while retaining the monotonic wake and tick checks. |
| M05-W4F-R03 | Partly resolved | `crates/app/src/operations/portable_m05.rs:315–380` | A conflicting or duplicated referenced hop is rejected and an omitted hop can resolve to a local direct managed definition. Repeated IDs are refused only after the first row. For two new rows with the same ID and different aliases, the first can still be written. This misses the ruling that duplicate IDs are refused. Refuse all rows with a count above one before claiming aliases. The defect alone establishes no trust or authority. |
| M05-W4F-R04 | Resolved | `crates/runtime/src/supervisor.rs:1354–1365,2075–2092`, `crates/domain/src/lifecycle.rs:93–118` | The four states that advance on `DeadlineReached` get the passed-bound retry for their grant deadline, anchor bound and continuous budget. Revocation retains its own retry at `supervisor.rs:808–832`. |
| M05-W4F-R05 | Resolved | `crates/runtime/src/supervisor.rs:738–762` | The next deadline and failed-pass retry use a monotonic sample after the scheduler pass. Cleanup applies its delay after cleanup returns. |

## R01 path coverage

- **Import, export and inspect.** The observed record and pending jump are written in one
  import transaction. Plain and redacted export retain the jump. Inspect publishes
  `route_pending.jump` and the store includes the marker in recovery metadata
  (`crates/app/src/operations.rs:9971–9979`, `crates/store/src/ext_m03.rs:295,2438–2457`).
- **Connect, ensure and run.** CLI connect reads the marker before dispatch. Fresh ensure
  rejects a pending pair during resolution (`crates/app/src/operations.rs:4617–4626`).
  Explicit and context-based run require ready ensure replies before binding or launching
  (`crates/heimdall/src/run_cmd.rs:285–304`). Run passes arbitrary child arguments through.
  Its check covers the ensured pairs. A child requested with unrelated scope can still
  use the owner's ordinary SSH configuration. The ensure remedy at `operations.rs:3946`
  supplies the destination ID in an alias position. Where they differ, following the
  suggestion can rename the alias (`crates/heimdall/src/catalog_cmd.rs:199–205,239–243`).
- **Default and shell hook.** Default planning skips unresolved pairs
  (`crates/app/src/operations/default_activation_m05.rs:398–420`). An all-pending covered
  scope yields generic `not_covered` without the bastion or setup instructions. The shell hook
  binds only ready results and treats `route_pending` as unavailable, so a fresh hook creates
  no slot for the pair (`crates/heimdall/src/activate_cmd.rs:181–225,282–336`).
- **Rendered alias and include.** Import invokes no projection. Setup builds its alias
  spec from managed destinations only, and rendering adds `ProxyJump` from that spec
  (`crates/app/src/setup.rs:644–685`, `crates/localenv/src/projection/plan.rs:1699–1710`).
  An observed pending entry adds no alias to the generated include. Existing SSH config
  stays callable by ordinary OpenSSH. There is no `heimdall ssh` command or passthrough
  (`crates/heimdall/src/cli.rs:118–222`, `crates/heimdall/src/main.rs:49–60`).
- **TUI and clearing.** Both destination screens lead to the raw SSH handoff in RC-R01.
  The diagnostic menu also offers explicitly authorized host-verification and authentication
  probes against the local SSH config (`crates/heimdall/src/tui/model.rs:330–361`,
  `crates/heimdall/src/tui/worker.rs:733–748`). Removal deletes the marker with the row.
  Changed upserts delete it too, subject only to ordinary definition checks, as in RC-R02.

## New findings

### M05-W4F-RC-R01 — Blocking. TUI connect bypasses the route refusal.

`crates/heimdall/src/tui/data.rs:87–101`, `tui/model.rs:1423–1437`,
`tui/mod.rs:380–383,399–428`. The TUI discards the pending jump, tests catalog membership,
then hands the bare alias to SSH. Import turns a previously unknown alias into a selectable
destination. If the owner's ordinary configuration has a direct alias, the TUI's **c**
action can take it without the imported bastion. Reuse a fresh route-readiness check at
the TUI handoff and report the same jump and setup instruction as CLI connect.

### M05-W4F-RC-R02 — Blocking. A catalog edit erases pending intent before the route exists.

`crates/app/src/catalog.rs:810–868`, `crates/heimdall/src/catalog_cmd.rs:199–209`,
`crates/heimdall/src/connect_cmd.rs:159–190,263–274`. A changed observed upsert, even one
adding only a label, deletes the jump. A direct managed upsert or a different accepted jump
does too. On the next ordinary connect, a direct alias can win and a later export loses
the imported jump. Even a matching managed upsert only changes the catalog. Before setup
applies the routed alias, attended connect can fall through to bare SSH when the managed
preference is absent or unapplied. Preserve pending intent on nonmatching edits and gate
the routed launch on the matching effective route before handing off the alias.

### M05-W4F-RC-R03 — Blocking. A previous successful ensure can deliver a pending pair again.

`crates/app/src/operations/pair_mechanism_m03.rs:345–363`,
`crates/app/src/operations.rs:9085–9120,9158–9166,10425–10549`. The precheck discards
the pending error and a settled request can replay its old ready result. If the owner
ensured an existing-access pair, removed the catalog row, then imported the same ID as
routed while the binding still lives, a retry can return that binding. Run can reuse it.
Bind checks the existing grant and policy, with no pending-route check, and the existing
access path uses the ordinary SSH configuration. Check current pending intent before
delivering a replayed binding and again before bind or launch reuses it.

### M05-W4F-RC-R04 — Nonblocking. WSL cleanup proves the name, with an ownership gap.

`tests/native/m05/run-wsl-hook-windows.ps1:666–671,698–712,764–792`,
`tests/native/m04/run-mode-b-windows.ps1:151–155,645–650`. Cleanup is in `finally`
and terminates and unregisters one exact attempted name, absent before and present now.
If two disposable runs draw the same name and both pass the initial census, the loser
can treat the winner's registration as its own after a failed import and unregister it.
That collision between harness runs affects disposable test state. Check a successful
initial census and verify the registration's install directory belongs to this run before
using or unregistering it, including after a partial import.

## Checks

- `git fetch origin m05/w4 main`, ref and parent assertions, and
  `git diff --check 959936c4 056a1692` — 0.
- `git diff`, candidate `git show` and `git grep` source tracing — successful reads exited 0.
  The standalone search for an SSH passthrough exited 1 with no matches.
- `python3 -I -B` source-constant arithmetic and revert-record checks — 0. The model puts
  the cutoff at elapsed 82.5 s with the old timer at 90 s. Committed R01, R02 and I-26
  records each report 101 reverted and 0 restored. This re-check did not rerun those tests.
- `git status --porcelain=v1 --untracked-files=all` and `test ! -e target` — 0, clean.
  Rust tests, live SSH and native Windows/WSL were unrun. No scratch output was created.
