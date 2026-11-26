# M08 W3 plan: the candidate phase (after the W2 merge at `7b98f6b2`)

**Status:** approved in outline by the orchestrator, 2026-11-24, with its three answers folded in (W3-4, W3-5, W3-6). Nothing in it starts before the contract
owner's U0 handoff. That handoff comes after M06's exit is merged and names the files M08 may
edit (m08-plan §3, rule 2).

**What "W3" covers here.** The M08 track's W3 is the rest of the plan after the handoff, in plan
§3's order:
- the plan's W1 (U3c), its W2 (U2b) and its W3 (U3b, U4b, U5b, U7b final);
- the records of record those produce for U8;
- U6b and U1b are M08's too and are listed where they sit in the order, but this draft schedules
  them, not their design.

**Inputs:**
- `docs/architecture/m08-plan.md` §2 to §7 and §12;
- ADR-0014 §2 to §7;
- the U0 rulings of 2026-11-24 (contract owner);
- the W2 records: `docs/architecture/m08-w2-plan.md`, `progress.md` row M08 W2,
  `tests/evidence/artifacts/m08/**`.

**Boundaries that shape every unit** (carried from W2):
- A release `heimdall` runs only in a container or a disposable account or VM.
- A number measured on any build but the candidate's is a rehearsal and is labelled with its
  executable's digest.
- The candidate commit is `main` after U2b and U3c merge, with the feature set frozen. ADR-0014
  §6.5 and m08-plan §6.3 say what a later change invalidates: the 72-hour soak is repeated for
  any change to a crate a long-lived process links, the manifests, the lock file, the feature
  set, the toolchain or the flags.
- Every machine rule stays in force:
  - one capped container at a time, except the soak and the fuzz of record together in the
    candidate phase;
  - heavy work through heavy-gate;
  - native PC and devbox runs at merge candidates;
  - no ssh during an announced pause.

## W3-0. Scope from the U0 rulings (what U2b, U3b and U3c take)

| Unit | Takes from the rulings | Not U2b's (owned elsewhere) |
|---|---|---|
| **U2b** | The live builds of the U0 skeletons that answer "not available in this build" today (ASK-H3):<br>- `heimdall state restore --backup <file>`, `state reset` and **`state repair`** (Q8, attended only, with typed confirmation: carry decodable records after the damage forward as fence records, raise the epoch, truncate at the first damaged record, report the count dropped and the residual);<br>- **H12's generation layout** (the pointer and operation records; adoption treats schema 14 as flat);<br>- **H13 as one change:** the server's epoch check, the envelope's `request_epoch`, `--request-epoch`, the capability `request-epoch/1`, and every consumer (CLI retry, TUI, wrapper, H1, H2), not split across waves;<br>- `REQUEST_STALE` with reasons `restore_epoch_stale` and `restored_before_completion`, which joins `Code::all()` with its emitter (ASK-CODE);<br>- `STATE_UNAVAILABLE` reasons `ledger_damaged` and `state_corrupt` (`next.action` `owner_decision`), and `state_newer_than_build` (`change_client`);<br>- the event `StateRestored` (ASK-H10), naming what ended;<br>- `access release --request-id/--request-epoch` where U3 does not land it first (ASK-FLAGS);<br>- the remainder of D14's help rewrite.<br>**Built from W2's provisional pieces:** `crates/stategen`, the generation switch, operation record, staging intent, adoption order and request ledger, moved into `crates/store`/`crates/runtime` under the handoff; plus the damaged-ledger refusal (ruled 2026-11-23) | M07 U3's live corrections (Q1 to Q7, Q11 to Q14). Q10's `alias_collision` doctor finding and `AliasCollision` (that is U1b, M08) |
| **U3c** | m08-plan U3c unchanged: cut the test-kit edge (`tempfile` to a dev-dependency, `proptest` behind a kit feature, or an explicit debug-support feature) so that a release build compiles none of the 14 to 16 test-only crates. Test `release_graph_holds_no_test_only_crate` | The manifests' owner lands it, or an implementer under the handoff (it touches M06's and M07's manifests) |
| **U3b** | The candidate archives at the version string `1.0.0-rc.1`. The string is set once at the candidate commit, with U8's claims-table update (ASK-VERSION). The feature set is ruled at M06's exit and frozen. Release artifacts stay without `iroh` (E2) unless that ruling changes it. Plus `examples/` (M07's skill, wrapper, harnesses), the final matrix and reference configuration, and the clean-machine and fresh-account rows | — |

## W3-1. Order, machines and expected durations

Durations are estimates from W2's observed runs (release build of one target: about 4 to 5
minutes on the Mac and on the PC; installer revert proofs: about 50 minutes on the Mac and 8 per
shell on the PC; the benchmark world: about 35 minutes per run with full idle windows).

| # | Step | Machine | Duration | Waits for |
|---|---|---|---|---|
| 1 | **U3c** test-kit edge, plus `release_graph_holds_no_test_only_crate` | Mac (focused tests, `check.sh` once) | half a day | the handoff (manifest files named) |
| 2 | **U2b** lifecycle: the stategen code moved under the handoff; restore, reset, repair; H12; H13 end to end; the restore and switch fault sets of m08-plan U2b | Mac first; **fault sets natively on the Mac, the devbox and the PC** (the rename and sync calls differ; Windows has no directory sync) | about 3 to 5 days of implementation, then 1 review and 1 re-check (ADR-0009), then the native runs (about half a day each on the devbox and the PC) | the handoff; M06's exit records (what a restore quarantines) |
| 3 | **U1b** new boundaries 12 to 15, as fuzz targets; Q10's `alias_collision`; the §14.3 table at the frozen tree | Mac | about 1 to 2 days | the handoff |
| 4 | **U6b** bundle command; **U7b** defaults audit | Mac | about 1 day each | the handoff |
| 5 | **The candidate commit:** `main` after 1 to 4 merge, with the feature set frozen and `1.0.0-rc.1` set | — | — | the merges |
| 6 | **U3b release set** at the candidate (W3-2) | Mac (macOS arm64, Linux x86-64 and arm64); PC (Windows x86-64) | about 1 hour of builds, plus the PC job | 5 |
| 7 | **The reproducibility pair at the candidate** (W3-3) | Mac and PC, beside step 6 | in step 6 | 6 |
| 8 | **The 72-hour soak of record**, lanes S and L (W3-4) | Mac, one capped container | 72 hours of running time, plus any gaps over 1 hour | 6 |
| 9 | **The fuzz campaign of record** on the candidate's build, together with the soak (W3-5) | Mac, the capped fuzz container | about 20 to 30 hours of wall time, at two targets at once | 5 (a fresh setup at the candidate) |
| 10 | **Benchmarks of record,** including the slow-provider key-handling row (W3-6) | the Mac's Docker (Linux arm64, supplementary); the disposable WSL2 distribution on the PC (Linux x86-64, in an idle window); B2 and B3 accounts where given | about 1 hour per platform | 6; it runs between soak checkpoints, never as a second capped container beside the soak and the fuzz |
| 11 | **Cross-checks:** 6-hour soak, lanes S and L, on the WSL2 distribution; Windows and macOS in B2 and B3 where given | PC (an idle window of about 8 hours with the benchmarks); disposable accounts | 6 hours each | 6 |
| 12 | **A31 journeys** at the candidate: install, update and rollback from W2's archive to the candidate, uninstall; clean-machine and fresh-account rows of m08-plan §4.2 | the WSL2 distribution (Linux clean-machine row); B2, B3 accounts; B15 for the true clean rows (otherwise `blocked`) | about half a day | 6 |
| 13 | **U8** case index, records, claim audit, the populated candidate worksheet | Mac | about 1 to 2 days | 8 to 12 |

**What may run at the same time:**
- the soak and the fuzz of record (the only pair of capped containers allowed together);
- PC jobs beside anything on the Mac;
- devbox runs beside anything, at merge candidates.

The fuzz campaign pauses if the Mac's 15-minute load stays above 30 for an hour.

## W3-2. The release set (U3b)

- **Built from a clean checkout of the candidate commit:**
  - `build-release.sh` for `aarch64-apple-darwin`, `x86_64-unknown-linux-gnu` and
    `aarch64-unknown-linux-gnu` on the Mac;
  - `build-release.ps1` on the PC, with the Linux x86-64 executable of the same commit as its
    helper.
- **Every script line seen in W2 must appear:**
  - `check-features`' pass line;
  - `staged the executable the build reported`;
  - `compiled set checked: yes`;
  - `verify_artifact: PASS` on the stage, the archive and against the index.
- **Output:** the index and the external records under
  `tests/evidence/artifacts/m08/release/1.0.0-rc.1/`. The archives are not uploaded.
- **Not yet true:**
  - `LICENSE` and `SECURITY.md` are packaged only once B17 and B18 are answered. Until then the
    build prints "not yet in the tree" and the worksheet lists them;
  - signatures stay ad hoc (macOS) or absent (B13, B16).
- **The PC job reruns the W2.3 feature self-test** (`build-release-features-selftest.ps1`,
  18 checks) and the installer self-test and revert proofs at the candidate. It captures long
  runs with `cmd /c … > file 2>&1`.

## W3-3. The reproducibility pair at the candidate

Two builds of the candidate per target, from two checkouts at different paths and depths on the
same host:
- the Mac's three targets;
- the PC's Windows archive, the first pair at a commit with every W2 fix (job 57 showed the
  pair identical at `7905a671`).

The record states for each target whether the archive and executable are identical, as observed.
Nothing says "reproducible" for a target whose pair differs.

## W3-4. The 72-hour soak of record

- **Where:** the Mac, one capped container (`--network none --cpus 2 --memory 2g --pids-limit
  512`).
- **Build:** the Linux arm64 candidate archive, with W2's archive as the previous build for lane
  L's update and rollback.
- **Lanes:** S and L as in m08-plan §6.2, with the host-load sampler W2 added. Lane R joins only
  if M06's exit supports it in containers.
- **Lane M** (ruled 2026-11-24) runs beside S and L **in the 72-hour run of record**, but only if
  the release build can run it with no test hooks.
  - In a container, that means a real secret service inside the container for the managed
    recipe's store. A rehearsal finds out whether one works.
  - If it cannot run without hooks, lane M is `blocked` on B3 or B11 (the release-managed row),
    stated as such.
  - A short separate run with hooks counts toward no release row.
- **Blocked rows,** named as such:
  - release-managed (B3 or B11);
  - provider (B1);
  - route (Iroh is not in the release set).
- **Supervision** (ADR-0014 §6.6):
  - the container supervises itself;
  - the orchestrator reads the status file at start, +1 h, +6 h, +24 h, +48 h and +72 h;
  - no worker waits on it;
  - a missing heartbeat for ten minutes ends the run as invalid;
  - total gaps above an hour extend it.
- **Passing** is ADR-0014 §6.2. Any later change that §6.3 names repeats it.

## W3-5. The fuzz campaign of record

- **Setup** (ruled 2026-11-24): a fresh `run-campaign.sh setup` on the candidate's sources in a
  second volume, `HM_FUZZ_VOLUME=hm-m08-fuzz-rc`. W2's `hm-m08-fuzz` is kept as evidence until
  M08's exit. It
  records the build identity under W2.1's formula, after W2.2's completed-setup check.
  `fuzz/run-campaign-selftest.sh` runs first.
- **Targets:** the 17 of W2, plus U1b's boundaries 12 to 15 once they exist.
- **The rule:** a counted time of at least 7200 s per target on the candidate's build, a last
  run of at least 1800 s with no new edges, and no finding. A target at the 8 CPU-hour ceiling
  still gaining edges is `not met` at the ceiling, named with its final edge count.
- **Watch items carried from W2:** `runtime_config` reached 934 MB and `project_manifest` 904 MB
  peak RSS of the 1024 MB limit. An out-of-memory kill is a finding, triaged as F1 was. It is
  never cleared by raising the limit without a ruling.
- **Record:** `tests/evidence/m08-fuzz-campaign.json` (one row per target), with the extracts
  copied out of the volume after each round, not only at the end (W2's lost `control_frame` log
  is the lesson).
- **Estimate:** with every target needing at least 7200 s at two at a time, 17 targets take at
  least 17 hours. Targets that keep gaining edges take more rounds, so about 20 to 30 hours.

## W3-6. Benchmarks of record, and the slow-provider key-handling row

- **Spec rows** (ADR-0014 §6.1), on the candidate archive, with W2's harness:
  - `inspect_warm`;
  - `ensure_warm`, the spec's "warm already-authorized ensure";
  - `tui_first_useful_frame`;
  - `key_to_frame`, timed once the reconstructed screen shows the key's effect and the effect
    was absent before the key (RC04);
  - idle CPU and memory of the runtime process alone, in three 5-minute windows after 10
    minutes' settle, with its children named as not measured.
- **The slow-provider case (ruled 2026-11-23, option a):** key handling while the runtime itself
  waits on a slow signer. W2 measured only "fast concurrent operations", because the covered
  ensure never contacts the provider.
  - **The plan:** the managed recipe, where the runtime signs. A delay is put in its path with
    no test hook (the release build refuses them):
    - either a byte relay like `agent-delay.py` in front of the issuer's socket, if the release
      configuration lets the runtime reach the issuer through a scratch path;
    - or a delaying agent as the provider of an adopted identity whose login the background work
      really performs.
  - **First step, a probe rehearsal on W2's build, run early** (ruled 2026-11-24): which of the
    two the release build allows, read from the configuration schema and tried in the capped
    container when its slot is free. It counts toward nothing. Its record says which approach
    worked, the byte relay in front of the issuer or the delaying agent behind an adopted
    identity, and what was tried. The candidate run then repeats a known method.
  - **What reading the code shows (2026-11-24, before any probe).** Neither approach as first
    framed puts a delay on a path the runtime waits on:
    - the issuer is a child of the runtime, over piped stdin and stdout, with no configuration
      that redirects it (`crates/issuer/src/client.rs`; `ManagedOptions.issuer_command` is set
      only by tests). Signing happens in the child from an in-memory key;
    - the runtime never signs with an adopted agent identity. `ssh` and the CLI talk to the
      agent directly, so a delaying agent there is never waited on by the runtime
      (`crates/adapters/src/native_agent.rs`, `crates/launch/src/lib.rs`).

    **The one real slow dependency left is the issuer's secret store.** On Linux that is the
    Secret Service over D-Bus, and the child inherits `DBUS_SESSION_BUS_ADDRESS`. The probe
    rehearsal therefore tries the following, in the capped slot:
    1. A Debian container with `dbus-daemon` and `gnome-keyring-daemon --unlock
       --components=secrets` under `dbus-run-session`, giving an unlocked login collection, so
       the managed recipe runs on a release build with no hook. Its session-lock source reads
       `unavailable` there, so policies use `continue`.
    2. If that works, the delaying relay in front of the bus socket. The background loop then
       forces issuer loads (`issuer unlock`, issuer restarts) and runs managed `ensure` requests
       that issue certificates, while the TUI's keys are timed. The delay reaches the store
       load, which is capped at 5 s per operation, not each signature.

    The same container answers whether lane M can run in the 72-hour run of record (W3-4).
  - **If neither is possible** without a hook, the row is a stated limitation: "key handling
    measured under fast concurrent operations; not measured under slow provider work". The
    go/no-go draft carries it. There is no option (b).
- **Platforms:**
  - the Mac's Docker (Linux arm64, supplementary);
  - the WSL2 distribution on the PC (Linux x86-64), with a fresh harness world there;
  - Windows and macOS only in the B2 and B3 accounts.
- **Records:** `tests/evidence/m08-a34-benchmarks.json`, with the host, its load samples and
  every condition.

## W3-7. Owner inputs that decide rows (m08-plan §12)

| Input | Without it |
|---|---|
| B2, B3 (disposable Windows and macOS accounts) | Windows and macOS release rows of A31 and A34 stay `blocked`; debug-build mechanism evidence only |
| B15 (clean VMs) | The Windows and macOS clean-machine rows stay `blocked`. The Linux x86-64 row runs in the disposable WSL2 distribution |
| B9 (native arm64) | Linux arm64 stays container-only, supplementary |
| B13, B16 | No signature claim beyond ad hoc |
| B17, B18 | `LICENSE` and `SECURITY.md` are not packaged, so no release |
| B1, B11 | The provider and release-managed soak rows stay `blocked` |
| An idle PC window of about 8 hours | The WSL2 clean-machine row, the Linux x86-64 benchmarks and the 6-hour cross-check wait |

## W3-8. Follow-ups carried in from W2

- **F-LOCKFLAKE** (assigned by the orchestrator): the M03 lock-harness self-test's timeouts of
  about 1 s under load. It is test-only, and must land before the candidate gate, so that the
  gate of record does not flake.
- **The fuzz RSS watch items** (W3-5).
- **The feature self-test's output:** print the refusal line beside each case, the next time
  `build-release-features-selftest.ps1` changes (job 59's note).

## Answers folded in (2026-11-24)

1. **The fuzz volume:** a second volume, `hm-m08-fuzz-rc`, for the campaign of record. W2's is
   kept until the exit (W3-5).
2. **The slow-provider probe:** run early on W2's build as a rehearsal, in the free capped slot
   (W3-6).
3. **Lane M:** in the 72-hour run of record if the release build runs it with no hooks (a real
   secret service in the container). Otherwise `blocked` on B3 or B11 (W3-4).
