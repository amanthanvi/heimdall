# Independent adversarial review (2) of ADR-0002 (G02 language/TUI/distribution)

Reviewer: independent agent, 2026-10-06. Subject: `docs/decisions/0002-language-tui-distribution.md` at commit
`19ed9ba` (status proposed). Earlier review: `tests/evidence/artifacts/review-adr-0002/review.md` (M1–M6, m1–m14).

Method: reads of committed evidence plus cheap recomputation (artifact sha256 and sizes, line counts, JSON fields,
weighted-score arithmetic, `codesign -dv` flags). Nothing was rebuilt and the harness was not run. Every "observed"
statement names its file. Items marked *inference* were not executed. Paths are relative to `<repo>`.

Severity: **major** = would mislead D1/D2 or misstates a gate; **minor** = factual error or omission that does not
change the picture alone; **cosmetic**.

Overall: the rewrite fixes almost all of the first review's findings, and the factual base (counts, digests,
measurements, environment) checks out almost everywhere. The remaining problems sit in the reasoning layer. The
main reason for recommending Rust leans on a signal-control advantage that the evidence shows only on Linux, and it
ignores a macOS behaviour where Go is observably better. The 0.20 score margin is presented as hinging on D2,
though either of two orchestrator-scored criteria flips or ties it on its own. And the child/IPC "pass" for both
finalists rests on a §9.5 classification that both reviewers escalated, but the gate table does not say so.

---

## 1. Status of the earlier findings

| ID | Status | Evidence / remaining gap |
|---|---|---|
| M1 (Go fail rested on post-hoc rulings) | **Resolved** | §1/§2.1: Go and Rust received every ruling before their last fix round; Go 139/139 both OSes (`tests/evidence/g02-go-conformance{,-linux}.json`). The `kill(0,SIGTSTP)` runtime-cause claim is gone. |
| M2 (K6c asymmetry) | **Partly resolved** | §5 now lists the reset dispositions for both (Go: QUIT/TERM/WINCH/PIPE; Rust: PIPE), and the security-gate cells no longer use them. But §9 reason 1 brings the asymmetry back: "Rust reaches all of them from safe std plus libc" while Go's resets are a "recurring cost". Rust's SIGPIPE reset has the same character (see N2). |
| M3 (Rust deviations missing) | **Mostly resolved** | §5 lists Rust's darwin duplicate terminal signals and SIGPIPE; §6 lists thread-spawn, SIGCONT-to-launcher and the nested shell; K6e was probed in rounds 3b/3c. Still missing: the macOS duplicate delivery is absent from "Why Rust could be rejected", and §9 reason 1 contradicts it (N2). |
| M4 (harness strength overstated) | **Resolved** | §2.2 is accurate on 136/136 (2.4.1), the scoped 2.4.2 run (6/6), the three harness reviews and the blind spots (`tests/g02/SELFTEST.md`). One count is wrong (n3). |
| M5 (TS verdict basis) | **Resolved** | §3.3 items 1–4 label K8's FFI clause as an orchestrator ruling the owner may overrule, and correct the musl claim and the freeze rationale. Small overreach remains (n7). |
| M6 (verdict vocabulary / reviewer differences) | **Partly resolved** | "marginal" is gone and Go and Rust are now symmetric on distribution. But the compound verdict "pass on Unix; Windows uncertain" is outside the declared vocabulary, and several reviewer verdicts are overridden without the promised note (n4). The review3c gate rows on §4 are not reflected in the child/IPC cells (N1). |
| m1 (Rust sizes) | **Resolved** | 0.72–0.88 MB (0.37–0.45 gzip) matches `prototypes/rust/dist/manifest.json` (718,080–876,464 B) and the round-3 tar.gz9 values in `g02-measurements.json` (373,642–448,197 B). |
| m2 (TS failure list) | **Resolved** | Matches the non-pass checks in `g02-ts-conformance{,-linux}.json` (K14 ×2, K8, K6a ×3, K6e, K12; K6d error; darwin resize). |
| m3 (disclosed majors) | **Obsolete** | The Go gate failure no longer exists. |
| m4 (commit IDs) | **Resolved, small residue** | §2.1 explains `build_commit = HEAD+dirty` and the digest link, and the commits exist (`git log`). Residue: `dist/manifest.json` is gitignored, the selftest records use other `build_commit` forms, and no reviewer reproduced the TS digests (n9). |
| m5 (Go selftest record) | **Obsolete for the ADR** | The ADR no longer cites it. Related evidence inconsistency: Go's record is `blocked` (Windows) but Rust's is `verified`, with Windows equally unexecuted (e2). |
| m6 (floor) | **Resolved** | 2.1 ms / ~6 ms matches the round-3 control rows (2.097 / 5.744–6.254). |
| m7 (LOC) | **Resolved** | Recomputed: Go 2,396 non-test `.go` lines; Rust 2,601 `src/**/*.rs` lines with `#[cfg(test)]` blocks removed; TS 1,414 `src/**/*.ts`. Like-for-like. |
| m8 (ring/zig) | **Resolved** | §8 and §9 reason 3 name ring under zig as an untested G06 risk. |
| m9 (Iroh deferral; Rust rejection) | **Resolved** | §8 is labelled a deferral to G06 with the G02-level position. §9 has "Why Rust could be rejected". |
| m10 (Windows conditionality) | **Resolved** | §3.1 lists the same four items for Go and Rust, and §3.1 and §9 say the recommendation is conditional on G03. Cosmetic: no TS column (c4). |
| m11 (`forbid` wording) | **Resolved** | §7 says `deny(unsafe_code)` with one allowed `sigaction`, matching `src/lib.rs:17` and `src/sigdisp.rs:58`. |
| m12 (round-2 position) | **Obsolete** | |
| m13 (inference as fact) | **Partly resolved** | White-on-white is now "probably … (inferred)". New instances: the Go goroutine-panic exit 2 is marked inferred in §5 but used as fact in §7 and §9 (N2), and the "agent experience" claim has no source (n6). |
| m14 (canary) | **Resolved** | §2.2 cites `CANARY-REDACTION.md`. Note e3. |

---

## 2. New findings

### Major

#### N1. The child/IPC "pass" for Go and Rust rests on the §9.5 non-gating classification, which both final reviewers escalated; the gate cells and D3 do not say so

- ADR §3 cells: "**pass**: 139/139 … review3c could not refute it. Non-gated deviations are in §6". §3 preamble:
  "Where a verdict differs from the round-3b/3c reviewer's verdict, the cell says so." D3: "§9.5, no further fix
  round for the two third-party-stop majors."
- Evidence:
  - `tests/evidence/artifacts/m00-wf6/review3c-go.json` hard_gate_findings: "§4 'heimdall-proto waits for the child
    and does not exit first' / no orphaned child, darwin … **uncertain** … Observed violated on darwin … a contract
    question I am escalating."
  - `m00-wf6/review3c-rust.json` hard_gate_findings: "No regression of round-3b behaviour: **fail**", with the
    escalation "the contract does not rule on third-party stop/continue of the child, so I am escalating."
  - `docs/g02/slice-contract.md` §9.5 makes two decisions. It classifies the cases as being "on paths that neither
    the harness nor §9.4 gates", recorded as deviations; and it declares no further fix round. The ADR's D3 offers
    the owner only the second. The ADR itself says both "violate the spirit of §4" (§6).
- Why it matters: if the owner reads §4 ("waits for the child and does not exit first", no orphan) as covering
  third-party stops, **both** finalists fail the child/IPC hard gate. G02 would then have no passing candidate
  until a fix round. The gate verdict is an orchestrator classification layered over two reviewer escalations, and
  the cell presents it as an unqualified pass.
- Suggested correction: in both child/IPC cells, add "pass under the §9.5 classification. Review3c rated §4
  'uncertain' (Go, darwin SIGSTOP orphan) / 'fail' on no-regression (Rust, third-party stop hang) and escalated
  both." In D3, split §9.5 into (a) "these cases are not gated under §4" and (b) "no further fix round". State
  that overruling (a) turns both gate cells to fail.

#### N2. Recommendation reason 1 and the 25 % security-core score (Go 3, Rust 4) rest on an asymmetric, partly inferred account of signal control; on macOS the evidence favours Go in the common interactive case

- ADR §9 reason 1: "Rust reaches all of them from safe std plus `libc`. Go needed workarounds in three places where
  the runtime or standard library decides: disposition resets (cgo to fix), goroutine panic exit codes, and the
  darwin wait-status decoding. Each of those is fixable, but each is a recurring cost." §7 security-core basis:
  "Go's remaining limits sit in the runtime or standard library: no `siginfo`, disposition resets that need cgo,
  goroutine panics that exit 2. Rust's sit in its own code, plus one std SIGPIPE limit."
- Evidence:
  1. **Rust does not reach SIGPIPE's inherited disposition from std at all.** `prototypes/rust/REPORT.md` line 192:
     "Rust std sets SIGPIPE to `SIG_IGN` before `main` (so the inherited disposition is unknowable) and resets it to
     `SIG_DFL` in every spawned child; the opt-out … is nightly-only … Workarounds (`#![no_main]` entry, `pre_exec`
     re-ignore) bypass the std runtime and were not applied (K8 spirit)." This is the same class of limit as Go's
     reset (runtime decides; remedy bypasses the runtime). The ADR's own §5 row says so, but reason 1 says the
     opposite.
  2. **`siginfo` helps Rust only on Linux.** On darwin, Rust's exec-semantics design forwards every
     terminal-generated signal that the child already got from the kernel. `prototypes/rust/REPORT.md` lines
     343–349 (round 3c, still `known_limitation` at line 468) say: "One Ctrl-C reaches the child **twice** … The same applies to Ctrl-\ (SIGQUIT),
     terminal resize (SIGWINCH) … A child that counts SIGINT … behaves differently on macOS." Go's exclusive mode
     (the ordinary interactive case) delivers terminal signals once on both OSes: `m00-wf5/review3-go.json`
     refuted_claims, "My independent terminal ^C through heimdall-proto gave exclusive 1/1/1 and shared 2 every
     time, on both OSes and three shells." So on the owner's own platform, Go meets §4's "a terminal-generated
     SIGINT is not delivered twice" in the common case and Rust does not (K6b permits both deviations). For balance,
     Go can double a hangup SIGHUP in exclusive mode (`prototypes/go/REPORT.md` line 373, "Not measured").
  3. **"Go needed workarounds in three places" is not what happened.** None of the three was worked around. The
     dispositions are a recorded K6c limit, the panic was never addressed, and the darwin wait-status is an open
     major. The goroutine-panic exit 2 is "Inferred from the bubbletea source, not demonstrated" (ADR §5;
     `m00-wf5/review3-go.json` unverifiable_here), yet §7 and §9 use it as a fact.
  4. Go's darwin wait-status major is counted as a "recurring cost" of the language, while Rust's stop-mirror major
     is counted as a one-off design issue. Both are single, localized defects (see n2 on remedies).
- Why it matters: reason 1 is the first and main reason for the recommendation, and the 25 % security-core score
  difference (0.25) is larger than the whole 0.20 margin (N3). As written, the owner is told Rust has categorically
  better control of the hardest area. The evidence supports "better on Linux (siginfo), worse on macOS for
  terminal-signal duplication, equal in kind on runtime-imposed disposition resets".
- Suggested correction: rewrite reason 1 per platform. Add "on macOS every terminal Ctrl-C/Ctrl-\/resize reaches
  the child twice (K6b-permitted); Go's exclusive mode delivers once" to "Why Rust could be rejected". Mark the
  panic exit code as inferred everywhere. Restate the §7 basis without "Rust reaches all of them". Then re-justify
  the 3-vs-4 score, or show it as contested (N3).

#### N3. "D2 is the deciding input" is misleading: the 0.20 margin ties or flips on a single-point change to either of two orchestrator-scored criteria, and one of them is undercut by the ADR's own text

- ADR §7: "Because these scores are judgments, a different reasonable scorer could reverse a 0.2 margin. D2 is the
  deciding input." Only D2 sensitivity is shown.
- Recomputed (ergonomics neutral at 3 each): Go = 3.35 + 0.15·E_go = 3.80; Rust = 3.55 + 0.15·E_rust = 4.00.
  (Both ADR totals and the "+2 points" threshold are arithmetically correct.) But:
  - Security core 25 %: Go 3→4 gives **Go 4.05 vs Rust 4.00**. The 3-vs-4 basis is the contested reasoning in N2.
  - Release simplicity 20 %: equal scores (both 4 or both 5) give a **tie at 3.80/3.80** (or 4.00/4.00). The ADR
    scores Rust 5 vs Go 4 on "Rust's is about 7× smaller", while §4 says "None of these differences is visible to a
    user at these sizes". Both ship one file; Go additionally builds every target without cargo-zigbuild.
  - Cross-platform 25 % (Go 5): the basis "Go cross-compiles every target with only its own toolchain" holds only
    while Go stays cgo-free and Iroh-free. §5's Go remedy is "cgo constructor", and §8/§9 offer Go "plus a Rust
    Iroh helper", which brings back a Rust toolchain, zigbuild and ring for the Go product (*inference* from §8;
    not built).
- Why it matters: the owner is told to focus on D2, but two of the orchestrator's own single-point judgments are
  each enough to change the outcome. The owner needs to be invited to rescore them, not only ergonomics.
- Suggested correction: add a one-line sensitivity per criterion (the gap each needs to flip). Say explicitly that
  the security-core and release-simplicity scores are as decisive as D2. Either drop the size-based release point,
  or reconcile it with §4's "not visible".

### Minor

#### n1. §6 lists Q16 as "Found in both Go and Rust", but neither final build shows it
- ADR §6: "**Found in both Go and Rust:** … Q16: a launcher may report a child's self-stop to the shell and then
  resume the child early."
- Evidence: `observations.k6e_child_self_stop` in all four final records (`g02-{go,rust}-conformance{,-linux}.json`)
  has `resumed_before_fg: false` in every observed form. Q16 comes from the harness reviewer's mutation
  `rv_cont_child_first` (`m00-wf6/review-harness-r4.json`), not from either prototype.
- Correction: move Q16 to the M01 input list (§11 already has it) and drop it from "found in both".

#### n2. The Go and Rust majors are scoped and characterized asymmetrically
- ADR §6 Go: "If the run child is stopped by SIGSTOP (sent by itself or by another process), `heimdall-proto` exits
  255". The reviewer says "**in exclusive mode**" (`review3c-go.json` defects[0]). In shared and no-tty modes, Go
  does not set `WUNTRACED` (`prototypes/go/internal/run/run_unix.go` lines 240–243), so those modes are not
  affected (*inference* from code).
- ADR §6 end: "Go's remedy is local and small; Rust's needs a design choice". §9: Rust's stop mirror "needs real
  design work". The Rust reviewer offered a narrowing: "mirror only when heimdall-proto's process group is the
  terminal's foreground group or a job-control context" (`review3c-rust.json` defects[0]). That is essentially
  what Go already does: it mirrors only in `modeExclusive`, while Rust's `run()` loop mirrors on every stop report
  (`prototypes/rust/src/runner.rs` lines 315–322). *Inference*: Rust's remedy may be about as local as Go's.
  "Real design work" is stronger than the reviewer's "escalating rather than deciding".
- Probe asymmetry: the Rust reviewer's `extstop.py` (third party stops and then continues only the child; reviewer
  parent non-interactive), SIGCONT-to-launcher and nested `bash -i` probes were not run against Go. *Inference*
  from `run_unix.go`: Go would not hang in the non-interactive case (no mirroring without a tty). In an
  interactive exclusive session, however, Go would stay stopped (the shell shows "Stopped") while a third party has
  continued the child, until the user runs `fg`. Neither is observed.
- "**Both majors** involve stops sent by a third party" conflicts with the Go major covering a self-sent SIGSTOP.
- Correction: add "(exclusive mode, i.e. interactive foreground)" to the Go major. Cite the reviewer's narrowing
  option for Rust. Soften "real design work". Note that the Rust-only probes were not run on Go.

#### n3. Harness review count for round 3c is wrong
- ADR §2.2: "v2.4.0 additions (round 3c) | 15 / 22".
- `m00-wf6/review-harness-r4.json` `mutations` has 22 entries. Two are conforming controls
  (`ctl_mirror_sigstop_always`, `ctl_mirror_delay_1s`), which correctly passed. Realistic defects: 20, caught: 15
  (K6e 8/12, K12 7/8, per the summary).
- Correction: "15 / 20 (2 conforming controls correctly accepted)". The follow-up text should also name Q16
  (`rv_cont_child_first`) and the SIGSTOP ruling (`rv_mirror_tstp_only`) among the "ruled" misses.

#### n4. Reviewer verdicts overridden without the promised note; compound verdict outside the vocabulary; "uncertain" misdefined for dependencies
- §3 preamble promises to flag differences from the round-3b/3c reviewer. Undisclosed differences:
  - Go practical distribution: `review3-go.json` **pass** → ADR uncertain.
  - Go security: reviewer **pass** → ADR "pass on Unix; Windows uncertain".
  - Rust security: `review3-rust.json` **uncertain** (Windows exe search order) → ADR "pass on Unix; Windows
    uncertain".
  - TS maintained dependencies: `m00-wf3/review-ts.json` **pass** → ADR uncertain.
  The ADR's harmonized verdicts are defensible, but the overrides should be stated.
- "pass on Unix; Windows uncertain" is a compound verdict, while §3 says only pass/fail/uncertain are used.
- §3 defines "uncertain" as "the evidence needed is not available on this host". Maintained dependencies is
  uncertain for all three as a judgment, not a host limitation (`review3-go.json`: "Maintenance quality is a
  judgment the evidence does not settle"). §3.2's "Go and Rust pass every gate that can be judged on this host"
  therefore glosses over a hard gate that is judgeable now but unresolved. plan.md §3 G02 puts hard gates "before
  preference scoring".
- Correction: add "(reviewer: X)" where different. Use "uncertain (Unix pass; Windows not executed)". Add an owner
  item to accept or reject the dependency caveats (ultraviolet pseudo-version, crossterm release cadence).

#### n5. Measurement-table errors and omissions (§4)
Checked against `tests/evidence/g02-measurements.json`. Every Go, Rust and control value in the table matches.
Exceptions:
- TS keystroke p50 is shown as "—", but round 2 measured 3.726 ms (`comparison_round2_vs_round3.tui_keystroke…
  .ts_round2_frozen_p50_p95 = [3.726, 7.379]`). It is about equal to Go's 3.90.
- TS filter typing is shown as "not re-run", but round-2 data exists (`tui_filter_typing_p50_p95.ts_round2_frozen =
  [3.319, 6.882]`). The Go and Rust numbers in that row come from the same `measure.py` filter-typing series, not
  from the harness K17 check, so the label "K17 method" needs checking too.
- linux-x64 row, TS "up to 97 MB": the linux-x64 TS artifact is 86,205,920 + 6,314,816 B ≈ 92.5 MB
  (`prototypes/ts/dist/manifest.json`). The 97.4 MB figure is windows-x64.
- TS RSS is given in MiB (24.8 / 28.4) next to Go and Rust in MB. In MB it is 25.95 / 29.75.
- "load average about 1.5–5": the TS rows are from round 2, whose pass 1 started at about 6–7
  (`g02-measurements.json` limitations[0]).
- "a TUI about 5–7× faster after subtracting the floor": the keystroke rows have no control/floor row
  (`harness_floors_control_rows.note`). First-frame large-100 net p50 is 22.67 vs 4.63 ms, i.e. 4.9×.

#### n6. D2 inputs: the ergonomics claim is unsourced, and available effort data is not cited
- ADR §7: "Agent experience: Rust changes needed more build and type-checking iterations." No evidence path; I
  found none in `m00-wf*` or the REPORTs.
- The REPORTs record round-1 build effort: Go "About 25 minutes from module init to green tests"
  (`prototypes/go/REPORT.md` line 79); Rust "about 1 h 40 min total; first green tests after about 25 min"
  (`prototypes/rust/REPORT.md` line 54); TS "about 40 minutes" (`prototypes/ts/REPORT.md` line 82). These are
  single agent runs with different amounts of hard-problem debugging, so they are weak evidence, but they are the
  only measured ergonomics data.
- §9 "Why Rust could be rejected: More code" vs §9 Go: "Its prototype is about as large as Rust's" (2,601 vs 2,396
  lines, +9 %).
- Correction: cite the effort figures with caveats, or drop the agent-experience sentence. Make the size wording
  consistent.

#### n7. §3.3 slightly overstates the TS research, and understates the cost of its musl path
- "The environment hooks are now verified, not inferred." `m00-wf5/ts-research.json` limitations[0]: "'No such
  flag' is an inference from reading the source plus black-box tests of the candidate flags, not a proof for every
  Bun release." It is settled for Bun 1.4.2 (`744846f8`) only. The rejection stands, but the wording should be
  scoped to that version.
- Item 3 (musl): the same record shows the Bun musl runtime is dynamically linked and needs `libstdc++` and
  `libgcc` ("not a static-musl artifact"). It also shows the prototype's `pinNativeAssets` deletes `OPENTUI_LIBC`.
  A TS musl build is therefore not equivalent to the Go/Rust static binaries.

#### n8. D3 omits rulings that shape the Go/Rust comparison
- D3 lists K8, the freeze, Q16, Q17 and §9.5. Missing:
  - **K6b** (duplicate terminal-signal delivery allowed when documented): it is what makes Rust's macOS double
    Ctrl-C and Go's shared-mode duplicates non-gating.
  - **K6c** (non-gating disposition resets).
  - **K13** (the G02 verdict platforms are darwin-arm64 and linux-arm64 in a Docker VM; linux-x64 was never
    executed natively, and neither was Windows).
  - The §9.5 classification split from the fix-round decision (N1).
- Correction: add these four.

#### n9. Traceability details
- "The binding link … `dist/manifest.json` = record `artifact_digest`": `prototypes/*/dist/` is gitignored
  (`.gitignore:2`), so the manifests are not in git. Tracked copies of the Go/Rust digests exist in the records and
  in `g02-{go,rust}/review3c/build/manifest-*.json`. Cite those.
- "The reviewers reproduced those digests from source": true for Go and Rust (review3/review3c). No reviewer rebuilt
  TS, so the TS link is producer-only.
- "Each evidence record carries `build_commit` = the repository HEAD at run time plus `+dirty`": true for the six
  conformance records (`0aaee74…+dirty`). The selftest records use prose forms (`g02-go-selftest.json` "0aaee74
  (HEAD at round-3c start …)"; `g02-ts-selftest.json` `18bb8df…`).

#### n10. "Practical distribution: macOS … pass without a toolchain" is weaker than plan §3 G02's "clean … machines"
- `prototypes/rust/REPORT.md` line 36: "darwin ran with `env -i PATH=/usr/bin:/bin` on the build machine itself".
  Go's darwin check was likewise `env -i` on the host (`review3-go.json`). Linux "clean" means containers on the
  same host. Since both cells are "uncertain" overall, this does not change a verdict, but the cell text should
  say "env -i on the build host" rather than imply a clean machine.

### Cosmetic

- c1. §3 Go: "Ad-hoc hardened-runtime signing"; Rust: "Ad-hoc signing". Both darwin artifacts carry
  `flags=0x10002(adhoc,runtime)` (`codesign -dv`, observed), and both build scripts pass `--options runtime`.
- c2. "one static file" for macOS: both darwin binaries link libSystem; "static" applies to the Linux musl/Go builds.
- c3. §1 "TypeScript was frozen after round 1", but the §2.1 table shows TS received the alignment (K1–K12) fixes
  before the freeze.
- c4. §3.1 heading "same four items for each candidate" has no TS column.
- c5. §9: "a single-language Go codebase plus a Rust Iroh helper" is self-contradictory. Say "a Go codebase plus a
  separately built Rust helper".
- c6. §1 rulings list "(K1–K18, Q16, Q17)" omits Q18, which §2.2 and §11 use.
- c7. §3 Rust child/IPC: review3 rated it "uncertain" over the self-stop **and** the K12 mismatch; round 3c fixed
  both.

### Evidence hygiene outside the ADR (for the owner)

- e1. `m00-wf6/conf3c-ts.json` gives the linux artifact sha256 as `ac48d2a6c789bb07fcf1…`. The record and manifest
  have `ac48d2a6c789bb073168…` (they differ after 16 hex digits). This is a wrong digest in a workflow result. The
  authoritative record is correct.
- e2. Status discipline (CLAUDE.md: a platform-missing test is `blocked`):
  - `g02-rust-selftest.json` is `verified`, although Windows was not executed.
  - `g02-go-selftest.json` is `blocked` for the same reason.
  - Both TS conformance records are `in_progress`, despite a completed fail verdict.
- e3. `review3c-go.json` defects[3]: synthetic canary-form strings remain in `g02-go/selftest/selftest.py`,
  `schema_check.py` and the round-1 probe logs. A ruling on whether the canary rule covers synthetic names is still
  pending (my grep found 5 files with a canary-form prefix, none of them a fixture value; the 5th is the earlier
  review quoting a key name).

---

## 3. Verified correct (spot checks that passed)

- Round counts: round 3 Go 135/136 darwin, 134/136 linux (K6d; K6e Linux), Rust 136/136, TS 127/136 and 128/136
  (`m00-wf5/final-conf-*.json`); 3b Go and Rust 136/136 (`conf3b-*-r1.json`); 3c pre-fix Go 138/139 (K12 error
  results), Rust 137/139 (K6e self-stop, K12) (`conf3c-{go,rust}.json`); final 139/139 on both OSes for both
  (`conf3c-post-*.json` and the four records, harness 2.4.2); TS 129/139 darwin, 130/139 linux.
- Final commits `38b6b72` (Go), `d8f0cbe` (Rust), `0bd7df9` (TS) are the last commits touching each prototype.
  `git status` shows no changes under `prototypes/`. The on-disk sha256 values of the darwin and linux-arm64
  artifacts equal the manifests and the record `artifact_digest`s (`31c3ee17…`, `d55b4ffe…`, `496684ed…`,
  `47160fdd…`). Round-3 measurements were taken on exactly these digests (`g02-measure/round3/artifact-inventory-pre.json`).
- Review3/review3c rebuilt in `/tmp`, reproduced the digests, and re-ran 2.4.2 on both OSes (`review3c-{go,rust}.json`).
- §2.2: 136/136 on 2.4.1 per platform; 2.4.2 scoped run 6/6 plus a 139/139 baseline on both (`SELFTEST.md`); the
  round-2 harness review 1/21, and round 3 14/17.
- §2.3 environment strings match the records and the measurement environment.
- §4: every Go, Rust and control figure (startup, profile, first frame, keystroke, filter typing, RSS, 300 s idle
  CPU 0.35/0.03/0.06, sizes and gzip) matches `g02-measurements.json` round-3 and round-2 tables. Spec §15.1
  budgets and the 0.5 % idle target match spec.md lines 752–762.
- §6 Go items: exit 255 / meta `exit_code -1`, the `syscall_bsd.go` cause, REPORT mis-description, duplicate env
  keys, and Linux SIGSTOP reported as 148 vs control 147 (observed in `g02-go-conformance-linux.json`
  `k6e_child_self_stop`). §6 Rust items match `review3c-rust.json` and `review3-rust.json`.
- §7 arithmetic: totals 4.00 / 3.80 with neutral ergonomics; 0.15 per ergonomics point; Go overtakes at +2.
- §7 and §9 LOC: 2.4k / 2.6k / 1.4k non-test (recomputed, see m7).
- §3.3: K8 7 of 8 elements changed; spec §10.4 "to the extent defined by the platform" (spec.md line 502, §10.4).
  The BUN_OPTIONS/BUN_BE_BUN/BUN_INSPECT experiments are as described (`ts-research.json`).
- §8 Iroh facts and the spec §3.1 deferral rule (spec.md line 147; G06 row line 1270).
- §1: the prior Go preference is labelled historical, as plan §3 G02 requires.

---

## 4. What the owner still needs for D1/D2

1. **A per-platform view of signal behaviour** (N2): on Linux, Rust has `siginfo` and avoids duplicates; on macOS,
   Rust duplicates every terminal Ctrl-C/Ctrl-\/resize in normal use while Go's exclusive mode does not. Both
   have runtime-imposed disposition resets (Go: four signals; Rust: SIGPIPE).
2. **Sensitivity on every orchestrator score, not only D2** (N3): equalizing security core flips to Go (4.05 vs
   4.00), and equalizing release simplicity ties. The owner may want to rescore those two along with ergonomics.
3. **The §9.5 classification as an explicit decision** (N1): whether §4's no-orphan / wait-for-child rule covers
   stops by third parties. Ruling it gating makes both finalists fail the child/IPC gate.
4. **Whatever ergonomics evidence exists** (n6): the round-1 effort figures, with their caveats. An owner-side
   reading of a small diff from each prototype would be stronger evidence than anything in the repo (*suggestion*).
5. **Acceptance of the open hard gates** (n4): maintained dependencies is uncertain for all three as a judgment,
   and Windows/WSL is unexecuted for all three; the recommendation is conditional on G03.
6. **The Go-with-Iroh cost** (N3): choosing Go plus a Rust Iroh helper brings back a Rust toolchain, zigbuild and
   the untested ring cross-compile for the product. Go's cross-platform 5 assumes otherwise.
7. **Unprobed parity** (n2): the Rust-only third-party-stop, SIGCONT-to-launcher and nested-shell probes were never
   run against Go. Before treating §6 as a like-for-like list, either run them on Go or read §6 knowing the probe
   coverage differed.
