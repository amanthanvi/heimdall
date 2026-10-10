# ADR-0002 revision 3: decision-logic and fairness review, round 2 (recheck)

Task M00-T05-adr0002-review3-logic-recheck. Read-only; written only here. Reviewed the uncommitted
`docs/decisions/0002-language-tui-distribution.md` after the round-1 fixes (diff against HEAD
ca3ef37f), `docs/g02/slice-contract.md` §9.7, and, for the claims the fixes introduced,
`x2/RESULTS.md` §5–§6 (current and at 101aeeb5), `x2/t1-calibration/README.md`,
`x2/cross-review/T3/README.md`, `x4/windows/RESULTS.md`, `m00-wf8/x1b-review-rust.json`, the three
re-scorer records and `orchestrator-prereg.md`, and `progress.md` line 81.

**Verdict: ready after fixes.** 11 of 15 round-1 findings resolved, 4 partly, 0 unresolved.
2 new majors, 7 new minors, no blocker. Same recommendation and confidence as round 1.

## 1. Resolution of the round-1 findings

| # | Status | Note |
|---|---|---|
| M1 midpoint vs V1 | resolved | One base stated (Iroh in V1, 4/4 offsetting), deferred case separate. The chosen base is the minority re-scorer reading; see N1. |
| M2 signal-model asymmetry | resolved | Both baselines' costs in the security-core row, netted 4/4; SIGSTOP misdecode moved there; the baseline-inheritance caveat sits next to "two traps" in §7.1 and §9. Residual: N4. |
| M3 rubric readings / provenance / cross-ref | partly | Three readings with counts in §7.3 and D3 (l); calibration timing and interim 4/4 disclosed; cross-ref fixed. The added mitigation clause in D3 (l) overclaims (N2). My round-1 "blind re-classification" was the imprecise source. |
| M4 re-scorer independence | resolved | §7.2 says what they saw (verified against SCORER-BRIEF.md and the 101aeeb5 §6); confidence cells and §9 carry the caveat; recommendation confidence is low. |
| M5 D3 (k) rationale | resolved | Threat-model rationale, Codex's uncertain rating, overrule consequence, §9 reason 1 qualified. Precision point: N6. |
| m1 ecosystem disagreement | resolved | |
| m2 Codex model | partly | Gap disclosed, no path. No launch record exists in the repo or the scratch dir; only progress.md:81 (the orchestrator's own log) names GPT-6.1 Sol. Cite it or drop the name. |
| m3 TUI-library bullet | resolved | Row under T1 alone and with (l) overruled computed; Q-E added. |
| m4 Q-B Rust side | resolved | |
| m5 drift symmetry | partly | §9 and §2.4 side by side; the §7.1 release row still names only Rust's drift. Small. |
| m6 notices false-green | resolved | §9 and §11. |
| m7 "Choose Go if" | resolved | Deferral = tie, weighting = tiebreaker. |
| m8 granularity caveat | partly | In §7.1; the §9 bullet still repeats the raw numbers. Low weight. |
| m9 what was re-run | resolved | |
| m10 macOS runner question | resolved | Q-F. |

## 2. New findings in the changed passages

**N1 (major). The two sensitivity anchors each use the re-scorer reading most favourable to Go,
and the ranges are not shown.** §7.1 now scores the release row 4/4 "assuming Iroh in V1".
Fable (`scores.md` line 128) and Opus (release basis) both read the V1 row as Go 3 / Rust 4, and
the draft of this revision said the same ("in V1 about Go 3 / Rust 4"); only Codex scores 4/4 with
Iroh. Under 3/4 the totals are Go 3.30 / Rust 3.90, a 0.60 lead, not 0.40. For the deferred case
§7.3 adopts Go 5 / Rust 3 (Opus's reading); Codex (demonstrated path) and Fable read it Go 4 /
Rust 3, which with ecosystem 4/3 gives Go 3.50 / Rust 3.65, Rust by 0.15, not a tie. The prereg's
4/4 is described there as "Offsetting; Go leads without Iroh, Rust with it", a cross-scenario
judgment, and the move of the orchestrator's own V1 reading from 3/4 to 4/4 is explained nowhere.
Direction unchanged and the selection is conservative against the recommendation, but Q-A is the
owner's largest lever and is described as "0.40 to a tie" when the four scorings' readings span
"0.40–0.60 to between Rust +0.15 and Go +0.05". *Fix:* add both ranges to §7.3; reword Q-A and §9
to "deferral narrows the lead to between a 0.15 Rust lead and a 0.05 Go lead, a tie within
precision"; say in the release row that 4/4 in V1 is the Codex reading and 3/4 the two Claude
re-scorers'.

**N2 (major). D3 (l) claims the rubric was "applied by agents that did not know which cell's
reviewer had rated what".** `t1-calibration/README.md` shows the opposite: the uniform
classification is "one row per (cell, defect): every defect the cell's reviewer listed", each table
carries the reviewer's severity in a `reviewer` column next to the calibrated `class`, and a section
"Where this contradicts a reviewer" lists the reversals (go-opus2 D1 minor→major, rust-sonnet1 D1
major→minor). The independent check was given `results.json` (which holds the cell reviews) "but
not this classification", so it was blind to the first classification, not to the reviewers'
ratings. `cross-review/T3/README.md` likewise "confirms or refutes each reviewer-listed defect".
The sentence sits in the ruling the owner is asked to ratify and overstates the independence of the
pro-Rust T1 count on exactly the point M3 raised. *Fix:* "applied by one agent per task that
re-rated every defect the cell reviewers had listed, with their ratings in view; for T1 a second
agent, given the same evidence but not the first classification, reached the same three majors and
no Rust major."

**Minors.**
- **N3.** §2.4 X4 row gives Rust's 20 unsafe sites and not Go's 30 (`x4/windows/RESULTS.md`
  line 66: cng 24, dpapi 5, pipe 1; counts mechanical, styles differ). Introduced by the F2 fix.
  Give both or neither.
- **N4.** The security-core row cites §6.2 (X2) for "fails harder when a stop goes wrong" while
  saying X2 is counted in maintainability, not here. §6.1 probes 3–4 are pre-X2 evidence of the
  same point; cite those.
- **N5.** §7.2 table says the orchestrator's recommendation is "Rust, low to medium"; §9 and §13 say
  "low". Label the column pre-registered or update the cell.
- **N6.** D3 (k) and §9.7: "Exploiting the path needs control of both a directory name on it and an
  environment variable" holds for the injected-command case; the wrong-file case
  (`os%OS%y\fwd.bat`) used the standard `%OS%` and needs only a `%`-bearing path and a directory.
  The threat-model conclusion stands; state the prerequisites per case.
- **N7.** §9 Go paragraph: "All are fixable or avoidable, as one implementer in each X2 task
  showed." No Go T1 cell avoided the major (go-opus1 D1 stays major under both recovery
  definitions; `kill -CONT %1` works only before `fg`). §6.2 says "partly avoided"; §9 should
  match: fixable (the T1 verification names stdlib fixes) or avoidable (one T3 implementer).
- **N8.** §7.3 commits to 3/4 when the maintainability row rests on T1 alone (the rubric-dependent,
  inherited half) but leaves the score open when it rests on T3 alone (the reproduced half):
  "scoring the row even gives 3.65/3.90". State the T3-alone score, and why T1 alone holds a point.
- **N9.** §7.1 cross-platform: the batch-argument escaping is cited "(X4)"; it is X1/X1b.

## 3. Checked and found correct

- All totals and every §7.3 figure recompute from the plan weights, including the figures N1 adds
  (3.30/3.90; 3.50/3.65; 3.75/3.65).
- §7.2's account of what the re-scorers saw: the brief names revision 2's lean; the 101aeeb5
  `x2/RESULTS.md` §6 says "Both causes sit in the Go stack" with the Fisher p in §5.3; the diff to
  ca3ef37f removes both. The confidence cells (two of three 4/4 on cross-platform; two scorers Rust
  +1 on TUI; all four 3/4 on maintainability; interim prereg 4/4 and 4/3) match the records.
- §6.2 and §7.1 provenance statements match `x2/RESULTS.md` §5 and §7; the independent re-run
  claims match §5.1 (P1 verified, the rest implemented_unverified) and T3/verify.
- "5 of 12", "concentrated in T1 (3 of 3) and T3 (2 of 3)", "5 of the 6 Go implementers of those
  two tasks", "most of their reviewers missed" match §5.3 and the cell-review counts.
- D3 (l)'s three readings and counts match `x2/RESULTS.md` §5.1; the §7.3 cross-reference reads
  D3 (l). D3 (k) and contract §9.7 carry the same text; the facts match `x1b-review-rust.json`
  including the `.NET Process.Start` control; §11 carries the M01 refusal stack-neutrally.
- §3.2, §7 and §9 consistently call the scores provisional until Q-D; Q-C lists the second Linux
  account and the in-progress rows; licensing and PIE rows match X3.
- §13 summarises both round-1 reviews accurately.

## 4. Section 10 and the recommendation

§10 is answerable in one sitting: D1 is a three-way choice, Q-A–Q-F are yes/no or either/or with
their consequences stated, and D3 (a)–(l) default to "stand". Two non-blocking improvements: order
by dependency (Q-D, Q-C: may D1 be recorded now; Q-A: which scenario; D3 (k), (l), Q-E, Q-F: which
readings; then D1) and add one line giving the default path's result with the §7.3 ranges. After
N1, Q-A should say "narrows to a tie within precision" rather than "makes it a tie".

Same recommendation and confidence as round 1: Rust + Ratatui, low confidence, conditional on Iroh
in V1. With Iroh in V1 every scoring and either V1 reading of the release row leaves Rust ahead by
0.40–0.60; with Iroh deferred the readings span Rust +0.15 to Go +0.05, a tie within precision.
N1 widens the range shown; N2 corrects an independence claim without changing the T1 count. Neither
moves the direction.
