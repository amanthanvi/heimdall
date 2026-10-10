# ADR-0002 revision 3: adversarial review, decision logic and fairness lens

Task M00-T05-adr0002-review3-logic. Read-only; written only here. Reviewed the uncommitted
`docs/decisions/0002-language-tui-distribution.md` (revision 3) and, as its inputs,
`tests/evidence/artifacts/g02-r4/x2/RESULTS.md`, `docs/g02/slice-contract.md` §9.7,
`tests/evidence/g02-{go,rust}-x1b-windows.json`, and
`tests/evidence/artifacts/review-adr-0002/rescore-r4/`. HEAD moved from 101aeeb5 to ca3ef37f during
the review; ca3ef37f committed the companion files and did not touch the ADR, so the diff reviewed is
unchanged.

**Verdict: ready after fixes.** 0 blockers, 5 majors, 10 minors.

## Majors

**M1. The headline total is a midpoint on Q-A while §7.3 says it assumes Iroh in V1.**
§7.1 release row: "deferred ... about Go 5 / Rust 3; in V1 ... about Go 3 / Rust 4. 4/4 is the
midpoint while that is open." §7.3: "Spec §3 makes Iroh a V1 target ..., so the scores above assume
it stays." These contradict. Under the stated V1 assumption the release row is 3/4 and the totals
are Go 3.30 / Rust 3.90 (lead 0.60), not 3.50 / 3.90. The deferred case stays Go 3.70 / Rust 3.65.
The headline embeds a 50/50 hedge on a decision the ADR asks the owner to make, and understates the
swing Q-A produces (0.60 to a 0.05 Go lead, not 0.40). Direction unaffected. *Fix:* score the base
under the spec default (Go 3.30 / Rust 3.90) and show the deferred table as the alternative, or
present two complete tables; make the §9 headline conditional on Q-A.

**M2. One architecture's cost is scored, the other's is not.** The X2 T1 recovery difference is,
per `t1-calibration/verify/README.md`, "a consequence of the two baselines' process-group models,
not of anything the six T1 implementers wrote": Go isolates the child (its `run_unix.go` header at
84c7665 gives the siginfo reason) and pays with the P1 recovery trap; Rust shares the group and pays
with double delivery of Ctrl-C, Ctrl-\ and resize on macOS (`runner.rs` header at 001a791; ADR §5
calls it user-visible; §6.1 called the two designs' failures "of comparable weight"). Revision 2's
security-core row counted both as offsetting ("Signal origin favours Rust on Linux; terminal-signal
duplication favours Go on macOS", HEAD line 336). Revision 3 removed both from that row, then
counted the Go design's cost in maintainability (T1, -1) and the darwin SIGSTOP misdecode in
cross-platform, while the Rust design's macOS cost appears in no scored row (grep of §7.1 for
twice/double/K6b/duplicate/macOS/darwin finds only the Go item). §7.1 and §9 also call T1 a
"Go-stack pitfall" / "the Go stack set two traps", stronger than §6.2 and the X2 record ("an
architecture effect that each language's signal API shaped"; avoidable within the Go stdlib; none of
the Rust cells' new code produces the recovery). *Fix:* count both signal-model costs in scored rows
or neither; adopt the X2 record's wording for T1 in §7.1 and §9.

**M3. D3 (l) is framed as binary, omits its provenance, and is mis-cited.** `x2/RESULTS.md` §5.1
gives three rubric readings: as applied (3-0 Go majors); third-party stops implausible (0-0); "if a
wrong job state counts as major whatever the recovery, all six cells get a major" (3-3). The ADR
offers the owner only the lenient alternative; the strict reading also removes the split. The 3-0
exists only in the middle reading. The calibrated rubric and cross-cell review were not
pre-registered outcomes (`docs/g02/round4-plan.md` row X2 lists hidden tests, regressions,
independent-reviewer defects, effort, all of which tied); they were added after per-cell reviewers
"proved inconsistent", and `orchestrator-prereg.md` shows the row moving 4/4 to 3/4 after them.
Opus concern 3 raised this; the ADR does not carry it, nor the mitigations (blind re-classification,
P1 independent re-run on byte-identical binaries, T3 N1 in tmux and xterm.js). The ADR also never
states what the maintainability score becomes under each reading. §7.3 cites "D3 k" for the X2
rubric; it is D3 (l). *Fix:* list all three readings with the resulting row score and totals; add
one sentence on provenance and mitigation; correct the cross-reference.

**M4. "Blind to the orchestrator" and "all four scorings agree" overstate independence.** The
timestamps hold (prereg 04:58:15, first re-scorer 05:04:05): the re-scorers did not see the round-4
scores. But `SCORER-BRIEF.md` gave them the revision-2 "low-confidence lean to Rust" as the prior,
and the X2 record they were sent to first (at HEAD 101aeeb5, live during the re-score) carried §6
"Reading for ADR-0002 (inference, for the re-score)" asserting "5 of 12 ... against 0 of 12 ... Both
causes sit in the Go stack" and a Fisher p of 0.02. All three adopted the implied 3/4; all three
also rejected the Fisher claim and two rejected the attribution, so they were adversarial but
primed. §7.1 uses the agreement as the confidence basis in three rows ("all four scorings agree";
"medium for direction ... all four scorings gave 3/4") and §9 leans on it. Three of the four
scorings rate this row or the recommendation "low". *Fix:* state exactly what the re-scorers were
blind to and what they were given; set the maintainability direction confidence to low or justify
medium; qualify §9.

**M5. D3 (k) hides the tension with D3 (j).** The §9.7 facts are correctly recorded
(`x1b-review-rust.json` defect 1, including the `Process.Start` control). The rationale is the
problem: §9.6 gated Go's argument injection under "§4 'without a shell' also covers batch files"
although a plain `CreateProcessW` of a `.bat` also hands the arguments to `cmd.exe` (BatBadBut), so
plain-exec equivalence was set aside for arguments; §9.7 then invokes plain-exec equivalence to
exclude the path. The defensible distinction (arguments are more often attacker-influenced than a
configured target path) is stated nowhere, so the owner ratifies (k) without seeing it. Codex rated
the security gate uncertain for both pending this ruling and asked for it as an owner question; the
ADR carries that only as a bracket in §3. §9 reason 1 says Rust "launches Windows batch files with
correct escaping" without the argv[0] qualification every other section carries. *Fix:* add the
threat-model distinction and the tension to D3 (k); qualify §9 reason 1.

## Minors

- **m1.** §7.2 "they differ on cross-platform, release and TUI by one point each": Fable also gave
  Go 3 on ecosystem (`fable/scores.json`).
- **m2.** §7.2 names "Codex GPT-6.1 Sol"; `codex/scores.json` names no model ("Codex independent
  scorer"). Cite the launch record or drop the model name.
- **m3.** §7.3 "TUI library" bullet: "the TUI row then ties" is already 3/3; the bullet does not say
  what maintainability becomes on T1 alone or with D3 (l) also overruled (4/4: Go 3.65 / Rust 3.90
  with Iroh in V1). Fable's owner question 4 (may the chosen language change TUI library?) is not in
  §10.
- **m4.** Q-B states only Go's cost; a Rust product launching batch targets also needs the §9.7
  path refusal/escaping component (smaller than Go's).
- **m5.** Rust's X1b drift (`x1b/rust/build/compare.txt`: same-day rebuild of d8f0cbe differs from
  the round-3c artifacts on three targets, cause "not investigated") is a scored negative and a §9
  rejection reason; Go's drift (go 1.27.1 to 1.27.2) is a §2.4 footnote. Both are host-toolchain
  drift (X3 used zig 0.16.0, the T1 verification zig 0.17.0, `build.sh` pins rustc not zig).
  Present both together: Rust's undiagnosed, Go's explained.
- **m6.** `cross-review/T4/README.md` §2: Rust notices generation failed offline in every build while
  `build.sh` exited 0 (Codex concern 7). §3 says "a full notices file ships"; §11 should require a
  fatal notices failure.
- **m7.** §9 "Choose Go if Iroh is deferred ..., if ..., and if ..." reads as a conjunction; §7.3
  says deferral alone is a tie.
- **m8.** §7.1 security core and §9 cite "17 modules vs 77-82 crates, many with unsafe" without
  X3's granularity caveat (modules bundle crates; the unsafe count is an uncfg'd upper bound,
  cargo-geiger 42 crates). All three re-scorers raised it.
- **m9.** §6.2 "Both were reproduced by an independent second execution" holds for P1 and N1 only;
  the other calibration scenarios, including the Rust P3/P8/P9e divergences the ADR cites, are
  `implemented_unverified`.
- **m10.** The SDK-free darwin cross-build (for Go) and the macOS SDK need (against Rust) in the
  cross-platform row are both moot if darwin artifacts are built on a macOS runner, which §11
  already requires for signing. Fable's owner question 7 asks this; §10 does not.

## Checked and found correct

- All totals (orchestrator, Codex, Fable, Opus, both prereg tables) and every §7.3 figure recompute
  from the row scores and the plan weights 25/25/20/15/10/5.
- Pre-registration ordering: prereg mtime 04:58:15, first re-scorer file 05:04:05, brief 04:30:32.
- plan.md §3 G02 gates and weights; D2 relabel per progress.md; spec §15.1 idle CPU budget 0.5 %;
  spec §3 Iroh V1 target deferrable only by recorded scope decision.
- X1: 67/71, 68/71, 8/16 injected (Go), 16/16 exact (Rust), 5-byte overwrite, pipe hang, Go refusal
  21-25 ms, linux-x64 139/139 both, first frame 40.2/20.2 ms, K17 17.7/2.7 ms.
- X1b records: status verified, commits and digests match the supersession notes; both reviews
  minors only; Go mutant killed; Rust 129 probes with 12 FAIL (9 trailing-dot, 3 %VAR% path); the
  ADR carries the %NAME% case (trailing-dot omitted, non-security).
- §9.7 restates the Rust review defect accurately, including the CreateProcessW control.
- X2: 24/24, 0 regressions, GM 1.02/0.98; 5 vs 0 from two causes; Fisher removed; darwin ^C
  correction carried; go-opus1 partial avoidance and go-opus2 repaint described correctly; Rust
  P3/P8/P9e and T2 190-205 MiB carried; T3 N1 reproduced in tmux 3.8 and xterm.js 6.0 on
  byte-identical builds; all three Go T1 cells decode the raw wait status.
- The Go baseline's header comment states the siginfo rationale itself, so §6.2's "its author chose
  because os/signal gives no siginfo" is the author's stated reason.
- X3, X4, X5, X6 figures the ADR cites (modules/crates, cross-host reproducibility with the darwin
  re-sign caveat, PIE/RELRO, GoReleaser, cargo-dist, cargo auditable; typed vs untyped bindings,
  pointer-lifetime pitfall, purego Linux-built darwin binary, no Go Keychain library,
  security-framework maintainer badge, plain vs DH session, pipe checks 5/5, DPAPI/CNG/TPM
  blocked; 12/12 iroh builds, 6-8x, 226-line supervisor, 1.5 s, iroh-go, 51k forked lines, Windows
  not run, Rosetta; 1 of 20 russh advisories, tie or +/-1, SIGSTOP root cause) all match their
  records.
- G03 §0: 17 verified, 11 blocked or in progress; Q-C's blockers match the table.
- Security-core row excludes the X2 finding; the T3 split follows the X2 caveat and both rows
  disclose it.
- Re-scorer owner questions carried except Fable Q4, Q7 and Codex Q4 (language-neutral G03 E-3).
  Re-scorer evidence concerns carried except those listed in M3, M4, m5, m6, m8, m9.
- §3.2's "neither uncertain gate separates the two" agrees with all three re-scorers.
- §10 presents D1 and four answerable questions; Q-A is correctly the largest lever.

## Would I reach the same recommendation and confidence?

Same direction, lower confidence, conditional. With Iroh in V1 the evidence leans Rust: the X2
undetected-defect pattern is real and reproduced, typed platform bindings are a structural difference
even though DPAPI/CNG/TPM never ran, and a Go product carries a Rust helper. With Iroh deferred the
scores do not separate the two. Confidence: low, not low-to-medium, because the four scorings share
one X2 reading (M4), the T1 half of the maintainability signal is an architecture effect whose
Rust-side counterpart is not scored (M2), and the 3-0 split exists in only one of three rubric
readings (M3). None of M1-M5 flips the direction; M1 changes the size of the lead shown to the owner,
M2 and M3 change how much of it rests on contestable readings.
