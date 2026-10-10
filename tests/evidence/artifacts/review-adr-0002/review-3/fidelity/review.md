# ADR-0002 revision 3 — evidence fidelity review

Task: `M00-T05-adr0002-review3-fidelity`  
Verdict: **ready after fixes**  
Findings: **0 blocker, 6 major, 4 minor**  
Reviewed working-tree ADR SHA-256: `c084f190eefe96e916fb7233927993e0c1da12e86ebdec72473d450e509e86fe`

No arithmetic error or refuted Windows pass count found. Six major issues affect gate completion, platform-FFI safety, visibility of demonstrated batch-path injection, X2 sample characterization, Iroh scenario assumptions, and the hardening comparison. Four minor issues concern stale/source-scoped platform statements, the Go license count, a rubric reference, and G03 status fidelity. Recommendation direction is not independently re-selected by this fidelity review.

## Findings

### F01 — major: §3.2, lines 210–213; §7 introduction, lines 427–430; §9 Go alternative, lines 565–566

**Claim:** "both must be closed before a release claim, not before D1"; "Go and Rust pass the same gates"; Go "passes every gate".

**Evidence:** plan.md:117–119 requires clean Windows/macOS/Linux artifact tests and names practical distribution and maintained dependencies as hard gates before preference scoring. The ADR itself marks both uncertain at lines 172–173 and 210–211. X1 RESULTS.md:263–278 records development-host, console, MOTW/SmartScreen/Defender and platform limits; X4 macOS RESULTS.md:35–36 records Gatekeeper rejection. No cited ruling moves these hard gates to release time; Q-D at ADR:605–607 asks the owner whether to accept that move.

**Fix:** Say both have the same five scoped passes and two unresolved hard gates. Present preference scores and D1 recommendation as provisional while those gates remain open. Remove the assertion that closure is already unnecessary before D1; obtain/record any owner-approved change to the G02 sequencing rather than treating Q-D as answered.

### F02 — major: §2.4 X4 row, line 152; §7.1 cross-platform basis, line 436; §9 reason 1, lines 526–529

**Claim:** Rust has "typed, safe wrappers (`security-framework`, `windows-sys`...)" and "reaches them through typed, safe wrappers" for Windows CNG/DPAPI/pipes/tokens.

**Evidence:** X4 windows RESULTS.md:37–40 describes typed windows-sys FFI rather than a safe high-level Windows wrapper, and lines 66–67 count 20 unsafe sites in Rust’s own spike (7 CNG, 11 pipe, 2 DPAPI). The source independently confirms unsafe CryptProtectData at x4/windows/rust/src/dpapi.rs:22–38 and unsafe NCryptOpenStorageProvider at cng.rs:12–17. X4 windows RESULTS.md:37 also says Go already has typed x/sys DPAPI wrappers; its untyped gap is NCrypt and one impersonation call, not every Windows API. The safe std pipe-client API and higher-level macOS wrapper are separate advantages.

**Fix:** Distinguish safe higher-level macOS/Linux wrappers and Rust’s safe std pipe client from typed but unsafe Windows FFI. State that CNG’s typed signatures catch argument-count/type errors but still require manual pointer, lifetime, handle and impersonation safety. Preserve Go’s existing typed DPAPI support. Correct the cross-platform score rationale accordingly; a score change is not mechanically required.

### F03 — major: §2.4 X1b row, line 149; §3 security row, line 171; §3.1 batch row, line 187; §9, lines 529 and 559; §10 D3(k), lines 626–627

**Claim:** The Rust batch-path issue is summarized only as "%NAME% ... expanded" or "batch-path expansion", next to the positive claim that Rust launches batch files "with correct escaping".

**Evidence:** tests/evidence/artifacts/m00-wf8/x1b-review-rust.json:70 and 97 records an attacker-controlled environment variable in the script path causing a second command to run and a different batch file to execute. docs/g02/slice-contract.md:457–466 explicitly records both consequences and excludes argv[0] only as a G02 ruling. tests/evidence/g02-rust-x1b-windows.json:727 retains the actual command injection and wrong-file execution and says the pass does not establish absence of this exposure. Independent probe report: 129 probes, 12 FAIL, including 3 percent-in-script-path cases (review-rust.json:37). Plain-exec equivalence does not remove the demonstrated exposure.

**Fix:** In the decision-facing Windows table/security caveat/rejection rationale, explicitly say "demonstrated environment-driven command injection and wrong-batch-file execution through argv[0]". Limit the correct-escaping claim to tested argv[1..] arguments. Keep §9.7’s non-gating classification separate from impact and the mandatory M01 refusal/launch-policy fix; the recorded classification need not be changed by this review.

### F04 — major: §7.1 agentic-maintainability basis, line 439; related §9 reason 2, lines 533–536

**Claim:** "most Go cells left a major the tests missed" (after "on four tasks").

**Evidence:** X2 RESULTS.md:280–296 reports 5 of 12 Go cells, not a majority: T1 3/3 and T3 2/3, with none in T2/T4. That is 41.7% overall, versus 0/12 Rust, and only two cause families. The underlying results.json independently contains 12 cells per language and all intended hidden suites pass. T1 recovery is inherited baseline architecture, not better work by the Rust implementers (X2 t1-calibration/verify/README.md:24–29); ADR §6.2 correctly carries that caveat.

**Fix:** Use "5/12 Go cells, concentrated in T1 (3/3) and T3 (2/3), versus 0/12 Rust; two correlated causes". Qualify "most implementers" as most implementers of those two tasks rather than most implementers/cells overall, and retain the baseline-architecture and small-sample caveats in the score/recommendation summary.

### F05 — major: §7.1 release/runtime basis, line 438; §7.3 Iroh sensitivity, lines 474–479 and 491–496

**Claim:** §7.1 calls 4/4 "the midpoint while [Iroh scope] is open", and supplies in-V1 release scores "about Go 3 / Rust 4". §7.3 instead says "the scores above assume it stays".

**Evidence:** The stated weighted arithmetic is correct for the published 4/4 row: 3.50/3.90, and the stated deferral changes produce 3.70/3.65. But the ADR’s own explicit in-V1 release basis of 3/4 would instead produce 3.30/3.90 with every other §7.1 row unchanged. X5 RESULTS.md:161–187 measures/infers the two-artifact helper boundary; G06 has not selected the final boundary. orchestrator-prereg.md:9 and 24 preserve 4/4 as an offsetting judgment rather than an explicitly in-V1 3/4 score. Thus the recommendation’s claimed 0.40 lead is attached to two incompatible scope explanations.

**Fix:** Choose and state one primary scenario: either keep the pre-registered 4/4 as an offsetting judgment with Iroh in V1 and delete the conflicting midpoint/3-vs-4 explanation, or explicitly label it a scope-neutral provisional comparison and supply separate in-V1 and deferred totals. If the explicit 3/4 in-V1 row is adopted, update totals, margins and sensitivity examples consistently. Do not describe the currently correct arithmetic as an arithmetic error.

### F06 — major: §2.4 X3 row, line 151; §7.1 release/runtime basis, line 438; §9 Rust rejection, lines 551–553

**Claim:** Go has "PIE and full RELRO on stable", contrasted with Rust "static-musl PIE not reachable on stable" / "no static-musl PIE on stable".

**Evidence:** X3 RESULTS.md:171–175 and 194–199 says both default Linux artifacts are non-PIE static executables. The tested Go PIE/full-RELRO variant is DYN with the glibc interpreter /lib/ld-linux-aarch64.so.1; hardening/checksec-linux-artifacts-round2.txt:14–24 directly confirms dynamic linkage and INTERP. X3 explicitly says musl-only compatibility would be lost by inference and was not tested. The Rust conclusion is only that none of the tried stable flags achieved PIE for the tested zig/musl artifacts, not a proof that static-musl PIE is categorically unavailable on stable.

**Fix:** Carry the linkage tradeoff into the score basis: "Go achieved dynamic PIE/full RELRO on stable, requiring a glibc interpreter; the static defaults of both were non-PIE. Rust static-musl PIE was not achieved with the tested toolchain/flags." Avoid presenting unlike static/dynamic variants as equivalent distribution paths or turning a negative experiment into a language-wide impossibility.

### F07 — minor: §2.1 final prototype commits, lines 78–81; §2.3 Linux environment, lines 134–136; §7.1 cross-platform basis, line 436

**Claim:** "Final prototype commits" remain 38b6b72/d8f0cbe; "linux-x64 ran only under emulation"; the four-platform native execution summary does not attach its different results to baseline versus post-X1b artifacts.

**Evidence:** X1 RESULTS.md:5 and 36–57 records native linux-x64 139/139 for the pre-X1b frozen artifacts. X1b uses Go 84c7665 and Rust 001a791. tests/evidence/g02-rust-x1b-windows.json:732 explicitly says rebuilt linux-x64 did not receive a fresh native run; its supplementary harness at lines 431 onward covers darwin-arm64/linux-arm64. The Go X1b supplementary_non_windows_harness likewise lists only darwin-arm64 and linux-arm64. The earlier text can be retained as historical round-3 context, but it currently reads as a current platform/source inventory.

**Fix:** Label §2.1/§2.3 as round-3 baseline context, mark the native-x64 correction locally, and list the post-X1b candidate commits. State explicitly that native linux-x64 execution is for round-3 bytes while post-fix Unix checks cover darwin/linux-arm64; do not imply the new x64 artifacts were executed.

### F08 — minor: §3 compatible-licensing row, line 174

**Claim:** Go: "18 modules, all MIT or BSD-3 (X3: go-licenses check rc 0)".

**Evidence:** X3 RESULTS.md:93 reports 17 third-party modules (15 MIT, 2 BSD-3-Clause), and the checks pass only with the unlicensed prototype ignored. X3:78 explains that 18 in buildinfo counts 17 third-party modules plus main. license/go-licenses-check-rc.txt:1–3 confirms the checks explicitly ignore self. The ADR itself says the root license is UNLICENSED at line 177.

**Fix:** Write "17 third-party modules, all MIT/BSD-3; check rc 0 with the unlicensed main module excluded". Do not describe the 18th, unlicensed main module as MIT/BSD-3.

### F09 — minor: §7.3 rubric sensitivity, line 485

**Claim:** "X2 rubric readings (§10, D3 k)".

**Evidence:** ADR:626–631 assigns D3(k) to the Windows batch-script-path ruling and D3(l) to the X2 rubric. X2 RESULTS.md:234–238 is the applicable rubric sensitivity evidence.

**Fix:** Change the cross-reference to §10 D3(l), and retain the existing X2 citation.

### F10 — minor: §3.1 G03 remainder, lines 197–200; §10 Q-C, lines 599–603

**Claim:** "most rows are verified; the rest are blocked"; owner prompt discusses only "remaining blocked rows" and a second Windows account.

**Evidence:** docs/research/g03-windows-wsl.md:25 and 27 records WSL Mode A elevation and Mode B endpoint-permissions as in_progress / inconclusive, not blocked. The latter needs a second Linux account with non-interactive sudo; the former needs operator observation. Lines 21–28 distinguish fully verified, partially executed blocked, and in_progress records. tests/evidence/README.md:16–24 distinguishes incomplete/inconclusive execution from inability to run.

**Fix:** Say remaining rows are "blocked or in_progress/inconclusive", and include the second Linux account in Q-C’s remaining inputs. Preserve the actual record status/verdict rather than collapsing every unresolved row to blocked.

## Checked and correct

- Read the revision-3 working-tree ADR and git diff HEAD; checked every requested revised section and inspected spec/plan G02/G03/G06, performance targets, evidence conventions, §9.6/§9.7 and the scope decisions. Production language remains pending; prototype evidence is not presented as product-requirement verification in the header.
- Recomputed all six-row weighted totals from retained score JSON: orchestrator Go 3.50 / Rust 3.90; Codex 3.75 / 3.80; Fable 3.70 / 3.90; Opus 3.50 / 4.00. All entries in §7.2 match the scorers and all four recommendations lean Rust; margins 0.05–0.50 are correct.
- Every stated numeric §7.3 example is arithmetically correct for its stated score changes: row-point increments 0.25/0.25/0.20/0.15/0.10 (ecosystem would be 0.05); Iroh deferral 3.70/3.65; deferral plus cross-platform 4/4 gives 3.95/3.65; cross-platform+maintenance ties give 3.90/3.90; adding Go TUI 4 gives 4.00/3.90. The scenario-basis contradiction is F05, not misaddition.
- Recounted all ten retained X1b Windows results.json files directly: each has 89 candidate rows, 71/71 gating passes and 4/4 shared host controls; all 94 verdict/gating pairs are identical across the three fix runs and two reviewer runs for each language. New JSON records pass the repository evidence schema using the existing minischema validator; status verified / observed verdict pass is correct for their explicitly scoped criterion. Every cited evidence_path in those two records exists.
- X1 §9.6 baseline is 67/71 Go and 68/71 Rust. Native linux-x64 is 139/139 both; first frame 40.2/20.2 ms and filter p95 17.7/2.7 ms match X1. The named-pipe hang, five-byte overwrite, batch refusal, executable search and console/TUI observations are carried forward accurately apart from the omissions/scope issues reported above.
- X4 Windows pipe subset is 5/5 per language; foreign-SID refusal is a deliberately mismatched expected SID with the same user, not another account. DPAPI/CNG/TPM were built but not run. Mac fixture-keychain/ephemeral-SE and Linux fixture backend parity, Go plaintext versus Rust DH Secret Service, and SDK versus purego cross-build evidence match the cited reports. No native lock/secure-store claim was closed by cross-compilation.
- Recomputed X2 from all 24 cells in results.json: every intended hidden suite passes; all-target builds and unit exits pass; T3 intentionally replaces three K9 checks and has 136/139 in the full harness. Go/Rust geometric means are 1.0178295534 output tokens and 0.9847316492 tool calls, correctly rounded 1.02/0.98. Totals are 770583/668620 output tokens and 682/635 calls. Original per-cell majors are 1/1.
- Cross-read X2 T1 independent execution and T3 tmux/xterm.js reproduction: all six T1 changes have the Running-state divergence; Go default-disposition Darwin Ctrl-C kills the job at 130, Linux lacks ordinary recovery, Rust Ctrl-Z then fg completes it. The recovery comes from baseline architecture. T3 reproduces in two Go cells; the third avoids it by full repaint. The ADR correctly counts two causes, retains rubric/small-sample caveats, and no longer reports Fisher significance.
- T2 memory ranges and attribution match cross-review: Rust sonnet1 205 MiB and opus1 190 MiB, other four 117–124 MiB, within 256 MiB; these are changed profile-lint implementations rather than baseline runtime measurements. T2/T4 have no calibrated major.
- Round-3 startup, first-frame, filter, CPU, RSS and artifact values in §4 match g02-measurements.json.round3; TS retained measurements match its round-2 data. The first-frame floor subtraction gives approximately 4.6 versus 22.7 ms; idle CPU is about 0.03 versus 0.35 percent. No product/soak/cold-reboot verification follows from those slice measurements.
- X3 dependency counts, scanner/SBOM behavior, same-host/cross-host reproducibility, release-tool results and CRT/unsafe caveats match the report and selected retained raw tables. X6 compiler/SSH-agent/ecosystem and 1-of-20 russh advisory snapshot claims match its retained data/report; desk research and small/confounded benchmark comparisons remain inference rather than a controlled Heimdall experiment.
- Recounted X5 build-matrix TSV: 12 Iroh crypto/target rows, each exit 0. Size-growth ratios and darwin 5.2+3.6 versus 4.5 MB comparisons match retained tables. Native darwin/linux-arm64, emulated linux-x64 and Windows build-only distinctions are correct; ring/zig closure is limited to building and §8 marks the real-helper lower-bound claim as inference.
- The scorer brief requires blind scoring, and copied score contents agree with the source records. Read-only stat of the original scratch files confirms the ADR’s 04:58:15 preregistration mtime precedes the first scorer (Opus) 05:04:05; Codex and Fable files are later. This verifies retained filesystem ordering, not an immutable transcript audit of blindness.

## Commands, validation, and limits

Commands were read-only repository inspection (`git status --short`, `git diff HEAD -- <ADR>`, `git diff --stat`, `rg`, `nl`, `sed`, `cat`, `stat`) and Python stdlib reads/recounts/weighted arithmetic. Existing `tests/g02/minischema.py` was loaded without running its self-test, solely to validate the two evidence records; bytecode writes were disabled for that validation. No prototype, harness or platform experiment was executed and no build, install, commit or push ran. Only this review.json and review.md were created in the authorized scratch directory; repository files were not edited.

Original scorer scratch-file metadata was read only to verify the timestamp-order claim; conclusions otherwise use current repository evidence. Memory guidance was used only to avoid treating historical status as live verification, with no historical claim substituted for current records.

Skipped: fresh builds/probes and live refresh of X6 external sources, as required by the read-only review. Risk: this is an artifact-fidelity review; retained evidence cannot independently establish unexecuted platform behavior, a complete source-transcript audit, or future production performance.
