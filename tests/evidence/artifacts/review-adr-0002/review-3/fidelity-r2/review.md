# ADR-0002 revision 3: round 2 evidence-fidelity recheck

**Task:** M00-T05-adr0002-review3-fidelity-recheck. **Verdict: ready after fixes.** All **10/10** original fidelity findings are resolved. New findings: **0 blocker, 1 major, 3 minor**.

Reviewed the uncommitted working-tree revision against HEAD `ca3ef37f71391934a1a76bc0545f84cd504a097b`, including every changed ADR passage and the §9.7 contract diff. This is a read-only evidence review; it does not select the owner's language or execute prototype behavior.

## Original findings

| Finding | Status | Resolution and evidence |
|---|---|---|
| F01 (major): unresolved hard gates described as passed or already deferrable until release | resolved | ADR §§3.2, 7 and 9 now state five scoped passes and two uncertain hard gates, make the scores/recommendation provisional, and explicitly leave the sequencing exception to Q-D. This matches plan.md:117-125. No owner decision is presumed. |
| F02 (major): Windows windows-sys FFI described as safe wrappers | resolved | ADR §2.4, §7.1 and §9 now distinguish safe higher-level macOS/Linux wrappers from typed but unsafe Windows FFI, record the 20 unsafe sites, and preserve Go typed x/sys DPAPI. X4 windows RESULTS.md:37-40,66,76-89 supports these distinctions; DPAPI/CNG/TPM execution remains unclaimed. |
| F03 (major): demonstrated batch-path injection understated beside unqualified correct escaping | resolved | ADR §2.4, security gate, §3.1 and §7.1 now explicitly identify command injection and wrong-file execution through argv[0]; §9 limits correct escaping to arguments and refers to §9.7. The M01 path refusal remains mandatory. This matches m00-wf8/x1b-review-rust.json:70,97 and g02-rust-x1b-windows.json:727. The separate new threat-model error is N01 below; the original impact/escaping omission is corrected. |
| F04 (major): most Go cells overstated the calibrated X2 count | resolved | ADR §7.1 now states 5/12 Go cells, T1 3/3 and T3 2/3, versus 0/12 Rust; §9 narrows 5/6 to the implementers of those two tasks and preserves two correlated causes, the small sample, and inherited Rust baseline recovery. X2 RESULTS.md:192-225,251-267,280-297 supports the count. |
| F05 (major): incompatible Iroh-in-V1 and midpoint explanations for the 4/4 release row | resolved | ADR §7.1 explicitly selects Iroh in V1 as the primary scenario and calls 4/4 an offsetting judgment: Go release advantages offset the additional Rust helper/toolchain. The conflicting midpoint and explicit in-V1 3/4 score are removed. This is the first resolution allowed by the original finding and is consistent with orchestrator-prereg.md. Recomputed 3.50/3.90 and deferred 3.70/3.65 are correct. N02 is a separate remaining qualitative helper-scenario inconsistency. |
| F06 (major): unlike static/dynamic PIE variants compared without their linkage tradeoff | resolved | ADR §2.4 and §7.1 now say both defaults are static non-PIE, Go obtained PIE/full RELRO as a dynamic build requiring a glibc interpreter, and Rust static-musl PIE was not achieved with the stable flags tried. §9 also limits the negative conclusion to tried flags. This matches X3 RESULTS.md:169-199. |
| F07 (minor): stale prototype commits and native linux-x64 coverage scope | resolved | ADR §2.1 labels 38b6b72/d8f0cbe as round-3 candidates and separately names post-X1b 84c7665/001a791; §2.3 labels the emulation statement as round-3 history; §7.1 explicitly separates native x64 baseline execution from post-fix Windows and arm64 checks. Both X1b records confirm no fresh linux-x64 execution. |
| F08 (minor): 18 Go modules incorrectly described as entirely MIT/BSD | resolved | ADR licensing row now says 17 third-party modules, all MIT/BSD-3, and explicitly excludes the unlicensed main module from the successful check. X3 RESULTS.md:78,93 and its license-check result support this. |
| F09 (minor): X2 rubric sensitivity cited D3(k) instead of D3(l) | resolved | ADR §7.3:508 now cites D3(l), which is the X2 rubric at §10:690-696; D3(k) remains the Windows batch-path ruling. |
| F10 (minor): unresolved G03 rows all called blocked and second Linux account omitted | resolved | ADR §3.1 and Q-C now distinguish blocked rows from in-progress/inconclusive rows and include a second Linux account with sudo. docs/research/g03-windows-wsl.md:19-28 confirms Mode A elevation and Mode B endpoint permissions are in_progress/inconclusive; Windows and Linux second-account requirements remain distinct. |

## New findings

### N01: major

**Location:** docs/g02/slice-contract.md:464-470 (§9.7); docs/decisions/0002-language-tui-distribution.md:679-688 (D3(k))

**Claim:** The new threat-model rationale says exploiting the script path needs control of both a directory name and an environment variable.

**Evidence:** The retained wrong-file probe uses the already-existing OS variable, not an attacker-supplied OS value: Probe-X1bRust.ps1:338-357 constructs os%OS%y and os + $env:OS + y, and the launch overrides only ARGVDUMP_OUT. batch2.scriptpath_existing_var_runs_other_file ran the other batch file, as recorded in m00-wf8/x1b-review-rust.json:70 and g02-rust-x1b-windows.json:727. The bespoke-variable command-injection probe does control HMRDIRVAR, but that is one demonstrated attack configuration, not a necessary condition for every path exploit.

**Fix:** Narrow the claim to the demonstrated HMRDIRVAR command-injection probe. Explicitly state that wrong-file execution also occurred with an existing variable whose value the attacker need not control, provided the expanded destination can be populated. Present the lower likelihood of attacker-influenced configured paths as the orchestrator threat-model judgment, rather than a universal technical prerequisite. Preserve the recorded non-gating ruling and M01 refusal obligation; this finding does not change the 71/71 verdict.

### N02: minor

**Location:** docs/decisions/0002-language-tui-distribution.md:503-505 (§7.3 helper sensitivity)

**Claim:** If Iroh is a supervised helper even in Rust, the release row would still lean Rust, by less.

**Evidence:** The corrected primary release row at §7.1:455 is explicitly 4/4 with Iroh in V1, an offsetting judgment; it does not currently lean Rust. X5 supports two artifacts but one language/toolchain for the Rust-helper option, not a scored Rust-leading release row. No alternative helper-specific numeric row is supplied.

**Fix:** Say the one-language/toolchain advantage remains but the artifact-count advantage disappears, and identify the overall comparison as a judgment. If asserting a release-row lean, give its explicit scenario scores and recompute totals; do not describe the primary 4/4 row as already Rust-leading.

### N03: minor

**Location:** docs/decisions/0002-language-tui-distribution.md:431-439 (§6.2), 603-610 (§9 Go alternative), and 408-410 (Linux recovery wording)

**Claim:** The text says at least one Go implementer avoided each pitfall and says all were fixable or avoidable as one implementer in each X2 task showed; the T1 summary also says on Linux nothing recovers it.

**Evidence:** All three Go T1 cells still have a calibrated P1 major (X2 RESULTS.md:192-210). go-opus1 only partly avoided the recovery trap by handling SIGCONT while running (X2 RESULTS.md:219-225,288-294). The independent re-run confirms kill -CONT %1 finishes go-opus1 on Linux as well as macOS (t1-calibration/verify/README.md:125-133), although the keyboard/fg ladder fails on Linux (103-117). Full avoidance was demonstrated by go-opus2 in T3, not by any T1 cell. ADR §6.2:415 correctly says partly, but these summaries drop that qualification.

**Fix:** Use avoided or partly avoided, and distinguish T1 partial SIGCONT handling plus proposed standard-library fixes from T3 demonstrated full repaint. Limit the Linux nothing-recovers statement to the tested fg/terminal-key ladder. Keep the existing 3/3 T1 major count and rubric unchanged.

### N04: minor

**Location:** docs/decisions/0002-language-tui-distribution.md:584-587 (§9 reproducibility rejection)

**Claim:** Go's bytes change only with its toolchain version.

**Evidence:** The retained X1b/X2 rebuild mismatches are explained by Go 1.27.1 versus 1.27.2, but X3 RESULTS.md:121-124 also conditions darwin cross-host equality on the same ad-hoc signing and filename, and uses a specific recipe and tested hosts. The evidence does not establish that toolchain version is the only possible input affecting Go artifact bytes.

**Fix:** State that the observed Go round-4 rebuild drift was explained by the toolchain patch upgrade, while Rust's observed drift was not diagnosed. Avoid the categorical only claim.

## Recomputed §7 totals and sensitivities

Used exact decimal weights `0.25, 0.25, 0.20, 0.15, 0.10, 0.05`, in the row order of §7.1. Score vectors and independent score-file totals agree. No numeric correction is required.

| Scoring | Go vector | Rust vector | Go total | Rust total | Rust minus Go |
|---|---|---|---:|---:|---:|
| Orchestrator | 3,4,4,3,3,4 | 4,4,4,4,3,4 | 3.50 | 3.90 | 0.40 |
| Codex | 4,4,4,3,3,4 | 4,4,3,4,4,4 | 3.75 | 3.80 | 0.05 |
| Fable | 4,4,4,3,3,3 | 4,4,4,4,3,4 | 3.70 | 3.90 | 0.20 |
| Opus | 3,4,4,3,3,4 | 4,4,4,4,4,4 | 3.50 | 4.00 | 0.50 |

The published margin range 0.05–0.50 is correct. The preliminary orchestrator table in `orchestrator-prereg.md` also recomputes to 3.75/3.90; the final one to 3.50/3.90.

| §7 scenario | Explicit score changes from §7.1 | Go | Rust | Result |
|---|---|---:|---:|---|
| Iroh deferred | Release 5/3; ecosystem 4/3 | 3.70 | 3.65 | Go +0.05, described as a practical tie |
| Deferred plus cross-platform even | Above plus cross-platform 4/4 | 3.95 | 3.65 | Go +0.30 |
| Either alternative T1 rubric, row scored even | Maintainability 4/4 | 3.65 | 3.90 | Rust +0.25 |
| TUI-library choice unbound, original T1 rubric retained | Maintainability remains 3/4 | 3.50 | 3.90 | Original totals unchanged |
| TUI-library choice unbound plus alternative T1 rubric | Maintainability 4/4 | 3.65 | 3.90 | Rust +0.25 |
| Cross-platform and maintainability even, Iroh in V1 | Cross-platform 4/4; maintainability 4/4 | 3.90 | 3.90 | Exact tie |
| Previous scenario plus Go TUI 4 | Above plus TUI 4/3 | 4.00 | 3.90 | Go +0.10 |

A point changes the weighted total by 0.25 for cross-platform/security, 0.20 for release, 0.15 for maintainability, 0.10 for TUI, and 0.05 for ecosystem. The stated largest single scenario lever is Iroh deferral (margin swing 0.45). From the deferred case, maintainability 4/4 yields 3.85/3.65 and Go TUI 4 yields 3.80/3.65, supporting the final sensitivity bullet. Batch refusal has no explicit numeric re-score; moving the cross-platform row to 4/4 alone yields 3.75/3.90 and does not flip the result. The Rust-helper scenario has no explicit new scores: see N02.

The rubric count alternatives match X2 §5.1: T1 3/0 as applied, 0/0 if background third-party stops are implausible, and 3/3 if wrong state is major regardless of recovery. The updated statements about post-hoc calibration, baseline signal costs, shared scorer framing, and independent reproduction limited to P1/T3 match the cited records. Their interpretation remains a judgment.

## Commands, validation, changed files, and limits

- Commands run: `pwd`; targeted `rg` searches; `cat` and `nl -ba ... | sed -n ...` for the rules, ADR, original reviews, contract and evidence; `git status --short`, `git diff HEAD -- ...`, `git diff --stat HEAD -- ...`, `git rev-parse HEAD`; read-only Python JSON/decimal calculations and row checks; Python writes and validates these two reports in the assigned output directory.
- Validation: recomputed every §7 total/numeric sensitivity example; compared the three retained scorer JSONs; rechecked the new path-rationale claim against the original probe source; inspected evidence status conventions and G03 rows; recounted all ten retained X1b Windows runs (five per language), each with 94 named rows and 75/75 gating passes including 71 candidate checks plus 4 controls, with every named verdict/gating pair identical across the five runs per language.
- One exploratory Python row-inspection command initially treated the evidence record's string-valued verdict map as row objects and raised AttributeError. A corrected inspection used that map as strings and then counted the raw `results.json` row objects; the final checks succeeded.
- Files written: only `review.json` and `review.md` in `<home>/.local/share/heimdall-m00/r4-scratch/review3-fidelity-r2/`. Repository files were not edited, built or committed.
- Limits: no builds, tests of live/native behavior, network research, or release-gate closure; scorer-model launch provenance was not independently recovered from a launch transcript. Review uses retained experiments and their stated platform limits. The new major is a false prerequisite in the gate rationale, not a refuted Windows gating result.
