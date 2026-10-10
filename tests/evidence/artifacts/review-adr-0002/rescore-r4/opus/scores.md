# G02 round 4 re-score: Go vs Rust

**Scorer:** M00-T05-r4-rescore-opus (Opus 5.5, independent, read-only, blind to other rescore-* directories)

**Summary.** Hard gates: Go and Rust both pass child/IPC (under §9.5), the Windows/WSL path, security assumptions (for the slice), licensing and the shared domain, after one native Windows fix round each. Distribution and dependency maintenance stay uncertain, the same for both, and do not separate them. §7 re-score: Go 3.50, Rust 4.00. Rust leads on cross-platform security integration (typed secure-store bindings, safe batch launching) by 1, on agentic maintainability by 1 (X2 T1 calibrated majors) and on TUI quality by 1 (X2 T3, Bubble Tea renderer and code-point defects); security core, release simplicity and ecosystem tie. Recommendation: Rust, low confidence. No single contested reading flips the result, but Go leads under combinations, most easily Iroh deferred plus an executed-evidence-only cross-platform reading. Main evidence concerns: the X2 rubric counts only new defects (Rust keeps more pre-existing divergence), there are only two root causes behind the 5-to-0 headline, the T3 finding is a library bug, Rust reproducibility drifted over time, Go's batch refusal is a product gap, and no clean-machine distribution test was run.

## 1. Hard gates (plan §3 G02)

| Gate | Go | Rust |
|---|---|---|
| Correctness of child/IPC behaviour | **pass** | **pass** |
| Viable Windows/WSL path | **pass** | **pass** |
| No unsupported security assumption | **pass** | **pass** |
| Practical distribution | **uncertain** | **uncertain** |
| Maintained dependencies | **uncertain** | **uncertain** |
| Compatible licensing | **pass** | **pass** |
| Ability to share domain operations across CLI/TUI | **pass** | **pass** |

### Correctness of child/IPC behaviour

- **Go (pass):** Holds under the slice-contract §9.5 classification (D3 keeps it). Harness 2.4.2 gives 139/139 on darwin-arm64 and linux-arm64 (ADR-0002 §2.1) and 139/139 on native linux-x64 under WSL2 (x1/RESULTS.md §1). The post-§9.6 Windows script gives 71/71 gating rows in 3 runs (x1b/go/windows-run/ROWS.md, commit 84c7665), and the independent reviewer re-ran it at 94/94 identical (x1b/review-go/commands.txt). The third-party-stop deviations in ADR §6 are still in the frozen build. In X2 T1, every Go cell fixed every baseline-failing S1–S5 check (x2/RESULTS.md §4.1), so they are fixable.
- **Rust (pass):** Same basis: 139/139 on darwin-arm64, linux-arm64 and native linux-x64 (x1/RESULTS.md §1); Windows 71/71 in 3 runs after the 001a791 fix, and the reviewer's runs were identical (x1b/review-rust/commands.txt). The ADR §6 stop-mirror hang is still in the frozen build; the X2 T1 cells fixed every S1–S5 check.
- **Changed since ADR:** The verdict platforms grew from darwin/linux arm64 to native linux-x64 and native Windows 11 x64. Each language failed §9.6 gating rows on first contact: Go 67/71 (cmd.exe argument injection through .bat/.cmd); Rust 68/71 (named-pipe --file hang; request frame written into a regular file given as --socket). Each fixed them in one round. Nothing blocks this gate under §9.5. If D3(a) were overruled, both would fail it again until a fix round.

### Viable Windows/WSL path

- **Go (pass):** Executed natively on Windows 11 Pro 26300 x64 (non-elevated) and WSL2 Ubuntu 24.04 x64: named-pipe agent list including a Unicode pipe name, argv quoting by UTF-16 code unit, exit codes, console Ctrl-C, TUI on a pseudoconsole, Unicode/spaced paths (x1/RESULTS.md §2; x1b/go). The X4 named-pipe server with a client-SID check passed 5/5 (x1/x4-windows-run/RESULTS.md). The G03 Mode A and Mode B probes that ran are language-neutral and pass (docs/research/g03-windows-wsl.md §0). Batch files are refused, not run: §9.6 allows this, but it is a product gap (see evidence concerns).
- **Rust (pass):** Same native runs and the same X4 pipe 5/5. Rust std escapes .bat/.cmd arguments (the CVE-2024-24576 fix), giving 16/16 exact in both path forms (x1/RESULTS.md §9.6 baseline). Recorded, not gated: std searches the application directory and System32 before PATH and does no PATHEXT lookup; cmd.exe expands %VAR% in the batch script path itself (x1b/review-rust/commands.txt, 3 probe FAILs).
- **Changed since ADR:** Moved from uncertain (compile and code review only) to pass for both. Still open, and the same for both languages: second-account DACL, SMB remote client, the real Win32-OpenSSH agent, classic conhost and Windows Terminal, CTRL_CLOSE/LOGOFF, MOTW/SmartScreen/Defender, Windows ARM64, and the G03 rows blocked on a second account or a disposable distribution. None of these is language-specific on current evidence.

### No unsupported security assumption

- **Go (pass):** Unix as in the ADR. Windows was observed for the slice's paths: no batch injection after the refusal; a regular file or directory given as --socket is not modified; no canary hit (harness.canary_scan); exe resolution refuses the current directory (ErrDot). Recorded, not gated: the pipe client connects at the Anonymous impersonation level (go-winio default), which only affects impersonation-based servers (x1-review correction). Residual risk: the hand-bound, untyped NCrypt/LazyProc.Call bindings for CNG were never executed (x4/windows/RESULTS.md; DPAPI/CNG/TPM blocked in x1/x4-windows-run).
- **Rust (pass):** Windows was observed for the slice's paths: batch arguments are escaped exactly; after the fix, GetFileType checks refuse non-disk --file and non-pipe --socket before any write; the pipe client opens at Identification level. Recorded, not gated: std's System32/app-dir-first search order and %VAR% expansion in a batch script path (M01 must define a resolution policy, §9.6). The refusals still open the path first (pipe_connects 1), which is recorded. CNG/DPAPI were also never executed, but those bindings are typed (windows-sys).
- **Changed since ADR:** Moved from uncertain to pass for the slice on both. The X1 baseline showed that each stack had a real Windows security defect on first contact: Go a command injection that comes from os/exec semantics, Rust a user-data overwrite in its own code. Both were fixed. The secure-store assumptions (DPAPI, CNG, TPM, the macOS data-protection keychain, persistent Secure Enclave keys) are unverified for both and belong to G04, not to this gate's slice.

### Practical distribution

- **Go (uncertain):** One static file per target. It ran natively on Windows 11 with PATH reduced to System32 and on WSL2 under env -i with an empty PATH (x1/RESULTS.md). None of these were clean machines: the Windows host has py.exe and toolchains installed, and the files came through WSL without Mark-of-the-Web. Signing and notarization are not done (owner-held). GoReleaser builds the full matrix locally on the first try, and builds are reproducible across hosts (x3/RESULTS.md §6, §8).
- **Rust (uncertain):** Same execution evidence. One static file per target, 0.72–0.89 MB. Release tooling is rougher: cargo-dist failed windows-gnu without cargo-xwin and leaked builder home paths in its default build; builds are not reproducible across hosts (x3 §6, §8); a later rebuild of unchanged source no longer reproduced the round-3c Linux bytes (Rust REPORT §16, commit 001a791). A darwin build that links frameworks needs the macOS SDK (x4/macos §2).
- **Changed since ADR:** Windows now runs natively for both. What keeps the verdict uncertain is the same for both and does not depend on the language: clean-machine runs, SmartScreen/MOTW/Defender, Developer ID signing and notarization. It does not discriminate between Go and Rust, so it does not block D1. It does block a release claim.

### Maintained dependencies

- **Go (uncertain):** A judgment. Watch items: ultraviolet, an untagged pseudo-version, now shown to carry a wide-character cursor bug (x2/cross-review/T3/README.md N1); go-winio's last release is v0.6.2 from 2024-04 (x6 §4.3); cancelreader dates from 2022; there is no maintained Go macOS keychain/SecKey library (x4/macos §2); go-keyring uses a plaintext Secret Service session (x4/linux). Core crypto, SSH and agent code is first-party x/crypto.
- **Rust (uncertain):** A judgment. Watch items: crossterm has had no release in 18 months (x6 §4.2); security-framework is marked looking-for-maintainer (x4/macos); ssh-agent-lib has a small bus factor (x6 §4.3); RustSec lists 1 of 20 GHSA advisories for russh (x6 §0); the graph has 77–82 crates, about 330 with iroh embedded (x3 §1, x5 §4).
- **Changed since ADR:** There is more data and the ambiguity is the same: each side has one unmaintained-leaning UI dependency (ultraviolet, crossterm) and one weak platform library. This should be an owner-accepted risk register, not a blocker.

### Compatible licensing

- **Go (pass):** 17 modules, MIT and BSD-3 only; go-licenses check rc=0 (x3 §4). Notices do not ship yet.
- **Rust (pass):** cargo-deny licenses rc=0 and cargo-about rc=0 with 12 permissive expressions (x3 §4). Whether the linked mingw-w64 CRT parts carry notice duties is still not determined, and iroh adds aws-lc/ring license terms (x5).
- **Changed since ADR:** Unchanged. The project license is still a placeholder.

### Ability to share domain operations across CLI/TUI

- **Go (pass):** ADR §3; unchanged. The X2 T2/T3 cells added CLI and TUI features on the shared domain without harness regressions.
- **Rust (pass):** Same.
- **Changed since ADR:** No change.

## 2. §7 criteria

| Criterion | Weight | Go | Rust | Go weighted | Rust weighted | Confidence |
|---|---:|---:|---:|---:|---:|---|
| Cross-platform integration | 25 % | 3 | 4 | 0.75 | 1.00 | low |
| Security-sensitive core correctness and maintainability | 25 % | 4 | 4 | 1.00 | 1.00 | medium |
| Release and runtime simplicity | 20 % | 4 | 4 | 0.80 | 0.80 | low |
| Agentic and open-source maintainability (replaces maintainer ergonomics, D2) | 15 % | 3 | 4 | 0.45 | 0.60 | low |
| TUI quality | 10 % | 3 | 4 | 0.30 | 0.40 | low |
| Integration ecosystem | 5 % | 4 | 4 | 0.20 | 0.20 | medium |
| **Total** | 100 % | | | **3.50** | **4.00** | |

### Cross-platform integration (25 %): Go 3, Rust 4

- **Basis:** Both run natively on all five targets and needed one Windows fix round each. Rust leads on the platform integrations Heimdall's core depends on (G04 secure stores, Windows process launch): typed windows-sys bindings for DPAPI, NCrypt, pipes and tokens against Go's hand-bound untyped LazyProc.Call for 10 NCrypt functions plus ImpersonateNamedPipeClient; a safe high-level macOS Security.framework wrapper (134 LOC, 2 small unsafe blocks) against Go's cgo (97 lines of C) or purego (228 LOC of untyped dlsym bindings); a DH-encrypted Secret Service session against go-keyring's plaintext session; std escaping of batch arguments against Go's refusal (Go cannot launch .bat/.cmd at all). Go leads on: Windows file-type semantics (correct on first contact; Rust std is_file needed FFI); a pipe server with overlapped I/O and deadlines (go-winio); ErrDot and PATHEXT resolution (Rust std searches System32 first and has no PATHEXT); Windows TUI CTRL_C_EVENT handling (terminal restored); single terminal-signal delivery on macOS (ADR §5); cross-compiling to every target with no extra tools. Iroh is native in Rust; a Go product needs a Rust helper (x5).
- **Evidence:** `tests/evidence/artifacts/g02-r4/x1/RESULTS.md`; `tests/evidence/artifacts/g02-r4/x1/x4-windows-run/RESULTS.md`; `git show 84c7665`; `git show 001a791`; `tests/evidence/artifacts/g02-r4/x4/windows/RESULTS.md`; `tests/evidence/artifacts/g02-r4/x4/macos/RESULTS.md`; `tests/evidence/artifacts/g02-r4/x4/linux/RESULTS.md`; `tests/evidence/artifacts/g02-r4/x5/RESULTS.md`; `docs/decisions/0002-language-tui-distribution.md §5`
- **Observed vs inferred:** Observed: the native Windows rows, the batch behaviour, the pipe server/client checks, the macOS keychain and Secure Enclave runs for all three implementations, the Linux Secret Service runs, the plaintext session (from go-keyring source), and the build requirements. Inferred: that untyped FFI is a material defect risk for agent maintenance (the DPAPI/CNG runtime was never executed for either language), and that batch-file support matters in the product (npm-style .cmd shims for agent CLIs).
- **Confidence:** low
- **Strongest counter:** On the evidence actually executed on Windows, Go had fewer own-code defects on first contact for file and socket semantics, and its toolchain cross-compiles every target with no zig, SDK or extra tooling. The secure-store differences are mostly unexecuted (X4 DPAPI/CNG/TPM blocked), and purego showed a working cgo-free macOS path. A reader who weights executed Windows behaviour over binding quality would score this 4/4.

### Security-sensitive core correctness and maintainability (25 %): Go 4, Rust 4

- **Basis:** Both pass every gated slice behaviour on four platforms. For Rust: memory and race safety outside unsafe; exhaustive matching; secrets as zeroizable byte buffers (Go strings cannot be zeroed, x4/linux); std's CVE-fixed batch escaping, where Go's os/exec allowed cmd.exe injection; typed FFI. Against Rust: its own-code Windows data-loss bug on first contact; std SIGPIPE control that is nightly-only; 77–82 third-party crates (49–55 containing unsafe) against Go's 17 modules (x3 §1–2); a linked C runtime (musl/mingw); stack protector and BTI only on nightly; RustSec's poor coverage of russh advisories; community SSH-agent crates. For Go: a small first-party supply chain (stdlib sha256, base64, json, signal); govulncheck with reachability and binary scanning; first-party x/crypto/ssh/agent (which itself had 2026 constraint-enforcement CVEs). Against Go: the darwin WaitStatus SIGSTOP mis-decoding in std; runtime disposition resets on four signals; no siginfo; dynamic race detection only. These offset. The X2 T1 split is counted under agentic maintainability, not here, to avoid double counting.
- **Evidence:** `tests/evidence/artifacts/g02-r4/x3/RESULTS.md`; `tests/evidence/artifacts/g02-r4/x1/RESULTS.md`; `tests/evidence/artifacts/g02-r4/x6/RESULTS.md §2, §4.3, §5`; `tests/evidence/artifacts/g02-r4/x4/linux/RESULTS.md`; `tests/evidence/artifacts/g02-parity-r3c/RESULTS.md`; `docs/decisions/0002-language-tui-distribution.md §5-§6`
- **Observed vs inferred:** Observed: dependency, unsafe and scanner results, fuzzing (60 s, no crashes either side), hardening flags, the Windows defects, and the parity probes. Inferred: how much the compiler guarantees will matter over a long-lived, agent-maintained core, and how much a smaller dependency graph reduces real risk.
- **Confidence:** medium
- **Strongest counter:** A reader who weights supply-chain size and first-party SSH/crypto heavily (Heimdall is an SSH-agent product) gives Go 5 / Rust 4. A reader who weights compile-time guarantees for an agent-maintained security core, and std's safe Windows process launch, gives Rust 5 / Go 4. Both readings are defensible, and they cancel.

### Release and runtime simplicity (20 %): Go 4, Rust 4

- **Basis:** This score is conditional on Iroh. Without Iroh, Go is clearly simpler: CGO_ENABLED=0 plus -trimpath gives bit-identical artifacts across hosts; buildinfo gives native binary SBOMs and govulncheck -mode binary; GoReleaser worked on the first try; cold builds take about 2 s against about 21 s. Rust needs zig, cargo-zigbuild, 5 remap flags and cargo-auditable; it was not reproducible across hosts and drifted over time; cargo-dist failed windows-gnu and leaked home paths. Without Iroh: Go 5, Rust 3. With Iroh (a spec §3 V1 target, deferrable only by a recorded scope decision), Go ships two artifacts from two toolchains: the Rust helper brings back zig, cargo-zigbuild, ring C/asm and about 240 crates, plus two lockfiles, SBOMs and signing passes and a versioned frame protocol. Rust ships one file, 6–8x larger. With Iroh: Go 3, Rust 4. The 4/4 is the probability-weighted midpoint, with Iroh shipping in V1 at about 0.6 likelihood (inference from spec §3, table row and line 147).
- **Evidence:** `tests/evidence/artifacts/g02-r4/x3/RESULTS.md §5, §6, §8`; `tests/evidence/artifacts/g02-r4/x5/RESULTS.md`; `tests/evidence/artifacts/g02-r4/x4/macos/RESULTS.md §2`; `spec.md §3 (lines 141, 147)`; `git show 001a791 (REPORT §16 build drift)`
- **Observed vs inferred:** Observed: reproducibility, SBOMs, release dry runs, the X5 builds of iroh with ring and aws-lc under zig for 4 targets, the helper supervisor run, and sizes. Inferred: the cost of two artifacts (two signing passes, version skew), and the likelihood that Iroh ships in V1.
- **Confidence:** low
- **Strongest counter:** Go's case: Iroh is opt-in and deferrable, the helper's build is isolated and needed only for that feature, and G06 might prefer a supervised helper for process isolation even in Rust, which would remove Rust's single-artifact advantage. Rust's case: Iroh is the V1 target, a pinned container fixes Rust's reproducibility, and two coordinated artifacts are worse than one.

### Agentic and open-source maintainability (replaces maintainer ergonomics, D2) (15 %): Go 3, Rust 4

- **Basis:** X2 (24 cells, same tasks, prompts and models): hidden-test correctness and effort are tied (all-pass; output-token and tool-call geometric means 1.02 and 0.98). Under calibrated review, the T1 job-control changes left 3/3 Go cells with a major (a redirected background job stopped by a third party: listed as Running, fg hangs, ^Z and ^C do nothing) and 0/3 Rust cells (^Z then fg recovers). An independent re-run verified this, and a blind re-classification reached the same majors. The cause traces to the Go baseline's separate-process-group model, which os/signal's missing siginfo pushed it towards: a stack-shaped pitfall that every agent and the cell reviewers missed. The T3 renderer major is counted in the TUI row instead. X6: an uncontrolled benchmark lean to Rust; compiler-caught agent errors; Go has better first-party tooling; the contributor pools are similar. Overall it is a modest Rust lead.
- **Evidence:** `tests/evidence/artifacts/g02-r4/x2/RESULTS.md`; `tests/evidence/artifacts/g02-r4/x2/results.json`; `tests/evidence/artifacts/g02-r4/x2/t1-calibration/README.md`; `tests/evidence/artifacts/g02-r4/x2/t1-calibration/verify/README.md`; `tests/evidence/artifacts/g02-r4/x2/cross-review/T2/README.md`; `tests/evidence/artifacts/g02-r4/x2/cross-review/T4/README.md`; `tests/evidence/artifacts/g02-r4/x6/RESULTS.md`
- **Observed vs inferred:** Observed: hidden-test results, harness results, token and tool-call usage, the probe matrices (2,388 T1 runs), and the T2/T4 cross-reviews (no majors on either side). Inferred: that the T1 recovery difference generalizes to future agent work, rather than reflecting the frozen baselines' architecture, which M01 will redesign anyway.
- **Confidence:** low
- **Strongest counter:** The T1 split rests on the rubric's reading of 'normal recovery' and on third-party stops of background jobs being plausible. X2 itself says that if those are implausible, the languages tie. The rubric only counts defects that are new relative to each baseline: the Rust T1 cells still diverge from plain exec in more scenarios (P3, P8, P9e) than the Go cells, so on end-state behaviour the gap narrows. Three runs per cell, and a ceiling effect on the hidden tests.

### TUI quality (10 %): Go 3, Rust 4

- **Basis:** Bubble Tea v2 with its ultraviolet renderer (a pinned pseudo-version) has a wide-character cursor bug. It corrupts list rows and the status line on CJK filter edits, including the shipped homelab.toml at 20x5. This was verified in pyte, tmux 3.8 and xterm.js, and a case of it already exists in the baseline (P-A). Every Go build also drops combining and zero-width code points (U+0301 shows 'cafe'), drops all attributes under TERM=dumb or unset, and exits 1 on kill -INT. Bubble Tea v2 forces SGR to be embedded in strings. Every Rust build rendered every T3 case correctly in all three emulators and styles Spans natively. Against Rust: crossterm is stale, and Unix input decoding and size handling are hand-written (prototype REPORT, ADR §5); bidi and zero-width characters are passed to the terminal unfiltered (§9.2, not gated); on Windows a CTRL_C_EVENT leaves the alternate screen active. Both are far inside the spec §15.1 budgets (linux-x64 first frame 40 ms vs 20 ms; K17 p95 17.7 ms vs 2.7 ms).
- **Evidence:** `tests/evidence/artifacts/g02-r4/x2/cross-review/T3/README.md`; `tests/evidence/artifacts/g02-r4/x2/cross-review/T3/verify/README.md`; `tests/evidence/artifacts/g02-r4/x1/RESULTS.md`; `tests/evidence/artifacts/g02-r4/x6/RESULTS.md §4.2, §5`; `docs/decisions/0002-language-tui-distribution.md §4, §7`
- **Observed vs inferred:** Observed: the corruption bytes and screens in three emulators, the code-point drops, the Windows CTRL_C_EVENT rows, and the latencies. Inferred: that the Bubble Tea and ultraviolet defects persist (no upstream check was recorded), and how much of the hand-written Rust input layer will need maintenance.
- **Confidence:** low
- **Strongest counter:** Bubble Tea gives the most out of the box, and the renderer bug was avoidable inside the task (go-opus2's full repaint); an upstream fix may exist or be cheap. Rust's Unix TUI rests on hand-written decoding over a stalled crossterm. The ADR's 4/3 for Go remains a defensible reading.

### Integration ecosystem (5 %): Go 4, Rust 4

- **Basis:** Iroh is native Rust, and the build of all 4 targets under zig is now observed (x5). The only pure-Go port is two months old, carries about 51k lines of forked TLS and QUIC, and is unaffiliated. Go has the first-party x/crypto/ssh/agent client and server (3,597 importers), against Rust's small community crates, and a larger body of Go security tooling (age, cosign, tailscale, teleport). Rust has better platform secure-store crates (windows-sys, security-framework, secret-service with DH). Net: a tie.
- **Evidence:** `tests/evidence/artifacts/g02-r4/x5/RESULTS.md §5`; `tests/evidence/artifacts/g02-r4/x6/RESULTS.md §4`; `tests/evidence/artifacts/g02-r4/x4/*/RESULTS.md`
- **Observed vs inferred:** Observed: registry and GitHub snapshots and the iroh builds. Inferred: how much of the SSH-agent protocol Heimdall will take from a library rather than own. x6 notes that the product must own constraint enforcement in either language.
- **Confidence:** medium
- **Strongest counter:** If Iroh ships and is the product's main differentiator, Rust is 5 (ADR's reading). If the SSH-agent server library dominates, Go is 5.

## 3. Sensitivity

The gap is 0.50 (Go 3.50, Rust 4.00). A single row needs a swing of at least 0.50/weight points to tie: 2 points in a 25 % row, 2.5 in the 20 % row, 3.3 in the 15 % row. The 10 % and 5 % rows cannot tie alone. No single one-point change flips the result. Contested readings, each alone: (a) Iroh deferred or out of V1, release row 5/3: Go 3.70, Rust 3.80, still Rust by 0.10. (b) The X2 T1 rubric reading reversed (third-party stops of background jobs implausible), agentic row 4/4: Go 3.65, Rust 4.00. (c) The X2 T3 finding charged to Bubble Tea as a replaceable library and the ADR's TUI row restored to Go 4 / Rust 3: Go 3.60, Rust 3.90. (d) Cross-platform scored 4/4 on executed Windows evidence only: Go 3.75, Rust 4.00. (e) Security core 5/4 for Go on supply chain: Go 3.75, Rust 4.00. Combinations: (a)+(d) gives Go 3.95, Rust 3.80, so Go leads. (b)+(c)+(d), with Iroh shipping, gives Go 4.00, Rust 3.90, so Go leads. (a)+(b)+(c)+(d) gives Go 4.20, Rust 3.70. So Rust leads under the base reading and under every single contested reading. Go wins when several Go-friendly readings coincide, most easily if Iroh is deferred and the executed-Windows-only reading of cross-platform is taken. The Iroh scope question and the cross-platform row (secure-store binding quality versus executed Windows behaviour) are the two levers that matter most.

## 4. Recommendation: RUST (confidence: low)

**Reasons:**

1. Platform security integration, which Heimdall's G03/G04 core depends on, is materially better served in Rust. Typed, mostly maintained bindings cover the Windows CNG/DPAPI/pipe/token APIs, macOS Security.framework and an encrypted Secret Service session. Rust std launches .bat/.cmd safely, where Go either refuses them or must hand-write a cmd.exe escaper (the BatBadBut bug class). Go needs untyped hand bindings (NCrypt, purego) or cgo for the same coverage.
2. X2 is the only controlled agent experiment. Hidden tests and effort tie, but calibrated review found stack-shaped majors that agents and per-cell reviewers missed: 5 of 12 Go cells against 0 of 12 Rust cells, from two independent causes (the job-control model that os/signal's missing siginfo pushed towards, and the Bubble Tea/ultraviolet renderer). Both were verified independently. This is a modest signal, but it is the kind of hidden cost that an agent-maintained open-source product pays.
3. Iroh, a V1 target, is native Rust and is now observed to build for all four targets under zig with ring or aws-lc. A Rust product stays single-language and single-artifact, while a Go product needs a Rust helper, a second toolchain and a second release pipeline, which takes away most of Go's release-simplicity advantage.

**Strongest case for the other side:** Go has a much smaller, mostly first-party supply chain: 17 modules against 81 crates (about 330 with iroh), no linked C runtime, stdlib crypto, and first-party x/crypto/ssh/agent for an SSH-agent product. It has govulncheck reachability with better coverage of SSH advisories (RustSec lists 1 of 20 russh GHSAs), bit-reproducible builds across hosts with two flags, native binary SBOMs, GoReleaser that works out of the box, and builds about 10x faster. It was cleaner on Windows file and socket semantics on first contact, delivers terminal signals once on macOS, and restores the terminal on Windows CTRL_C_EVENT. If Iroh is deferred, Go's release story is clearly better, and the remaining Rust advantages rest on unexecuted secure-store bindings and rubric-dependent X2 readings.

**Reverse if:**

- The owner defers Iroh out of V1, or G06 chooses a supervised helper process for isolation even in a Rust product, and the cross-platform row is read on executed evidence only (4/4).
- Native X4 runs (DPAPI, CNG/TPM on a disposable Windows account; a provisioned macOS bundle) show Go's bindings working and Rust's crates defective or unmaintained (for example, security-framework stays without a maintainer).
- A follow-up X2 with harder or longer-lived tasks, or one scored on end-state behaviour rather than new-defect-relative-to-baseline, shows no Rust advantage or a Go advantage.
- Rust release builds cannot be made bit-reproducible even in a pinned container, or the larger crate graph produces an unpatched advisory that blocks a release.
- An upstream Bubble Tea/ultraviolet release fixes the wide-character and combining-character defects, and crossterm becomes unmaintained with no viable alternative backend.

## 5. Evidence concerns

1. X2 §5.3 headline '5 of 12 Go vs 0 of 12 Rust' and the Fisher p≈0.02: the five majors come from two causes (T1×3 with one root cause, T3×2 with one root cause), so the effective sample is two findings. RESULTS.md acknowledges this, but the p-value should not be quoted in ADR-0002.
2. X2 T1 rubric asymmetry: 'major' requires the defect to be new relative to the same-language baseline. The Rust baseline diverges from plain exec in more scenarios (P3 hang, P8, P9e), and the Rust cells keep those as 'pre-existing'; the Go cells pass P3 and P9e (t1-calibration/README.md 'Results in brief'). The calibration measures what agents broke, not end-state exec-equivalence, and on end-state behaviour Go is closer than 3-to-0 suggests.
3. X2 T1 rubric timing: the rubric ('normal recovery', 'plausible for an interactive user') was handed to the calibration task after the per-cell reviews had shown inconsistency (x2/RESULTS.md §5; t1-calibration/README.md 'the rubric given to this task'). The blind re-classification reduces, but does not remove, the risk that the thresholds were chosen with the outcome visible.
4. X2 T1 tests prototype architecture, not language: by X2's own account (§5.1), the recovery difference comes from the baselines' process-group design, which round-1 agents chose. M01 has to redesign exec-equivalent job control anyway (ADR §11), so the result's forward relevance is indirect. The claim that os/signal 'pushed' Go towards isolation is an inference.
5. X2 T3 is attributed to 'the Go stack', but it is a Bubble Tea/ultraviolet renderer defect at a pinned untagged pseudo-version. Nothing records whether a newer ultraviolet or Bubble Tea fixes it. Charging it to the agentic row as well as the TUI row would double-count it.
6. X2 calibrated minor and pre-existing ratings are implemented_unverified; the T2–T4 cross-reviews used one reviewer per task and probed darwin-arm64 only; nothing was probed on Windows; most cells had one hidden run per platform (x2/RESULTS.md §4.1, §7).
7. X2 T2 note: two Rust cells peak at 190–205 MiB of the 256 MiB K15 limit on a 1 MiB profile, against ≤124 MiB for the others (cross-review T2). This is recorded as 'not a defect', but it is a memory-headroom signal against Rust that the summaries do not carry forward.
8. X1 'no toolchain' and 'clean machine': the Windows host has py.exe, an owner cmd.exe AutoRun entry and installed toolchains, with only PATH reduced, and the WSL host has go, gcc and node in /usr/bin (acknowledged). The files came through WSL with no Mark-of-the-Web. plan §3 G02 asks for clean machines, so practical distribution is not closed for either language.
9. X1 §9.6 script changes: 'No independent review yet' (x1/RESULTS.md §9.6). The x1b reviewers re-ran the script and probed beyond it, but no record shows a review of the script's own criteria, for example the batch 'exact delivery' rule that accepts either the CommandLineToArgvW or the UCRT decoding.
10. Go's X1b fix (84c7665) passes §9.6 by refusing every .bat/.cmd target, including bare names resolved through PATHEXT. That makes npm-style .cmd shims, a common install form for agent CLIs on Windows (inference), unlaunchable. The gate passes, but the product gap and the security-sensitive escaper Go would need are not in any score input.
11. Rust X1b: the reviewer's probe had 12 FAILs (9 trailing-dot batch names exit 1; 3 cases of %VAR% in the batch script path expanded by cmd.exe), while the commit message says 'independent review: holds (no major)' (x1b/review-rust/commands.txt). %VAR% expansion in argv[0] is an injection-adjacent behaviour that only appears as 'Recorded'. Its severity was not rated under a stated rubric.
12. Rust reproducibility contradiction: X3 §6 reports bit-identical Rust builds on one host (linux-x64 961e3fb9…), but the X1b fix round found that rebuilding the same unchanged source no longer reproduces those bytes (876,464 to 887,072 B), cause not investigated (Rust REPORT §16 in 001a791). Rust reproducibility is time- and toolchain-fragile, not just host-dependent.
13. X5 framing: it presents the Go cost as 'two binaries'. It does not discuss that embedding iroh puts about 240 crates and ring/aws-lc C/asm (including prebuilt nasm objects on Windows) into the same process as the security core, which is an argument for a helper even in Rust. Also, Windows iroh binaries were built but never executed, and linux-x64 ran only under Rosetta.
14. X4 Windows: DPAPI, CNG and TPM were never run in either language, so the 'untyped Go bindings' risk and the 'typed Rust bindings' benefit are both unexecuted. X4 macOS: Rust darwin builds that link frameworks cannot be cross-linked from Linux, a point against the Rust release story that X3 does not mention.
15. X3 counts compare Go modules with Rust crates and compiled-only Go unsafe with uncfg'd Rust grep counts (acknowledged). The 4.5–5x dependency ratio overstates the gap in maintainers and publishers. cargo-geiger exited 1.
16. X6: many figures came through an LLM fetch tool (§8), the benchmarks are uncontrolled, and there is no independent review. Its 'slight Rust lean' should carry little weight.
17. ADR-0002 is partly stale: §3 and §3.1 still say Windows is 'compile and code review only', while §8's Go row already cites X5. The re-score should update §3, §3.1, §5 and §6 consistently and say which statements predate round 4.
18. ADR-0002 §7 TUI row (Go 4, Rust 3) rested on 'most out of the box'. Round 4 adds observed Go rendering defects with wide and combining characters, which the prior score did not have, so that row should be re-derived, not carried over.

## 6. Owner questions (beyond D1)

1. Is the Iroh/Pigeons reference flow in V1 scope, or will it be deferred by a recorded scope decision (spec §3)? This is the largest lever on the release-simplicity row and on the result.
2. Must `run` launch Windows batch targets (.cmd/.bat, including npm shims for agent CLIs resolved by bare name)? If yes, Go needs a hand-written cmd.exe escaper, a security-sensitive component. If no, Go's refusal is acceptable, and Rust's std search order still needs an M01 policy.
3. Will you authorize the X4 secure-store runs (DPAPI, CNG Software KSP, TPM Platform KSP) on a disposable Windows account or host, and a provisioned macOS bundle, before D1, or accept D1 with those unexecuted for both languages?
4. Do you accept the remaining uncertain gates (clean-machine, signed distribution; the dependency-maintenance watch lists) as owner-accepted risks that are the same for both languages, so they do not hold D1?
5. Should G06 prefer a supervised Iroh helper for process isolation regardless of language? If yes, Rust's single-artifact advantage largely disappears.
