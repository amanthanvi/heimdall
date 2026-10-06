# ADR-0002: Implementation language, TUI stack, and distribution (G02)

**Status:** proposed. The owner decides the language. No production stack is
locked until that decision is recorded in §10.
**Date:** 2026-10-06 · **Gate:** G02 · **Task:** M00-T05
**Affects:** every production requirement, through the stack choice. This ADR
cites prototype-level evidence for R-SS-04, R-UX-05, R-DI-01, R-AP-02 and
R-SE-05. That evidence does not verify those requirements.

## 1. Context

plan.md §3 G02 asks for the same small slice to be built in each of three
candidates: Go + Bubble Tea, Rust + Ratatui, and TypeScript + OpenTUI. Hard
gates are applied before any preference scoring. The deliverables are:
- one recommended stack;
- one rejection rationale per candidate;
- the embedding-versus-helper position for Iroh.

A Go preference stated earlier is historical only and does not count as
approval.

The slice is defined in `docs/g02/slice-contract.md` §1–§8. The rulings behind
every verdict are in §9–§9.5 (K1–K18, Q16, Q17). They were issued in rounds,
whenever a prototype or a review exposed a gap. Go and Rust received every
ruling before their last fix round. TypeScript was frozen after round 1 (§3.3).

## 2. Process and evidence

### 2.1 Rounds

| Round | What happened | Go | Rust | TS |
|---|---|---|---|---|
| 1 | Build to one contract; first adversarial review | built | built | built |
| Alignment | K1–K12 conformance fixes | fixed | fixed | fixed, then frozen (§3.3) |
| 2 | Review-driven fixes under K13–K16, K6a–c | fixed | fixed | frozen |
| 3 | Harness gains K6d/K6e/K17; baseline on round-2 builds | 135/136 darwin, 134/136 linux (K6d; K6e on Linux) | 136/136 both | 127/136 darwin, 128/136 linux |
| 3b | Fix round under the complete rulings (K6b, K6d, K6e) | fixed → 136/136 both | fixed → 136/136 both | research only |
| 3c | Harness gains K6e child self-stop and K12 closed stdout (§9.4) | 138/139 both (K12 error results) → fixed → **139/139 both** | 137/139 both (K6e self-stop, K12) → fixed → **139/139 both** | **129/139 darwin, 130/139 linux** |

Go and Rust each had four fix rounds. In each round both got the same
rulings, and each round's changes were reviewed independently afterwards.

An independent reviewer, who did not build the prototype, rebuilt each round
3b and 3c Go and Rust build from source in `/tmp`. The reviewer reproduced the
manifest digests, re-ran the full harness on darwin-arm64 and linux-arm64, and
probed beyond the harness. No reviewer could refute a harness verdict. §6
lists what the reviewers found outside the harness.

**Final prototype commits:**
- Go: `38b6b72`
- Rust: `d8f0cbe`
- TypeScript: `0bd7df9` (frozen)

Each evidence record carries `build_commit` = the repository HEAD at run time
plus `+dirty`, because the prototype changes were committed after their
verdict runs. The binding link from a verdict to its source is the artifact
sha256: `dist/manifest.json` = record `artifact_digest`. The reviewers
reproduced those digests from source.

### 2.2 The shared harness and how far to trust it

One Python harness (`tests/g02/`, now version 2.4.2 with 139 checks) judges
all three candidates. Its self-test runs a reference implementation with
injected defects. On 2.4.1 it caught 136/136 observable mutations on each
platform (`tests/g02/SELFTEST.md`, `selftest-results/2026-10-05-r7/`). Version
2.4.2 only makes the Q17 error-result cases gating. Its self-test was scoped:
a full-catalogue baseline plus 6/6 targeted mutations on each platform
(`selftest-results/2026-10-05-r8/`).

The self-test mutations were written by the harness authors. So that the
harness was not checking only what its authors expected, three independent
reviewers each tried to get realistic defects past it:

| Harness review | Realistic defects caught | Follow-up |
|---|---|---|
| v2.0.0 (round 2) | 1 / 21 | 13 harness defects fixed in 2.1.0 |
| v2.2 additions (round 3) | 14 / 17 | 3 misses fixed in 2.3.0 |
| v2.4.0 additions (round 3c) | 15 / 22 | misses fixed in 2.4.1, or ruled (Q17 gated; Q18 recorded as a race the harness cannot detect reliably) |

The harness got much stronger at each review, but every review still found
gaps. A 139/139 pass is therefore strong evidence on the paths the harness
exercises, not proof of correctness. The reviews in §6 show that edge cases
outside those paths remain.

Known blind spots include:
- Windows and WSL (not executed);
- stops sent by third parties, and SIGSTOP (recorded, not gated);
- zsh (recorded, not gated);
- an inherited SIGPIPE ignore;
- a reader that closes mid-output;
- timing races in stop mirroring (Q18).

Evidence records follow the canary rule. Historical full canary values that
harness v1 leaked into its own assertion text were redacted
(`tests/evidence/artifacts/CANARY-REDACTION.md`).

### 2.3 Environment

- **Host:** Apple M5 Max (Mac17,6), 64 GiB, macOS 27.0 (26A428). The host was
  shared with other work, and the load average was recorded for each run.
- **Linux:** Docker Desktop 29.8.1, linuxkit 7.0.14 arm64 VM, in a
  digest-pinned runner image. linux-x64 ran only under emulation, which proves
  nothing for x64.
- **Toolchains:** Go 1.27.1; Rust 1.99.0 (pinned by build.sh); Bun 1.4.2.
- **Libraries:** Bubble Tea v2.0.10; Ratatui 0.30.2 with crossterm 0.29.0;
  OpenTUI 0.5.14.

## 3. Hard gates (plan §3 G02)

Verdicts use **pass / fail / uncertain** only. "Uncertain" means the evidence
needed is not available on this host. Where a verdict differs from the
round-3b/3c reviewer's verdict, the cell says so.

| Gate | Go + Bubble Tea | Rust + Ratatui | TS + OpenTUI (frozen) |
|---|---|---|---|
| Child/IPC correctness | **pass**: 139/139 on darwin-arm64 and linux-arm64; review3c could not refute it. Non-gated deviations are in §6 | **pass**: 139/139 on darwin-arm64 and linux-arm64; review3c could not refute it. Non-gated deviations are in §6. Review3 rated this gate "uncertain" over the self-stop issue, which round 3c fixed | **fail**: K8, K14 ×2, K6a ×3, K6e and K12 (usage error on a closed stdout). K6d errors on a harness precondition. A darwin resize timing race in the harness is not counted |
| Viable Windows/WSL path | **uncertain**: compile and code review only (§3.1) | **uncertain**: compile and code review only (§3.1) | **uncertain**: Bun named-pipe support taken from Bun's source only |
| No unsupported security assumption | **pass on Unix; Windows uncertain**. No helper processes, no stray writes under a hostile environment, bounded parser. Terminfo is no longer read (round 3b) | **pass on Unix; Windows uncertain**. No helper execs and no stray writes (strace, sandbox-exec). Windows: std searches the app directory and System32 before PATH (code review) | **fail**. In compiled Bun binaries, BUN_OPTIONS `--preload`, BUN_BE_BUN and BUN_INSPECT cannot be disabled. This is confirmed from the Bun 1.4.2 source and by experiment (`artifacts/g02-ts/research/`). OTUI_* keystroke logging must also be scrubbed |
| Practical distribution | **uncertain** (Windows not executed). macOS and Linux arm64 pass without a toolchain: one static file, 5.2 MB (2.0 MB gzip). Ad-hoc hardened-runtime signing, no notarization | **uncertain** (Windows not executed). macOS and Linux arm64 pass without a toolchain: one static file, 0.72–0.88 MB (0.37–0.45 MB gzip). Ad-hoc signing, no notarization | **uncertain**. 73–97 MB per target (28–42 MB gzip) plus a native sidecar. musl targets exist for both Bun and OpenTUI, but the prototype never built them |
| Maintained dependencies | **uncertain** (as the reviewer rated it). ultraviolet is an untagged pseudo-version. xo/terminfo (2022) is still linked but no longer reached. cancelreader is from 2022 | **uncertain** (as the reviewer rated it). crossterm 0.29.0 dates from 2025-04 while master is active; winapi 0.3.9 dates from 2020 | **uncertain**. OpenTUI is pre-1.0, with 335 versions since 2025 |
| Compatible licensing | **pass**. 18 modules, all MIT or BSD-3. Notices are not shipped yet | **pass**. Permissive, and a full notices file ships. Which LGPL-marked mingw-w64 parts are linked into the Windows build was not determined | **uncertain**. The artifact embeds LGPL-2 JavaScriptCore and LGPL-2.1 tinycc, which carry relink and notice obligations |
| Domain shared across CLI/TUI | pass | pass | pass |

Every candidate's project license is still a placeholder (`UNLICENSED`).

### 3.1 Windows (code review only, same four items for each candidate)

| Item | Go | Rust |
|---|---|---|
| Named-pipe client open flags | go-winio defaults to `SECURITY_SQOS_PRESENT \| SECURITY_ANONYMOUS`, so the server cannot impersonate the client | opened with `SECURITY_IDENTIFICATION` |
| Server identity check | none | none |
| Job object for the child | none | none |
| Console Ctrl-C forwarding | swallowed, not forwarded | not forwarded |
| Other | os/exec command-line quoting is unsafe for `.bat`/`.cmd` (disclosed) | std exe search order (above); `agent list --socket` writes into a path that is not a pipe |

Native Windows and WSL execution is blocked: there is no Windows 11 or WSL2
host. **The recommendation in §9 is conditional on G03.**

### 3.2 Gate result

Go and Rust pass every gate that can be judged on this host. Both are
uncertain on the same Windows-dependent gates, and both have the
dependency-maintenance caveats above. TypeScript fails child/IPC correctness
and the security-assumption gate.

### 3.3 How the TypeScript verdict was reached

Four things the owner should know:

1. **The K8 failure is gating by orchestrator ruling.** Bun decodes argv to
   U+FFFD before user code runs (7 of 8 invalid-UTF-8 elements are changed).
   K8 counts reaching raw argv through FFI as routing around the stack, so it
   was recorded as a production option and not built. spec.md §10.4 requires
   argv preservation only "to the extent defined by the platform"; byte-exact
   argv comes from plan §3 G02 together with K8. **You can overrule K8's FFI
   clause.**
2. **The environment hooks are now verified, not inferred.** The TS research
   read the Bun 1.4.2 source (`744846f8`) and ran compiled binaries with
   every compile flag that could plausibly help. No flag or embedded option
   disables BUN_OPTIONS preloads, BUN_BE_BUN or BUN_INSPECT. A Node
   single-executable path was researched from documentation only; whether
   OpenTUI's native core works inside a Node SEA is unverified.
3. **The earlier "glibc only" claim was wrong.** Bun and OpenTUI both publish
   musl builds; the frozen prototype simply never built one.
4. **The freeze was an orchestrator decision.** plan §3's "do not keep
   polishing losing prototypes" was applied mid-comparison, after a
   deterministic K8 failure (`slice-contract.md` §9.1). As a result, TS never
   got a fix round for K6a, K6e, K12 or K14. Go and Rust fixed equivalent
   items. Those TS failures are unfixed, which does not make them unfixable.

The TS rejection stands even without K8, because of the security-assumption
gate (item 2).

## 4. Measurements

All measurements are from darwin-arm64. Go and Rust were measured in round 3
on the final builds; TS in round 2 on its frozen build. The method is in
`tools/benchmarks/g02/`, and the data is in `tests/evidence/g02-measurements.json`.

| Metric | Go | Rust | TS (round 2) | Control floor |
|---|---|---|---|---|
| `version --json` startup p50 / p95 (ms) | 3.63 / 4.13 | 2.78 / 3.19 | 17.4 / 19.1 | 2.10 / 2.50 |
| `profile show` large-100 p50 / p95 (ms) | 4.10 / 4.44 | 3.39 / 3.76 | 19.2 / 20.7 | 2.13 / 2.45 |
| TUI first frame large-100 p50 / p95 (ms) | 28.4 / 33.8 | 10.4 / 13.0 | 54.3 / 60.0 | 5.7 / 6.6 |
| Keystroke-to-update p50 / p95 (ms) | 3.90 / 15.9 | 0.58 / 2.65 | — / 7.4 | pty path |
| Filter typing p95, K17 method (ms) | 16.2 | 2.67 | not re-run | — |
| Peak RSS, version / profile large-100 | 7.5 / 8.3 MB | 2.3 / 3.5 MB | 24.8 / 28.4 MiB | 1.3 MB |
| Idle CPU, 300 s × 3 (% of one core) | 0.35 | 0.03 | 0.06 | — |
| darwin-arm64 artifact, raw (gzip -9) | 5.21 MB (1.99) | 0.72 MB (0.37) | 72.7 MB incl. sidecar (28.0) | — |
| linux-x64 artifact, raw (gzip -9) | 5.45 MB (2.17) | 0.88 MB (0.45) | up to 97 MB | — |

**What these numbers show:**
- Every candidate is far inside the spec §15.1 budgets: first frame p95
  ≤ 750 ms, keys p95 ≤ 100 ms, idle memory ≤ 150 MiB.
- Rust is consistently leaner: about 7× smaller, a TUI about 5–7× faster after
  subtracting the floor, and an order of magnitude less idle CPU.
- None of these differences is visible to a user at these sizes. Go's
  0.35 % idle CPU meets the 0.5 % target only for this profile-viewer slice.

**Limits:**
- Numbers include the measurement floor: about 2.1 ms for startup rows and
  about 6 ms for the pty rows.
- The host was shared (load average about 1.5–5).
- The pty floor moved between rounds, which explains Rust's first-frame
  change from round 2 to 3.
- RSS is macOS max RSS.
- Cold start after a reboot was not measured.

## 5. Stack limitations (K6c and similar)

These limitations are non-gating, but they are inputs for production. They
are listed the same way for every candidate.

| Limitation | Go | Rust | TS |
|---|---|---|---|
| Inherited ignored dispositions reset in the child | SIGQUIT, SIGTERM, SIGWINCH and SIGPIPE. Remedy: cgo constructor or re-exec | SIGPIPE. Remedy: the nightly-only `unix_sigpipe`, or a manual pre-exec reset | SIGHUP and SIGINT as well (the K6a failure) |
| Signal origin (`siginfo`) | not exposed by `os/signal`. Shared mode delivers terminal signals twice (K6b, documented) | used on Linux. Darwin cannot tell a tty signal from `kill()`, so terminal signals reach the child twice there (K6b, documented) | not available |
| Panics | a panic in a Bubble Tea goroutine without `recover` still exits 2, not 1. Inferred from the bubbletea source, not demonstrated. Remedy: a supervisor or a patched library | `catch_unwind` covers it | n/a |
| Terminal capability detection | terminfo is avoided entirely. Truecolor advertised only through terminfo is not detected | crossterm is used only for output on Unix. Input decoding and size handling are hand-written; crossterm is still used for both on Windows | OpenTUI native core |

## 6. Recorded deviations found by the final reviews (not gated)

The round-3/3c reviews found these items outside the harness. Each is
recorded for M01 (`slice-contract.md` §9.4, §9.5).

**Found in both Go and Rust:**
- An explicit SIGTSTP or SIGSTOP sent to the launcher's PID stops only the
  launcher, while the child keeps running.
- Q16: a launcher may report a child's self-stop to the shell and then
  resume the child early. This is recorded, not gated.

**Go:**
- **Major, darwin, present before round 3c.** If the run child is stopped by
  SIGSTOP (sent by itself or by another process), `heimdall-proto` exits 255
  and leaves the child stopped in an orphaned process group. The meta file
  then records `exit_code -1`.
  - The reviewer traced it to Go's BSD `WaitStatus.Stopped()`, which does not
    treat a SIGSTOP stop as a stop on darwin.
  - The remedy is a few lines of code: decode the raw wait status instead of
    using that helper.
  - REPORT.md describes this behaviour incorrectly.
- Duplicate environment keys are dropped, because the Go runtime
  de-duplicates them.
- On Linux, a SIGSTOP self-stop is reported to the shell as if it were
  SIGTSTP (`$?` is 148 instead of 147).

**Rust:**
- **Major, introduced by the round-3c stop mirror.** If another process stops
  the child and then continues only the child's PID, the launcher stays
  stopped forever. The child is never reaped. This is a trade-off inherent to
  mirroring stops, and the contract does not cover it.
- After a mirrored stop, a SIGCONT sent only to the launcher leaves the child
  stopped while the shell shows the job as running.
- If the child is itself an interactive job-control shell, `fg` leaves that
  inner shell stopped. This comes from the design and was already true
  before round 3c.
- `agent list` still uses `std::thread::spawn`. If no thread can be created,
  it fails with INTERNAL (exit 1); no child process is involved.

**Both majors** involve stops sent by a third party, and both violate the
spirit of §4 ("waits for the child", no orphan). §9.5 records them with equal
weight and closes the prototype rounds. M01 must design exec-equivalent job
control for these cases in whichever language is chosen. Go's remedy is local
and small; Rust's needs a design choice about how stops are mirrored.

## 7. Comparison criteria (plan §3 G02 weights)

The scores are orchestrator judgments on a 1–5 scale, not measurements. Go
and Rust both pass the judgeable gates, so these scores decide between them.
TS is shown for completeness only.

| Criterion (weight) | Go | Rust | TS | Basis |
|---|---|---|---|---|
| Cross-platform integration (25 %) | 5 | 4 | 2 | Go cross-compiles every target with only its own toolchain. Rust needs cargo-zigbuild for musl and windows-gnu. Windows is unverified for all three |
| Security-sensitive core correctness and maintainability (25 %) | 3 | 4 | 2 | Both pass and both have one major from a third-party stop (§6). Go's remaining limits sit in the runtime or standard library: no `siginfo`, disposition resets that need cgo, goroutine panics that exit 2. Rust's sit in its own code, plus one std SIGPIPE limit. Rust uses `deny(unsafe_code)` crate-wide, with one allowed query-only `sigaction` |
| Release and runtime simplicity (20 %) | 4 | 5 | 1 | Both ship one static file; Rust's is about 7× smaller. TS is a 73–97 MB runtime plus a sidecar |
| Maintainer development ergonomics (15 %) | **?** | **?** | **?** | **Owner input needed (D2).** Observed size: Go 2.4k non-test lines; Rust 2.6k non-test lines, including a hand-written key decoder and job-control code; TS 1.4k. Agent experience: Rust changes needed more build and type-checking iterations |
| TUI quality (10 %) | 4 | 3 | 3 | Bubble Tea provides the most out of the box. Ratatui renders well, but Unix input needed hand-written decoding. OpenTUI's selected row probably rendered white-on-white (inferred from SGR codes) |
| Integration ecosystem (5 %) | 3 | 5 | 3 | Iroh is native Rust (§8) |

**Sensitivity to D2:**
- With ergonomics scored neutrally (3 for each candidate), the totals are
  Rust 4.00 and Go 3.80.
- Each point of ergonomics advantage moves Go 0.15 relative to Rust. Go
  therefore overtakes Rust if you score Go's ergonomics at least 2 points
  higher, for example Go 5 and Rust 3.
- Because these scores are judgments, a different reasonable scorer could
  reverse a 0.2 margin. D2 is the deciding input.

## 8. Iroh: embedding versus helper (deferred to G06)

G02 does not make the final embedding-versus-helper decision. plan §3 G06 owns
it ("Iroh integration versus managed helper"), and it will be decided from
lifecycle and packaging evidence. G02 establishes this much:

| Candidate | Path available | Evidence (none compiled or networked) |
|---|---|---|
| Rust | Embed the `iroh` crate (1.3.0, MIT OR Apache-2.0) in an async runtime thread, or run it as a supervised helper built from the same codebase | Scratch dependency resolve: 363 crates, including tokio, rustls and ring 0.17.14 (C and assembly). **Cross-compiling ring under zig is untested**, so the single-toolchain claim is a G06 risk |
| Go | A supervised Rust helper only. No official Go binding exists; the community binding is "highly experimental", needs cgo and is musl-only | Registry inspection. This means a second toolchain and a second artifact |
| TS | npm `@number0/iroh` 1.1.0 (napi). There is no darwin-x64 build. Under `bun --compile` it extracts a 13 MB `.node` file to TMPDIR, which conflicts with K11 | Loaded and survived compile in a scratch probe |

plan §3 G02 notes that published bindings do not substitute for packaging
tests. Under spec §3, Iroh is the only deferral that scope allows.

## 9. Recommendation and rejections

**Recommended, narrowly and conditionally: Rust + Ratatui**, with crossterm
used only for output on Unix, static musl builds on Linux, and one executable
per target. The recommendation depends on your D2 answer (§7) and on G03
(Windows).

The reasons:
1. **Control of the hardest correctness area without a second language.**
   Process groups, dispositions, `siginfo` and wait-status handling are the
   slice's hardest area, and spec §10.4 transparency depends on them. Rust
   reaches all of them from safe std plus `libc`. Go needed workarounds in
   three places where the runtime or standard library decides: disposition
   resets (cgo to fix), goroutine panic exit codes, and the darwin
   wait-status decoding. Each of those is fixable, but each is a recurring
   cost.
2. **The smallest and simplest artifacts**, which run without a toolchain on
   macOS and Linux.
3. **Iroh is native**, so G06 can embed or use a helper with one toolchain
   and one codebase, with the ring/zig risk in §8 still to test.

**Why Rust could be rejected:**
- More code and slower builds for each feature.
- Hand-written terminal input decoding on Unix.
- crossterm's release cadence.
- Its round-3c stop mirror introduced a liveness bug that needs real design
  work.
- It needs cargo-zigbuild for musl and windows-gnu builds.
- If ergonomics matters to you, these costs are paid on every change for the
  life of the project.

**Go + Bubble Tea, the closest alternative, not recommended.** It passes
every judgeable gate after the same four fix rounds. Its prototype is about
as large as Rust's, and its TUI library is the most capable. It is not
recommended because of the runtime and standard-library limits in §5 and §6,
and because Iroh would need a separate Rust helper. **Choose Go if** you
score its ergonomics advantage at about 2 points or more (D2), or if a
single-language Go codebase plus a Rust Iroh helper is acceptable to you.

**TypeScript + OpenTUI, rejected.** It fails the security-assumption gate:
runtime environment hooks that load code or open an inspector cannot be
disabled in compiled Bun binaries (verified). It also fails K8 under the
orchestrator's FFI ruling, which you can overrule. Its artifacts are
73–97 MB and embed LGPL components. **Reopen if** Bun gains raw-argv access
and a way to disable its environment hooks in compiled binaries, or if a
verified Node single-executable path keeps OpenTUI's native core without
those hooks.

## 10. Owner decisions (required before M01)

- **D1. Language and stack:** Rust + Ratatui (recommended), Go + Bubble Tea,
  or another choice.
- **D2. Ergonomics weighting:** score each candidate's ergonomics for you
  (1–5). §7 shows how the result changes.
- **D3. G02 rulings you may overrule** (each is recorded in
  `slice-contract.md`):
  - K8's FFI clause (§9);
  - the TS freeze (§9.1);
  - Q16, early resume after a self-stop is not gated (§9.4);
  - Q17, closed-stdout parity covers error results (§9.4);
  - §9.5, no further fix round for the two third-party-stop majors.
- **Recorded decision:** _pending_.

## 11. Consequences once decided

- The plan §7.1 layout is adopted in the chosen language. The losing
  prototypes are archived in git history and not maintained.
- The G02 slice contract is not a public contract. M01 designs the
  production CLI and IPC contracts (G08).
- Inputs carried into M01:
  - Exec-equivalent job control, covering stops sent by third parties,
    explicit SIGTSTP/SIGSTOP to the launcher, early resume (Q16) and
    mirroring races (Q18).
  - Signal transparency beyond the five forwarded signals, including SIGKILL
    and orphaning.
  - Restoring the TUI after unhandled signals.
  - `--meta-file` failure semantics.
  - Passing duplicate keys in the environment block through unchanged.
  - Bidi and zero-width display spoofing.
  - Reads of environment-selected files.
  - Windows exe search order, named-pipe server identity, job objects and
    console Ctrl-C.
  - The project license.
  - darwin Developer-ID signing and notarization.
  - Windows-native execution (G03, blocked on hardware).

## 12. Reopen conditions

Reopen this ADR if any of the following happens:
- A native Windows run shows that the chosen stack cannot meet G03.
- Iroh integration (G06) fails on the chosen stack where another stack would
  pass, including ring under cross-compilation.
- The chosen stack's dependencies become unmaintained.
- A license changes.
- The owner overrules a D3 ruling in a way that changes a gate verdict.
