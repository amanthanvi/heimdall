# ADR-0002: Implementation language, TUI stack, and distribution (G02)

**Status:** proposed. The owner decides the language. No production stack is
locked until that decision is recorded in §10.
**Date:** 2026-10-06 · **Gate:** G02 · **Task:** M00-T05
**Affects:** every production requirement, through the stack choice. This ADR
cites prototype-level evidence for R-SS-04, R-UX-05, R-DI-01, R-AP-02 and
R-SE-05. That evidence does not verify those requirements.
**Reviews of this ADR:**
- `tests/evidence/artifacts/review-adr-0002/review.md` reviewed the first
  draft.
- `review-2.md` reviewed the second draft. Its findings are addressed in this
  revision.

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
every verdict are in §9–§9.5: K1–K18 and Q16–Q18. They were issued in rounds,
whenever a prototype or a review exposed a gap. Go and Rust received every
ruling before their last fix round. TypeScript received the K1–K12 alignment
fixes and was then frozen (§3.3).

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

Go and Rust each had four fix rounds, and both received the same rulings in
each round.

For every Go and Rust build from rounds 3b and 3c, an independent reviewer
(not the builder) did the following:
- rebuilt it from source in `/tmp` and reproduced the manifest digests;
- re-ran the full harness on darwin-arm64 and linux-arm64;
- probed beyond the harness.

No reviewer could refute a harness verdict. §6 lists what the reviewers found
outside the harness. No reviewer rebuilt TS, so its digest link is
producer-only.

**Final prototype commits:**
- Go: `38b6b72`
- Rust: `d8f0cbe`
- TypeScript: `0bd7df9` (frozen)

**How verdicts trace to source.** Each conformance record carries
`build_commit` as the HEAD at run time plus `+dirty`, because the prototype
changes were committed after their verdict runs. Selftest records describe
the commit in prose. The binding link is the artifact sha256, which appears
in three places:
- the record's `artifact_digest`;
- `dist/manifest.json` (gitignored, so not in git);
- the tracked copies in `tests/evidence/artifacts/g02-{go,rust}/review3c/build/`.

### 2.2 The shared harness and how far to trust it

One Python harness judges all three candidates: `tests/g02/`, version 2.4.2,
with 139 checks. Its self-test runs a reference implementation with injected
defects:
- **2.4.1:** caught 136/136 observable mutations on each platform
  (`tests/g02/SELFTEST.md`, `selftest-results/2026-10-05-r7/`).
- **2.4.2:** only makes the Q17 error-result cases gating. Its self-test was
  scoped: a full-catalogue baseline plus 6/6 targeted mutations on each
  platform (`selftest-results/2026-10-05-r8/`).

The self-test mutations come from the harness's own authors. Three
independent reviewers therefore tried to get realistic defects past it:

| Harness review | Realistic defects caught | Follow-up |
|---|---|---|
| v2.0.0 (round 2) | 1 / 21 | 13 harness defects fixed in 2.1.0 |
| v2.2 additions (round 3) | 14 / 17 | 3 misses fixed in 2.3.0 |
| v2.4.0 additions (round 3c) | 15 / 20 (plus 2 conforming controls correctly accepted) | Misses fixed in 2.4.1, or ruled: Q16 early resume and SIGSTOP self-stop recorded, Q17 gated, Q18 a timing race the harness cannot detect reliably |

The harness got much stronger at each review, but every review still found
gaps. A 139/139 pass is strong evidence on the paths the harness exercises.
It is not proof of correctness, and §6 shows that edge cases remain outside
those paths.

Known blind spots include:
- Windows and WSL (not executed);
- stops sent by third parties, and SIGSTOP (recorded, not gated);
- zsh (recorded, not gated);
- an inherited SIGPIPE ignore;
- a reader that closes mid-output;
- timing races in stop mirroring (Q18).

Records follow the canary rule. Full canary values that harness v1 leaked
into its own assertion text were redacted
(`tests/evidence/artifacts/CANARY-REDACTION.md`).

### 2.3 Environment

- **Host:** Apple M5 Max (Mac17,6), 64 GiB, macOS 27.0 (26A428). The host was
  shared with other work, and the load average was recorded for each run.
- **Linux:** Docker Desktop 29.8.1 with a linuxkit 7.0.14 arm64 VM and a
  digest-pinned runner image. linux-x64 ran only under emulation, which proves
  nothing for x64.
- **Toolchains:** Go 1.27.1; Rust 1.99.0 (pinned by build.sh); Bun 1.4.2.
- **Libraries:** Bubble Tea v2.0.10; Ratatui 0.30.2 with crossterm 0.29.0;
  OpenTUI 0.5.14.

## 3. Hard gates (plan §3 G02)

Verdicts use **pass / fail / uncertain** only. "Uncertain" means the evidence
does not settle the gate: either the platform needed is not available, or the
question is a judgment the evidence leaves open. A bracketed note marks every
place the verdict differs from the latest reviewer's.

| Gate | Go + Bubble Tea | Rust + Ratatui | TS + OpenTUI (frozen) |
|---|---|---|---|
| Child/IPC correctness | **pass, given the §9.5 classification.** 139/139 on darwin-arm64 and linux-arm64, and review3c could not refute it. [Review3c rated §4 "waits for the child, no orphan" **uncertain** because of the darwin SIGSTOP orphan (§6), and escalated it.] | **pass, given the §9.5 classification.** 139/139 on darwin-arm64 and linux-arm64, and review3c could not refute it. [Review3c rated "no regression" **fail** because of the third-party-stop hang (§6), and escalated it.] | **fail.** K8, K14 ×2, K6a ×3, K6e, and K12 for a usage error on a closed stdout. K6d errors on a harness precondition. A darwin resize timing race in the harness is not counted |
| Viable Windows/WSL path | **uncertain.** Compile and code review only (§3.1) | **uncertain.** Compile and code review only (§3.1) | **uncertain.** Bun named-pipe support taken from Bun's source only |
| No unsupported security assumption | **uncertain.** Unix: no helper processes, no stray writes under a hostile environment, bounded parser, terminfo no longer read. Windows not executed. [Review3: pass] | **uncertain.** Unix: no helper execs or stray writes (strace, sandbox-exec). Windows, from code review: std searches the app directory and System32 before PATH. [Review3: uncertain, for that reason] | **fail.** In compiled Bun 1.4.2 binaries, BUN_OPTIONS `--preload`, BUN_BE_BUN and BUN_INSPECT cannot be disabled, as far as source reading and experiments with every plausible flag show (`artifacts/g02-ts/research/`). OTUI_* keystroke logging must also be scrubbed |
| Practical distribution | **uncertain.** Windows not executed. One file per target, 5.2 MB (2.0 MB gzip), static on Linux. Ran without a toolchain under `env -i` on the build host and in Linux containers, not on clean machines. Ad-hoc signing with hardened runtime, no notarization. [Review3: pass for macOS and Linux] | **uncertain.** Windows not executed. One file per target, 0.72–0.88 MB (0.37–0.45 MB gzip), static on Linux. Same `env -i` and container method. Ad-hoc signing with hardened runtime, no notarization | **uncertain.** 73–97 MB per target (28–42 MB gzip) plus a native sidecar. Bun and OpenTUI have musl builds, but Bun's musl runtime is dynamically linked (it needs libstdc++ and libgcc), and the prototype never built for musl |
| Maintained dependencies | **uncertain**, a judgment. ultraviolet is an untagged pseudo-version. xo/terminfo (2022) is still linked but no longer reached. cancelreader dates from 2022 | **uncertain**, a judgment. crossterm 0.29.0 dates from 2025-04 while master is active. winapi 0.3.9 dates from 2020 | **uncertain**, a judgment. OpenTUI is pre-1.0, with 335 versions since 2025. [Round-1 review: pass] |
| Compatible licensing | **pass.** 18 modules, all MIT or BSD-3. Notices are not shipped yet | **pass.** Permissive, and a full notices file ships. Which LGPL-marked mingw-w64 parts the Windows build links was not determined | **uncertain.** The artifact embeds LGPL-2 JavaScriptCore and LGPL-2.1 tinycc, which carry relink and notice obligations |
| Domain shared across CLI/TUI | pass | pass | pass |

Every candidate's project license is still a placeholder (`UNLICENSED`).

### 3.1 Windows (code review only)

| Item | Go | Rust |
|---|---|---|
| Named-pipe client open flags | go-winio defaults to `SECURITY_SQOS_PRESENT \| SECURITY_ANONYMOUS`, so the server cannot impersonate the client | opened with `SECURITY_IDENTIFICATION` |
| Server identity check | none | none |
| Job object for the child | none | none |
| Console Ctrl-C forwarding | swallowed, not forwarded | not forwarded |
| Other | os/exec command-line quoting is unsafe for `.bat`/`.cmd` (disclosed) | std exe search order (see §3); `agent list --socket` writes into a path that is not a pipe |

TS was not reviewed at this depth.

Native Windows and WSL execution is blocked: there is no Windows 11 or WSL2
host. **Any choice made now is conditional on G03.**

### 3.2 Gate result

**Go and Rust:**
- **Pass:** licensing, the shared domain, and child/IPC correctness. The
  child/IPC pass holds only under the §9.5 classification. If you rule that
  §4 covers stops sent by a third party (D3), **both** fail that gate until a
  further fix round.
- **Uncertain, identically for both:** Windows/WSL, security assumptions on
  Windows, distribution on Windows, and the dependency-maintenance judgment.
  You have to accept those caveats, or decide that no choice can be made
  before G03 (D4).

**TypeScript** fails both child/IPC correctness and the security-assumption
gate.

### 3.3 How the TypeScript verdict was reached

1. **The K8 failure is gating by orchestrator ruling.** Bun decodes argv to
   U+FFFD before user code runs: 7 of 8 invalid-UTF-8 elements are changed.
   K8 counts reaching raw argv through FFI as routing around the stack, so
   that route was recorded as a production option and not built. spec.md
   §10.4 requires argv preservation only "to the extent defined by the
   platform"; byte-exact argv comes from plan §3 G02 together with K8. **You
   can overrule K8's FFI clause.**
2. **The environment hooks were confirmed for Bun 1.4.2** (`744846f8`), by
   reading the source and by running compiled binaries with every candidate
   compile flag. No flag or embedded option was found that disables
   BUN_OPTIONS preloads, BUN_BE_BUN or BUN_INSPECT. That "no such flag
   exists" is an inference for this version, not a proof for later ones. A
   Node single-executable path was researched from documentation only.
3. **The earlier "glibc only" claim was wrong.** Musl builds exist for both
   Bun and OpenTUI. They are not equivalent to Go's and Rust's static
   binaries (see §3).
4. **The freeze was an orchestrator decision.** plan §3's "do not keep
   polishing losing prototypes" was applied mid-comparison, after a
   deterministic K8 failure (§9.1). TS therefore never had a fix round for
   K6a, K6e, K12 or K14. Those failures are unfixed, which does not mean they
   are unfixable.

The TS rejection would stand without K8, because of the security-assumption
gate (item 2).

## 4. Measurements

All measurements were taken on darwin-arm64:
- Go and Rust: round 3, final builds, load average about 1.5–5.
- TS: round 2, frozen build, load average about 1.5–7.

The method is in `tools/benchmarks/g02/`; the data is in
`tests/evidence/g02-measurements.json`.

| Metric | Go | Rust | TS (round 2) | Control floor |
|---|---|---|---|---|
| `version --json` startup p50 / p95 (ms) | 3.63 / 4.13 | 2.78 / 3.19 | 17.4 / 19.1 | 2.10 / 2.50 |
| `profile show` large-100 p50 / p95 (ms) | 4.10 / 4.44 | 3.39 / 3.76 | 19.2 / 20.7 | 2.13 / 2.45 |
| TUI first frame large-100 p50 / p95 (ms) | 28.4 / 33.8 | 10.4 / 13.0 | 54.3 / 60.0 | 5.7 / 6.6 |
| Keystroke-to-update, all keys, p50 / p95 (ms) | 3.90 / 15.9 | 0.58 / 2.65 | 3.73 / 7.38 | no control row |
| Filter typing p50 / p95 (ms; measure.py series, the metric K17 gates at 100 ms) | 4.03 / 16.2 | 0.60 / 2.67 | 3.32 / 6.88 | no control row |
| Peak RSS, version / profile large-100 (MB) | 7.5 / 8.3 | 2.3 / 3.5 | 26.0 / 29.8 | 1.3 |
| Idle CPU, 300 s × 3 (% of one core) | 0.35 | 0.03 | 0.06 | — |
| darwin-arm64 artifact, raw (gzip -9), MB | 5.21 (1.99) | 0.72 (0.37) | 72.7 incl. sidecar (28.0) | — |
| linux-x64 artifact, raw (gzip -9), MB | 5.45 (2.17) | 0.88 (0.45) | 92.5 incl. sidecar | — |

**What these numbers show:**
- Every candidate is far inside the spec §15.1 budgets: first frame p95
  ≤ 750 ms, keys p95 ≤ 100 ms, and idle memory ≤ 150 MiB.
- Rust is consistently leaner:
  - about 7× smaller;
  - first frame about 5× faster after subtracting the floor (net p50
    4.6 ms against 22.7 ms);
  - an order of magnitude less idle CPU.
- None of these differences is visible to a user at these sizes. Go's
  0.35 % idle CPU meets the 0.5 % target for this profile-viewer slice only.

**Limits:**
- The floor is about 2.1 ms for startup rows and about 6 ms for pty rows.
- The pty floor moved between rounds.
- RSS is macOS max RSS.
- Cold start after a reboot was not measured.

## 5. Platform signal behaviour and stack limitations

These items are non-gating (K6b, K6c), but they matter for production. The
same rows are given for every candidate.

| Item | Go | Rust | TS |
|---|---|---|---|
| Terminal Ctrl-C, Ctrl-\ and resize in the normal interactive case | **once on both OSes** (exclusive mode). Twice in shared mode, e.g. in a pipeline (K6b, documented) | **once on Linux** (`siginfo` identifies the source). **Twice on macOS in normal use**, because Darwin cannot tell a tty signal from `kill()` (K6b, documented). A child that counts SIGINT behaves differently on macOS | n/a (frozen) |
| Inherited ignored dispositions reset in the child | SIGQUIT, SIGTERM, SIGWINCH and SIGPIPE. The Go runtime decides this. Remedy: a cgo constructor or a re-exec (not applied) | SIGPIPE. Rust std decides this; the inherited value cannot be read. Remedy: the nightly-only `unix_sigpipe`, or bypassing std's entry or `pre_exec` (not applied) | SIGHUP and SIGINT as well (the K6a failure) |
| Signal origin (`siginfo`) | not exposed by `os/signal` | used on Linux; no help on macOS | not available |
| Panics | a panic in a Bubble Tea goroutine without `recover` may exit 2, not 1. *Inferred* from the bubbletea source, not demonstrated | `catch_unwind` covers it | n/a |
| Terminal capability detection | terminfo is avoided entirely, so truecolor advertised only through terminfo is not detected | crossterm is used only for output on Unix. Input decoding and size handling are hand-written. Windows still uses crossterm for both | OpenTUI's native core |

## 6. Deviations found by the final reviews (not gated)

The round-3/3c reviews found the following outside the harness. All are
recorded for M01 (`slice-contract.md` §9.4, §9.5).

Most probes were run against only one prototype. A parity run of the same
probes against both builds is in
`tests/evidence/artifacts/g02-parity-r3c/RESULTS.md`; its results are
summarised in §6.1.

**Found in both:** an explicit SIGTSTP or SIGSTOP sent to the launcher's PID
stops only the launcher, while the child keeps running.

**Go:**
- **Major, darwin only, exclusive (interactive foreground) mode, present
  before round 3c.**
  - What happens: if the run child is stopped by SIGSTOP, whether it sent the
    signal itself or another process did, `heimdall-proto` exits 255 and
    leaves the child stopped in an orphaned process group. The meta file
    records `exit_code -1`.
  - Cause, per the reviewer: Go's BSD `WaitStatus.Stopped()` does not treat a
    SIGSTOP stop as a stop on darwin.
  - Remedy: decode the raw wait status instead of using that helper.
  - REPORT.md describes this behaviour incorrectly.
- Duplicate environment keys are dropped, because the Go runtime
  de-duplicates them.
- On Linux, a SIGSTOP self-stop is reported to the shell as if it were
  SIGTSTP (`$?` is 148 instead of 147).

**Rust:**
- **Major, introduced by the round-3c stop mirror.**
  - What happens: another process stops the child and then continues only
    the child's PID. The launcher has already stopped itself to mirror the
    stop, nothing continues it, and the child is never reaped.
  - Remedy suggested by the reviewer: mirror only in a job-control context.
    That is how Go already behaves. Whether the fix stays as local as Go's is
    *inferred* from the code, not demonstrated.
- After a mirrored stop, a SIGCONT sent only to the launcher leaves the child
  stopped while the shell shows the job as running.
- If the child is itself an interactive job-control shell, `fg` leaves that
  inner shell stopped. This comes from the design and predates round 3c.
- `agent list` still uses `std::thread::spawn`. If a thread cannot be
  created, it returns INTERNAL with exit 1, and no child process is involved.

Both majors involve a SIGSTOP or SIGTSTP stop that the job-control shell did
not send, and both violate the spirit of §4 ("waits for the child", no
orphan). §9.5 classifies them as not gated, records them with equal weight
and closes the prototype rounds. D3 lets you overrule that. Whichever
language is chosen, M01 must design exec-equivalent job control for these
cases.

### 6.1 Parity probes

_Pending: filled in from `tests/evidence/artifacts/g02-parity-r3c/RESULTS.md`._

## 7. Comparison criteria (plan §3 G02 weights)

Scores run from 1 to 5. They are orchestrator judgments, not measurements.
Go and Rust both pass the judgeable gates under §9.5, so these scores decide
between them. TS is shown for completeness only.

| Criterion (weight) | Go | Rust | TS | Basis |
|---|---|---|---|---|
| Cross-platform integration (25 %) | 4 | 4 | 2 | Go cross-compiles every target with only its own toolchain, provided it stays cgo-free and Iroh is not added. A Rust Iroh helper (§8) would bring back a Rust toolchain, zigbuild and ring. Rust needs cargo-zigbuild for musl and windows-gnu. Windows is unverified for all three |
| Security-sensitive core correctness and maintainability (25 %) | 4 | 4 | 2 | Both pass. Each has one localized major from an unexpected stop (§6). Each has runtime-imposed disposition resets, Go's covering more signals. Signal origin favours Rust on Linux; terminal-signal duplication favours Go on macOS (§5). Rust uses `deny(unsafe_code)` crate-wide, allowing only one query-only `sigaction` call; Go needs no unsafe code |
| Release and runtime simplicity (20 %) | 4 | 4 | 1 | Each ships one file per target, with no runtime to install. Rust's file is about 7× smaller, which users do not notice (§4). If Go needs a separate Iroh helper, it ships two artifacts. TS is a 73–97 MB runtime plus a sidecar |
| Maintainer development ergonomics (15 %) | **?** | **?** | **?** | **Owner input needed (D2).** Size: Go 2.4k non-test lines; Rust 2.6k, including a hand-written key decoder; TS 1.4k. Round-1 build effort by one agent each: Go about 25 min, Rust about 1 h 40 min (first green tests at about 25 min), TS about 40 min. Each figure is a single run with different debugging detours, so it is weak evidence |
| TUI quality (10 %) | 4 | 3 | 3 | Bubble Tea provides the most out of the box. Ratatui renders well, but Unix input needed hand-written decoding. OpenTUI's selected row probably rendered white-on-white (*inferred* from SGR codes) |
| Integration ecosystem (5 %) | 3 | 5 | 3 | Iroh is native Rust (§8) |

**Totals with ergonomics scored 3 for both: Go 3.80, Rust 3.80, a tie.** The
previous draft scored Go 3 and Rust 4 on security core and release
simplicity. review-2 showed that those scores rested on an asymmetric
account of signal control, and on a size
difference the ADR itself calls invisible to users. Both are now scored
equal.

**Sensitivity (one change at a time, starting from the tie):**
- Each ergonomics point in Go's favour moves the total 0.15 towards Go.
- Each TUI point moves it 0.10.
- Each security-core or cross-platform point moves it 0.25.
- Each release-simplicity point moves it 0.20.
- Rust's only scored lead is the Iroh ecosystem row (+2 × 0.05), and Go's is
  the TUI row (+1 × 0.10). These cancel exactly.

**What decides it:** the evidence does not separate Go and Rust. The decision
rests on:
- your ergonomics weighting (D2);
- whether a two-language product (Go + a Rust Iroh helper) is acceptable;
- how much weight you give to the platform you use most (§5: Go is cleaner on
  macOS terminal signals, Rust is cleaner on Linux).

## 8. Iroh: embedding versus helper (deferred to G06)

G02 does not make the final embedding-versus-helper decision. plan §3 G06
owns it ("Iroh integration versus managed helper"), and it will be decided
from lifecycle and packaging evidence. G02 establishes this much:

| Candidate | Path available | Evidence (none compiled or networked) |
|---|---|---|
| Rust | Embed the `iroh` crate (1.3.0, MIT OR Apache-2.0) in an async runtime thread, or run it as a supervised helper from the same codebase | A scratch dependency resolve found 363 crates, including tokio, rustls and ring 0.17.14 (C and assembly). **Cross-compiling ring under zig is untested**, which is a G06 risk |
| Go | Only a supervised helper written in Rust. There is no official Go binding; the community binding is "highly experimental", needs cgo and supports musl only | Registry inspection. A Go product would gain a second toolchain and a second artifact, including the same ring and zig risk |
| TS | npm `@number0/iroh` 1.1.0 (napi). There is no darwin-x64 build. Under `bun --compile` it extracts a 13 MB `.node` file to TMPDIR, which conflicts with K11 | Loaded and survived compile in a scratch probe |

plan §3 G02 notes that published bindings do not substitute for packaging
tests. Spec §3 allows Iroh to be deferred, and it is the only item that may
be. If Iroh is deferred or dropped, the Go two-language cost disappears.

## 9. Recommendation and rejections

**Recommendation: Rust + Ratatui, with low confidence.** The design would use
crossterm only for output on Unix, static musl builds on Linux, and one
executable per target. The scored comparison is a tie (§7), so this is a lean
based on structure, not a measured advantage. It is conditional on G03
(Windows) and on your D2 answer.

Why the lean is Rust:
1. **One language for the whole product.** Iroh is native Rust, so G06 can
   embed it or run it as a helper with one toolchain and one codebase. With
   Go, shipping Iroh means also maintaining a Rust helper. The ring/zig risk
   in §8 applies to both choices.
2. **Its known limits are mostly in its own code.** Each stack has one
   runtime-imposed disposition limit (Go: four signals, Rust: SIGPIPE).
   Beyond that, Rust's open issues are in prototype code: the stop-mirror
   hang and the double delivery of terminal signals on macOS. Go's include
   behaviour in its standard library and libraries: the darwin wait-status
   decoding, and possibly goroutine panic exit codes (inferred). This is a
   weak preference, since all of them are fixable.
3. **Leaner artifacts.** They are smaller and use less CPU, which helps
   distribution and review but is invisible to users.

**Why Rust could be rejected:**
- On macOS, every terminal Ctrl-C, Ctrl-\ and resize reaches the child twice
  in normal use. Go's interactive mode delivers each once. Fixing this needs
  a different job-control design on darwin.
- Its stop mirror has an open liveness bug (§6).
- Each change costs more. Unix terminal input decoding is hand-written.
  Builds are slower, and cargo-zigbuild is needed for musl and windows-gnu.
- crossterm's release cadence is a risk.
- The round-1 build effort was the highest of the three (weak evidence, §7).

**Go + Bubble Tea, the close alternative.** It passes every judgeable gate
after the same four fix rounds, ties on the scored comparison, has the most
capable TUI library, and behaves better on macOS terminal signals. It is not
recommended only because of the structural points above: a second language
for Iroh, and more of its limits sitting in the runtime or standard library.
**Choose Go if** you rate its ergonomics higher, if macOS terminal-signal
behaviour matters most to you, or if a Go codebase plus a separately built
Rust Iroh helper (or deferring Iroh) is acceptable.

**TypeScript + OpenTUI, rejected.** It fails the security-assumption gate:
runtime environment hooks that load code or open an inspector could not be
disabled in compiled Bun 1.4.2 binaries. It also fails K8 under the
orchestrator's FFI ruling, which you can overrule. Its artifacts are
73–97 MB and embed LGPL components. **Reopen if** Bun gains raw-argv access
and a way to disable its environment hooks in compiled binaries, or if a
verified Node single-executable path keeps OpenTUI's native core without
those hooks.

## 10. Owner decisions (required before M01)

- **D1. Language and stack:** Rust + Ratatui (lean), Go + Bubble Tea, or
  another choice.
- **D2. Ergonomics weighting:** score each candidate's ergonomics for you,
  1–5, and rescore any other row in §7 you disagree with. Reading a small
  part of each prototype will tell you more than this ADR can, for example
  the run loop: `prototypes/go/internal/run/run_unix.go` and
  `prototypes/rust/src/runner.rs`.
- **D3. G02 rulings you may overrule** (all recorded in `slice-contract.md`):
  - (a) **§9.5 classification:** stops sent by a third party are not gated
    under §4. If you overrule it, both Go and Rust fail child/IPC until a
    further fix round.
  - (b) **§9.5:** no further fix round.
  - (c) **K6b:** documented duplicate delivery of terminal signals is allowed.
    This is what makes Rust's macOS double Ctrl-C and Go's shared-mode
    duplicates non-gating.
  - (d) **K6c:** disposition resets are not gated.
  - (e) **K13:** the verdict platforms are darwin-arm64 and linux-arm64 in a
    Docker VM.
  - (f) **K8:** reaching raw argv through FFI counts as routing around the
    stack.
  - (g) **The TS freeze** (§9.1).
  - (h) **Q16:** an early resume after a self-stop is not gated.
  - (i) **Q17:** closed-stdout parity covers error results.
- **D4. Open hard-gate caveats:** accept that Windows/WSL and dependency
  maintenance are uncertain for every candidate and decide now, conditional
  on G03, or wait for G03.
- **Recorded decision:** _pending_.

## 11. Consequences once decided

- The plan §7.1 layout is adopted in the chosen language. The losing
  prototypes are archived in git history and not maintained.
- The G02 slice contract is not a public contract. M01 designs the
  production CLI and IPC contracts (G08).
- Inputs carried into M01:
  - Exec-equivalent job control: third-party stops, explicit SIGTSTP or
    SIGSTOP sent to the launcher, early resume (Q16), and mirroring races
    (Q18).
  - On macOS: avoiding double delivery of terminal signals (Rust) or keeping
    single delivery (Go).
  - Signal transparency beyond the five forwarded signals, including SIGKILL
    and orphaning.
  - Restoring the TUI after unhandled signals.
  - `--meta-file` failure semantics.
  - Passing duplicate keys in the environment block through unchanged.
  - Bidi and zero-width display spoofing.
  - Reads of environment-selected files.
  - Windows: exe search order, named-pipe server identity, job objects and
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
