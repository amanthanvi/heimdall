# ADR-0002: Implementation language, TUI stack, and distribution (G02)

**Status:** accepted 2026-10-31: **Rust + Ratatui** (§10, decided under the owner's delegation,
ADR-0004). Revision 3's analysis below is unchanged.
**Date:** 2026-10-10 (revision 3, after round 4) · **Gate:** G02 · **Task:** M00-T05
**Affects:** every production requirement, through the stack choice. This ADR
cites prototype-level evidence for R-SS-04, R-UX-05, R-DI-01, R-AP-02 and
R-SE-05. That evidence does not verify those requirements.
**Reviews of this ADR:**
- `tests/evidence/artifacts/review-adr-0002/review.md` reviewed the first
  draft.
- `review-2.md` reviewed the second draft. Its findings were addressed in
  revision 2.
- Round 4 re-score: three blind scorings by models from two vendors, compared
  with the orchestrator's scores recorded before any of them returned
  (`rescore-r4/`, §7.2).
- `review-3/`: two adversarial reviews of this revision (evidence fidelity;
  decision logic and fairness) and how each finding was handled (§13).

## What changed in revision 3

The owner deferred D1 until more experiments and native Windows/WSL testing
had run (§10). Round 4 (`docs/g02/round4-plan.md`) ran six experiments, X1–X6
(§2.4). This revision:
- updates the gate table with the native Windows and linux-x64 runs (§3);
- replaces the ergonomics row with agentic and open-source maintainability,
  as the owner ruled (D2), and re-scores every row from the round-4 evidence
  (§7);
- updates the Iroh section with built and run evidence (§8);
- restates the recommendation and the owner's decisions (§9, §10).

Sections 2.1–2.3, 3.3, 4 and 6 keep their round-3 content, with round-4
corrections marked.

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

**Final prototype commits of round 3** (the artifacts X1 ran on Windows and
linux-x64):
- Go: `38b6b72`
- Rust: `d8f0cbe`
- TypeScript: `0bd7df9` (frozen)

**After the round-4 Windows fix round (X1b):** Go `84c7665`, Rust `001a791`.
These were run natively on Windows x64 (71/71), re-checked on darwin-arm64 and
linux-arm64, and (2026-10-31) run natively on linux-x64 under WSL2: 139/139
for both, every check the same as on the other platforms
(`tests/evidence/artifacts/g02-r4/x1c/`).

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
- Windows (the harness does not run there; round 4 used a separate native
  Windows script, §3.1);
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
  digest-pinned runner image. In round 3, linux-x64 ran only under
  emulation, which proves nothing for x64; round 4 ran the round-3 artifacts
  natively on linux-x64 under WSL2 (§2.4).
- **Toolchains:** Go 1.27.1; Rust 1.99.0 (pinned by build.sh); Bun 1.4.2.
- **Libraries:** Bubble Tea v2.0.10; Ratatui 0.30.2 with crossterm 0.29.0;
  OpenTUI 0.5.14.

### 2.4 Round 4 (2026-10-06 to 2026-10-10)

The prototypes stayed frozen except for one Windows fix round each (X1b).
Every record is under `tests/evidence/artifacts/g02-r4/`.

| ID | Question | What ran | Result | Record |
|---|---|---|---|---|
| X1 | Do the artifacts work natively on linux-x64 and Windows 11 x64? | The frozen artifacts on the owner's Windows 11 PC and its WSL2 Ubuntu (non-elevated, fixture agents only); then the Windows script under contract §9.6 | linux-x64: **139/139 both**, every check the same outcome as on darwin-arm64 and linux-arm64. Windows under §9.6: Go 67/71 (batch-file arguments ran as commands), Rust 68/71 (a named pipe given as `--file` hung `profile show` and `tui`; `--socket` overwrote a regular file) | `x1/RESULTS.md`, `x1-review/` |
| X1b | One Windows fix round each | Go `84c7665` refuses `.bat`/`.cmd` targets (exit 127). Rust `001a791` checks the file type (`--file` must be a disk file, `--socket` a pipe, before any write) | **71/71 gating both**, harness still 139/139 on darwin and linux; independent review of each: no major. Go can no longer launch batch files (npm-style `.cmd` shims). Rust's reviewer demonstrated environment-driven command injection and wrong-batch-file execution through a batch file's *path* (`argv[0]`), which `cmd.exe` expands as it does under plain exec (not gated, §9.7; M01 must refuse such paths) | `x1b/`, `tests/evidence/g02-{go,rust}-x1b-windows.json` |
| X2 | Which codebase do agents change more reliably? | 4 tasks × 2 languages × 3 runs (2 Opus 5.5, 1 Sonnet 5.5), hidden acceptance tests, full harness, per-cell review; then a cross-cell review of every task with one rubric and probes on rebuilt binaries | Hidden tests: **all 24 cells pass every check**, no harness regression; effort equal (geometric-mean Go/Rust 1.02 output tokens, 0.98 tool calls). Calibrated review: two causes of a major the hidden tests miss, each in 2–3 of 3 Go cells and no Rust cell (§6.2) | `x2/RESULTS.md` |
| X3 | Supply-chain and security tooling | Dependency graphs, unsafe/C surface, scanners, SBOMs, reproducibility, fuzzing, release tooling, hardening flags on the frozen prototypes | Go: 17 modules linked against Rust's 77–82 crates; reproducible across hosts with stock flags; buildinfo gives binary SBOMs and `govulncheck` reachability; GoReleaser worked first try. Rust: cargo-deny policy gating; reproducible on one host only (pinned build environment needed); `cargo auditable` needed for binary SBOMs. Both default Linux artifacts are static non-PIE; Go reached PIE and full RELRO only as a dynamic build that needs a glibc interpreter, Rust reached no PIE with the stable flags tried for static musl | `x3/RESULTS.md` |
| X4 | Native platform integration per language | Spikes: macOS Keychain and Secure Enclave, Linux Secret Service and kernel keyring, Windows DPAPI/CNG and a named-pipe server with a client-SID check | Functional parity where executed. Rust: safe high-level wrappers on macOS (`security-framework`) and Linux (DH-encrypted Secret Service); on Windows, typed but `unsafe` `windows-sys` FFI (20 unsafe sites in the spike). Go: cgo or untyped `purego` bindings on macOS; typed `x/sys` DPAPI but untyped `uintptr` calls for the 10 NCrypt functions and one impersonation call; a plaintext Secret Service session. Windows pipe checks pass 5/5 both; DPAPI, CNG and TPM **not executed** (owner authorization) | `x4/*/RESULTS.md`, `x1/x4-windows-run/` |
| X5 | Is one toolchain realistic once Iroh is added? | iroh 1.3.0 embedded in Rust and cross-built; a Go supervisor driving Rust helpers | ring and aws-lc build under zig for every target (12/12); loopback-only exchanges ran on darwin and linux-arm64 (Windows built, not run). Embedding grows the Rust artifact 6–8×; a Go product ships a Go binary plus a Rust helper (two toolchains, two artifacts) | `x5/RESULTS.md` |
| X6 | Outside evidence on agentic and open-source maintainability | Desk research with primary sources | LLM benchmarks lean slightly to Rust but are uncontrolled; Rust's compiler catches more agent mistakes; Go has more first-party tooling and the first-party `x/crypto/ssh/agent`; a tie or ±1 | `x6/RESULTS.md` |

The host's Go toolchain moved from 1.27.1 to 1.27.2 on 2026-10-09; rebuilds
after that date differ in bytes from the pinned Go artifacts, with identical
sources and behaviour.

## 3. Hard gates (plan §3 G02)

Verdicts use **pass / fail / uncertain** only. "Uncertain" means the evidence
does not settle the gate: either the platform needed is not available, or the
question is a judgment the evidence leaves open. A bracketed note marks every
place the verdict differs from a reviewer's or a re-scorer's.

| Gate | Go + Bubble Tea | Rust + Ratatui | TS + OpenTUI (frozen) |
|---|---|---|---|
| Child/IPC correctness | **pass, given the §9.5 classification.** 139/139 on darwin-arm64, linux-arm64 and (round 4) native linux-x64; the Windows `run` rows pass after X1b. [Review3c rated "waits for the child, no orphan" **uncertain** because of the darwin SIGSTOP orphan (§6), and escalated it.] | **pass, given the §9.5 classification.** 139/139 on the same three platforms; Windows `run` rows pass. [Review3c rated "no regression" **fail** because of the third-party-stop hang (§6), and escalated it.] | **fail.** K8, K14 ×2, K6a ×3, K6e, and K12 for a usage error on a closed stdout. K6d errors on a harness precondition |
| Viable Windows/WSL path | **pass** (round 4). Native Windows 11 x64: 71/71 gating rows after one fix round (X1b), independently reviewed; native linux-x64 under WSL2: 139/139. The fix refuses `.bat`/`.cmd` targets, so `run` cannot launch npm-style `.cmd` shims (§3.1) | **pass** (round 4). Native Windows 11 x64: 71/71 after one fix round, independently reviewed; linux-x64: 139/139 | **uncertain.** Bun named-pipe support taken from Bun's source only |
| No unsupported security assumption | **pass for the slice** (round 4). Unix as before. Windows, executed: batch targets refused; ErrDot refuses resolution through the current directory; `--socket` on a non-pipe path refused without writing. The pipe client connects at the Anonymous impersonation level (matters only to servers that identify clients by impersonation). Native secure-store APIs not executed (X4) [Codex re-scorer: uncertain] | **pass for the slice** (round 4). Windows, executed after X1b: file-type checks before any read or write; std escapes batch arguments (`argv[1..]`, 16/16 exact). Recorded, not gated: std searches the application directory and System32 before PATH; a batch file's own path is not escaped, and the reviewer demonstrated command injection and wrong-file execution through it, as under plain exec (§9.7). Native secure-store APIs not executed [Codex re-scorer: uncertain] | **fail.** In compiled Bun 1.4.2 binaries, BUN_OPTIONS `--preload`, BUN_BE_BUN and BUN_INSPECT cannot be disabled (`artifacts/g02-ts/research/`). OTUI_* keystroke logging must also be scrubbed |
| Practical distribution | **uncertain.** One file per target, 5.2 MB (2.0 MB gzip), static on Linux. **Linux (2026-10-31, X1d):** the post-fix artifact ran 139/139 on two long-lived hosts with no Go or Rust toolchain installed (Ubuntu 24.04 VM, Debian 13), from a directory with spaces and non-ASCII characters, and with a read-only filesystem. Windows: ran without a toolchain on PATH, but on a development host, files carried no Mark-of-the-Web. macOS: development host only. Ad-hoc signing only, no notarization or Authenticode [Fable re-scorer: pass] | **uncertain.** One file per target, 0.72–0.88 MB (0.37–0.45 MB gzip), static on Linux. Same results and the same gaps [Fable re-scorer: pass] | **uncertain.** 73–97 MB per target plus a native sidecar; musl runtime dynamically linked |
| Maintained dependencies | **uncertain**, a judgment. ultraviolet (Bubble Tea's renderer) is an untagged pseudo-version and has the wide-character cursor bug X2 found (§6.2); cancelreader dates from 2022; there is no maintained Go library for the macOS Keychain and SecKey (X4) | **uncertain**, a judgment. crossterm's last release (0.29.0, 2025-04) is about 18 months old and still carries the Windows path; `security-framework` is looking for a maintainer and drops one error status (X4); winapi 0.3.9 dates from 2020 | **uncertain**, a judgment. OpenTUI is pre-1.0 |
| Compatible licensing | **pass.** 17 third-party modules, all MIT or BSD-3 (X3: go-licenses check rc 0 with the unlicensed main module excluded). Notices are not shipped yet | **pass.** Permissive; a full notices file ships; cargo-deny and cargo-about rc 0 (X3). Which LGPL-marked mingw-w64 parts the Windows build links was not determined | **uncertain.** LGPL-2 JavaScriptCore and LGPL-2.1 tinycc |
| Domain shared across CLI/TUI | pass | pass | pass |

Every candidate's project license is still a placeholder (`UNLICENSED`).

### 3.1 Windows (executed in round 4)

| Item | Go | Rust |
|---|---|---|
| Named-pipe client | go-winio connects at `SECURITY_ANONYMOUS`; a server that identifies clients by impersonation cannot identify it, one that uses the process token can (Win32-OpenSSH does; x1-review) | `SECURITY_IDENTIFICATION` |
| Pipe server with a client-SID check (X4 spike) | 5/5 pass: same user accepted at Identification level, a foreign SID and Anonymous refused, impersonation control, first instance exclusive (other-user and remote clients not tested); overlapped I/O with deadlines | 5/5 pass; blocking, thread per connection, no read deadline (a product server needs overlapped I/O or timeouts) |
| `--file` given a named pipe or other non-regular path | refused, exit 2 in about 25 ms (correct on first contact) | hung on first contact; refused after X1b (`GetFileType`) |
| `--socket` given a regular file, directory or missing path | refused, nothing written | overwrote the first 5 bytes of a regular file on first contact; refused after X1b, checked before any write |
| `.bat`/`.cmd` targets | first contact: arguments ran as commands (8 of 16 injected); after X1b **refused** (exit 127), including bare names resolved through PATHEXT | arguments (`argv[1..]`) escaped by std, 16/16 delivered exactly; the batch file's own path is not escaped: an attacker-controlled `%NAME%` in it ran a second command, and another ran a different batch file (§9.7; plain exec does the same) |
| Executable resolution | PATH order; refuses the current directory (ErrDot); runs `.cmd` through PATHEXT (before X1b) | application directory and System32 before PATH; `.exe` only |
| Console Ctrl-C | `run`: the child sees one interrupt, the launcher exits with the child's status; `agent list`: exit 130 `CANCELLED` | same |
| TUI receiving CTRL_C_EVENT from another process (not gated) | exits 1, terminal restored | killed by the default handler, alternate screen left active |
| Job object for the child | none | none |
| Native secure stores (X4: DPAPI, CNG, TPM) | built; **not executed** (writes to the owner's key store and TPM need authorization) | same |

Remaining Windows gaps, the same for both: one host and one Windows build,
non-elevated, pseudoconsoles only (no conhost window or Windows Terminal), no
second account, no ARM64, no clean machine, no SmartScreen or Defender
interaction. G03's own Windows and WSL records (`docs/research/g03-windows-wsl.md`
§0) are language-independent: most rows are verified; the rest are blocked
or in progress (inconclusive), waiting on a second Windows account, a second
Linux account with sudo, a disposable distribution or host, or an operator at
the console.

### 3.2 Gate result

**Go and Rust:**
- **Pass:** child/IPC correctness (under §9.5), the Windows/WSL path, the
  security assumptions of the slice, licensing and the shared domain. The
  child/IPC pass still holds only under the §9.5 classification: if you rule
  that §4 covers stops sent by a third party (D3), **both** fail that gate
  until a further fix round.
- **Uncertain, identically for both:** practical distribution (no
  clean-machine run, no signing) and the dependency-maintenance judgment.
  Neither separates the two. plan.md §3 G02 puts all hard gates before
  preference scoring, so the scores in §7 and the recommendation in §9 are
  **provisional** until you either accept these two as open for both stacks
  (Q-D) or they are closed. Linux now has runs on two machines without
  either candidate's toolchain (X1d, not freshly installed); closing practical
  distribution still needs clean Windows and macOS machines and signing
  identities.

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

**Round 4 additions:**
- Native linux-x64 (WSL2): TUI first frame Go 40.2 ms, Rust 20.2 ms; K17
  filter p95 Go 17.7 ms, Rust 2.7 ms (X1 observations, single runs).
- X2 T2's `profile lint` implementations: two Rust cells peaked at 190–205 MiB
  on the worst 1 MiB profile (K15 limit 256 MiB); the other four cells stayed
  at or below 124 MiB. This measures those implementations, not the baselines.

## 5. Platform signal behaviour and stack limitations

These items are non-gating (K6b, K6c), but they matter for production. The
same rows are given for every candidate.
Windows behaviour, executed in round 4, is in §3.1.

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

The reviewers ran most of these probes against only one prototype. §6.1
gives the parity run of the same probes against both builds
(`tests/evidence/artifacts/g02-parity-r3c/RESULTS.md`).

**Found in both:** an explicit SIGTSTP or SIGSTOP sent to the launcher's PID
stops only the launcher, while the child keeps running.

**Go:**
- **Major, darwin only, exclusive (interactive foreground) mode, present
  before round 3c.**
  - What happens: if the run child is stopped by SIGSTOP, whether it sent the
    signal itself or another process did, `heimdall-proto` exits 255 and
    leaves the child stopped in an orphaned process group. The meta file
    records `exit_code -1`.
  - Cause: Go's BSD `WaitStatus.Stopped()` does not treat a SIGSTOP stop as
    a stop on darwin, a standard-library behaviour (X6 §5, from the source).
    Every X2 T1 Go cell decoded the raw status instead (round 4).
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
  - Remedy suggested by the reviewer: mirror stops only in a job-control
    context, which is what Go does. The parity probes (§6.1) show this avoids
    the non-interactive hang but not the interactive one: there, Go ends in
    the same stuck state.
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

Each probe ran against both final builds and a plain-exec control, on
darwin-arm64 and linux-arm64. The binaries were the unmodified ones, with
digests checked. Probes 2 and 3 were run 3 times per platform; probes 1 and 4
once per platform. The probe-harness bugs hit along the way are recorded in
`RESULTS.md`.

| Probe | Go | Rust |
|---|---|---|
| 1a. Non-interactive parent; a third party stops the child, then continues only the child's PID | **matches the control** on both OSes, for both signals | **hangs.** The launcher stays stopped and the child becomes an unreaped zombie. This happens for SIGSTOP on both OSes, and for SIGTSTP when the process group is not orphaned |
| 1b. Same, in `bash -i` or `zsh` with the job in the foreground | **does not match.** The launcher stays stopped, the child becomes a zombie, and the job waits for `fg` (SIGTSTP on both OSes; SIGSTOP on Linux). darwin SIGSTOP: the launcher exits 255 and the child is killed | **does not match.** Launcher stopped, child a zombie, the job waits for `fg` (both OSes, both signals) |
| 2. The child stops itself, then SIGCONT goes only to the launcher | **matches the control** (both OSes and shells, 3/3) | **does not match.** The child stays stopped while zsh, and bash 5.2 on Linux, show the job as running, which breaches the K6e clause through an explicit signal (3/3) |
| 3. Nested `bash -i` as the child, `suspend`, then `fg` | Linux **matches**. **darwin (3/3): the launcher exits 255 and the user's outer interactive shell exits too**, ending the terminal session. The cause was not isolated | **does not match** on either OS. The nested shell stays stopped after `fg`; the outer shell survives |
| 4. SIGSTOP stops the child in exclusive mode | darwin: **exit 255, both processes gone, meta `exit_code -1`**, reproducing the Go reviewer's finding. Linux works but reports 148 where the control gives 147 | **matches the control** on both OSes |

**What parity shows:**
- Neither prototype handles stops that another process sends to the child.
  In an interactive session, both end in the same stuck state (probe 1b).
- Go avoids the hang only when it is not mirroring stops (probe 1a).
- Rust's distinct failures are the non-interactive hang and the launcher-only
  SIGCONT case.
- Go's distinct failures are the darwin SIGSTOP cases. In the worst of them,
  a nested job-control shell, the user's terminal session ends.

These findings are of comparable weight and have different shapes. They
left the round-3 scores unchanged and strengthen the M01 job-control
requirement. Round 4's X2 adds what agents did when asked to fix them (§6.2).

### 6.2 What agents left behind when changing each codebase (X2)

X2 gave the same four tasks to fresh agents in each language (`x2/RESULTS.md`).
Every cell passed every hidden check, and effort was equal, so the hidden tests
did not separate the languages. A second review of each task across its six
cells, with one rubric and probes on rebuilt binaries, found two causes of a
major defect that the hidden tests and most per-cell reviewers missed. Both
were reproduced by an independent second execution.

- **T1, job control (all three Go cells).** Every one of the six T1 changes,
  in both languages, added a rule for "is a job-control shell watching?" that
  misses a background job with redirected stdio: when another process stops
  the job's child, the shell shows the job as Running. In the Go cells `fg`
  then hangs and ^Z does nothing; on Linux no shell key recovers it, on
  darwin ^C kills it (a `kill -CONT %1` typed before `fg` finishes the job
  only in the one Go cell that handles SIGCONT while running). In the Rust
  cells ^Z then `fg` finishes the job. The difference
  comes from the baselines: the Go prototype runs the child in its own process
  group and hands it the terminal, a design its author chose because
  `os/signal` gives no `siginfo` without cgo; the Rust prototype shares the
  group, which `signal-hook` and `libc` make affordable. None of the Rust
  cells' new code produces the recovery, and one Go cell partly avoided the
  trap. The 3-to-0 count depends on two rubric readings (a third-party stop
  of a background job is plausible; ending the job is not a normal
  recovery), and the Rust cells keep more baseline divergences from plain
  exec, all recoverable.
- **T3, TUI (two of three Go cells).** Bubble Tea v2 makes the Go code embed
  the underline escape codes in the row text, and its renderer (ultraviolet,
  a pinned untagged version) then puts the cursor one column short next to
  double-width characters: on the shipped `homelab.toml` at 20x5, typing
  `/東京` shows `> vps- 京`. Reproduced in pyte, tmux and xterm.js; the Go
  baseline already loses a CJK filter character in the status line the same
  way. The third Go cell avoided it with a full repaint. No Rust cell has it.
- **T2 and T4:** no major in either language. T2's two Rust cells peak at
  190–205 MiB of the 256 MiB K15 limit on the worst 1 MiB profile, against
  at most 124 MiB for the other four cells.

The honest count is two causes, each in two or three of three Go cells and in
no Rust cell; it is not five independent findings. Only the facts behind these
two majors (T1's P1 scenario and T3's rendering case) were re-run
independently; the other calibrated ratings come from one reviewer per task.
The calibration itself was not in the round-4 plan: it was added after the
per-cell reviews disagreed, when the planned X2 measures had all come out
even. Both are pitfalls of the Go stack, not limits of it: in T3 one Go
implementer avoided the trap entirely (a full repaint); in T1 every Go cell
fell into it, one partly mitigated it, and the independent re-run names fixes
within the standard library.

## 7. Comparison criteria (plan §3 G02 weights)

Scores run from 1 to 5. They are judgments over the cited evidence, not
measurements. Go and Rust have the same five passes and the same two
uncertain gates (§3.2), so these scores are what separates them, provisionally
until Q-D is answered. The 15 % row is agentic and open-source maintainability (owner
D2). TS is not re-scored.

### 7.1 Scores

| Criterion (weight) | Go | Rust | Basis | Confidence |
|---|---|---|---|---|
| Cross-platform integration (25 %) | 3 | 4 | The post-fix artifacts ran natively on Windows x64 (71/71) and linux-x64 (139/139, X1c), and were re-checked on darwin-arm64 and linux-arm64 (139/139) (§2.4, §3.1). For Rust: safe high-level wrappers for the macOS Keychain and Secure Enclave and a DH-encrypted Secret Service session; typed (but `unsafe`) `windows-sys` FFI for CNG, DPAPI, pipes and tokens, whose signatures the compiler checks (X4; 20 `unsafe` sites in the spike against Go's 30); std escaping of batch-file arguments, so `run` can launch batch files (X1b). For Go: cross-compiles every target with its own toolchain and no SDK (purego even builds a working darwin Keychain binary on Linux, X4); typed `x/sys` DPAPI; correct Windows file and socket semantics on first contact. Against Go: untyped `uintptr` calls for the 10 NCrypt functions and one impersonation call (a pointer-lifetime pitfall `go vet` misses), cgo or untyped purego on macOS, a plaintext Secret Service session, and no batch-file launch after X1b. Against Rust: darwin builds that link frameworks need the macOS SDK; the System32-first search order; demonstrated command injection and wrong-file execution through a batch file's own path, as under plain exec (§3.1, §9.7) | low: two of three re-scorers gave 4/4; the typed-binding advantage is in code and builds, while DPAPI, CNG and TPM never ran |
| Security-sensitive core correctness and maintainability (25 %) | 4 | 4 | Both pass the gates with one localized round-3 major each (§6) and one Windows fix round each. Each baseline's signal model has a cost: Go's separate process group gives single delivery of terminal signals on macOS, but the standard library misdecodes a darwin SIGSTOP (§6) and the design fails harder when a stop goes wrong (§6.1, probes 3–4); Rust's shared group delivers every terminal Ctrl-C, Ctrl-\ and resize to the child twice on macOS (K6b, §5) and its stop mirror has a liveness bug (§6). Go: 17 linked modules against Rust's 77–82 crates (different granularity: a Go module often bundles what Rust splits into crates, so the ratio overstates the gap in independent maintainers), no C runtime, call-graph vulnerability scanning and binary SBOMs (X3). Rust: compile-time memory and data-race safety, exhaustive matching, `deny(unsafe_code)` in its own code; but many more crates contain `unsafe` (a grep upper bound; cargo-geiger counts 42 crates with unsafe used by the build) and the Linux and Windows builds link a C runtime (X3). The X2 finding that agents left more defects in the Go job-control code is counted in the maintainability row, not here | medium: all four scorings agree (but see the §7.2 caveat on their independence) |
| Release and runtime simplicity (20 %) | 4 | 4 | Release favours Go: stock flags give byte-identical builds across hosts, buildinfo gives binary SBOMs and vulnerability scans, GoReleaser built the matrix first try; PIE and full RELRO are reachable on stable, though only as a dynamic build that needs a glibc interpreter (X3). Rust needs zig, cargo-zigbuild, remap flags, a pinned build environment for cross-host reproducibility (not reproducible across hosts in X3; an X1b rebuild of unchanged source also differed, cause not investigated, while Go's round-4 rebuild differences came from its toolchain upgrade), and `cargo auditable`. Runtime favours Rust: 7× smaller artifacts, idle CPU 0.03 % against Go's 0.35 % (spec §15.1 budget 0.5 %), 2–4 MB peak RSS against 7–8 MB (§4). **This row assumes Iroh in V1** (spec §3 default, §8): Go's simpler, reproducible pipeline then offsets its second toolchain and artifact for the Rust Iroh helper, so 4/4 (the orchestrator's pre-registered judgment; the Fable and Opus re-scorers read the in-V1 case as Go 3 / Rust 4, and the Codex re-scorer scored the row Go 4 / Rust 3 overall; §7.3). If Iroh is deferred, Go is simpler outright (about Go 5 / Rust 3; §7.3) | low: hinges on the Iroh scope (§10 Q-A) |
| Agentic and open-source maintainability (15 %) | 3 | 4 | X2: on four tasks, agents changed both codebases with identical hidden-test results and equal effort, but 5 of 12 Go cells left a major the tests missed, concentrated in T1 (3 of 3) and T3 (2 of 3), from two correlated causes: the Go baseline's separate-group job-control architecture (which its author chose because `os/signal` exposes no `siginfo` without cgo; the Rust cells inherited a more forgiving design rather than writing better code) and Bubble Tea v2's inline-SGR renderer next to wide characters; no Rust cell did (§6.2). This rests on a cross-cell calibration that was not in the round-4 plan: it was added after the planned X2 measures (hidden tests, regressions, per-cell reviewer majors 1 and 1, effort) had all come out even, and the orchestrator's interim scores, recorded before it, had this row at 4/4. Under the rubric's other readings (§7.3) the lean narrows or disappears. X6: compiler guarantees favour Rust; first-party tooling and the SSH-agent library favour Go; outside benchmarks are uncontrolled. The X2 signal is two causes on one sample of three runs each, so the row moves one point, not more | low: all four scorings gave 3/4, but the difference comes from a post-hoc calibration, one rubric reading and two causes (§7.2 caveat, §7.3) |
| TUI quality (10 %) | 3 | 3 | Round 4 replaced the round-3 judgment ("Bubble Tea provides the most out of the box") with observations. Against Go: the renderer's wide-character bug (in the baseline's status line too), dropped combining and zero-width characters, no underline when `TERM` is `dumb` or unset (X2 T3). Against Rust: hand-written Unix input decoding over a stale crossterm, bidi and zero-width characters passed to the terminal, the alternate screen left active after an external CTRL_C_EVENT on Windows (§3.1). Rust's first frame and filter latency are 2–6× faster, invisible at these sizes | low: two scorers gave Rust a point more (rendering correctness observed in three emulators) |
| Integration ecosystem (5 %) | 4 | 4 | Iroh is native Rust and now built for every target (X5); the only pure-Go Iroh port is young and experimental. Go has the first-party `x/crypto/ssh/agent` client and server with wide adoption; Rust's SSH-agent crates are community-maintained (X6). The round-3 Rust 5 counted Iroh only | medium |

**Totals: Go 3.50, Rust 3.90.**

### 7.2 Independent scorings

The orchestrator recorded its scores twice before any re-scorer returned
(`rescore-r4/orchestrator-prereg.md`: once on the interim X2 data, once on the
final X2 results; the file was last written at 04:58:15 and the first
re-scorer's file at 05:04:05). Three re-scorers then worked from the same
brief and evidence (`rescore-r4/SCORER-BRIEF.md`), blind to each other's
scores and to the orchestrator's. They were not blind to the orchestrator's
framing: the brief named revision 2's lean to Rust, and `x2/RESULTS.md` as
they read it (commit 101aeeb) carried the orchestrator's reading of X2,
including a significance figure and a "traces to the Go stack" attribution
that were later removed as overclaims (ca3ef37f). The agreement below is
therefore less independent than four separate scorings would suggest. The
Codex scorer's model is recorded in `rescore-r4/PROVENANCE.md`, not in its file.

| Criterion | Orchestrator | Codex GPT-6.1 Sol | Claude Fable 5.1 | Claude Opus 5.5 |
|---|---|---|---|---|
| Cross-platform (25 %) | 3 / 4 | 4 / 4 | 4 / 4 | 3 / 4 |
| Security core (25 %) | 4 / 4 | 4 / 4 | 4 / 4 | 4 / 4 |
| Release and runtime (20 %) | 4 / 4 | 4 / 3 | 4 / 4 | 4 / 4 |
| Agentic and OSS maintainability (15 %) | 3 / 4 | 3 / 4 | 3 / 4 | 3 / 4 |
| TUI quality (10 %) | 3 / 3 | 3 / 4 | 3 / 3 | 3 / 4 |
| Integration ecosystem (5 %) | 4 / 4 | 4 / 4 | 3 / 4 | 4 / 4 |
| **Total (Go / Rust)** | **3.50 / 3.90** | **3.75 / 3.80** | **3.70 / 3.90** | **3.50 / 4.00** |
| Recommendation | Rust, low (low to medium before review-3, §13) | Rust, low | Rust, medium | Rust, low |

All four lean to Rust, by 0.05 to 0.50. They agree on the security-core and
maintainability rows; they differ on cross-platform, release, TUI and
ecosystem by one point each.

### 7.3 Sensitivity

- **One change at a time from §7.1:** each cross-platform or security-core
  point moves the total 0.25; each release point 0.20; each maintainability
  point 0.15; each TUI point 0.10. Rust's lead is 0.40.
- **Iroh scope (§10 Q-A) is the largest single lever.** Spec §3 makes Iroh a
  V1 target that only a recorded scope decision can defer, so §7.1 assumes it
  stays.
  - *Iroh in V1:* the release row is 4/4 in §7.1, the reading most favourable
    to Go; the Fable and Opus re-scorers read it Go 3 / Rust 4, which widens
    Rust's lead from 0.40 to 0.60.
  - *Iroh deferred:* the ecosystem row becomes Go 4 / Rust 3, and the release
    row Go 4 / Rust 3 (Codex's and Fable's reading) or Go 5 / Rust 3 (Opus's).
    Totals: Go 3.50 / Rust 3.65 (Rust +0.15) or Go 3.70 / Rust 3.65
    (Go +0.05), a tie within the precision of these judgments. If
    cross-platform is then also scored 4/4 (two re-scorers' reading), Go
    leads by 0.10 to 0.30.
- **Iroh as a supervised helper even in Rust (G06):** Rust would then ship two
  artifacts too; its one-language, one-toolchain advantage remains, but the
  artifact-count advantage disappears. The primary release row is already
  4/4, so this case argues against moving it toward Rust, not for a change.
- **Batch files not required (§10 Q-B):** removes one of Rust's
  cross-platform arguments; on its own it does not flip the result.
- **X2 rubric readings (§10, D3 l).** `x2/RESULTS.md` §5.1 gives three:
  as applied (a third-party stop of a background job is plausible, ending
  the job is not a normal recovery): T1 Go 3, Rust 0; if such stops are
  implausible: T1 Go 0, Rust 0, so only T3's two Go cells remain; if a
  wrong job state is major whatever the recovery: T1 Go 3, Rust 3. Under
  either alternative only the T3 cause separates the languages.
- **TUI library (§10 Q-E):** if the chosen language may later change TUI
  library, the T3 finding weighs on Bubble Tea, not on Go, and only the T1
  cause separates the languages.
- **One X2 cause left** (either of the two bullets above): the
  maintainability row is a judgment between 3/4 and 4/4, so Go 3.50 or 3.65
  against Rust 3.90. **Neither left** (both apply): the row is even, Go 3.65
  against Rust 3.90.
- **What gives Go the lead:** Iroh deferred on its own gives between
  Rust +0.15 and Go +0.05, a tie in practice; any one further reading for Go
  (cross-platform 4/4, maintainability even, or TUI for Go) then gives Go a
  clear lead. With Iroh in V1, no single defensible change flips the result:
  cross-platform 4/4 plus maintainability 4/4 gives a tie (3.90 each), and a
  Go lead needs a third change (for example the TUI row for Go: 4.00 to
  3.90).

## 8. Iroh: embedding versus helper (deferred to G06)

G02 does not make the final embedding-versus-helper decision. plan.md §3 G06
owns it ("Iroh integration versus managed helper"), and it will be decided
from lifecycle and packaging evidence. Round 4 (X5) built and ran what §8
previously inferred:

| Candidate | Path | Evidence (X5, loopback only, relays and discovery disabled) |
|---|---|---|
| Rust | Embed the `iroh` crate (1.3.0, MIT OR Apache-2.0), or run it as a supervised helper from the same codebase | Built for darwin-arm64, linux-x64/arm64 (musl, zig) and windows-x64 (gnu) with ring and with aws-lc: 12 of 12 builds exit 0, so the ring-under-zig risk is **closed for building**. On windows-x64 both crypto crates link prebuilt assembly objects shipped inside the crates. Ran on darwin and in a `--network none` linux-arm64 container, and (2026-10-31) natively on linux-x64 under WSL2: selftest 14/14, supervisor 14/14, supervisor-death 6/6, all traffic 127.0.0.1 to 127.0.0.1 (`x5/native-x64/`). A whole-run trace there found what X5's socket snapshots missed: each endpoint briefly opens a UDP socket bound to the IPv4 wildcard address to discover the local address (netdev, through netwatch; no packet sent), and none of the relay, discovery, portmapper or net-report settings disables it. Windows: built, not run, because that wildcard bind might raise a firewall prompt on the owner's PC (§10 Q-G). Embedding grows the prototype 6–8× (darwin 0.72 → 4.5 MB); iroh's own dependency tree is 225–250 crates per target (`x5/results/dep-census.tsv`), including C and assembly, in the same process as the security core |
| Go | A supervised Rust helper. A 226-line stdlib-only Go supervisor drove two Rust helpers over framed stdio; both exited within 1.5 s of the supervisor's SIGKILL | Two binaries from two toolchains: darwin 5.2 MB + 3.6 MB against Rust's 4.5 MB single file (similar ratios on the other targets; X5's claim that a real helper makes the gap "at least" this large is an inference). The community `iroh-go` binding is experimental, Linux-only and needs cgo; the only pure-Go port is young and carries about 51k lines of forked TLS and QUIC (X5 §5; not adoptable) |
| TS | npm `@number0/iroh` (napi) | unchanged from round 3: no darwin-x64 build; extracts a native library to TMPDIR under `bun --compile` |

Spec §3 makes Iroh a V1 target that may be deferred only by a recorded scope
decision. If Iroh ships in V1, Rust ships one toolchain and Go two; if it is
deferred or dropped, the Go two-language cost disappears (§7.3). G06 may still
prefer a supervised helper in either language to keep Iroh's dependency tree
out of the security core's process.

## 9. Recommendation and rejections

**Recommendation: Rust + Ratatui, with low confidence, conditional on Iroh
staying in V1.** All four scorings in §7.2 lean the same way, by 0.05 to
0.50, but they are not fully independent (§7.2). The lead rests on several
moderate advantages, not one decisive one; if Iroh is deferred the
comparison is a tie within precision (§7.3), and the scores stay provisional until Q-D is
answered. The design would keep crossterm for output only on Unix,
static musl builds on Linux, and one executable per target.

Why Rust:
1. **Platform security integration.** Heimdall's core talks to the platforms'
   security APIs (G04 secure stores, Windows pipes and process launch). Rust
   reaches macOS and Linux through safe wrappers and Windows through typed
   (though `unsafe`) FFI, and its standard library escapes batch-file
   arguments correctly (not the batch file's own path, §9.7). Go needs
   untyped bindings for NCrypt and cgo or untyped purego for the macOS
   Keychain, and its X1b fix refuses batch files outright (X4, §3.1). Much of
   this is code and build evidence: DPAPI, CNG and TPM did not run.
2. **What agents leave behind.** Agents changed both codebases equally
   successfully and at equal cost, but the Go stack set two traps (the
   job-control design `os/signal` pushes toward, and Bubble Tea's renderer next
   to wide characters) that 5 of the 6 Go implementers of those two tasks fell
   into and most of their reviewers missed (§6.2); no Rust cell had a major.
   For a product maintained mostly by agents, that is the relevant cost. It
   is two correlated causes on a small sample, and the T1 half reflects the
   baseline design the Rust cells inherited.
3. **One language with Iroh.** Iroh is native Rust and now builds for every
   target (§8). With Go, shipping Iroh means also maintaining a Rust helper.
4. **Runtime headroom.** About 7× smaller artifacts and an order of magnitude
   less idle CPU (§4), which matters for an always-running broker against the
   spec §15.1 idle budget, although users do not see it in the slice.

**Why Rust could be rejected:**
- A much larger supply chain: 77–82 crates against 17 Go modules (different
  granularity, so the ratio overstates the gap in maintainers), many with
  `unsafe`, a linked C runtime on Linux and Windows, and Iroh's own tree of
  225–250 crates if it is embedded (X3, X5). It needs cargo-deny, `cargo auditable`, an
  OSV/GHSA scanner beyond RustSec (which lists 1 of 20 `russh` advisories,
  X6) and a pinned build environment.
- Weaker release reproducibility and hardening: not reproducible across hosts
  (an X1b rebuild of unchanged source also differed from the committed bytes,
  cause not investigated; the Go rebuild differences seen in round 4 were
  explained by the toolchain patch upgrade), no static-musl PIE with the stable flags tried, darwin builds
  that need the macOS SDK, cargo-dist rough edges (X3, X4).
- On macOS every terminal Ctrl-C, Ctrl-\ and resize reaches the child twice
  (K6b); its stop mirror has an open liveness bug and keeps more divergences
  from plain exec (§6, §6.2).
- Hand-written Unix input decoding over a crossterm without a release for
  18 months; `security-framework` is looking for a maintainer.
- Windows: System32-first executable search, demonstrated command injection
  through a batch file's own path (as under plain exec; §9.7),
  and a TUI killed by an external CTRL_C_EVENT with the alternate screen left
  active.
- The SSH-agent ecosystem is community crates, while Go's is first-party.
- Two T2 implementations used up to 205 MiB of the 256 MiB budget (§6.2).
- The prototype's `build.sh` exits 0 when notices generation fails and when
  any one target builds (X2 T4 cross-review), a false-green a release
  pipeline must not inherit.

**Go + Bubble Tea, the close alternative.** It has the same gate results as
Rust after the same fix rounds, has the smaller first-party-heavy supply chain, the simplest
reproducible release pipeline, cross-compilation without an SDK, and the
first-party SSH-agent library. Its sharpest open defects are in the standard
library and the TUI renderer: the darwin SIGSTOP misdecode (§6), the
separate-group job-control design X2 showed agents getting wrong, and the
wide-character renderer bug. All are fixable: one T3 implementer avoided the
renderer bug, and the job-control fixes need only the standard library. **Choose Go if** Iroh is deferred or dropped (the
comparison is then within Rust +0.15 to Go +0.05, a tie in practice, §7.3) and you weigh supply-chain size and release
simplicity most. Not needing batch files on Windows (Q-B) removes one more of
Rust's arguments.

**TypeScript + OpenTUI, rejected.** Unchanged from revision 2: it fails the
security-assumption gate (runtime environment hooks that load code or open an
inspector could not be disabled in compiled Bun 1.4.2 binaries) and K8 under
the orchestrator's FFI ruling, which you can overrule. Its artifacts are
73–97 MB and embed LGPL components. **Reopen if** Bun gains raw-argv access
and a way to disable its environment hooks in compiled binaries, or a
verified Node single-executable path keeps OpenTUI's native core without
those hooks.

## 10. Owner decisions (required before M01)

**D1. Language and stack:** Rust + Ratatui (recommended), Go + Bubble Tea, or
another choice.

Questions that change the recommendation's strength, in order of effect:
- **Q-A. Iroh scope.** Does Iroh stay a V1 target (spec §3 default), or do you
  defer it by a recorded scope decision? Deferral narrows the comparison to
  between Rust +0.15 and Go +0.05, a tie within the precision of these
  judgments (§7.3).
- **Q-B. Windows batch targets.** Must `run` launch `.bat`/`.cmd` targets
  (for example npm-installed agent CLIs on Windows)? If yes, a Go product
  needs its own `cmd.exe` escaping layer, a security-sensitive component,
  and a Rust product must still refuse batch paths that `cmd.exe` expands
  (§9.7). If no, Go's refusal is acceptable and Rust's batch support goes
  unused (both should then refuse batch targets the same way).
- **Q-C. D4 completion.** You asked to wait until Windows/WSL had been
  tested. The G02 slice now runs natively on Windows 11 and WSL2 (§3.1), and
  most G03 records are verified. Is that enough to decide, or must the
  remaining blocked and in-progress rows run first? Those need a second
  Windows account, a second Linux account with sudo, a disposable
  distribution or host, an operator at the console, and your authorization
  for the X4 DPAPI/CNG/TPM runs. Only the X4 runs bear on the language
  choice.
- **Q-D. Shared uncertain gates.** plan.md §3 G02 puts the hard gates
  before preference scoring. Do you accept practical distribution (clean
  machines, signing) and dependency maintenance as open for both stacks, to
  be closed before a release claim rather than before D1? If not, D1 waits
  for clean Windows and macOS machines (Linux is covered by two toolchain-free
  hosts, X1d) and signing identities.
- **Q-E. TUI library.** Is the choice "Go + Bubble Tea" against "Rust +
  Ratatui" as plan.md names them, or may the chosen language change TUI
  library later? If it may, the X2 T3 finding weighs on Bubble Tea rather
  than on Go (§7.3).
- **Q-F. macOS release builds.** Will darwin artifacts be built and signed on
  a macOS runner (Developer ID and notarization, G04 D3)? If so, Go's ability
  to build darwin binaries on Linux without the SDK no longer matters, and
  neither does Rust's need for the SDK.

- **Q-G. Iroh on Windows.** Running the Iroh probes natively on your PC
  needs one of: you present to decline any firewall prompt, a probe patched to
  avoid the wildcard bind (§8), or your confirmation that such a bind does not
  prompt there. Not needed for D1; it informs Q-A and G06.

**Default path.** If you accept Q-C and Q-D, keep Iroh in V1 (Q-A) and let
the D3 rulings stand, the recommendation is Rust + Ratatui; Q-B, Q-E, Q-F and Q-G
then only adjust M01 work. Q-C and Q-D come first, because they decide
whether D1 can be taken now.

**D3. G02 rulings you may overrule** (recorded in `slice-contract.md`, except
(l), which is in `x2/RESULTS.md` §5.1):
- (a) **§9.5 classification:** stops sent by a third party are not gated
  under §4. If you overrule it, both Go and Rust fail child/IPC until a
  further fix round.
- (b) **§9.5:** no further fix round.
- (c) **K6b:** documented duplicate delivery of terminal signals is allowed.
- (d) **K6c:** disposition resets are not gated.
- (e) **K13:** the verdict platforms are darwin-arm64 and linux-arm64 in a
  Docker VM.
- (f) **K8:** reaching raw argv through FFI counts as routing around the
  stack.
- (g) **The TS freeze** (§9.1).
- (h) **Q16:** an early resume after a self-stop is not gated.
- (i) **Q17:** closed-stdout parity covers error results.
- (j) **§9.6:** the Windows rulings (K14 for named pipes, `--socket` never
  writes to a non-endpoint, no argument byte of a batch target runs as a
  command).
- (k) **§9.7 (new):** a batch file's own path is not gated. Plain exec
  misreads both arguments and the path, so that alone does not separate
  them; the ruling rests on the threat model. Arguments routinely carry data
  from elsewhere (host names, file names, prompts) that the launcher promises
  to pass verbatim (§4, K8), so their injection is a launcher defect and
  §9.6 gates it. Exploiting the path needs the ability to name or create
  directories on the batch file's path: command injection needed an
  attacker-chosen environment variable as well, while running a different
  batch file needed only an existing variable (the reviewer used `%OS%`) and
  a directory created at the expanded name. The Rust reviewer demonstrated
  both, and the Codex re-scorer rated the security gate
  uncertain partly for it. If you overrule this, Rust fails that Windows row
  until it refuses such paths (a small fix), as Go failed the argument rows
  until it refused batch files.
- (l) **X2 rubric (new, `x2/RESULTS.md` §5.1):** a third-party stop of a
  background job counts as plausible for an interactive user, and ending the
  job is not a normal recovery. This reading gives T1 Go 3, Rust 0; judging
  such stops implausible gives 0 and 0, and counting a wrong job state as
  major whatever the recovery gives 3 and 3 (§7.3). The rubric was set by
  the orchestrator after the per-cell reviews disagreed. The calibrating
  agent saw every cell reviewer's rating (it re-rated each listed defect and
  reports where it disagrees); the separate check of its classification saw
  the same evidence and the cell reviews, but not the first
  classification.

**Owner input recorded 2026-10-06** (not yet a decision):
- **D1: deferred** until round 4 and the Windows/WSL tests. Both are now
  done to the extent §3.1 and Q-C describe.
- **D2:** the owner's personal ergonomics are **not a factor**; the 15 % row
  is agentic and open-source maintainability (re-scored in §7).
- **D3:** all of the orchestrator's rulings stand ((a)–(i); (j) followed the
  first native Windows run; (k) and (l) are new in this revision).
- **D4:** wait until Windows/WSL has been tested (see Q-C).
- **Recorded decision (2026-10-31):** **D1 = Rust + Ratatui.** Taken by the orchestrator under
  the owner's explicit delegation ("I trust your judgement on all of these and the rest of the
  decisions"). Q-A: Iroh stays a V1 target, G06 decides the boundary. Q-B: `run` launches batch
  files, refusing script paths `cmd.exe` would expand. Q-C, Q-D: accepted; the shared uncertain
  gates must close before any stable-release claim. Q-E: Ratatui, replaceable only by ADR. Q-F:
  darwin builds signed on macOS; Developer ID needs the owner's Apple membership. Q-G: inside G06.
  D3 (a)–(l) stand. Full reasons: ADR-0004 §1.

## 11. Consequences once decided

- The plan §7.1 layout is adopted in the chosen language. The losing
  prototypes are archived in git history and not maintained.
- The G02 slice contract is not a public contract. M01 designs the
  production CLI and IPC contracts (G08).
- Inputs carried into M01, whichever stack is chosen:
  - Exec-equivalent job control: third-party stops, explicit SIGTSTP or
    SIGSTOP sent to the launcher, early resume (Q16), and mirroring races
    (Q18). X2 adds that a "terminal is watching" rule for deciding whether to
    mirror a stop fails for background jobs with redirected stdio in every
    implementation tried (§6.2); the design needs a test for it.
  - On macOS: avoiding double delivery of terminal signals (Rust) or keeping
    single delivery (Go).
  - Signal transparency beyond the five forwarded signals, including SIGKILL
    and orphaning.
  - Restoring the TUI after unhandled signals, including an external
    CTRL_C_EVENT on Windows.
  - `--meta-file` failure semantics.
  - Passing duplicate keys in the environment block through unchanged.
  - Bidi and zero-width display spoofing, and correct rendering of wide and
    combining characters.
  - Reads of environment-selected files.
  - Windows: the batch-target policy (Q-B) and refusing batch paths that
    `cmd.exe` would expand (§9.7); the executable resolution policy; a
    named-pipe server with a client-SID check and overlapped I/O; the client
    impersonation level; job objects; console Ctrl-C.
  - Clean-machine and signed-distribution tests on all three platforms.
  - The project license.
  - darwin Developer-ID signing and notarization.
- If Rust is chosen: a release build that fails when notices generation or
  any target fails; a pinned build environment for reproducible releases;
  cargo-deny, `cargo auditable` and an OSV/GHSA scanner in CI; a PIE strategy
  for static musl; a watch on crossterm and `security-framework`; a memory
  budget test for the profile parser on 1 MiB inputs.
- If Go is chosen: a fixed Bubble Tea/ultraviolet renderer (or a full repaint
  around wide text) with a wide-character test; raw wait-status decoding on
  darwin; a cgo-or-purego policy for the macOS Keychain; a DH session for
  Secret Service; batch-file escaping if Q-B requires batch targets; and, if
  Iroh ships, a second toolchain and artifact for the Rust helper.

## 12. Reopen conditions

Reopen this ADR if any of the following happens:
- The owner changes the Iroh scope (Q-A) after the decision.
- A native Windows run shows that the chosen stack cannot meet G03, or the
  X4 DPAPI/CNG/TPM runs show it cannot meet G04 on Windows.
- Iroh integration (G06) fails on the chosen stack where another stack would
  pass.
- The chosen stack's dependencies become unmaintained.
- A license changes.
- The owner overrules a D3 ruling in a way that changes a gate verdict.

## 13. Review of revision 3

Two adversarial reviews ran on the draft of this revision, each with one lens
(`tests/evidence/artifacts/review-adr-0002/review-3/`): evidence fidelity
(Codex GPT-6.1 Sol) and decision logic and fairness (Claude Fable 5.1). Both
returned "ready after fixes", with no blocker; both found every total and
sensitivity figure arithmetically correct. The decision-logic reviewer reached
the same recommendation, conditional on Iroh in V1, with low confidence.

| Finding (major) | Change made |
|---|---|
| The two uncertain hard gates were said to be closable after D1, which plan.md does not allow without the owner (fidelity 1) | §3.2, §7 and §9 now call the scores provisional until Q-D is answered |
| Rust's Windows bindings were called safe; they are typed but `unsafe`, and Go has typed DPAPI (fidelity 2) | §2.4, §7.1 and §9 distinguish safe macOS/Linux wrappers from typed `unsafe` Windows FFI |
| The batch-path finding was understated next to "correct escaping" (fidelity 3; logic M5) | The demonstrated injection is stated in §2.4, §3, §3.1 and §9; the escaping claim is limited to `argv[1..]`; §9.7 and D3 (k) now give the threat-model reason the argument and path cases differ, and what overruling it means |
| "Most Go cells" overstated X2 (fidelity 4) | 5 of 12 Go cells, concentrated in T1 and T3, two correlated causes |
| The release row was a midpoint while §7.3 assumed Iroh in V1 (fidelity 5; logic M1) | The row now states its Iroh-in-V1 judgment (Go's pipeline offsets its second toolchain) and gives the deferred case separately |
| PIE was compared across a static and a dynamic build (fidelity 6) | Stated as a static-versus-dynamic trade-off |
| Rust's macOS double delivery of terminal signals was in no scored row while Go's signal costs were (logic M2) | Both baselines' signal-model costs are in the security-core row; the darwin SIGSTOP misdecode moved there from cross-platform |
| The X2 rubric was presented as binary, and the calibration's timing was not disclosed (logic M3) | §6.2, §7.1, §7.3 and D3 (l) give all three readings with their counts and say the calibration was added after the planned X2 measures came out even |
| The re-scorers were not blind to the orchestrator's framing (logic M4) | §7.2 says what they saw; the confidence notes cite it; the recommendation's confidence is now low |

The minor findings (round-3 versus post-fix artifact labels, the Go license
count, a cross-reference, G03 statuses, the ecosystem-row disagreement, the
Codex model's provenance, Q-B's Rust side, reproducibility drift on both sides,
the notices false-green, the X3 granularity caveat, which X2 facts were re-run,
and the TUI-library and macOS-runner questions, now Q-E and Q-F) were all
applied.

**Round 2.** Each reviewer then checked the fixes (`review-3/fidelity-r2/`,
`review-3/logic-r2/`). The fidelity reviewer found all 10 of its findings
resolved and the arithmetic correct, and one new major: the §9.7 threat model
overstated what an attacker needs (running a different batch file needed only
an existing variable such as `%OS%` and a created directory). The logic
reviewer found 11 of 15 resolved and 4 partly, and two new majors: the
sensitivity anchors took the reading most favourable to Go without showing the
range, and D3 (l) overstated how blind the calibration was. All three, and the
round-2 minors (Go's 30 `unsafe` sites beside Rust's 20, two citations, the
§7.2 confidence label, the T1 avoidance wording, symmetric single-cause
sensitivity, a default path in §10), were applied. Both reviewers kept the
same recommendation: Rust + Ratatui, low confidence, conditional on Iroh in V1;
a tie within precision if Iroh is deferred.
