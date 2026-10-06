# M00-T05-r4-x6: outside evidence on agentic and open-source maintainability (Go vs Rust)

**Status:** `verified` for what this record claims: each number below was read from the cited
source or obtained by a command whose output is kept in `data/`. This is desk research. It runs no
Heimdall code and does not close any gate. **Feeds:** ADR-0002 §7, the row "agentic and open-source
maintainability (15 %)". **Date:** 2026-10-06, 05:46–06:10 UTC (started `date -u` 05:46:37Z;
registry and GitHub snapshots taken 05:54–06:01Z).

Labels used below. **Observed** means read in the source, or a command output kept here.
**Inference** means this record's reasoning; it is always marked. Sources are listed as `[S#]` in
the table at the end. No Heimdall prototype was built, run or edited. The `prototypes/` paths are
cited read-only at frozen commits Go `38b6b72` and Rust `d8f0cbe`.

## 0. Bottom line

1. **LLM benchmarks lean slightly towards Rust for issue resolution, but nothing is controlled.**
   - In the 2025–2026 repository-level benchmarks that report Go and Rust separately, Rust usually
     scores higher (§1). The clearest case is Claw-SWE-Bench: Rust beats Go for all 11 models, by
     17.1–31.1 pp [S5].
   - Every one of these comparisons uses different repositories and tasks for each language.
   - The largest Rust leads all come from one task set, SWE-bench Multilingual, and its Go share is
     only 42 tasks from 5 repos [S3, S5].
   - Evidence pointing the other way:
     - SWE-bench Pro finds Go among the languages with the *highest* resolve rates; Rust is not in
       it [S7].
     - A 2026 study of building a CLI from scratch finds Go the bottleneck language, failing mostly
       at the build step; Rust is not in it either [S8].
     - In ProMax, two of six models do better on Go than on Rust [S6].
   - **Inference:** this is weak evidence for Rust (perhaps +0.5 on a 1–5 scale at most). It does
     not settle the question. X2 (same tasks, both languages) is the in-repo experiment that can.
2. **Compiler guarantees.**
   - **Observed:**
     - Safe Rust rules out data races and (outside `unsafe`) memory-safety bugs [S14, S12].
     - Rust requires exhaustive `match` [S16].
     - Go relies on a dynamic race detector, which finds only races that actually run [S18], plus
       opt-in linters [S19, S20].
     - The Go memory model says a race on interfaces, slices, strings or maps "can in turn lead to
       arbitrary memory corruption" [S17].
   - **Observed (against Rust):**
     - In agent studies, Rust failures move to compile time. In RustRepoTrans, 92.3 % of failures
       are compile errors and 0 % are runtime errors [S9].
     - Agents average about three compile errors per task [S10]. These are mostly name, path,
       method and trait errors, not borrow-checker errors [S9, S10].
     - Compiled LLM Rust crypto code still had vulnerabilities in 57 % of samples [S11].
     - Concurrency studies find deadlocks and blocking bugs in *safe* Rust [S13]. In Go, message
       passing causes about 58 % of blocking bugs [S21].
     - The SSH CVEs that matter to Heimdall in both languages are logic, resource and panic bugs
       that neither compiler prevents (§4.3).
3. **Tooling.** Go has more first-party tooling and needs less setup. Rust's tooling is richer but
   relies more on third-party projects.
   - **Observed, Go:** native fuzzing since 1.18 [S22]; govulncheck reachability backed by a
     curated database [S24, S25]; perfectly reproducible toolchains since Go 1.21 [S27];
     a Go 1 compatibility promise [S29].
   - **Observed, Rust:** cargo-fuzz needs nightly plus a C++ compiler [S23]; cargo-audit checks
     the lockfile only and does no reachability analysis [S26]; path trimming is still unstable in
     Cargo [S28]; Clippy has about 830 lints [S30].
   - **Observed, important for an SSH product:**
     - RustSec, the database cargo-audit and cargo-deny read, lists **1** of the **20** GitHub
       advisories (GHSA) for `russh`.
     - Go's vulnerability database lists the 2026 `x/crypto/ssh(/agent)` advisories, some
       **before** GHSA did (§3.4, `data/osv_query.tsv`).
4. **Ecosystem for SSH and the agent protocol.**
   - **Go:** `golang.org/x/crypto/ssh/agent` is first-party, provides both client and server, and
     has 3,597 known importers [S31, S32].
   - **Rust:** the equivalents are community crates.
     - `ssh-agent-lib` has 15 contributors and 24 reverse dependencies, including `rbw` and
       `radicle-crypto`.
     - `ssh-key` (RustCrypto) and `russh` are active and widely used.
   - Both ecosystems got a burst of SSH advisories in 2026: 17 OSV records for `x/crypto` (Go
     database entries only) and 17 for `russh` (§4.3). The Go set includes **agent constraint
     enforcement bugs** that bear directly on Heimdall's design.
   - The contributor pools are similar: Stack Overflow 2025 usage is Go 16.4 % and Rust 14.8 %
     [S38].
5. **Signal, process and terminal pitfalls exist in both** (§5). The repo's own evidence has
   traced one Go darwin defect to the Go standard library. **Observed:** Go's BSD
   `WaitStatus.Stopped()` excludes SIGSTOP. Darwin's `WIFSTOPPED` excludes 0x13, which is SIGCONT
   (19); darwin's SIGSTOP is 17 [S34, S35]. The Rust standard library's SIGPIPE handling can only
   be changed with a nightly-only flag [S36]. Both TUI stacks needed workarounds for hangs or
   unsafe terminal behaviour [P3, P4].

## 1. LLM coding benchmarks with per-language results

Only the numbers read in each source are given. "pp" means percentage points.

| Benchmark (source, version) | Go tasks | Rust tasks | What was read | Notes / caveats |
|---|---|---|---|---|
| Aider polyglot [S1, S2] (leaderboard last updated 2025-11-20; benchmark post 2024-12-21) | 39 | 30 | Per-language results are **not published**. Top entry: gpt-5 (high), 88.0 % (2025-08-23) | Exercism exercises picked as those "solved by 3 or fewer" of 7 reference models. Cannot separate Go from Rust |
| SWE-bench Multilingual [S3] (page © 2026, undated) | 42 (caddy 14, terraform 5, prometheus 8, hugo 7, gin 8) | 43 (tokio 9, coreutils 5, nushell 5, axum 7, ripgrep 2, bat 8, ruff 7) | Claude 3.7 Sonnet + SWE-agent: **Go 30.95 %, Rust 58.14 %**, overall 42.67 %. "Rust having the highest resolution rate". "solutions to Rust tasks modify more lines of code on average" | One model and one agent. Different repos per language. caddy alone (14 of 42 Go tasks) resolved 14.3 % |
| Claw-SWE-Bench [S5] (arXiv 2606.12344v2, 2026-09-28), Table F.2 | the Multilingual Go set (42) | the Multilingual Rust set (43) | 11 models under OpenClaw. **Rust > Go for every model**, by 17.1–31.1 pp. Examples: GPT 5.5 Go 61.9 / Rust 93.0; Claude Opus 4.7 61.9 / 88.4; GLM 5.1 59.5 / 81.4; Seed 2.0-mini 33.3 / 55.8. "Go is the worst language for all 11 models without exception (range 33.3–64.3%)" | **Not independent of S3:** 350 tasks drawn from SWE-bench Multilingual plus SWE-bench-Verified-Mini (Python). The pattern holds across models on one fixed task set, so it may reflect that set (*inference*) |
| Multi-SWE-bench [S4] (arXiv 2504.02605v1, 2025-04-03), Table 4 | 428 (cli/cli 397, grpc-go 16, go-zero 15) | 239 (10 repos; clap 132, nushell 14, …) | 2025 models, 3 agent frameworks × 9 models: Rust > Go in **16 of 27** rows. Best scores: Rust 15.90 % and Go 7.48 % (both MopenHands + Claude-3.7-Sonnet). Python 52.20 % for the same configuration | 93 % of the Go tasks come from one repo (cli/cli). The authors blame low Go, Rust and C/C++ scores on benchmark difficulty, Python-biased methods, and "intricate type systems" |
| SWE-Bench ProMax [S6] (arXiv 2608.09802v1, 2026-08-10), Table 3, multi-file refactoring | 23 (16 repos) | 22 (5 repos) | OpenHands: Rust > Go for 4 of 6 models (Sonnet 4.6 Go 26.1 / Rust 63.6; GPT-5.2 26.1 / 54.5); Go > Rust for Kimi-K2.5 (43.5 / 18.2) and Qwen3.5 (39.1 / 22.7). mini-SWE-agent: Rust ≥ Go for 6 of 6. Authors: the variance "may reflect differences in language-specific training data rather than inherent language difficulty" | Very small samples: one Rust task is about 4.5 pp |
| SWE-bench Pro [S7] (arXiv 2509.16941v2, 2025-11-14) | yes (count not extracted) | **none** | "Go and Python generally show higher resolve rates across most models"; JS/TS vary more | Against "Go is hard for agents". Rust is "underrepresented" (authors' word) |
| 0-to-1 CLI-tool generation [S8] (arXiv 2604.06742v2, 2026-07-17) | 45 projects | **none** | "Golang emerges as a severe bottleneck"; models "often generat[e] code that fails to build". In example trajectories the build fails on `go.sum` / `go mod tidy`, and Claude Sonnet 4.6 often submitted without running `go build` | Python, JS and Go only. The per-language scores are in radar charts and were not transcribed. The failures shown are toolchain/dependency steps, not language semantics (*inference*) |
| MultiPL-E [S15] (arXiv 2208.08227v4) | HumanEval/MBPP translations | same | Key finding 5: "Static type-checking neither helps nor hinders code generation model performance." Codex pass@1 > 40 % on Rust (Go not in that list) | 2022-era models; single functions, not agentic. Weak relevance today |
| SWE-PolyBench [S39] (arXiv 2504.08703v3) | none | none | Java, JS, TS and Python only | Not usable for Go vs Rust |
| Multi-SWE-bench live leaderboard | — | — | Not used: the repository's `data.json` was last changed 2024-08-24 and holds no per-language data | — |

**Related Go-only and Rust-only evidence (observed):**
- Rust-SWE-bench [S10] (ICSE 2026, arXiv 2602.22764v1): 500 tasks from 34 repos.
  - The best ReAct-style baseline resolves 21.2 % (106 of 500, OpenHands + Claude-Sonnet-3.7). The
    authors' RustForger resolves 28.6 %.
  - The bottleneck is reproducing the issue. Of the failed reproductions, 52.5 % came from
    dependency or Cargo/workspace misconfiguration.
  - Of agent compile errors, 43.7 % come from repository structure (paths, imports) and 32.6 %
    from type and trait semantics.
- A translation study [S40] (arXiv 2605.02195v3): Go's rule against unused imports and variables
  causes "frequent build failures unique to Go's strict tooling" in LLM translations.

**What predicts agentic maintainability here (inference):**
- Results swing more with the model, the agent harness and the repository than with the
  language. ProMax shows the harness alone moving GPT-5.2 from 21.8 % to 41.2 %.
- The task sets differ per language, so a "language effect" cannot be separated from a
  "repository effect" in any source above.
- Rust's lead is real but rests mostly on one task set (SWE-bench Multilingual, re-used by
  Claw-SWE-Bench).
- The Go-negative results (CLI-from-scratch, MultiPL-E-era compile errors) mostly concern
  toolchain hygiene: `go.sum` entries and unused imports. For a project with an established
  module and CI, those failures are cheap and quickly caught (inference).

## 2. Compiler-enforced guarantees against agent and human mistakes

| Mistake class | Go | Rust | Evidence |
|---|---|---|---|
| Data races | Allowed by the compiler. Caught dynamically by `-race`, which "only finds races that happen at runtime" and costs 5–10× memory and 2–20× time [S18]. The Go memory model: a race on interfaces, maps, slices or strings "can in turn lead to arbitrary memory corruption" [S17]. At Uber, 46 M lines of Go: "found over 2000 data races, and fixed over 1000" in six months [S19] | "Safe Rust guarantees an absence of data races" [S14]. Not guaranteed inside `unsafe` | Observed |
| Other concurrency bugs | "around 58% of blocking bugs are caused by message passing". The built-in deadlock detector caught 2 blocking bugs. The race detector caught 7 of 13 traditional and 3 of 4 anonymous-function non-blocking bugs [S21] | "all blocking bugs we studied are in safe code"; "non-blocking bugs can happen in both unsafe and safe code" [S13]. "Rust does not prevent general race conditions … deadlocked" [S14] | Observed. Neither language prevents deadlocks |
| Memory safety | Memory-safe apart from data races (above) and `unsafe` | Of 186 memory-safety bug reports (all Rust CVEs up to 2020-12-31), "all memory-safety bugs … except compiler bugs require unsafe code" [S12]. Android: Rust about 0.2 memory-safety vulns per MLOC against about 1,000 for C/C++; Rust changes have about 4× lower rollback rate, about 25 % less review time and about 20 % fewer revisions **than C++** [S33] | Observed. S33 compares with C++, **not Go** |
| Unhandled cases | `switch` need not be exhaustive. The opt-in `exhaustive` linter covers `iota` "enums" [S20]; golangci-lint offers it and `errcheck` [S20b]. `go vet` has no unchecked-error or exhaustiveness analyzer [S41] | Non-exhaustive `match` is error E0004 [S16]. Ignoring a `Result` gives a `must_use` warning (*not re-verified in this task*) | Observed, except as marked |
| Linting depth | `go vet` (30+ analyzers, "heuristics that do not guarantee all reports are genuine problems") [S41]; staticcheck; golangci-lint (about 130 linters, page updated 2026-10-04) [S20b] | Clippy stable page: 847 entries, 17 deprecated, so about 830 active; 67 in `correctness` (deny by default) [S30] | Observed (Clippy counted from the page HTML) |
| What agents actually trip on | Build hygiene: unused imports and variables [S40]; `go.sum` / `go mod tidy` [S8] | Name, path and method resolution (E0599, E0433, E0432, E0425) and trait bounds (E0277). **No borrow-checker error code** appears in the top-10 [S9] or top-13 [S10] lists | Observed. Inference: the borrow checker is not the main source of agent friction in these studies; the type and trait system is |
| Failure shifted left | — | RustRepoTrans: of failed translations, compile errors 92.3 %, runtime 0 %, functional 7.7 %, against 58.3–83.3 % compile errors for other target languages [S9] | Observed. Different benchmarks per language (cross-study) |
| Crypto/logic misuse | not studied in this pass | Only 23.3 % of LLM-generated Rust AES-GCM / ChaCha20-Poly1305 samples compiled. Of those, 57 % had crypto vulnerabilities by a rule-based analyzer [S11] | Observed. Single-shot, no compiler loop, older models |
| Runtime panics as DoS | nil dereference and index panics (e.g. CVE-2020-29652, CVE-2021-43565 in x/crypto/ssh) | many 2026 `russh` advisories are pre-auth panics or out-of-bounds slicing [S37] | Observed (`data/ghsa_advisories.tsv`) |

**Inference.**
- For Heimdall's riskiest code (agent protocol parsing, key-constraint enforcement, process
  supervision), the compiler-checkable classes favour Rust: data races, unhandled enum cases, and
  memory safety under concurrency.
- The bug classes actually found in 2026 SSH libraries in *both* languages are not
  compiler-checkable: unenforced constraints, unbounded allocation, panics and deadlocks (§4.3).
- So the guarantee advantage is real but bounded. It does not replace fuzzing, limits on
  allocation and recursion, and protocol conformance tests.

## 3. Test, fuzz, lint, format and release tooling

| Area | Go | Rust | Source |
|---|---|---|---|
| Formatting | `gofmt` (in the toolchain) | `rustfmt` (rustup component) | general knowledge; not re-fetched |
| Fuzzing | Native since Go 1.18 (`go test -fuzz`). Coverage-guided on AMD64 and ARM64; "exactly one fuzz target per fuzz test"; argument types limited to primitives, `string` and `[]byte`; supported by OSS-Fuzz | cargo-fuzz "requires the nightly compiler" (`-Z` sanitizer flags) and "a C++ compiler with C++11 support". libFuzzer on x86-64 Linux, x86-64 and aarch64 macOS, and Windows (MSVC ASan) | [S22], [S23] |
| Vulnerability scanning | govulncheck: symbol-level reachability, so it "only surfaces vulnerabilities that actually affect you". Binary mode exists but drops call stacks and may give false positives. Database: curated Go vulndb in OSV format | cargo-audit checks `Cargo.lock` against RustSec; no reachability (points to the experimental `reachsec`). `cargo audit bin` is "fully accurate" only for binaries built with `cargo auditable` | [S24, S25], [S26] |
| Database coverage (snapshot 2026-10-06) | OSV query for `golang.org/x/crypto`: 32 GO-* records plus 26 GHSA. The Go database published the 2026 ssh/agent CVEs on 2026-05-22; GHSA on 2026-06-25. It also has three newer `x/crypto/ssh` entries (2026-08-28 and 2026-09-02) | OSV query for `russh`: 20 GHSA records and **1 RUSTSEC** (RUSTSEC-2026-0154). `rustsec/advisory-db/crates/russh/` holds only that file | `data/osv_query.tsv`, `data/ghsa_advisories.tsv`; [S37] |
| Reproducible builds | "Go 1.21.0 is the first Go toolchain with perfectly reproducible builds" (toolchain; cgo programs depend on the host C toolchain). The prototype builds with `CGO_ENABLED=0 -trimpath -buildvcs=false` | Cargo `trim-paths` is still an **unstable** feature; the prototype uses manual `--remap-path-prefix` for five path roots | [S27]; [P1], [P2]; [S28] |
| Compatibility promise | Go 1 compatibility promise, with exceptions for security, unspecified behaviour, bugs and `unsafe` | "Stability without stagnation"; editions are opt-in per crate and must interoperate | [S29], [S42] |
| Toolchain cadence | Go 1.27.1 (pkg.go.dev, 2026-09-01) | Rust 1.99.0 (2026-09-28) | [S36b], [S41] |
| Release tooling | goreleaser: 504 contributors, 1,040 commits in the last 52 weeks, v2.18.2 on 2026-09-17 | cargo-dist: 84 contributors, 233 commits in 52 weeks, v0.33.0 on 2026-09-11 (still 0.x). cargo-auditable 0.7.7 (2026-10-02), cargo-vet 0.10.2 | `data/gh_meta.tsv`, `data/registry_meta.tsv` |
| Lint runners | golangci-lint v2.14.0 (2026-09-24, 399 contributors); staticcheck 2026.2.1 (2026-08-21, 80 contributors) | Clippy ships with rustup (1,503 contributors); cargo-deny 0.20.2 (2026-07-09) | `data/gh_meta.tsv` |

**Inference.**
- The release-simplicity differences ADR-0002 already records still hold: Go cross-compiles with
  its own toolchain, Rust uses zigbuild.
- The new, consequential finding is the RustSec gap for `russh`. An agent-maintained Rust SSH
  product that relies on `cargo audit` / `cargo deny` alone would have missed 19 of 20 known
  `russh` advisories at this snapshot.
- Mitigation: also query OSV/GHSA (for example osv-scanner). This is a process fix, not a reason
  to rule Rust out. X3 should confirm it by running the tools.

## 4. Open-source ecosystem and contributor pools

### 4.1 Contributor pools (observed)

| Signal | Go | Rust |
|---|---|---|
| Stack Overflow 2025 usage, all respondents / professional developers [S38] | 16.4 % / 17.4 % | 14.8 % / 14.5 % |
| Language repos: contributors (GitHub API, anon included) / commits in last 52 weeks | golang/go 3,005 / 3,442 (GitHub mirror of Gerrit) | rust-lang/rust 8,863 / 33,188 (*inference:* probably includes merge-bot commits, so not comparable 1:1) |

The 2026 Stack Overflow survey page returned 404 at fetch time, so 2025 is the latest read.

### 4.2 Security tools and libraries (GitHub snapshot 2026-10-06 05:54Z, `data/gh_meta.tsv`)

| Language | Project | Stars | Contributors | Commits 52 w | Latest release | Status |
|---|---|---|---|---|---|---|
| Go | golang/crypto (x/crypto) | 3,350 | 313 | 126 | v0.57.0 (proxy, 2026-09-08) | active, first-party |
| Go | FiloSottile/age | 23,822 | 62 | 108 | v1.3.2 (2026-08-29) | active |
| Go | sigstore/cosign | 6,347 | 275 | 335 | v3.1.3 (2026-08-06) | active |
| Go | tailscale/tailscale | 37,177 | 409 | 1,710 | v1.102.5 (2026-09-29) | active |
| Go | gravitational/teleport | 20,965 | 375 | 3,747 | v18.10.0 (2026-07-09) | active, AGPL-3.0 |
| Go | charmbracelet/bubbletea | 45,289 | 167 | 213 | v2.0.10 (2026-09-24) | active |
| Rust | str4d/rage | 3,675 | 39 | 102 | v0.12.1 (2026-07-14) | active |
| Rust | rustls/rustls | 7,656 | 223 | 1,225 | 0.23.45 (2026-09-14) | active |
| Rust | sequoia-pgp (crates.io `sequoia-openpgp`) | n/a (GitLab) | — | — | 2.4.1 (2026-07-09) | active (registry only) |
| Rust | sigstore/sigstore-rs | 243 | 40 | 169 | v0.14.0 (2026-05-22) | active, smaller than cosign |
| Rust | warp-tech/warpgate (SSH bastion) | 8,013 | 77 | 907 | v0.29.1 (2026-09-23) | active |
| Rust | ratatui/ratatui | 22,872 | 308 | 432 | 0.30.2 (2026-06-19) | active |
| Rust | crossterm-rs/crossterm | 4,238 | 200 | 31 | crates.io 0.29.0 (2025-04-05) | **slow**: no release in 18 months; the prototype hit a hangup bug [P4] |
| Rust | n0-computer/iroh | 12,654 | 68 | 605 | v1.3.0 (2026-09-28) | active, Rust-native (ADR-0002 §8) |

### 4.3 SSH and SSH-agent protocol libraries

| Language | Library | Scope | Maintenance (observed) | Advisories (observed) |
|---|---|---|---|---|
| Go | `golang.org/x/crypto/ssh` and `/ssh/agent` [S31, S32] | Full SSH client and server. The agent package "provides both a client and a server" (`NewClient`, `ServeAgent`, `NewKeyring`, constraint extensions) | First-party (Go team), v0.57.0 2026-09-08; agent package "Known importers: 3,597" | Go vulndb: 21 records for `x/crypto/ssh`, 5 for `/ssh/agent`. 2026 includes: `NewKeyring()` "silently accepted keys with the ConfirmBeforeUse constraint but never enforced it" (CVE-2026-39833); destination-restriction constraints "silently stripped when forwarding keys" (CVE-2026-39832); FIDO presence bypass; `@revoked` not enforced; source-address not enforced (GO-2026-6303) |
| Go | gliderlabs/ssh | server wrapper over x/crypto | **stale:** last commit 2025-01-27, 0 commits in 52 weeks, v0.3.8 | none in GHSA |
| Go | charmbracelet/wish | SSH apps on x/crypto | active, v2.0.5 2026-10-01 | — |
| Go | Foxboron/ssh-tpm-agent | TPM-backed ssh-agent | active, v0.9.0, 38 commits in 52 weeks | — |
| Go | FiloSottile/yubikey-agent | YubiKey ssh-agent | **stale:** last commit 2022-12-31 | — |
| Rust | `russh` (warp-tech/russh) | SSH client and server, plus an agent client and server | active: 0.64.1 on 2026-10-05; 126 contributors; 217 commits in 52 weeks; 236 crates.io reverse deps. `russh-keys` has had no release since 0.49.2 (2025-01-08); *inference:* folded into `russh` | 20 GHSA records, 17 of them in 2026: many pre-auth panics and allocation DoS; channel callbacks reachable without an open channel; auth-attempt cap not enforced. RustSec has 1 |
| Rust | `ssh-key` / `ssh-encoding` (RustCrypto/SSH) | key formats, sshsig | active: 124 commits in 52 weeks; 190 reverse deps; latest 0.6.7 (2026-06-29) | none in GHSA |
| Rust | `ssh-agent-lib` (wiktor-k) | types for custom agents and clients; Unix sockets and **Windows named pipes** | small: 36 stars, 15 contributors, 42 commits in 52 weeks, 0.6.0 (2026-05-21). Forked because the upstream "seems not be maintained". 24 reverse deps, including `rbw` and `radicle-crypto` | none in GHSA |
| Rust | `ssh-agent-client-rs` | client only | 1.1.3 (2026-06-06), 12 reverse deps | — |
| Rust | `openssh` (openssh-rust) | drives the system `ssh` binary | 0.11.6 (2025-12-03), 6 commits in 52 weeks | — |
| Rust | `ssh2` | libssh2 C bindings | 0.9.6 (2026-06-30) | — |
| Rust | `thrussh` | original pure-Rust SSH (Pijul) | 0.49.0 published 2026-08-28, but only about 7.4k downloads in 90 days, against 3.2 M for `russh` | — |

**Inference.**
- Go's SSH-agent story is a single first-party package with a very large user base, plus
  `go-winio` for Windows pipes (active, but its last release is v0.6.2 from 2024-04).
- Rust's equivalent is a set of smaller community crates. `ssh-agent-lib` is the closest match to
  Heimdall's needs and also covers Windows named pipes, but it has a small bus factor.
- In both languages, Heimdall would have to own its constraint-enforcement logic and test it
  itself. The 2026 x/crypto CVEs show that a first-party library can silently not enforce agent
  constraints.

## 5. Pitfalls for signal, process and terminal code

| Pitfall | Go | Rust | Repo evidence |
|---|---|---|---|
| Stop/continue decoding | **Observed in Go source** (master `77fb1abefe3a`, file last changed 2023-11-07): `syscall_bsd.go` `Stopped()` returns `w&mask == stopped && Signal(w>>shift) != SIGSTOP`, and `Continued()` is `… == SIGSTOP`. XNU `wait.h`: `WIFSTOPPED` excludes `WSTOPSIG == 0x13`, and darwin SIGSTOP is 17, SIGCONT is 19. So on darwin a SIGSTOP stop is misread as "continued". The Go prototype calls `ws.Stopped()` after `syscall.Wait4(…, WUNTRACED)` and leaves its wait loop when that returns false (`internal/run/run_unix.go` 242–261, read-only). **Inference (from reading the code; not re-run here):** this is the root cause of the Go prototype's darwin SIGSTOP exit-255 failures. A `gh search issues` on golang/go (three queries) returned no matching issue | The Rust prototype uses `rustix::process::waitid(…, STOPPED \| NOHANG)` and `stopping_signal()` (`src/runner.rs` 184–193), which is siginfo-based, so no status-bit decoding is involved | ADR-0002 §6 and §6.1 probe 4; [P5] |
| Disposition and mask at startup | Programs started with SIGHUP or SIGINT ignored keep them ignored unless `Notify` is called. Some signals are always unblocked. Children inherit the modified mask [S43]. The prototype found the runtime resets SIGQUIT, SIGTERM, SIGWINCH and SIGPIPE in children | std sets SIGPIPE to `SIG_IGN` before `main` and to `SIG_DFL` in spawned children. The only control is `-Zon-broken-pipe`, which is **unstable/nightly** (tracking issue #97889 still open) [S36] | ADR-0002 §5 |
| Runtime signals | Since Go 1.14, async preemption sends extra signals, so "more slow system calls fail with EINTR" for `syscall` / `x/sys/unix` users [S44] | No runtime-injected signals (std) | — |
| Code between fork and exec | Not available: no `pre_exec` hook; remedies are a cgo constructor or a re-exec (ADR-0002 §5) | `CommandExt::pre_exec` is `unsafe`; "only async-signal-safe operations are guaranteed to work"; other threads may be running [S45] | ADR-0002 §5 |
| Environment handling | `os/exec`: "If Env contains duplicate environment keys, only the last value … is used" [S46] | passes duplicates through (prototype) | ADR-0002 §6 (Go dedup deviation) |
| Signal origin | `os/signal` does not expose `siginfo` | the prototype uses `siginfo` on Linux (not helpful on darwin) | ADR-0002 §5 |
| TUI stack hazards | Bubble Tea stack: environment-selected terminfo reads caused unbounded memory (776–858 MiB), FIFO hangs and a panic. Fixed by avoiding terminfo entirely [P3] | crossterm 0.29: spins at 100 % CPU on terminal hangup; `terminal::size()` runs `tput` from PATH when the ioctl fails; Ratatui `clear()` sends a cursor query and waits 2 s. Fixed with a hand-written Unix key decoder and size handling [P4] | prototype REPORT.md files |
| Panics | Bubble Tea goroutine panic may exit 2 (*inferred*, ADR-0002 §5) | `catch_unwind` with `panic = "unwind"` | ADR-0002 §5 |
| `unsafe` surface | Prototype: no `unsafe` import in non-test Go code (grep) | Prototype: `#![forbid(unsafe_code)]` in `main.rs`, `#![deny(unsafe_code)]` in `lib.rs`, one `#[allow(unsafe_code)]` query-only `sigaction` in `sigdisp.rs` (grep) | [P6] |

**Inference.**
- Each language has a standard-library behaviour Heimdall must work around:
  - Go: BSD `WaitStatus` decoding, runtime disposition resets, no `pre_exec`.
  - Rust: SIGPIPE reset that is fixed only on nightly, and an `unsafe` `pre_exec`.
- Go's darwin bug is a misdecoding that a raw-status decoder can avoid. Rust's SIGPIPE issue
  limits faithful exec-equivalence.
- Neither is decisive, but the evidence that Go's defect is in std (not in the prototype) is new
  and should be in ADR-0002 §6.

## 6. Evidence that cuts against each language

**Against Rust:**
- Agents and LLMs produce many compile errors. Translation failures are 92.3 % compile errors
  [S9], and agents average about 3 per task [S10]. The cost is iteration time and tokens (X2
  measures this).
- 2025 Multi-SWE-bench rows: Go ≥ Rust in 11 of 27.
- In ProMax, Kimi-K2.5 and Qwen3.5 do better on Go [S6].
- Compiled LLM crypto code was still vulnerable in 57 % of samples [S11].
- Deadlocks are common in safe Rust [S13].
- cargo-fuzz needs nightly [S23]; `trim-paths` is unstable [S28]; SIGPIPE control is
  nightly-only [S36].
- RustSec lags GHSA for `russh` [S37].
- The SSH-agent crates are community-maintained with small teams.
- crossterm releases have stalled (18 months).

**Against Go:**
- On the shared Multilingual task set, Go is the worst language for all 11 models [S5]. It is
  also a 0-to-1 CLI bottleneck [S8].
- Races are possible and can corrupt memory [S17]. Over 2,000 races were found at Uber [S19],
  and the detector is dynamic [S18].
- No exhaustive enums unless a linter is opted into.
- The Go stdlib mis-decodes SIGSTOP on darwin [S34].
- Async-preemption EINTR [S44].
- No fork-to-exec hook.
- 13 x/crypto advisories in one 2026 batch, including agent constraint enforcement (CVE-2026-39832
  and -39833).
- gliderlabs/ssh and yubikey-agent are stale.

## 7. Suggested input to ADR-0002 §7, 15 % row (inference; for the orchestrator and owner)

- **Benchmarks:** slight Rust lean, low confidence. Confounded by repository choice, and the
  strongest data re-uses a single task set.
- **Guarantees:** Rust is stronger on the classes a compiler can check. That matters for an
  agent-maintained security core: fewer silent races, and exhaustive state machines. It does not
  cover the observed SSH bug classes.
- **Tooling and supply chain:** Go is stronger out of the box. It has a first-party fuzzer,
  reachability scanning, a curated database with better coverage of the SSH libraries in this
  snapshot, and a reproducible toolchain.
- **Ecosystem:** Go is stronger for SSH and the agent protocol, with a first-party library and
  large adoption. Rust is stronger for Iroh. Contributor pools are similar.
- A defensible reading is a **tie or at most ±1 point either way**. The direction should come from
  X2's controlled results, not from this desk research.

## 8. Limitations

- Benchmarks are not controlled. No source holds tasks equal across Go and Rust. Sample sizes per
  language are 22–43 in the recent benchmarks.
- Model versions in the papers (Claude 3.7, Sonnet 4.6, Opus 4.7, GPT-5.x) differ from the ones X2
  uses (Opus 5.5, Sonnet 5.5).
- Some numbers came through an LLM-based fetch tool rather than direct text extraction. These
  are: S1–S3, S7 (abstract), S14, S16–S18, S22–S26, S27–S29, S31–S33, S36, S38, S39, S41–S46.
- PDFs S4–S6, S8–S13, S15, S19, S21 and S40 were downloaded and read with `pdftotext`. Their
  sha256 digests are in `data/source-digests.txt`. The PDFs themselves are not kept (size,
  licence).
- GitHub counts are a snapshot.
  - Contributor counts come from the `Link` header with `anon=1` and are approximate.
  - Commits in 52 weeks come from `stats/participation` and cover the default branch only.
  - GitHub releases are not authoritative for crates or Go modules (for example golang/vuln shows
    v1.1.4 while the proxy shows v1.8.0), so the registry rows in `data/registry_meta.tsv` take
    precedence.
- The RustSec-gap finding is a database comparison only. `cargo audit` was not run here (X3's
  scope).
- The Go `WaitStatus` root cause is inferred from the source code. It was not re-run in this task.
- The Rust `must_use` claim on `Result` and the gofmt/rustfmt row were not re-fetched.
- No independent review of this record has happened yet.

## 9. Commands run (all exit 0 unless noted)

- `curl -sSfL https://arxiv.org/pdf/<id>` and `pdftotext -layout`, for each PDF in
  `data/source-digests.txt`.
- `sh scripts/repo_meta.sh …` → `data/gh_meta.tsv`.
- `sh scripts/registry_meta.sh` → `data/registry_meta.tsv`.
- `sh scripts/advisories.sh …` → `data/ghsa_advisories.tsv`.
- OSV `POST /v1/query` for `crates.io/russh` and `Go/golang.org/x/crypto` →
  `data/osv_query.tsv`.
- crates.io `reverse_dependencies` → `data/crates_reverse_deps.tsv`.
- `gh api` raw fetches of `golang/go:src/syscall/syscall_bsd.go`, `syscall_linux.go` and
  `apple-oss-distributions/xnu:bsd/sys/wait.h`, plus local `grep` of the macOS SDK
  `sys/signal.h`.
- `grep` of `prototypes/` (read-only).
- Failures along the way:
  - A first advisory loop hung, because zsh did not word-split `set -- $spec`. Its background task
    was stopped by its own task ID and the loop rerun as `scripts/advisories.sh`.
  - `rust-clippy/stable/lints.json` returned 404 (curl exit 56). The lints were counted from the
    stable `index.html` instead.

## Sources

Accessed 2026-10-06 unless stated otherwise.

| ID | Source | URL | Version / date |
|---|---|---|---|
| S1 | Aider LLM leaderboards | https://aider.chat/docs/leaderboards/ | last updated 2025-11-20 |
| S2 | Aider polyglot benchmark post | https://aider.chat/2024/12/21/polyglot.html | 2024-12-21 |
| S3 | SWE-bench Multilingual | https://www.swebench.com/multilingual.html | page © 2026 (undated) |
| S4 | Multi-SWE-bench (Zan et al.) | https://arxiv.org/abs/2504.02605 | v1, 2025-04-03 |
| S5 | Claw-SWE-Bench | https://arxiv.org/abs/2606.12344 | v2, 2026-09-28 |
| S6 | SWE-Bench ProMax | https://arxiv.org/abs/2608.09802 | v1, 2026-08-10 |
| S7 | SWE-Bench Pro (Deng et al.) | https://arxiv.org/abs/2509.16941 | v2, 2025-11-14 |
| S8 | 0-to-1 CLI tool generation | https://arxiv.org/abs/2604.06742 | v2, 2026-07-17 |
| S9 | RustRepoTrans (Ou et al.) | https://arxiv.org/abs/2411.13990 | v6, 2025-10-17 |
| S10 | Rust-SWE-bench / RustForger (Xiang et al., ICSE 2026) | https://arxiv.org/abs/2602.22764 | v1, 2026-02-26 |
| S11 | Security of LLM-generated crypto Rust | https://arxiv.org/abs/2604.27001 | v1, 2026-04-29 |
| S12 | Memory-Safety Challenge Considered Solved? (Xu et al.) | https://arxiv.org/abs/2003.03296 | v6, 2021-02-25 |
| S13 | Memory and thread safety in real-world Rust (Qin et al., PLDI 2020) | https://songlh.github.io/paper/rust-study.pdf | PLDI 2020 |
| S14 | Rustonomicon, Data Races and Race Conditions | https://doc.rust-lang.org/nomicon/races.html | current |
| S15 | MultiPL-E (Cassano et al.) | https://arxiv.org/abs/2208.08227 | v4 |
| S16 | Rust error E0004 | https://doc.rust-lang.org/error_codes/E0004.html | current |
| S17 | The Go Memory Model | https://go.dev/ref/mem | version of 2022-06-06 |
| S18 | Go Data Race Detector | https://go.dev/doc/articles/race_detector | current |
| S19 | A Study of Real-World Data Races in Golang (Chabbi, Uber; PLDI 2022) | https://arxiv.org/abs/2204.00764 | v2, 2022-04-05 |
| S20 | nishanths/exhaustive | https://github.com/nishanths/exhaustive | current |
| S20b | golangci-lint linters | https://golangci-lint.run/docs/linters/ | updated 2026-10-04 |
| S21 | Understanding Real-World Concurrency Bugs in Go (Tu et al., ASPLOS 2019) | https://songlh.github.io/paper/go-study.pdf | ASPLOS 2019 |
| S22 | Go Fuzzing | https://go.dev/doc/security/fuzz/ | current |
| S23 | Rust Fuzz Book, cargo-fuzz setup | https://rust-fuzz.github.io/book/cargo-fuzz/setup.html | current |
| S24 | Go vulnerability management | https://go.dev/doc/security/vuln/ | current |
| S25 | govulncheck command docs | https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck | x/vuln v1.8.0 (2026-09-08) |
| S26 | cargo-audit README | https://github.com/rustsec/rustsec/tree/main/cargo-audit | main, 2026-10 |
| S27 | Perfectly Reproducible, Verified Go Toolchains (Cox) | https://go.dev/blog/rebuild | 2023-08-28 |
| S28 | Cargo unstable features (`trim-paths`) | https://doc.rust-lang.org/cargo/reference/unstable.html | current stable docs |
| S29 | Go 1 and the Future of Go Programs | https://go.dev/doc/go1compat | current |
| S30 | Clippy lint list (stable) | https://rust-lang.github.io/rust-clippy/stable/index.html | fetched 2026-10-06 |
| S31 | x/crypto/ssh/agent package | https://pkg.go.dev/golang.org/x/crypto/ssh/agent | v0.57.0 (2026-09-08) |
| S32 | x/crypto/ssh/agent importers | https://pkg.go.dev/golang.org/x/crypto/ssh/agent?tab=importedby | 2026-10-06 |
| S33 | Rust in Android: move fast and fix things (Vander Stoep) | https://blog.google/security/rust-in-android-move-fast-fix-things/ | 2025-11-13 |
| S34 | Go `src/syscall/syscall_bsd.go` | https://github.com/golang/go/blob/77fb1abefe3a/src/syscall/syscall_bsd.go | master 77fb1abefe3a (2026-10-06) |
| S35 | XNU `bsd/sys/wait.h` | https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/wait.h | main f6217f891ac0 (2025-10-16) |
| S36 | `-Zon-broken-pipe` (unstable book) and tracking issue #97889 | https://doc.rust-lang.org/nightly/unstable-book/compiler-flags/on-broken-pipe.html ; https://github.com/rust-lang/rust/issues/97889 | nightly docs; issue open |
| S36b | `std::os::unix::process::CommandExt` docs | https://doc.rust-lang.org/std/os/unix/process/trait.CommandExt.html | Rust 1.99.0 (2026-09-28) |
| S37 | GitHub Advisory DB API, OSV API, rustsec/advisory-db | https://api.github.com/advisories ; https://api.osv.dev/v1/query ; https://github.com/rustsec/advisory-db | snapshot 2026-10-06 06:01Z (`data/`) |
| S38 | Stack Overflow Developer Survey 2025, Technology | https://survey.stackoverflow.co/2025/technology | 2025 survey |
| S39 | SWE-PolyBench | https://arxiv.org/abs/2504.08703 | v3, 2025-04-23 |
| S40 | Beyond Translation Accuracy (Rabbi et al.) | https://arxiv.org/abs/2605.02195 | v3, 2026-05-08 |
| S41 | `cmd/vet` docs | https://pkg.go.dev/cmd/vet | go1.27.1 (2026-09-01) |
| S42 | Rust Edition Guide | https://doc.rust-lang.org/edition-guide/editions/index.html | current |
| S43 | `os/signal` docs | https://pkg.go.dev/os/signal | go1.27.1 |
| S44 | Go 1.14 release notes | https://go.dev/doc/go1.14 | 2020-02 |
| S45 | (= S36b) `pre_exec` safety notes | as S36b | Rust 1.99.0 |
| S46 | `os/exec` docs (`Cmd.Env`) | https://pkg.go.dev/os/exec | go1.27.1 |
| S47 | GitHub REST API repo metadata; crates.io API; proxy.golang.org | api.github.com, crates.io/api/v1, proxy.golang.org | snapshot 2026-10-06 05:54–05:55Z (`data/gh_meta.tsv`, `data/registry_meta.tsv`) |
| P1 | `prototypes/go/build.sh` lines 39–40 | repo, frozen 38b6b72 | — |
| P2 | `prototypes/rust/build.sh` lines 19, 48 | repo, frozen d8f0cbe | — |
| P3 | `prototypes/go/REPORT.md` line 343 (terminfo hazards) | repo | — |
| P4 | `prototypes/rust/REPORT.md` lines 56–57, 89, 210 (crossterm and Ratatui hazards) | repo | — |
| P5 | `docs/decisions/0002-language-tui-distribution.md` §5, §6, §6.1; `tests/evidence/artifacts/g02-parity-r3c/RESULTS.md` | repo | — |
| P6 | `prototypes/rust/src/{main,lib,sigdisp}.rs` unsafe attributes; Go grep (no `unsafe` import) | repo | — |
