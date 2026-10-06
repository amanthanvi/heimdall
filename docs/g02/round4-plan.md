# G02 round 4: decision experiments (Go vs Rust)

**Status:** in_progress. **Date:** 2026-10-06.
**Why:** the owner deferred D1 and asked for more research and experiments.
Round 3c left Go and Rust tied (ADR-0002 §7). The owner then ruled that
personal ergonomics do not count: the project will be developed and
maintained mostly by agents, published as open source, and judged on what is
best for the product, namely maintainability, security and performance. The
owner also wants Windows/WSL tested before deciding (D4).

TypeScript is not re-tested: it fails two hard gates, and the owner let those
rulings stand. The prototypes stay frozen at Go `38b6b72` and Rust `d8f0cbe`.
Experiments work on copies.

## Experiments

| ID | Question | Method | Feeds (ADR-0002 §7) |
|---|---|---|---|
| X1 | Do the artifacts work natively on Windows 11 x64 and linux-x64? Do the Windows code paths (named pipe, quoting, console Ctrl-C, TUI) hold up? | Native runs on the owner's Windows 11 PC and its WSL2 Ubuntu (G03 host), using fixture agents only. Runs after the owner installs the dedicated test key | hard gates (Windows/WSL, distribution); cross-platform 25 % |
| X2 | Which codebase do agents change more reliably? | The same four tasks are given to fresh agents in each language, three runs per cell (two Opus 5.5, one Sonnet 5.5). Each task has a language-neutral spec and black-box acceptance tests the implementers never see. The tasks are T1 exec-equivalent job control (the §6.1 parity failures), T2 a new CLI subcommand, T3 a TUI feature, T4 diagnosing and fixing a seeded bug from a user-style report. Outcomes: hidden-test pass rate, full-harness regressions on darwin and Linux, defects found by an independent reviewer, plus tokens, tool calls and duration taken from the transcripts | agentic and open-source maintainability 15 % (replaces ergonomics); security core 25 % |
| X3 | How does the supply-chain and security tooling compare? | Count direct and transitive dependencies, unsafe/cgo surface, vulnerability scanners (govulncheck vs cargo-audit/cargo-deny), SBOM generation, reproducibility, fuzzing support and release tooling, all run on the final prototypes | security core 25 %; release simplicity 20 % |
| X4 | What native platform integration does the product need, and at what cost per language? | Minimal spikes in each language: macOS Keychain and Secure Enclave plus signed-bundle feasibility (G04 D3); Linux Secret Service/keyring in a container; Windows DPAPI/CNG and a named-pipe server with a client-SID check (compile-only until X1). Record whether cgo/unsafe/FFI is needed and what that does to the build | cross-platform 25 %; security core 25 % |
| X5 | Is a single toolchain realistic once Iroh is added? | Embed iroh in Rust and cross-compile it (ring under zig for linux-musl and windows-gnu). Build a Go supervisor talking to a minimal Rust helper. Measure size, build steps, and a loopback-only exchange with relays disabled | integration ecosystem 5 %; cross-platform; release simplicity |
| X6 | What does outside evidence say about agentic and open-source maintainability? | Research with primary sources: LLM coding benchmarks broken down by language, compiler-enforced guarantees that catch agent mistakes, test, fuzz and release tooling, and the open-source security-tool ecosystem | agentic and open-source maintainability 15 % |

## Fairness rules

- **Same inputs.** Both languages get identical prompts, models, effort and
  task specs. Implementers never see the hidden tests or the other
  language's results.
- **Independent checks.** Every task pack is reviewed for language
  neutrality before use. Every result is judged by an evaluator running the
  hidden tests and a reviewer who did not implement it.
- **Noisy metrics are labelled.** Wall time is affected by contention, so it
  is reported but not scored. Tokens and tool calls are taken from the
  transcripts.
- **Negative results are reported** as fully as positive ones.

## Outputs

- `tests/evidence/artifacts/g02-r4/` holds the raw results, and
  `tests/evidence/artifacts/m00-wf7/` holds the workflow results.
- ADR-0002 §7 is re-scored, with the 15 % row redefined as agentic and
  open-source maintainability.
- The re-scored ADR gets an independent review, and then goes to the owner.
  The decision is still made only after X1 (D4).
