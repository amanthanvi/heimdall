# Orchestrator's preliminary §7 scores (pre-registered 2026-10-09 23:35 EDT, before any blind scorer ran)

Inputs read: X1 + §9.6 baseline, X1b commits, X3, X4 (macOS/Linux/Windows), X5, X6, X2 interim (23/24 cells).

| Criterion (weight) | Go | Rust | Main reason |
|---|---|---|---|
| Cross-platform integration (25) | 3 | 4 | Go's "own toolchain only" advantage does not survive the product's native needs: macOS Keychain/SE needs cgo or untyped purego (X4), Windows CNG is untyped uintptr (X4), Iroh needs a Rust helper (X5). Go's §9.6 fix refuses .bat/.cmd outright (npm shims); Rust std quotes them safely. Rust negatives: darwin link needs the macOS SDK, Windows exe search order, alt screen left on external CTRL_C_EVENT |
| Security core (25) | 4 | 4 | X2: equal correctness under agent change, one T1 job-control major each. X3: Go far smaller graph (17 modules vs ~80 crates), no C runtime; Rust compile-time guarantees, typed FFI. Offsetting |
| Release simplicity (20) | 4 | 4 | X3: Go cross-host reproducible with stock flags, binary SBOM/vuln scan built in, goreleaser first try; Rust needs pinned container + cargo-auditable. X5: with Iroh Go ships two files and two toolchains. Offsetting; Go leads without Iroh, Rust with it |
| Agentic/OSS maintainability (15) | 4 | 4 | X2: no measurable difference (hidden-test pass, regressions, defects, effort geometric-mean ratio ~1.0). X6: tie ±1 |
| TUI quality (10) | 4 | 3 | unchanged; X2 T3 equal success; X1 Windows TUI both pass, Rust leaves alt screen on external CTRL_C_EVENT |
| Integration ecosystem (5) | 4 | 4 | Iroh native Rust; first-party x/crypto/ssh/agent for Go (X6) |
| **Total** | **3.75** | **3.90** | lean Rust, low confidence |

## Update after the final X2 results (2026-10-10, recorded before any blind scorer returned)

X2 is now complete with calibrated severities: hidden tests and effort equal; calibrated majors Go 5/12
cells (T1 x3: separate-group signal model; T3 x2: Bubble Tea renderer wide-char bug) vs Rust 0/12.

| Criterion (weight) | Go | Rust | Change and reason |
|---|---|---|---|
| Cross-platform integration (25) | 3 | 4 | unchanged |
| Security core (25) | 4 | 4 | unchanged (T1 finding counted in the maintainability row, not twice) |
| Release simplicity (20) | 4 | 4 | unchanged |
| Agentic/OSS maintainability (15) | 3 | 4 | was 4/4: calibrated X2 majors 5 vs 0, both from Go-stack pitfalls agents and reviewers missed; modest (two causes, n=3) |
| TUI quality (10) | 3 | 3 | was 4/3: Bubble Tea's renderer corrupts rows next to wide characters (baseline status line too); Ratatui side keeps hand-written Unix input decoding, alt screen left on external CTRL_C_EVENT (Windows), bidi passthrough |
| Integration ecosystem (5) | 4 | 4 | unchanged |
| **Total** | **3.50** | **3.90** | lean Rust, low-to-medium confidence |
