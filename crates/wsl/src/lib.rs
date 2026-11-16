//! Heimdall's WSL realization (M04; ADR-0010 §2–§3; m04-plan).
//!
//! **Will own:** WSL distribution discovery (ADR-0010 §2), the `heimdall-wsl/1` helper
//! channel between the Windows runtime and the in-distribution helper (`heimdall internal
//! wsl-helper`), and the two realization modes, Mode A and Mode B (ADR-0010 §3).
//!
//! **Must not be imported by:** `heimdall-app`. This crate implements `app` ports and the
//! runtime wires it (`heimdall-runtime → heimdall-wsl`); the crate-graph step refuses an
//! `app → wsl` edge (`tools/validation/crate_graph.py`).
//!
//! **Planned production edges:** `credential`, `localenv`, `ipc`, `app` (ports), `domain`,
//! `contract`. Wave 0 registers the crate with `contract` and `domain` only; the M04 track
//! adds the rest and enables this crate's tests with its first meaningful case.
