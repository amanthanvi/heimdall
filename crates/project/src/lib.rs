//! Heimdall's trusted-work project logic (M05; ADR-0011 §2.2–§2.4; m05-plan).
//!
//! **Will own:** the pure manifest parser, the access digest, workspace discovery over an
//! `FsView` (ADR-0011 §2.2), `match_workspace` (§2.3), and the portable bundle (§2.4).
//!
//! **Must stay pure:** production edges are `heimdall-contract` and `heimdall-domain` only,
//! with no process, network, file or terminal I/O of its own (file access goes through the
//! `FsView` seam). The crate-graph step refuses any other workspace edge
//! (`tools/validation/crate_graph.py`); `heimdall-app` depends on this crate, never the
//! reverse.
//!
//! Wave 0 registers the crate with `contract` and `domain` only; the M05 track fills it and
//! enables this crate's tests with its first meaningful case.
