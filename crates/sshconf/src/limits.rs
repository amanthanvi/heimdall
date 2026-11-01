//! Bounds on everything the loader reads (m02-plan U1; ADR-0007 §6 "bounded").

/// Read bounds for one evaluation. Exceeding any of them is recorded as
/// `UnresolvedReason::BoundExceeded` (never a silent truncation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Bytes per configuration file (1 MiB).
    pub file_bytes: usize,
    /// Bytes over every file one evaluation reads (8 MiB).
    pub total_bytes: usize,
    /// Files one evaluation reads (256).
    pub files: usize,
    /// Include nesting depth (16; OpenSSH's own limit).
    pub depth: usize,
    /// Results of one `Include` glob (256).
    pub glob_results: usize,
    /// Bytes per line (4096).
    pub line_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            file_bytes: 1 << 20,
            total_bytes: 8 << 20,
            files: 256,
            depth: 16,
            glob_results: 256,
            line_bytes: 4096,
        }
    }
}
