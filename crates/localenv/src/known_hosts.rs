//! Known-host lookup (m02-plan U3): `ssh-keygen -F` as a local query, or a parse of
//! plain (unhashed) entries. Never writes `known_hosts`.

use crate::local_query::LocalQueries;
use crate::paths::SshPaths;

/// One host key Heimdall found for a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKeyObservation {
    /// Key type (`ssh-ed25519` …).
    pub key_type: String,
    /// SHA-256 fingerprint (`SHA256:…`).
    pub fingerprint: String,
    /// The known-hosts file and line (display form).
    pub origin_display: String,
    /// Whether the entry is marked `@revoked`.
    pub revoked: bool,
}

/// Known host keys for `host:port`.
#[must_use]
pub fn lookup(
    paths: &SshPaths,
    host: &str,
    port: u16,
    queries: LocalQueries,
) -> Vec<HostKeyObservation> {
    let _ = (paths, host, port, queries);
    todo!("M02-U3 known_hosts::lookup")
}
