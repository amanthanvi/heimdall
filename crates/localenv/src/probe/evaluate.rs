//! The `evaluate` level: `ssh -G` over the real tree (m02-plan U3; ADR-0007 §6). It
//! runs the configuration's commands, so it needs `allow_config_commands`.
//!
//! The record follows [`super::run_real_tree`]: declined before anything runs without
//! the flag or on a tree the static pass could not fully read; otherwise contained,
//! bounded, with `executed_config_commands` from the static pass only and
//! `effects_excluded` empty. Exit 0 is `ok`, any other exit `failed`.

use std::collections::BTreeMap;

use heimdall_contract::doctor::{ProbeOutcome, ProbeRecord};
use heimdall_contract::provider::ProbeLevel;

use super::ProbeContext;

/// What `ssh -G` printed: each lowercase keyword with its values in order (a keyword
/// printed several times, such as `identityfile`, keeps every line). Held in memory
/// for comparison only; never put in a report.
pub type SshGOutput = BTreeMap<String, Vec<String>>;

/// Run `ssh -G <alias>` under the probe's containment.
#[must_use]
pub fn ssh_g(ctx: &ProbeContext<'_>, alias: &str) -> ProbeRecord {
    ssh_g_observed(ctx, alias).0
}

/// [`ssh_g`], with the parsed output when the child exited 0.
#[must_use]
pub fn ssh_g_observed(ctx: &ProbeContext<'_>, alias: &str) -> (ProbeRecord, Option<SshGOutput>) {
    let run = super::run_real_tree(ctx, ProbeLevel::Evaluate, alias, &["-G"], &[], &|_| None);
    let mut record = run.record;
    let Some(finished) = run.finished else {
        return (record, None);
    };
    if record.outcome != ProbeOutcome::Ok {
        return (record, None);
    }
    if finished.status.is_some_and(|s| s.success()) {
        (record, Some(parse_ssh_g(&finished.stdout)))
    } else {
        record.outcome = ProbeOutcome::Failed;
        (record, None)
    }
}

/// Parse `ssh -G` output: `keyword value…` per line.
#[must_use]
pub fn parse_ssh_g(out: &[u8]) -> SshGOutput {
    let text = String::from_utf8_lossy(out);
    let mut map: SshGOutput = BTreeMap::new();
    for line in text.lines() {
        let (k, v) = line.split_once(' ').unwrap_or((line, ""));
        if k.is_empty() {
            continue;
        }
        map.entry(k.to_ascii_lowercase())
            .or_default()
            .push(v.to_owned());
    }
    map
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn ssh_g_output_parses_repeated_keywords_in_order() {
        let out = b"hostname a.example\nport 22\nidentityfile /x/a\nidentityfile /x/b\nproxycommand echo '$X'  \"q\"\n";
        let m = parse_ssh_g(out);
        assert_eq!(m["hostname"], ["a.example"]);
        assert_eq!(m["identityfile"], ["/x/a", "/x/b"]);
        assert_eq!(m["proxycommand"], ["echo '$X'  \"q\""]);
    }
}
