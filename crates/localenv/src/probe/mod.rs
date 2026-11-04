//! Explicit probes (m02-plan U3; ADR-0007 §6).
//!
//! Each probe has a timeout and runs its children in their own process group (Unix,
//! `killpg` through `sys`) or a kill-on-close job object without breakaway (Windows,
//! `sys`). Each fills `ProbeRecord.{authorization, executed_config_commands,
//! effects_excluded, containment, config_tree_changed, config_tree_differences}`
//! exactly as ADR-0007 §6 states. `executed_config_commands` holds what the static
//! pass found **before** the run and is never described as complete.
//!
//! The level functions take a [`ProbeContext`] and return their [`ProbeRecord`]; the
//! level-specific observations a unit needs beyond the record are U3's to add (each
//! level module has an `…_observed` variant that also returns them).
//!
//! **The real-tree levels** (`evaluate`, `host_verification`, `authentication`) share
//! [`run_real_tree`]:
//!
//! 1. the static pass for the alias: the evaluation and the first tree snapshot;
//! 2. declined with `config_not_fully_readable` when the pass met an unreadable
//!    include, a bound or an include path it could not expand, **with or without** the
//!    flag (that check comes first);
//! 3. declined with `config_commands_not_authorized` without `--allow-config-commands`,
//!    whatever the pass found (M2-R06);
//! 4. the test-only [`ProbeHook`] at [`ProbePoint::AfterStaticPass`];
//! 5. the `ssh` child, contained and bounded, with the caller's environment snapshot;
//! 6. the second snapshot, compared with the first.
//!
//! A declined level ran nothing (no hook, no child), so its record excludes every
//! effect. A level that ran the real tree excludes nothing: the configuration may run
//! anything (`effects_excluded` empty).

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use heimdall_contract::Timestamp;
use heimdall_contract::code::Code;
use heimdall_contract::doctor::{
    ConfigProvenance, Containment, ExcludedEffect, ProbeOutcome, ProbeRecord, decline_reason,
};
use heimdall_contract::provider::ProbeLevel;
use heimdall_sshconf::eval::{
    Evaluation, Invocation, OpenSshVersion, Query, SYSTEM_ROOT_SPAN, USER_ROOT_SPAN, evaluate,
};
use heimdall_sshconf::include::{ConfigSet, Roots};
use heimdall_sshconf::parse::Span;
use heimdall_sshconf::relevant::{executing_constructs, unreadable_includes};

use crate::clients::{ClientInventory, ClientKind};
use crate::doctor::LocalContext;
use crate::fs::BoundedSource;
use crate::local_query::{Finished, Spec, run_contained};

pub mod agent;
pub mod auth;
pub mod evaluate;
pub mod host;
pub mod network;
pub mod snapshot;

/// The default per-level bound.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Bytes kept from each output stream of a probe child.
pub const PROBE_OUTPUT_BYTES: usize = 1 << 20;

/// The authorization string recorded for `--allow-config-commands`.
pub const ALLOW_CONFIG_COMMANDS: &str = "allow_config_commands";

/// The test-only hook points (never compiled into a release build's request paths;
/// env-gated through the test configuration, like `ReplaceHook`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProbePoint {
    /// Between the static pass and the start of the `ssh` child.
    AfterStaticPass,
}

/// A test-only hook run at a [`ProbePoint`].
pub trait ProbeHook: Send + Sync {
    /// Called at `point` for `level`.
    fn at(&self, point: ProbePoint, level: ProbeLevel);
}

/// What every level gets.
#[derive(Debug, Clone)]
pub struct ProbeContext<'a> {
    /// The local facts.
    pub local: &'a LocalContext,
    /// `--allow-config-commands`.
    pub allow_config_commands: bool,
    /// Whether prompts are allowed.
    pub interactive: bool,
    /// The level's bound.
    pub timeout: Duration,
    /// The client inventory (the verified `ssh` and its version); `None` resolves the
    /// selected `ssh` from the context without hashing or querying.
    pub inventory: Option<&'a ClientInventory>,
}

impl<'a> ProbeContext<'a> {
    /// A context with the default bound and no inventory.
    #[must_use]
    pub fn new(local: &'a LocalContext, allow_config_commands: bool, interactive: bool) -> Self {
        Self {
            local,
            allow_config_commands,
            interactive,
            timeout: PROBE_TIMEOUT,
            inventory: None,
        }
    }

    /// The verified `ssh`.
    #[must_use]
    pub fn ssh(&self) -> Option<PathBuf> {
        match self.inventory {
            Some(inv) => inv.selected(ClientKind::Ssh).map(|c| c.path.clone()),
            None => {
                crate::clients::selected_path(&self.local.env, &self.local.clients, ClientKind::Ssh)
            }
        }
    }

    /// The verified `ssh`'s version, when known.
    #[must_use]
    pub fn ssh_version(&self) -> Option<OpenSshVersion> {
        self.inventory
            .and_then(|inv| inv.selected(ClientKind::Ssh))
            .and_then(|c| c.version)
    }
}

/// Every effect: what a level that ran nothing (or ran no configuration and touched
/// nothing) excludes.
#[must_use]
pub fn all_effects() -> BTreeSet<ExcludedEffect> {
    [
        ExcludedEffect::ConfigExecution,
        ExcludedEffect::AgentContact,
        ExcludedEffect::ProviderContact,
        ExcludedEffect::Network,
        ExcludedEffect::Signing,
        ExcludedEffect::Mutation,
    ]
    .into_iter()
    .collect()
}

fn duration_ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// A record skeleton for `level` at `target`, started now.
pub(crate) fn record(level: ProbeLevel, target: &str, started_at: Timestamp) -> ProbeRecord {
    ProbeRecord {
        level,
        target: target.to_owned(),
        started_at,
        duration_ms: 0,
        outcome: ProbeOutcome::Ok,
        decline_reason: None,
        code: None,
        authorization: Vec::new(),
        executed_config_commands: Vec::new(),
        effects_excluded: all_effects(),
        containment: Containment::None,
        config_tree_changed: None,
        config_tree_differences: Vec::new(),
    }
}

/// Build the record of a level declined before anything ran.
#[must_use]
pub fn declined(level: ProbeLevel, target: &str, reason: &'static str) -> ProbeRecord {
    let mut r = record(level, target, Timestamp::now());
    r.outcome = ProbeOutcome::Declined;
    r.decline_reason = Some(reason.to_owned());
    r
}

/// A record of a level refused before anything ran (an unusable target, a
/// non-interactive refusal).
pub(crate) fn refused(level: ProbeLevel, target: &str, code: Code) -> ProbeRecord {
    let mut r = record(level, target, Timestamp::now());
    r.outcome = ProbeOutcome::Refused;
    r.code = Some(code);
    r
}

/// Whether an alias is safe to put on a client's command line: not empty, no leading
/// `-` (it would be read as an option), no whitespace or control character.
#[must_use]
pub fn alias_is_usable(alias: &str) -> bool {
    !alias.is_empty()
        && !alias.starts_with('-')
        && !alias.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// The static pass for one alias.
#[derive(Debug, Clone)]
pub struct StaticPass {
    /// The evaluation.
    pub evaluation: Evaluation,
    /// The files it read.
    pub set: ConfigSet,
    /// The roots it started from.
    pub roots: Roots,
    /// The snapshot taken with it.
    pub snapshot: snapshot::TreeSnapshot,
    /// The executing constructs it found, as file:line.
    pub executed: Vec<ConfigProvenance>,
    /// Whether it met an unreadable include, a bound or an unexpandable include path.
    pub not_fully_readable: bool,
    /// The invocation it evaluated: the one the level's `ssh` child runs (ADR-0007
    /// §12.25 item 1).
    pub invocation: Invocation,
}

/// `span` as file:line (display form), for the files of `set` and the two roots.
#[must_use]
pub fn provenance(
    local: &LocalContext,
    set: &ConfigSet,
    roots: &Roots,
    span: Span,
) -> ConfigProvenance {
    let path = if span == USER_ROOT_SPAN {
        roots.user.clone()
    } else if span == SYSTEM_ROOT_SPAN {
        roots.system.clone()
    } else {
        set.path_of(span.source).map(std::path::Path::to_path_buf)
    };
    // ADR-0007 §12.26 item 7: a path the plain display cannot place under the home is
    // shown through the canonicalized home too, so a home behind a symlink is still
    // `~/…`.
    let shown = |p: &std::path::Path| {
        let plain = local.paths.display(p);
        if plain.starts_with('~') {
            plain
        } else {
            crate::doctor::path_display(p, &local.paths.account_home)
        }
    };
    ConfigProvenance {
        path_display: path.map_or_else(|| "?".to_owned(), |p| shown(&p)),
        line: span.line,
    }
}

/// [`provenance`] for a span of `evaluation`: its file named as the evaluation names it,
/// the path the configuration gives it, never its canonical form (ADR-0007 §12.28 item
/// 6); a span of a file the evaluation did not record falls back to [`provenance`].
#[must_use]
pub fn provenance_in(
    local: &LocalContext,
    set: &ConfigSet,
    evaluation: &Evaluation,
    roots: &Roots,
    span: Span,
) -> ConfigProvenance {
    match evaluation.files.get(&span.source) {
        Some(path) if span != USER_ROOT_SPAN && span != SYSTEM_ROOT_SPAN => {
            let plain = local.paths.display(path);
            ConfigProvenance {
                path_display: if plain.starts_with('~') {
                    plain
                } else {
                    crate::doctor::path_display(path, &local.paths.account_home)
                },
                line: span.line,
            }
        }
        _ => provenance(local, set, roots, span),
    }
}

/// The query for `alias` (interactive shell, no `-l`).
#[must_use]
pub fn query_for(local: &LocalContext, alias: &str, version: Option<OpenSshVersion>) -> Query {
    query_with(local, alias, version, Invocation::Shell)
}

/// The query for `alias` under `invocation` (no `-l`). `local_user` is the account
/// database's name (ADR-0007 §12.25 item 2, [`LocalContext::local_user`]), `None` for
/// an account that cannot be established: the evaluator then leaves `Match localuser`,
/// `Match user` on the local account, `%u` and `%r` undetermined, and only those
/// (ADR-0007 §12.28 item 3).
#[must_use]
pub fn query_with(
    local: &LocalContext,
    alias: &str,
    version: Option<OpenSshVersion>,
    invocation: Invocation,
) -> Query {
    Query {
        host: alias.to_owned(),
        user: None,
        local_user: local.local_user(),
        client_version: version.unwrap_or(OpenSshVersion::MINIMUM),
        invocation,
    }
}

/// The invocation `ssh <options> <alias> <trailing>` runs (ADR-0007 §12.25 item 1): an
/// interactive shell with no command, otherwise the remote command `ssh` sends (its
/// arguments joined by spaces, as `ssh` joins them).
#[must_use]
pub fn invocation_of(trailing: &[&str]) -> Invocation {
    if trailing.is_empty() {
        Invocation::Shell
    } else {
        Invocation::Exec(Some(trailing.join(" ")))
    }
}

/// Run the static pass for `alias` as an interactive shell (passive: reads only,
/// executes nothing).
#[must_use]
pub fn static_pass(
    local: &LocalContext,
    alias: &str,
    version: Option<OpenSshVersion>,
) -> StaticPass {
    static_pass_for(local, alias, version, Invocation::Shell)
}

/// [`static_pass`] under `invocation`, the one the level's child runs (ADR-0007
/// §12.25 item 1).
#[must_use]
pub fn static_pass_for(
    local: &LocalContext,
    alias: &str,
    version: Option<OpenSshVersion>,
    invocation: Invocation,
) -> StaticPass {
    let source = BoundedSource::new(local.paths.clone(), local.env.clone(), local.limits);
    let roots = local.roots();
    let query = query_with(local, alias, version, invocation.clone());
    let mut set = ConfigSet::new();
    let evaluation = evaluate(&mut set, &source, &roots, &query, &local.limits);
    let snapshot = snapshot::take(&source, &roots, &query, &local.limits);
    let executed = executing_constructs(&evaluation)
        .into_iter()
        .map(|span| provenance_in(local, &set, &evaluation, &roots, span))
        .collect();
    let not_fully_readable = !unreadable_includes(&evaluation).is_empty();
    StaticPass {
        evaluation,
        set,
        roots,
        snapshot,
        executed,
        not_fully_readable,
        invocation,
    }
}

/// A real-tree level that ran (or was declined or refused before running).
#[derive(Debug, Clone)]
pub(crate) struct RealTreeRun {
    /// Its record; the caller sets `outcome` and `code` from `finished` when it ran.
    pub record: ProbeRecord,
    /// The child's result, when one ran.
    pub finished: Option<Finished>,
}

/// Run `ssh <level_args> <alias> <trailing>` against the real tree (module
/// documentation). `gate` may refuse after the static pass (non-interactive
/// authentication) before anything runs.
pub(crate) fn run_real_tree(
    ctx: &ProbeContext<'_>,
    level: ProbeLevel,
    alias: &str,
    level_args: &[&str],
    trailing: &[&str],
    gate: &dyn Fn(&StaticPass) -> Option<Code>,
) -> RealTreeRun {
    let started_at = Timestamp::now();
    let t0 = Instant::now();
    if !alias_is_usable(alias) {
        return RealTreeRun {
            record: refused(level, alias, Code::UsageError),
            finished: None,
        };
    }
    // ADR-0007 §12.25 item 1: the pass evaluates the invocation the child runs.
    let invocation = invocation_of(trailing);
    let pass = static_pass_for(ctx.local, alias, ctx.ssh_version(), invocation.clone());
    if pass.not_fully_readable {
        return RealTreeRun {
            record: declined(level, alias, decline_reason::CONFIG_NOT_FULLY_READABLE),
            finished: None,
        };
    }
    if !ctx.allow_config_commands {
        return RealTreeRun {
            record: declined(level, alias, decline_reason::CONFIG_COMMANDS_NOT_AUTHORIZED),
            finished: None,
        };
    }
    if let Some(code) = gate(&pass) {
        let mut r = refused(level, alias, code);
        r.authorization = vec![ALLOW_CONFIG_COMMANDS.to_owned()];
        return RealTreeRun {
            record: r,
            finished: None,
        };
    }
    let Some(ssh) = ctx.ssh() else {
        let mut r = record(level, alias, started_at);
        r.outcome = ProbeOutcome::Failed;
        r.code = Some(Code::UnsupportedClient);
        r.authorization = vec![ALLOW_CONFIG_COMMANDS.to_owned()];
        return RealTreeRun {
            record: r,
            finished: None,
        };
    };
    if let Some(hook) = &ctx.local.probe_hook {
        hook.at(ProbePoint::AfterStaticPass, level);
    }
    let mut args: Vec<OsString> = ctx.local.client_isolation.clone().unwrap_or_default();
    args.extend(level_args.iter().map(OsString::from));
    args.push(alias.into());
    args.extend(trailing.iter().map(OsString::from));
    let finished = run_contained(&Spec {
        program: &ssh,
        args,
        env: Some(&ctx.local.env),
        cwd: None,
        timeout: ctx.timeout,
        max_output: PROBE_OUTPUT_BYTES,
    });
    let source = BoundedSource::new(
        ctx.local.paths.clone(),
        ctx.local.env.clone(),
        ctx.local.limits,
    );
    let query = query_with(ctx.local, alias, ctx.ssh_version(), invocation);
    let after = snapshot::take(&source, &pass.roots, &query, &ctx.local.limits);
    let differences = snapshot::compare(&pass.snapshot, &after);
    let mut r = record(level, alias, started_at);
    r.authorization = vec![ALLOW_CONFIG_COMMANDS.to_owned()];
    r.executed_config_commands = pass.executed.clone();
    r.effects_excluded = BTreeSet::new();
    r.config_tree_changed = Some(!differences.is_empty());
    r.config_tree_differences = differences;
    let finished = match finished {
        Ok(f) => {
            r.containment = f.containment;
            if f.timed_out {
                r.outcome = ProbeOutcome::Timeout;
            }
            Some(f)
        }
        Err(_) => {
            r.outcome = ProbeOutcome::Failed;
            r.code = Some(Code::UnsupportedClient);
            None
        }
    };
    r.duration_ms = duration_ms(t0.elapsed());
    RealTreeRun {
        record: r,
        finished,
    }
}

/// Run `f` on a fresh thread with its own current-thread Tokio runtime, so a level that
/// uses an async client works whether or not the caller is inside a runtime.
pub(crate) fn block_on_fresh<T, F>(f: F) -> Option<T>
where
    T: Send + 'static,
    F: std::future::Future<Output = T> + Send + 'static,
{
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .ok()?;
        Some(rt.block_on(f))
    })
    .join()
    .ok()
    .flatten()
}

pub(crate) fn elapsed_ms(t0: Instant) -> u64 {
    duration_ms(t0.elapsed())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn declined_records_ran_nothing_and_exclude_everything() {
        let r = declined(
            ProbeLevel::Evaluate,
            "a",
            decline_reason::CONFIG_COMMANDS_NOT_AUTHORIZED,
        );
        assert_eq!(r.outcome, ProbeOutcome::Declined);
        assert_eq!(
            r.decline_reason.as_deref(),
            Some(decline_reason::CONFIG_COMMANDS_NOT_AUTHORIZED)
        );
        assert_eq!(r.effects_excluded, all_effects());
        assert_eq!(r.containment, Containment::None);
        assert!(r.config_tree_changed.is_none());
        assert!(r.executed_config_commands.is_empty());
        assert!(r.authorization.is_empty());
    }

    #[test]
    fn aliases_that_look_like_options_are_unusable() {
        assert!(alias_is_usable("db-1.example"));
        for bad in ["", "-oProxyCommand=x", "a b", "a\nb"] {
            assert!(!alias_is_usable(bad), "{bad:?}");
        }
    }
}
