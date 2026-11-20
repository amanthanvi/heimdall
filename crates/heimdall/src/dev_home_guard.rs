//! The debug-build guard against the account's real home (orchestrator ruling I-15).
//!
//! A freshly built debug `heimdall` run without a scratch home resolves the per-user default
//! directories (`Paths::platform_defaults`) and may start a runtime there. That already
//! happened twice in a fixture run, so a **debug build** now refuses it, before any directory
//! is created, read or started:
//!
//! - no explicit home (`--home` / `HEIMDALL_HOME`), and
//! - the process's home is the account's real home, and
//! - `HEIMDALL_DEV_ALLOW_ACCOUNT_HOME=1` is not set.
//!
//! **The process home** is what the default paths are derived from: Unix `HOME`, Windows
//! `USERPROFILE`, each only when set and non-empty (`std::env::home_dir`, which
//! `etcetera::home_dir` calls, falls back to the account database or the known folder
//! otherwise). An unset or empty variable therefore resolves to the real home too, and is
//! refused.
//!
//! **The account home** never comes from the environment: it is
//! `heimdall_localenv::sys::account_home()`, Unix `getpwuid_r(getuid())`, Windows
//! `GetUserProfileDirectoryW` on the process token (the registry's `ProfileList` entry for
//! the token's SID, not `USERPROFILE`; `SHGetKnownFolderPath` was not used because its
//! behaviour with a redirected profile is a separate question this guard does not need).
//! Reusing it adds no `unsafe` and no dependency to this crate.
//!
//! **Fail closed:** when the account home cannot be read, the guard cannot tell the two
//! apart and refuses (the escape variable still applies).
//!
//! **Release builds** compile the check away: [`refusal`] is a constant `None` without
//! `debug_assertions`, and the decision code is not compiled into the binary at all.

#[cfg(any(debug_assertions, test))]
use std::ffi::OsString;
#[cfg(any(debug_assertions, test))]
use std::path::{Path, PathBuf};

/// The developer's deliberate opt-in to the real home (the value must be exactly `1`).
#[cfg(any(debug_assertions, test))]
pub const ALLOW_ENV: &str = "HEIMDALL_DEV_ALLOW_ACCOUNT_HOME";

/// The environment variable the default directories are derived from.
#[cfg(all(unix, any(debug_assertions, test)))]
const PROCESS_HOME_ENV: &str = "HOME";
/// The environment variable the default directories are derived from.
#[cfg(all(windows, any(debug_assertions, test)))]
const PROCESS_HOME_ENV: &str = "USERPROFILE";

/// What the guard decided.
#[cfg(any(debug_assertions, test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Use the directories as resolved.
    Allow,
    /// The process home is the account's real home.
    RefuseAccountHome,
    /// The account home could not be read, so the two cannot be told apart.
    RefuseUnknown,
}

/// The pure decision. `process_home` is `None` when the variable is unset or empty (the
/// default paths then resolve to the account home); both paths are compared as given, so
/// the caller normalizes them ([`normalized`]).
#[cfg(any(debug_assertions, test))]
#[must_use]
pub(crate) fn decide(
    explicit_home: bool,
    process_home: Option<&Path>,
    account_home: Option<&Path>,
    allow: bool,
) -> Verdict {
    if explicit_home || allow {
        return Verdict::Allow;
    }
    match (process_home, account_home) {
        (_, None) => Verdict::RefuseUnknown,
        (None, Some(_)) => Verdict::RefuseAccountHome,
        (Some(process), Some(account)) => {
            if same_path(process, account) {
                Verdict::RefuseAccountHome
            } else {
                Verdict::Allow
            }
        }
    }
}

/// Lexical equality: components (so a trailing separator and `.` segments do not matter);
/// on Windows also case-insensitive and ignoring a `\\?\` verbatim prefix.
#[cfg(any(debug_assertions, test))]
fn same_path(a: &Path, b: &Path) -> bool {
    #[cfg(windows)]
    {
        fn key(p: &Path) -> Vec<String> {
            let s = p.to_string_lossy().to_lowercase();
            let s = s.strip_prefix(r"\\?\").unwrap_or(&s).replace('/', r"\");
            s.split('\\')
                .filter(|c| !c.is_empty() && *c != ".")
                .map(str::to_owned)
                .collect()
        }
        key(a) == key(b)
    }
    #[cfg(not(windows))]
    {
        a == b
    }
}

/// `p` resolved through the filesystem when that works (a symlink to the real home is the
/// real home), otherwise as given. Read-only; creates nothing.
#[cfg(any(debug_assertions, test))]
#[must_use]
pub(crate) fn normalized(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

/// The guard over an injected environment and account lookup (the unit tests; no process
/// state).
#[cfg(any(debug_assertions, test))]
pub(crate) fn verdict_with(
    explicit_home: bool,
    env: &dyn Fn(&str) -> Option<OsString>,
    account_home: &dyn Fn() -> Option<PathBuf>,
) -> Verdict {
    let allow = env(ALLOW_ENV).is_some_and(|v| v == "1");
    if explicit_home || allow {
        return Verdict::Allow;
    }
    let process = env(PROCESS_HOME_ENV)
        .filter(|v| !v.is_empty())
        .map(|v| normalized(Path::new(&v)));
    let account = account_home().map(|p| normalized(&p));
    decide(explicit_home, process.as_deref(), account.as_deref(), allow)
}

/// The refusal message for a debug build, `None` when the directories may be used. Called by
/// `Ctx::paths()` before anything is created, read or started.
#[cfg(debug_assertions)]
#[must_use]
pub(crate) fn refusal(explicit_home: bool) -> Option<String> {
    let verdict = verdict_with(explicit_home, &|n| std::env::var_os(n), &|| {
        heimdall_localenv::sys::account_home().ok()
    });
    message(verdict)
}

/// Release builds have no guard.
#[cfg(not(debug_assertions))]
#[must_use]
pub(crate) fn refusal(_explicit_home: bool) -> Option<String> {
    None
}

#[cfg(any(debug_assertions, test))]
fn message(verdict: Verdict) -> Option<String> {
    let why = match verdict {
        Verdict::Allow => return None,
        Verdict::RefuseAccountHome => "this debug build would use the account's real home",
        Verdict::RefuseUnknown => {
            "this debug build cannot tell whether it would use the account's real home"
        }
    };
    Some(format!(
        "{why}; nothing was created or started. Set HEIMDALL_HOME (or pass --home) to a \
         scratch directory, or set {ALLOW_ENV}=1 to use the real home on purpose"
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn p(s: &str) -> Option<&Path> {
        Some(Path::new(s))
    }

    /// The decision table: (explicit, process home, account home, allow) → verdict.
    #[test]
    fn decision_table() {
        let acct = if cfg!(windows) {
            r"C:\Users\dev"
        } else {
            "/home/dev"
        };
        let other = if cfg!(windows) {
            r"C:\scratch\home"
        } else {
            "/tmp/scratch-home"
        };
        let trailing = if cfg!(windows) {
            r"C:\Users\dev\"
        } else {
            "/home/dev/"
        };
        let dotted = if cfg!(windows) {
            r"C:\Users\dev\."
        } else {
            "/home/dev/."
        };
        use Verdict::{Allow, RefuseAccountHome as Real, RefuseUnknown as Unknown};
        type Row<'a> = (bool, Option<&'a str>, Option<&'a str>, bool, Verdict);
        let rows: &[Row] = &[
            // The real home, nothing explicit: refused.
            (false, Some(acct), Some(acct), false, Real),
            (false, Some(trailing), Some(acct), false, Real),
            (false, Some(dotted), Some(acct), false, Real),
            // The variable unset or empty resolves to the account home: refused.
            (false, None, Some(acct), false, Real),
            // A scratch home as the process home: allowed.
            (false, Some(other), Some(acct), false, Allow),
            // An explicit home or the escape: allowed, whatever the rest.
            (true, Some(acct), Some(acct), false, Allow),
            (true, None, None, false, Allow),
            (false, Some(acct), Some(acct), true, Allow),
            (false, None, None, true, Allow),
            // The account home unreadable: cannot tell, refused (fail closed).
            (false, Some(other), None, false, Unknown),
            (false, None, None, false, Unknown),
        ];
        for (explicit, process, account, allow, want) in rows {
            let got = decide(*explicit, process.and_then(p), account.and_then(p), *allow);
            assert_eq!(
                got, *want,
                "explicit={explicit} process={process:?} account={account:?} allow={allow}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_compares_case_insensitively_and_ignores_the_verbatim_prefix() {
        assert!(same_path(
            Path::new(r"c:\users\DEV"),
            Path::new(r"C:\Users\dev")
        ));
        assert!(same_path(
            Path::new(r"\\?\C:\Users\dev"),
            Path::new(r"C:\Users\dev")
        ));
        assert!(!same_path(
            Path::new(r"C:\Users\dev2"),
            Path::new(r"C:\Users\dev")
        ));
    }

    /// The injected-environment path: the escape is exactly `1`, an empty process home is
    /// the account home, and a symlink to the account home is the account home.
    #[test]
    fn environment_rules() {
        let scratch = tempfile::tempdir().expect("scratch");
        let account = scratch.path().join("account");
        std::fs::create_dir(&account).expect("account dir");
        let acct = account.clone();
        let account_home = move || Some(acct.clone());
        let env_of = |pairs: Vec<(&'static str, OsString)>| {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == name)
                    .map(|(_, v)| v.clone())
            }
        };
        let real = || vec![(PROCESS_HOME_ENV, account.clone().into_os_string())];

        assert_eq!(
            verdict_with(false, &env_of(real()), &account_home),
            Verdict::RefuseAccountHome
        );
        // Unset and empty.
        assert_eq!(
            verdict_with(false, &env_of(vec![]), &account_home),
            Verdict::RefuseAccountHome
        );
        assert_eq!(
            verdict_with(
                false,
                &env_of(vec![(PROCESS_HOME_ENV, OsString::new())]),
                &account_home
            ),
            Verdict::RefuseAccountHome
        );
        // The escape counts only as `1`.
        for (value, want) in [
            ("1", Verdict::Allow),
            ("0", Verdict::RefuseAccountHome),
            ("true", Verdict::RefuseAccountHome),
            ("", Verdict::RefuseAccountHome),
        ] {
            let mut env = real();
            env.push((ALLOW_ENV, value.into()));
            assert_eq!(
                verdict_with(false, &env_of(env), &account_home),
                want,
                "{ALLOW_ENV}={value:?}"
            );
        }
        // A scratch home that is not the account's.
        let other = scratch.path().join("other");
        std::fs::create_dir(&other).expect("other dir");
        assert_eq!(
            verdict_with(
                false,
                &env_of(vec![(PROCESS_HOME_ENV, other.into_os_string())]),
                &account_home
            ),
            Verdict::Allow
        );
        // A symlink to the account home is the account home.
        #[cfg(unix)]
        {
            let link = scratch.path().join("link");
            std::os::unix::fs::symlink(&account, &link).expect("symlink");
            assert_eq!(
                verdict_with(
                    false,
                    &env_of(vec![(PROCESS_HOME_ENV, link.into_os_string())]),
                    &account_home
                ),
                Verdict::RefuseAccountHome
            );
        }
        // The account home unreadable: fail closed.
        assert_eq!(
            verdict_with(false, &env_of(real()), &|| None),
            Verdict::RefuseUnknown
        );
    }

    #[test]
    fn the_message_names_the_home_variable_and_the_escape() {
        for v in [Verdict::RefuseAccountHome, Verdict::RefuseUnknown] {
            let m = message(v).expect("refusal");
            assert!(m.contains("HEIMDALL_HOME"), "{m}");
            assert!(m.contains(ALLOW_ENV), "{m}");
        }
        assert_eq!(message(Verdict::Allow), None);
    }
}
