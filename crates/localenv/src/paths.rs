//! Where OpenSSH reads its configuration (m02-plan U3; ADR-0007 F19).
//!
//! OpenSSH takes the account home from the account database, never from `$HOME`
//! (F19), so `SshPaths` resolves it through `sys::account_home()`. Tests redirect it
//! only through the env-gated test configuration.
//!
//! **`[I]` settled on macOS 10.3p1 by `integration_doctor::home_resolution_matches_ssh_g`:**
//! the `%d` token and the defaults follow the account database (F19), but an
//! `Include` path's `~` (and a relative `Include`, which OpenSSH rewrites to
//! `~/.ssh/<path>`) is expanded by `glob(3)` with `GLOB_TILDE`, which consults `$HOME`
//! first. Under a `$HOME` other than the account's, those includes resolve under
//! `$HOME`; the doctor reports `home_mismatch` for that case.
//!
//! ADR-0007 §12.17 item 9: `crate::fs::BoundedSource` therefore reports the account
//! home as the include home only when the runtime's `HOME` is unset or names the
//! account home (`crate::fs::include_home_for`); otherwise such an `Include` is
//! undetermined (reason `environment_reference`), and B's own target is always an
//! absolute path, so B loads P whatever `$HOME` is.
//!
//! **⟨M08 U1b; M06-F3⟩ The test configuration.** Every `HEIMDALL_TEST_*` variable is test
//! configuration ([`TEST_ENV_PREFIX`]), and a test configuration never reads the account's
//! `~/.ssh`. In a **debug build** [`SshPaths::resolve`] therefore answers, before the account
//! database is consulted ([`test_configuration`]):
//!
//! * `HEIMDALL_TEST_SSH_HOME` set to an absolute path: the scratch paths under it
//!   ([`SshPaths::with_test_override`], system directory `<home>/etc-ssh`), the paths the
//!   CLI's own test hooks give, so every caller of `resolve` (the runtime's account wiring,
//!   the runner's sshd check, the WSL helper, the CLI's fallbacks) follows the same scratch
//!   home;
//! * `HEIMDALL_TEST_SSH_HOME` relative: refused;
//! * any other `HEIMDALL_TEST_*` variable without `HEIMDALL_TEST_SSH_HOME`: refused
//!   ([`HomeUnavailable`]), so the caller fails closed (the doctor and the static pass stop,
//!   setup has no projection) instead of reading the account's real configuration;
//! * no `HEIMDALL_TEST_*` variable at all: the account database, as in production.
//!
//! A **release build** reads none of these variables here: `resolve` is the account
//! database's paths, always, and every command that honours the test configuration refuses
//! a set `HEIMDALL_TEST_*` variable before it runs (`heimdall`'s `testcfg::refusal`,
//! `tools/validation/release-gate.sh`).

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// ⟨M08 U1b; M06-F3⟩ The prefix every test-configuration variable shares (module docs).
pub const TEST_ENV_PREFIX: &str = "HEIMDALL_TEST_";

/// ⟨M08 U1b; M06-F3⟩ The scratch account home of the test configuration (module docs).
pub const TEST_SSH_HOME_ENV: &str = "HEIMDALL_TEST_SSH_HOME";

/// ⟨M08 U1b; M06-F3⟩ The test configuration's answer for the SSH paths (module docs), over an
/// injected lookup (`get`) and the names of the variables set (`names`): `Ok(None)` when no
/// `HEIMDALL_TEST_*` variable is set, so the account database applies; the scratch paths under
/// an absolute `HEIMDALL_TEST_SSH_HOME`; a refusal for a relative one, or for a test
/// configuration without it. Pure. [`SshPaths::resolve`] calls it in debug builds only.
///
/// # Errors
/// [`HomeUnavailable`] for a relative `HEIMDALL_TEST_SSH_HOME`, or a `HEIMDALL_TEST_*`
/// variable without it.
pub fn test_configuration(
    get: &dyn Fn(&str) -> Option<OsString>,
    names: &mut dyn Iterator<Item = OsString>,
) -> Result<Option<SshPaths>, HomeUnavailable> {
    if let Some(home) = get(TEST_SSH_HOME_ENV) {
        let home = PathBuf::from(home);
        if !home.is_absolute() {
            return Err(HomeUnavailable(format!(
                "{TEST_SSH_HOME_ENV} must be an absolute path"
            )));
        }
        let system = home.join("etc-ssh");
        return Ok(Some(SshPaths::with_test_override(home, system)));
    }
    let mut test_vars = names.filter(|n| n.to_string_lossy().starts_with(TEST_ENV_PREFIX));
    if let Some(first) = test_vars.next() {
        return Err(HomeUnavailable(format!(
            "the HEIMDALL_TEST_* test configuration is active ({} is set) without {TEST_SSH_HOME_ENV}, and the account's ~/.ssh is never read under it",
            first.to_string_lossy()
        )));
    }
    Ok(None)
}

/// The SSH configuration locations for this account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshPaths {
    /// The account home (Unix `getpwuid_r`; Windows the profile folder).
    pub account_home: PathBuf,
    /// `~/.ssh/config`.
    pub user_config: PathBuf,
    /// `~/.ssh`.
    pub user_dir: PathBuf,
    /// `/etc/ssh/ssh_config` or `%PROGRAMDATA%\ssh\ssh_config`.
    pub system_config: PathBuf,
    /// `/etc/ssh` or `%PROGRAMDATA%\ssh`.
    pub system_dir: PathBuf,
}

/// The account home could not be resolved.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("account home unavailable: {0}")]
pub struct HomeUnavailable(pub String);

impl SshPaths {
    /// Resolve the paths for the current account: the home from the account database
    /// (F19), the user directory `~/.ssh`, and the system directory (`/etc/ssh`; on
    /// Windows `%PROGRAMDATA%\ssh`, the Win32-OpenSSH location). ⟨M08 U1b; M06-F3⟩ In a
    /// debug build the test configuration answers first ([`test_configuration`], module
    /// docs); a release build reads no variable here.
    ///
    /// # Errors
    /// [`HomeUnavailable`]; in a debug build also a test configuration's refusal.
    pub fn resolve() -> Result<Self, HomeUnavailable> {
        #[cfg(debug_assertions)]
        if let Some(paths) = test_configuration(
            &|n| std::env::var_os(n),
            &mut std::env::vars_os().map(|(k, _)| k),
        )? {
            return Ok(paths);
        }
        Self::account()
    }

    /// The account database's paths (production's [`SshPaths::resolve`]).
    fn account() -> Result<Self, HomeUnavailable> {
        let account_home =
            crate::sys::account_home().map_err(|e| HomeUnavailable(e.to_string()))?;
        let user_dir = account_home.join(".ssh");
        let system_dir = system_dir();
        Ok(Self {
            user_config: user_dir.join("config"),
            user_dir,
            system_config: system_dir.join("ssh_config"),
            system_dir,
            account_home,
        })
    }

    /// Paths under a scratch home, for the env-gated test configuration only (never
    /// compiled into a release build's request paths).
    #[must_use]
    pub fn with_test_override(account_home: PathBuf, system_dir: PathBuf) -> Self {
        let user_dir = account_home.join(".ssh");
        Self {
            user_config: user_dir.join("config"),
            user_dir,
            system_config: system_dir.join("ssh_config"),
            system_dir,
            account_home,
        }
    }

    /// `path` for display: `~` for the account home (ADR-0007 §6 "Paths are shown with
    /// `~` for the home directory").
    #[must_use]
    pub fn display(&self, path: &Path) -> String {
        display_path(&self.account_home, path)
    }
}

/// `path` with a leading `home` shown as `~` (lossy UTF-8), with `/` separators on every
/// platform, as every other display does (ADR-0007 §12.26 item 7, §12.43 item 1): on
/// Windows `\` is a separator and is shown as `/`; on Unix it is a file-name character
/// and is kept.
#[must_use]
pub fn display_path(home: &Path, path: &Path) -> String {
    let text = |p: &Path| {
        let s = p.to_string_lossy();
        if cfg!(windows) {
            s.replace('\\', "/")
        } else {
            s.into_owned()
        }
    };
    match path.strip_prefix(home) {
        Ok(rest) if rest.as_os_str().is_empty() => "~".to_owned(),
        Ok(rest) => format!("~/{}", text(rest)),
        Err(_) => text(path),
    }
}

#[cfg(windows)]
fn system_dir() -> PathBuf {
    // Win32-OpenSSH reads `__PROGRAMDATA__\ssh` (G03-S08). `ProgramData` is a
    // machine-wide value set by Windows, not the user's home.
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("ssh")
}

#[cfg(not(windows))]
fn system_dir() -> PathBuf {
    PathBuf::from("/etc/ssh")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn resolve_uses_the_account_home_and_its_ssh_directory() {
        // The account database's paths (what `resolve` gives with no test variable set).
        let p = SshPaths::account().unwrap();
        assert_eq!(p.account_home, crate::sys::account_home().unwrap());
        assert_eq!(p.user_dir, p.account_home.join(".ssh"));
        assert_eq!(p.user_config, p.user_dir.join("config"));
        assert_eq!(p.system_config, p.system_dir.join("ssh_config"));
        assert!(p.system_dir.is_absolute());
    }

    /// A scratch home that is absolute on this platform.
    fn scratch_home() -> PathBuf {
        if cfg!(windows) {
            PathBuf::from(r"C:\hm-scratch\home")
        } else {
            PathBuf::from("/hm-scratch/home")
        }
    }

    /// ⟨M08 U1b; M06-F3⟩ The test configuration's answer (module docs): no test variable,
    /// the account database; an absolute `HEIMDALL_TEST_SSH_HOME`, its scratch paths; a
    /// relative one, refused; any other `HEIMDALL_TEST_*` variable without it, refused and
    /// named, so nothing falls back to the account's `~/.ssh`.
    #[test]
    fn a_test_configuration_never_falls_back_to_the_account_home() {
        let none = |_: &str| None;
        let names = |n: &[&str]| n.iter().map(OsString::from).collect::<Vec<_>>().into_iter();
        assert_eq!(
            test_configuration(&none, &mut names(&["HOME", "PATH", "HEIMDALL_HOME"])),
            Ok(None)
        );
        let home = scratch_home();
        let given = home.clone().into_os_string();
        let set = |n: &str| (n == TEST_SSH_HOME_ENV).then(|| given.clone());
        assert_eq!(
            test_configuration(
                &set,
                &mut names(&[TEST_SSH_HOME_ENV, "HEIMDALL_TEST_ADAPTER"])
            ),
            Ok(Some(SshPaths::with_test_override(
                home.clone(),
                home.join("etc-ssh")
            )))
        );
        let relative = |n: &str| (n == TEST_SSH_HOME_ENV).then(|| OsString::from("rel/home"));
        assert!(test_configuration(&relative, &mut names(&[TEST_SSH_HOME_ENV])).is_err());
        let err = test_configuration(
            &none,
            &mut names(&[
                "PATH",
                "HEIMDALL_TEST_SECRET_STORE",
                "HEIMDALL_TEST_ADAPTER",
            ]),
        )
        .unwrap_err();
        assert!(
            err.0.contains("HEIMDALL_TEST_SECRET_STORE") && err.0.contains(TEST_SSH_HOME_ENV),
            "{err}"
        );
    }

    /// ⟨M08 U1b; M06-F3⟩ The product path itself, in a debug build: this test binary re-run
    /// on this test alone with a test variable and no `HEIMDALL_TEST_SSH_HOME` gets a refusal
    /// from `SshPaths::resolve`, and with an absolute scratch home its paths, never the
    /// account's (a child process, because setting the environment in a threaded test
    /// process is unsound). A release build compiles the test configuration out of
    /// `resolve`, so the child's expectation is the account database there.
    #[test]
    fn resolve_in_a_test_configuration_never_reads_the_account_home() {
        const CHILD: &str = "HEIMDALL_TEST_PATHS_CHILD";
        const MARKER: &str = "paths-child: ok";
        if let Some(want) = std::env::var_os(CHILD) {
            let got = SshPaths::resolve();
            if cfg!(debug_assertions) {
                match want.to_str() {
                    Some("refused") => assert!(got.is_err(), "{got:?}"),
                    _ => {
                        let home = scratch_home();
                        assert_eq!(
                            got.unwrap(),
                            SshPaths::with_test_override(home.clone(), home.join("etc-ssh"))
                        );
                    }
                }
            } else {
                assert_eq!(got.unwrap(), SshPaths::account().unwrap());
            }
            #[allow(clippy::print_stdout)]
            {
                println!("\n{MARKER}");
            }
            return;
        }
        let module = module_path!();
        let name = format!(
            "{}::resolve_in_a_test_configuration_never_reads_the_account_home",
            module.split_once("::").map_or(module, |(_, rest)| rest)
        );
        for (want, ssh_home) in [("refused", None), ("scratch", Some(scratch_home()))] {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap());
            child
                .args([name.as_str(), "--exact", "--nocapture", "--test-threads=1"])
                .env(CHILD, want)
                .env_remove(TEST_SSH_HOME_ENV);
            if let Some(home) = &ssh_home {
                child.env(TEST_SSH_HOME_ENV, home);
            }
            let out = child.output().unwrap();
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(
                out.status.success() && stdout.lines().any(|l| l.trim_end().ends_with(MARKER)),
                "{want}: child exit {:?}\n{stdout}\n{}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    #[test]
    fn display_shows_the_home_as_tilde_only_at_a_component_boundary() {
        let home = PathBuf::from("/scratch/home");
        assert_eq!(display_path(&home, &home), "~");
        assert_eq!(
            display_path(&home, &home.join(".ssh").join("config")),
            "~/.ssh/config"
        );
        assert_eq!(
            display_path(&home, Path::new("/scratch/homework/x")),
            "/scratch/homework/x"
        );
    }
}
