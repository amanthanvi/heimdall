//! ⟨M06 W5⟩ The debug-build guard between a scratch installation and the account's real
//! key stores (the 2026-11-22 incident: a hand-run debug `heimdall environment add` under a
//! scratch `HEIMDALL_HOME` created a K_mgmt item in the owner's login keychain, because the
//! platform stores are selected by the account, not by the Heimdall home).
//!
//! **The rule.** A debug build whose resolved Heimdall home is inside a temporary or scratch
//! directory never opens the platform store for K_mgmt or K_iroh. Without the fixture store
//! variable of that key ([`MGMT_FIXTURE_ENV`], [`IROH_FIXTURE_ENV`]) it refuses, naming the
//! variable; there is no fallback in either direction.
//!
//! **Scratch** ([`is_scratch_home`]) is decided from the path alone, component by component
//! (so `/tmpfoo` is not under `/tmp`): the home is under one of [`FIXED_ROOTS`], under a
//! temporary directory the environment names (`TMPDIR`, `TEMP`, `TMP`, and
//! `std::env::temp_dir()`), or has a component named `target` (a Cargo build directory).
//! The path is examined as given and, where it resolves, through the filesystem too (macOS
//! `/tmp` is `/private/tmp`). Windows compares case-insensitively.
//!
//! **Release builds** contain no check: [`home_is_scratch`] is a constant `false` there and
//! nothing else in this module is reachable from the selection sites
//! (`crate::iroh::requested_test_store`; `heimdall`'s `mgmt_store`).

use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

/// The variable naming the Heimdall home (`heimdall_runtime::paths::HOME_ENV`; this crate
/// has no edge to the runtime, and `heimdall`'s tests pin the two names equal).
pub const HOME_ENV: &str = "HEIMDALL_HOME";

/// The fixture K_mgmt store's variable (`heimdall`'s `TEST_MGMT_STORE_ENV`).
pub const MGMT_FIXTURE_ENV: &str = "HEIMDALL_TEST_MGMT_STORE";

/// The fixture K_iroh store's variable ([`crate::iroh::FIXTURE_STORE_ENV`]).
pub const IROH_FIXTURE_ENV: &str = crate::iroh::FIXTURE_STORE_ENV;

/// The K_mgmt refusal's message.
pub const MGMT_REFUSAL: &str = "this debug build's Heimdall home is a temporary or scratch \
     directory, so it will not use the account's key store for the management key: set \
     HEIMDALL_TEST_MGMT_STORE=fixture-file:<absolute scratch path> (there is no fallback)";

/// The K_iroh refusal's detail (the parenthesis of `transport_key_store_unavailable`).
pub const IROH_REFUSAL_DETAIL: &str = "this debug build's Heimdall home is a temporary or \
     scratch directory, so it will not use the account's key store for the transport key: \
     set HEIMDALL_TEST_IROH_KEY_STORE=<absolute owner-only scratch directory>; there is no \
     fallback";

/// The directories that are scratch on every host, whatever the environment says.
pub const FIXED_ROOTS: [&str; 6] = [
    "/tmp",
    "/private/tmp",
    "/var/tmp",
    "/private/var/tmp",
    "/var/folders",
    "/private/var/folders",
];

/// The variables that name a temporary directory.
pub const TEMP_ENVS: [&str; 3] = ["TMPDIR", "TEMP", "TMP"];

/// The component that marks a Cargo build directory.
pub const BUILD_DIR: &str = "target";

/// `path`'s normal components, lowercased on Windows; `None` for a relative path.
fn key(path: &Path) -> Option<Vec<String>> {
    if !path.is_absolute() {
        return None;
    }
    let mut out = Vec::new();
    for component in path.components() {
        let text = match component {
            Component::Normal(part) => part.to_string_lossy().into_owned(),
            Component::Prefix(prefix) => {
                // A verbatim prefix names the same volume (`\\?\C:` is `C:`).
                let text = prefix.as_os_str().to_string_lossy().into_owned();
                text.strip_prefix(r"\\?\").unwrap_or(&text).to_owned()
            }
            Component::RootDir | Component::CurDir => continue,
            // Never resolved lexically: a path with `..` is compared as it resolves on disk.
            Component::ParentDir => return None,
        };
        out.push(if cfg!(windows) {
            text.to_lowercase()
        } else {
            text
        });
    }
    Some(out)
}

/// The pure decision (module docs): whether `home` is under one of `roots` or
/// [`FIXED_ROOTS`], or inside a `target` directory. A relative `home` is never scratch (the
/// product refuses a relative Heimdall home before any key store).
#[must_use]
pub fn is_scratch_home(home: &Path, roots: &[PathBuf]) -> bool {
    let Some(home) = key(home) else {
        return false;
    };
    let build_dir = if cfg!(windows) {
        BUILD_DIR.to_lowercase()
    } else {
        BUILD_DIR.to_owned()
    };
    if home.contains(&build_dir) {
        return true;
    }
    let fixed = FIXED_ROOTS.iter().map(PathBuf::from);
    fixed.chain(roots.iter().cloned()).any(|root| {
        key(&root).is_some_and(|root| !root.is_empty() && home.starts_with(root.as_slice()))
    })
}

/// The temporary directories `var` names ([`TEMP_ENVS`]) and the process's own, each as
/// given and as it resolves on disk.
fn temp_roots(var: &dyn Fn(&str) -> Option<OsString>) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = TEMP_ENVS
        .iter()
        .filter_map(|name| var(name))
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .collect();
    roots.push(std::env::temp_dir());
    let resolved: Vec<PathBuf> = roots
        .iter()
        .filter_map(|r| std::fs::canonicalize(r).ok())
        .collect();
    roots.extend(resolved);
    roots
}

/// Whether `home` (the resolved Heimdall home) is scratch, as given or as it resolves on
/// disk; `var` is the process environment. Read-only; creates nothing.
#[must_use]
pub fn scratch_home(home: &Path, var: &dyn Fn(&str) -> Option<OsString>) -> bool {
    let roots = temp_roots(var);
    is_scratch_home(home, &roots)
        || std::fs::canonicalize(home).is_ok_and(|resolved| is_scratch_home(&resolved, &roots))
}

/// **The guard** for one key: `true` when this is a debug build, `home` is scratch
/// ([`scratch_home`]) and `fixture_env` is not set, so the platform store must not be
/// opened. `home` is the explicit Heimdall home when the caller resolved one (`--home`),
/// otherwise [`HOME_ENV`] is read through `var`. Always `false` in a release build.
#[must_use]
pub fn home_is_scratch(
    home: Option<&Path>,
    fixture_env: &str,
    var: &dyn Fn(&str) -> Option<OsString>,
) -> bool {
    #[cfg(debug_assertions)]
    {
        if var(fixture_env).is_some() {
            return false;
        }
        let from_env = var(HOME_ENV).map(PathBuf::from);
        home.or(from_env.as_deref())
            .is_some_and(|home| scratch_home(home, var))
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = (home, fixture_env, var);
        false
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    fn none(_: &str) -> Option<OsString> {
        None
    }

    #[cfg(unix)]
    #[test]
    fn scratch_is_a_temp_root_or_a_build_directory_by_whole_components() {
        let no_roots: [PathBuf; 0] = [];
        for scratch in [
            "/tmp/hm",
            "/private/tmp/hm/home",
            "/var/tmp/x",
            "/var/folders/ab/cd/T/hm",
            "/private/var/folders/ab/cd/T/hm",
            "/work/repo/target/m06/home",
            "/work/repo/target",
        ] {
            assert!(is_scratch_home(Path::new(scratch), &no_roots), "{scratch}");
        }
        for real in [
            "/tmpfoo/hm",
            "/home/someone/.local/state/heimdall",
            "/home/someone/targets/hm",
            "/var/lib/heimdall",
            "/",
            "relative/tmp",
            "/tmp/../home/someone",
        ] {
            assert!(!is_scratch_home(Path::new(real), &no_roots), "{real}");
        }
        // A temporary directory the environment names; a relative or empty root is ignored.
        let roots = [
            PathBuf::from("/scratch/t"),
            PathBuf::from("rel"),
            PathBuf::new(),
        ];
        assert!(is_scratch_home(Path::new("/scratch/t/hm"), &roots));
        assert!(!is_scratch_home(Path::new("/scratch/tt/hm"), &roots));
        assert!(!is_scratch_home(Path::new("/srv/hm"), &roots));
    }

    #[cfg(windows)]
    #[test]
    fn windows_compares_without_case_and_through_a_verbatim_prefix() {
        let roots = [PathBuf::from(r"C:\Users\someone\AppData\Local\Temp")];
        assert!(is_scratch_home(
            Path::new(r"c:\users\SOMEONE\appdata\local\temp\hm"),
            &roots
        ));
        assert!(is_scratch_home(
            Path::new(r"\\?\C:\Users\someone\AppData\Local\Temp\hm"),
            &roots
        ));
        assert!(is_scratch_home(Path::new(r"D:\repo\Target\hm"), &roots));
        assert!(!is_scratch_home(
            Path::new(r"C:\Users\someone\AppData\Local\Heimdall"),
            &roots
        ));
    }

    #[test]
    fn the_guard_needs_a_scratch_home_and_an_unset_fixture_variable() {
        let scratch = tempfile::tempdir().unwrap();
        let home = scratch.path().join("hm");
        // The explicit home (`--home`), with nothing in the environment.
        assert!(home_is_scratch(Some(&home), MGMT_FIXTURE_ENV, &none));
        assert!(home_is_scratch(Some(&home), IROH_FIXTURE_ENV, &none));
        // The home from the environment.
        let home_os = home.clone().into_os_string();
        let env_home = |n: &str| (n == HOME_ENV).then(|| home_os.clone());
        assert!(home_is_scratch(None, IROH_FIXTURE_ENV, &env_home));
        // Each key's own variable lifts the guard for that key only.
        let with_mgmt = |n: &str| match n {
            HOME_ENV => Some(home_os.clone()),
            MGMT_FIXTURE_ENV => Some("fixture-file:/x".into()),
            _ => None,
        };
        assert!(!home_is_scratch(None, MGMT_FIXTURE_ENV, &with_mgmt));
        assert!(home_is_scratch(None, IROH_FIXTURE_ENV, &with_mgmt));
        // No home at all: the default directories (the account-home guard is `heimdall`'s).
        assert!(!home_is_scratch(None, MGMT_FIXTURE_ENV, &none));
    }

    #[cfg(unix)]
    #[test]
    fn a_link_into_a_scratch_directory_is_scratch_and_a_named_temp_dir_counts() {
        // A directory named by TMPDIR only (outside every fixed root is not available to a
        // test, so the pure decision carries that case); here: the resolved form.
        let scratch = tempfile::tempdir().unwrap();
        let real = scratch.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let resolved = std::fs::canonicalize(&real).unwrap();
        assert!(scratch_home(&resolved, &none));
        let named = |n: &str| (n == "TMPDIR").then(|| OsString::from("/srv/scratch"));
        assert!(scratch_home(Path::new("/srv/scratch/hm"), &named));
        assert!(!scratch_home(Path::new("/srv/other/hm"), &named));
    }

    #[test]
    fn the_messages_name_their_variable() {
        assert!(MGMT_REFUSAL.contains(MGMT_FIXTURE_ENV));
        assert!(IROH_REFUSAL_DETAIL.contains(IROH_FIXTURE_ENV));
    }
}
