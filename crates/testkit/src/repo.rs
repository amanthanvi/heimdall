//! The repository root for tests that read repository files: schemas, golden files,
//! snapshots, documents, fixtures and the sources a static scan reads (ADR-0007 §12.32
//! item 3).
//!
//! [`repo_root`] honours [`ENV`] (`HM_REPO_ROOT`) at run time and otherwise falls back to
//! the compile-time path (the workspace root two levels above this crate's manifest). The
//! native harnesses set the variable to the copy of the repository they ship next to the
//! test binaries, so a test binary cross-built on one host reads its repository files on
//! another. A set variable that does not name an absolute directory is a test failure, never
//! a silent fall back to the compile-time path (that path may not exist on the run host, or
//! may hold a different tree).
//!
//! Every test that reads the repository resolves it here; the scan
//! `tests::no_other_test_reads_the_compile_time_root` fails on any other run-time use of
//! the manifest directory under `crates/` and `tests/`. Files embedded at compile time
//! (`include_str!`) are not run-time reads and stay as they are.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// The variable the native harnesses set to the shipped repository copy.
pub const ENV: &str = "HM_REPO_ROOT";

/// The workspace root at compile time.
fn compiled_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The repository root: `HM_REPO_ROOT` when set and not empty, else the compile-time root.
///
/// # Panics
/// When `HM_REPO_ROOT` is set to a path that is not absolute or is not a directory.
#[must_use]
pub fn repo_root() -> PathBuf {
    resolve(std::env::var_os(ENV), compiled_root()).unwrap_or_else(|e| panic!("{e}"))
}

/// `rel` under [`repo_root`].
///
/// # Panics
/// As [`repo_root`].
#[must_use]
pub fn repo_path(rel: impl AsRef<Path>) -> PathBuf {
    repo_root().join(rel)
}

/// The rule of [`repo_root`], over an explicit variable value and fallback (no process
/// environment), so it is testable without changing the environment.
///
/// # Errors
/// A message naming the variable (never its value) when the value is not an absolute
/// directory.
pub fn resolve(var: Option<OsString>, compiled: PathBuf) -> Result<PathBuf, String> {
    match var {
        Some(v) if !v.is_empty() => {
            let p = PathBuf::from(v);
            if !p.is_absolute() {
                return Err(format!("{ENV} is set but is not an absolute path"));
            }
            if !p.is_dir() {
                return Err(format!("{ENV} is set but does not name a directory"));
            }
            Ok(p)
        }
        _ => Ok(compiled),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_or_empty_is_the_compile_time_root() {
        let compiled = compiled_root();
        assert_eq!(resolve(None, compiled.clone()).unwrap(), compiled);
        assert_eq!(
            resolve(Some(OsString::new()), compiled.clone()).unwrap(),
            compiled
        );
        assert!(compiled.join("Cargo.toml").is_file());
        assert!(compiled.join("schemas").is_dir());
    }

    #[test]
    fn a_set_directory_wins_over_the_compile_time_root() {
        let dir = tempfile::tempdir().unwrap();
        let got = resolve(Some(dir.path().as_os_str().to_owned()), compiled_root()).unwrap();
        assert_eq!(got, dir.path());
    }

    #[test]
    fn a_set_value_that_is_not_an_absolute_directory_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, b"").unwrap();
        for bad in [
            OsString::from("relative/root"),
            dir.path().join("missing").into_os_string(),
            file.into_os_string(),
        ] {
            let e = resolve(Some(bad), compiled_root()).unwrap_err();
            assert!(e.starts_with(ENV), "{e}");
        }
    }

    /// Every run-time read of the repository goes through [`repo_root`]: no Rust source
    /// under `crates/` or `tests/` names the manifest directory except this module, and
    /// none names the hook binary's compile-time path except through
    /// `HookBinary::locate_or` (which honours `HM_FIXTURE_HOOK`). The scan reads the
    /// sources through [`repo_root`] too, so a shipped copy is scanned the same way.
    #[test]
    fn no_other_test_reads_the_compile_time_root() {
        let root = repo_root();
        let manifest = concat!("CARGO_", "MANIFEST_DIR");
        let hook = concat!("CARGO_BIN_EXE_", "hm-fixture-hook");
        let mut offenders = Vec::new();
        let mut scanned = 0usize;
        let mut stack = vec![root.join("crates"), root.join("tests")];
        while let Some(dir) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&dir) else {
                continue;
            };
            for e in rd.flatten() {
                let p = e.path();
                let Ok(ft) = e.file_type() else { continue };
                if ft.is_dir() {
                    // Build output, and the evidence artifacts (data, never tests).
                    if p.file_name().is_some_and(|n| n == "target")
                        || p == root.join("tests").join("evidence")
                    {
                        continue;
                    }
                    stack.push(p);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    let rel = p.strip_prefix(&root).unwrap_or(&p).to_path_buf();
                    if rel == Path::new("crates/testkit/src/repo.rs") {
                        continue;
                    }
                    scanned += 1;
                    let text = std::fs::read_to_string(&p).unwrap_or_default();
                    for (n, line) in text.lines().enumerate() {
                        let code = line.split("//").next().unwrap_or("");
                        let reads_root = code.contains(manifest);
                        let reads_hook = code.contains(hook) && !code.contains("locate_or");
                        if reads_root || reads_hook {
                            offenders.push(format!("{}:{}", rel.display(), n + 1));
                        }
                    }
                }
            }
        }
        assert!(
            scanned > 100,
            "scanned only {scanned} sources under {}",
            root.display()
        );
        offenders.sort();
        assert!(
            offenders.is_empty(),
            "read the repository through heimdall_testkit::repo::repo_root (HM_REPO_ROOT): {offenders:?}"
        );
    }
}
