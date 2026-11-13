//! ⟨ADR-0008 §17.25 item 7 (b)⟩ **Debug builds only**: a disposable store of a
//! **product** kind for tests, which the test creates in its scratch home and the test
//! configuration selects (`HEIMDALL_TEST_SECRET_STORE=product-file:<abs path>`, read by
//! the `heimdall` crate's `testcfg`):
//!
//! * **macOS:** `<path>` is a file keychain made by `SecKeychainCreate` by path
//!   ([`super::MacosLoginKeychain::create_disposable_file_keychain`]): never added to the
//!   search list, never the default, deleted by path. Its kind is
//!   `macos_login_keychain`, so the real registration, the passphrase step and the R2B
//!   deletion run on the keychain code path.
//! * **Windows:** `<path>` is the DPAPI blob directory ([`super::WindowsDpapi::in_dir`]).
//! * **Linux:** none (no disposable Secret Service exists): the selector is refused.
//!
//! **What the selector refuses** ([`refusal`]), so a test can never point it at the
//! owner's store:
//! 1. a relative path, or one with `.`/`..` components;
//! 2. a path whose canonical form is not strictly under the test's **scratch home**: the
//!    explicit `HEIMDALL_HOME` a test configuration already requires; a scratch home
//!    that is the account's home or one of its ancestors is refused too;
//! 3. any path with the components `Library/Keychains` (the user's keychains,
//!    wherever the account home is), or under the account home's `Library/Keychains`;
//! 4. a path that existed before the test created it. **Proof of creation:** the test
//!    creates [`marker_path`] first (exclusively, owner-only, its content naming the
//!    store, [`marker_contents`]) and only then the store, both through [`create`]; the
//!    selector requires the marker, a regular file (not a link), owner-only on Unix with
//!    the same owner as the scratch home and the store, and a marker birth time no later
//!    than the store's. A store that existed before its marker was made fails that
//!    order; a platform without birth times refuses (fail closed).
//!
//! A release build has none of this: the module is compiled out, and the `heimdall`
//! crate refuses every `HEIMDALL_TEST_*` variable first. Claims made through it stay
//! disqualified by the debug profile (ADR-0008 F03).

use std::path::{Component, Path, PathBuf};

/// The marker's suffix, appended to the store's path.
pub const MARKER_SUFFIX: &str = ".heimdall-test-store";

/// The marker's first line.
const MARKER_TAG: &str = "heimdall-test-product-store/1";

/// The marker of the store at `store`: `<store>` + [`MARKER_SUFFIX`].
#[must_use]
pub fn marker_path(store: &Path) -> PathBuf {
    let mut p = store.as_os_str().to_owned();
    p.push(MARKER_SUFFIX);
    PathBuf::from(p)
}

/// What the marker of `store` holds: the tag and the store's file name.
#[must_use]
pub fn marker_contents(store: &Path) -> String {
    let name = store
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    format!("{MARKER_TAG}\n{name}\n")
}

/// Whether a store at a path is a directory here (Windows DPAPI) or a file (a keychain).
const STORE_IS_DIR: bool = cfg!(windows);

/// Whether `path` has the consecutive components `Library`, `Keychains`.
fn names_keychains(path: &Path) -> bool {
    let parts: Vec<_> = path.components().collect();
    parts.windows(2).any(|w| {
        matches!(w, [Component::Normal(a), Component::Normal(b)]
            if a.eq_ignore_ascii_case("Library") && b.eq_ignore_ascii_case("Keychains"))
    })
}

/// Why `store` cannot be the test configuration's product store, or `None` when it
/// can (module docs: the four refusals). `scratch_home` is the explicit Heimdall home;
/// `account_home` the account database's home, when known. Nonsecret text.
#[must_use]
pub fn refusal(store: &Path, scratch_home: &Path, account_home: Option<&Path>) -> Option<String> {
    let refuse = |why: &str| Some(format!("the product-file test store {why}"));
    if !store.is_absolute() {
        return refuse("path must be absolute");
    }
    if store
        .components()
        .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
    {
        return refuse("path must not contain . or .. components");
    }
    if names_keychains(store) {
        return refuse("must not be under a Library/Keychains directory");
    }
    let (Some(parent), Some(name)) = (store.parent(), store.file_name()) else {
        return refuse("path has no file name");
    };
    let Ok(home) = scratch_home.canonicalize() else {
        return refuse("needs an existing explicit HEIMDALL_HOME (the test's scratch home)");
    };
    let Ok(parent) = parent.canonicalize() else {
        return refuse("must be in an existing directory");
    };
    let canonical = parent.join(name);
    if names_keychains(&canonical) {
        return refuse("must not be under a Library/Keychains directory");
    }
    if let Some(account) = account_home {
        let account = account
            .canonicalize()
            .unwrap_or_else(|_| account.to_path_buf());
        if account.starts_with(&home) {
            return refuse(
                "needs a scratch HEIMDALL_HOME that is not the account's home or one of its ancestors",
            );
        }
        if canonical.starts_with(account.join("Library").join("Keychains")) {
            return refuse("must not be under the account's Library/Keychains");
        }
    }
    if !canonical.starts_with(&home) || canonical == home {
        return refuse("must be inside the test's scratch home (HEIMDALL_HOME)");
    }
    // 4. Created by this test, after its marker.
    let Ok(meta) = std::fs::symlink_metadata(&canonical) else {
        return refuse("does not exist: the test creates it (with its marker) first");
    };
    if meta.file_type().is_symlink() || meta.is_dir() != STORE_IS_DIR {
        return refuse(if STORE_IS_DIR {
            "must be a directory, not a link"
        } else {
            "must be a regular file, not a link"
        });
    }
    let marker = marker_path(&canonical);
    let Ok(mark) = std::fs::symlink_metadata(&marker) else {
        return refuse("has no marker: it was not created by this test");
    };
    if !mark.file_type().is_file() {
        return refuse("marker must be a regular file, not a link");
    }
    match std::fs::read_to_string(&marker) {
        Ok(text) if text == marker_contents(&canonical) => {}
        _ => return refuse("marker does not name this store"),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let Ok(home_meta) = std::fs::metadata(&home) else {
            return refuse("needs an existing explicit HEIMDALL_HOME (the test's scratch home)");
        };
        if mark.mode() & 0o077 != 0 {
            return refuse("marker must be owner-only");
        }
        if mark.uid() != home_meta.uid() || meta.uid() != home_meta.uid() {
            return refuse("and its marker must belong to the scratch home's owner");
        }
    }
    match (mark.created(), meta.created()) {
        (Ok(m), Ok(s)) if m <= s => None,
        (Ok(_), Ok(_)) => refuse("existed before its marker: it was not created by this test"),
        _ => refuse("cannot be proven created by this test (no birth times here)"),
    }
}

/// Write the marker of `store` exclusively, owner-only.
#[cfg(any(target_os = "macos", windows, test))]
fn write_marker(store: &Path) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut f = options.open(marker_path(store))?;
    f.write_all(marker_contents(store).as_bytes())?;
    f.sync_all()
}

/// **The test's** creation of the store at `store` (module docs, refusal 4): refused when
/// the store or its marker exists; the marker first, then a file keychain protected by
/// `password` (in memory, never an argument; no lock timeout). A failed creation removes
/// the marker it made.
///
/// # Errors
/// [`super::StoreError::AlreadyExists`] when either exists; [`super::StoreError::Failed`].
#[cfg(target_os = "macos")]
pub fn create(store: &Path, password: &str) -> Result<(), super::StoreError> {
    if std::fs::symlink_metadata(store).is_ok()
        || std::fs::symlink_metadata(marker_path(store)).is_ok()
    {
        return Err(super::StoreError::AlreadyExists);
    }
    write_marker(store).map_err(|_| super::StoreError::Failed)?;
    super::MacosLoginKeychain::create_disposable_file_keychain(store, password).inspect_err(|_| {
        let _ = std::fs::remove_file(marker_path(store));
    })
}

/// **The test's** creation of the DPAPI directory at `store` (module docs, refusal 4):
/// refused when it or its marker exists; the marker first, then the directory.
///
/// # Errors
/// [`super::StoreError::AlreadyExists`] when either exists; [`super::StoreError::Failed`].
#[cfg(windows)]
pub fn create(store: &Path) -> Result<(), super::StoreError> {
    if std::fs::symlink_metadata(store).is_ok()
        || std::fs::symlink_metadata(marker_path(store)).is_ok()
    {
        return Err(super::StoreError::AlreadyExists);
    }
    write_marker(store).map_err(|_| super::StoreError::Failed)?;
    std::fs::create_dir(store).map_err(|_| {
        let _ = std::fs::remove_file(marker_path(store));
        super::StoreError::Failed
    })
}

/// **The test's** removal of the store at `store` and its marker: the keychain by path
/// (`SecKeychainDelete`), the DPAPI directory with its blobs. Only a store [`refusal`]
/// accepts under `scratch_home` is removed.
///
/// # Errors
/// [`super::StoreError::Failed`] when it is not such a store or cannot be removed.
#[cfg(any(target_os = "macos", windows))]
pub fn remove(store: &Path, scratch_home: &Path) -> Result<(), super::StoreError> {
    if refusal(store, scratch_home, None).is_some() {
        return Err(super::StoreError::Failed);
    }
    #[cfg(target_os = "macos")]
    super::MacosLoginKeychain::delete_disposable_file_keychain(store)?;
    #[cfg(windows)]
    std::fs::remove_dir_all(store).map_err(|_| super::StoreError::Failed)?;
    std::fs::remove_file(marker_path(store)).map_err(|_| super::StoreError::Failed)
}

/// The store at `store` (accepted by [`refusal`]) for `environment`: the platform's
/// product implementation at that path. `None` on Linux and where there is none.
#[must_use]
pub fn open(
    store: &Path,
    environment: &heimdall_contract::ids::EnvironmentId,
) -> Option<Box<dyn super::SecretStore>> {
    #[cfg(target_os = "macos")]
    {
        Some(Box::new(
            super::MacosLoginKeychain::disposable_file_keychain(store, environment),
        ))
    }
    #[cfg(windows)]
    {
        Some(Box::new(super::WindowsDpapi::in_dir(store, environment)))
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        let _ = (store, environment);
        None
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// A scratch home with a store "created by the test" at `name` (marker first).
    fn made(home: &Path, name: &str) -> PathBuf {
        let store = home.join(name);
        write_marker(&store).unwrap();
        if STORE_IS_DIR {
            std::fs::create_dir(&store).unwrap();
        } else {
            std::fs::write(&store, b"x").unwrap();
        }
        store
    }

    fn scratch() -> tempfile::TempDir {
        let dir = tempfile::Builder::new()
            .prefix("hm-is2-tp-")
            .tempdir()
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        dir
    }

    /// ⟨ADR-0008 §17.25 item 7 (b)⟩ The selector's four refusals, and its one acceptance.
    #[test]
    fn product_file_selector_refuses_exactly_the_four_cases() {
        let tmp = scratch();
        let home = tmp.path().join("hh");
        std::fs::create_dir(&home).unwrap();
        let account = tmp.path().join("account");
        std::fs::create_dir(&account).unwrap();
        let ok = made(&home, "t.keychain-db");
        assert_eq!(refusal(&ok, &home, Some(&account)), None);

        // 1. Relative, or with . / .. components.
        assert!(refusal(Path::new("t.keychain-db"), &home, None).is_some());
        let dotted = home.join("..").join("hh").join("t.keychain-db");
        assert!(refusal(&dotted, &home, None).unwrap().contains(".."));

        // 2. Outside the scratch home (and the home itself), or a home that is the
        // account's home or an ancestor of it.
        let outside = made(tmp.path(), "o.keychain-db");
        assert!(
            refusal(&outside, &home, None)
                .unwrap()
                .contains("scratch home")
        );
        assert!(refusal(&home, tmp.path(), None).is_some());
        let inner = account.join("in");
        std::fs::create_dir(&inner).unwrap();
        let under_account = made(&inner, "a.keychain-db");
        assert!(
            refusal(&under_account, &account, Some(&account))
                .unwrap()
                .contains("ancestors")
        );
        assert!(refusal(&ok, tmp.path(), Some(&account)).is_some());

        // 3. Any Library/Keychains, by name or under the account's.
        let kc = home.join("Library").join("Keychains");
        std::fs::create_dir_all(&kc).unwrap();
        let in_kc = made(&kc, "login.keychain-db");
        assert!(refusal(&in_kc, &home, None).unwrap().contains("Keychains"));

        // 4. Not created by this test: no marker, a marker naming another store, a
        // marker made after the store, a linked store.
        let bare = home.join("bare.keychain-db");
        if STORE_IS_DIR {
            std::fs::create_dir(&bare).unwrap();
        } else {
            std::fs::write(&bare, b"x").unwrap();
        }
        assert!(refusal(&bare, &home, None).unwrap().contains("marker"));
        assert!(
            refusal(&home.join("absent.keychain-db"), &home, None)
                .unwrap()
                .contains("does not exist")
        );
        let wrong = made(&home, "w.keychain-db");
        std::fs::write(
            marker_path(&wrong),
            "heimdall-test-product-store/1\nother\n",
        )
        .unwrap();
        assert!(refusal(&wrong, &home, None).unwrap().contains("marker"));
        std::thread::sleep(std::time::Duration::from_millis(20));
        write_marker(&bare).unwrap();
        assert!(
            refusal(&bare, &home, None)
                .unwrap()
                .contains("existed before its marker"),
            "a store older than its marker"
        );
        #[cfg(unix)]
        {
            let link = home.join("link.keychain-db");
            std::os::unix::fs::symlink(&ok, &link).unwrap();
            write_marker(&link).unwrap();
            assert!(refusal(&link, &home, None).is_some(), "a link");
            use std::os::unix::fs::PermissionsExt as _;
            let open = made(&home, "m.keychain-db");
            std::fs::set_permissions(marker_path(&open), std::fs::Permissions::from_mode(0o644))
                .unwrap();
            assert!(refusal(&open, &home, None).unwrap().contains("owner-only"));
        }
        // The accepted one is still accepted.
        assert_eq!(refusal(&ok, &home, Some(&account)), None);
    }
}
