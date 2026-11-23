//! ⟨M06 W5⟩ **Debug-build test store** for K_iroh in a scratch directory (fixture custody;
//! mechanism evidence only, never product persistence).
//!
//! `HEIMDALL_TEST_IROH_KEY_STORE=<absolute scratch dir>` ([`super::FIXTURE_STORE_ENV`];
//! `heimdall`'s `testcfg` refuses it in a release build like every `HEIMDALL_TEST_*`
//! variable) selects [`FileFixtureIrohStore`] over that directory, so the separate
//! processes of one test (a runtime, its serve child, the route helper) share one K_iroh
//! without the account's platform key store. The module is compiled only under
//! `debug_assertions`: a release build contains no file store for K_iroh (ADR-0012 §2.4
//! item 2 stands for the product).
//!
//! * **Kind:** [`IrohStoreKind::Test`] (`fixture_store`, [`super::FIXTURE_STORE_KIND`]), so
//!   the `transport_keys` row and everything derived from it say `fixture_store` and it can
//!   never satisfy a product-store claim.
//! * **No fallback in either direction** ([`super::requested_test_store`]): while the
//!   variable is set this store is the only one used; a value that is not an absolute path
//!   of an existing owner-only directory of this user makes every operation
//!   [`IrohStoreAvailability::Missing`] (`transport_key_store_unavailable`), and the
//!   platform store is never opened. While it is unset nothing here is reachable.
//! * **Files:** one `<endpoint>.key` per endpoint, created exclusively with mode `0600`,
//!   holding the store encoding. The directory is never created here (the test owns it).
//!   A lock flag `locked` in the directory stands in for a locked platform store.
//! * **Only K_iroh:** nothing else reads or writes the directory.
//! * **Unix only:** elsewhere (Windows) the store has no owner-only check and therefore
//!   refuses every operation the same way (`Missing`); it never falls back there either.

use std::path::{Path, PathBuf};

use heimdall_contract::ids::IrohEndpointId;

use super::{
    FIXTURE_STORE_KIND, ITEM_SERVICE, IrohKeyMaterial, IrohKeyStore, IrohStoreAvailability,
    IrohStoreError, IrohStoreKind,
};

/// The lock flag's file name in the store directory.
pub const LOCK_FLAG: &str = "locked";

/// The fixture K_iroh store of one scratch directory (module docs).
pub struct FileFixtureIrohStore {
    dir: PathBuf,
}

impl std::fmt::Debug for FileFixtureIrohStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // No path and no content.
        f.debug_struct("FileFixtureIrohStore")
            .field("availability", &self.availability())
            .finish_non_exhaustive()
    }
}

impl FileFixtureIrohStore {
    /// The store over `dir`. Nothing is created or read here; an unusable `dir` makes every
    /// operation `Unavailable(Missing)`.
    #[must_use]
    pub fn in_dir(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
        }
    }

    /// Whether the directory is usable: absolute, an existing directory (not a symbolic
    /// link) that this user can list and that grants nothing to the group or to others.
    fn usable(&self) -> bool {
        if !self.dir.is_absolute() {
            return false;
        }
        let Ok(meta) = std::fs::symlink_metadata(&self.dir) else {
            return false;
        };
        if !meta.is_dir() {
            return false;
        }
        owner_only(&meta) && std::fs::read_dir(&self.dir).is_ok()
    }

    fn check(&self) -> Result<(), IrohStoreError> {
        match self.availability() {
            IrohStoreAvailability::Available => Ok(()),
            other => Err(IrohStoreError::Unavailable(other)),
        }
    }

    fn item(&self, endpoint: &IrohEndpointId) -> PathBuf {
        // An endpoint ID is 64 lowercase hex characters: never a path component of its own.
        self.dir.join(format!("{}.key", endpoint.as_str()))
    }
}

/// Whether `meta` grants nothing to the group or to others. (Another user's owner-only
/// directory cannot be listed, which [`FileFixtureIrohStore::usable`] checks.)
#[cfg(unix)]
fn owner_only(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    meta.mode() & 0o077 == 0
}

/// Not Unix (Windows): this store has no owner-only check there, so it is never usable:
/// every operation refuses `Unavailable(Missing)` (`transport_key_store_unavailable`), and
/// the platform store is still never opened while the variable is set.
#[cfg(not(unix))]
fn owner_only(_meta: &std::fs::Metadata) -> bool {
    false
}

impl IrohKeyStore for FileFixtureIrohStore {
    fn kind(&self) -> IrohStoreKind {
        IrohStoreKind::Test(FIXTURE_STORE_KIND)
    }

    fn availability(&self) -> IrohStoreAvailability {
        if !self.usable() {
            IrohStoreAvailability::Missing
        } else if std::fs::symlink_metadata(self.dir.join(LOCK_FLAG)).is_ok() {
            IrohStoreAvailability::Locked
        } else {
            IrohStoreAvailability::Available
        }
    }

    fn store_ref(&self, endpoint: &IrohEndpointId) -> String {
        // The kind and the endpoint, never the directory.
        format!("{ITEM_SERVICE}/{FIXTURE_STORE_KIND}/{}", endpoint.as_str())
    }

    fn put(&self, endpoint: &IrohEndpointId, key: &IrohKeyMaterial) -> Result<(), IrohStoreError> {
        use std::io::Write as _;
        self.check()?;
        key.check_endpoint(endpoint)?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let path = self.item(endpoint);
        let mut file = options.open(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                IrohStoreError::AlreadyExists
            } else {
                IrohStoreError::Failed
            }
        })?;
        let written = file
            .write_all(&key.to_store_bytes())
            .and_then(|()| file.sync_all());
        if written.is_err() {
            // Never leave a partial item behind.
            let _ = std::fs::remove_file(&path);
            return Err(IrohStoreError::Failed);
        }
        Ok(())
    }

    fn load(&self, endpoint: &IrohEndpointId) -> Result<IrohKeyMaterial, IrohStoreError> {
        self.check()?;
        let path = self.item(endpoint);
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(IrohStoreError::NotFound);
            }
            Err(_) => return Err(IrohStoreError::Failed),
        };
        // A link, a directory or a file somebody else can read is not an item of ours.
        if !meta.is_file() || !owner_only(&meta) {
            return Err(IrohStoreError::Corrupt);
        }
        let bytes =
            zeroize::Zeroizing::new(std::fs::read(&path).map_err(|_| IrohStoreError::Failed)?);
        IrohKeyMaterial::from_store_bytes(&bytes, endpoint)
    }

    fn destroy(&self, endpoint: &IrohEndpointId) -> Result<(), IrohStoreError> {
        self.check()?;
        let path = self.item(endpoint);
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(IrohStoreError::NotFound);
            }
            Err(_) => return Err(IrohStoreError::Failed),
        }
        if std::fs::symlink_metadata(&path).is_ok() {
            return Err(IrohStoreError::Failed);
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::ffi::OsString;

    use super::super::{
        FIXTURE_STORE_ENV, UnsupportedIrohStore, create_key, doctor_finding, requested_test_store,
    };
    use super::*;

    fn owner_dir(parent: &Path, name: &str) -> PathBuf {
        let dir = parent.join(name);
        std::fs::create_dir(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        dir
    }

    /// Mechanism evidence only (fixture custody, kind `fixture_store`): a key is created,
    /// read back by another store object over the same directory (another process), never
    /// overwritten, kept in an owner-only file, and destroyed exactly.
    #[cfg(unix)]
    #[test]
    fn the_file_fixture_store_round_trips_across_objects_in_owner_only_files() {
        let scratch = tempfile::tempdir().unwrap();
        let dir = owner_dir(scratch.path(), "k");
        let store = FileFixtureIrohStore::in_dir(&dir);
        assert_eq!(store.kind(), IrohStoreKind::Test("fixture_store"));
        assert_eq!(store.kind().column(), "fixture_store");
        assert_eq!(store.kind().product(), None, "never a product claim");
        assert_eq!(doctor_finding(&store), None);

        let first = create_key(&store).unwrap();
        let second = create_key(&store).unwrap();
        assert_ne!(first, second);
        assert_eq!(
            store.store_ref(&first),
            format!("heimdall-iroh/fixture_store/{first}"),
            "the locator names no directory"
        );
        let other_process = FileFixtureIrohStore::in_dir(&dir);
        let loaded = other_process.load(&first).unwrap();
        assert_eq!(loaded.endpoint_id(), first);
        let copy = IrohKeyMaterial::from_bytes(*loaded.expose());
        assert_eq!(store.put(&first, &copy), Err(IrohStoreError::AlreadyExists));
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let mode = std::fs::metadata(dir.join(format!("{first}.key")))
                .unwrap()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // A key under another endpoint's name is corrupt, not a key.
        std::fs::copy(
            dir.join(format!("{first}.key")),
            dir.join(format!("{}.key", "0".repeat(64))),
        )
        .unwrap();
        let zero = IrohEndpointId::parse(&"0".repeat(64)).unwrap();
        assert_eq!(
            store.load(&zero).map(|_| ()),
            Err(IrohStoreError::Corrupt),
            "the stored key is not that endpoint's"
        );
        // The lock flag: unavailable while locked, nothing lost.
        std::fs::write(dir.join(LOCK_FLAG), b"").unwrap();
        assert_eq!(store.availability(), IrohStoreAvailability::Locked);
        assert_eq!(
            store.load(&first).map(|_| ()),
            Err(IrohStoreError::Unavailable(IrohStoreAvailability::Locked))
        );
        std::fs::remove_file(dir.join(LOCK_FLAG)).unwrap();
        // Destroy removes exactly that item.
        store.destroy(&first).unwrap();
        assert_eq!(
            store.load(&first).map(|_| ()),
            Err(IrohStoreError::NotFound)
        );
        assert_eq!(store.destroy(&first), Err(IrohStoreError::NotFound));
        assert_eq!(store.load(&second).unwrap().endpoint_id(), second);
    }

    /// Unix: a directory others can enter, and a symbolic link to a good one. Elsewhere:
    /// the good directory itself (the store refuses there, module docs).
    #[cfg(unix)]
    fn more_unusable(scratch: &Path, good: &Path) -> Vec<OsString> {
        use std::os::unix::fs::PermissionsExt as _;
        let open = owner_dir(scratch, "open");
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
        let link = scratch.join("link");
        std::os::unix::fs::symlink(good, &link).unwrap();
        vec![open.into_os_string(), link.into_os_string()]
    }

    #[cfg(not(unix))]
    fn more_unusable(_scratch: &Path, good: &Path) -> Vec<OsString> {
        vec![good.as_os_str().to_owned()]
    }

    /// Condition 2, first direction: with the variable set, only the fixture store is ever
    /// selected, and a missing or unusable directory is an error
    /// (`transport_key_store_unavailable`), never the platform store and never a directory
    /// created on the way.
    #[test]
    fn a_set_variable_selects_only_the_fixture_store_and_an_unusable_directory_is_an_error() {
        let scratch = tempfile::tempdir().unwrap();
        let good = owner_dir(scratch.path(), "good");
        let select = |value: &std::ffi::OsStr| {
            let value = value.to_owned();
            requested_test_store(&move |name: &str| {
                (name == FIXTURE_STORE_ENV).then(|| value.clone())
            })
            .expect("a set variable always selects a store")
        };
        let store = select(good.as_os_str());
        assert_eq!(store.kind(), IrohStoreKind::Test("fixture_store"));
        #[cfg(unix)]
        assert_eq!(store.availability(), IrohStoreAvailability::Available);

        let missing = scratch.path().join("missing");
        let file = scratch.path().join("file");
        std::fs::write(&file, b"").unwrap();
        let unusable: Vec<OsString> = [
            missing.clone().into_os_string(),
            file.into_os_string(),
            OsString::from("relative/dir"),
            OsString::new(),
        ]
        .into_iter()
        .chain(more_unusable(scratch.path(), &good))
        .collect();
        for value in unusable {
            let store = select(&value);
            assert_eq!(
                store.kind(),
                IrohStoreKind::Test("fixture_store"),
                "still the fixture store: no fallback to the platform store"
            );
            assert_eq!(store.availability(), IrohStoreAvailability::Missing);
            let err = create_key(store.as_ref()).unwrap_err();
            assert_eq!(
                err,
                IrohStoreError::Unavailable(IrohStoreAvailability::Missing)
            );
            assert_eq!(err.reason(), "transport_key_store_unavailable");
            let finding = doctor_finding(store.as_ref()).unwrap();
            assert_eq!(finding.reason, "transport_key_store_unavailable");
            let any = IrohEndpointId::parse(&"1".repeat(64)).unwrap();
            assert_eq!(
                store.load(&any).map(|_| ()),
                Err(IrohStoreError::Unavailable(IrohStoreAvailability::Missing))
            );
        }
        assert!(!missing.exists(), "the directory is never created");
    }

    /// Condition 2, second direction: with the variable unset no test store is selected at
    /// all (the caller goes to the platform store), whatever else the environment holds.
    #[test]
    fn an_unset_variable_selects_no_test_store() {
        assert!(requested_test_store(&|_| None).is_none());
        // (A Heimdall home that is not a scratch directory; the scratch case is the next
        // test. The variables naming a temporary directory are left unset, so the home is
        // not under one.)
        assert!(
            requested_test_store(&|name: &str| {
                (name != FIXTURE_STORE_ENV && !crate::scratch_guard::TEMP_ENVS.contains(&name))
                    .then(|| OsString::from("/srv/heimdall-home"))
            })
            .is_none()
        );
        // The store a release build answers with for a set variable refuses everything.
        assert_eq!(
            UnsupportedIrohStore.availability(),
            IrohStoreAvailability::Unsupported
        );
    }

    /// ⟨M06 W5, the 2026-11-22 incident⟩ A debug build under a scratch Heimdall home with
    /// the variable unset gets no platform store: the selected store refuses every
    /// operation, creates no key, and its detail names the variable. With the variable set
    /// the fixture store is selected as before.
    #[test]
    fn a_scratch_home_without_the_variable_is_refused_and_names_it() {
        let scratch = tempfile::tempdir().unwrap();
        let home = scratch.path().join("hm").into_os_string();
        let env = {
            let home = home.clone();
            move |name: &str| (name == crate::scratch_guard::HOME_ENV).then(|| home.clone())
        };
        let store = requested_test_store(&env).expect("the guard selects a refusing store");
        assert_eq!(store.kind(), IrohStoreKind::Test("fixture_store_required"));
        assert!(store.kind().product().is_none(), "never a product claim");
        assert_eq!(
            store.availability(),
            IrohStoreAvailability::FixtureStoreRequired
        );
        let err = create_key(store.as_ref()).unwrap_err();
        assert_eq!(
            err,
            IrohStoreError::Unavailable(IrohStoreAvailability::FixtureStoreRequired)
        );
        assert_eq!(err.reason(), "transport_key_store_unavailable");
        assert!(err.detail().contains(FIXTURE_STORE_ENV), "{}", err.detail());
        let any = IrohEndpointId::parse(&"1".repeat(64)).unwrap();
        assert!(store.load(&any).is_err());
        assert!(store.destroy(&any).is_err());
        // The same through the explicit home (`--home`), nothing in the environment.
        assert!(crate::iroh::scratch_home_refusal(Some(Path::new(&home)), &|_| None).is_some());
        // A home that is not scratch: the platform store (no test store is selected).
        assert!(
            requested_test_store(&|name: &str| {
                (name == crate::scratch_guard::HOME_ENV)
                    .then(|| OsString::from("/srv/heimdall-home"))
            })
            .is_none()
        );
        // The variable set: the fixture store and only it, scratch home or not.
        let dir = scratch.path().join("keys").into_os_string();
        let with_store = move |name: &str| match name {
            n if n == crate::scratch_guard::HOME_ENV => Some(home.clone()),
            n if n == FIXTURE_STORE_ENV => Some(dir.clone()),
            _ => None,
        };
        let fixture = requested_test_store(&with_store).unwrap();
        assert_eq!(fixture.kind(), IrohStoreKind::Test(FIXTURE_STORE_KIND));
    }
}
