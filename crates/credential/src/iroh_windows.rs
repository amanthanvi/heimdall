//! `WindowsDpapiIroh` (ADR-0012 §2.4; m06-plan U56): K_iroh protected with DPAPI for the
//! current user (`CryptProtectData`, never `CRYPTPROTECT_LOCAL_MACHINE`), with Heimdall
//! entropy bound to the environment ID and the endpoint ID and `CRYPTPROTECT_UI_FORBIDDEN`,
//! one blob file `<endpoint ID>.dpapi` per endpoint, created exclusively with a
//! **protected owner-only DACL** in a directory created owner-only. The product directory
//! is `%LOCALAPPDATA%\Heimdall\iroh\<environment ID>` ([`WindowsDpapiIroh::default_dir`],
//! the local, non-roaming application data, one directory per installation); a run with
//! `HEIMDALL_HOME` in scratch passes a scratch directory ([`WindowsDpapiIroh::in_dir`]),
//! which is still the product store kind.
//!
//! The blob holds DPAPI ciphertext only: this is not a plaintext or owner-only key file
//! (spec §7.3). DPAPI never prompts here, and there is no plaintext fallback: an unprotect
//! that fails is an error, never a file. `put` never overwrites, and `destroy` removes
//! exactly that endpoint's blob.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use heimdall_contract::ids::{EnvironmentId, IrohEndpointId};
use heimdall_contract::issuer::StoreKind;

use super::{
    IrohKeyMaterial, IrohKeyStore, IrohStoreAvailability, IrohStoreError, IrohStoreKind, item_label,
};
use crate::mgmt::windows::{BlobOpenError, DirState, dir_state, open_blob};
use crate::sys::windows as sys;

/// The fixed part of the DPAPI entropy (the environment ID, then the fixed-length endpoint
/// ID, follow it).
const ENTROPY_PREFIX: &[u8] = b"heimdall-iroh/1 K_iroh dpapi entropy\0";
/// The blob file's extension.
const BLOB_EXTENSION: &str = "dpapi";
/// The largest blob read (a protected 56-byte secret is a few hundred bytes).
const BLOB_MAX_BYTES: u64 = 64 * 1024;

/// The Windows DPAPI K_iroh store of one installation.
#[derive(Debug, Clone)]
pub struct WindowsDpapiIroh {
    dir: PathBuf,
    environment: EnvironmentId,
}

impl WindowsDpapiIroh {
    /// The product directory of the installation `environment`,
    /// `%LOCALAPPDATA%\Heimdall\iroh\<environment ID>` (one per installation).
    ///
    /// # Errors
    /// [`IrohStoreError::Unavailable`] (`missing`) when `LOCALAPPDATA` is unset or not
    /// absolute.
    pub fn default_dir(environment: &EnvironmentId) -> Result<PathBuf, IrohStoreError> {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .ok_or(IrohStoreError::Unavailable(IrohStoreAvailability::Missing))?;
        Ok(base
            .join("Heimdall")
            .join("iroh")
            .join(environment.as_str()))
    }

    /// The store whose blobs live in `dir` ([`Self::default_dir`], or a directory under a
    /// scratch `HEIMDALL_HOME`).
    #[must_use]
    pub fn in_dir(dir: impl Into<PathBuf>, environment: &EnvironmentId) -> Self {
        Self {
            dir: dir.into(),
            environment: environment.clone(),
        }
    }

    /// The blob directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// `endpoint`'s blob file, `<endpoint ID>.dpapi` (an endpoint ID is 64 lowercase hex
    /// characters, so it is always a plain file name).
    #[must_use]
    pub fn blob_path(&self, endpoint: &IrohEndpointId) -> PathBuf {
        self.dir
            .join(format!("{}.{BLOB_EXTENSION}", endpoint.as_str()))
    }

    /// The DACL of `path` as SDDL, read without following a reparse point (for the
    /// owner-only check and `doctor`).
    ///
    /// # Errors
    /// The OS error.
    pub fn dacl_sddl(path: &Path) -> std::io::Result<String> {
        sys::dacl_sddl(path)
    }

    /// The protected owner-only DACL a blob carries (`D:P(A;;FA;;;<user SID>)`).
    ///
    /// # Errors
    /// The OS error (the process token cannot be read).
    pub fn expected_blob_dacl() -> std::io::Result<String> {
        Ok(sys::owner_only_dacl(&sys::current_user_sid()?, false))
    }

    fn entropy(&self, endpoint: &IrohEndpointId) -> Vec<u8> {
        let mut e = ENTROPY_PREFIX.to_vec();
        e.extend_from_slice(self.environment.as_str().as_bytes());
        e.extend_from_slice(endpoint.as_str().as_bytes());
        e
    }

    /// ⟨M06-W2-R04⟩ The store directory itself, never what a reparse point names (as
    /// the K_mgmt store: `crate::mgmt::windows::dir_state`).
    fn ensure_dir(&self) -> Result<(), IrohStoreError> {
        match dir_state(&self.dir) {
            DirState::Plain => return Ok(()),
            DirState::Refused => return Err(IrohStoreError::Failed),
            DirState::Absent => {}
        }
        if let Some(parent) = self.dir.parent() {
            std::fs::create_dir_all(parent).map_err(|_| IrohStoreError::Failed)?;
        }
        match sys::create_owner_only_dir(&self.dir) {
            Ok(()) => Ok(()),
            Err(e)
                if e.kind() == std::io::ErrorKind::AlreadyExists
                    && dir_state(&self.dir) == DirState::Plain =>
            {
                Ok(())
            }
            Err(_) => Err(IrohStoreError::Failed),
        }
    }
}

impl IrohKeyStore for WindowsDpapiIroh {
    fn kind(&self) -> IrohStoreKind {
        IrohStoreKind::Product(StoreKind::WindowsDpapi)
    }

    fn availability(&self) -> IrohStoreAvailability {
        match std::fs::symlink_metadata(&self.dir) {
            Ok(m) if m.is_dir() => IrohStoreAvailability::Available,
            Ok(_) => IrohStoreAvailability::Corrupt,
            // The directory is created, owner-only, by the first `put`.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => IrohStoreAvailability::Available,
            Err(_) => IrohStoreAvailability::Missing,
        }
    }

    fn store_ref(&self, endpoint: &IrohEndpointId) -> String {
        item_label(&self.environment, endpoint)
    }

    fn put(&self, endpoint: &IrohEndpointId, key: &IrohKeyMaterial) -> Result<(), IrohStoreError> {
        key.check_endpoint(endpoint)?;
        match self.availability() {
            IrohStoreAvailability::Available => {}
            other => return Err(IrohStoreError::Unavailable(other)),
        }
        self.ensure_dir()?;
        let path = self.blob_path(endpoint);
        if std::fs::symlink_metadata(&path).is_ok() {
            return Err(IrohStoreError::AlreadyExists);
        }
        let secret = key.to_store_bytes();
        // The blob's description carries the label (the item's identity).
        let sealed = sys::protect(
            &secret,
            &self.entropy(endpoint),
            &item_label(&self.environment, endpoint),
        )
        .map_err(|_| IrohStoreError::Failed)?;
        drop(secret);
        let mut file = sys::create_owner_only_new(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                IrohStoreError::AlreadyExists
            } else {
                IrohStoreError::Failed
            }
        })?;
        let written = file.write_all(&sealed).and_then(|()| file.sync_all());
        drop(file);
        if written.is_err() {
            // Our own just-created, incomplete blob: leave no half-written item behind.
            let _ = std::fs::remove_file(&path);
            return Err(IrohStoreError::Failed);
        }
        Ok(())
    }

    fn load(&self, endpoint: &IrohEndpointId) -> Result<IrohKeyMaterial, IrohStoreError> {
        // ⟨M06-W2-R04⟩ The directory and the blob themselves, never through a link.
        if dir_state(&self.dir) == DirState::Refused {
            return Err(IrohStoreError::Failed);
        }
        let file = match open_blob(&self.blob_path(endpoint)) {
            Ok(f) => f,
            Err(BlobOpenError::NotFound) => return Err(IrohStoreError::NotFound),
            Err(BlobOpenError::NotRegular) => return Err(IrohStoreError::Corrupt),
            Err(BlobOpenError::Failed) => return Err(IrohStoreError::Failed),
        };
        let mut sealed = Vec::new();
        file.take(BLOB_MAX_BYTES + 1)
            .read_to_end(&mut sealed)
            .map_err(|_| IrohStoreError::Failed)?;
        if u64::try_from(sealed.len()).unwrap_or(u64::MAX) > BLOB_MAX_BYTES {
            return Err(IrohStoreError::Corrupt);
        }
        let secret = sys::unprotect(&sealed, &self.entropy(endpoint))
            .map_err(|_| IrohStoreError::Corrupt)?;
        IrohKeyMaterial::from_store_bytes(&secret, endpoint)
    }

    fn destroy(&self, endpoint: &IrohEndpointId) -> Result<(), IrohStoreError> {
        let path = self.blob_path(endpoint);
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
    use super::*;
    use crate::iroh::create_key;

    fn environment() -> EnvironmentId {
        EnvironmentId::from_random_bytes([6; 16])
    }

    /// Mechanism evidence only (a scratch directory standing in for
    /// `%LOCALAPPDATA%\Heimdall\iroh\<environment ID>`; the owner's DPAPI items are never
    /// touched): round trip, `put` never overwrites, two endpoints keep independent blobs,
    /// a blob holds no plaintext key and carries the protected owner-only DACL, another
    /// installation's entropy does not decrypt it, and destroy removes exactly that blob.
    /// Compile-checked on non-Windows hosts; run only on native Windows.
    #[test]
    fn iroh_dpapi_round_trip_owner_only_and_bound() {
        let scratch = tempfile::tempdir().unwrap();
        let dir = scratch.path().join("iroh").join(environment().as_str());
        let store = WindowsDpapiIroh::in_dir(&dir, &environment());
        assert_eq!(
            store.kind(),
            IrohStoreKind::Product(StoreKind::WindowsDpapi)
        );
        assert_eq!(store.kind().column(), "dpapi");
        assert_eq!(store.availability(), IrohStoreAvailability::Available);

        let key = IrohKeyMaterial::generate().unwrap();
        let endpoint = key.endpoint_id();
        assert_eq!(
            store.load(&endpoint).map(|_| ()),
            Err(IrohStoreError::NotFound)
        );
        assert_eq!(store.destroy(&endpoint), Err(IrohStoreError::NotFound));
        store.put(&endpoint, &key).unwrap();
        assert_eq!(
            store.put(&endpoint, &IrohKeyMaterial::from_bytes(*key.expose())),
            Err(IrohStoreError::AlreadyExists)
        );
        assert_eq!(store.load(&endpoint).unwrap().expose(), key.expose());
        let second = create_key(&store).unwrap();
        assert_ne!(second, endpoint);

        let blob = std::fs::read(store.blob_path(&endpoint)).unwrap();
        let secret = key.to_store_bytes();
        assert!(!blob.windows(secret.len()).any(|w| w == secret.as_slice()));
        assert!(!blob.windows(32).any(|w| w == key.expose()));
        assert_eq!(
            WindowsDpapiIroh::dacl_sddl(&store.blob_path(&endpoint)).unwrap(),
            WindowsDpapiIroh::expected_blob_dacl().unwrap()
        );

        let other_env = EnvironmentId::from_random_bytes([7; 16]);
        let other = WindowsDpapiIroh::in_dir(&dir, &other_env);
        assert_eq!(
            other.load(&endpoint).map(|_| ()),
            Err(IrohStoreError::Corrupt)
        );

        store.destroy(&endpoint).unwrap();
        assert_eq!(
            store.load(&endpoint).map(|_| ()),
            Err(IrohStoreError::NotFound)
        );
        assert_eq!(store.load(&second).unwrap().endpoint_id(), second);
        store.destroy(&second).unwrap();
    }

    /// ⟨M06-W2-R04; Windows job 23⟩ Mechanism evidence only (scratch directories; run only
    /// on native Windows, compile-checked elsewhere), as the K_mgmt store's test: a blob
    /// path that is not a regular file is `Corrupt` (a directory, a file symlink), a store
    /// path that is not a plain directory is refused (a directory symlink, a junction), and
    /// nothing is read through a link. Every sub-case is judged on its own; one that
    /// cannot be set up says so on standard error.
    #[test]
    fn iroh_reparse_points_and_non_regular_entries_are_never_followed() {
        use crate::mgmt::windows::test_links::{
            SubCases, dir_symlink, file_symlink, junction, skipped,
        };
        const TEST: &str = "iroh_reparse_points_and_non_regular_entries_are_never_followed";
        let mut cases = SubCases::default();
        let scratch = tempfile::tempdir().unwrap();
        let key = IrohKeyMaterial::generate().unwrap();
        let endpoint = key.endpoint_id();
        // A real store elsewhere, holding a valid blob for the same environment.
        let real = scratch.path().join("real");
        let real_store = WindowsDpapiIroh::in_dir(&real, &environment());
        real_store.put(&endpoint, &key).unwrap();
        let blob_name = real_store
            .blob_path(&endpoint)
            .file_name()
            .unwrap()
            .to_owned();
        let load = |dir: &Path| {
            WindowsDpapiIroh::in_dir(dir, &environment())
                .load(&endpoint)
                .map(|_| ())
        };
        cases.check("the real store loads", &load(&real), &Ok(()));

        // A directory where the blob should be.
        let odd = scratch.path().join("odd");
        std::fs::create_dir_all(odd.join(&blob_name)).unwrap();
        cases.check(
            "a directory at the blob's name is corrupt",
            &load(&odd),
            &Err(IrohStoreError::Corrupt),
        );

        // A file symlink at the blob's name, to the real blob.
        let via = scratch.path().join("via");
        std::fs::create_dir(&via).unwrap();
        if file_symlink(&real.join(&blob_name), &via.join(&blob_name)) {
            let mark = cases.failures();
            cases.check(
                "a file symlink at the blob's name is corrupt, never followed",
                &load(&via),
                &Err(IrohStoreError::Corrupt),
            );
            cases.ran(mark, "iroh", "file-symlink");
        } else {
            skipped(
                TEST,
                "file symlink at the blob's name",
                "no privilege to create symbolic links",
            );
        }

        // A directory symlink, and a junction, at the store directory's path.
        let linked = scratch.path().join("linked");
        if dir_symlink(&real, &linked) {
            let mark = cases.failures();
            let store = WindowsDpapiIroh::in_dir(&linked, &environment());
            cases.check(
                "a directory symlink is refused",
                &dir_state(&linked),
                &DirState::Refused,
            );
            cases.check(
                "a store behind a directory symlink is not loaded",
                &store.load(&endpoint).map(|_| ()),
                &Err(IrohStoreError::Failed),
            );
            cases.check(
                "a store behind a directory symlink is not created into",
                &store.ensure_dir(),
                &Err(IrohStoreError::Failed),
            );
            cases.ran(mark, "iroh", "directory-symlink");
        } else {
            skipped(
                TEST,
                "directory symlink at the store directory",
                "no privilege to create symbolic links",
            );
        }
        let joined = scratch.path().join("joined");
        if junction(&real, &joined) {
            let mark = cases.failures();
            let store = WindowsDpapiIroh::in_dir(&joined, &environment());
            cases.check(
                "a junction is refused",
                &dir_state(&joined),
                &DirState::Refused,
            );
            cases.check(
                "a store behind a junction is not loaded",
                &store.load(&endpoint).map(|_| ()),
                &Err(IrohStoreError::Failed),
            );
            cases.check(
                "a store behind a junction is not created into",
                &store.ensure_dir(),
                &Err(IrohStoreError::Failed),
            );
            cases.ran(mark, "iroh", "junction");
        } else {
            skipped(
                TEST,
                "junction at the store directory",
                "mklink /J did not create one",
            );
        }
        cases.finish();
    }
}
