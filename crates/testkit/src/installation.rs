//! A second Heimdall installation (m03-plan U11 `installation::SecondInstallation`;
//! ADR-0008 §17.1 item 11, D13 item 2; F07). Feature `fixtures`.
//!
//! Foreign removal from a recovery bundle runs from an installation that did not make
//! the enrollment: its own `HEIMDALL_HOME` (so its own state database, catalog,
//! runtime directory and issuer store), its own scratch account home for the static
//! selection pass, and destination IDs from a prefix no first installation uses. The
//! fixture lays out the directories and composes the test-configuration environment;
//! the catalog itself is created through the binary under test (U10's e2e), with
//! [`SecondInstallation::destination_add_args`].

use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use crate::agent::random_hex;
use crate::home::Scratch;

/// The destination-ID prefix of a first installation's fixtures (`sshd::TwoHosts`, …).
pub const FIRST_PREFIX: &str = "hm-fx-";
/// The destination-ID prefix of a [`SecondInstallation`].
pub const SECOND_PREFIX: &str = "hm-fx2-";

/// One installation's scratch layout and environment.
#[derive(Debug)]
pub struct SecondInstallation {
    root: PathBuf,
    home: PathBuf,
    ssh_home: PathBuf,
    tag: String,
    next: AtomicU32,
}

impl SecondInstallation {
    /// Lay out `<scratch>/inst<n>/{home,ssh-home/.ssh}` (owner-only).
    ///
    /// # Errors
    /// A directory cannot be created.
    pub fn new(scratch: &Scratch) -> io::Result<SecondInstallation> {
        let root = scratch.subdir("inst")?;
        let home = root.join("home");
        let ssh_home = root.join("ssh-home");
        for d in [&home, &ssh_home, &ssh_home.join(".ssh")] {
            fs::create_dir(d)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(d, fs::Permissions::from_mode(0o700))?;
            }
        }
        Ok(SecondInstallation {
            root,
            home,
            ssh_home,
            tag: random_hex(4),
            next: AtomicU32::new(1),
        })
    }

    /// The installation's root directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Its `HEIMDALL_HOME`.
    #[must_use]
    pub fn heimdall_home(&self) -> &Path {
        &self.home
    }

    /// Its state directory (`<home>/state`, where the catalog's database lives;
    /// `heimdall_runtime::Paths::under`).
    #[must_use]
    pub fn state_dir(&self) -> PathBuf {
        self.home.join("state")
    }

    /// Its runtime directory (`<home>/run`).
    #[must_use]
    pub fn runtime_dir(&self) -> PathBuf {
        self.home.join("run")
    }

    /// Its scratch account home for the static selection pass
    /// (`HEIMDALL_TEST_SSH_HOME`).
    #[must_use]
    pub fn ssh_home(&self) -> &Path {
        &self.ssh_home
    }

    /// A fresh destination ID of this installation: `hm-fx2-<tag>-<n>`.
    #[must_use]
    pub fn destination_id(&self) -> String {
        let n = self.next.fetch_add(1, Ordering::Relaxed);
        format!("{SECOND_PREFIX}{}-{n}", self.tag)
    }

    /// The environment of the binary under test for this installation: exactly
    /// `HEIMDALL_HOME`, `HEIMDALL_TEST_SSH_HOME` and `HEIMDALL_TEST_SECRET_STORE=scratch`
    /// (add the rest of the test configuration as the test needs).
    #[must_use]
    pub fn env(&self) -> Vec<(OsString, OsString)> {
        vec![
            ("HEIMDALL_HOME".into(), self.home.clone().into_os_string()),
            (
                "HEIMDALL_TEST_SSH_HOME".into(),
                self.ssh_home.clone().into_os_string(),
            ),
            ("HEIMDALL_TEST_SECRET_STORE".into(), "scratch".into()),
        ]
    }

    /// `destination add <alias> --hostname … --port … --account … --identity … --id
    /// <destination>` for the binary under test.
    #[must_use]
    pub fn destination_add_args(
        alias: &str,
        destination: &str,
        hostname: &str,
        port: u16,
        account: &str,
        identity: &str,
    ) -> Vec<OsString> {
        [
            "destination",
            "add",
            alias,
            "--hostname",
            hostname,
            "--port",
            &port.to_string(),
            "--account",
            account,
            "--identity",
            identity,
            "--id",
            destination,
        ]
        .iter()
        .map(OsString::from)
        .collect()
    }
}
