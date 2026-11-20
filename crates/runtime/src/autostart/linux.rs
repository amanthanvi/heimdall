//! Linux login autostart: the systemd user unit (M04 U1; ADR-0010 §6; m04-plan U1).
//! Owner: the M04 track.
//!
//! The unit is `<unit dir>/heimdall.service` (the unit directory is
//! `$XDG_CONFIG_HOME/systemd/user`, `~/.config/systemd/user` by default), enabled with
//! `systemctl --user enable heimdall.service` (`WantedBy=default.target`): it starts at
//! the next login of the user's manager. **Never** `--now` and never `loginctl
//! enable-linger`, so a host with no user session has no boot persistence (§6 item 2).
//! Disable is `systemctl --user disable`, then the unit file and its `wants` link are
//! removed, then a `daemon-reload`.
//!
//! **No user manager, no entry.** [`user_manager_available`] asks the user's manager
//! (`systemctl --user show-environment`, exit 0 only when it is reachable); without one
//! the system host is [`super::NoLoginHost`] and the runtime is `on_demand`.
//!
//! The file part (write, compare, replace, remove) is plain filesystem work against an
//! injected directory and is unit-tested anywhere; the activation is an injected
//! [`CommandRunner`] (`None`: file only).

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::render::{self, LoginCommand, SYSTEMD_UNIT_NAME};
use super::{
    ACTIVATION_TIMEOUT, CommandRunner, EntryState, InstallOutcome, LoginError, LoginHost,
    LoginKind, RemoveOutcome,
};

/// `systemctl`, by absolute path where the usual locations have it.
fn systemctl() -> &'static str {
    ["/usr/bin/systemctl", "/bin/systemctl"]
        .into_iter()
        .find(|p| Path::new(p).is_file())
        .unwrap_or("systemctl")
}

/// The user's unit directory: `$XDG_CONFIG_HOME/systemd/user` when that is absolute,
/// else `~/.config/systemd/user`.
#[must_use]
pub fn user_unit_dir() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| etcetera::home_dir().ok().map(|h| h.join(".config")))?;
    Some(base.join("systemd").join("user"))
}

/// Whether this user's systemd manager answers (the only host kind that gets an entry).
#[must_use]
pub fn user_manager_available(runner: &dyn CommandRunner) -> bool {
    runner
        .run(
            systemctl(),
            &["--user", "show-environment"],
            ACTIVATION_TIMEOUT,
        )
        .unwrap_or(false)
}

/// The systemd user-unit host.
#[derive(Debug)]
pub struct SystemdUserHost {
    unit_dir: PathBuf,
    runner: Option<Arc<dyn CommandRunner>>,
}

impl SystemdUserHost {
    /// A host over `unit_dir`; `runner` activates the unit (`None`: the file only, for
    /// scratch roots).
    #[must_use]
    pub fn new(unit_dir: &Path, runner: Option<Arc<dyn CommandRunner>>) -> Self {
        Self {
            unit_dir: unit_dir.to_owned(),
            runner,
        }
    }

    fn unit_path(&self) -> PathBuf {
        self.unit_dir.join(SYSTEMD_UNIT_NAME)
    }

    fn run(&self, args: &[&str]) -> Result<bool, LoginError> {
        match &self.runner {
            Some(r) => r
                .run(systemctl(), args, ACTIVATION_TIMEOUT)
                .map_err(|e| LoginError::Activation(format!("systemctl: {}", e.kind()))),
            None => Ok(true),
        }
    }

    /// The `default.target.wants` link `systemctl --user enable` makes, removed by hand
    /// only when it is a symlink (never a directory or a file of the user's).
    fn remove_wants_link(&self) {
        let link = self
            .unit_dir
            .join("default.target.wants")
            .join(SYSTEMD_UNIT_NAME);
        if std::fs::symlink_metadata(&link).is_ok_and(|m| m.file_type().is_symlink()) {
            let _ = std::fs::remove_file(link);
        }
    }
}

impl LoginHost for SystemdUserHost {
    fn kind(&self) -> LoginKind {
        LoginKind::SystemdUser
    }

    fn location(&self) -> String {
        self.unit_path().display().to_string()
    }

    fn render(&self, command: &LoginCommand) -> Result<String, LoginError> {
        Ok(render::systemd_unit(command))
    }

    fn observe(&self) -> Result<EntryState, LoginError> {
        Ok(match super::read_entry_file(&self.unit_path())? {
            None => EntryState::Absent,
            Some(Err(())) => EntryState::Foreign,
            Some(Ok(text)) => {
                render::owned_unit(&text).map_or(EntryState::Foreign, EntryState::Owned)
            }
        })
    }

    fn install(&self, command: &LoginCommand) -> Result<InstallOutcome, LoginError> {
        let data = render::systemd_unit(command);
        let path = self.unit_path();
        let outcome = match self.observe()? {
            EntryState::Foreign => return Err(LoginError::Conflict),
            EntryState::Owned(current) if &current == command => InstallOutcome::Unchanged,
            EntryState::Owned(_) => {
                super::replace(&path, data.as_bytes())?;
                InstallOutcome::Updated
            }
            EntryState::Absent => {
                std::fs::create_dir_all(&self.unit_dir)?;
                match super::write_new(&path, data.as_bytes()) {
                    Ok(()) => InstallOutcome::Created,
                    // A file appeared since the look: it is not ours.
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                        return Err(LoginError::Conflict);
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        };
        let activated = self.run(&["--user", "daemon-reload"]).and_then(|_| {
            if self.run(&["--user", "enable", SYSTEMD_UNIT_NAME])? {
                Ok(())
            } else {
                Err(LoginError::Activation("systemctl enable failed".to_owned()))
            }
        });
        if let Err(e) = activated {
            if outcome == InstallOutcome::Created {
                let _ = std::fs::remove_file(&path);
            }
            return Err(e);
        }
        Ok(outcome)
    }

    fn remove(&self) -> Result<RemoveOutcome, LoginError> {
        match self.observe()? {
            EntryState::Absent => Ok(RemoveOutcome::Absent),
            EntryState::Foreign => Err(LoginError::Conflict),
            EntryState::Owned(_) => {
                // A failed `disable` (the unit is not enabled, or no manager answers) does
                // not keep the file: the wants link is removed below either way.
                let _ = self.run(&["--user", "disable", SYSTEMD_UNIT_NAME]);
                self.remove_wants_link();
                std::fs::remove_file(self.unit_path())?;
                let _ = self.run(&["--user", "daemon-reload"]);
                Ok(RemoveOutcome::Removed)
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::Mutex;
    use std::time::Duration;

    use super::*;

    /// Records every command and answers from a script (default: success).
    #[derive(Debug, Default)]
    pub(crate) struct Recorder {
        pub calls: Mutex<Vec<String>>,
        pub fail: Mutex<Option<&'static str>>,
    }

    impl CommandRunner for Recorder {
        fn run(&self, _program: &str, args: &[&str], _t: Duration) -> io::Result<bool> {
            let line = args.join(" ");
            let fail = *self.fail.lock().unwrap();
            self.calls.lock().unwrap().push(line.clone());
            Ok(fail.is_none_or(|f| !line.contains(f)))
        }
    }

    fn command() -> LoginCommand {
        LoginCommand::new(Path::new("/opt/heimdall/bin/heimdall")).unwrap()
    }

    /// A scratch unit directory: the unit is written, read back as owned, replaced for
    /// another command, and removed with its commands in order; a foreign file at the
    /// name is never written over or removed; a failed `enable` leaves no unit behind.
    /// (The real `systemctl` row runs on a disposable WSL distribution.)
    #[test]
    fn systemd_user_host_installs_replaces_removes_and_never_touches_a_foreign_unit() {
        let dir = tempfile::tempdir().unwrap();
        let unit_dir = dir.path().join("systemd").join("user");
        let runner = Arc::new(Recorder::default());
        let host = SystemdUserHost::new(&unit_dir, Some(runner.clone()));
        assert_eq!(host.observe().unwrap(), EntryState::Absent);
        assert_eq!(host.install(&command()).unwrap(), InstallOutcome::Created);
        assert_eq!(host.observe().unwrap(), EntryState::Owned(command()));
        assert_eq!(host.install(&command()).unwrap(), InstallOutcome::Unchanged);
        let moved = LoginCommand::new(Path::new("/usr/local/bin/heimdall")).unwrap();
        assert_eq!(host.install(&moved).unwrap(), InstallOutcome::Updated);
        assert_eq!(host.observe().unwrap(), EntryState::Owned(moved));
        assert_eq!(host.remove().unwrap(), RemoveOutcome::Removed);
        assert_eq!(host.remove().unwrap(), RemoveOutcome::Absent);
        assert!(!unit_dir.join("heimdall.service").exists());
        let calls = runner.calls.lock().unwrap().clone();
        assert_eq!(
            calls,
            [
                // Created, then Unchanged (enable again: it heals a unit someone
                // disabled), then Updated.
                "--user daemon-reload",
                "--user enable heimdall.service",
                "--user daemon-reload",
                "--user enable heimdall.service",
                "--user daemon-reload",
                "--user enable heimdall.service",
                "--user disable heimdall.service",
                "--user daemon-reload",
            ]
        );
        assert!(
            calls
                .iter()
                .all(|c| !c.contains("linger") && !c.contains("--now")),
            "never lingering, never --now"
        );

        // A foreign unit at the name.
        let foreign = "[Service]\nExecStart=/bin/true\n";
        std::fs::write(unit_dir.join("heimdall.service"), foreign).unwrap();
        runner.calls.lock().unwrap().clear();
        assert_eq!(host.observe().unwrap(), EntryState::Foreign);
        assert!(matches!(
            host.install(&command()),
            Err(LoginError::Conflict)
        ));
        assert!(matches!(host.remove(), Err(LoginError::Conflict)));
        assert_eq!(
            std::fs::read_to_string(unit_dir.join("heimdall.service")).unwrap(),
            foreign
        );
        assert!(runner.calls.lock().unwrap().is_empty(), "no command ran");

        // A symlink at the name is foreign and is not followed.
        std::fs::remove_file(unit_dir.join("heimdall.service")).unwrap();
        let target = dir.path().join("elsewhere");
        std::fs::write(&target, render::systemd_unit(&command())).unwrap();
        std::os::unix::fs::symlink(&target, unit_dir.join("heimdall.service")).unwrap();
        assert_eq!(host.observe().unwrap(), EntryState::Foreign);
        assert!(matches!(host.remove(), Err(LoginError::Conflict)));
        assert!(target.exists());
        std::fs::remove_file(unit_dir.join("heimdall.service")).unwrap();

        // A failed `enable` removes the unit this call created.
        *runner.fail.lock().unwrap() = Some("enable");
        assert!(matches!(
            host.install(&command()),
            Err(LoginError::Activation(_))
        ));
        assert!(!unit_dir.join("heimdall.service").exists());
    }
}
