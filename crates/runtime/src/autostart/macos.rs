//! macOS login autostart: the LaunchAgent (M04 U1; ADR-0010 §6; m04-plan U1). Owner: the
//! M04 track.
//!
//! The plist is `<LaunchAgents dir>/<label>.plist` (`~/Library/LaunchAgents`), with
//! `RunAtLoad` and `KeepAlive` on an unsuccessful exit only, loaded with `launchctl
//! bootstrap gui/<uid> <plist>` and unloaded with `launchctl bootout gui/<uid>/<label>`
//! (the modern verbs; never the deprecated `load`/`unload`). The directory, the label,
//! the uid and the runner are injected: a test boots a scratch plist with a unique label
//! into the real `gui/<uid>` domain and always boots it out again (the one allowed
//! exception, m04-plan §0), and everything else runs with no runner.
//!
//! The file part is plain filesystem work and is unit-tested with a recording runner.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::render::{self, LoginCommand};
use super::{
    ACTIVATION_TIMEOUT, CommandRunner, EntryState, InstallOutcome, LoginError, LoginHost,
    LoginKind, RemoveOutcome,
};

/// `launchctl`'s absolute path.
const LAUNCHCTL: &str = "/bin/launchctl";

/// `~/Library/LaunchAgents`.
#[must_use]
pub fn launch_agents_dir() -> Option<PathBuf> {
    etcetera::home_dir()
        .ok()
        .map(|h| h.join("Library").join("LaunchAgents"))
}

/// The LaunchAgent host.
#[derive(Debug)]
pub struct LaunchAgentHost {
    dir: PathBuf,
    label: String,
    uid: u32,
    runner: Option<Arc<dyn CommandRunner>>,
}

impl LaunchAgentHost {
    /// A host over `dir` for `label`, in the launchd domain `gui/<uid>`; `runner`
    /// activates the agent (`None`: the plist only).
    #[must_use]
    pub fn new(dir: &Path, label: &str, uid: u32, runner: Option<Arc<dyn CommandRunner>>) -> Self {
        Self {
            dir: dir.to_owned(),
            label: label.to_owned(),
            uid,
            runner,
        }
    }

    fn plist_path(&self) -> PathBuf {
        self.dir.join(format!("{}.plist", self.label))
    }

    fn domain(&self) -> String {
        format!("gui/{}", self.uid)
    }

    fn run(&self, args: &[&str]) -> Result<bool, LoginError> {
        match &self.runner {
            Some(r) => r
                .run(LAUNCHCTL, args, ACTIVATION_TIMEOUT)
                .map_err(|e| LoginError::Activation(format!("launchctl: {}", e.kind()))),
            None => Ok(true),
        }
    }

    fn bootout(&self) {
        // Not loaded is an ordinary answer (exit 3 or 113): ignored.
        let _ = self.run(&["bootout", &format!("{}/{}", self.domain(), self.label)]);
    }
}

impl LoginHost for LaunchAgentHost {
    fn kind(&self) -> LoginKind {
        LoginKind::LaunchAgent
    }

    fn location(&self) -> String {
        self.plist_path().display().to_string()
    }

    fn render(&self, command: &LoginCommand) -> Result<String, LoginError> {
        Ok(render::launch_agent_plist(&self.label, command))
    }

    fn observe(&self) -> Result<EntryState, LoginError> {
        Ok(match super::read_entry_file(&self.plist_path())? {
            None => EntryState::Absent,
            Some(Err(())) => EntryState::Foreign,
            Some(Ok(text)) => render::owned_plist(&text, &self.label)
                .map_or(EntryState::Foreign, EntryState::Owned),
        })
    }

    fn install(&self, command: &LoginCommand) -> Result<InstallOutcome, LoginError> {
        let data = render::launch_agent_plist(&self.label, command);
        let path = self.plist_path();
        let outcome = match self.observe()? {
            EntryState::Foreign => return Err(LoginError::Conflict),
            EntryState::Owned(current) if &current == command => InstallOutcome::Unchanged,
            EntryState::Owned(_) => {
                self.bootout();
                super::replace(&path, data.as_bytes())?;
                InstallOutcome::Updated
            }
            EntryState::Absent => {
                std::fs::create_dir_all(&self.dir)?;
                match super::write_new(&path, data.as_bytes()) {
                    Ok(()) => InstallOutcome::Created,
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                        return Err(LoginError::Conflict);
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        };
        let plist = path.display().to_string();
        if !self.run(&["bootstrap", &self.domain(), &plist])? {
            if outcome == InstallOutcome::Created {
                let _ = std::fs::remove_file(&path);
            }
            return Err(LoginError::Activation(
                "launchctl bootstrap failed".to_owned(),
            ));
        }
        Ok(outcome)
    }

    fn remove(&self) -> Result<RemoveOutcome, LoginError> {
        match self.observe()? {
            EntryState::Absent => Ok(RemoveOutcome::Absent),
            EntryState::Foreign => Err(LoginError::Conflict),
            EntryState::Owned(_) => {
                self.bootout();
                std::fs::remove_file(self.plist_path())?;
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

    #[derive(Debug, Default)]
    struct Recorder {
        calls: Mutex<Vec<String>>,
        bootstrap_ok: Mutex<bool>,
    }

    impl CommandRunner for Recorder {
        fn run(&self, program: &str, args: &[&str], _t: Duration) -> io::Result<bool> {
            assert_eq!(program, "/bin/launchctl");
            self.calls.lock().unwrap().push(args.join(" "));
            Ok(args[0] != "bootstrap" || *self.bootstrap_ok.lock().unwrap())
        }
    }

    /// The agent's file and its `launchctl` verbs, on a scratch directory with a
    /// recording runner: `bootstrap gui/<uid> <plist>` to load, `bootout
    /// gui/<uid>/<label>` to unload (also before replacing), a foreign plist at the
    /// label's path never touched, and a failed bootstrap leaving no plist. (The real
    /// launchd row is `login_entry_install_remove_round_trip`.)
    #[test]
    fn launch_agent_host_uses_bootstrap_and_bootout_and_leaves_a_foreign_plist_alone() {
        let dir = tempfile::tempdir().unwrap();
        let runner = Arc::new(Recorder::default());
        *runner.bootstrap_ok.lock().unwrap() = true;
        let host =
            LaunchAgentHost::new(dir.path(), "io.example.hm-test", 501, Some(runner.clone()));
        let command = LoginCommand::new(Path::new("/usr/bin/true")).unwrap();
        assert_eq!(host.install(&command).unwrap(), InstallOutcome::Created);
        assert_eq!(host.observe().unwrap(), EntryState::Owned(command.clone()));
        let moved = LoginCommand::new(Path::new("/bin/echo")).unwrap();
        assert_eq!(host.install(&moved).unwrap(), InstallOutcome::Updated);
        assert_eq!(host.remove().unwrap(), RemoveOutcome::Removed);
        assert_eq!(host.remove().unwrap(), RemoveOutcome::Absent);
        let plist = dir.path().join("io.example.hm-test.plist");
        assert!(!plist.exists());
        let calls = runner.calls.lock().unwrap().clone();
        let p = plist.display();
        assert_eq!(
            calls,
            [
                format!("bootstrap gui/501 {p}"),
                "bootout gui/501/io.example.hm-test".to_owned(),
                format!("bootstrap gui/501 {p}"),
                "bootout gui/501/io.example.hm-test".to_owned(),
            ]
        );

        std::fs::write(&plist, "<plist><dict/></plist>").unwrap();
        runner.calls.lock().unwrap().clear();
        assert!(matches!(host.install(&command), Err(LoginError::Conflict)));
        assert!(matches!(host.remove(), Err(LoginError::Conflict)));
        assert_eq!(
            std::fs::read_to_string(&plist).unwrap(),
            "<plist><dict/></plist>"
        );
        assert!(runner.calls.lock().unwrap().is_empty());
        std::fs::remove_file(&plist).unwrap();

        *runner.bootstrap_ok.lock().unwrap() = false;
        assert!(matches!(
            host.install(&command),
            Err(LoginError::Activation(_))
        ));
        assert!(!plist.exists());
    }
}
