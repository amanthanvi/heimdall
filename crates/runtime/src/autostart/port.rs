//! The application's [`LoginEntryPort`] over a platform [`LoginHost`] (M04 U1): the
//! setup item `login_entry` and `inspect capabilities` → `login_start` read and write the
//! entry through this, never through a registry path or a plist.

use std::sync::Arc;

use heimdall_app::ports::{LoginEntryEffect, LoginEntryFailure, LoginEntryPort, LoginEntryState};
use heimdall_contract::environment::LoginStartKind;

use super::{
    EntryState, InstallOutcome, LoginCommand, LoginError, LoginHost, LoginKind, RemoveOutcome,
};

/// A host and the command its entry runs (the current executable, or none when that path
/// cannot be rendered: an install then fails with a fixed sentence).
#[derive(Debug)]
pub struct HostLoginPort {
    host: Arc<dyn LoginHost>,
    command: Option<LoginCommand>,
}

impl HostLoginPort {
    /// A port over `host` running `command`.
    #[must_use]
    pub fn new(host: Arc<dyn LoginHost>, command: Option<LoginCommand>) -> Self {
        Self { host, command }
    }

    /// The system host for `state_dir`'s installation (module [`super::system_host`]),
    /// running the current executable. `scratch_root` is the test root (no activation).
    #[must_use]
    pub fn system(state_dir: &std::path::Path, scratch_root: Option<&std::path::Path>) -> Self {
        let token = super::installation_token(state_dir);
        Self::new(
            super::system_host(&token, scratch_root),
            super::current_exe_command().ok(),
        )
    }

    fn command(&self) -> Result<&LoginCommand, LoginEntryFailure> {
        self.command.as_ref().ok_or_else(|| {
            LoginEntryFailure::Failed(
                "the executable's path cannot be used in a login entry".to_owned(),
            )
        })
    }
}

fn failure(e: LoginError) -> LoginEntryFailure {
    match e {
        LoginError::Conflict => LoginEntryFailure::Conflict,
        LoginError::NoUserManager => LoginEntryFailure::NoUserManager,
        other => LoginEntryFailure::Failed(other.to_string()),
    }
}

impl LoginEntryPort for HostLoginPort {
    fn kind(&self) -> LoginStartKind {
        match self.host.kind() {
            LoginKind::RunValue => LoginStartKind::RunValue,
            LoginKind::LaunchAgent => LoginStartKind::LaunchAgent,
            LoginKind::SystemdUser => LoginStartKind::SystemdUser,
            LoginKind::None => LoginStartKind::None,
        }
    }

    fn location(&self) -> String {
        self.host.location()
    }

    fn observe(&self) -> Result<LoginEntryState, LoginEntryFailure> {
        Ok(match self.host.observe().map_err(failure)? {
            EntryState::Absent => LoginEntryState::Absent,
            EntryState::Owned(_) => LoginEntryState::Owned,
            EntryState::Foreign => LoginEntryState::Foreign,
        })
    }

    fn render(&self) -> Result<String, LoginEntryFailure> {
        self.host.render(self.command()?).map_err(failure)
    }

    fn install(&self) -> Result<LoginEntryEffect, LoginEntryFailure> {
        Ok(match self.host.install(self.command()?).map_err(failure)? {
            InstallOutcome::Created => LoginEntryEffect::Created,
            InstallOutcome::Updated => LoginEntryEffect::Updated,
            InstallOutcome::Unchanged => LoginEntryEffect::Unchanged,
        })
    }

    fn remove(&self) -> Result<LoginEntryEffect, LoginEntryFailure> {
        Ok(match self.host.remove().map_err(failure)? {
            RemoveOutcome::Removed => LoginEntryEffect::Removed,
            RemoveOutcome::Absent => LoginEntryEffect::Absent,
        })
    }
}
