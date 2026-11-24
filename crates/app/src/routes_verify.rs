//! ⟨M06 U5a⟩ The `ssh -G` verification of projected route aliases at both hops (ADR-0012
//! §5.2; m06-plan U5a), at projection time and in doctor.
//!
//! * **The final hop:** `ssh [-F <config>] -G <alias>` evaluates the alias as the user's own
//!   `ssh` will (an earlier `Host` or `Match` block included), and
//!   `heimdall_registry::routes::verify_effective` requires the catalog pin to hold
//!   effectively. Without `-F`, that is the user's and the system's configuration: the
//!   verification's subject is exactly the settings an isolation option would mask, so none
//!   is added.
//! * **The jump hop** of a helper route: `ssh -G -F none <the jump leg's pins> <jump alias>`
//!   (`heimdall_registry::routes::jump_leg_check_args`), the same client and the same pins
//!   the jump leg runs with.
//!
//! `ssh -G` connects to nothing. It runs non-interactively (`heimdall_app::no_window!`), with
//! `SSH_AUTH_SOCK`, `SSH_AGENT_PID`, `SSH_ASKPASS` and `SSH_ASKPASS_REQUIRE` removed, standard
//! input null, standard output bounded, and a time bound.

use std::ffi::OsString;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use heimdall_registry::routes::{
    HostPinDefeated, JumpHop, PinExpectation, jump_leg_check_args, jump_leg_expectation,
    verify_effective,
};
use heimdall_registry::step::alias_ok;
use tokio::io::AsyncReadExt as _;

/// The bound on one `ssh -G`.
pub const SSH_G_TIMEOUT: Duration = Duration::from_secs(20);

/// The bound on `ssh -G`'s output.
pub const SSH_G_OUTPUT_MAX: usize = 1 << 20;

/// Which hop a verification refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Hop {
    /// The projected alias itself (the final hop).
    Final,
    /// The helper route's jump hop (its index in the given hops).
    Jump(usize),
}

/// Why a route alias does not verify.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RouteVerifyError {
    /// The catalog pin does not hold effectively (`host_pin_defeated`, naming the setting).
    #[error("{hop:?}: {defeated}")]
    Defeated {
        /// The hop.
        hop: Hop,
        /// The setting.
        defeated: HostPinDefeated,
    },
    /// `ssh -G` could not be run, failed, timed out or printed too much (fail closed).
    #[error("{0:?}: the effective configuration could not be read")]
    Unreadable(Hop),
    /// The alias, or the jump leg's pins, could not be built.
    #[error("{0:?}: the alias or its pins are not valid literals")]
    Invalid(Hop),
}

/// Run `client` with `args` (an `ssh -G` invocation) and return its standard output.
async fn effective_config(client: &Path, args: &[OsString]) -> Option<String> {
    let mut command = crate::no_window!(tokio::process::Command::new(client));
    command
        .args(args)
        .env_remove("SSH_AUTH_SOCK")
        .env_remove("SSH_AGENT_PID")
        .env_remove("SSH_ASKPASS")
        .env_remove("SSH_ASKPASS_REQUIRE")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = command.spawn().ok()?;
    let mut stdout = child.stdout.take()?;
    let run = async {
        let mut out = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let n = stdout.read(&mut chunk).await.ok()?;
            if n == 0 {
                break;
            }
            if out.len() + n > SSH_G_OUTPUT_MAX {
                return None;
            }
            out.extend_from_slice(&chunk[..n]);
        }
        let status = child.wait().await.ok()?;
        status.success().then_some(out)
    };
    let out = tokio::time::timeout(SSH_G_TIMEOUT, run).await.ok()??;
    String::from_utf8(out).ok()
}

/// The effective configuration of `alias` as `client [-F config] -G alias` prints it;
/// `None` when it could not be read (an invalid alias, a failed, slow or oversized run).
pub async fn effective_alias_config(
    client: &Path,
    config: Option<&Path>,
    alias: &str,
) -> Option<String> {
    if !alias_ok(alias) {
        return None;
    }
    let mut args: Vec<OsString> = Vec::new();
    if let Some(config) = config {
        args.push("-F".into());
        args.push(config.into());
    }
    args.push("-G".into());
    args.push(alias.into());
    effective_config(client, &args).await
}

/// Verify the projected `alias` (ADR-0012 §5.2): `client [-F config] -G alias` must meet
/// `expect`.
///
/// # Errors
/// [`RouteVerifyError`] with [`Hop::Final`].
pub async fn verify_projected_alias(
    client: &Path,
    config: Option<&Path>,
    alias: &str,
    expect: &PinExpectation,
) -> Result<(), RouteVerifyError> {
    if !alias_ok(alias) {
        return Err(RouteVerifyError::Invalid(Hop::Final));
    }
    let mut args: Vec<OsString> = Vec::new();
    if let Some(config) = config {
        args.push("-F".into());
        args.push(config.into());
    }
    args.push("-G".into());
    args.push(alias.into());
    let text = effective_config(client, &args)
        .await
        .ok_or(RouteVerifyError::Unreadable(Hop::Final))?;
    verify_effective(&text, expect).map_err(|defeated| RouteVerifyError::Defeated {
        hop: Hop::Final,
        defeated,
    })
}

/// Verify a jump leg's own effective configuration (ADR-0012 §5.2 "for the jump alias
/// too"): the client must honour every pin it is given.
///
/// # Errors
/// [`RouteVerifyError`] with `hop`.
pub async fn verify_jump_leg(
    client: &Path,
    hop_args: &JumpHop,
    hop: Hop,
) -> Result<(), RouteVerifyError> {
    let args: Vec<OsString> = jump_leg_check_args(hop_args)
        .map_err(|_| RouteVerifyError::Invalid(hop))?
        .into_iter()
        .map(OsString::from)
        .collect();
    let text = effective_config(client, &args)
        .await
        .ok_or(RouteVerifyError::Unreadable(hop))?;
    verify_effective(&text, &jump_leg_expectation(hop_args))
        .map_err(|defeated| RouteVerifyError::Defeated { hop, defeated })
}

/// Verify a helper route alias at both hops: the projected alias, then each jump leg.
///
/// # Errors
/// The first [`RouteVerifyError`].
pub async fn verify_helper_route(
    client: &Path,
    config: Option<&Path>,
    alias: &str,
    expect: &PinExpectation,
    jumps: &[JumpHop],
) -> Result<(), RouteVerifyError> {
    verify_projected_alias(client, config, alias, expect).await?;
    for (i, hop) in jumps.iter().enumerate() {
        verify_jump_leg(client, hop, Hop::Jump(i)).await?;
    }
    Ok(())
}
