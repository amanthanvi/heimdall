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
//!
//! ⟨M08 U1b; M06-F6, exit review R02⟩ Like every M06 launch of `ssh`, each run gets the
//! caller's [`OpensshEnvFill`] first and, on Windows, the client-environment guard
//! (`crate::remote_env::ssh::prepare_launch`): a Windows process without a usable `ProgramData`
//! gets it from the fill, and when the fill cannot supply it nothing is started and the hop is
//! unreadable (fail closed), never an `ssh -G` that exits 255 having printed nothing.

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

use crate::remote_env::ssh::OpensshEnvFill;

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

/// Run `client` with `args` (an `ssh -G` invocation) and return its standard output. `fill`
/// and the guard first (module docs): a refused environment starts nothing (`None`).
async fn effective_config(
    client: &Path,
    args: &[OsString],
    fill: OpensshEnvFill,
) -> Option<String> {
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
    crate::remote_env::ssh::prepare_launch(&mut command, fill).ok()?;
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
/// `None` when it could not be read (an invalid alias, a refused environment, a failed, slow
/// or oversized run). `fill`: the OpenSSH environment fill (module docs).
pub async fn effective_alias_config(
    client: &Path,
    config: Option<&Path>,
    alias: &str,
    fill: OpensshEnvFill,
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
    effective_config(client, &args, fill).await
}

/// Verify the projected `alias` (ADR-0012 §5.2): `client [-F config] -G alias` must meet
/// `expect`. `fill`: the OpenSSH environment fill (module docs).
///
/// # Errors
/// [`RouteVerifyError`] with [`Hop::Final`].
pub async fn verify_projected_alias(
    client: &Path,
    config: Option<&Path>,
    alias: &str,
    expect: &PinExpectation,
    fill: OpensshEnvFill,
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
    let text = effective_config(client, &args, fill)
        .await
        .ok_or(RouteVerifyError::Unreadable(Hop::Final))?;
    verify_effective(&text, expect).map_err(|defeated| RouteVerifyError::Defeated {
        hop: Hop::Final,
        defeated,
    })
}

/// Verify a jump leg's own effective configuration (ADR-0012 §5.2 "for the jump alias
/// too"): the client must honour every pin it is given. `fill`: the OpenSSH environment fill
/// (module docs).
///
/// # Errors
/// [`RouteVerifyError`] with `hop`.
pub async fn verify_jump_leg(
    client: &Path,
    hop_args: &JumpHop,
    hop: Hop,
    fill: OpensshEnvFill,
) -> Result<(), RouteVerifyError> {
    let args: Vec<OsString> = jump_leg_check_args(hop_args)
        .map_err(|_| RouteVerifyError::Invalid(hop))?
        .into_iter()
        .map(OsString::from)
        .collect();
    let text = effective_config(client, &args, fill)
        .await
        .ok_or(RouteVerifyError::Unreadable(hop))?;
    verify_effective(&text, &jump_leg_expectation(hop_args))
        .map_err(|defeated| RouteVerifyError::Defeated { hop, defeated })
}

/// Verify a helper route alias at both hops: the projected alias, then each jump leg, each
/// with `fill` (module docs).
///
/// # Errors
/// The first [`RouteVerifyError`].
pub async fn verify_helper_route(
    client: &Path,
    config: Option<&Path>,
    alias: &str,
    expect: &PinExpectation,
    jumps: &[JumpHop],
    fill: OpensshEnvFill,
) -> Result<(), RouteVerifyError> {
    verify_projected_alias(client, config, alias, expect, fill).await?;
    for (i, hop) in jumps.iter().enumerate() {
        verify_jump_leg(client, hop, Hop::Jump(i), fill).await?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub(crate) mod tests {
    use super::*;

    /// ⟨M08 U1b; M06-F6⟩ A stand-in for the operating system's fill (as `remote_env::ssh`'s
    /// tests use): sets `ProgramData` to a fixed value.
    #[cfg(unix)]
    pub(crate) fn stand_in_fill(command: &mut std::process::Command, inherits: bool) {
        assert!(inherits, "a route launch never clears its environment");
        command.env("ProgramData", "C:\\filled");
    }

    /// ⟨M08 U1b; M06-F6⟩ The documented default `ProgramData` (`%SystemDrive%\ProgramData`;
    /// Microsoft Learn, *KNOWNFOLDERID*) on the Windows directory's drive: a stand-in for the
    /// operating system's fill, which this crate cannot reach (`heimdall-localenv`).
    #[cfg(windows)]
    pub(crate) fn default_program_data_fill(command: &mut std::process::Command, inherits: bool) {
        assert!(inherits, "a route launch never clears its environment");
        let root = std::env::var("SystemRoot").unwrap_or_default();
        if let Some(drive) = root.get(..2).filter(|d| d.ends_with(':')) {
            command.env("ProgramData", format!("{drive}\\ProgramData"));
        }
    }

    /// ⟨M08 U1b; M06-F6⟩ The in-box Win32-OpenSSH client.
    #[cfg(windows)]
    pub(crate) fn inbox_client() -> std::path::PathBuf {
        let root = std::env::var_os("SystemRoot").expect("SystemRoot");
        std::path::PathBuf::from(root)
            .join("System32")
            .join("OpenSSH")
            .join("ssh.exe")
    }

    /// ⟨M08 U1b; M06-F6⟩ A jump hop to loopback port 1 (nothing listens there) whose every
    /// path is under `dir`; none of them need exist (`ssh -G` only parses them).
    pub(crate) fn hop(dir: &Path) -> JumpHop {
        let path = |name: &str| dir.join(name).to_string_lossy().replace('\\', "/");
        JumpHop {
            alias: "bastion".into(),
            hostname: "127.0.0.1".into(),
            port: Some(1),
            user: "jump".into(),
            host_key_alias: "hm-dest-bastion".into(),
            pin_file: path("pins"),
            host_key_algorithms: Some("ssh-ed25519".into()),
            identity_agent: path("agent.sock"),
            identity_file: path("id.pub"),
            certificate_file: None,
        }
    }

    /// ⟨M08 U1b; M06-F6, exit review R02⟩ Every route check's `ssh -G` applies its fill: the
    /// effective configuration, the final hop and a jump hop, each run against a stand-in
    /// client (a shell script, never a real `ssh`) that records the `ProgramData` it was
    /// given and prints it as its configuration. With the stand-in fill each run carries the
    /// filled value; with a fill that sets nothing, none does (this host's own environment
    /// has no `ProgramData`). The guard is Windows only
    /// ([`a_route_check_without_program_data_is_filled_or_starts_nothing`]).
    #[cfg(unix)]
    #[tokio::test]
    async fn every_route_check_carries_the_fill() {
        use std::os::unix::fs::PermissionsExt as _;

        use heimdall_registry::routes::ExpectedProxy;
        assert!(
            std::env::var_os("ProgramData").is_none(),
            "blocked: this host's environment sets ProgramData"
        );
        let dir = std::env::temp_dir().join(format!("hm-f6-verify-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("seen.txt");
        let client = dir.join("ssh");
        std::fs::write(
            &client,
            format!(
                "#!/bin/sh\nprintf 'ProgramData=%s\\n' \"${{ProgramData-unset}}\" >> '{}'\n\
                 printf 'programdata %s\\n' \"${{ProgramData-unset}}\"\nexit 0\n",
                log.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&client, std::fs::Permissions::from_mode(0o700)).unwrap();
        let config = dir.join("config");
        let expect = PinExpectation {
            host_key_alias: "hm-dest-final".into(),
            pin_file: dir.join("pins").to_string_lossy().into_owned(),
            owned_control_path: None,
            proxy: ExpectedProxy::None,
        };
        let mut seen = Vec::new();
        for (fill, want) in [
            (stand_in_fill as OpensshEnvFill, "C:\\filled"),
            (|_, _| {}, "unset"),
        ] {
            let _ = std::fs::remove_file(&log);
            let printed = effective_alias_config(&client, Some(&config), "final", fill).await;
            // The stand-in prints nothing an expectation accepts: each check reads it (never
            // `Unreadable`) and refuses it.
            let last = verify_projected_alias(&client, Some(&config), "final", &expect, fill).await;
            let jump = verify_jump_leg(&client, &hop(&dir), Hop::Jump(0), fill).await;
            let text = std::fs::read_to_string(&log).unwrap_or_default();
            seen.push((want, printed, last, jump, text));
        }
        let _ = std::fs::remove_dir_all(&dir);
        for (want, printed, last, jump, text) in seen {
            assert_eq!(printed, Some(format!("programdata {want}\n")));
            assert!(
                matches!(
                    last,
                    Err(RouteVerifyError::Defeated {
                        hop: Hop::Final,
                        ..
                    })
                ),
                "{last:?}"
            );
            assert!(
                matches!(
                    jump,
                    Err(RouteVerifyError::Defeated {
                        hop: Hop::Jump(0),
                        ..
                    })
                ),
                "{jump:?}"
            );
            let line = format!("ProgramData={want}");
            let lines: Vec<&str> = text.lines().collect();
            assert_eq!(
                lines,
                [line.as_str(); 3],
                "configuration, final hop, jump hop"
            );
        }
    }

    /// ⟨M08 U1b; M06-F6⟩ The child half of
    /// [`a_route_check_without_program_data_is_filled_or_starts_nothing`]: from this process's
    /// own environment (the parent removed `ProgramData` and `ALLUSERSPROFILE`), the in-box
    /// client's effective configuration of a scratch `-F` alias and a jump hop's check, with
    /// the stand-in fill and with a fill that sets nothing, printing what each read. Does
    /// nothing unless the parent set `HM_F6_CHILD`.
    #[cfg(windows)]
    #[tokio::test]
    #[ignore = "the child of a_route_check_without_program_data_is_filled_or_starts_nothing"]
    #[allow(clippy::print_stdout)]
    async fn f6_verify_child() {
        if std::env::var_os("HM_F6_CHILD").is_none() {
            return;
        }
        let ssh = inbox_client();
        let dir = std::env::temp_dir().join(format!("hm-f6-verify-win-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("config");
        std::fs::write(
            &config,
            "Host final\n    HostName 127.0.0.1\n    Port 1\n    IdentitiesOnly yes\n    \
             IdentityFile none\n    IdentityAgent none\n    CertificateFile none\n",
        )
        .unwrap();
        let mut said = Vec::new();
        for (name, fill) in [
            ("filled", default_program_data_fill as OpensshEnvFill),
            ("unfilled", |_, _| {}),
        ] {
            let read = effective_alias_config(&ssh, Some(&config), "final", fill)
                .await
                .is_some_and(|t| t.lines().any(|l| l.trim_end() == "hostname 127.0.0.1"));
            let jump = match verify_jump_leg(&ssh, &hop(&dir), Hop::Jump(0), fill).await {
                Ok(()) => "ok",
                Err(RouteVerifyError::Unreadable(_)) => "unreadable",
                Err(_) => "other",
            };
            said.push(format!("{name}={read}/{jump}"));
        }
        let _ = std::fs::remove_dir_all(&dir);
        // The parent reads this line.
        println!("f6-verify-child {} end", said.join(" "));
    }

    /// ⟨M08 U1b; M06-F6, exit review R02⟩ On Windows, a route check started from a process
    /// without `ProgramData` (as a stripped parent environment leaves it) gets the variable
    /// from its fill, so the in-box client reads the alias and the jump hop verifies; with a
    /// fill that cannot supply it, the guard starts nothing and both are unreadable (fail
    /// closed), never an `ssh -G` that exits 255 having printed nothing. This test binary
    /// re-runs itself without the variable. Ignored: it needs the in-box client, so it runs
    /// on the PC by exact name with `--ignored`.
    #[cfg(windows)]
    #[test]
    #[ignore = "needs the in-box OpenSSH client: run on the Windows PC by exact name"]
    fn a_route_check_without_program_data_is_filled_or_starts_nothing() {
        assert!(
            inbox_client().exists(),
            "blocked: the in-box OpenSSH client is not installed"
        );
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "routes::verify::tests::f6_verify_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("HM_F6_CHILD", "1")
            .env_remove("ProgramData")
            .env_remove("ALLUSERSPROFILE")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        // The harness may print the test's name on the same line first.
        let line = text
            .lines()
            .find(|l| l.contains("f6-verify-child "))
            .unwrap_or_default();
        assert!(
            line.contains("f6-verify-child filled=true/ok unfilled=false/unreadable end"),
            "{line}"
        );
    }
}
