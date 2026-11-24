//! ⟨M06 U5a⟩ The direct and jump legs of the route helper (ADR-0012 §5.4, §5.5; ADR-0010 §5
//! items 1–4). [`TokioLegDialer`] refuses the Iroh leg; ⟨M06 U56⟩ [`RouteLegDialer`] adds it
//! through an [`IrohLegDialer`] port (the runtime's, over `heimdall-transport-iroh`).
//! ⟨M06 exit, Q-B⟩ In a build without the `iroh` feature [`RouteLegDialer`] reports the Iroh
//! leg as [`DialFailure::DriverUnavailable`] (failed over; a destination whose every leg is
//! Iroh is refused `driver_unavailable` by `heimdall_app::routes::route_connect`).
//!
//! * **Direct:** a TCP connect to the route's `host:port`, bounded by the connect timeout.
//! * **Jump:** `ssh -F none <the jump's catalog pin and access> -W <final host>:<port> <jump
//!   alias>` (`heimdall_registry::routes::jump_leg_args`), a non-interactive child
//!   (`heimdall_app::no_window!`, ruling I-24) with `SSH_AUTH_SOCK`, `SSH_AGENT_PID`,
//!   `SSH_ASKPASS` and `SSH_ASKPASS_REQUIRE` removed from its environment, its standard
//!   streams piped and killed on drop. Its standard error is kept (bounded) to tell a
//!   host-key or authentication failure, which is never failed over, from a refusal, which
//!   is; it is then relayed to the helper's own standard error when asked.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use heimdall_contract::ids::IrohEndpointId;
use heimdall_contract::route::ExposurePolicy;
use heimdall_registry::routes::{JumpHop, jump_leg_args, jump_leg_failure_is_terminal};
use tokio::io::AsyncReadExt as _;

use super::failover::{DialFailure, Leg, LegDialer, LegEnd, LegEnding};
use super::{LegPlan, PlannedRoute};

/// How long a jump leg's `ssh` gets to exit once its stream has ended.
pub const JUMP_EXIT_BOUND: Duration = Duration::from_secs(5);

/// The bound on a jump leg's kept standard error.
pub const JUMP_STDERR_MAX: usize = 64 * 1024;

/// The production dialer: direct TCP and the jump leg's `ssh`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokioLegDialer {
    /// The `ssh` client the jump leg runs (an absolute path).
    pub ssh_client: PathBuf,
    /// Relay a jump leg's standard error to this process's own once it ends.
    pub relay_jump_stderr: bool,
}

#[async_trait]
impl LegDialer for TokioLegDialer {
    async fn dial(
        &self,
        route: &PlannedRoute,
        connect_timeout: Duration,
    ) -> Result<Leg, DialFailure> {
        match &route.leg {
            LegPlan::Direct { host, port } => dial_direct(host, *port, connect_timeout).await,
            LegPlan::Jump {
                hop: Some(hop),
                final_host,
                final_port,
                ..
            } => self.dial_jump(hop, final_host, *final_port),
            // No pin and access resolved, or an Iroh route (U56): never connected here.
            LegPlan::Jump { hop: None, .. } | LegPlan::Iroh { .. } => Err(DialFailure::Refused),
        }
    }
}

/// A TCP connect to `host:port` within `timeout`.
///
/// # Errors
/// [`DialFailure::Timeout`] past the bound, [`DialFailure::Refused`] otherwise.
pub async fn dial_direct(host: &str, port: u16, timeout: Duration) -> Result<Leg, DialFailure> {
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect((host, port))).await {
        Err(_) => Err(DialFailure::Timeout),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::TimedOut => Err(DialFailure::Timeout),
        Ok(Err(_)) => Err(DialFailure::Refused),
        Ok(Ok(stream)) => {
            let _ = stream.set_nodelay(true);
            let (reader, writer) = stream.into_split();
            Ok(Leg {
                reader: Box::new(reader),
                writer: Box::new(writer),
                ending: None,
            })
        }
    }
}

impl TokioLegDialer {
    fn dial_jump(
        &self,
        hop: &JumpHop,
        final_host: &str,
        final_port: u16,
    ) -> Result<Leg, DialFailure> {
        let args = jump_leg_args(hop, final_host, final_port).map_err(|_| DialFailure::Refused)?;
        let mut command = crate::no_window!(tokio::process::Command::new(&self.ssh_client));
        command
            .args(&args)
            .env_remove("SSH_AUTH_SOCK")
            .env_remove("SSH_AGENT_PID")
            .env_remove("SSH_ASKPASS")
            .env_remove("SSH_ASKPASS_REQUIRE")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = command.spawn().map_err(|_| DialFailure::Refused)?;
        let (Some(stdin), Some(stdout), Some(mut stderr)) =
            (child.stdin.take(), child.stdout.take(), child.stderr.take())
        else {
            return Err(DialFailure::Refused);
        };
        let captured = Arc::new(Mutex::new(Vec::new()));
        let sink = captured.clone();
        let stderr_task = tokio::spawn(async move {
            let mut chunk = [0u8; 4096];
            loop {
                match stderr.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let mut kept = sink
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let room = JUMP_STDERR_MAX.saturating_sub(kept.len());
                        kept.extend_from_slice(&chunk[..n.min(room)]);
                    }
                }
            }
        });
        Ok(Leg {
            reader: Box::new(stdout),
            writer: Box::new(stdin),
            ending: Some(Box::new(JumpEnding {
                child,
                stderr_task: Some(stderr_task),
                captured,
                relay: self.relay_jump_stderr,
                result: None,
            })),
        })
    }
}

/// The jump leg's `ssh` child.
struct JumpEnding {
    child: tokio::process::Child,
    stderr_task: Option<tokio::task::JoinHandle<()>>,
    captured: Arc<Mutex<Vec<u8>>>,
    relay: bool,
    result: Option<LegEnd>,
}

impl JumpEnding {
    async fn finish(&mut self, kill_first: bool) -> LegEnd {
        if let Some(r) = self.result {
            return r;
        }
        if kill_first {
            let _ = self.child.start_kill();
        }
        let status = match tokio::time::timeout(JUMP_EXIT_BOUND, self.child.wait()).await {
            Ok(Ok(status)) => Some(status),
            _ => {
                let _ = self.child.kill().await;
                None
            }
        };
        if let Some(task) = self.stderr_task.take() {
            let _ = tokio::time::timeout(Duration::from_secs(1), task).await;
        }
        let text = {
            let kept = self
                .captured
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            String::from_utf8_lossy(&kept).into_owned()
        };
        if self.relay && !text.is_empty() {
            let _ = std::io::stderr().write_all(text.as_bytes());
        }
        let r = LegEnd {
            success: !kill_first && status.is_some_and(|s| s.success()),
            terminal: jump_leg_failure_is_terminal(&text),
            admission_refused: false,
        };
        self.result = Some(r);
        r
    }
}

#[async_trait]
impl LegEnding for JumpEnding {
    async fn end(&mut self) -> LegEnd {
        self.finish(false).await
    }

    async fn abort(&mut self) -> LegEnd {
        self.finish(true).await
    }
}

// --- ⟨M06 U56⟩ the Iroh leg ----------------------------------------------------------------

/// One Iroh leg to dial: the approved route's endpoint, recorded addresses and exposure
/// policy (ADR-0012 §2.1: every address, relay and hint comes from these alone).
#[derive(Debug, Clone, Copy)]
pub struct IrohLegTarget<'a> {
    /// The serving endpoint.
    pub endpoint: &'a IrohEndpointId,
    /// The route record's direct addresses (`ip:port`).
    pub direct_addresses: &'a [String],
    /// The route's effective exposure policy.
    pub exposure: &'a ExposurePolicy,
    /// An adopted stock roost (ADR-0012 §2.8).
    pub external_roost: bool,
}

/// Dials an Iroh leg (`/pigeons/0`). Implemented by the runtime over
/// `heimdall-transport-iroh` with this host's K_iroh; `heimdall-app` never imports the
/// transport. Every failure before a stream exists is a [`DialFailure`] that is failed over
/// (refused: a policy refusal, no verified key store, no bind; timeout; an admission refusal
/// seen while dialing). The returned [`Leg`]'s ending reports a later admission refusal
/// ([`LegEnd::admission_refused`]).
#[async_trait]
pub trait IrohLegDialer: Send + Sync {
    /// Dial `target` within `connect_timeout`.
    async fn dial_iroh(
        &self,
        target: IrohLegTarget<'_>,
        connect_timeout: Duration,
    ) -> Result<Leg, DialFailure>;
}

/// The helper's dialer: the direct and jump legs through `base` (normally
/// [`TokioLegDialer`]), the Iroh leg through `iroh`. Without an Iroh dialer an Iroh route is
/// failed over: [`DialFailure::DriverUnavailable`] when the build has no Iroh driver
/// (`iroh_in_build` false), [`DialFailure::Refused`] when it has one but no verified key
/// store. Direct and jump routes are unaffected (ADR-0012 §2.4 item 3).
#[derive(Clone)]
pub struct RouteLegDialer<D> {
    /// The direct and jump legs.
    pub base: D,
    /// The Iroh leg.
    pub iroh: Option<Arc<dyn IrohLegDialer>>,
    /// ⟨M06 exit, Q-B⟩ This build has the Iroh driver (the `iroh` feature;
    /// `heimdall_runtime::supervise_transport::ROUTE_IROH_IN_BUILD`).
    pub iroh_in_build: bool,
}

impl<D> RouteLegDialer<D> {
    fn iroh_driver_missing(&self, route: &PlannedRoute) -> bool {
        matches!(route.leg, LegPlan::Iroh { .. }) && self.iroh.is_none() && !self.iroh_in_build
    }
}

impl<D: std::fmt::Debug> std::fmt::Debug for RouteLegDialer<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouteLegDialer")
            .field("base", &self.base)
            .field("iroh", &self.iroh.is_some())
            .field("iroh_in_build", &self.iroh_in_build)
            .finish()
    }
}

#[async_trait]
impl<D: LegDialer> LegDialer for RouteLegDialer<D> {
    async fn dial(
        &self,
        route: &PlannedRoute,
        connect_timeout: Duration,
    ) -> Result<Leg, DialFailure> {
        match (&route.leg, &self.iroh) {
            (
                LegPlan::Iroh {
                    endpoint,
                    direct_addresses,
                    exposure,
                    external_roost,
                },
                Some(iroh),
            ) => {
                iroh.dial_iroh(
                    IrohLegTarget {
                        endpoint,
                        direct_addresses,
                        exposure,
                        external_roost: *external_roost,
                    },
                    connect_timeout,
                )
                .await
            }
            (LegPlan::Iroh { .. }, None) if self.iroh_driver_missing(route) => {
                Err(DialFailure::DriverUnavailable)
            }
            (LegPlan::Iroh { .. }, None) => Err(DialFailure::Refused),
            _ => self.base.dial(route, connect_timeout).await,
        }
    }

    fn driver_unavailable(&self, route: &PlannedRoute) -> bool {
        match route.leg {
            LegPlan::Iroh { .. } => self.iroh_driver_missing(route),
            _ => self.base.driver_unavailable(route),
        }
    }
}
