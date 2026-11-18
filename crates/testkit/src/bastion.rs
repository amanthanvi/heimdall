//! A bastion fixture: two `LoopbackSshd`s, one the jump host and one the final host (M04 U6;
//! ADR-0010 §5; m04-plan U6). Owner: the M04 track.
//!
//! * The **jump** allows TCP forwarding administratively (`AllowTcpForwarding yes`) but only
//!   to the final host's port (`PermitOpen 127.0.0.1:<final port>`), so the jump's own
//!   `sshd` limit is the operative one (ADR-0010 §5 option (d): reported, not enforced by
//!   Heimdall). Its authorized-keys lines carry `restrict,port-forwarding`, so the existing-
//!   access positive control is not prohibited by its own fixture (ADR-0010 §9 item 8); a
//!   certificate's forwarding is still decided by its `permit-port-forwarding` extension.
//! * The **final host** allows no forwarding, as every other fixture.
//! * Optionally both allow agent forwarding administratively (`AllowAgentForwarding yes`), so
//!   what stops `ssh -A` is the certificate's `permit-agent-forwarding` extension alone.
//!
//! Local sshd only: a harness server (Windows, WSL) cannot honour forwarding settings, so
//! [`Bastion::start`] is [`SshdUnavailable`] there (never silently ignored).

use ssh_key::PublicKey;

use crate::home::Scratch;
use crate::sshd::{LOOPBACK, LoopbackSshd, SshdConfig, SshdUnavailable};

/// How a [`Bastion`] is configured.
#[derive(Debug, Clone, Default)]
pub struct BastionOptions {
    /// Both hosts: `AllowAgentForwarding yes`.
    pub agent_forwarding: bool,
    /// Authorized (existing-access) public keys of the jump host, for an existing-access
    /// jump hop. The final host never takes one.
    pub jump_authorized: Vec<PublicKey>,
}

/// A jump host and the final host it may open connections to.
#[derive(Debug)]
pub struct Bastion {
    /// The jump host (declared first: stopped first).
    pub jump: LoopbackSshd,
    /// The final host.
    pub target: LoopbackSshd,
}

impl Bastion {
    /// Start both hosts (module docs). Both keep an account-form registry (an empty seed)
    /// for the test to append its `cert-authority` lines to.
    ///
    /// # Errors
    /// [`SshdUnavailable`].
    pub fn start(scratch: &Scratch, options: BastionOptions) -> Result<Bastion, SshdUnavailable> {
        // The final host first: the jump's `PermitOpen` names its port.
        let target = LoopbackSshd::start(
            scratch,
            SshdConfig {
                registry_seed: Some(Vec::new()),
                agent_forwarding: options.agent_forwarding,
                ..SshdConfig::default()
            },
        )?;
        let jump = LoopbackSshd::start(
            scratch,
            SshdConfig {
                authorized: options.jump_authorized,
                registry_seed: Some(Vec::new()),
                tcp_forwarding_permit_open: Some(vec![format!("{LOOPBACK}:{}", target.port)]),
                agent_forwarding: options.agent_forwarding,
                ..SshdConfig::default()
            },
        )?;
        Ok(Bastion { jump, target })
    }
}
