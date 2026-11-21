//! ⟨M06 U5a⟩ Verification through an approved single-hop jump (ADR-0012 §5.7; ADR-0010 §5
//! item 5, §9 item 4, §10 item 6; m06-plan U5a "enrollment and verification through a jump").
//!
//! [`generated_routed_config`] is the Verifier's generated configuration
//! ([`crate::verify::generated_config`]) reached through the catalog's approved jump: the
//! final block is unchanged except that it names `ProxyJump hm-verify-jump` (and so no
//! `ProxyCommand none`, which would take the same first-wins slot), and a second block,
//! `Host hm-verify-jump`, carries the jump's **own** catalog pin (`HostKeyAlias
//! hm-dest-<jump id>` and its pin file, strict checking, no other trust source) and its own
//! access (a managed pair in the same grant, or existing access; ADR-0010 §5 item 2). OpenSSH
//! passes `-F <file>` to the jump's `ssh`, so both hops are read from the generated file
//! only, and the user's configuration is never read.
//!
//! **The final-key rule** (ADR-0012 §5.7, ADR-0010 §10 item 6): the final host's key is
//! checked end to end against the approved key whatever the route, so a changed final key
//! through the jump fails host-key verification before any authentication at the final host;
//! the trace's host-key failure is classified `host_key_mismatch`, which holds the enrollment
//! (`host_key_changed`), exactly as on the direct route.
//!
//! **Not wired here** (outside this unit's files): `app::enrollment::verification_may_connect`
//! still opens a verification session only over the direct route, and
//! `app::ports::VerificationRunner` carries no jump hop; the integrator connects the two.

use std::path::Path;

use crate::verify::{GeneratedConfig, config_path, generated_config, host_key_algorithms};

/// The generated jump `Host` name.
pub const VERIFY_JUMP_HOST: &str = "hm-verify-jump";

/// The jump hop of a routed verification (module docs).
#[derive(Debug, Clone, Copy)]
pub struct VerifyJump<'a> {
    /// The jump's `HostName`.
    pub hostname: &'a str,
    /// Its `Port`.
    pub port: u16,
    /// Its `User`.
    pub user: &'a str,
    /// `HostKeyAlias hm-dest-<jump id>`.
    pub host_key_alias: &'a str,
    /// The jump's pin file (its catalog-pinned key under that alias).
    pub known_hosts: &'a Path,
    /// The pinned key's algorithm.
    pub host_key_algorithm: &'a str,
    /// `IdentityAgent` of the jump hop's access, already an `ssh_config` argument.
    pub identity_agent: &'a str,
    /// The jump hop's public key (existing access) or certificate (managed) file.
    pub identity_file: &'a Path,
}

fn literal_ok(text: &str, extra: &[u8]) -> bool {
    !text.is_empty()
        && !text.starts_with('-')
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || extra.contains(&b))
}

/// The generated configuration through `jump` (module docs), or `None` when a value cannot be
/// written literally.
#[must_use]
pub fn generated_routed_config(c: &GeneratedConfig<'_>, jump: &VerifyJump<'_>) -> Option<String> {
    let direct = generated_config(c)?;
    let pin_ok = jump
        .host_key_alias
        .strip_prefix("hm-dest-")
        .is_some_and(|id| literal_ok(id, b"._-"));
    if !literal_ok(jump.hostname, b".-:_")
        || !literal_ok(jump.user, b".-_")
        || !pin_ok
        || jump.port == 0
    {
        return None;
    }
    let algorithms = host_key_algorithms(jump.host_key_algorithm)?;
    let mut final_block: Vec<String> = Vec::new();
    for line in direct.lines() {
        match line {
            "  ProxyCommand none" => {}
            "  ProxyJump none" => final_block.push(format!("  ProxyJump {VERIFY_JUMP_HOST}")),
            other => final_block.push(other.to_owned()),
        }
    }
    let jump_block = [
        format!("Host {VERIFY_JUMP_HOST}"),
        format!("  HostName {}", jump.hostname),
        format!("  Port {}", jump.port),
        format!("  User {}", jump.user),
        format!("  HostKeyAlias {}", jump.host_key_alias),
        format!("  UserKnownHostsFile {}", config_path(jump.known_hosts)?),
        "  GlobalKnownHostsFile none".to_owned(),
        "  KnownHostsCommand none".to_owned(),
        "  VerifyHostKeyDNS no".to_owned(),
        format!("  HostKeyAlgorithms {algorithms}"),
        "  StrictHostKeyChecking yes".to_owned(),
        "  CheckHostIP no".to_owned(),
        "  UpdateHostKeys no".to_owned(),
        "  NoHostAuthenticationForLocalhost no".to_owned(),
        "  CanonicalizeHostname no".to_owned(),
        "  ForkAfterAuthentication no".to_owned(),
        format!("  IdentityAgent {}", jump.identity_agent),
        "  IdentitiesOnly yes".to_owned(),
        format!("  IdentityFile {}", config_path(jump.identity_file)?),
        "  CertificateFile none".to_owned(),
        "  PreferredAuthentications publickey".to_owned(),
        "  PasswordAuthentication no".to_owned(),
        "  KbdInteractiveAuthentication no".to_owned(),
        "  BatchMode yes".to_owned(),
        "  ControlMaster no".to_owned(),
        "  ControlPath none".to_owned(),
        "  ProxyCommand none".to_owned(),
        "  ForwardAgent no".to_owned(),
        "  ClearAllForwardings yes".to_owned(),
        "  PermitLocalCommand no".to_owned(),
        "  RequestTTY no".to_owned(),
        "  ConnectTimeout 20".to_owned(),
    ];
    let mut out = final_block.join("\n");
    out.push_str("\n\n");
    out.push_str(&jump_block.join("\n"));
    out.push('\n');
    Some(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use heimdall_contract::enrollment::{ApprovedHostKey, ApprovedTarget};
    use heimdall_contract::ids::AccountName;

    fn target() -> ApprovedTarget {
        ApprovedTarget {
            hostname: "10.0.0.2".into(),
            port: 22,
            user: AccountName::parse("deploy").unwrap(),
            proxy: Default::default(),
            host_key: ApprovedHostKey {
                algorithm: "ssh-ed25519".into(),
                key: "AAAAC3NzaC1lZDI1NTE5AAAAIB".into(),
                fingerprint: "SHA256:x".into(),
            },
        }
    }

    /// The final block keeps every host-trust pin and names only the jump; the jump block
    /// carries the jump's own catalog pin and access; nothing reads another configuration.
    #[test]
    fn routed_config_pins_both_hops() {
        let t = target();
        let c = GeneratedConfig {
            target: &t,
            alias: "hm-verify-0123456789abcdef",
            known_hosts: Path::new("/r/v/x/known_hosts"),
            global_known_hosts: Path::new("/r/v/x/global_known_hosts"),
            identity_agent: "\"/r/s/agent.sock\"",
            identity_file: Path::new("/r/v/x/k_verify.pub"),
            certificate_file: Path::new("/r/v/x/positive-cert.pub"),
        };
        let j = VerifyJump {
            hostname: "10.0.0.1",
            port: 2200,
            user: "jump",
            host_key_alias: "hm-dest-bastion",
            known_hosts: Path::new("/r/pins/known_hosts"),
            host_key_algorithm: "ssh-ed25519",
            identity_agent: "\"/r/e/agent.sock\"",
            identity_file: Path::new("/r/k/jump.pub"),
        };
        let text = generated_routed_config(&c, &j).unwrap();
        let (final_block, jump_block) = text.split_once("\n\nHost hm-verify-jump\n").unwrap();
        assert!(final_block.starts_with("Host hm-verify\n"));
        assert!(
            final_block
                .lines()
                .any(|l| l == "  ProxyJump hm-verify-jump")
        );
        assert!(
            !final_block.contains("ProxyCommand"),
            "the slot is the jump's"
        );
        for line in [
            "  HostKeyAlias hm-verify-0123456789abcdef",
            "  StrictHostKeyChecking yes",
            "  UserKnownHostsFile \"/r/v/x/known_hosts\"",
            "  KnownHostsCommand none",
        ] {
            assert!(final_block.lines().any(|l| l == line), "{line}");
        }
        for line in [
            "  HostName 10.0.0.1",
            "  Port 2200",
            "  HostKeyAlias hm-dest-bastion",
            "  UserKnownHostsFile \"/r/pins/known_hosts\"",
            "  GlobalKnownHostsFile none",
            "  StrictHostKeyChecking yes",
            "  IdentityAgent \"/r/e/agent.sock\"",
            "  IdentityFile \"/r/k/jump.pub\"",
            "  ProxyCommand none",
            "  ControlPath none",
        ] {
            assert!(jump_block.lines().any(|l| l == line), "{line}");
        }
        let bad = |f: &dyn Fn(&mut VerifyJump<'_>)| {
            let mut j2 = j;
            f(&mut j2);
            generated_routed_config(&c, &j2)
        };
        assert!(bad(&|j| j.host_key_alias = "bastion").is_none());
        assert!(bad(&|j| j.hostname = "-oProxyCommand=x").is_none());
        assert!(bad(&|j| j.known_hosts = Path::new("/r/%h")).is_none());
        assert!(bad(&|j| j.host_key_algorithm = "ssh-ed25519-cert-v01@openssh.com").is_none());
    }
}
