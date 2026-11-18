//! ⟨M04⟩ U5: the files a container environment's stable directory holds besides the signing
//! endpoint (ADR-0010 §4 item 2; the integrator's design §5): `ssh_config` and
//! `known_hosts`, rendered with **in-container** paths under `/run/heimdall/`.
//!
//! * **`ssh_config`** goes through [`heimdall_sshconf::render::render_sections`], the one
//!   renderer, with ordinary Unix [`RenderPath`]s: one `Host <alias>` per pair with the same
//!   `HostName`, `Port` and `User` the native managed alias renders, `IdentityAgent
//!   /run/heimdall/agent.sock`, `IdentitiesOnly yes`, the certificate as the identity file
//!   (the renderer's selected form), `ControlMaster no` and `ControlPath none`. The renderer
//!   cannot express host-verification directives, so the preamble this module writes before
//!   the first `Host` (global, hence read first) adds `StrictHostKeyChecking yes`,
//!   `UserKnownHostsFile /run/heimdall/known_hosts` and `GlobalKnownHostsFile none`. Never
//!   `ForwardAgent`, never a relaxed host-key setting.
//! * **`known_hosts`** holds the approved host key of each pair's enrollment record (the only
//!   trust source in a container, which has no user trust to inherit), named as OpenSSH looks
//!   it up for that `HostName` and `Port` (`host`, or `[host]:port`). It is the approved key,
//!   not a fresh scan.
//!
//! Pure: no I/O, no secret. The adapters write the bytes atomically inside the directory,
//! under the generation marker (`heimdall_adapters::managed::files`).

use std::path::Path;

use heimdall_app::environments::{
    CONTAINER_AGENT_SOCKET, CONTAINER_KNOWN_HOSTS, CONTAINER_MOUNT_TARGET,
};
use heimdall_contract::ids::DestinationId;
use heimdall_sshconf::render::{
    AliasName, HostName, ManagedIdentityForm, PathStyle, RenderError, RenderPath, Section,
    render_sections,
};

use crate::known_hosts::lookup_name;
use crate::projection::content::slot_component;

/// The OpenSSH configuration's file name in the directory.
pub const SSH_CONFIG_FILE: &str = "ssh_config";
/// The known-hosts file's name in the directory.
pub const KNOWN_HOSTS_FILE: &str = "known_hosts";
/// The binding's public key file, as the native binding directory names it.
pub const KEY_FILE: &str = "key.pub";

/// One pair of the container's binding, with what its enrollment approved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerPair {
    /// The destination (names the certificate file).
    pub destination: DestinationId,
    /// The managed alias (`Host`).
    pub alias: String,
    /// `HostName`.
    pub hostname: String,
    /// `Port`.
    pub port: u16,
    /// `User`.
    pub user: String,
    /// The approved host key's algorithm (`ssh-ed25519`).
    pub host_key_algorithm: String,
    /// The approved host key, base64.
    pub host_key: String,
}

/// The two rendered files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerFiles {
    /// `ssh_config`.
    pub ssh_config: String,
    /// `known_hosts`.
    pub known_hosts: String,
}

/// Why the files cannot be rendered. Nonsecret: a fixed reason, never a value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ContainerRenderError {
    /// The renderer refused a value (alias, host name, user, port, path).
    #[error("container configuration refused a value: {0}")]
    Render(RenderError),
    /// A destination ID that cannot name a file.
    #[error("a destination cannot name a certificate file")]
    Destination,
    /// A host key that is not one algorithm token and base64.
    #[error("an approved host key is malformed")]
    HostKey,
    /// Two pairs name the same host and port with different approved keys.
    #[error("two pairs approve different host keys for one host")]
    ConflictingHostKeys,
    /// No pair.
    #[error("a container binding has at least one pair")]
    NoPairs,
}

impl From<RenderError> for ContainerRenderError {
    fn from(e: RenderError) -> Self {
        ContainerRenderError::Render(e)
    }
}

/// The in-container name of `destination`'s certificate file
/// (`cert-<destination component>.pub`, as the native binding directory names it).
///
/// # Errors
/// [`ContainerRenderError::Destination`].
pub fn certificate_file(destination: &DestinationId) -> Result<String, ContainerRenderError> {
    slot_component(destination)
        .map(|c| format!("cert-{c}.pub"))
        .map_err(|_| ContainerRenderError::Destination)
}

fn in_container(name: &str) -> Result<RenderPath, ContainerRenderError> {
    Ok(RenderPath::unix(
        &Path::new(CONTAINER_MOUNT_TARGET).join(name),
    )?)
}

fn host_key_ok(algorithm: &str, key: &str) -> bool {
    !algorithm.is_empty()
        && algorithm
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'@' | b'.' | b'_'))
        && !key.is_empty()
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
}

/// Render `ssh_config` and `known_hosts` for `pairs` (module docs).
///
/// # Errors
/// [`ContainerRenderError`]; nothing is partially rendered.
pub fn render(pairs: &[ContainerPair]) -> Result<ContainerFiles, ContainerRenderError> {
    if pairs.is_empty() {
        return Err(ContainerRenderError::NoPairs);
    }
    let endpoint = RenderPath::unix(Path::new(CONTAINER_AGENT_SOCKET))?;
    let key_pub = in_container(KEY_FILE)?;
    let mut sections = Vec::with_capacity(pairs.len());
    let mut hosts: std::collections::BTreeMap<String, (&str, &str)> =
        std::collections::BTreeMap::new();
    for p in pairs {
        let hostname = HostName::parse(&p.hostname)?;
        if !host_key_ok(&p.host_key_algorithm, &p.host_key) {
            return Err(ContainerRenderError::HostKey);
        }
        let name = lookup_name(&hostname.as_str().to_ascii_lowercase(), p.port);
        match hosts.get(&name) {
            Some(have) if *have != (p.host_key_algorithm.as_str(), p.host_key.as_str()) => {
                return Err(ContainerRenderError::ConflictingHostKeys);
            }
            Some(_) => {}
            None => {
                hosts.insert(name, (&p.host_key_algorithm, &p.host_key));
            }
        }
        sections.push(Section::ManagedCertificate {
            alias: AliasName::parse(&p.alias)?,
            hostname,
            port: Some(p.port).filter(|p| *p != 22),
            user: p.user.clone(),
            endpoint: endpoint.clone(),
            key_pub: key_pub.clone(),
            cert: in_container(&certificate_file(&p.destination)?)?,
            control_path: None,
        });
    }
    let rendered = render_sections(
        &sections,
        PathStyle::Unix,
        ManagedIdentityForm::select(None),
    )?;
    let rendered = String::from_utf8(rendered)
        .map_err(|_| ContainerRenderError::Render(RenderError::RefusedValue("path")))?;
    // The renderer's header line, then the global host-verification directives (read
    // before every `Host`), then the sections.
    let (header, rest) = rendered.split_once('\n').unwrap_or((&rendered, ""));
    let ssh_config = format!(
        "{header}\nStrictHostKeyChecking yes\nUserKnownHostsFile \"{CONTAINER_KNOWN_HOSTS}\"\nGlobalKnownHostsFile none\n{rest}"
    );
    let mut known_hosts = String::new();
    for (name, (algorithm, key)) in &hosts {
        known_hosts.push_str(&format!("{name} {algorithm} {key}\n"));
    }
    Ok(ContainerFiles {
        ssh_config,
        known_hosts,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn pair(dest: &str, alias: &str, host: &str, port: u16, key: &str) -> ContainerPair {
        ContainerPair {
            destination: DestinationId::parse(dest).unwrap(),
            alias: alias.to_owned(),
            hostname: host.to_owned(),
            port,
            user: "deploy".to_owned(),
            host_key_algorithm: "ssh-ed25519".to_owned(),
            host_key: key.to_owned(),
        }
    }

    /// The directory's two files: in-container paths only, the approved key as the only
    /// trust, strict host checking, and never `ForwardAgent`.
    #[test]
    fn rendering_is_in_container_strict_and_never_forwards_the_agent() {
        let files = render(&[
            pair("dst-a", "alpha", "Host-A.example", 2222, "AAAAC3Nza"),
            pair("dst-b", "beta", "10.0.0.2", 22, "AAAAC3Nzb"),
        ])
        .unwrap();
        let c = &files.ssh_config;
        assert!(c.contains("StrictHostKeyChecking yes\n"), "{c}");
        assert!(
            c.contains("UserKnownHostsFile \"/run/heimdall/known_hosts\"\n")
                && c.contains("GlobalKnownHostsFile none\n")
        );
        assert!(c.contains("IdentityAgent \"/run/heimdall/agent.sock\""));
        assert!(c.contains("IdentityFile \"/run/heimdall/cert-dst-a.pub\""));
        assert!(c.contains("Port 2222") && !c.contains("Port 22\n"));
        assert!(c.contains("ControlPath none"));
        assert!(!c.to_ascii_lowercase().contains("forwardagent"), "{c}");
        // Only in-container paths: no host path can appear.
        assert!(
            c.lines()
                .filter(|l| l.contains('"'))
                .all(|l| l.contains("\"/run/heimdall/"))
        );
        assert_eq!(
            files.known_hosts,
            "10.0.0.2 ssh-ed25519 AAAAC3Nzb\n[host-a.example]:2222 ssh-ed25519 AAAAC3Nza\n"
        );
    }

    #[test]
    fn two_keys_for_one_host_and_malformed_keys_are_refused() {
        let a = pair("dst-a", "alpha", "h.example", 22, "AAAA");
        let b = pair("dst-b", "beta", "h.example", 22, "BBBB");
        assert_eq!(
            render(&[a.clone(), b]).unwrap_err(),
            ContainerRenderError::ConflictingHostKeys
        );
        let mut bad = a;
        bad.host_key = "AA AA".to_owned();
        assert_eq!(render(&[bad]).unwrap_err(), ContainerRenderError::HostKey);
    }
}
