//! ⟨M06 U2⟩ The isolated management configuration (ADR-0012 §3.1, §5.2; m06-plan U2). Pure:
//! text only.
//!
//! A management connection runs `ssh -F <heimdall-mgmt.conf> … hm-env-<id>`, so neither the
//! user's configuration nor the system's is read. [`render_mgmt_config`] writes that file:
//! one `Host` block for the runner (`hm-env-<id>`), one for the optional single jump hop
//! (`hm-dest-<id>`, defined in the same file with its own pin, ADR-0012 §5.2), and a final
//! `Host *` block that repeats the trust and forwarding settings so that a name matching no
//! block still gets none of OpenSSH's permissive defaults. Every hop block carries, in this
//! order:
//!
//! ```text
//! Host hm-env-<id>
//!     HostName <host>
//!     Port <port>                         (when not 22)
//!     User <account>
//!     ProxyJump hm-dest-<jump id>          (only with a jump hop)
//!     HostKeyAlias hm-env-<id>
//!     HostKeyAlgorithms <the pinned keys' algorithms>
//!     StrictHostKeyChecking yes
//!     UserKnownHostsFile "<pins>"
//!     GlobalKnownHostsFile none
//!     KnownHostsCommand none
//!     VerifyHostKeyDNS no
//!     UpdateHostKeys no
//!     CheckHostIP no
//!     ControlMaster no
//!     ControlPath none
//!     ControlPersist no
//!     ForwardAgent no
//!     ForwardX11 no
//!     ClearAllForwardings yes
//!     RequestTTY no
//!     PermitLocalCommand no
//!     IdentityAgent "<the K_mgmt agent endpoint>"
//!     IdentityFile "<K_mgmt public key file>"
//!     IdentitiesOnly yes
//! ```
//!
//! * **No `SetEnv`, no `SendEnv`.** With `-F` no other file contributes one, and this file
//!   names neither ([`check_isolated`] refuses a rendering that does).
//! * **No multiplexing.** `ControlMaster no`, `ControlPath none`, `ControlPersist no`: no
//!   management connection reuses a master.
//! * **Typed inputs only.** Names are validated tokens, host names [`HostName`]s, paths
//!   [`RenderPath`]s (never `none`: a path type cannot spell it), and the host-key algorithms
//!   are derived from the pinned keys' types, never taken as text.
//! * **The agent regression (G07 §8).** With OpenSSH 9.6p1, `IdentityAgent none` silently
//!   disables agent forwarding even when `ForwardAgent` names a socket. A management hop
//!   always renders `ForwardAgent no` and a real `IdentityAgent` path, and
//!   [`agent_forwarding_conflicts`] (run on every rendering here, and usable on any rendered
//!   configuration) refuses a block that combines `IdentityAgent none` with a `ForwardAgent`
//!   other than `no`.
//!
//! [`render_mgmt_pin_file`] renders the pins: `hm-env-<id> <type> <base64>` and
//! `hm-dest-<id> <type> <base64>` lines, sorted. A ProxyJump's derived command is run by a
//! shell with `-F <this file>`, so [`check_config_path_for_jump`] refuses a configuration
//! path a shell would split or expand.

use std::fmt::Write as _;

use crate::render::{HostName, PathKind, PathStyle, RenderError, RenderPath, check_user};
use crate::routes::HOST_KEY_ALIAS_PREFIX;

/// The `Host` name and `HostKeyAlias` prefix of a runner environment's management hop.
pub const ENV_ALIAS_PREFIX: &str = "hm-env-";

/// The header comment of the management configuration.
const MGMT_HEADER: &str =
    "# heimdall management ssh configuration (generated; do not edit; read only with ssh -F)\n";

/// Characters a shell would split, quote or expand in a ProxyJump's derived command line.
const SHELL_SPECIAL: &[char] = &[
    ' ', '\t', '$', '`', '\\', '!', '^', '&', '|', '<', '>', ';', '%', '\'', '"', '*', '?', '[',
    ']', '(', ')', '{', '}', '#', '~',
];

/// A name usable after `hm-env-` or `hm-dest-`: `[A-Za-z0-9._-]`, not starting with `-`,
/// the whole name at most 255 bytes.
fn suffix_ok(prefix: &str, id: &str) -> bool {
    !id.is_empty()
        && id.len() + prefix.len() <= 255
        && !id.starts_with('-')
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// A pinned host key's type and base64 blob, validated: one plain key of a type that can be
/// the only trust source (no certificate, DSA, security-key or unknown type).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PinnedKey {
    key_type: String,
    blob: String,
}

impl PinnedKey {
    /// Parse an OpenSSH public key line (`<type> <base64> [comment]`); the comment is
    /// dropped.
    ///
    /// # Errors
    /// [`RenderError::RefusedValue`] (`host_key`).
    pub fn parse(line: &str) -> Result<PinnedKey, RenderError> {
        if line.chars().any(char::is_control) {
            return Err(RenderError::RefusedValue("host_key"));
        }
        let mut words = line.split_ascii_whitespace();
        let (Some(key_type), Some(blob)) = (words.next(), words.next()) else {
            return Err(RenderError::RefusedValue("host_key"));
        };
        let blob_ok = !blob.is_empty()
            && blob
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='));
        if algorithms_of(key_type).is_none() || !blob_ok {
            return Err(RenderError::RefusedValue("host_key"));
        }
        Ok(PinnedKey {
            key_type: key_type.to_owned(),
            blob: blob.to_owned(),
        })
    }

    /// The key type (`ssh-ed25519`, …).
    #[must_use]
    pub fn key_type(&self) -> &str {
        &self.key_type
    }
}

/// The host-key signature algorithms that verify a key of `key_type` (an RSA key verifies
/// only with the SHA-2 algorithms: `ssh-rsa`, SHA-1, is never offered).
fn algorithms_of(key_type: &str) -> Option<&'static [&'static str]> {
    match key_type {
        "ssh-ed25519" => Some(&["ssh-ed25519"]),
        "ecdsa-sha2-nistp256" => Some(&["ecdsa-sha2-nistp256"]),
        "ecdsa-sha2-nistp384" => Some(&["ecdsa-sha2-nistp384"]),
        "ecdsa-sha2-nistp521" => Some(&["ecdsa-sha2-nistp521"]),
        "ssh-rsa" => Some(&["rsa-sha2-512", "rsa-sha2-256"]),
        _ => None,
    }
}

/// The identity a hop authenticates with: an agent endpoint and the public key file that
/// selects the key in it. For the runner hop that is K_mgmt, served by Heimdall's own
/// per-session agent; a jump hop names the existing access recorded for it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HopIdentity {
    agent: RenderPath,
    public_key_file: RenderPath,
}

impl HopIdentity {
    /// Validate: `agent` an absolute socket path or a named pipe, `public_key_file` an
    /// absolute file path (neither `~`-relative: the file is read with `-F` only, whatever
    /// `$HOME` is).
    ///
    /// # Errors
    /// [`RenderError::RefusedValue`] (`identity_agent`, `identity_file`).
    pub fn new(agent: RenderPath, public_key_file: RenderPath) -> Result<HopIdentity, RenderError> {
        let agent_ok = agent.kind == PathKind::Pipe || agent.is_absolute_file();
        if !agent_ok {
            return Err(RenderError::RefusedValue("identity_agent"));
        }
        if !public_key_file.is_absolute_file() {
            return Err(RenderError::RefusedValue("identity_file"));
        }
        Ok(HopIdentity {
            agent,
            public_key_file,
        })
    }
}

/// One hop of a management connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MgmtHop {
    /// `HostName`.
    pub hostname: HostName,
    /// `Port`, when not 22.
    pub port: Option<u16>,
    /// `User`.
    pub user: String,
    /// The hop's catalog-pinned host keys (at least one).
    pub pins: Vec<PinnedKey>,
    /// The identity it authenticates with.
    pub identity: HopIdentity,
}

/// The optional single jump hop (ADR-0012 §5.1 `jump{via}`; multi-hop chains stay
/// `route_chain_unsupported`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MgmtJump {
    /// The jump destination's ID (`hm-dest-<id>`).
    pub destination: String,
    /// Its hop.
    pub hop: MgmtHop,
}

/// What [`render_mgmt_config`] renders: the runner environment's hop, and its jump hop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MgmtTarget {
    /// The runner environment's ID (`hm-env-<id>`).
    pub environment: String,
    /// The runner hop.
    pub hop: MgmtHop,
    /// The single jump hop, when the approved route is a jump.
    pub jump: Option<MgmtJump>,
}

impl MgmtTarget {
    /// The runner hop's `Host` name and `HostKeyAlias`: `hm-env-<id>`.
    #[must_use]
    pub fn alias(&self) -> String {
        format!("{ENV_ALIAS_PREFIX}{}", self.environment)
    }
}

/// The trust and forwarding settings every block carries (module docs), after
/// `HostKeyAlgorithms`, up to and including `PermitLocalCommand`.
fn trust_lines(out: &mut String, pins_file: &RenderPath) {
    let _ = write!(
        out,
        "    StrictHostKeyChecking yes\n    UserKnownHostsFile {}\n    \
         GlobalKnownHostsFile none\n    KnownHostsCommand none\n    VerifyHostKeyDNS no\n    \
         UpdateHostKeys no\n    CheckHostIP no\n    ControlMaster no\n    ControlPath none\n    \
         ControlPersist no\n    ForwardAgent no\n    ForwardX11 no\n    \
         ClearAllForwardings yes\n    RequestTTY no\n    PermitLocalCommand no\n",
        pins_file.ssh_quoted()
    );
}

/// One hop's block.
fn hop_block(
    out: &mut String,
    alias: &str,
    hop: &MgmtHop,
    proxy_jump: Option<&str>,
    pins_file: &RenderPath,
    style: PathStyle,
) -> Result<(), RenderError> {
    check_user(&hop.user)?;
    if hop.pins.is_empty() {
        return Err(RenderError::RefusedValue("host_key"));
    }
    if hop.port == Some(0) {
        return Err(RenderError::RefusedValue("port"));
    }
    if !hop.identity.agent.fits(style) || !hop.identity.public_key_file.fits(style) {
        return Err(RenderError::RefusedValue("identity_agent"));
    }
    let mut algorithms: Vec<&str> = Vec::new();
    for pin in &hop.pins {
        for a in algorithms_of(&pin.key_type).ok_or(RenderError::RefusedValue("host_key"))? {
            if !algorithms.contains(a) {
                algorithms.push(a);
            }
        }
    }
    let _ = writeln!(out, "\nHost {alias}");
    let _ = writeln!(out, "    HostName {}", hop.hostname.as_str());
    if let Some(port) = hop.port.filter(|p| *p != 22) {
        let _ = writeln!(out, "    Port {port}");
    }
    let _ = writeln!(out, "    User {}", hop.user);
    if let Some(jump) = proxy_jump {
        let _ = writeln!(out, "    ProxyJump {jump}");
    }
    let _ = writeln!(out, "    HostKeyAlias {alias}");
    let _ = writeln!(out, "    HostKeyAlgorithms {}", algorithms.join(","));
    trust_lines(out, pins_file);
    let _ = writeln!(out, "    IdentityAgent {}", hop.identity.agent.ssh_quoted());
    let _ = writeln!(
        out,
        "    IdentityFile {}",
        hop.identity.public_key_file.ssh_quoted()
    );
    out.push_str("    IdentitiesOnly yes\n");
    Ok(())
}

/// Render the isolated management configuration for `target` (module docs), its pins in
/// `pins_file` ([`render_mgmt_pin_file`]), LF line endings, deterministic.
///
/// # Errors
/// [`RenderError::RefusedValue`]: an environment or jump ID that cannot be a name, a refused
/// user or port, a hop with no pin, a path that does not fit `style`, a pin file that is not
/// an absolute file path; and, unreachable by construction, a rendering that
/// [`check_isolated`] refuses.
pub fn render_mgmt_config(
    target: &MgmtTarget,
    pins_file: &RenderPath,
    style: PathStyle,
) -> Result<Vec<u8>, RenderError> {
    if !suffix_ok(ENV_ALIAS_PREFIX, &target.environment) {
        return Err(RenderError::RefusedValue("environment"));
    }
    if !pins_file.is_absolute_file() || !pins_file.fits(style) {
        return Err(RenderError::RefusedValue("pin_file"));
    }
    let mut out = String::from(MGMT_HEADER);
    let jump_alias = match &target.jump {
        Some(jump) => {
            if !suffix_ok(HOST_KEY_ALIAS_PREFIX, &jump.destination) {
                return Err(RenderError::RefusedValue("destination"));
            }
            Some(format!("{HOST_KEY_ALIAS_PREFIX}{}", jump.destination))
        }
        None => None,
    };
    hop_block(
        &mut out,
        &target.alias(),
        &target.hop,
        jump_alias.as_deref(),
        pins_file,
        style,
    )?;
    if let (Some(jump), Some(alias)) = (&target.jump, &jump_alias) {
        hop_block(&mut out, alias, &jump.hop, None, pins_file, style)?;
    }
    out.push_str("\nHost *\n");
    trust_lines(&mut out, pins_file);
    out.push_str("    IdentitiesOnly yes\n");
    check_isolated(&out)?;
    Ok(out.into_bytes())
}

/// Render the management pin file: one `<alias> <type> <base64>` line per pinned key of the
/// runner hop (`hm-env-<id>`) and of the jump hop (`hm-dest-<id>`), sorted, LF line endings.
///
/// # Errors
/// [`RenderError::RefusedValue`] (`environment`, `destination`, `host_key`).
pub fn render_mgmt_pin_file(target: &MgmtTarget) -> Result<Vec<u8>, RenderError> {
    if !suffix_ok(ENV_ALIAS_PREFIX, &target.environment) {
        return Err(RenderError::RefusedValue("environment"));
    }
    let mut lines = Vec::new();
    let mut add = |alias: &str, pins: &[PinnedKey]| -> Result<(), RenderError> {
        if pins.is_empty() {
            return Err(RenderError::RefusedValue("host_key"));
        }
        for pin in pins {
            lines.push(format!("{alias} {} {}\n", pin.key_type, pin.blob));
        }
        Ok(())
    };
    add(&target.alias(), &target.hop.pins)?;
    if let Some(jump) = &target.jump {
        if !suffix_ok(HOST_KEY_ALIAS_PREFIX, &jump.destination) {
            return Err(RenderError::RefusedValue("destination"));
        }
        add(
            &format!("{HOST_KEY_ALIAS_PREFIX}{}", jump.destination),
            &jump.hop.pins,
        )?;
    }
    lines.sort();
    lines.dedup();
    Ok(lines.concat().into_bytes())
}

/// Refuse a configuration path that a shell would split or expand: a ProxyJump runs `ssh -F
/// <this path> -W …` through the user's shell, so the path must be one plain word.
///
/// # Errors
/// [`RenderError::RefusedValue`] (`config_path`).
pub fn check_config_path_for_jump(path: &str) -> Result<(), RenderError> {
    if path.is_empty() || path.contains(SHELL_SPECIAL) || path.chars().any(char::is_control) {
        return Err(RenderError::RefusedValue("config_path"));
    }
    Ok(())
}

/// One `Host`/`Match` block's agent settings, as the first value OpenSSH would obtain.
#[derive(Debug, Default)]
struct BlockAgent {
    identity_agent: Option<String>,
    forward_agent: Option<String>,
}

/// A directive's keyword (lowercased) and its first argument with one layer of double quotes
/// removed (`Keyword value`, `Keyword=value`, `Keyword = value`).
fn keyword_value(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let split = line.find(|c: char| c.is_ascii_whitespace() || c == '=')?;
    let (keyword, rest) = line.split_at(split);
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=').unwrap_or(rest).trim_start();
    let value = match rest.strip_prefix('"') {
        Some(quoted) => quoted.split('"').next().unwrap_or(""),
        None => rest.split_ascii_whitespace().next().unwrap_or(""),
    };
    Some((keyword.to_ascii_lowercase(), value.to_owned()))
}

/// The blocks of rendered configuration `text` (the global section first, named `""`) that
/// combine `IdentityAgent none` with a `ForwardAgent` other than `no` (G07 §8: OpenSSH 9.6p1
/// then silently drops agent forwarding). Each block's first value of each keyword is the
/// one read, as OpenSSH reads it; a value set in the global section applies to every block
/// that does not set its own.
#[must_use]
pub fn agent_forwarding_conflicts(text: &str) -> Vec<String> {
    let mut blocks: Vec<(String, BlockAgent)> = vec![(String::new(), BlockAgent::default())];
    for line in text.lines() {
        let Some((keyword, value)) = keyword_value(line) else {
            continue;
        };
        match keyword.as_str() {
            "host" | "match" => {
                let name = line.trim().to_owned();
                blocks.push((name, BlockAgent::default()));
            }
            "identityagent" => {
                if let Some((_, b)) = blocks.last_mut() {
                    b.identity_agent.get_or_insert(value);
                }
            }
            "forwardagent" => {
                if let Some((_, b)) = blocks.last_mut() {
                    b.forward_agent.get_or_insert(value);
                }
            }
            _ => {}
        }
    }
    let global_identity = blocks[0].1.identity_agent.clone();
    let global_forward = blocks[0].1.forward_agent.clone();
    let mut conflicts = Vec::new();
    for (name, b) in &blocks {
        let identity = b.identity_agent.clone().or_else(|| global_identity.clone());
        let forward = b.forward_agent.clone().or_else(|| global_forward.clone());
        let identity_none = identity.is_some_and(|v| v.eq_ignore_ascii_case("none"));
        let forwarding = forward.is_some_and(|v| !v.eq_ignore_ascii_case("no"));
        if identity_none && forwarding {
            conflicts.push(name.clone());
        }
    }
    conflicts
}

/// Check a rendered management configuration: no block combines `IdentityAgent none` with
/// agent forwarding ([`agent_forwarding_conflicts`]), and no `SetEnv` or `SendEnv` appears.
///
/// # Errors
/// [`RenderError::RefusedValue`] (`agent_forwarding`, `environment_passing`).
pub fn check_isolated(text: &str) -> Result<(), RenderError> {
    if !agent_forwarding_conflicts(text).is_empty() {
        return Err(RenderError::RefusedValue("agent_forwarding"));
    }
    let passes_environment = text
        .lines()
        .filter_map(keyword_value)
        .any(|(k, _)| matches!(k.as_str(), "setenv" | "sendenv"));
    if passes_environment {
        return Err(RenderError::RefusedValue("environment_passing"));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::render::{
        AliasName, DEFAULT_MANAGED_IDENTITY_FORM, ManagedAlias, Section, forward_agent_options,
        render_sections,
    };

    const ED: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOVqmTNbwT7nI0Fk7RzD4mgwA0ke2pRDCgUNQ0FHb8xn runner";
    const RSA: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7 bastion";

    fn unix(p: &str) -> RenderPath {
        RenderPath::unix(Path::new(p)).unwrap()
    }

    fn identity() -> HopIdentity {
        HopIdentity::new(
            unix("/home/u/.local/state/heimdall/run/mgmt-agent.sock"),
            unix("/home/u/.local/state/heimdall/mgmt/k_mgmt.pub"),
        )
        .unwrap()
    }

    fn hop(host: &str, port: Option<u16>, user: &str, pin: &str) -> MgmtHop {
        MgmtHop {
            hostname: HostName::parse(host).unwrap(),
            port,
            user: user.into(),
            pins: vec![PinnedKey::parse(pin).unwrap()],
            identity: identity(),
        }
    }

    fn pins() -> RenderPath {
        unix("/home/u/.local/state/heimdall/mgmt/known_hosts")
    }

    fn render(target: &MgmtTarget) -> String {
        String::from_utf8(render_mgmt_config(target, &pins(), PathStyle::Unix).unwrap()).unwrap()
    }

    const TRUST: &str = "    StrictHostKeyChecking yes\n\
         \x20   UserKnownHostsFile \"/home/u/.local/state/heimdall/mgmt/known_hosts\"\n\
         \x20   GlobalKnownHostsFile none\n\
         \x20   KnownHostsCommand none\n\
         \x20   VerifyHostKeyDNS no\n\
         \x20   UpdateHostKeys no\n\
         \x20   CheckHostIP no\n\
         \x20   ControlMaster no\n\
         \x20   ControlPath none\n\
         \x20   ControlPersist no\n\
         \x20   ForwardAgent no\n\
         \x20   ForwardX11 no\n\
         \x20   ClearAllForwardings yes\n\
         \x20   RequestTTY no\n\
         \x20   PermitLocalCommand no\n";

    const IDENTITY: &str = "    IdentityAgent \"/home/u/.local/state/heimdall/run/mgmt-agent.sock\"\n\
         \x20   IdentityFile \"/home/u/.local/state/heimdall/mgmt/k_mgmt.pub\"\n\
         \x20   IdentitiesOnly yes\n";

    /// Golden (ADR-0012 §5.2; m06-plan U2): the isolated configuration for a direct runner
    /// hop renders every §5.2 setting, byte for byte, and the catch-all block repeats the
    /// trust and forwarding settings.
    #[test]
    fn golden_isolated_config_direct() {
        let target = MgmtTarget {
            environment: "env_0123456789abcdef0123456789abcdef".into(),
            hop: hop("runner.example.net", Some(2222), "deploy", ED),
            jump: None,
        };
        let expected = format!(
            "# heimdall management ssh configuration (generated; do not edit; read only with ssh -F)\n\
             \n\
             Host hm-env-env_0123456789abcdef0123456789abcdef\n\
             \x20   HostName runner.example.net\n\
             \x20   Port 2222\n\
             \x20   User deploy\n\
             \x20   HostKeyAlias hm-env-env_0123456789abcdef0123456789abcdef\n\
             \x20   HostKeyAlgorithms ssh-ed25519\n\
             {TRUST}{IDENTITY}\
             \n\
             Host *\n\
             {TRUST}\
             \x20   IdentitiesOnly yes\n"
        );
        assert_eq!(render(&target), expected);
        // Deterministic.
        assert_eq!(render(&target), render(&target));
    }

    /// ⟨M06 W5; ADR-0012 §2.6⟩ Golden for a Windows controller: `IdentityAgent` is the K_mgmt
    /// session agent's named pipe (`//./pipe/heimdall-<token>`), the files are Windows paths
    /// with forward slashes, and every other line is byte for byte the Unix rendering's: no
    /// §5.2 setting changes with the platform.
    #[test]
    fn golden_isolated_config_windows_pipe_agent() {
        let pipe = r"\\.\pipe\heimdall-0123456789abcdef0123456789abcdef";
        let windows = |p: &str| RenderPath::windows(Path::new(p)).unwrap();
        let pins = windows(r"C:\Users\u\AppData\Local\Heimdall\run\mgmt\ab12\known_hosts");
        let mut target = MgmtTarget {
            environment: "env_0123456789abcdef0123456789abcdef".into(),
            hop: hop("runner.example.net", Some(2222), "deploy", ED),
            jump: None,
        };
        let unix_text = render(&target);
        target.hop.identity = HopIdentity::new(
            RenderPath::pipe(pipe).unwrap(),
            windows(r"C:\Users\u\AppData\Local\Heimdall\run\mgmt\ab12\k_mgmt.pub"),
        )
        .unwrap();
        let text =
            String::from_utf8(render_mgmt_config(&target, &pins, PathStyle::Windows).unwrap())
                .unwrap();
        let trust = TRUST.replace(
            "\"/home/u/.local/state/heimdall/mgmt/known_hosts\"",
            "\"C:/Users/u/AppData/Local/Heimdall/run/mgmt/ab12/known_hosts\"",
        );
        let expected = format!(
            "# heimdall management ssh configuration (generated; do not edit; read only with ssh -F)\n\
             \n\
             Host hm-env-env_0123456789abcdef0123456789abcdef\n\
             \x20   HostName runner.example.net\n\
             \x20   Port 2222\n\
             \x20   User deploy\n\
             \x20   HostKeyAlias hm-env-env_0123456789abcdef0123456789abcdef\n\
             \x20   HostKeyAlgorithms ssh-ed25519\n\
             {trust}\
             \x20   IdentityAgent \"//./pipe/heimdall-0123456789abcdef0123456789abcdef\"\n\
             \x20   IdentityFile \"C:/Users/u/AppData/Local/Heimdall/run/mgmt/ab12/k_mgmt.pub\"\n\
             \x20   IdentitiesOnly yes\n\
             \n\
             Host *\n\
             {trust}\
             \x20   IdentitiesOnly yes\n"
        );
        assert_eq!(text, expected);
        // Line by line against the Unix rendering: only the three path-valued settings
        // differ, and each keeps its keyword.
        let path_valued = ["UserKnownHostsFile", "IdentityAgent", "IdentityFile"];
        let (ours, theirs): (Vec<&str>, Vec<&str>) =
            (text.lines().collect(), unix_text.lines().collect());
        assert_eq!(ours.len(), theirs.len());
        let mut differing = Vec::new();
        for (a, b) in ours.iter().zip(&theirs) {
            if a != b {
                let keyword = a.split_whitespace().next().unwrap();
                assert_eq!(Some(keyword), b.split_whitespace().next());
                assert!(path_valued.contains(&keyword), "{a}");
                differing.push(keyword);
            }
        }
        assert_eq!(
            differing,
            [
                "UserKnownHostsFile",
                "IdentityAgent",
                "IdentityFile",
                "UserKnownHostsFile"
            ]
        );
        assert!(agent_forwarding_conflicts(&text).is_empty());
        // The pipe agent is refused in a Unix-style file, and a pipe is never a file.
        assert_eq!(
            render_mgmt_config(&target, &unix("/run/known_hosts"), PathStyle::Unix),
            Err(RenderError::RefusedValue("identity_agent"))
        );
        assert_eq!(
            HopIdentity::new(windows(r"C:\a\k.pub"), RenderPath::pipe(pipe).unwrap()),
            Err(RenderError::RefusedValue("identity_file"))
        );
        assert_eq!(
            render_mgmt_config(
                &target,
                &RenderPath::pipe(pipe).unwrap(),
                PathStyle::Windows
            ),
            Err(RenderError::RefusedValue("pin_file"))
        );
    }

    /// Golden, through a jump (ADR-0012 §5.2 "the jump hop is defined in the same file with
    /// its own pin"): the runner block names the jump with `ProxyJump`, the jump block has its
    /// own `HostKeyAlias` and algorithms (RSA through SHA-2 only), and both blocks carry every
    /// setting.
    #[test]
    fn golden_isolated_config_jump() {
        let target = MgmtTarget {
            environment: "env_aa".into(),
            hop: hop("10.0.0.7", None, "runner", ED),
            jump: Some(MgmtJump {
                destination: "bastion".into(),
                hop: hop("bastion.example.net", Some(22), "jumper", RSA),
            }),
        };
        let expected = format!(
            "# heimdall management ssh configuration (generated; do not edit; read only with ssh -F)\n\
             \n\
             Host hm-env-env_aa\n\
             \x20   HostName 10.0.0.7\n\
             \x20   User runner\n\
             \x20   ProxyJump hm-dest-bastion\n\
             \x20   HostKeyAlias hm-env-env_aa\n\
             \x20   HostKeyAlgorithms ssh-ed25519\n\
             {TRUST}{IDENTITY}\
             \n\
             Host hm-dest-bastion\n\
             \x20   HostName bastion.example.net\n\
             \x20   User jumper\n\
             \x20   HostKeyAlias hm-dest-bastion\n\
             \x20   HostKeyAlgorithms rsa-sha2-512,rsa-sha2-256\n\
             {TRUST}{IDENTITY}\
             \n\
             Host *\n\
             {TRUST}\
             \x20   IdentitiesOnly yes\n"
        );
        assert_eq!(render(&target), expected);
        let pin_file = String::from_utf8(render_mgmt_pin_file(&target).unwrap()).unwrap();
        assert_eq!(
            pin_file,
            "hm-dest-bastion ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7\n\
             hm-env-env_aa ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOVqmTNbwT7nI0Fk7RzD4mgwA0ke2pRDCgUNQ0FHb8xn\n"
        );
        // No environment is ever passed, no master is ever shared.
        let text = render(&target);
        assert!(!text.contains("SetEnv") && !text.contains("SendEnv"));
        assert!(!text.contains("ProxyCommand"));
        assert_eq!(text.matches("ControlMaster no").count(), 3);
    }

    /// Typed inputs only: names, pins, paths and users that OpenSSH would read differently
    /// are refused, never escaped.
    #[test]
    fn refused_inputs() {
        let base = MgmtTarget {
            environment: "env_aa".into(),
            hop: hop("10.0.0.7", None, "runner", ED),
            jump: None,
        };
        for bad in ["", "-x", "env aa", "env%aa", "env:aa", "env*"] {
            let mut t = base.clone();
            t.environment = bad.into();
            assert!(
                render_mgmt_config(&t, &pins(), PathStyle::Unix).is_err(),
                "{bad:?}"
            );
        }
        let mut t = base.clone();
        t.hop.pins.clear();
        assert!(render_mgmt_config(&t, &pins(), PathStyle::Unix).is_err());
        let mut t = base.clone();
        t.hop.user = "-oProxyCommand=x".into();
        assert!(render_mgmt_config(&t, &pins(), PathStyle::Unix).is_err());
        for bad_pin in [
            "ssh-dss AAAA",
            "ssh-ed25519-cert-v01@openssh.com AAAA",
            "sk-ssh-ed25519@openssh.com AAAA",
            "ssh-ed25519",
            "ssh-ed25519 AA\"AA",
        ] {
            assert!(PinnedKey::parse(bad_pin).is_err(), "{bad_pin}");
        }
        assert!(
            render_mgmt_config(&base, &unix("~/.ssh/pins"), PathStyle::Unix).is_err(),
            "a home-relative pin file depends on $HOME"
        );
        assert!(HopIdentity::new(unix("~/agent.sock"), unix("/k.pub")).is_err());
        assert!(HopIdentity::new(unix("/agent.sock"), unix("~/k.pub")).is_err());
        assert!(check_config_path_for_jump("/home/u/.local/state/heimdall/mgmt/env.conf").is_ok());
        for bad in ["/home/u/my files/env.conf", "/tmp/$x.conf", "/tmp/a;b", ""] {
            assert!(check_config_path_for_jump(bad).is_err(), "{bad:?}");
        }
    }

    /// Regression (G07 §8; m06-plan U2): a rendered alias never combines `IdentityAgent none`
    /// with `ForwardAgent <path>`, which OpenSSH 9.6p1 silently drops. The checker finds the
    /// combination in a block, through the global section, and with `=`/quoted spellings; the
    /// management configuration, P's managed sections and the forwarding launch option never
    /// produce it (a [`RenderPath`] cannot spell `none`).
    #[test]
    fn identity_agent_none_never_combines_with_forward_agent_path() {
        // The checker itself.
        let bad_block =
            "Host lab\n    IdentityAgent none\n    ForwardAgent \"/run/fixture-agent.sock\"\n";
        assert_eq!(agent_forwarding_conflicts(bad_block), ["Host lab"]);
        let bad_global = "IdentityAgent=none\nHost lab\n    ForwardAgent=yes\n";
        assert_eq!(agent_forwarding_conflicts(bad_global), ["Host lab"]);
        let fine = "Host lab\n    IdentityAgent none\n    ForwardAgent no\n\
                    Host b\n    IdentityAgent \"/run/a.sock\"\n    ForwardAgent \"/run/a.sock\"\n";
        assert!(agent_forwarding_conflicts(fine).is_empty());
        // First value wins, as OpenSSH reads it.
        let first_wins =
            "Host lab\n    ForwardAgent no\n    ForwardAgent /run/a.sock\n    IdentityAgent none\n";
        assert!(agent_forwarding_conflicts(first_wins).is_empty());
        assert_eq!(
            check_isolated(bad_block),
            Err(RenderError::RefusedValue("agent_forwarding"))
        );
        assert_eq!(
            check_isolated("Host a\n    SendEnv LANG\n"),
            Err(RenderError::RefusedValue("environment_passing"))
        );

        // The management configuration, direct and through a jump.
        for jump in [false, true] {
            let target = MgmtTarget {
                environment: "env_aa".into(),
                hop: hop("10.0.0.7", None, "runner", ED),
                jump: jump.then(|| MgmtJump {
                    destination: "bastion".into(),
                    hop: hop("10.0.0.8", None, "jumper", ED),
                }),
            };
            let text = render(&target);
            assert!(agent_forwarding_conflicts(&text).is_empty());
            assert!(!text.contains("IdentityAgent none"));
            assert!(!text.lines().any(|l| l.trim() == "ForwardAgent yes"));
        }

        // P's managed sections, and the forwarding launch option for the same endpoint.
        assert!(RenderPath::unix(Path::new("none")).is_err());
        assert!(RenderPath::windows(Path::new("none")).is_err());
        let agent = unix("/run/user/1000/heimdall/b/ab/agent.sock");
        let section = Section::ExistingAccess(ManagedAlias {
            alias: AliasName::parse("lab").unwrap(),
            hostname: HostName::parse("10.0.0.2").unwrap(),
            port: None,
            user: "deploy".into(),
            identity_agent: Some(agent.clone()),
            identity_files: vec![],
            identities_only: true,
        });
        let p = String::from_utf8(
            render_sections(&[section], PathStyle::Unix, DEFAULT_MANAGED_IDENTITY_FORM).unwrap(),
        )
        .unwrap();
        assert!(p.contains("IdentityAgent \"/run/user/1000/heimdall/b/ab/agent.sock\""));
        // The launch option applies to the alias's own block (`lab` is P's last block).
        let options = forward_agent_options(&agent, PathStyle::Unix).unwrap();
        let forward_line = format!("    {}\n", options[1].replacen('=', " ", 1));
        let launched = format!("{p}{forward_line}");
        assert!(
            agent_forwarding_conflicts(&launched).is_empty(),
            "{launched}"
        );
        // Positive control: the same launch over an `IdentityAgent none` block is caught.
        let defeated = launched.replace(
            "IdentityAgent \"/run/user/1000/heimdall/b/ab/agent.sock\"",
            "IdentityAgent none",
        );
        assert_eq!(agent_forwarding_conflicts(&defeated), ["Host lab"]);
    }
}
