//! ⟨M06 U5a⟩ Routes and host-key pins: the helper's isolated jump leg and the `ssh -G`
//! verification of projected aliases (ADR-0012 §5.2, §5.4, §5.5; m06-plan U5a). **Pure: no
//! I/O.**
//!
//! * [`jump_leg_args`]: the arguments of the route helper's jump leg, `ssh -F none <pins> -W
//!   <final host>:<port> <jump alias>`. `-F none` reads neither the user's nor the system's
//!   configuration, and every setting ADR-0012 §5.2 lists for a management hop is pinned on
//!   the command line with the jump's own catalog pin (`HostKeyAlias hm-dest-<jump id>`, the
//!   pin file, strict checking, no other trust source, no multiplexing, no forwarding but the
//!   one `-W` stream). ADR-0010 §5 items 1–4 are unchanged: the jump authenticates with its own
//!   access (a managed pair in the same grant, or existing access), decided by the caller.
//! * [`verify_effective`]: the effective configuration `ssh -G` prints for a projected alias
//!   (or for the jump leg's own arguments) must hold the catalog pin: `StrictHostKeyChecking
//!   yes` exactly, the expected `HostKeyAlias`, catalog-only trust, and no multiplexing or a
//!   `ControlPath` the active context's binding owns. Anything else is
//!   [`HostPinDefeated`] naming the setting (`host_pin_defeated`), including an override from
//!   an earlier `Host` or `Match` block, which `ssh -G` reports as the effective value.
//! * [`jump_leg_failure_is_terminal`]: a jump leg that ends before identification on a
//!   host-key or authentication failure is never failed over (ADR-0012 §5.5 item 3).

use crate::step::{absolute_path, alias_ok, hostname_ok, literal, unquoted};

/// The `HostKeyAlias` prefix of a destination's catalog pin (ADR-0012 §5.2; the same text
/// as `heimdall_domain::routes::HOST_KEY_ALIAS_PREFIX`).
pub const HOST_KEY_ALIAS_PREFIX: &str = "hm-dest-";

/// Why no jump-leg argument list was built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum JumpLegError {
    /// The jump's alias, host name, user or the final host is not a literal.
    #[error("the jump leg's target is not a valid literal")]
    Target,
    /// A path, endpoint or algorithm list is not a validated literal.
    #[error("a pinned value of the jump leg is not a validated literal")]
    Literal,
    /// The `HostKeyAlias` is not `hm-dest-<id>`.
    #[error("the jump's host-key alias is not a catalog pin")]
    Alias,
}

/// The jump hop of a helper route (ADR-0012 §5.4): reachability and the jump's own catalog
/// pin from the catalog, its access from the resolved binding (a managed pair in the same
/// grant: the binding endpoint and the jump pair's certificate) or from existing access (the
/// jump identity's endpoint and public key file). Paths are absolute, Windows paths with `/`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JumpHop {
    /// The jump destination's alias (the host argument; the pins decide everything else).
    pub alias: String,
    /// `HostName`.
    pub hostname: String,
    /// `Port`; 22 when absent.
    pub port: Option<u16>,
    /// `User`.
    pub user: String,
    /// `HostKeyAlias hm-dest-<jump id>`.
    pub host_key_alias: String,
    /// The pin file holding the jump's catalog-pinned key(s) under that alias.
    pub pin_file: String,
    /// `HostKeyAlgorithms`, when the pinned keys determine one.
    pub host_key_algorithms: Option<String>,
    /// `IdentityAgent`: the endpoint that holds the jump hop's identity.
    pub identity_agent: String,
    /// `IdentityFile`: the public key (existing access) or certificate (managed) file.
    pub identity_file: String,
    /// `CertificateFile`; `none` when absent.
    pub certificate_file: Option<String>,
}

fn pair(k: &str, v: impl Into<String>) -> (String, String) {
    (k.to_owned(), v.into())
}

/// `host:port` for `-W`, an IPv6 literal in brackets.
fn forward_target(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// An absolute path literal (no token, no environment reference, no quote).
fn path_literal(path: &str) -> Result<String, JumpLegError> {
    if !absolute_path(path) {
        return Err(JumpLegError::Literal);
    }
    literal(path).map_err(|_| JumpLegError::Literal)
}

/// The jump leg's `-o` pins, in order (module docs), without `-F none`, `-W` or the alias.
///
/// # Errors
/// [`JumpLegError`].
pub fn jump_leg_pins(hop: &JumpHop) -> Result<Vec<(String, String)>, JumpLegError> {
    if !alias_ok(&hop.alias)
        || !hostname_ok(&hop.hostname)
        || !crate::line::principal_part_ok(&hop.user)
        || hop.port == Some(0)
    {
        return Err(JumpLegError::Target);
    }
    let alias_ok = hop
        .host_key_alias
        .strip_prefix(HOST_KEY_ALIAS_PREFIX)
        .is_some_and(|id| {
            !id.is_empty()
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        });
    if !alias_ok {
        return Err(JumpLegError::Alias);
    }
    let endpoint = hop.identity_agent.to_ascii_lowercase();
    if endpoint == "none" || endpoint.contains("ssh_auth_sock") {
        return Err(JumpLegError::Literal);
    }
    let mut out = vec![
        pair("HostName", hop.hostname.clone()),
        pair("Port", hop.port.unwrap_or(22).to_string()),
        pair("User", hop.user.clone()),
        pair("ProxyCommand", "none"),
        pair("ProxyJump", "none"),
        pair("CanonicalizeHostname", "no"),
        pair("UserKnownHostsFile", path_literal(&hop.pin_file)?),
        pair("GlobalKnownHostsFile", "none"),
        pair("KnownHostsCommand", "none"),
        pair("VerifyHostKeyDNS", "no"),
    ];
    if let Some(alg) = &hop.host_key_algorithms {
        let ok = !alg.is_empty()
            && alg
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b',' | b'.' | b'@'));
        if !ok {
            return Err(JumpLegError::Literal);
        }
        out.push(pair("HostKeyAlgorithms", alg.clone()));
    }
    out.extend([
        pair("HostKeyAlias", hop.host_key_alias.clone()),
        pair("StrictHostKeyChecking", "yes"),
        pair("CheckHostIP", "no"),
        pair("UpdateHostKeys", "no"),
        pair("NoHostAuthenticationForLocalhost", "no"),
        pair("IdentityAgent", path_literal(&hop.identity_agent)?),
        pair("IdentityFile", path_literal(&hop.identity_file)?),
        pair("IdentitiesOnly", "yes"),
        pair(
            "CertificateFile",
            match &hop.certificate_file {
                Some(c) => path_literal(c)?,
                None => "none".to_owned(),
            },
        ),
        pair("ControlMaster", "no"),
        pair("ControlPath", "none"),
        pair("ControlPersist", "no"),
        pair("BatchMode", "yes"),
        pair("ForwardAgent", "no"),
        pair("ClearAllForwardings", "yes"),
        pair("PermitLocalCommand", "no"),
        pair("RequestTTY", "no"),
        pair("ForkAfterAuthentication", "no"),
        pair("LogLevel", "ERROR"),
    ]);
    Ok(out)
}

/// The jump leg's arguments after the client path (ADR-0012 §5.4): `-F none`, every pin of
/// [`jump_leg_pins`], `-W <final host>:<final port>` and the jump alias. The final host is the
/// destination's own address as the jump host reaches it.
///
/// # Errors
/// [`JumpLegError`].
pub fn jump_leg_args(
    hop: &JumpHop,
    final_host: &str,
    final_port: u16,
) -> Result<Vec<String>, JumpLegError> {
    if !hostname_ok(final_host) || final_port == 0 {
        return Err(JumpLegError::Target);
    }
    let mut args = vec!["-F".to_owned(), "none".to_owned()];
    for (k, v) in jump_leg_pins(hop)? {
        args.push("-o".to_owned());
        args.push(format!("{k}={v}"));
    }
    args.push("-W".to_owned());
    args.push(forward_target(final_host, final_port));
    args.push(hop.alias.clone());
    Ok(args)
}

/// The arguments of the jump leg's own effective-configuration check: `-G`, `-F none`, the
/// same pins and the alias (no `-W`).
///
/// # Errors
/// [`JumpLegError`].
pub fn jump_leg_check_args(hop: &JumpHop) -> Result<Vec<String>, JumpLegError> {
    let mut args = vec!["-G".to_owned(), "-F".to_owned(), "none".to_owned()];
    for (k, v) in jump_leg_pins(hop)? {
        args.push("-o".to_owned());
        args.push(format!("{k}={v}"));
    }
    args.push(hop.alias.clone());
    Ok(args)
}

/// The [`PinExpectation`] the jump leg's own `ssh -G` must meet.
#[must_use]
pub fn jump_leg_expectation(hop: &JumpHop) -> PinExpectation {
    PinExpectation {
        host_key_alias: hop.host_key_alias.clone(),
        pin_file: unquoted(&hop.pin_file).to_owned(),
        owned_control_path: None,
        proxy: ExpectedProxy::None,
    }
}

// --- the effective-configuration verification (ADR-0012 §5.2) ---------------------------

/// What the effective proxy of a verified alias must be.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ExpectedProxy {
    /// Direct (`ProxyCommand` and `ProxyJump` unset or `none`).
    None,
    /// Heimdall's route helper: exactly this `ProxyCommand` text (as rendered).
    Helper(String),
    /// A native single-hop jump: exactly this `ProxyJump` alias.
    Jump(String),
}

/// What a verified alias's effective configuration must hold (ADR-0012 §5.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PinExpectation {
    /// The expected `HostKeyAlias` (`hm-dest-<id>`).
    pub host_key_alias: String,
    /// The pin file, as `ssh -G` prints it (absolute, `~` expanded).
    pub pin_file: String,
    /// The `ControlPath` the active context's binding owns (its stable mux path), if any.
    pub owned_control_path: Option<String>,
    /// The effective proxy.
    pub proxy: ExpectedProxy,
}

/// What is wrong with a setting ([`HostPinDefeated::kind`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DefeatKind {
    /// Absent where a value is required.
    Missing,
    /// Another value.
    Mismatch,
    /// Printed more than once.
    Repeated,
}

/// The catalog pin does not hold effectively (`CAPABILITY_UNAVAILABLE`, reason
/// `host_pin_defeated`, naming the setting; ADR-0012 §5.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
#[error("host_pin_defeated: {setting} ({kind:?})")]
pub struct HostPinDefeated {
    /// The setting, as `ssh -G` names it (lowercase).
    pub setting: &'static str,
    /// What is wrong.
    pub kind: DefeatKind,
}

/// The stable reason of a [`HostPinDefeated`] refusal.
pub const HOST_PIN_DEFEATED: &str = "host_pin_defeated";

fn yes(v: &str) -> bool {
    v == "yes" || v == "true"
}

fn no(v: &str) -> bool {
    v == "no" || v == "false"
}

fn none_or_absent(v: Option<&str>) -> bool {
    v.is_none_or(|v| v.eq_ignore_ascii_case("none"))
}

/// A path as `ssh -G` prints it, compared with `\` read as `/` and a drive letter's case
/// aside.
fn same_path(a: &str, b: &str) -> bool {
    let (a, b) = (a.replace('\\', "/"), b.replace('\\', "/"));
    if a.as_bytes().get(1) == Some(&b':') {
        a.eq_ignore_ascii_case(&b)
    } else {
        a == b
    }
}

/// Verify `ssh -G` output against `expect` (ADR-0012 §5.2, module docs). Checked, in order:
/// `stricthostkeychecking` exactly `yes` (`no`, `off`, `accept-new` and `ask` are refused even
/// with the pin file in use); `hostkeyalias`; `userknownhostsfile` the pin file only;
/// `globalknownhostsfile` `none` or `/dev/null`; no `knownhostscommand`; `verifyhostkeydns
/// no`; `updatehostkeys no`; `controlmaster no` with `controlpath` none or the owned path;
/// and the proxy. A setting printed twice is refused.
///
/// # Errors
/// [`HostPinDefeated`] naming the first setting that does not hold.
pub fn verify_effective(
    ssh_g_output: &str,
    expect: &PinExpectation,
) -> Result<(), HostPinDefeated> {
    let effective: Vec<(String, &str)> = ssh_g_output
        .lines()
        .map(|l| l.trim_end_matches('\r'))
        .map(|l| {
            let (k, v) = l.split_once(' ').unwrap_or((l, ""));
            (k.to_ascii_lowercase(), v)
        })
        .collect();
    let get = |setting: &'static str| -> Result<Option<&str>, HostPinDefeated> {
        let mut found = effective
            .iter()
            .filter(|(k, _)| k == setting)
            .map(|(_, v)| *v);
        let first = found.next();
        if found.next().is_some() {
            return Err(HostPinDefeated {
                setting,
                kind: DefeatKind::Repeated,
            });
        }
        Ok(first)
    };
    let check = |setting: &'static str, ok: &dyn Fn(Option<&str>) -> bool| {
        let got = get(setting)?;
        if ok(got) {
            Ok(())
        } else {
            Err(HostPinDefeated {
                setting,
                kind: if got.is_none() {
                    DefeatKind::Missing
                } else {
                    DefeatKind::Mismatch
                },
            })
        }
    };
    check("stricthostkeychecking", &|v| v.is_some_and(yes))?;
    check("hostkeyalias", &|v| {
        v.is_some_and(|v| v.eq_ignore_ascii_case(&expect.host_key_alias))
    })?;
    check("userknownhostsfile", &|v| {
        v.is_some_and(|v| same_path(v, &expect.pin_file))
    })?;
    check("globalknownhostsfile", &|v| {
        v.is_some_and(|v| v.eq_ignore_ascii_case("none") || v == "/dev/null")
    })?;
    check("knownhostscommand", &none_or_absent)?;
    check("verifyhostkeydns", &|v| v.is_some_and(no))?;
    check("updatehostkeys", &|v| v.is_some_and(no))?;
    check("controlmaster", &|v| v.is_some_and(no))?;
    check("controlpath", &|v| match (v, &expect.owned_control_path) {
        (None, _) => true,
        (Some(v), _) if v.eq_ignore_ascii_case("none") => true,
        (Some(v), Some(owned)) => same_path(v, owned),
        (Some(_), None) => false,
    })?;
    match &expect.proxy {
        ExpectedProxy::None => {
            check("proxycommand", &none_or_absent)?;
            check("proxyjump", &none_or_absent)?;
        }
        ExpectedProxy::Helper(command) => {
            check("proxycommand", &|v| v == Some(command.as_str()))?;
            check("proxyjump", &none_or_absent)?;
        }
        ExpectedProxy::Jump(alias) => {
            check("proxyjump", &|v| v == Some(alias.as_str()))?;
            check("proxycommand", &none_or_absent)?;
        }
    }
    Ok(())
}

/// Whether a jump leg that ended before the server's identification ended on a host-key or
/// authentication failure (its `stderr`, at `LogLevel ERROR`): such a failure is never failed
/// over (ADR-0012 §5.5 item 3), even though a jump leg's exit before identification otherwise
/// is (item 2). Read conservatively: any of OpenSSH's host-key or authentication messages
/// counts.
#[must_use]
pub fn jump_leg_failure_is_terminal(stderr: &str) -> bool {
    [
        "Host key verification failed",
        "REMOTE HOST IDENTIFICATION HAS CHANGED",
        "No ED25519 host key is known",
        "No RSA host key is known",
        "No ECDSA host key is known",
        "host key is known for",
        "Permission denied",
        "Too many authentication failures",
        "No more authentication methods",
    ]
    .iter()
    .any(|m| stderr.contains(m))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn hop() -> JumpHop {
        JumpHop {
            alias: "bastion".into(),
            hostname: "10.0.0.1".into(),
            port: Some(2200),
            user: "jump".into(),
            host_key_alias: "hm-dest-bastion".into(),
            pin_file: "/run/hm/pins/known hosts".into(),
            host_key_algorithms: Some("ssh-ed25519".into()),
            identity_agent: "/run/hm/b/agent.sock".into(),
            identity_file: "/data/managed/bastion/cert.pub".into(),
            certificate_file: None,
        }
    }

    /// ADR-0012 §5.2, §5.4: the jump leg reads no configuration file and pins every
    /// management-hop setting with the jump's own catalog pin.
    #[test]
    fn jump_leg_pins_every_setting_and_reads_no_configuration() {
        let args = jump_leg_args(&hop(), "10.0.0.2", 22).unwrap();
        assert_eq!(&args[..2], ["-F", "none"]);
        assert_eq!(&args[args.len() - 3..], ["-W", "10.0.0.2:22", "bastion"]);
        for want in [
            "HostName=10.0.0.1",
            "Port=2200",
            "User=jump",
            "ProxyCommand=none",
            "ProxyJump=none",
            "UserKnownHostsFile=\"/run/hm/pins/known hosts\"",
            "GlobalKnownHostsFile=none",
            "KnownHostsCommand=none",
            "VerifyHostKeyDNS=no",
            "HostKeyAlgorithms=ssh-ed25519",
            "HostKeyAlias=hm-dest-bastion",
            "StrictHostKeyChecking=yes",
            "UpdateHostKeys=no",
            "IdentityAgent=/run/hm/b/agent.sock",
            "IdentityFile=/data/managed/bastion/cert.pub",
            "IdentitiesOnly=yes",
            "CertificateFile=none",
            "ControlMaster=no",
            "ControlPath=none",
            "ForwardAgent=no",
            "ClearAllForwardings=yes",
            "PermitLocalCommand=no",
            "BatchMode=yes",
        ] {
            assert!(args.iter().any(|a| a == want), "{want}: {args:?}");
        }
        assert_eq!(
            jump_leg_args(&hop(), "::1", 2222).unwrap()[args.len() - 2],
            "[::1]:2222"
        );
        // Refused: a token, an environment reference, the environment's agent, a non-pin
        // alias, an option-looking alias, a relative path.
        let refused = |f: &dyn Fn(&mut JumpHop)| {
            let mut h = hop();
            f(&mut h);
            jump_leg_args(&h, "10.0.0.2", 22).unwrap_err()
        };
        assert_eq!(
            refused(&|h| h.pin_file = "/p/%h".into()),
            JumpLegError::Literal
        );
        assert_eq!(
            refused(&|h| h.identity_file = "$HOME/k".into()),
            JumpLegError::Literal
        );
        assert_eq!(
            refused(&|h| h.identity_agent = "/x/SSH_AUTH_SOCK".into()),
            JumpLegError::Literal
        );
        assert_eq!(
            refused(&|h| h.host_key_alias = "bastion".into()),
            JumpLegError::Alias
        );
        assert_eq!(
            refused(&|h| h.alias = "-oProxyCommand=x".into()),
            JumpLegError::Target
        );
        assert_eq!(
            refused(&|h| h.pin_file = "pins".into()),
            JumpLegError::Literal
        );
        assert_eq!(
            jump_leg_args(&hop(), "-oProxyCommand=x", 22),
            Err(JumpLegError::Target)
        );
    }

    fn good() -> String {
        [
            "user deploy",
            "hostname 10.0.0.2",
            "stricthostkeychecking true",
            "hostkeyalias hm-dest-lab",
            "userknownhostsfile /run/hm/pins/known hosts",
            "globalknownhostsfile none",
            "verifyhostkeydns false",
            "updatehostkeys false",
            "controlmaster false",
            "proxycommand \"/opt/heimdall\" route connect --destination lab --account deploy --endpoint \"/run/a.sock\"",
        ]
        .join("\n")
    }

    fn expect() -> PinExpectation {
        PinExpectation {
            host_key_alias: "hm-dest-lab".into(),
            pin_file: "/run/hm/pins/known hosts".into(),
            owned_control_path: Some("/run/hm/mux/lab".into()),
            proxy: ExpectedProxy::Helper(
                "\"/opt/heimdall\" route connect --destination lab --account deploy --endpoint \"/run/a.sock\""
                    .into(),
            ),
        }
    }

    /// ADR-0012 §5.2: every effective setting that defeats the catalog pin is refused,
    /// named, including `StrictHostKeyChecking no` with the pin file in use.
    #[test]
    fn each_defeating_setting_is_named() {
        assert_eq!(verify_effective(&good(), &expect()), Ok(()));
        let defeated = |from: &str, to: &str| {
            let text = good().replace(from, to);
            assert_ne!(text, good(), "{from}");
            verify_effective(&text, &expect()).unwrap_err()
        };
        for (from, to, setting) in [
            (
                "stricthostkeychecking true",
                "stricthostkeychecking false",
                "stricthostkeychecking",
            ),
            (
                "stricthostkeychecking true",
                "stricthostkeychecking accept-new",
                "stricthostkeychecking",
            ),
            (
                "stricthostkeychecking true",
                "stricthostkeychecking ask",
                "stricthostkeychecking",
            ),
            (
                "hostkeyalias hm-dest-lab",
                "hostkeyalias other",
                "hostkeyalias",
            ),
            (
                "userknownhostsfile /run/hm/pins/known hosts",
                "userknownhostsfile /run/hm/pins/known hosts /home/u/.ssh/known_hosts",
                "userknownhostsfile",
            ),
            (
                "globalknownhostsfile none",
                "globalknownhostsfile /etc/ssh/ssh_known_hosts",
                "globalknownhostsfile",
            ),
            (
                "verifyhostkeydns false",
                "verifyhostkeydns ask",
                "verifyhostkeydns",
            ),
            (
                "updatehostkeys false",
                "updatehostkeys ask",
                "updatehostkeys",
            ),
            ("controlmaster false", "controlmaster auto", "controlmaster"),
            (
                "proxycommand \"/opt",
                "proxycommand \"/other",
                "proxycommand",
            ),
        ] {
            assert_eq!(defeated(from, to).setting, setting, "{to}");
        }
        assert_eq!(
            defeated("hostkeyalias hm-dest-lab\n", "").kind,
            DefeatKind::Missing
        );
        let with = |extra: &str| verify_effective(&format!("{}\n{extra}", good()), &expect());
        assert_eq!(
            with("knownhostscommand /bin/kh %H").unwrap_err().setting,
            "knownhostscommand"
        );
        assert_eq!(
            with("controlpath /tmp/foreign").unwrap_err().setting,
            "controlpath"
        );
        assert_eq!(with("proxyjump other").unwrap_err().setting, "proxyjump");
        assert_eq!(
            with("stricthostkeychecking true").unwrap_err().kind,
            DefeatKind::Repeated
        );
        // The binding's own mux path, `none` and `/dev/null` are accepted.
        assert_eq!(with("controlpath /run/hm/mux/lab"), Ok(()));
        assert_eq!(with("knownhostscommand none"), Ok(()));
        let dev_null = good().replace(
            "globalknownhostsfile none",
            "globalknownhostsfile /dev/null",
        );
        assert_eq!(verify_effective(&dev_null, &expect()), Ok(()));
    }

    #[test]
    fn jump_leg_terminal_failures() {
        assert!(jump_leg_failure_is_terminal(
            "Host key verification failed.\r\n"
        ));
        assert!(jump_leg_failure_is_terminal(
            "jump@127.0.0.1: Permission denied (publickey).\n"
        ));
        assert!(!jump_leg_failure_is_terminal(
            "ssh: connect to host 127.0.0.1 port 9: Connection refused\n"
        ));
    }
}
