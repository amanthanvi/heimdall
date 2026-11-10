//! The remote step builder (ADR-0008 D5 §6.3; m03-plan U5 `registry::step`):
//! [`remote_step`] with the full pin set and the fixed remote command, [`trust_pins`]
//! and [`check_effective`] (the `ssh -G` comparison, with the Q23 default).
//!
//! The frozen wire shape is `heimdall_contract::enrollment::{RemoteStep, StepPins}`
//! (m03-plan U0 "Frozen in wave 0"). Every `-o` is `Key=Value`, rendered in this
//! order (D5 §6.3 "Invocation"):
//! * **target** ([`target_pins`]): `HostName`, `Port`, `User` (the approved target),
//!   `ProxyCommand=none`, `ProxyJump=none`, `CanonicalizeHostname=no`;
//! * **host trust** ([`trust_pins`], the table of D5 §6.3, in its order):
//!   `UserKnownHostsFile=<generated>`, `GlobalKnownHostsFile=<generated, empty>`,
//!   `KnownHostsCommand=none`, `VerifyHostKeyDNS=no`, `HostKeyAlgorithms=<the approved
//!   key's>`, `HostKeyAlias=hm-target-<16 hex>`, `StrictHostKeyChecking=yes`,
//!   `CheckHostIP=no`, `UpdateHostKeys=no`, `NoHostAuthenticationForLocalhost=no`,
//!   and `GSSAPIKeyExchange=no` only for a client whose `ssh -G` lists the option
//!   (Q23 default, [`client_lists_gssapi_kex`]);
//! * **existing access** ([`access_pins`]): `IdentityAgent=<the approved concrete
//!   endpoint>`, `IdentityFile`, `IdentitiesOnly=yes`, `CertificateFile=none`,
//!   `ControlMaster=no`, `ControlPath=none`;
//! * **narrowing** ([`narrowing_pins`]): `BatchMode` (`yes` unless the step is
//!   interactive), `ForwardAgent=no`, `ClearAllForwardings=yes`,
//!   `PermitLocalCommand=no`, `RequestTTY=no`, `ForkAfterAuthentication=no`;
//!
//! then `-T`, the alias and [`REMOTE_COMMAND`] ([`ssh_args`]).
//!
//! **Literals.** A value is a validated literal ([`literal`]): no control character,
//! no `"`, `'`, `\`, `%` (a token), `$` (an environment reference), `#` or backtick;
//! a value with a space is written in double quotes, which `ssh -o` removes. A
//! Windows path is given with `/` separators (`C:/…`, `//./pipe/<name>`).

use heimdall_contract::enrollment::{
    AccessPins, ApprovedTarget, EnrollmentPlan, NarrowingPins, RegistryCanonical,
    RegistryResolvedBy, RemoteStage, RemoteStep, SshOption, StepPins, TargetPins, TrustPins,
};

use crate::classify::token_ok;
use crate::line::marker_of;
use crate::script::{
    self, AppendParams, BootstrapParams, FenceParams, InspectParams, Marker, NotAfter, Payload,
    RegistryLine, RegistryLocation, RemoveParams, StepToken,
};

/// The fixed remote command (D5 §6.3, the ready handshake).
pub const REMOTE_COMMAND: &str = "printf 'HM1 ready\\n'; exec /bin/sh -s";

/// The `HostKeyAlias` prefix; the alias is `hm-target-<16 hex>`.
pub const HOST_KEY_ALIAS_PREFIX: &str = "hm-target-";

/// The host-trust options of D5 §6.3's table, in order (without the Q23 option).
pub const TRUST_KEYS: [&str; 10] = [
    "UserKnownHostsFile",
    "GlobalKnownHostsFile",
    "KnownHostsCommand",
    "VerifyHostKeyDNS",
    "HostKeyAlgorithms",
    "HostKeyAlias",
    "StrictHostKeyChecking",
    "CheckHostIP",
    "UpdateHostKeys",
    "NoHostAuthenticationForLocalhost",
];

/// The Q23 option, pinned `no` where the client lists it.
pub const GSSAPI_KEX: &str = "GSSAPIKeyExchange";

/// The target options, in order.
pub const TARGET_KEYS: [&str; 6] = [
    "HostName",
    "Port",
    "User",
    "ProxyCommand",
    "ProxyJump",
    "CanonicalizeHostname",
];

/// The existing-access options, in order.
pub const ACCESS_KEYS: [&str; 6] = [
    "IdentityAgent",
    "IdentityFile",
    "IdentitiesOnly",
    "CertificateFile",
    "ControlMaster",
    "ControlPath",
];

/// The narrowing options, in order.
pub const NARROWING_KEYS: [&str; 6] = [
    "BatchMode",
    "ForwardAgent",
    "ClearAllForwardings",
    "PermitLocalCommand",
    "RequestTTY",
    "ForkAfterAuthentication",
];

/// Why no step (or pin) was built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum StepError {
    /// The approved host key's type cannot be pinned (`HostKeyAlgorithms`).
    #[error("the approved host key's type cannot be pinned")]
    HostKeyType,
    /// The approved target's host name or user is not a literal.
    #[error("the approved target is not a valid literal")]
    Target,
    /// The alias is not a literal host name.
    #[error("the alias is not a literal host name")]
    Alias,
    /// A path or endpoint is not a validated literal.
    #[error("a pinned value is not a validated literal")]
    Literal,
    /// The approved host-trust pins are not the documented set.
    #[error("the approved host-trust pins are not the documented set")]
    TrustPins,
    /// The approved existing-access invocation is not the documented set.
    #[error("the approved existing-access invocation is not the documented set")]
    Invocation,
    /// The step token is not 32 lowercase hex.
    #[error("the step token is malformed")]
    Token,
    /// The not-after is missing for a locking stage, or present for another.
    #[error("the remote not-after does not fit the stage")]
    NotAfter,
    /// The client path is not absolute.
    #[error("the client path is not absolute")]
    Client,
    /// The script parameters were refused (`registry::script`).
    #[error("the script parameters were refused")]
    Script,
    /// A stage this build does not know.
    #[error("the stage is not supported")]
    Stage,
}

/// Whether `alias` is a literal OpenSSH host name (the catalog's rule): from
/// `[A-Za-z0-9._-]`, no leading `-` or `.`, at most 255 bytes.
#[must_use]
pub fn alias_ok(alias: &str) -> bool {
    !alias.is_empty()
        && alias.len() <= 255
        && !alias.starts_with(['-', '.'])
        && alias
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Whether `host` is a literal `HostName` (the catalog's rule): from
/// `[A-Za-z0-9._:[]-]`, no leading `-`, at most 255 bytes; no `%` token.
#[must_use]
pub fn hostname_ok(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 255
        && !host.starts_with('-')
        && host.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':' | b'[' | b']')
        })
}

/// `HostKeyAlgorithms` for an approved key type: the type itself, or for RSA
/// `rsa-sha2-512,rsa-sha2-256`. `None` for anything else (a certificate type, DSA,
/// a security-key type, an unknown name): such a key cannot be the only trust source.
#[must_use]
pub fn host_key_algorithms(key_type: &str) -> Option<&'static str> {
    Some(match key_type {
        "ssh-ed25519" => "ssh-ed25519",
        "ecdsa-sha2-nistp256" => "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384" => "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521" => "ecdsa-sha2-nistp521",
        "ssh-rsa" => "rsa-sha2-512,rsa-sha2-256",
        _ => return None,
    })
}

/// A validated literal for an `-o Key=Value` value (module docs); a value with a
/// space is quoted.
///
/// # Errors
/// [`StepError::Literal`].
pub fn literal(raw: &str) -> Result<String, StepError> {
    let refused =
        |c: char| c.is_control() || matches!(c, '"' | '\'' | '\\' | '%' | '$' | '#' | '`');
    if raw.is_empty() || raw.len() > 1024 || raw.chars().any(refused) || raw.trim() != raw {
        return Err(StepError::Literal);
    }
    Ok(if raw.contains(' ') {
        format!("\"{raw}\"")
    } else {
        raw.to_owned()
    })
}

/// The literal's text as `ssh -G` prints it (the quotes removed).
#[must_use]
pub fn unquoted(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value)
}

/// Whether `path` is absolute: `/…`, a drive path `X:/…`, or a pipe `//./pipe/…`.
#[must_use]
pub fn absolute_path(path: &str) -> bool {
    let b = path.as_bytes();
    path.starts_with('/')
        || (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'/')
}

/// The generated files a step's host trust names (D5 §6.3 table; written and
/// digest-checked by the runtime before it returns the step).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TrustPaths {
    /// 16 lowercase hex: `HostKeyAlias hm-target-<tag>` (and the directory
    /// `<runtime_dir>/e/<tag>/`).
    pub tag: String,
    /// The owner-only known-hosts file holding exactly one line: the alias and the
    /// approved key.
    pub user_known_hosts: String,
    /// The empty global known-hosts file.
    pub global_known_hosts: String,
}

fn tag_ok(tag: &str) -> bool {
    tag.len() == 16 && tag.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn pair(k: &str, v: impl Into<String>) -> (String, String) {
    (k.to_owned(), v.into())
}

/// The host-trust pins of D5 §6.3's table, in order, for `target` and the generated
/// `paths` (without the Q23 option; [`remote_step`] adds it per client).
///
/// # Errors
/// [`StepError::HostKeyType`] for a key that cannot be pinned; [`StepError::Literal`]
/// for a tag or path that is not a validated absolute literal.
pub fn trust_pins(
    target: &ApprovedTarget,
    paths: &TrustPaths,
) -> Result<Vec<(String, String)>, StepError> {
    let algorithms =
        host_key_algorithms(&target.host_key.algorithm).ok_or(StepError::HostKeyType)?;
    if !tag_ok(&paths.tag)
        || !absolute_path(&paths.user_known_hosts)
        || !absolute_path(&paths.global_known_hosts)
    {
        return Err(StepError::Literal);
    }
    Ok(vec![
        pair(TRUST_KEYS[0], literal(&paths.user_known_hosts)?),
        pair(TRUST_KEYS[1], literal(&paths.global_known_hosts)?),
        pair(TRUST_KEYS[2], "none"),
        pair(TRUST_KEYS[3], "no"),
        pair(TRUST_KEYS[4], algorithms),
        pair(
            TRUST_KEYS[5],
            format!("{HOST_KEY_ALIAS_PREFIX}{}", paths.tag),
        ),
        pair(TRUST_KEYS[6], "yes"),
        pair(TRUST_KEYS[7], "no"),
        pair(TRUST_KEYS[8], "no"),
        pair(TRUST_KEYS[9], "no"),
    ])
}

/// The target pins, in order.
///
/// # Errors
/// [`StepError::Target`] for a host name or user that is not a literal.
pub fn target_pins(target: &ApprovedTarget) -> Result<Vec<(String, String)>, StepError> {
    let user = target.user.as_str();
    if !hostname_ok(&target.hostname) || !crate::line::principal_part_ok(user) {
        return Err(StepError::Target);
    }
    Ok(vec![
        pair(TARGET_KEYS[0], target.hostname.clone()),
        pair(TARGET_KEYS[1], target.port.to_string()),
        pair(TARGET_KEYS[2], user),
        pair(TARGET_KEYS[3], "none"),
        pair(TARGET_KEYS[4], "none"),
        pair(TARGET_KEYS[5], "no"),
    ])
}

/// The existing-access pins, in order, for the approved concrete endpoint and the
/// adopted public key file (both validated literals; [`literal`]).
///
/// # Errors
/// [`StepError::Literal`].
pub fn access_pins(
    endpoint: &str,
    identity_file: &str,
) -> Result<Vec<(String, String)>, StepError> {
    let lower = endpoint.to_ascii_lowercase();
    if !absolute_path(endpoint) || lower == "none" || lower.contains("ssh_auth_sock") {
        return Err(StepError::Literal);
    }
    Ok(vec![
        pair(ACCESS_KEYS[0], literal(endpoint)?),
        pair(ACCESS_KEYS[1], literal(identity_file)?),
        pair(ACCESS_KEYS[2], "yes"),
        pair(ACCESS_KEYS[3], "none"),
        pair(ACCESS_KEYS[4], "no"),
        pair(ACCESS_KEYS[5], "none"),
    ])
}

/// The narrowing pins, in order.
#[must_use]
pub fn narrowing_pins(interactive: bool) -> Vec<(String, String)> {
    vec![
        pair(NARROWING_KEYS[0], if interactive { "no" } else { "yes" }),
        pair(NARROWING_KEYS[1], "no"),
        pair(NARROWING_KEYS[2], "yes"),
        pair(NARROWING_KEYS[3], "no"),
        pair(NARROWING_KEYS[4], "no"),
        pair(NARROWING_KEYS[5], "no"),
    ]
}

/// `Key=Value` strings (the plan's `host_trust`).
#[must_use]
pub fn render_pairs(pairs: &[(String, String)]) -> Vec<String> {
    pairs.iter().map(|(k, v)| format!("{k}={v}")).collect()
}

/// `["-o", "Key=Value", …]` (the plan's existing-access `invocation`).
#[must_use]
pub fn render_invocation(pairs: &[(String, String)]) -> Vec<String> {
    pairs
        .iter()
        .flat_map(|(k, v)| ["-o".to_owned(), format!("{k}={v}")])
        .collect()
}

fn options(pairs: Vec<(String, String)>) -> Vec<SshOption> {
    pairs
        .into_iter()
        .map(|(key, value)| SshOption { key, value })
        .collect()
}

/// Parse `Key=Value` strings back, requiring exactly `keys` in order.
fn parse_pairs<'a>(
    items: impl Iterator<Item = &'a str>,
    keys: &[&str],
) -> Option<Vec<(String, String)>> {
    let pairs: Vec<(String, String)> = items
        .map(|item| {
            item.split_once('=')
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
        })
        .collect::<Option<_>>()?;
    let same = pairs.len() == keys.len() && pairs.iter().zip(keys).all(|((k, _), want)| k == want);
    same.then_some(pairs)
}

fn literal_round_trips(value: &str) -> bool {
    literal(unquoted(value)).is_ok_and(|v| v == value)
}

/// Check the approved host-trust strings against the documented set for `target`.
fn approved_trust(
    target: &ApprovedTarget,
    host_trust: &[String],
) -> Result<Vec<(String, String)>, StepError> {
    let pairs = parse_pairs(host_trust.iter().map(String::as_str), &TRUST_KEYS)
        .ok_or(StepError::TrustPins)?;
    let algorithms =
        host_key_algorithms(&target.host_key.algorithm).ok_or(StepError::HostKeyType)?;
    let v = |i: usize| pairs[i].1.as_str();
    let ok = literal_round_trips(v(0))
        && absolute_path(unquoted(v(0)))
        && literal_round_trips(v(1))
        && absolute_path(unquoted(v(1)))
        && v(2) == "none"
        && v(3) == "no"
        && v(4) == algorithms
        && v(5).strip_prefix(HOST_KEY_ALIAS_PREFIX).is_some_and(tag_ok)
        && v(6) == "yes"
        && v(7) == "no"
        && v(8) == "no"
        && v(9) == "no";
    if ok {
        Ok(pairs)
    } else {
        Err(StepError::TrustPins)
    }
}

/// Check the approved existing-access invocation (`-o`, `Key=Value` pairs).
fn approved_access(invocation: &[String]) -> Result<Vec<(String, String)>, StepError> {
    if invocation.len() != 2 * ACCESS_KEYS.len() || invocation.iter().step_by(2).any(|o| o != "-o")
    {
        return Err(StepError::Invocation);
    }
    let pairs = parse_pairs(
        invocation.iter().skip(1).step_by(2).map(String::as_str),
        &ACCESS_KEYS,
    )
    .ok_or(StepError::Invocation)?;
    let rebuilt = access_pins(unquoted(&pairs[0].1), unquoted(&pairs[1].1))
        .map_err(|_| StepError::Invocation)?;
    if rebuilt == pairs {
        Ok(pairs)
    } else {
        Err(StepError::Invocation)
    }
}

/// What a step runs against: the approved target and invocation, the registry, the
/// marker and the line. From an [`EnrollmentPlan`] ([`StepTarget::from_plan`]) or
/// from a record (a removal).
#[derive(Debug, Clone, Copy)]
pub struct StepTarget<'a> {
    /// The managed alias.
    pub alias: &'a str,
    /// The approved target.
    pub target: &'a ApprovedTarget,
    /// The approved host-trust pins (`Key=Value`, the plan's `host_trust`).
    pub host_trust: &'a [String],
    /// The approved existing-access invocation (`-o`, `Key=Value`, …).
    pub invocation: &'a [String],
    /// The canonical registry (never the display form).
    pub registry: &'a RegistryCanonical,
    /// The exact registry line (its last field is the marker).
    pub line: &'a str,
}

impl<'a> StepTarget<'a> {
    /// The plan's target, with the canonical `registry` the caller holds (the plan
    /// carries only the display form).
    #[must_use]
    pub fn from_plan(plan: &'a EnrollmentPlan, registry: &'a RegistryCanonical) -> Self {
        StepTarget {
            alias: &plan.alias,
            target: &plan.approved_target,
            host_trust: &plan.host_trust,
            invocation: &plan.existing_access.invocation,
            registry,
            line: &plan.line,
        }
    }
}

/// The stage of a step, with what its script needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StageInput<'a> {
    /// `inspect`.
    Inspect,
    /// `bootstrap`.
    Bootstrap,
    /// `append`.
    Append,
    /// `remove`, with the inspected preimage and the post-image
    /// ([`crate::post_image::post_image_without`]).
    Remove {
        /// The preimage the registry must still equal.
        preimage: &'a [u8],
        /// The post-image renamed over the registry.
        post_image: &'a [u8],
    },
    /// `fence` (`terminate`: `--terminate`).
    Fence {
        /// TERM then KILL of an `alive` holder past its not-after.
        terminate: bool,
    },
}

impl StageInput<'_> {
    /// The wire stage.
    #[must_use]
    pub fn stage(&self) -> RemoteStage {
        match self {
            StageInput::Inspect => RemoteStage::Inspect,
            StageInput::Bootstrap => RemoteStage::Bootstrap,
            StageInput::Append => RemoteStage::Append,
            StageInput::Remove { .. } => RemoteStage::Remove,
            StageInput::Fence { .. } => RemoteStage::Fence,
        }
    }
}

/// The runtime's facts for one step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StepEnv<'a> {
    /// The verified client's absolute path.
    pub client: &'a str,
    /// The step timeout.
    pub timeout_ms: u64,
    /// The owner's terminal is attached (`BatchMode=no`); otherwise `BatchMode=yes`.
    pub interactive: bool,
    /// The client's `ssh -G` lists `gssapikeyexchange` (Q23): `GSSAPIKeyExchange=no`
    /// is added to the host-trust pins.
    pub gssapi_key_exchange: bool,
}

fn location(registry: &RegistryCanonical) -> Result<RegistryLocation, StepError> {
    let path = match registry.resolved_by {
        RegistryResolvedBy::RemoteHome => {
            if registry.path.is_some() {
                return Err(StepError::Script);
            }
            None
        }
        RegistryResolvedBy::Explicit => Some(registry.path.as_deref().ok_or(StepError::Script)?),
        _ => return Err(StepError::Script),
    };
    RegistryLocation::from_plan(path).map_err(|_| StepError::Script)
}

fn script_for(
    stage: StageInput<'_>,
    target: &StepTarget<'_>,
    token: &str,
    not_after_remote: Option<i64>,
) -> Result<String, StepError> {
    let registry = location(target.registry)?;
    let marker_text = marker_of(target.line).ok_or(StepError::Script)?;
    let marker = Marker::parse(marker_text).map_err(|_| StepError::Script)?;
    let step_token = StepToken::parse(token).map_err(|_| StepError::Token)?;
    let not_after = |n: Option<i64>| -> Result<NotAfter, StepError> {
        NotAfter::new(n.ok_or(StepError::NotAfter)?).map_err(|_| StepError::NotAfter)
    };
    let locking = matches!(stage, StageInput::Append | StageInput::Remove { .. });
    if !locking && not_after_remote.is_some() {
        return Err(StepError::NotAfter);
    }
    let rendered = match stage {
        StageInput::Inspect => script::inspect(&InspectParams { registry, marker }),
        StageInput::Bootstrap => script::bootstrap(&BootstrapParams { registry }),
        StageInput::Append => script::append(&AppendParams {
            registry,
            line: RegistryLine::parse(target.line, &marker).map_err(|_| StepError::Script)?,
            marker,
            token: step_token,
            not_after_remote: not_after(not_after_remote)?,
        }),
        StageInput::Remove {
            preimage,
            post_image,
        } => script::remove(&RemoveParams {
            registry,
            marker,
            token: step_token,
            not_after_remote: not_after(not_after_remote)?,
            preimage: Payload::new(preimage).map_err(|_| StepError::Script)?,
            post_image: Payload::new(post_image).map_err(|_| StepError::Script)?,
        }),
        StageInput::Fence { terminate } => script::fence(&FenceParams {
            registry,
            token: step_token,
            terminate,
        }),
    };
    Ok(rendered.into_text())
}

/// Build one remote step for an [`EnrollmentPlan`] (m03-plan U5 `remote_step`): the
/// full pin set of D5 §6.3 in order (from the plan's approved target, host-trust pins
/// and existing-access invocation, each re-checked against the documented set), the
/// fixed remote command and the script of `registry::script`. `registry` is the
/// canonical registry the caller holds; `hard_deadline_ms` is on the runtime's
/// continuous clock; `not_after_remote` is required for `append` and `remove` and
/// refused for every other stage.
///
/// # Errors
/// [`StepError`].
pub fn remote_step(
    stage: StageInput<'_>,
    plan: &EnrollmentPlan,
    registry: &RegistryCanonical,
    token: &str,
    hard_deadline_ms: u64,
    not_after_remote: Option<i64>,
    env: &StepEnv<'_>,
) -> Result<RemoteStep, StepError> {
    remote_step_for(
        stage,
        &StepTarget::from_plan(plan, registry),
        token,
        hard_deadline_ms,
        not_after_remote,
        env,
    )
}

/// [`remote_step`] for any [`StepTarget`] (a removal built from its record).
///
/// # Errors
/// [`StepError`].
pub fn remote_step_for(
    stage: StageInput<'_>,
    target: &StepTarget<'_>,
    token: &str,
    hard_deadline_ms: u64,
    not_after_remote: Option<i64>,
    env: &StepEnv<'_>,
) -> Result<RemoteStep, StepError> {
    if !token_ok(token) {
        return Err(StepError::Token);
    }
    if !alias_ok(target.alias) {
        return Err(StepError::Alias);
    }
    if !absolute_path(env.client) || env.client.chars().any(char::is_control) {
        return Err(StepError::Client);
    }
    let mut trust = approved_trust(target.target, target.host_trust)?;
    if env.gssapi_key_exchange {
        trust.push(pair(GSSAPI_KEX, "no"));
    }
    let pins = StepPins {
        target: TargetPins(options(target_pins(target.target)?)),
        host_trust: TrustPins(options(trust)),
        existing_access: AccessPins(options(approved_access(target.invocation)?)),
        narrowing: NarrowingPins(options(narrowing_pins(env.interactive))),
    };
    let script = script_for(stage, target, token, not_after_remote)?;
    Ok(RemoteStep {
        stage: stage.stage(),
        step_token: token.to_owned(),
        client: env.client.to_owned(),
        pins,
        alias: target.alias.to_owned(),
        remote_command: REMOTE_COMMAND.to_owned(),
        script,
        timeout_ms: env.timeout_ms,
        hard_deadline_ms,
        not_after_remote,
    })
}

/// Every `-o` of `pins`, in the order of D5 §6.3: `["-o", "Key=Value", …]`.
#[must_use]
pub fn pin_args(pins: &StepPins) -> Vec<String> {
    [
        &pins.target.0,
        &pins.host_trust.0,
        &pins.existing_access.0,
        &pins.narrowing.0,
    ]
    .into_iter()
    .flatten()
    .flat_map(|o| ["-o".to_owned(), format!("{}={}", o.key, o.value)])
    .collect()
}

/// The client's arguments for `step` (after the client path): the pins, `-T`, the
/// alias and the remote command. The runner adds nothing and drops nothing.
#[must_use]
pub fn ssh_args(step: &RemoteStep) -> Vec<String> {
    let mut args = pin_args(&step.pins);
    args.extend([
        "-T".to_owned(),
        step.alias.clone(),
        step.remote_command.clone(),
    ]);
    args
}

/// The arguments of the effective-configuration check (`ssh -G` with exactly the
/// step's pins and alias; D5 §6.3).
#[must_use]
pub fn effective_config_args(step: &RemoteStep) -> Vec<String> {
    let mut args = vec!["-G".to_owned()];
    args.extend(pin_args(&step.pins));
    args.push(step.alias.clone());
    args
}

// --- the effective-configuration check -----------------------------------------------

/// Why the effective configuration does not hold the pins (`host_trust_unpinnable`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
#[error("the effective configuration does not pin {option} ({kind:?})")]
pub struct HostTrustUnpinnable {
    /// The option (`ssh -G`'s lowercase name).
    pub option: String,
    /// What is wrong.
    pub kind: UnpinnableKind,
}

/// What is wrong with an option in `ssh -G`'s output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum UnpinnableKind {
    /// Absent where a value is required.
    Missing,
    /// Another value.
    Mismatch,
    /// Printed more than once.
    Repeated,
    /// A pin required by the check is not in the step's pins.
    PinAbsent,
    /// The client lists `gssapikeyexchange` but the pins lack `GSSAPIKeyExchange=no`
    /// (Q23): add it ([`StepEnv::gssapi_key_exchange`]) and check again.
    GssapiPinRequired,
}

/// Whether a client's `ssh -G` output lists `gssapikeyexchange` (Q23).
#[must_use]
pub fn client_lists_gssapi_kex(ssh_g_output: &str) -> bool {
    ssh_g_output
        .lines()
        .any(|l| l.split_once(' ').map_or(l, |(k, _)| k) == "gssapikeyexchange")
}

/// How an option's effective value must look.
#[derive(Debug, Clone, Copy)]
enum Want<'a> {
    /// This value (case-sensitive).
    Exact(&'a str),
    /// This value, ASCII case aside.
    NoCase(&'a str),
    /// A path, `\` read as `/` and a drive path's case aside.
    Path(&'a str),
    /// `yes` (`ssh -G` prints `true` for some options).
    Yes,
    /// `no` (`false` for some options).
    No,
    /// `none`: the option is cleared, so `ssh -G` prints nothing (or `none`).
    NoneOrAbsent,
}

fn path_eq(a: &str, b: &str) -> bool {
    let norm = |s: &str| s.replace('\\', "/");
    let (a, b) = (norm(a), norm(b));
    if absolute_path(&a) && a.as_bytes().get(1) == Some(&b':') {
        a.eq_ignore_ascii_case(&b)
    } else {
        a == b
    }
}

fn holds(want: Want<'_>, got: Option<&str>) -> bool {
    match (want, got) {
        (Want::NoneOrAbsent, None) => true,
        (Want::NoneOrAbsent, Some(v)) => v.eq_ignore_ascii_case("none"),
        (_, None) => false,
        (Want::Exact(w), Some(v)) => w == v,
        (Want::NoCase(w), Some(v)) => w.eq_ignore_ascii_case(v),
        (Want::Path(w), Some(v)) => path_eq(w, v),
        (Want::Yes, Some(v)) => v == "yes" || v == "true",
        (Want::No, Some(v)) => v == "no" || v == "false",
    }
}

fn pin_value<'a>(list: &'a [SshOption], key: &str) -> Option<&'a str> {
    list.iter()
        .find(|o| o.key == key)
        .map(|o| unquoted(&o.value))
}

/// Compare a client's `ssh -G` output (run with exactly the step's pins and alias)
/// with `pins` (D5 §6.3 "The effective configuration is checked"): every option of
/// the host-trust table (the ten host-trust options, `ControlMaster`, `ControlPath`,
/// `ProxyCommand`, `ProxyJump`, `CanonicalizeHostname`) and `HostName`, `Port` and
/// `User` must have the pinned value; an option pinned `none` must be cleared. Q23:
/// when the output lists `gssapikeyexchange`, the pins must hold
/// `GSSAPIKeyExchange=no` and the output `no`.
///
/// # Errors
/// [`HostTrustUnpinnable`] naming the first option that does not hold.
pub fn check_effective(ssh_g_output: &str, pins: &StepPins) -> Result<(), HostTrustUnpinnable> {
    let fail = |option: &str, kind| HostTrustUnpinnable {
        option: option.to_owned(),
        kind,
    };
    let mut effective: Vec<(String, &str)> = Vec::new();
    for line in ssh_g_output.lines() {
        let (k, v) = line.split_once(' ').unwrap_or((line, ""));
        effective.push((k.to_ascii_lowercase(), v));
    }
    let get = |option: &str| -> Result<Option<&str>, HostTrustUnpinnable> {
        let mut found = effective
            .iter()
            .filter(|(k, _)| k == option)
            .map(|(_, v)| *v);
        let first = found.next();
        if found.next().is_some() {
            return Err(fail(option, UnpinnableKind::Repeated));
        }
        Ok(first)
    };
    let (t, h, a) = (&pins.target.0, &pins.host_trust.0, &pins.existing_access.0);
    let need =
        |list: &[SshOption], key: &str, option: &str| -> Result<String, HostTrustUnpinnable> {
            pin_value(list, key)
                .map(str::to_owned)
                .ok_or_else(|| fail(option, UnpinnableKind::PinAbsent))
        };
    let hostname = need(t, "HostName", "hostname")?;
    let port = need(t, "Port", "port")?;
    let user = need(t, "User", "user")?;
    let ukh = need(h, "UserKnownHostsFile", "userknownhostsfile")?;
    let gkh = need(h, "GlobalKnownHostsFile", "globalknownhostsfile")?;
    let hka = need(h, "HostKeyAlgorithms", "hostkeyalgorithms")?;
    let alias = need(h, "HostKeyAlias", "hostkeyalias")?;
    let checks: [(&str, &str, &[SshOption], Want<'_>); 18] = [
        ("hostname", "HostName", t, Want::NoCase(&hostname)),
        ("port", "Port", t, Want::Exact(&port)),
        ("user", "User", t, Want::Exact(&user)),
        ("proxycommand", "ProxyCommand", t, Want::NoneOrAbsent),
        ("proxyjump", "ProxyJump", t, Want::NoneOrAbsent),
        ("canonicalizehostname", "CanonicalizeHostname", t, Want::No),
        (
            "userknownhostsfile",
            "UserKnownHostsFile",
            h,
            Want::Path(&ukh),
        ),
        (
            "globalknownhostsfile",
            "GlobalKnownHostsFile",
            h,
            Want::Path(&gkh),
        ),
        (
            "knownhostscommand",
            "KnownHostsCommand",
            h,
            Want::NoneOrAbsent,
        ),
        ("verifyhostkeydns", "VerifyHostKeyDNS", h, Want::No),
        (
            "hostkeyalgorithms",
            "HostKeyAlgorithms",
            h,
            Want::Exact(&hka),
        ),
        ("hostkeyalias", "HostKeyAlias", h, Want::NoCase(&alias)),
        (
            "stricthostkeychecking",
            "StrictHostKeyChecking",
            h,
            Want::Yes,
        ),
        ("checkhostip", "CheckHostIP", h, Want::No),
        ("updatehostkeys", "UpdateHostKeys", h, Want::No),
        (
            "nohostauthenticationforlocalhost",
            "NoHostAuthenticationForLocalhost",
            h,
            Want::No,
        ),
        ("controlmaster", "ControlMaster", a, Want::No),
        ("controlpath", "ControlPath", a, Want::NoneOrAbsent),
    ];
    for (option, key, list, want) in checks {
        if pin_value(list, key).is_none() {
            return Err(fail(option, UnpinnableKind::PinAbsent));
        }
        let got = get(option)?;
        if !holds(want, got) {
            let kind = if got.is_none() {
                UnpinnableKind::Missing
            } else {
                UnpinnableKind::Mismatch
            };
            return Err(fail(option, kind));
        }
    }
    if let Some(got) = get("gssapikeyexchange")? {
        if pin_value(h, GSSAPI_KEX) != Some("no") {
            return Err(fail("gssapikeyexchange", UnpinnableKind::GssapiPinRequired));
        }
        if !holds(Want::No, Some(got)) {
            return Err(fail("gssapikeyexchange", UnpinnableKind::Mismatch));
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn literals_refuse_tokens_and_quote_spaces() {
        assert_eq!(literal("/a b/c").unwrap(), "\"/a b/c\"");
        assert_eq!(literal("/a/c").unwrap(), "/a/c");
        for bad in [
            "", "/a%d", "/a\"b", "/a$HOME", "C:\\x", "/a\nb", " /a", "/a#b",
        ] {
            assert_eq!(literal(bad), Err(StepError::Literal), "{bad:?}");
        }
        assert!(alias_ok("lab-1.x_y"));
        assert!(!alias_ok("-oProxyCommand=x"));
        assert_eq!(
            host_key_algorithms("ssh-rsa"),
            Some("rsa-sha2-512,rsa-sha2-256")
        );
        assert_eq!(
            host_key_algorithms("ssh-ed25519-cert-v01@openssh.com"),
            None
        );
    }
}
