//! ⟨M04⟩ ADR-0006 revision 5 (§17; m04-plan §5): environments a runtime manages, their
//! realizations and the owner requests that add or remove them (ADR-0010 §2–§4, §9 item 1).
//!
//! Types and wire forms only. Joint wave 0 lands them fail closed: every
//! [`EnvironmentRequest`] answers `CAPABILITY_UNAVAILABLE` / `driver_unavailable` before any
//! record is written, and the capability [`crate::ipc::capability::ENVIRONMENTS_V1`] is
//! declared and not offered.

use serde::{Deserialize, Serialize};

use crate::ids::{AccountName, DestinationId, EnvironmentId};

/// Maximum length of an environment label or a WSL account name, in bytes.
pub const MAX_ENVIRONMENT_LABEL_BYTES: usize = 64;

/// A WSL distribution's registration GUID under `HKCU\...\Lxss` (ADR-0010 §3 item 1): the
/// identity of a distribution, kept across renames; a re-registered distribution is a new
/// GUID. Wire form: 36 lowercase hex-and-hyphen characters, `8-4-4-4-12`, no braces
/// (validated on decode; the CLI normalizes case and strips braces before sending).
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(try_from = "String", into = "String")]
pub struct DistributionGuid(String);

/// A string that is not a canonical distribution GUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a distribution GUID is 8-4-4-4-12 lowercase hex")]
pub struct DistributionGuidError;

impl DistributionGuid {
    /// Parse the canonical wire form.
    ///
    /// # Errors
    /// [`DistributionGuidError`] for anything but `8-4-4-4-12` lowercase hex.
    pub fn parse(s: &str) -> Result<Self, DistributionGuidError> {
        let groups: Vec<&str> = s.split('-').collect();
        let lengths = [8usize, 4, 4, 4, 12];
        let ok = groups.len() == lengths.len()
            && groups.iter().zip(lengths).all(|(g, n)| {
                g.len() == n
                    && g.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            });
        if ok {
            Ok(Self(s.to_owned()))
        } else {
            Err(DistributionGuidError)
        }
    }

    /// The wire string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for DistributionGuid {
    type Error = DistributionGuidError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

impl From<DistributionGuid> for String {
    fn from(g: DistributionGuid) -> Self {
        g.0
    }
}

impl std::fmt::Display for DistributionGuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// `Request::Environment`, tagged by `action` (m04-plan §5 item 2). Synchronous, owner
/// role, capability `environments/1`. Mode B and containers add a place where authority
/// can be realized, so each creates a decision record (ADR-0006 §3.1) and never executes
/// on dispatch; Mode A alone goes through the setup confirmation only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "action", rename_all = "snake_case")]
#[non_exhaustive]
pub enum EnvironmentRequest {
    /// Enable WSL integration for one distribution (ADR-0010 §2, §3). Kind
    /// `environment.wsl_enable`.
    WslEnable {
        /// The distribution.
        distribution_guid: DistributionGuid,
        /// The Linux account chosen at enable (Mode B's environment identity, with the
        /// GUID).
        account: String,
        /// Mode A: the distribution's Git uses the Windows in-box `ssh.exe`.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        mode_a: bool,
        /// Mode B: a Linux-native scoped endpoint through the supervised helper.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        mode_b: bool,
    },
    /// Disable it: release the environment's bindings, withdraw the endpoints, roll back
    /// the distribution's projection, end the helper (ADR-0010 §3 item 13). Kind
    /// `environment.wsl_disable`.
    WslDisable {
        /// The distribution.
        distribution_guid: DistributionGuid,
        /// The explicit authorized start of a stopped distribution so its cleanup runs
        /// now (ADR-0010 §9 item 2); without it a stopped distribution's cleanup stays a
        /// retained, reported obligation.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        start: bool,
    },
    /// Create a container environment and its stable directory (ADR-0010 §4 item 1). Kind
    /// `environment.container_add`.
    ContainerAdd {
        /// The owner's label (1 to 64 bytes, no control characters).
        label: String,
    },
    /// Release the container environment's binding and remove its directory (ADR-0010 §4
    /// item 6). Kind `environment.container_remove`.
    ContainerRemove {
        /// The container environment.
        environment_id: EnvironmentId,
    },
}

impl EnvironmentRequest {
    /// The operation-kind name.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            EnvironmentRequest::WslEnable { .. } => "environment.wsl_enable",
            EnvironmentRequest::WslDisable { .. } => "environment.wsl_disable",
            EnvironmentRequest::ContainerAdd { .. } => "environment.container_add",
            EnvironmentRequest::ContainerRemove { .. } => "environment.container_remove",
        }
    }
}

/// An environment's kind on the wire (`EnvironmentView.kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EnvironmentKindView {
    /// The runtime's own native session.
    NativeSession,
    /// A WSL distribution in Mode B.
    WslDistribution,
    /// A local container environment.
    Container,
    /// ⟨M06⟩ Revision 6 (ADR-0012 §4.1, §9 item 5): a Heimdall runtime on a headless Linux
    /// host under the runner account, managed over the management channel.
    RemoteRunner,
}

/// An environment's state (m04-plan §5 item 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EnvironmentState {
    /// In the managed set and running.
    Active,
    /// In the managed set; its distribution is not running (background repair never
    /// starts it).
    NotRunning,
    /// Removed by the owner (`wsl disable`, `container remove`); kept as a removed
    /// identity, refused as a target (`environment_removed`).
    Removed,
    /// Its distribution was unregistered; refused as a target.
    Gone,
}

/// The modes enabled for a WSL distribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum WslMode {
    /// Mode A (Windows SSH authority).
    A,
    /// Mode B (Linux-native scoped endpoint).
    B,
}

/// The helper's observed state for a Mode B distribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum HelperState {
    /// Running and past its hello.
    Running,
    /// Not running (no active binding, or the distribution is stopped).
    Stopped,
    /// No Linux-visible helper path resolves (`wsl_helper_unavailable`).
    Unavailable,
}

/// How an environment is realized, as `inspect environments` shows it (m04-plan §5
/// item 4). Tagged by `kind`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum RealizationView {
    /// The runtime's own session.
    Native,
    /// A WSL distribution.
    Wsl {
        /// Current distribution name (mutable; not identity).
        name: String,
        /// Registration GUID (identity).
        guid: DistributionGuid,
        /// Linux account.
        account: String,
        /// Enabled modes.
        modes: Vec<WslMode>,
        /// The helper's state (Mode B only).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        helper: Option<HelperState>,
    },
    /// A container environment.
    Container {
        /// The owner's label.
        label: String,
        /// The stable host directory (`<runtime_dir>/c/<16 hex>/`).
        directory: String,
        /// Where it is mounted inside the container (`/run/heimdall`).
        in_container_path: String,
    },
    /// ⟨M06⟩ Revision 6: a remote runner, reached through a catalog destination's approved
    /// routes as its runner account (ADR-0012 §3.3, §5).
    RemoteRunner {
        /// The catalog destination of the runner host.
        destination: DestinationId,
        /// The runner account.
        account: AccountName,
    },
}

/// One environment in `inspect environments` (m04-plan §5 item 4: every environment, not
/// only the caller's).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EnvironmentView {
    /// Environment ID.
    pub environment_id: EnvironmentId,
    /// Kind.
    pub kind: EnvironmentKindView,
    /// Owner label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// State.
    pub state: EnvironmentState,
    /// Realization.
    pub realization: RealizationView,
    /// ⟨M06⟩ Revision 6 (ADR-0012 §7.1, §9 item 5): a remote runner's connectivity. Every
    /// revision-6 field is omitted when absent, so every M04 view is unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connectivity: Option<crate::remote::Connectivity>,
    /// ⟨M06⟩ When the runner was last reached.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<crate::Timestamp>,
    /// ⟨M06⟩ The runner runtime's lifetime (ADR-0012 §4.3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runner_lifetime: Option<crate::remote::RunnerLifetime>,
    /// ⟨M06⟩ Narrowing steps reported but not yet applied on the runner (ADR-0012 §7.1).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remote_pending: Vec<crate::remote::RemotePending>,
    /// ⟨M06⟩ The runner's pinned host key (ADR-0012 §3.3, §7.5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned_host_key: Option<crate::ids::KeyFingerprint>,
    /// ⟨M06⟩ Whether limited roles may enroll (ADR-0012 §3.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub management_policy: Option<crate::remote::ManagementPolicy>,
}

impl EnvironmentView {
    /// A view with no revision-6 field (a local environment: native, WSL or container).
    #[must_use]
    pub fn new(
        environment_id: EnvironmentId,
        kind: EnvironmentKindView,
        label: Option<String>,
        state: EnvironmentState,
        realization: RealizationView,
    ) -> Self {
        Self {
            environment_id,
            kind,
            label,
            state,
            realization,
            connectivity: None,
            last_seen_at: None,
            runner_lifetime: None,
            remote_pending: Vec::new(),
            pinned_host_key: None,
            management_policy: None,
        }
    }
}

/// `inspect environments` data.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EnvironmentsView {
    /// Every environment the runtime knows, its own first.
    pub items: Vec<EnvironmentView>,
}

/// A bind mount a consumer must set up (the container recipe's read-only directory).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MountSpec {
    /// Host path.
    pub source: String,
    /// In-environment path.
    pub target: String,
    /// Read-only (always true for the container recipe).
    pub read_only: bool,
}

/// `ConsumerIntegration.realization` (m04-plan §5 item 5): where a binding is realized when
/// that is not the native session. Paths are in-environment paths; never secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RealizationDescriptor {
    /// The environment's kind.
    pub environment_kind: EnvironmentKindView,
    /// The in-environment signing endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// The in-environment OpenSSH configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<String>,
    /// The mount to set up (containers).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount: Option<MountSpec>,
    /// In-environment variables (names and values; never secrets).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub environment: Vec<(String, String)>,
}

/// How the jump hop of a route is accessed (ADR-0010 §5 item 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum JumpAccess {
    /// A managed pair in the same grant's scope.
    Managed,
    /// Existing access, outside the grant.
    Existing,
}

/// `PairIntegration.route` (m04-plan §5 item 6): a single-hop `ProxyJump`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RouteView {
    /// The jump destination.
    pub jump: DestinationId,
    /// Its alias, as `ProxyJump` renders it.
    pub jump_alias: String,
    /// How the jump hop is accessed.
    pub jump_access: JumpAccess,
}

/// The login entry kind of `inspect capabilities` `login_start` (ADR-0010 §1, §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum LoginStartKind {
    /// `HKCU\...\Run` value (Windows).
    RunValue,
    /// A LaunchAgent (macOS).
    LaunchAgent,
    /// A systemd user unit (Linux with a user manager).
    SystemdUser,
    /// No login entry is possible (`on_demand`).
    None,
}

/// `inspect capabilities` → `login_start` (m04-plan §5 item 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LoginStartView {
    /// The host's entry kind.
    pub kind: LoginStartKind,
    /// Whether Heimdall's entry is installed.
    pub installed: bool,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// The GUID is identity on the wire: only the canonical form decodes.
    #[test]
    fn distribution_guid_accepts_only_the_canonical_form() {
        let ok = "0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0";
        assert_eq!(DistributionGuid::parse(ok).unwrap().as_str(), ok);
        for bad in [
            "",
            "{0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0}",
            "0B1C2D3E-4F50-6172-8394-A5B6C7D8E9F0",
            "0b1c2d3e4f5061728394a5b6c7d8e9f0",
            "0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f",
            "0b1c2d3e-4f50-6172-8394-a5b6c7d8e9fg",
        ] {
            assert!(DistributionGuid::parse(bad).is_err(), "{bad}");
            let wire = serde_json::Value::String(bad.to_owned());
            assert!(serde_json::from_value::<DistributionGuid>(wire).is_err());
        }
    }
}
