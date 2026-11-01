//! The renderer (m02-plan U2; ADR-0007 §4).
//!
//! Output is deterministic (two renders give identical bytes) and sorted. Values that
//! OpenSSH or Git would read differently from what Heimdall means are refused, never
//! escaped into something else: `%` in a host name, `${` or `"` in a path, a wildcard
//! in an alias, `'` and `"` in a Git value. Rendered bytes are the only bytes a setup
//! intent stores (ADR-0007 §5.7 "Provenance"; the domain `Rendered` type wraps them).

/// A managed alias: a literal `Host` name with no pattern characters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AliasName(String);

impl AliasName {
    /// Validate an alias.
    ///
    /// # Errors
    /// [`RenderError::RefusedValue`] for a wildcard, negation, whitespace, a control
    /// character or an empty name.
    pub fn parse(s: &str) -> Result<Self, RenderError> {
        let _ = s;
        todo!("M02-U2 render::AliasName::parse")
    }

    /// The alias text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A destination host name as it will be written to `HostName`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostName(String);

impl HostName {
    /// Validate a host name (`%` refused; `%%` is never produced from user input).
    ///
    /// # Errors
    /// [`RenderError::RefusedValue`].
    pub fn parse(s: &str) -> Result<Self, RenderError> {
        let _ = s;
        todo!("M02-U2 render::HostName::parse")
    }

    /// The host name text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A path as it will be written into a configuration file.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RenderPath(String);

impl RenderPath {
    /// A Unix path.
    ///
    /// # Errors
    /// [`RenderError::RefusedValue`] for `${`, `"` or a control character.
    pub fn unix(path: &std::path::Path) -> Result<Self, RenderError> {
        let _ = path;
        todo!("M02-U2 render::RenderPath::unix")
    }

    /// A Windows path, written with forward slashes.
    ///
    /// # Errors
    /// [`RenderError::RefusedValue`].
    pub fn windows(path: &std::path::Path) -> Result<Self, RenderError> {
        let _ = path;
        todo!("M02-U2 render::RenderPath::windows")
    }

    /// A Windows named pipe, written as `//./pipe/<name>`.
    ///
    /// # Errors
    /// [`RenderError::RefusedValue`].
    pub fn pipe(name: &str) -> Result<Self, RenderError> {
        let _ = name;
        todo!("M02-U2 render::RenderPath::pipe")
    }

    /// The text written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Which platform's path rules apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathStyle {
    /// Unix.
    Unix,
    /// Windows (forward slashes, `//./pipe/`).
    Windows,
}

/// The line ending of the file a block is inserted into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Newline {
    /// `\n`.
    Lf,
    /// `\r\n`.
    CrLf,
}

/// The marker that brackets a Heimdall block (ADR-0007 §2).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MarkerId(String);

impl MarkerId {
    /// Validate a marker identifier.
    ///
    /// # Errors
    /// [`RenderError::RefusedValue`].
    pub fn parse(s: &str) -> Result<Self, RenderError> {
        let _ = s;
        todo!("M02-U2 render::MarkerId::parse")
    }

    /// The marker text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One managed alias section of P.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedAlias {
    /// The `Host` name.
    pub alias: AliasName,
    /// `HostName`.
    pub hostname: HostName,
    /// `Port`, when not 22.
    pub port: Option<u16>,
    /// `User`.
    pub user: String,
    /// `IdentityAgent`.
    pub identity_agent: Option<RenderPath>,
    /// `IdentityFile` entries (public key files only).
    pub identity_files: Vec<RenderPath>,
    /// `IdentitiesOnly yes`.
    pub identities_only: bool,
}

/// A value or construct the renderer refuses.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RenderError {
    /// A value the target client would read differently (the value is not echoed).
    #[error("refused value: {0}")]
    RefusedValue(&'static str),
    /// Two sections with the same alias.
    #[error("duplicate alias")]
    DuplicateAlias,
}

/// Render P, the managed include file.
///
/// # Errors
/// [`RenderError`].
pub fn render_managed(aliases: &[ManagedAlias], style: PathStyle) -> Result<Vec<u8>, RenderError> {
    let _ = (aliases, style);
    todo!("M02-U2 render::render_managed")
}

/// Render B, the marked `Include` block for the user file.
#[must_use]
pub fn render_include_block(marker: &MarkerId, target: &RenderPath, newline: Newline) -> Vec<u8> {
    let _ = (marker, target, newline);
    todo!("M02-U2 render::render_include_block")
}

/// Render P_git, the managed Git file setting `core.sshCommand` to the verified
/// client.
///
/// # Errors
/// [`RenderError`].
pub fn render_git_managed(verified_client: &RenderPath) -> Result<Vec<u8>, RenderError> {
    let _ = verified_client;
    todo!("M02-U2 render::render_git_managed")
}

/// Render B_git, the marked `[include]` block for the global Git file.
///
/// # Errors
/// [`RenderError`].
pub fn render_git_include_block(
    marker: &MarkerId,
    target: &RenderPath,
    newline: Newline,
) -> Result<Vec<u8>, RenderError> {
    let _ = (marker, target, newline);
    todo!("M02-U2 render::render_git_include_block")
}
