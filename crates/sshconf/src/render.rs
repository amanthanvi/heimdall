//! The renderer (m02-plan U2; ADR-0007 §4).
//!
//! Output is deterministic (two renders give identical bytes) and sorted. Values that
//! OpenSSH or Git would read differently from what Heimdall means are refused, never
//! escaped into something else: `%` in a host name, `${` or `"` in a path, a wildcard
//! in an alias, `'` and `"` in a Git value. Rendered bytes are the only bytes a setup
//! intent stores (ADR-0007 §5.7 "Provenance"; the domain `Rendered` type wraps them).
//!
//! **What P may contain** (ADR-0007 §2). Only `Host <literal alias>` sections with the
//! closed M02 directive set, in this fixed order: `HostName`, `Port`, `User`,
//! `IdentityAgent`, `IdentityFile`, `IdentitiesOnly`. [`ManagedAlias`] cannot express
//! anything else, so no executing directive (`ProxyCommand`, `LocalCommand`,
//! `PermitLocalCommand`, `KnownHostsCommand`), no host-verification directive and no
//! forwarding can ever be rendered.
//!
//! **Paths** are always double-quoted, and `%` is written `%%` (OpenSSH expands tokens
//! in `Include`, `IdentityFile` and `IdentityAgent`, F7, F15). A [`RenderPath`] holds
//! the path text itself; the `%%` escaping is applied only where an OpenSSH directive
//! is rendered, because Git gives `%` no meaning.
//!
//! **The include target** (B's `Include` argument) is stricter (ADR-0007 §12.16 item 3,
//! §12.17 item 9): it is absolute, never `~` (OpenSSH expands an Include's `~` from
//! `$HOME`, so B must load P whatever `$HOME` is), and literal. OpenSSH globs inside a
//! quoted Include argument, so a target holding `*`, `?`, `[` or `]` is refused as
//! [`RenderError::Unmanageable`] (`include_target_glob`), which is manual mode before
//! any edit. `IdentityFile` and `IdentityAgent` are not globbed and keep the path rules
//! above.
//!
//! **Provenance.** The `rendered_*` functions wrap the same bytes in the domain
//! [`Rendered`] type, the only input a `StepContent` accepts. This file is one of the
//! three places allowed to call `Rendered::from_renderer` (source-scanned by
//! `heimdall-domain`, wave-0 escalation E9).
//!
//! **⟨M03⟩ The directive-set revision** (ADR-0008 D10 item 1; m03-plan U8). P renders
//! [`Section`]s. An existing-access alias ([`Section::ExistingAccess`]) renders exactly as
//! in M02, byte for byte ([`render_managed`] is unchanged and is that path). A
//! managed-certificate alias ([`Section::ManagedCertificate`]) renders, in this order:
//! `HostName`, `Port`, `User`, `IdentityAgent` (the **environment** endpoint; a Windows
//! pipe as `//./pipe/…`), then the identity directives of the selected
//! [`ManagedIdentityForm`], then `ControlMaster no` and `ControlPath none` or the slot's
//! stable mux path (Unix only: Windows refuses owned masters, M-F7). Paths follow
//! ADR-0007 §4. The identity directives sit behind one switch, [`ManagedIdentityForm`]
//! (reading R4, ADR-0008 §17.18 item 3, INT-Q10), and the one selector
//! [`ManagedIdentityForm::select`] is used by P and by `connect`'s command line alike
//! ([`managed_identity_options`]).
//!
//! **⟨M03⟩ Owned launches stay in the foreground** (ADR-0008 D8 item 2, §17.4 item 7):
//! [`OWNED_LAUNCH_PINS`] go right after the program name, and
//! [`check_owned_ssh_arguments`] refuses the arguments that would move the connection
//! out of the launched process. They are the command-line half of the same directive set,
//! so they live beside it.

use std::ffi::OsString;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use heimdall_contract::ids::AccountName;
use heimdall_domain::projection::Rendered;

use crate::eval::OpenSshVersion;

/// The first line of every Heimdall include block, before the marker id.
pub(crate) const BEGIN_PREFIX: &str = "# >>> heimdall managed include (id ";
/// The rest of the first line after the marker id.
pub(crate) const BEGIN_SUFFIX: &str = "); remove with `heimdall setup rollback`";
/// The last line of every Heimdall include block, before the marker id.
pub(crate) const END_PREFIX: &str = "# <<< heimdall managed include (id ";

/// The header comment of P.
const MANAGED_HEADER: &str = "# heimdall managed ssh configuration (generated; do not edit)\n";
/// The header comment of P_git.
const GIT_MANAGED_HEADER: &str = "# heimdall managed git configuration (generated; do not edit)\n";

/// A managed alias: a literal `Host` name with no pattern characters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AliasName(String);

impl AliasName {
    /// Validate an alias: `[A-Za-z0-9][A-Za-z0-9._-]{0,63}` (ADR-0007 §4). That
    /// excludes `*`, `?`, `!`, `,`, whitespace, `%`, control characters and the empty
    /// name.
    ///
    /// # Errors
    /// [`RenderError::RefusedValue`] for a wildcard, negation, whitespace, a control
    /// character or an empty name.
    pub fn parse(s: &str) -> Result<Self, RenderError> {
        let b = s.as_bytes();
        let ok = !b.is_empty()
            && b.len() <= 64
            && b[0].is_ascii_alphanumeric()
            && b[1..]
                .iter()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'));
        if ok {
            Ok(Self(s.to_owned()))
        } else {
            Err(RenderError::RefusedValue("alias"))
        }
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
    /// Validate a host name (`%` refused; `%%` is never produced from user input):
    /// an IPv4 address, an IPv6 literal, or a DNS name over `[A-Za-z0-9.-]` of at most
    /// 253 bytes whose labels are 1 to 63 bytes and which does not start with `-` or
    /// `.` (ADR-0007 §4; a leading `-` could read as an option).
    ///
    /// # Errors
    /// [`RenderError::RefusedValue`].
    pub fn parse(s: &str) -> Result<Self, RenderError> {
        let refused = Err(RenderError::RefusedValue("hostname"));
        if s.is_empty() || s.contains('%') {
            return refused;
        }
        if s.parse::<Ipv4Addr>().is_ok() {
            return Ok(Self(s.to_owned()));
        }
        if s.contains(':') {
            return if s.parse::<Ipv6Addr>().is_ok() {
                Ok(Self(s.to_owned()))
            } else {
                refused
            };
        }
        let b = s.as_bytes();
        if b.len() > 253
            || !b
                .iter()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-'))
            || b[0] == b'-'
            || b[0] == b'.'
        {
            return refused;
        }
        // A trailing dot (a rooted name) is allowed; every other label is 1..=63.
        let body = s.strip_suffix('.').unwrap_or(s);
        if body.split('.').any(|l| l.is_empty() || l.len() > 63) {
            return refused;
        }
        Ok(Self(s.to_owned()))
    }

    /// The host name text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Which constructor made a [`RenderPath`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum PathKind {
    /// [`RenderPath::unix`].
    Unix,
    /// [`RenderPath::windows`].
    Windows,
    /// [`RenderPath::pipe`].
    Pipe,
}

/// A path as it will be written into a configuration file.
///
/// The text is the path itself (forward slashes on Windows). `%` is kept as is here
/// and escaped to `%%` only when an OpenSSH directive is rendered.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RenderPath {
    text: String,
    kind: PathKind,
}

/// Characters no rendered path may contain, on any platform (ADR-0007 §4): `${`
/// (OpenSSH environment expansion, F7), `"` (quoting) and any control character,
/// newline included.
fn common_path_check(text: &str) -> Result<(), RenderError> {
    if text.is_empty()
        || text.contains("${")
        || text.contains('"')
        || text.chars().any(char::is_control)
    {
        return Err(RenderError::RefusedValue("path"));
    }
    Ok(())
}

/// `X:/` (a drive-absolute Windows path, after separator normalization).
fn is_drive_absolute(text: &str) -> bool {
    let b = text.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'/'
}

/// `~/…` or `~` alone (the account home, F19).
fn is_home_relative(text: &str) -> bool {
    text == "~" || text.starts_with("~/")
}

impl RenderPath {
    /// A Unix path: absolute, or `~/…` relative to the account home.
    ///
    /// # Errors
    /// [`RenderError::RefusedValue`] for `${`, `"`, `\`, a control character, a path
    /// that is not UTF-8, or a relative path.
    pub fn unix(path: &std::path::Path) -> Result<Self, RenderError> {
        let text = path.to_str().ok_or(RenderError::RefusedValue("path"))?;
        common_path_check(text)?;
        if text.contains('\\') {
            return Err(RenderError::RefusedValue("path"));
        }
        if !(text.starts_with('/') || is_home_relative(text)) {
            return Err(RenderError::RefusedValue("path"));
        }
        Ok(Self {
            text: text.to_owned(),
            kind: PathKind::Unix,
        })
    }

    /// A Windows path, written with forward slashes: drive-absolute (`C:/…`), UNC
    /// (`//server/share/…`) or `~/…`. Device paths (`//./`, `//?/`) are refused; a
    /// named pipe goes through [`RenderPath::pipe`].
    ///
    /// # Errors
    /// [`RenderError::RefusedValue`].
    pub fn windows(path: &std::path::Path) -> Result<Self, RenderError> {
        let raw = path.to_str().ok_or(RenderError::RefusedValue("path"))?;
        let text = raw.replace('\\', "/");
        common_path_check(&text)?;
        if text.starts_with("//./") || text.starts_with("//?/") {
            return Err(RenderError::RefusedValue("path"));
        }
        let unc = text.starts_with("//") && text.len() > 2;
        if !(is_drive_absolute(&text) || unc || is_home_relative(&text)) {
            return Err(RenderError::RefusedValue("path"));
        }
        Ok(Self {
            text,
            kind: PathKind::Windows,
        })
    }

    /// A Windows named pipe, written as `//./pipe/<name>` (F14). `name` is the bare
    /// pipe name; a `\\.\pipe\` or `//./pipe/` prefix is accepted and stripped.
    ///
    /// # Errors
    /// [`RenderError::RefusedValue`] for an empty name, a separator, `"`, `${` or a
    /// control character.
    pub fn pipe(name: &str) -> Result<Self, RenderError> {
        let bare = strip_pipe_prefix(name);
        common_path_check(bare)?;
        if bare.contains('/') || bare.contains('\\') {
            return Err(RenderError::RefusedValue("pipe"));
        }
        Ok(Self {
            text: format!("//./pipe/{bare}"),
            kind: PathKind::Pipe,
        })
    }

    /// A path written `~/…` when it is under `account_home` (ADR-0007 §4
    /// "home-relative paths"), otherwise absolute, under `style`'s rules.
    ///
    /// Only the Windows style reads `\` as a separator and writes it `/`. On Unix a
    /// backslash is a file-name character, so the remainder is kept as it is and the
    /// Unix rule refuses it; a path is never rewritten into another one (ADR-0007
    /// §12.16 item 5).
    ///
    /// Not for the include block's target, which is always absolute (ADR-0007 §12.17
    /// item 9; [`RenderPath::absolute`], [`render_include_block`]).
    ///
    /// # Errors
    /// [`RenderError::RefusedValue`] as for [`RenderPath::unix`] and
    /// [`RenderPath::windows`].
    pub fn home_relative(
        path: &Path,
        account_home: &Path,
        style: PathStyle,
    ) -> Result<Self, RenderError> {
        let candidate = match path.strip_prefix(account_home) {
            Ok(rest) if !account_home.as_os_str().is_empty() => {
                let rest = rest.to_str().ok_or(RenderError::RefusedValue("path"))?;
                let rest = match style {
                    PathStyle::Windows => rest.replace('\\', "/"),
                    PathStyle::Unix => rest.to_owned(),
                };
                if rest.is_empty() {
                    "~".to_owned()
                } else {
                    format!("~/{rest}")
                }
            }
            _ => {
                return match style {
                    PathStyle::Unix => Self::unix(path),
                    PathStyle::Windows => Self::windows(path),
                };
            }
        };
        match style {
            PathStyle::Unix => Self::unix(Path::new(&candidate)),
            PathStyle::Windows => Self::windows(Path::new(&candidate)),
        }
    }

    /// An absolute path under `style`'s rules: [`RenderPath::unix`] or
    /// [`RenderPath::windows`], with a `~` path refused. The include block's target is
    /// built this way, so B loads P whatever `$HOME` is (ADR-0007 §12.17 item 9).
    ///
    /// # Errors
    /// [`RenderError::RefusedValue`] as for [`RenderPath::unix`] and
    /// [`RenderPath::windows`], and for a path beginning with `~`.
    pub fn absolute(path: &Path, style: PathStyle) -> Result<Self, RenderError> {
        let rendered = match style {
            PathStyle::Unix => Self::unix(path)?,
            PathStyle::Windows => Self::windows(path)?,
        };
        if rendered.text.starts_with('~') {
            return Err(RenderError::RefusedValue("path"));
        }
        Ok(rendered)
    }

    /// The text written (the path itself; OpenSSH directives escape `%` as `%%`).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The path quoted for an OpenSSH directive: `"…"` with `%` as `%%`.
    fn ssh_quoted(&self) -> String {
        format!("\"{}\"", self.text.replace('%', "%%"))
    }

    /// An absolute path (not `~`-relative, not a pipe), as Git needs.
    fn is_absolute_file(&self) -> bool {
        match self.kind {
            PathKind::Unix => self.text.starts_with('/'),
            PathKind::Windows => {
                is_drive_absolute(&self.text)
                    || (self.text.starts_with("//") && !is_home_relative(&self.text))
            }
            PathKind::Pipe => false,
        }
    }

    /// Whether the path may be written into a file of `style`.
    fn fits(&self, style: PathStyle) -> bool {
        match (style, self.kind) {
            (PathStyle::Unix, PathKind::Unix) => true,
            (PathStyle::Windows, PathKind::Windows | PathKind::Pipe) => true,
            // `~/…` reads the same on both platforms.
            (_, PathKind::Unix | PathKind::Windows) => is_home_relative(&self.text),
            (PathStyle::Unix, PathKind::Pipe) => false,
        }
    }
}

/// `name` without a leading `\\.\pipe\` or `//./pipe/` (ASCII case aside). The prefix
/// length is checked as a character boundary before slicing, so a name whose bytes at
/// that offset fall inside a multi-byte character is compared, not split (ADR-0007
/// §12.16 item 6).
fn strip_pipe_prefix(name: &str) -> &str {
    for prefix in ["\\\\.\\pipe\\", "//./pipe/"] {
        if let (Some(head), Some(rest)) = (name.get(..prefix.len()), name.get(prefix.len()..))
            && head.eq_ignore_ascii_case(prefix)
        {
            return rest;
        }
    }
    name
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

impl Newline {
    /// The bytes of the line ending.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Newline::Lf => "\n",
            Newline::CrLf => "\r\n",
        }
    }
}

/// The marker that brackets a Heimdall block (ADR-0007 §2): `hm-` and 16 lowercase
/// hexadecimal characters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MarkerId(String);

impl MarkerId {
    /// Validate a marker identifier: exactly `hm-<16 lowercase hex>`.
    ///
    /// # Errors
    /// [`RenderError::RefusedValue`].
    pub fn parse(s: &str) -> Result<Self, RenderError> {
        let ok = s.len() == 19
            && s.starts_with("hm-")
            && s.as_bytes()[3..]
                .iter()
                .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'));
        if ok {
            Ok(Self(s.to_owned()))
        } else {
            Err(RenderError::RefusedValue("marker"))
        }
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
    /// A target no rendering can name literally, so Heimdall cannot manage it: the
    /// caller goes to manual mode before any edit (ADR-0007 §12.16 item 3). The reason
    /// is a stable `snake_case` code: `include_target_glob` for an include target
    /// holding `*`, `?`, `[` or `]`, which OpenSSH globs even inside quotes.
    #[error("unmanageable: {0}")]
    Unmanageable(&'static str),
}

/// The [`RenderError::Unmanageable`] reason of an include target that holds a glob
/// metacharacter (ADR-0007 §12.16 item 3).
pub const INCLUDE_TARGET_GLOB: &str = "include_target_glob";

/// `User`: the contract `AccountName` token rule (which excludes `%`), and no leading
/// `-`.
fn check_user(user: &str) -> Result<(), RenderError> {
    if AccountName::parse(user).is_err() || user.starts_with('-') {
        return Err(RenderError::RefusedValue("user"));
    }
    Ok(())
}

/// Render P, the managed include file: a header comment, then one `Host` section per
/// alias, sorted bytewise by alias, LF line endings, a trailing newline, nothing that
/// varies between renders of the same input.
///
/// # Errors
/// [`RenderError`]: a duplicate alias (compared case-insensitively, so two sections
/// never differ only in case), a refused user or port, or a path that does not fit
/// `style` (a pipe in a Unix file, a Unix path in a Windows file).
pub fn render_managed(aliases: &[ManagedAlias], style: PathStyle) -> Result<Vec<u8>, RenderError> {
    let sections: Vec<Section> = aliases
        .iter()
        .cloned()
        .map(Section::ExistingAccess)
        .collect();
    render_sections(&sections, style, ManagedIdentityForm::select(None))
}

/// The `Host`, `HostName`, `Port` and `User` lines every section starts with.
fn push_route(
    out: &mut String,
    alias: &AliasName,
    hostname: &HostName,
    port: Option<u16>,
    user: &str,
) -> Result<(), RenderError> {
    check_user(user)?;
    if port == Some(0) {
        return Err(RenderError::RefusedValue("port"));
    }
    out.push('\n');
    out.push_str("Host ");
    out.push_str(alias.as_str());
    out.push('\n');
    out.push_str("    HostName ");
    out.push_str(hostname.as_str());
    out.push('\n');
    if let Some(port) = port {
        out.push_str(&format!("    Port {port}\n"));
    }
    out.push_str("    User ");
    out.push_str(user);
    out.push('\n');
    Ok(())
}

/// An existing-access section, exactly as M02 renders it.
fn push_existing(out: &mut String, a: &ManagedAlias, style: PathStyle) -> Result<(), RenderError> {
    push_route(out, &a.alias, &a.hostname, a.port, &a.user)?;
    if let Some(agent) = &a.identity_agent {
        if !agent.fits(style) {
            return Err(RenderError::RefusedValue("identity_agent"));
        }
        out.push_str("    IdentityAgent ");
        out.push_str(&agent.ssh_quoted());
        out.push('\n');
    }
    for file in &a.identity_files {
        if file.kind == PathKind::Pipe || !file.fits(style) {
            return Err(RenderError::RefusedValue("identity_file"));
        }
        out.push_str("    IdentityFile ");
        out.push_str(&file.ssh_quoted());
        out.push('\n');
    }
    if a.identities_only {
        out.push_str("    IdentitiesOnly yes\n");
    }
    Ok(())
}

// --- ⟨M03⟩ managed-certificate sections (ADR-0008 D10) ----------------------------------

/// Which identity directives a managed-certificate alias carries (reading R4; ADR-0008
/// §17.18 item 3, INT-Q10). OpenSSH 9.5p2 and 9.6p1 were observed never to ask the agent
/// for the certificate in D10's shape (`IdentityFile` naming K_env's `.pub`), so the form
/// is a named switch the integrator sets from the per-client evidence. Every form starts
/// with `IdentitiesOnly yes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ManagedIdentityForm {
    /// ADR-0008 D10 item 1 as written: `IdentityFile "<key.pub>"`, `CertificateFile
    /// "<cert.pub>"`.
    D10AsWritten,
    /// `IdentityFile "<cert.pub>"`, and no `CertificateFile`.
    CertificateAsIdentityFile,
    /// `IdentityFile "<cert.pub>"` and `CertificateFile "<cert.pub>"`.
    CertificateAsIdentityFileAndCertificateFile,
}

/// **The one place the default form is chosen** (reading R4), set by the integrator
/// from the INT-Q10 evidence (`.m03-wave2-api.md` §INT-Q10, 2026-11-10): D10 item 1 as
/// written failed on both macOS OpenSSH 10.5p1 and 9.6p1 (ssh pairs the
/// `CertificateFile` certificate with the `key.pub` file identity, tries to load a
/// private key from the public file and never asks the agent), while naming the
/// **certificate** as the `IdentityFile` made both clients ask the agent to sign the
/// certificate blob. Windows in-box 9.5p2 is observed natively by the orchestrator.
pub const DEFAULT_MANAGED_IDENTITY_FORM: ManagedIdentityForm =
    ManagedIdentityForm::CertificateAsIdentityFile;

impl ManagedIdentityForm {
    /// Every form, in declaration order.
    pub const ALL: [ManagedIdentityForm; 3] = [
        ManagedIdentityForm::D10AsWritten,
        ManagedIdentityForm::CertificateAsIdentityFile,
        ManagedIdentityForm::CertificateAsIdentityFileAndCertificateFile,
    ];

    /// The form for the selected `ssh` client of `version` (`None`: not known). This is
    /// the one selector P and `connect` use. Today it is
    /// [`DEFAULT_MANAGED_IDENTITY_FORM`] for every client; INT-Q10 may make it
    /// per-client, here and nowhere else.
    #[must_use]
    pub fn select(version: Option<OpenSshVersion>) -> ManagedIdentityForm {
        let _ = version;
        DEFAULT_MANAGED_IDENTITY_FORM
    }

    /// A stable `snake_case` name (for logs and test labels).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ManagedIdentityForm::D10AsWritten => "d10_as_written",
            ManagedIdentityForm::CertificateAsIdentityFile => "certificate_as_identity_file",
            ManagedIdentityForm::CertificateAsIdentityFileAndCertificateFile => {
                "certificate_as_identity_file_and_certificate_file"
            }
        }
    }

    /// The identity entries after `IdentitiesOnly yes`, in order: `(keyword, path)`.
    fn entries<'a>(
        self,
        key_pub: &'a RenderPath,
        cert: &'a RenderPath,
    ) -> Vec<(&'static str, &'a RenderPath)> {
        match self {
            ManagedIdentityForm::D10AsWritten => {
                vec![("IdentityFile", key_pub), ("CertificateFile", cert)]
            }
            ManagedIdentityForm::CertificateAsIdentityFile => vec![("IdentityFile", cert)],
            ManagedIdentityForm::CertificateAsIdentityFileAndCertificateFile => {
                vec![("IdentityFile", cert), ("CertificateFile", cert)]
            }
        }
    }
}

/// One `Host` section of P (ADR-0007 §2, ADR-0008 D10 item 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Section {
    /// An existing-access alias: rendered exactly as in M02.
    ExistingAccess(ManagedAlias),
    /// ⟨M03⟩ A pair whose preference is `managed_certificate` (ADR-0008 D10 item 1).
    ManagedCertificate {
        /// The `Host` name.
        alias: AliasName,
        /// `HostName`.
        hostname: HostName,
        /// `Port`, when not 22.
        port: Option<u16>,
        /// `User`.
        user: String,
        /// `IdentityAgent`: the **environment** endpoint (a Unix socket path, or the
        /// stable Windows pipe, written `//./pipe/heimdall-<token>-signing`).
        endpoint: RenderPath,
        /// The slot's public key, `<data_dir>/managed/<destination-id>/key.pub`.
        key_pub: RenderPath,
        /// The slot's certificate, `<data_dir>/managed/<destination-id>/cert.pub`.
        cert: RenderPath,
        /// `None`: `ControlPath none`. `Some`: only ever the slot's **stable** mux path
        /// `<runtime_dir>/mux/<destination-id>`, once owned masters are enabled and
        /// applied (ADR-0008 D8 item 3). Refused in a Windows file (M-F7).
        control_path: Option<RenderPath>,
    },
}

impl Section {
    /// The section's alias.
    #[must_use]
    pub fn alias(&self) -> &AliasName {
        match self {
            Section::ExistingAccess(a) => &a.alias,
            Section::ManagedCertificate { alias, .. } => alias,
        }
    }
}

/// A file path for a managed section: never a pipe, and fit for `style`.
fn check_file(path: &RenderPath, style: PathStyle, what: &'static str) -> Result<(), RenderError> {
    if path.kind == PathKind::Pipe || !path.fits(style) {
        return Err(RenderError::RefusedValue(what));
    }
    Ok(())
}

/// A managed-certificate section (module docs; ADR-0008 D10 item 1).
#[allow(clippy::too_many_arguments)]
fn push_managed(
    out: &mut String,
    alias: &AliasName,
    hostname: &HostName,
    port: Option<u16>,
    user: &str,
    endpoint: &RenderPath,
    key_pub: &RenderPath,
    cert: &RenderPath,
    control_path: Option<&RenderPath>,
    style: PathStyle,
    form: ManagedIdentityForm,
) -> Result<(), RenderError> {
    if !endpoint.fits(style) {
        return Err(RenderError::RefusedValue("identity_agent"));
    }
    check_file(key_pub, style, "identity_file")?;
    check_file(cert, style, "certificate_file")?;
    if let Some(path) = control_path
        && (style == PathStyle::Windows || path.kind != PathKind::Unix || !path.fits(style))
    {
        return Err(RenderError::RefusedValue("control_path"));
    }
    push_route(out, alias, hostname, port, user)?;
    out.push_str("    IdentityAgent ");
    out.push_str(&endpoint.ssh_quoted());
    out.push('\n');
    out.push_str("    IdentitiesOnly yes\n");
    for (keyword, path) in form.entries(key_pub, cert) {
        out.push_str("    ");
        out.push_str(keyword);
        out.push(' ');
        out.push_str(&path.ssh_quoted());
        out.push('\n');
    }
    out.push_str("    ControlMaster no\n");
    match control_path {
        None => out.push_str("    ControlPath none\n"),
        Some(path) => {
            out.push_str("    ControlPath ");
            out.push_str(&path.ssh_quoted());
            out.push('\n');
        }
    }
    Ok(())
}

/// Render P from its sections: a header comment, then one `Host` section per alias,
/// sorted bytewise by alias, LF line endings, a trailing newline, nothing that varies
/// between renders of the same input. Existing-access sections are rendered exactly as
/// [`render_managed`] renders them in M02; managed-certificate sections as the module
/// docs say, with the identity directives of `form`.
///
/// # Errors
/// [`RenderError`]: a duplicate alias (compared case-insensitively), a refused user or
/// port, a path that does not fit `style` (a pipe in a Unix file, a Unix path in a
/// Windows file, a pipe as a key or certificate file), or a mux path in a Windows file.
pub fn render_sections(
    sections: &[Section],
    style: PathStyle,
    form: ManagedIdentityForm,
) -> Result<Vec<u8>, RenderError> {
    let mut sorted: Vec<&Section> = sections.iter().collect();
    sorted.sort_by(|a, b| a.alias().0.as_bytes().cmp(b.alias().0.as_bytes()));
    let mut seen = std::collections::BTreeSet::new();
    for s in &sorted {
        if !seen.insert(s.alias().0.to_ascii_lowercase()) {
            return Err(RenderError::DuplicateAlias);
        }
    }
    let mut out = String::from(MANAGED_HEADER);
    for s in sorted {
        match s {
            Section::ExistingAccess(a) => push_existing(&mut out, a, style)?,
            Section::ManagedCertificate {
                alias,
                hostname,
                port,
                user,
                endpoint,
                key_pub,
                cert,
                control_path,
            } => push_managed(
                &mut out,
                alias,
                hostname,
                *port,
                user,
                endpoint,
                key_pub,
                cert,
                control_path.as_ref(),
                style,
                form,
            )?,
        }
    }
    Ok(out.into_bytes())
}

/// [`render_sections`], wrapped as [`Rendered`] provenance for a `StepContent`.
///
/// # Errors
/// As [`render_sections`].
pub fn rendered_sections(
    sections: &[Section],
    style: PathStyle,
    form: ManagedIdentityForm,
) -> Result<Rendered, RenderError> {
    render_sections(sections, style, form).map(Rendered::from_renderer)
}

// --- ⟨M03⟩ the command-line half (ADR-0008 D8 item 2, D10 item 4) ------------------------

/// The pins an owned launch inserts **right after the program name** (ADR-0008 D8 item
/// 2; §17.4 item 7), so they are read before the user's arguments and before every
/// configuration file: the connection stays in the launched process.
pub const OWNED_LAUNCH_PINS: [&str; 6] = [
    "-o",
    "ForkAfterAuthentication=no",
    "-o",
    "ControlMaster=no",
    "-o",
    "ControlPath=none",
];

/// One `-o Keyword="<path>"` value, quoted and `%`-escaped as P writes the path.
fn option_value(keyword: &str, path: &RenderPath) -> String {
    format!("{keyword}={}", path.ssh_quoted())
}

/// `connect`'s identity options for a managed binding (ADR-0008 D10 item 4): `-o
/// IdentityAgent=<binding endpoint>`, `-o IdentitiesOnly=yes`, then the identity options
/// of `form` (the same [`ManagedIdentityForm`] P uses), each value quoted and
/// `%`-escaped as in P. Command-line values win (F1), so they apply to a binding whether
/// or not it holds the slot. The foreground pins ([`OWNED_LAUNCH_PINS`]) are separate:
/// they go first, right after the program name.
///
/// # Errors
/// [`RenderError::RefusedValue`] for an endpoint or file that does not fit `style`, or a
/// pipe given as a file.
pub fn managed_identity_options(
    endpoint: &RenderPath,
    key_pub: &RenderPath,
    cert: &RenderPath,
    style: PathStyle,
    form: ManagedIdentityForm,
) -> Result<Vec<String>, RenderError> {
    if !endpoint.fits(style) {
        return Err(RenderError::RefusedValue("identity_agent"));
    }
    check_file(key_pub, style, "identity_file")?;
    check_file(cert, style, "certificate_file")?;
    let mut out = vec![
        "-o".to_owned(),
        option_value("IdentityAgent", endpoint),
        "-o".to_owned(),
        "IdentitiesOnly=yes".to_owned(),
    ];
    for (keyword, path) in form.entries(key_pub, cert) {
        out.push("-o".to_owned());
        out.push(option_value(keyword, path));
    }
    Ok(out)
}

/// Why an owned launch's arguments are refused before launch (ADR-0008 D8 item 2;
/// `CONFIG_CONFLICT`, reason `owned_connection_option_conflict`, `prelaunch_failed`). The
/// argument is named by its index in the user's arguments (1-based, after the program),
/// never by its text (ADR-0007 §8 argument privacy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum OwnedOptionConflict {
    /// `-f`, alone or bundled (`-fN`).
    #[error("argument {index}: -f would move the connection into the background")]
    Fork {
        /// The argument's 1-based index.
        index: usize,
    },
    /// `-M`.
    #[error("argument {index}: -M would make the connection a master")]
    Master {
        /// The argument's 1-based index.
        index: usize,
    },
    /// `-S`.
    #[error("argument {index}: -S would name a control socket")]
    ControlSocket {
        /// The argument's 1-based index.
        index: usize,
    },
    /// `-O`.
    #[error("argument {index}: -O would send a control command")]
    ControlCommand {
        /// The argument's 1-based index.
        index: usize,
    },
    /// A `-o` form of `ForkAfterAuthentication`, `ControlMaster`, `ControlPath` or
    /// `ControlPersist`.
    #[error("argument {index}: -o {keyword} conflicts with an owned connection")]
    Option {
        /// The argument's 1-based index (the one holding the value).
        index: usize,
        /// The keyword, as this table spells it.
        keyword: &'static str,
    },
}

/// The `-o` keywords an owned launch refuses (ADR-0008 D8 item 2).
pub const OWNED_REFUSED_KEYWORDS: [&str; 4] = [
    "ForkAfterAuthentication",
    "ControlMaster",
    "ControlPath",
    "ControlPersist",
];

/// The `ssh` option letters that take an argument (OpenSSH's `getopt` string
/// `1246ab:c:e:fgi:kl:m:no:p:qstvxAB:CD:E:F:GI:J:KL:MNO:P:Q:R:S:TVw:W:XYy`).
const SSH_OPTIONS_WITH_ARGUMENT: &[u8] = b"bceilmopBDEFIJLOPQRSwW";

/// OpenSSH's whitespace for configuration tokens (`misc.c` `WHITESPACE`).
const CONFIG_WHITESPACE: &[u8] = b" \t\r\n";

/// The bytes of `s` after its leading configuration whitespace.
fn skip_config_whitespace(s: &[u8]) -> &[u8] {
    let n = s
        .iter()
        .take_while(|c| CONFIG_WHITESPACE.contains(c))
        .count();
    &s[n..]
}

/// One token as OpenSSH's `strdelim` (splitting on `=`) takes it from `s`, and the
/// rest: the token ends at whitespace, `=` or a quote; a quote joins the text before it
/// with everything up to the matching quote; at most one `=` (with the whitespace
/// around it) is consumed after a token. `None` for an unmatched quote (OpenSSH 10.5p1
/// `ssh -G` was observed to ignore such a value: no keyword is set).
fn config_token(s: &[u8]) -> Option<(Vec<u8>, &[u8])> {
    let Some(i) = s
        .iter()
        .position(|c| CONFIG_WHITESPACE.contains(c) || *c == b'"' || *c == b'=')
    else {
        return Some((s.to_vec(), &[]));
    };
    if s[i] == b'"' {
        let after = &s[i + 1..];
        let j = after.iter().position(|c| *c == b'"')?;
        let mut token = s[..i].to_vec();
        token.extend_from_slice(&after[..j]);
        return Some((token, skip_config_whitespace(&after[j + 1..])));
    }
    let equals = s[i] == b'=';
    let mut rest = skip_config_whitespace(&s[i + 1..]);
    if !equals && rest.first() == Some(&b'=') {
        rest = skip_config_whitespace(&rest[1..]);
    }
    Some((s[..i].to_vec(), rest))
}

/// The keyword of a `-o` value as OpenSSH's `process_config_line` reads it: the first
/// [`config_token`], or, when that is empty (leading whitespace or `=`), the next one.
/// So `ControlMaster=yes`, `"ControlMaster" yes`, `=ControlPersist=yes`,
/// ` =ForkAfterAuthentication=yes` and `Control"Master"` all name their keyword
/// (integrator fix after the wave-2 review; each spelling checked with OpenSSH 10.5p1
/// `ssh -G -o …`). `None` for an unmatched quote, which sets nothing.
fn option_keyword(value: &[u8]) -> Option<Vec<u8>> {
    let (first, rest) = config_token(value)?;
    if !first.is_empty() {
        return Some(first);
    }
    config_token(rest).map(|(keyword, _)| keyword)
}

/// One `-<letter>` option given at argument `index` (1-based), with its value and the
/// value's own index when it takes one.
fn check_option(
    letter: u8,
    index: usize,
    value: Option<(&[u8], usize)>,
) -> Result<(), OwnedOptionConflict> {
    match letter {
        b'f' => Err(OwnedOptionConflict::Fork { index }),
        b'M' => Err(OwnedOptionConflict::Master { index }),
        b'S' => Err(OwnedOptionConflict::ControlSocket { index }),
        b'O' => Err(OwnedOptionConflict::ControlCommand { index }),
        b'o' => {
            let Some((value, at)) = value else {
                return Ok(());
            };
            // An unmatched quote sets no keyword (observed with `ssh -G`, 10.5p1).
            let Some(keyword) = option_keyword(value) else {
                return Ok(());
            };
            match OWNED_REFUSED_KEYWORDS
                .iter()
                .find(|k| k.as_bytes().eq_ignore_ascii_case(&keyword))
            {
                Some(k) => Err(OwnedOptionConflict::Option {
                    index: at,
                    keyword: k,
                }),
                None => Ok(()),
            }
        }
        _ => Ok(()),
    }
}

/// One `getopt` pass from `args[start..]` (BSD semantics, as portable OpenSSH bundles:
/// no permutation). Returns where the first non-option is and whether `--` ended the
/// options.
fn option_pass(args: &[OsString], start: usize) -> Result<(usize, bool), OwnedOptionConflict> {
    let mut i = start;
    while i < args.len() {
        let a = args[i].as_encoded_bytes();
        if a == b"--" {
            return Ok((i + 1, true));
        }
        if a.len() < 2 || a[0] != b'-' {
            return Ok((i, false));
        }
        let index = i + 1;
        let mut j = 1;
        while j < a.len() {
            let letter = a[j];
            if SSH_OPTIONS_WITH_ARGUMENT.contains(&letter) {
                let value = if j + 1 < a.len() {
                    Some((&a[j + 1..], index))
                } else {
                    // The value is the next argument (absent at the end: ssh refuses).
                    i += 1;
                    args.get(i).map(|v| (v.as_encoded_bytes(), i + 1))
                };
                check_option(letter, index, value)?;
                break;
            }
            check_option(letter, index, None)?;
            j += 1;
        }
        i += 1;
    }
    Ok((i, false))
}

/// Refuse the user's `ssh` arguments (`args`, after the program name) that would move
/// an owned connection out of the launched process (ADR-0008 D8 item 2): `-f` alone or
/// bundled, `-M`, `-S`, `-O`, and any `-o` form of `ForkAfterAuthentication`,
/// `ControlMaster`, `ControlPath` or `ControlPersist` (keyword case-insensitive, `=` or
/// whitespace separated, attached as in `-oControlMaster=yes` or separate).
///
/// The arguments are read as `ssh` reads them: options, the destination, options again
/// (OpenSSH re-parses options after the destination unless `--` ended them), then the
/// remote command, whose words are never options. So `ssh host ls -f` is accepted and
/// `ssh host -f` is refused.
///
/// # Errors
/// The first conflicting argument ([`OwnedOptionConflict`]).
pub fn check_owned_ssh_arguments(args: &[OsString]) -> Result<(), OwnedOptionConflict> {
    let (host, terminated) = option_pass(args, 0)?;
    if terminated || host >= args.len() {
        return Ok(());
    }
    // The destination, then (when more follows) a second option pass.
    if host + 1 < args.len() {
        option_pass(args, host + 1)?;
    }
    Ok(())
}

/// The arguments of an owned `ssh` launch: [`OWNED_LAUNCH_PINS`] right after the program
/// name, then the user's `args` unchanged, once [`check_owned_ssh_arguments`] accepts
/// them.
///
/// # Errors
/// As [`check_owned_ssh_arguments`].
pub fn owned_ssh_arguments(args: &[OsString]) -> Result<Vec<OsString>, OwnedOptionConflict> {
    check_owned_ssh_arguments(args)?;
    let mut out: Vec<OsString> = OWNED_LAUNCH_PINS.iter().map(OsString::from).collect();
    out.extend(args.iter().cloned());
    Ok(out)
}

/// The begin marker line of a block (no line ending).
pub(crate) fn begin_line(marker: &MarkerId) -> String {
    format!("{BEGIN_PREFIX}{}{BEGIN_SUFFIX}", marker.as_str())
}

/// The end marker line of a block (no line ending).
pub(crate) fn end_line(marker: &MarkerId) -> String {
    format!("{END_PREFIX}{})", marker.as_str())
}

/// Whether an include target may be written: an absolute file path (never `~`, never
/// a pipe), and no glob metacharacter (ADR-0007 §12.16 item 3, §12.17 item 9).
///
/// # Errors
/// [`RenderError::Unmanageable`] with [`INCLUDE_TARGET_GLOB`] for `*`, `?`, `[` or `]`
/// (OpenSSH globs inside a quoted `Include` argument, and escaping is not verified
/// across the client matrix); [`RenderError::RefusedValue`] (`include_target`) for a
/// `~` path or a pipe: B's target is absolute, so B loads P whatever `$HOME` is.
pub fn check_include_target(target: &RenderPath) -> Result<(), RenderError> {
    if target.text.contains(['*', '?', '[', ']']) {
        return Err(RenderError::Unmanageable(INCLUDE_TARGET_GLOB));
    }
    if !target.is_absolute_file() || target.text.starts_with('~') {
        return Err(RenderError::RefusedValue("include_target"));
    }
    Ok(())
}

/// Render B, the marked `Include` block for the user file: three lines in the user
/// file's line-ending style. The target is absolute and literal
/// ([`check_include_target`]); build it with [`RenderPath::absolute`].
///
/// # Errors
/// As [`check_include_target`]: [`RenderError::Unmanageable`] (`include_target_glob`)
/// for a glob metacharacter, which is manual mode before any edit;
/// [`RenderError::RefusedValue`] (`include_target`) for a `~` path or a pipe.
pub fn render_include_block(
    marker: &MarkerId,
    target: &RenderPath,
    newline: Newline,
) -> Result<Vec<u8>, RenderError> {
    check_include_target(target)?;
    let nl = newline.as_str();
    Ok(format!(
        "{}{nl}Include {}{nl}{}{nl}",
        begin_line(marker),
        target.ssh_quoted(),
        end_line(marker)
    )
    .into_bytes())
}

/// Git configuration double-quoting: `\` and `"` escaped (F22).
fn git_quoted(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        if c == '\\' || c == '"' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

/// Render P_git, the managed Git file setting `core.sshCommand` to the verified
/// client: the absolute path with `/` separators, single-quoted for the POSIX shell
/// Git runs it through, then Git-config double-quoted (ADR-0007 §4).
///
/// # Errors
/// [`RenderError::RefusedValue`] for a path that is not absolute (a `~` path or a
/// pipe), or that contains `'` (`"` and control characters are already refused by
/// [`RenderPath`]).
pub fn render_git_managed(verified_client: &RenderPath) -> Result<Vec<u8>, RenderError> {
    if !verified_client.is_absolute_file() {
        return Err(RenderError::RefusedValue("git_ssh_command_path"));
    }
    let text = verified_client.as_str();
    if text.contains('\'') || text.contains('"') || text.chars().any(char::is_control) {
        return Err(RenderError::RefusedValue("git_ssh_command_path"));
    }
    let value = git_quoted(&format!("'{text}'"));
    Ok(format!("{GIT_MANAGED_HEADER}[core]\n\tsshCommand = {value}\n").into_bytes())
}

/// Render B_git, the marked `[include]` block for the global Git file: four lines in
/// the file's line-ending style, the path absolute and Git-config double-quoted.
///
/// # Errors
/// [`RenderError::RefusedValue`] for a path that is not absolute or contains a
/// control character.
pub fn render_git_include_block(
    marker: &MarkerId,
    target: &RenderPath,
    newline: Newline,
) -> Result<Vec<u8>, RenderError> {
    if !target.is_absolute_file() || target.as_str().chars().any(char::is_control) {
        return Err(RenderError::RefusedValue("git_include_path"));
    }
    let nl = newline.as_str();
    Ok(format!(
        "{}{nl}[include]{nl}\tpath = {}{nl}{}{nl}",
        begin_line(marker),
        git_quoted(target.as_str()),
        end_line(marker)
    )
    .into_bytes())
}

/// [`render_managed`], wrapped as [`Rendered`] provenance for a `StepContent`.
///
/// # Errors
/// As [`render_managed`].
pub fn rendered_managed(
    aliases: &[ManagedAlias],
    style: PathStyle,
) -> Result<Rendered, RenderError> {
    render_managed(aliases, style).map(Rendered::from_renderer)
}

/// [`render_include_block`], wrapped as [`Rendered`] provenance.
///
/// # Errors
/// As [`render_include_block`].
pub fn rendered_include_block(
    marker: &MarkerId,
    target: &RenderPath,
    newline: Newline,
) -> Result<Rendered, RenderError> {
    render_include_block(marker, target, newline).map(Rendered::from_renderer)
}

/// [`render_git_managed`], wrapped as [`Rendered`] provenance.
///
/// # Errors
/// As [`render_git_managed`].
pub fn rendered_git_managed(verified_client: &RenderPath) -> Result<Rendered, RenderError> {
    render_git_managed(verified_client).map(Rendered::from_renderer)
}

/// [`render_git_include_block`], wrapped as [`Rendered`] provenance.
///
/// # Errors
/// As [`render_git_include_block`].
pub fn rendered_git_include_block(
    marker: &MarkerId,
    target: &RenderPath,
    newline: Newline,
) -> Result<Rendered, RenderError> {
    render_git_include_block(marker, target, newline).map(Rendered::from_renderer)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn alias(name: &str, host: &str) -> ManagedAlias {
        ManagedAlias {
            alias: AliasName::parse(name).unwrap(),
            hostname: HostName::parse(host).unwrap(),
            port: None,
            user: "deploy".into(),
            identity_agent: Some(RenderPath::unix(Path::new("/run/agent.sock")).unwrap()),
            identity_files: vec![
                RenderPath::unix(Path::new("~/.config/heimdall/keys/k.pub")).unwrap(),
            ],
            identities_only: true,
        }
    }

    #[test]
    fn managed_render_is_deterministic_sorted_and_closed() {
        let a = [alias("zeta", "z.example"), alias("alpha", "10.0.0.1")];
        let b = [alias("alpha", "10.0.0.1"), alias("zeta", "z.example")];
        let one = render_managed(&a, PathStyle::Unix).unwrap();
        let two = render_managed(&b, PathStyle::Unix).unwrap();
        assert_eq!(one, two, "input order must not matter");
        assert_eq!(one, render_managed(&a, PathStyle::Unix).unwrap());
        let text = String::from_utf8(one).unwrap();
        assert!(text.find("Host alpha").unwrap() < text.find("Host zeta").unwrap());
        assert!(text.ends_with('\n') && !text.contains('\r'));
        for forbidden in [
            "ProxyCommand",
            "LocalCommand",
            "PermitLocalCommand",
            "KnownHostsCommand",
            "StrictHostKeyChecking",
            "ForwardAgent",
            "Match",
            "Include",
            "*",
        ] {
            assert!(!text.contains(forbidden), "{forbidden}");
        }
    }

    #[test]
    fn duplicate_alias_is_refused() {
        let a = [alias("box", "a.example"), alias("BOX", "b.example")];
        assert_eq!(
            render_managed(&a, PathStyle::Unix),
            Err(RenderError::DuplicateAlias)
        );
    }

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    /// ⟨M03⟩ ADR-0008 D8 item 2: the arguments are read as ssh's BSD `getopt` reads them,
    /// before and after the destination, never inside the remote command.
    #[test]
    fn owned_arguments_follow_ssh_option_parsing() {
        use OwnedOptionConflict as C;
        let check = |a: &[&str]| check_owned_ssh_arguments(&os(a));
        assert_eq!(check(&["host"]), Ok(()));
        assert_eq!(check(&["-f", "host"]), Err(C::Fork { index: 1 }));
        assert_eq!(check(&["-vfN", "host"]), Err(C::Fork { index: 1 }));
        assert_eq!(check(&["host", "-f"]), Err(C::Fork { index: 2 }));
        assert_eq!(check(&["host", "ls", "-f"]), Ok(()));
        assert_eq!(check(&["--", "host", "-f"]), Ok(()));
        assert_eq!(check(&["-l", "-f", "host"]), Ok(()), "-f is -l's value");
        assert_eq!(check(&["-M", "host"]), Err(C::Master { index: 1 }));
        assert_eq!(
            check(&["-Snone", "host"]),
            Err(C::ControlSocket { index: 1 })
        );
        assert_eq!(
            check(&["-O", "exit", "host"]),
            Err(C::ControlCommand { index: 1 })
        );
        for value in [
            "ControlMaster=yes",
            "controlmaster yes",
            "  CONTROLPATH=/tmp/x",
            "ControlPersist\tyes",
            "\"ForkAfterAuthentication\" yes",
            // ⟨integrator, wave-2 review⟩ the spellings OpenSSH's `strdelim` also reads
            // as the keyword: a leading `=` (alone or after whitespace), a quoted
            // keyword followed directly by its value, a quote inside the keyword.
            "=ControlPersist=yes",
            " =ForkAfterAuthentication=yes",
            "\"ControlMaster\"yes",
            "Control\"Master\" yes",
            " \"ControlPath\" /tmp/x",
        ] {
            assert!(
                matches!(
                    check(&["-o", value, "host"]),
                    Err(C::Option { index: 2, .. })
                ),
                "{value}"
            );
            let attached = format!("-o{value}");
            assert!(
                matches!(check(&[&attached, "host"]), Err(C::Option { index: 1, .. })),
                "{attached}"
            );
        }
        assert_eq!(check(&["-o", "ControlMasterX=yes", "host"]), Ok(()));
        assert_eq!(
            check(&["-o", "==ControlMaster=yes", "host"]),
            Ok(()),
            "ssh ignores it"
        );
        assert_eq!(
            check(&["-o", "\"ControlMaster yes", "host"]),
            Ok(()),
            "an unmatched quote sets nothing (ssh -G, 10.5p1)"
        );
        assert_eq!(check(&["-o", "User=x", "host"]), Ok(()));
        assert_eq!(check(&["-o"]), Ok(()), "a missing value is ssh's own error");
        let pinned = owned_ssh_arguments(&os(&["-p", "22", "host"])).unwrap();
        assert_eq!(pinned[..6], os(&OWNED_LAUNCH_PINS)[..]);
        assert_eq!(pinned[6..], os(&["-p", "22", "host"])[..]);
    }
}
