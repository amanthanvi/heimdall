//! The directive table (m02-plan U1; ADR-0007 F1–F4, F7).
//!
//! [`KnownKeyword`] lists every keyword of ssh_config(5) at the S01 pin
//! (`docs/sources/pins.json`, snapshot `docs/sources/snapshots/S01.txt.gz`; the list
//! was checked against that snapshot when the skeleton was written). Spelling is
//! case-insensitive, as in OpenSSH. A deprecated alias OpenSSH still accepts is U1's
//! to map; anything else is [`Keyword::Unknown`].
//!
//! **Aliases (U1).** [`KnownKeyword::parse`] also accepts the two aliases S01 names
//! (`ChallengeResponseAuthentication` for `KbdInteractiveAuthentication`, and
//! `HostbasedKeyTypes`, "formerly named", for `HostbasedAcceptedAlgorithms`) and the
//! other obsolete spellings OpenSSH's keyword table maps to a live option
//! ([`ALIASES`]). Those others are not in the pinned manual, so they are `[I]`; the U3
//! corpus comparison against `ssh -G` settles them per client.
//!
//! **Retired keywords (U1).** OpenSSH accepts, and ignores, a few keywords it no longer
//! implements (`Protocol`, `UseRoaming` …). They parse as [`Keyword::Unknown`] (the
//! frozen AST has no other place for them); [`obsolete`] tells an evaluator that ssh
//! ignores such a line instead of refusing the file, and `eval::evaluate` uses it that
//! way: such a line is not invalid, changes no value, and is recorded in
//! `Evaluation::ignored` (ADR-0007 §12.15 item 4). Also `[I]`, settled the same way.
//!
//! **Classes.** [`class`] follows F1–F4 and the S01 text: the six keywords whose entry
//! says that occurrences add up are [`DirectiveClass::Accumulates`]; `Host`/`Match` are
//! sections; the three local commands of F4 are [`DirectiveClass::Executes`];
//! everything else is first-wins. [`expands_tokens`], [`tokens`] and [`expands_env`]
//! follow S01's TOKENS and ENVIRONMENT VARIABLES sections plus each entry's own text
//! (see each function).

/// A directive's keyword as parsed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Keyword {
    /// A keyword ssh_config(5) defines.
    Known(KnownKeyword),
    /// A keyword this table does not know, as written (invalid unless `IgnoreUnknown`
    /// covers it).
    Unknown(String),
    /// The line is not UTF-8. Nothing is guessed about it.
    Unreadable,
}

/// The keyword for a spelling as written: [`Keyword::Known`] when
/// [`KnownKeyword::parse`] knows it (aliases included), otherwise [`Keyword::Unknown`]
/// with the spelling unchanged.
#[must_use]
pub fn keyword(spelling: &str) -> Keyword {
    KnownKeyword::parse(spelling)
        .map_or_else(|| Keyword::Unknown(spelling.to_owned()), Keyword::Known)
}

/// How OpenSSH combines a directive's occurrences (ADR-0007 F1–F4, F7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DirectiveClass {
    /// The first obtained value wins (F1).
    FirstWins,
    /// Every occurrence adds to a list, in order (F2: `IdentityFile`,
    /// `CertificateFile`, forwardings, `SendEnv` …).
    Accumulates,
    /// Opens a section (`Host`, `Match`).
    Section,
    /// `Include` (F3).
    Include,
    /// Names a command OpenSSH may run (`ProxyCommand`, `KnownHostsCommand`,
    /// `LocalCommand`); never run here.
    Executes,
    /// Anything else.
    Other,
}

/// Every keyword of ssh_config(5) at the S01 pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KnownKeyword {
    /// `Host`.
    Host,
    /// `Match`.
    Match,
    /// `AddKeysToAgent`.
    AddKeysToAgent,
    /// `AddressFamily`.
    AddressFamily,
    /// `BatchMode`.
    BatchMode,
    /// `BindAddress`.
    BindAddress,
    /// `BindInterface`.
    BindInterface,
    /// `CanonicalDomains`.
    CanonicalDomains,
    /// `CanonicalizeFallbackLocal`.
    CanonicalizeFallbackLocal,
    /// `CanonicalizeHostname`.
    CanonicalizeHostname,
    /// `CanonicalizeMaxDots`.
    CanonicalizeMaxDots,
    /// `CanonicalizePermittedCNAMEs`.
    CanonicalizePermittedCnames,
    /// `CASignatureAlgorithms`.
    CaSignatureAlgorithms,
    /// `CertificateFile`.
    CertificateFile,
    /// `ChannelTimeout`.
    ChannelTimeout,
    /// `CheckHostIP`.
    CheckHostIp,
    /// `Ciphers`.
    Ciphers,
    /// `ClearAllForwardings`.
    ClearAllForwardings,
    /// `Compression`.
    Compression,
    /// `ConnectionAttempts`.
    ConnectionAttempts,
    /// `ConnectTimeout`.
    ConnectTimeout,
    /// `ControlMaster`.
    ControlMaster,
    /// `ControlPath`.
    ControlPath,
    /// `ControlPersist`.
    ControlPersist,
    /// `DynamicForward`.
    DynamicForward,
    /// `EnableEscapeCommandline`.
    EnableEscapeCommandline,
    /// `EnableSSHKeysign`.
    EnableSshKeysign,
    /// `EscapeChar`.
    EscapeChar,
    /// `ExitOnForwardFailure`.
    ExitOnForwardFailure,
    /// `FingerprintHash`.
    FingerprintHash,
    /// `ForkAfterAuthentication`.
    ForkAfterAuthentication,
    /// `ForwardAgent`.
    ForwardAgent,
    /// `ForwardX11`.
    ForwardX11,
    /// `ForwardX11Timeout`.
    ForwardX11Timeout,
    /// `ForwardX11Trusted`.
    ForwardX11Trusted,
    /// `GatewayPorts`.
    GatewayPorts,
    /// `GlobalKnownHostsFile`.
    GlobalKnownHostsFile,
    /// `GSSAPIAuthentication`.
    GssapiAuthentication,
    /// `GSSAPIDelegateCredentials`.
    GssapiDelegateCredentials,
    /// `HashKnownHosts`.
    HashKnownHosts,
    /// `HostbasedAcceptedAlgorithms`.
    HostbasedAcceptedAlgorithms,
    /// `HostbasedAuthentication`.
    HostbasedAuthentication,
    /// `HostKeyAlgorithms`.
    HostKeyAlgorithms,
    /// `HostKeyAlias`.
    HostKeyAlias,
    /// `Hostname`.
    Hostname,
    /// `IdentitiesOnly`.
    IdentitiesOnly,
    /// `IdentityAgent`.
    IdentityAgent,
    /// `IdentityFile`.
    IdentityFile,
    /// `IgnoreUnknown`.
    IgnoreUnknown,
    /// `Include`.
    Include,
    /// `IPQoS`.
    IpQos,
    /// `KbdInteractiveAuthentication`.
    KbdInteractiveAuthentication,
    /// `KbdInteractiveDevices`.
    KbdInteractiveDevices,
    /// `KexAlgorithms`.
    KexAlgorithms,
    /// `KnownHostsCommand`.
    KnownHostsCommand,
    /// `LocalCommand`.
    LocalCommand,
    /// `LocalForward`.
    LocalForward,
    /// `LogLevel`.
    LogLevel,
    /// `LogVerbose`.
    LogVerbose,
    /// `MACs`.
    Macs,
    /// `NoHostAuthenticationForLocalhost`.
    NoHostAuthenticationForLocalhost,
    /// `NumberOfPasswordPrompts`.
    NumberOfPasswordPrompts,
    /// `ObscureKeystrokeTiming`.
    ObscureKeystrokeTiming,
    /// `PasswordAuthentication`.
    PasswordAuthentication,
    /// `PermitLocalCommand`.
    PermitLocalCommand,
    /// `PermitRemoteOpen`.
    PermitRemoteOpen,
    /// `PKCS11Provider`.
    Pkcs11Provider,
    /// `Port`.
    Port,
    /// `PreferredAuthentications`.
    PreferredAuthentications,
    /// `ProxyCommand`.
    ProxyCommand,
    /// `ProxyJump`.
    ProxyJump,
    /// `ProxyUseFdpass`.
    ProxyUseFdpass,
    /// `PubkeyAcceptedAlgorithms`.
    PubkeyAcceptedAlgorithms,
    /// `PubkeyAuthentication`.
    PubkeyAuthentication,
    /// `RefuseConnection`.
    RefuseConnection,
    /// `RekeyLimit`.
    RekeyLimit,
    /// `RemoteCommand`.
    RemoteCommand,
    /// `RemoteForward`.
    RemoteForward,
    /// `RequestTTY`.
    RequestTty,
    /// `RequiredRSASize`.
    RequiredRsaSize,
    /// `RevokedHostKeys`.
    RevokedHostKeys,
    /// `SecurityKeyProvider`.
    SecurityKeyProvider,
    /// `SendEnv`.
    SendEnv,
    /// `ServerAliveCountMax`.
    ServerAliveCountMax,
    /// `ServerAliveInterval`.
    ServerAliveInterval,
    /// `SessionType`.
    SessionType,
    /// `SetEnv`.
    SetEnv,
    /// `StdinNull`.
    StdinNull,
    /// `StreamLocalBindMask`.
    StreamLocalBindMask,
    /// `StreamLocalBindUnlink`.
    StreamLocalBindUnlink,
    /// `StrictHostKeyChecking`.
    StrictHostKeyChecking,
    /// `SyslogFacility`.
    SyslogFacility,
    /// `TCPKeepAlive`.
    TcpKeepAlive,
    /// `Tag`.
    Tag,
    /// `Tunnel`.
    Tunnel,
    /// `TunnelDevice`.
    TunnelDevice,
    /// `UpdateHostKeys`.
    UpdateHostKeys,
    /// `User`.
    User,
    /// `UserKnownHostsFile`.
    UserKnownHostsFile,
    /// `VerifyHostKeyDNS`.
    VerifyHostKeyDns,
    /// `VersionAddendum`.
    VersionAddendum,
    /// `VisualHostKey`.
    VisualHostKey,
    /// `WarnWeakCrypto`.
    WarnWeakCrypto,
    /// `XAuthLocation`.
    XauthLocation,
}

impl KnownKeyword {
    /// Every known keyword, in table order.
    pub const ALL: &[KnownKeyword] = &[
        KnownKeyword::Host,
        KnownKeyword::Match,
        KnownKeyword::AddKeysToAgent,
        KnownKeyword::AddressFamily,
        KnownKeyword::BatchMode,
        KnownKeyword::BindAddress,
        KnownKeyword::BindInterface,
        KnownKeyword::CanonicalDomains,
        KnownKeyword::CanonicalizeFallbackLocal,
        KnownKeyword::CanonicalizeHostname,
        KnownKeyword::CanonicalizeMaxDots,
        KnownKeyword::CanonicalizePermittedCnames,
        KnownKeyword::CaSignatureAlgorithms,
        KnownKeyword::CertificateFile,
        KnownKeyword::ChannelTimeout,
        KnownKeyword::CheckHostIp,
        KnownKeyword::Ciphers,
        KnownKeyword::ClearAllForwardings,
        KnownKeyword::Compression,
        KnownKeyword::ConnectionAttempts,
        KnownKeyword::ConnectTimeout,
        KnownKeyword::ControlMaster,
        KnownKeyword::ControlPath,
        KnownKeyword::ControlPersist,
        KnownKeyword::DynamicForward,
        KnownKeyword::EnableEscapeCommandline,
        KnownKeyword::EnableSshKeysign,
        KnownKeyword::EscapeChar,
        KnownKeyword::ExitOnForwardFailure,
        KnownKeyword::FingerprintHash,
        KnownKeyword::ForkAfterAuthentication,
        KnownKeyword::ForwardAgent,
        KnownKeyword::ForwardX11,
        KnownKeyword::ForwardX11Timeout,
        KnownKeyword::ForwardX11Trusted,
        KnownKeyword::GatewayPorts,
        KnownKeyword::GlobalKnownHostsFile,
        KnownKeyword::GssapiAuthentication,
        KnownKeyword::GssapiDelegateCredentials,
        KnownKeyword::HashKnownHosts,
        KnownKeyword::HostbasedAcceptedAlgorithms,
        KnownKeyword::HostbasedAuthentication,
        KnownKeyword::HostKeyAlgorithms,
        KnownKeyword::HostKeyAlias,
        KnownKeyword::Hostname,
        KnownKeyword::IdentitiesOnly,
        KnownKeyword::IdentityAgent,
        KnownKeyword::IdentityFile,
        KnownKeyword::IgnoreUnknown,
        KnownKeyword::Include,
        KnownKeyword::IpQos,
        KnownKeyword::KbdInteractiveAuthentication,
        KnownKeyword::KbdInteractiveDevices,
        KnownKeyword::KexAlgorithms,
        KnownKeyword::KnownHostsCommand,
        KnownKeyword::LocalCommand,
        KnownKeyword::LocalForward,
        KnownKeyword::LogLevel,
        KnownKeyword::LogVerbose,
        KnownKeyword::Macs,
        KnownKeyword::NoHostAuthenticationForLocalhost,
        KnownKeyword::NumberOfPasswordPrompts,
        KnownKeyword::ObscureKeystrokeTiming,
        KnownKeyword::PasswordAuthentication,
        KnownKeyword::PermitLocalCommand,
        KnownKeyword::PermitRemoteOpen,
        KnownKeyword::Pkcs11Provider,
        KnownKeyword::Port,
        KnownKeyword::PreferredAuthentications,
        KnownKeyword::ProxyCommand,
        KnownKeyword::ProxyJump,
        KnownKeyword::ProxyUseFdpass,
        KnownKeyword::PubkeyAcceptedAlgorithms,
        KnownKeyword::PubkeyAuthentication,
        KnownKeyword::RefuseConnection,
        KnownKeyword::RekeyLimit,
        KnownKeyword::RemoteCommand,
        KnownKeyword::RemoteForward,
        KnownKeyword::RequestTty,
        KnownKeyword::RequiredRsaSize,
        KnownKeyword::RevokedHostKeys,
        KnownKeyword::SecurityKeyProvider,
        KnownKeyword::SendEnv,
        KnownKeyword::ServerAliveCountMax,
        KnownKeyword::ServerAliveInterval,
        KnownKeyword::SessionType,
        KnownKeyword::SetEnv,
        KnownKeyword::StdinNull,
        KnownKeyword::StreamLocalBindMask,
        KnownKeyword::StreamLocalBindUnlink,
        KnownKeyword::StrictHostKeyChecking,
        KnownKeyword::SyslogFacility,
        KnownKeyword::TcpKeepAlive,
        KnownKeyword::Tag,
        KnownKeyword::Tunnel,
        KnownKeyword::TunnelDevice,
        KnownKeyword::UpdateHostKeys,
        KnownKeyword::User,
        KnownKeyword::UserKnownHostsFile,
        KnownKeyword::VerifyHostKeyDns,
        KnownKeyword::VersionAddendum,
        KnownKeyword::VisualHostKey,
        KnownKeyword::WarnWeakCrypto,
        KnownKeyword::XauthLocation,
    ];

    /// The keyword's canonical spelling in ssh_config(5).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            KnownKeyword::Host => "Host",
            KnownKeyword::Match => "Match",
            KnownKeyword::AddKeysToAgent => "AddKeysToAgent",
            KnownKeyword::AddressFamily => "AddressFamily",
            KnownKeyword::BatchMode => "BatchMode",
            KnownKeyword::BindAddress => "BindAddress",
            KnownKeyword::BindInterface => "BindInterface",
            KnownKeyword::CanonicalDomains => "CanonicalDomains",
            KnownKeyword::CanonicalizeFallbackLocal => "CanonicalizeFallbackLocal",
            KnownKeyword::CanonicalizeHostname => "CanonicalizeHostname",
            KnownKeyword::CanonicalizeMaxDots => "CanonicalizeMaxDots",
            KnownKeyword::CanonicalizePermittedCnames => "CanonicalizePermittedCNAMEs",
            KnownKeyword::CaSignatureAlgorithms => "CASignatureAlgorithms",
            KnownKeyword::CertificateFile => "CertificateFile",
            KnownKeyword::ChannelTimeout => "ChannelTimeout",
            KnownKeyword::CheckHostIp => "CheckHostIP",
            KnownKeyword::Ciphers => "Ciphers",
            KnownKeyword::ClearAllForwardings => "ClearAllForwardings",
            KnownKeyword::Compression => "Compression",
            KnownKeyword::ConnectionAttempts => "ConnectionAttempts",
            KnownKeyword::ConnectTimeout => "ConnectTimeout",
            KnownKeyword::ControlMaster => "ControlMaster",
            KnownKeyword::ControlPath => "ControlPath",
            KnownKeyword::ControlPersist => "ControlPersist",
            KnownKeyword::DynamicForward => "DynamicForward",
            KnownKeyword::EnableEscapeCommandline => "EnableEscapeCommandline",
            KnownKeyword::EnableSshKeysign => "EnableSSHKeysign",
            KnownKeyword::EscapeChar => "EscapeChar",
            KnownKeyword::ExitOnForwardFailure => "ExitOnForwardFailure",
            KnownKeyword::FingerprintHash => "FingerprintHash",
            KnownKeyword::ForkAfterAuthentication => "ForkAfterAuthentication",
            KnownKeyword::ForwardAgent => "ForwardAgent",
            KnownKeyword::ForwardX11 => "ForwardX11",
            KnownKeyword::ForwardX11Timeout => "ForwardX11Timeout",
            KnownKeyword::ForwardX11Trusted => "ForwardX11Trusted",
            KnownKeyword::GatewayPorts => "GatewayPorts",
            KnownKeyword::GlobalKnownHostsFile => "GlobalKnownHostsFile",
            KnownKeyword::GssapiAuthentication => "GSSAPIAuthentication",
            KnownKeyword::GssapiDelegateCredentials => "GSSAPIDelegateCredentials",
            KnownKeyword::HashKnownHosts => "HashKnownHosts",
            KnownKeyword::HostbasedAcceptedAlgorithms => "HostbasedAcceptedAlgorithms",
            KnownKeyword::HostbasedAuthentication => "HostbasedAuthentication",
            KnownKeyword::HostKeyAlgorithms => "HostKeyAlgorithms",
            KnownKeyword::HostKeyAlias => "HostKeyAlias",
            KnownKeyword::Hostname => "Hostname",
            KnownKeyword::IdentitiesOnly => "IdentitiesOnly",
            KnownKeyword::IdentityAgent => "IdentityAgent",
            KnownKeyword::IdentityFile => "IdentityFile",
            KnownKeyword::IgnoreUnknown => "IgnoreUnknown",
            KnownKeyword::Include => "Include",
            KnownKeyword::IpQos => "IPQoS",
            KnownKeyword::KbdInteractiveAuthentication => "KbdInteractiveAuthentication",
            KnownKeyword::KbdInteractiveDevices => "KbdInteractiveDevices",
            KnownKeyword::KexAlgorithms => "KexAlgorithms",
            KnownKeyword::KnownHostsCommand => "KnownHostsCommand",
            KnownKeyword::LocalCommand => "LocalCommand",
            KnownKeyword::LocalForward => "LocalForward",
            KnownKeyword::LogLevel => "LogLevel",
            KnownKeyword::LogVerbose => "LogVerbose",
            KnownKeyword::Macs => "MACs",
            KnownKeyword::NoHostAuthenticationForLocalhost => "NoHostAuthenticationForLocalhost",
            KnownKeyword::NumberOfPasswordPrompts => "NumberOfPasswordPrompts",
            KnownKeyword::ObscureKeystrokeTiming => "ObscureKeystrokeTiming",
            KnownKeyword::PasswordAuthentication => "PasswordAuthentication",
            KnownKeyword::PermitLocalCommand => "PermitLocalCommand",
            KnownKeyword::PermitRemoteOpen => "PermitRemoteOpen",
            KnownKeyword::Pkcs11Provider => "PKCS11Provider",
            KnownKeyword::Port => "Port",
            KnownKeyword::PreferredAuthentications => "PreferredAuthentications",
            KnownKeyword::ProxyCommand => "ProxyCommand",
            KnownKeyword::ProxyJump => "ProxyJump",
            KnownKeyword::ProxyUseFdpass => "ProxyUseFdpass",
            KnownKeyword::PubkeyAcceptedAlgorithms => "PubkeyAcceptedAlgorithms",
            KnownKeyword::PubkeyAuthentication => "PubkeyAuthentication",
            KnownKeyword::RefuseConnection => "RefuseConnection",
            KnownKeyword::RekeyLimit => "RekeyLimit",
            KnownKeyword::RemoteCommand => "RemoteCommand",
            KnownKeyword::RemoteForward => "RemoteForward",
            KnownKeyword::RequestTty => "RequestTTY",
            KnownKeyword::RequiredRsaSize => "RequiredRSASize",
            KnownKeyword::RevokedHostKeys => "RevokedHostKeys",
            KnownKeyword::SecurityKeyProvider => "SecurityKeyProvider",
            KnownKeyword::SendEnv => "SendEnv",
            KnownKeyword::ServerAliveCountMax => "ServerAliveCountMax",
            KnownKeyword::ServerAliveInterval => "ServerAliveInterval",
            KnownKeyword::SessionType => "SessionType",
            KnownKeyword::SetEnv => "SetEnv",
            KnownKeyword::StdinNull => "StdinNull",
            KnownKeyword::StreamLocalBindMask => "StreamLocalBindMask",
            KnownKeyword::StreamLocalBindUnlink => "StreamLocalBindUnlink",
            KnownKeyword::StrictHostKeyChecking => "StrictHostKeyChecking",
            KnownKeyword::SyslogFacility => "SyslogFacility",
            KnownKeyword::TcpKeepAlive => "TCPKeepAlive",
            KnownKeyword::Tag => "Tag",
            KnownKeyword::Tunnel => "Tunnel",
            KnownKeyword::TunnelDevice => "TunnelDevice",
            KnownKeyword::UpdateHostKeys => "UpdateHostKeys",
            KnownKeyword::User => "User",
            KnownKeyword::UserKnownHostsFile => "UserKnownHostsFile",
            KnownKeyword::VerifyHostKeyDns => "VerifyHostKeyDNS",
            KnownKeyword::VersionAddendum => "VersionAddendum",
            KnownKeyword::VisualHostKey => "VisualHostKey",
            KnownKeyword::WarnWeakCrypto => "WarnWeakCrypto",
            KnownKeyword::XauthLocation => "XAuthLocation",
        }
    }

    /// The keyword for a spelling, compared case-insensitively as OpenSSH does
    /// (ASCII case folding, like OpenSSH's `lowercase()` in the C locale). Accepts the
    /// canonical spellings and the obsolete aliases of [`ALIASES`].
    #[must_use]
    pub fn parse(spelling: &str) -> Option<KnownKeyword> {
        Self::ALL
            .iter()
            .copied()
            .find(|k| k.as_str().eq_ignore_ascii_case(spelling))
            .or_else(|| {
                ALIASES
                    .iter()
                    .find(|(alias, _, _)| alias.eq_ignore_ascii_case(spelling))
                    .map(|(_, k, _)| *k)
            })
    }
}

/// Where a fact in this table comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Provenance {
    /// Stated in ssh_config(5) at the S01 pin.
    S01,
    /// OpenSSH's own keyword table (readconf.c), not pinned: `[I]` until the U3 corpus
    /// comparison against `ssh -G` settles it per client.
    Inferred,
}

/// Obsolete spellings OpenSSH maps to a live option, lowercase as in OpenSSH's table:
/// `(spelling, option, provenance)`.
pub const ALIASES: &[(&str, KnownKeyword, Provenance)] = &[
    (
        "challengeresponseauthentication",
        KnownKeyword::KbdInteractiveAuthentication,
        Provenance::S01,
    ),
    (
        "hostbasedkeytypes",
        KnownKeyword::HostbasedAcceptedAlgorithms,
        Provenance::S01,
    ),
    (
        "pubkeyacceptedkeytypes",
        KnownKeyword::PubkeyAcceptedAlgorithms,
        Provenance::Inferred,
    ),
    (
        "skeyauthentication",
        KnownKeyword::KbdInteractiveAuthentication,
        Provenance::Inferred,
    ),
    (
        "tisauthentication",
        KnownKeyword::KbdInteractiveAuthentication,
        Provenance::Inferred,
    ),
    (
        "dsaauthentication",
        KnownKeyword::PubkeyAuthentication,
        Provenance::Inferred,
    ),
    (
        "identityfile2",
        KnownKeyword::IdentityFile,
        Provenance::Inferred,
    ),
    (
        "keepalive",
        KnownKeyword::TcpKeepAlive,
        Provenance::Inferred,
    ),
    (
        "smartcarddevice",
        KnownKeyword::Pkcs11Provider,
        Provenance::Inferred,
    ),
];

/// What OpenSSH does with a keyword it no longer implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Obsolete {
    /// Ignored silently (`Protocol`).
    Ignored,
    /// Ignored with a "Deprecated option" debug message.
    Deprecated,
    /// Ignored with an "Unsupported option" error message; the file still loads.
    Unsupported,
}

/// Retired spellings OpenSSH still accepts and ignores, lowercase as in OpenSSH's
/// keyword table. All [`Provenance::Inferred`]: none is in the pinned manual.
pub const OBSOLETE: &[(&str, Obsolete)] = &[
    ("protocol", Obsolete::Ignored),
    ("cipher", Obsolete::Deprecated),
    ("fallbacktorsh", Obsolete::Deprecated),
    ("globalknownhostsfile2", Obsolete::Deprecated),
    ("rhostsauthentication", Obsolete::Deprecated),
    ("userknownhostsfile2", Obsolete::Deprecated),
    ("useroaming", Obsolete::Deprecated),
    ("usersh", Obsolete::Deprecated),
    ("useprivilegedport", Obsolete::Deprecated),
    ("afstokenpassing", Obsolete::Unsupported),
    ("kerberosauthentication", Obsolete::Unsupported),
    ("kerberostgtpassing", Obsolete::Unsupported),
    ("rsaauthentication", Obsolete::Unsupported),
    ("rhostsrsaauthentication", Obsolete::Unsupported),
    ("compressionlevel", Obsolete::Unsupported),
];

/// Whether `spelling` (a [`Keyword::Unknown`]) is a retired keyword OpenSSH ignores
/// rather than refuses (`[I]`; module documentation). `None` for anything else: an
/// unknown keyword not covered by `IgnoreUnknown` makes ssh refuse the file.
#[must_use]
pub fn obsolete(spelling: &str) -> Option<Obsolete> {
    OBSOLETE
        .iter()
        .find(|(s, _)| s.eq_ignore_ascii_case(spelling))
        .map(|(_, o)| *o)
}

/// How occurrences of `keyword` combine (F1–F4, F7).
///
/// * [`DirectiveClass::Accumulates`]: the S01 entries that say occurrences add up:
///   `IdentityFile` and `CertificateFile` ("Multiple … directives will add to the
///   list", F2), `LocalForward`, `RemoteForward` and `DynamicForward` ("Multiple
///   forwardings may be specified"), and `SendEnv` ("spread across multiple SendEnv
///   directives"). A list given on one line (`PermitRemoteOpen`, `CanonicalDomains`,
///   `UserKnownHostsFile` …) is still first-wins.
/// * [`DirectiveClass::Section`]: `Host`, `Match`.
/// * [`DirectiveClass::Include`]: `Include` (F3).
/// * [`DirectiveClass::Executes`]: the local commands of F4, `ProxyCommand`,
///   `KnownHostsCommand` and `LocalCommand`. `Match exec` is a criterion of the
///   `Match` section, and `RemoteCommand` runs on the server, not here.
/// * [`DirectiveClass::FirstWins`]: everything else (F1, "unless noted otherwise").
///   That includes `IgnoreUnknown`, whose value in force also decides how later
///   unknown keywords are treated, `SetEnv` (S01 notes no accumulation), and
///   `ProxyJump`, which competes with `ProxyCommand` (F10).
///
/// No keyword at the S01 pin is [`DirectiveClass::Other`].
#[must_use]
pub fn class(keyword: KnownKeyword) -> DirectiveClass {
    use KnownKeyword as K;
    match keyword {
        K::Host | K::Match => DirectiveClass::Section,
        K::Include => DirectiveClass::Include,
        K::ProxyCommand | K::KnownHostsCommand | K::LocalCommand => DirectiveClass::Executes,
        K::IdentityFile
        | K::CertificateFile
        | K::LocalForward
        | K::RemoteForward
        | K::DynamicForward
        | K::SendEnv => DirectiveClass::Accumulates,
        K::AddKeysToAgent
        | K::AddressFamily
        | K::BatchMode
        | K::BindAddress
        | K::BindInterface
        | K::CanonicalDomains
        | K::CanonicalizeFallbackLocal
        | K::CanonicalizeHostname
        | K::CanonicalizeMaxDots
        | K::CanonicalizePermittedCnames
        | K::CaSignatureAlgorithms
        | K::ChannelTimeout
        | K::CheckHostIp
        | K::Ciphers
        | K::ClearAllForwardings
        | K::Compression
        | K::ConnectionAttempts
        | K::ConnectTimeout
        | K::ControlMaster
        | K::ControlPath
        | K::ControlPersist
        | K::EnableEscapeCommandline
        | K::EnableSshKeysign
        | K::EscapeChar
        | K::ExitOnForwardFailure
        | K::FingerprintHash
        | K::ForkAfterAuthentication
        | K::ForwardAgent
        | K::ForwardX11
        | K::ForwardX11Timeout
        | K::ForwardX11Trusted
        | K::GatewayPorts
        | K::GlobalKnownHostsFile
        | K::GssapiAuthentication
        | K::GssapiDelegateCredentials
        | K::HashKnownHosts
        | K::HostbasedAcceptedAlgorithms
        | K::HostbasedAuthentication
        | K::HostKeyAlgorithms
        | K::HostKeyAlias
        | K::Hostname
        | K::IdentitiesOnly
        | K::IdentityAgent
        | K::IgnoreUnknown
        | K::IpQos
        | K::KbdInteractiveAuthentication
        | K::KbdInteractiveDevices
        | K::KexAlgorithms
        | K::LogLevel
        | K::LogVerbose
        | K::Macs
        | K::NoHostAuthenticationForLocalhost
        | K::NumberOfPasswordPrompts
        | K::ObscureKeystrokeTiming
        | K::PasswordAuthentication
        | K::PermitLocalCommand
        | K::PermitRemoteOpen
        | K::Pkcs11Provider
        | K::Port
        | K::PreferredAuthentications
        | K::ProxyJump
        | K::ProxyUseFdpass
        | K::PubkeyAcceptedAlgorithms
        | K::PubkeyAuthentication
        | K::RefuseConnection
        | K::RekeyLimit
        | K::RemoteCommand
        | K::RequestTty
        | K::RequiredRsaSize
        | K::RevokedHostKeys
        | K::SecurityKeyProvider
        | K::ServerAliveCountMax
        | K::ServerAliveInterval
        | K::SessionType
        | K::SetEnv
        | K::StdinNull
        | K::StreamLocalBindMask
        | K::StreamLocalBindUnlink
        | K::StrictHostKeyChecking
        | K::SyslogFacility
        | K::TcpKeepAlive
        | K::Tag
        | K::Tunnel
        | K::TunnelDevice
        | K::UpdateHostKeys
        | K::User
        | K::UserKnownHostsFile
        | K::VerifyHostKeyDns
        | K::VersionAddendum
        | K::VisualHostKey
        | K::WarnWeakCrypto
        | K::XauthLocation => DirectiveClass::FirstWins,
    }
}

/// Whether the parser keeps the raw rest of the line (`parse::Directive::raw`) for this
/// keyword: the four whose text OpenSSH stores as written and hands to a shell,
/// `ProxyCommand`, `LocalCommand`, `RemoteCommand` and `KnownHostsCommand`
/// (ADR-0007 §12.15 item 2). `RemoteCommand` runs on the server, so [`class`] does not
/// call it [`DirectiveClass::Executes`], but its quoting changes the command all the
/// same.
#[must_use]
pub fn keeps_raw(keyword: KnownKeyword) -> bool {
    matches!(
        keyword,
        KnownKeyword::ProxyCommand
            | KnownKeyword::LocalCommand
            | KnownKeyword::RemoteCommand
            | KnownKeyword::KnownHostsCommand
    )
}

/// Every `%` token letter of S01's TOKENS section (`%%` aside).
pub const ALL_TOKENS: &[char] = &[
    'C', 'd', 'f', 'H', 'h', 'I', 'i', 'j', 'K', 'k', 'L', 'l', 'n', 'p', 'r', 'T', 't', 'u',
];

/// The common token set S01 gives CertificateFile, ControlPath, IdentityAgent,
/// IdentityFile, Include, KnownHostsCommand, LocalForward, `Match exec`,
/// RemoteCommand, RemoteForward, RevokedHostKeys, UserKnownHostsFile and
/// VersionAddendum: `%C %d %h %i %j %k %L %l %n %p %r %u` (and `%%`).
pub const COMMON_TOKENS: &[char] = &['C', 'd', 'h', 'i', 'j', 'k', 'L', 'l', 'n', 'p', 'r', 'u'];

/// The `%` token letters OpenSSH accepts in `keyword`'s arguments (`%%`, a literal
/// `%`, is accepted wherever any token is and is not listed). Empty when the keyword
/// expands no tokens. From S01's TOKENS section, plus the `User` entry ("with the
/// exception of %r and %C") and the `SetEnv` entry (the TOKENS section without a
/// narrower list, so [`COMMON_TOKENS`]). For `Match` it is the `exec` criterion's set.
#[must_use]
pub fn tokens(keyword: KnownKeyword) -> &'static [char] {
    use KnownKeyword as K;
    match keyword {
        K::CertificateFile
        | K::ControlPath
        | K::IdentityAgent
        | K::IdentityFile
        | K::Include
        | K::LocalForward
        | K::Match
        | K::RemoteCommand
        | K::RemoteForward
        | K::RevokedHostKeys
        | K::UserKnownHostsFile
        | K::VersionAddendum
        | K::SetEnv => COMMON_TOKENS,
        K::KnownHostsCommand => &[
            'C', 'd', 'f', 'H', 'h', 'I', 'i', 'j', 'K', 'k', 'L', 'l', 'n', 'p', 'r', 't', 'u',
        ],
        K::Hostname => &['h'],
        K::LocalCommand => ALL_TOKENS,
        K::ProxyCommand | K::ProxyJump => &['h', 'n', 'p', 'r'],
        K::User => &['d', 'h', 'i', 'j', 'k', 'L', 'l', 'n', 'p', 'u'],
        _ => &[],
    }
}

/// Whether OpenSSH expands `%` tokens in this directive's arguments: S01's TOKENS
/// section (for `Match`, only the `exec` criterion's argument), plus the `User` and
/// `SetEnv` entries, which say so themselves. Exactly the keywords whose [`tokens`] set
/// is non-empty.
#[must_use]
pub fn expands_tokens(keyword: KnownKeyword) -> bool {
    !tokens(keyword).is_empty()
}

/// Whether OpenSSH expands `${VAR}` in this directive's arguments (F7).
///
/// F7 quotes S01's ENVIRONMENT VARIABLES section: CertificateFile, ControlPath,
/// IdentityAgent, IdentityFile, Include, KnownHostsCommand and UserKnownHostsFile.
/// The same section adds LocalForward and RemoteForward, for Unix-domain socket paths
/// only (the caller checks that the argument is one). The S01 entries of `User`,
/// `SetEnv` and `RevokedHostKeys` also say that they accept environment variables, so
/// they are included (the pinned text wins over F7's shorter quotation). An older
/// client may expand fewer and take `${…}` literally there; that difference is
/// per client version and the U3 corpus comparison settles it.
#[must_use]
pub fn expands_env(keyword: KnownKeyword) -> bool {
    use KnownKeyword as K;
    matches!(
        keyword,
        K::CertificateFile
            | K::ControlPath
            | K::IdentityAgent
            | K::IdentityFile
            | K::Include
            | K::KnownHostsCommand
            | K::UserKnownHostsFile
            | K::LocalForward
            | K::RemoteForward
            | K::User
            | K::SetEnv
            | K::RevokedHostKeys
    )
}
