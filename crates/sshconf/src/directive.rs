//! The directive table (m02-plan U1; ADR-0007 F1–F4, F7).
//!
//! [`KnownKeyword`] lists every keyword of ssh_config(5) at the S01 pin
//! (`docs/sources/pins.json`, snapshot `docs/sources/snapshots/S01.txt.gz`; the list
//! was checked against that snapshot when the skeleton was written). Spelling is
//! case-insensitive, as in OpenSSH. A deprecated alias OpenSSH still accepts is U1's
//! to map; anything else is [`Keyword::Unknown`].

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

    /// The keyword for a spelling, compared case-insensitively as OpenSSH does.
    #[must_use]
    pub fn parse(spelling: &str) -> Option<KnownKeyword> {
        Self::ALL
            .iter()
            .copied()
            .find(|k| k.as_str().eq_ignore_ascii_case(spelling))
    }
}

/// How occurrences of `keyword` combine (F1–F4, F7).
#[must_use]
pub fn class(keyword: KnownKeyword) -> DirectiveClass {
    let _ = keyword;
    todo!("M02-U1 directive::class")
}

/// Whether OpenSSH expands `%` tokens in this directive's arguments.
#[must_use]
pub fn expands_tokens(keyword: KnownKeyword) -> bool {
    let _ = keyword;
    todo!("M02-U1 directive::expands_tokens")
}

/// Whether OpenSSH expands `${VAR}` in this directive's arguments (F7).
#[must_use]
pub fn expands_env(keyword: KnownKeyword) -> bool {
    let _ = keyword;
    todo!("M02-U1 directive::expands_env")
}
