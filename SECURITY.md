# Security Policy

## Boundary

Heimdall is non-custodial. It never stores, copies, imports, encrypts, decrypts, parses, or reads private key contents. It never stores passphrases, OAuth tokens, agent protocol secrets, or refresh-hook tokens.

OpenSSH remains the SSH client and configuration authority. Heimdall owns only its generated fragment.

## Supported Security Reports

Please report:

- private-key content read paths;
- secret logging or redaction bypasses;
- unsafe config mutation or rollback failures;
- ambient `SSH_AUTH_SOCK` fallback;
- active probes that run without consent;
- shell injection or ProxyCommand risk expansion;
- broad bridge/socket permissions;
- docs that overstate the security model.

## Out of Scope

Same-user malware, root/admin compromise, malicious OpenSSH binaries, compromised agent providers, compromised remotes after agent forwarding, and compromised external transport binaries are outside Heimdall's security boundary.

## Reporting

Open a private security advisory on the repository once GitHub security advisories are enabled. Until then, contact the maintainer directly.

