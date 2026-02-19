# Security Policy

## Reporting a Vulnerability

Report suspected vulnerabilities privately by emailing:

- amanthanvi2002@gmail.com

Please include:

- Affected version or commit SHA
- Reproduction steps / proof-of-concept
- Impact assessment and any suggested remediation

## Disclosure Process

- Initial acknowledgement target: within 72 hours
- Triage and severity assessment target: within 7 days
- Fix timeline: based on severity and exploitability
- Public disclosure: coordinated after a patch or mitigation is available

## Supported Versions

| Version | Supported |
| --- | --- |
| v0.1.x | Yes |
| < v0.1.0 | No |

## Scope

This policy applies to:

- CLI command execution and validation paths
- Daemon and gRPC interfaces
- Vault cryptography and key/secret handling
- Import/export/backup/restore paths

Out-of-scope:

- Local misconfiguration without a security boundary bypass
- Denial-of-service from unsupported runtime environments
