# Package Audit

This document records the current reboot disposition for the main runtime
packages.

Status values:

- `reuse`
- `reuse with boundary cleanup`
- `rewrite`
- `deferred`
- `removed`

| Package | Status | Notes |
| --- | --- | --- |
| `internal/crypto` | `reuse` | Core derivation, AEAD, HKDF, and wrapped-VMK handling are the security spine. |
| `internal/storage` | `reuse` | Encrypted storage, audit persistence, and the narrowed reboot schema are part of the trusted core. |
| `internal/audit` | `reuse` | Hash-chain logic and verification behavior fit the reboot directly. |
| `internal/daemon` | `reuse` | Local daemon lifecycle, socket handling, and `daemon.info` are part of the core runtime. |
| `internal/grpc` | `reuse with boundary cleanup` | Local transport is kept, but proto mappings and command semantics are being narrowed to the reboot surface. |
| `internal/app` | `rewrite` | This is the main behavior layer that drifted furthest from product truth and now carries the reboot contract. |
| `internal/cli` | `rewrite` | The public surface is being cut back to truthful commands and canonical host/connect behavior. |
| `internal/ssh` | `reuse` | `CommandBuilder` is the single renderer for SSH execution and should remain the source of truth. |
| `internal/agent` | `reuse` | Session-scoped signing and agent socket support remain part of managed-key connect flows. |
| `internal/fido2` | `reuse with boundary cleanup` | Keep the implementation as deferred infrastructure; the rebooted CLI no longer ships passkey enroll/unlock/test until end-to-end wiring exists. |
| `internal/config` | `reuse with boundary cleanup` | Config loading is retained; stale config sections for deferred features should be removed or ignored. |
| `internal/log` | `reuse` | Redaction and rotation behavior remain valid. |
| `internal/policy` | `reuse` | Small supporting package; no reboot-specific concern found so far. |
| `internal/version` | `reuse` | Simple build metadata surface. |
| `internal/buildcheck` | `reuse` | Useful guardrails for dependency boundaries. |
| `internal/integration` | `reuse with boundary cleanup` | Coverage remains valuable, but tests must follow the reboot surface only. |
| `internal/sshconfig` | `removed` | Deleted from the active tree; managed ssh-config is outside the reboot. |
| `internal/tui` | `removed` | Deleted from the active tree; CLI-first reboot does not ship a TUI. |
| `internal/debug` | `removed` | Deleted from the active tree; no reboot command depends on debug bundle helpers. |
| `internal/tools` | `reuse` | Tool pinning and generation support remain useful. |

## Current Audit Summary

- Verified reusable spine: `crypto`, `audit`, `daemon`, `ssh`, `agent`, `fido2`.
- Reboot focus: `app`, `cli`, proto contract, integration coverage.
- Deferred: public transfer workflows only.
