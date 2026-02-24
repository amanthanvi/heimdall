# SPEC Drift Notes (Reconciled)

This file captures high-impact mismatches that were corrected in `SPEC.md`.

## Corrected mismatches

1. **Version/runtime mismatch**
   - Was: v0.1.0 framing + Go >=1.22
   - Now: v0.2.0 framing + Go 1.26

2. **Command surface mismatch**
   - Was: legacy aliases (`host ls`, `key gen`, `secret rm`, etc.)
   - Now: canonical command names (`list/remove/generate`) and current top-level tree including `tui`/`ui`

3. **SSH config behavior mismatch**
   - Was: blanket “must not modify ~/.ssh/config”
   - Now: default is no modification; explicit `ssh-config enable/disable` manages Include directive

4. **Key import capability mismatch**
   - Was: PEM/PKCS#8 unsupported
   - Now: private key imports support OpenSSH + PEM/PKCS#8 parse paths

5. **Daemon metadata mismatch**
   - Was: `daemon.pid` process model
   - Now: `daemon.info` JSON process metadata model

6. **Config schema mismatch**
   - Was: no `[ssh_config]` or `[audit]` sections
   - Now: includes managed ssh-config and audit connection logging config

7. **Backup semantics mismatch**
   - Was: stale `--unencrypted` references
   - Now: documents current encrypted backup flow + restore overwrite re-auth behavior

8. **Audit semantics mismatch**
   - Was: host trust-centric events
   - Now: includes SSH connection start/end metadata events

## Remaining caveat

- `SPEC.md` still contains historical sections for traceability; when any detail conflicts, the “Current Truth Overrides (v0.2.0)” block is authoritative.
