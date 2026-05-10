# Architecture

Heimdall is CLI-first and daemonless by default. Cobra commands and the Bubble Tea TUI call shared services:

- `internal/config`: strict YAML, validation, atomic writes.
- `internal/model`: persisted and runtime types.
- `internal/inventory`: public key, cert, and agent observation.
- `internal/openssh`: argv-based subprocess runner and generated fragment rendering.
- `internal/doctor`: evidence-based findings.
- `internal/launcher`: scoped child environments.
- `internal/platform`: Linux/macOS/Windows/WSL/container probes.
- `internal/bridge`: isolated session relay, permission checks, TTL cleanup.
- `internal/certs`: certificate inspection.
- `internal/transport`: external transport config helpers.
- `internal/redact`: display/log redaction.
- `internal/tui`: display only; no separate security logic.

OpenSSH remains authoritative for connection behavior. Heimdall renders transparent config and diagnoses the local control plane.
