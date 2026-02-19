# Heimdall Implementation Plan

Status key: `todo` | `in_progress` | `done`

## Batch 1 Scope (Completed)
- Implement Section 1 (scaffolding + build/lint/CI + dependency/version enforcement tests)
- Implement Section 2 (`internal/crypto`) with TDD-first 18 tests
- Implement Section 4 (`internal/config`, `internal/log`) with TDD-first test suite
- Validate each section with `go test -race ./...` and `go vet ./...`

## Section 1 — Project Scaffolding
- [x] `done` Create `go.mod` and module path, then pin Section 1 dependency set via `internal/tools/tools.go`
- [x] `done` Create baseline directory structure from plan
- [x] `done` Add initial CLI entrypoint with version metadata surface
- [x] `done` Add Makefile targets: `build`, `build-nofido2`, `test`, `lint`, `generate`, `completions`, `man`
- [x] `done` Add CI workflow matrix for macOS arm64 + Linux amd64
- [x] `done` Add `.golangci.yml`
- [x] `done` Add Section 1 tests first (build tags, vet, dependency boundaries, ldflags version embedding)
- [x] `done` Implement missing code to satisfy Section 1 tests
- [x] `done` Validate (`go test -race ./...`, `go vet ./...`)

## Section 2 — Crypto Module (`internal/crypto`)
- [x] `done` Add 18 tests first (KATs, round-trips, auth failures, nonce uniqueness, parameter validation, zeroization)
- [x] `done` Implement `argon2.go`
- [x] `done` Implement `hkdf.go`
- [x] `done` Implement `aead.go`
- [x] `done` Implement `vault_crypto.go`
- [x] `done` Validate (`go test -race ./...`, `go vet ./...`)

## Section 4 — Config & Logging (`internal/config`, `internal/log`)
- [x] `done` Add Section 4 tests first (precedence, TOML parse, validation, policy overrides, redaction, rotation)
- [x] `done` Implement config loading with precedence + policy override (`HEIMDALL_POLICY_FILE` support)
- [x] `done` Implement `slog` redaction handler with sensitive key masking
- [x] `done` Implement lumberjack log rotation defaults (10 MiB, 5 files)
- [x] `done` Validate (`go test -race ./...`, `go vet ./...`)

## Batch 1 Finalization
- [x] `done` Ensure `PLAN.md` reflects completed status
- [x] `done` Push commits to `origin/main`
- [x] `done` Final report: changed files, commands run, validation, risks/TODOs

## Batch 2 Scope (Sections 3, 9)
- Implement Section 3 (`internal/storage`) with TDD-first 18 tests
- Implement Section 9 (`internal/fido2`) with TDD-first 15 tests
- Build order: Section 3 fully complete before Section 9
- Validate each section with `go test -race ./...` and `go vet ./...`

## Section 3 — Storage Layer (`internal/storage`)
- [x] `done` Add 18 tests first (migrations, rollback protection, CRUD, WAL, concurrency, timestamps, env_refs)
- [x] `done` Implement SQLite schema (11 tables) + embedded migrations + version checks
- [x] `done` Implement repository interfaces: Host, Identity, Secret, Passkey, Audit, Session, Template (+ pending ops)
- [x] `done` Inject `*crypto.VaultCrypto` into repositories and implement field-level encryption for sensitive fields
- [x] `done` Configure SQLite pragmas (`journal_mode=WAL`, `foreign_keys=ON`, `busy_timeout=5000`, `wal_autocheckpoint=0`)
- [x] `done` Implement rollback protection helpers (pre-unlock version file check + post-unlock HMAC verification)
- [x] `done` Validate (`go test -race ./...`, `go vet ./...`)

## Section 9 — FIDO2 Integration (`internal/fido2`)
- [x] `done` Add 15 tests first (nofido2 behavior, mock authenticator, enrollment/unlock/reauth flows)
- [x] `done` Implement `Authenticator` interface and shared types
- [x] `done` Implement `fido2` cgo wrapper (`//go:build fido2`) using libfido2
- [x] `done` Implement `nofido2` stub (`//go:build nofido2`) returning exit code 6 behavior
- [x] `done` Implement enrollment/unlock/reauth flows using storage passkey persistence
- [x] `done` Validate (`go test -race ./...`, `go vet ./...`)

## Batch 3 Scope (Sections 12, 5, 7)
- Implement Section 12 (`internal/audit`) with TDD-first hash-chain + verification flow
- Implement Section 5 (`internal/daemon`) with lifecycle management, socket/info handling, and timers
- Implement Section 7 (`internal/app`) with Host/Secret/Key/Connect (Plan-only) services
- Build order: Section 12 fully complete before Section 5, then Section 7
- Validate each section with `go test -race ./...` and `go vet ./...`

## Section 12 — Audit & History (`internal/audit`)
- [x] `done` Add Section 12 tests first (hash chain integrity/tamper detection/canonical JSON/concurrency/filtering)
- [x] `done` Extend storage audit persistence for chain fields and filterable event model
- [x] `done` Implement audit service `Record`, `Verify`, `List` with mutex serialization and canonical JSON
- [x] `done` Validate (`go test -race ./...`, `go vet ./...`)

## Section 5 — Daemon Process (`internal/daemon`)
- [x] `done` Add Section 5 tests first (socket perms, daemon.info lifecycle, stale detection, signals, timers)
- [x] `done` Implement daemon lifecycle (start/stop/lock), socket runtime paths, daemon.info JSON management
- [x] `done` Implement signal handling, auto-lock timer reset, max-session signing cutoff semantics
- [x] `done` Implement client-side `EnsureDaemon` auto-start and readiness checks
- [x] `done` Validate (`go test -race ./...`, `go vet ./...`)

## Section 7 — Application Services (`internal/app`)
- [x] `done` Add Section 7 tests first (host validation/list filters, secret encrypt/decrypt policy, key operations, connect plan)
- [x] `done` Implement `HostService` CRUD/list/import path
- [x] `done` Implement `SecretService` create/get-value with reveal policy enforcement (no InjectEnv in daemon)
- [x] `done` Implement `KeyService` generate/import/export/rotate behavior
- [x] `done` Implement `ConnectService.Plan` only (no Execute)
- [x] `done` Validate (`go test -race ./...`, `go vet ./...`)

## Batch 3 Finalization
- [x] `done` Keep `PLAN.md` updated during implementation
- [x] `done` Validate full repo after each section (`go test -race ./...`, `go vet ./...`)
- [x] `done` Commit and push logical units on `main`

## Batch 4 Scope (Sections 6, 8, 10)
- Implement Section 6 (`api/v1`, `internal/grpc`) with TDD-first gRPC API + client package
- Implement Section 8 (`internal/ssh`) with TDD-first command builder, binary checks, known_hosts, executor
- Implement Section 10 (`internal/agent`) with TDD-first SSH agent server + daemon signing constraints
- Build order: Section 6 first, then Section 8, then Section 10
- Validate each section with `go test -race ./...` and `go vet ./...`

## Section 6 — gRPC API (`api/v1`, `internal/grpc`)
- [x] `done` Add proto definitions for all required services and RPCs (no `ConnectService.Execute`)
- [x] `done` Generate Go stubs with `protoc` + go plugins
- [x] `done` Implement gRPC server registration + service handlers
- [x] `done` Implement unary interceptors (auth tiers, audit hook, per-tier PID rate limit)
- [x] `done` Implement re-auth cache (PID+start-time key, TTL, lock-clear)
- [x] `done` Implement error model helpers (`google.rpc.ErrorInfo` with required metadata)
- [x] `done` Implement streaming file secret RPCs (upload/download chunking)
- [x] `done` Implement client wrapper with typed service clients
- [x] `done` Add Section 6 tests first, then satisfy all tests
- [x] `done` Validate (`go test -race ./...`, `go vet ./...`)

## Section 8 — SSH Integration (`internal/ssh`)
- [x] `done` Add Section 8 tests first for builder/known_hosts/executor/binary checks/validation
- [x] `done` Implement SSH binary detection + ProxyJump version support checks
- [x] `done` Implement command builder (`SSHCommand`) including identity, jump, forwards, known_hosts policy
- [x] `done` Implement forward spec parser/validator with strict address and port checks
- [x] `done` Implement known_hosts manager (trust/check/file path behavior)
- [x] `done` Implement process executor (signal relay, exit code propagation, cleanup, zombie prevention)
- [x] `done` Validate (`go test -race ./...`, `go vet ./...`)

## Section 10 — SSH Agent (`internal/agent`)
- [x] `done` Add Section 10 tests first for agent protocol, TTL expiry, lock behavior, external fallback
- [x] `done` Implement `agent.Agent` compatible server with socket lifecycle and 0600 permissions
- [x] `done` Implement key add/remove/remove-all/sign/list flows with TTL eviction
- [x] `done` Enforce daemon lock/session semantics (`IsLocked`, `CanSign`) without killing sessions
- [x] `done` Implement external `ssh-add` fallback via secure temp file + immediate cleanup
- [x] `done` Integrate daemon agent socket path `${RUNTIME_DIR}/heimdall/agent.sock`
- [x] `done` Validate (`go test -race ./...`, `go vet ./...`)

## Batch 4 Finalization
- [x] `done` Keep `PLAN.md` updated as each subsection completes
- [x] `done` Commit and push logical units on `main`
- [ ] `todo` Final report with changed files, commands, validation, risks/TODOs

## Batch 5 Scope (Sections 11, 14, 13 + final gRPC expansion)
- Extend Section 6 surface first: fill proto service gaps and implement daemon gRPC handlers for all missing RPCs.
- Implement Section 11 CLI command tree as thin gRPC wrappers (daemonless exceptions only).
- Implement Section 14 import/export/backup flows (JSON metadata import/export + encrypted backup create/restore).
- Implement Section 13 TUI core screens with Bubble Tea MVU (`lock`, `hosts`, `secrets`, `keys`).
- Implement debug diagnostics bundle (`internal/debug`) with sanitized output.
- Validate at each subsection boundary (`go test -race ./...`, `go vet ./...`).

## Batch 5 Live Checklist
- [ ] `todo` Proto: extend `api/v1/heimdall.proto` with missing RPCs/messages
- [ ] `todo` Proto: regenerate stubs (`protoc --go_out=. ... api/v1/heimdall.proto`)
- [ ] `todo` gRPC server: implement all new RPC handlers and wire dependencies cleanly
- [ ] `todo` CLI: add global flags + exit code model + root plumbing
- [ ] `todo` CLI: implement `status`, `doctor`, `vault`, `host`, `secret`, `key`, `passkey`, `connect`
- [ ] `todo` CLI: implement `backup`, `audit`, `import`, `export`, `debug bundle`
- [ ] `todo` App/Backup: implement WAL checkpointed encrypted backup create/restore with manifest checksums
- [ ] `todo` App/ImportExport: add JSON export/import metadata flow and extend SSH import if needed
- [ ] `todo` TUI: implement practical Bubble Tea screens and command entry point
- [ ] `todo` Tests: add/update table-driven tests for new RPCs + CLI/TUI/import/export/backup/debug paths
- [ ] `todo` Validate full gate (`go test -race ./...` then `go vet ./...`)

## Batch 5 Progress Log
- [x] `done` Context prime complete: AGENTS + sections 11/13/14 (plan + TDD) reviewed.
- [x] `done` Gap audit complete: proto/server/cli/tui/debug/import-export-backup baseline mapped.
- [ ] `in_progress` Implementing Batch 5 in build order (proto/server -> CLI -> section 14 -> section 13 -> debug -> full validation).
