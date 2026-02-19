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
- [ ] `in_progress` Add 15 tests first (nofido2 behavior, mock authenticator, enrollment/unlock/reauth flows)
- [ ] `todo` Implement `Authenticator` interface and shared types
- [ ] `todo` Implement `fido2` cgo wrapper (`//go:build fido2`) using libfido2
- [ ] `todo` Implement `nofido2` stub (`//go:build nofido2`) returning exit code 6 behavior
- [ ] `todo` Implement enrollment/unlock/reauth flows using storage passkey persistence
- [ ] `todo` Validate (`go test -race ./...`, `go vet ./...`)
