# Heimdall Batch 1 Plan (Sections 1, 2, 4)

Status key: `todo` | `in_progress` | `done`

## Scope
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

## Finalization
- [x] `done` Ensure `PLAN.md` reflects completed status
- [ ] `in_progress` Push commits to `origin/main`
- [ ] `todo` Final report: changed files, commands run, validation, risks/TODOs
