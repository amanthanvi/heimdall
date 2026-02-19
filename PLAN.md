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
- [ ] `in_progress` Add 18 tests first (KATs, round-trips, auth failures, nonce uniqueness, parameter validation, zeroization)
- [ ] `todo` Implement `argon2.go`
- [ ] `todo` Implement `hkdf.go`
- [ ] `todo` Implement `aead.go`
- [ ] `todo` Implement `vault_crypto.go`
- [ ] `todo` Validate (`go test -race ./...`, `go vet ./...`) and commit

## Section 4 — Config & Logging (`internal/config`, `internal/log`)
- [ ] `todo` Add Section 4 tests first (precedence, TOML parse, validation, policy overrides, redaction, rotation)
- [ ] `todo` Implement config loading with precedence + policy override (`HEIMDALL_POLICY_FILE` support)
- [ ] `todo` Implement `slog` redaction handler with sensitive key masking
- [ ] `todo` Implement lumberjack log rotation defaults (10 MiB, 5 files)
- [ ] `todo` Validate (`go test -race ./...`, `go vet ./...`) and commit

## Finalization
- [ ] `todo` Ensure `PLAN.md` reflects completed status
- [ ] `todo` Push commits to `origin/main`
- [ ] `todo` Final report: changed files, commands run, validation, risks/TODOs
