# Validation Log — v0.2.0 Reconciliation

## Commands run (this run)

```bash
go run ./cmd/heimdall --help
go run ./cmd/heimdall completion zsh
go run ./cmd/heimdall __complete host show ""
go run ./cmd/heimdall host add --help
go run ./cmd/heimdall key --help
go run ./cmd/heimdall secret --help
go run ./cmd/heimdall completion install --help
go run ./cmd/heimdall ssh-config --help
go run ./cmd/heimdall status --help
go run ./cmd/heimdall key agent --help
go run ./cmd/heimdall secret add --help
go run ./cmd/heimdall key import --help
go run ./cmd/heimdall backup create --help
go run ./cmd/heimdall backup restore --help
go run ./cmd/heimdall audit list --help
go test -race ./internal/cli -run 'TestRootHasBatchFiveTopLevelCommands|TestRootIncludesUIAliasForTUI|TestCompletionGenerationBashZshFish|TestCompletionInstallWritesScript|TestCompletionDirectiveSummaryGoesToStderr'
go test -race ./internal/tui
go test -race ./internal/cli
go build ./...
go vet ./...
go test -race ./...
golangci-lint run ./...
go test -tags=integration -race ./internal/integration -count=1
go test -run='^$' -bench='Benchmark(VaultOpenCold|CLIRoundTrip|KeyDerivation)$' -benchmem ./internal/crypto ./internal/cli
```

## GitHub release visibility checks

```bash
gh auth status
gh release list --repo amanthanvi/heimdall --limit 100
git tag --sort=version:refname
tags_to_delete=$(git tag | grep -v '^v0.2.0$' || true)
for tag in $tags_to_delete; do gh release delete "$tag" --repo amanthanvi/heimdall --yes; done
for tag in $tags_to_delete; do git tag -d "$tag"; git push origin ":refs/tags/$tag"; done
gh release list --repo amanthanvi/heimdall --limit 200
git tag --sort=version:refname
```

## Result snapshot

- `go build ./...`: pass
- `go vet ./...`: pass
- `go test -race ./...`: pass
- `golangci-lint run ./...`: pass (`0 issues`)
- `go test -tags=integration -race ./internal/integration -count=1`: pass
- benchmark suite command: pass
- release/tag prune verification:
  - `gh release list`: only `v0.2.0`
  - `git tag`: only `v0.2.0`

## Commands run (continuation)

```bash
make build
./dist/heimdall --help
./dist/heimdall ssh-config --help
./dist/heimdall tui --help
./dist/heimdall completion zsh | rg -n "(^:|:0|:4|ShellCompDirective)" || true
./dist/heimdall host add --help
./dist/heimdall key generate --help
./dist/heimdall secret add --help
./dist/heimdall backup create --help
./dist/heimdall import --help
./dist/heimdall secret show --help
./dist/heimdall secret env --help
./dist/heimdall backup restore --help
./dist/heimdall export --help
./dist/heimdall key import --help
./dist/heimdall vault unlock --help
./dist/heimdall key export --help
# full isolated smoke run in /tmp/heimdall-smoke-p6JbUu (init/unlock/host/key/connect/secret/export/import/backup/restore/ssh-config/completion/status/doctor/lock/daemon stop)
./dist/heimdall audit list --help
rg -n "ActionConnect(Start|End)|connect\\.start|connection_logging|RecordConnect|audit.*connect" internal -g'*.go'
go test -race ./internal/cli -run 'TestConnectWithKeyRegistersSessionLifecycle|TestConnectWithoutKeyRecordsSessionLifecycle|TestConnectExecutionUsesCommandContextWithoutTimeout|TestConnectDryRunPrintsSSHCommand'
go test -race ./internal/cli
go build ./...
make build
# identity-mode connect audit verification against /tmp/heimdall-smoke-p6JbUu/src/*
```

## Continuation snapshot

- Added CLI regression coverage so identity-file connects record session lifecycle and emit connect audit events when `[audit].connection_logging=true`.
- Manual smoke run confirmed:
  - SSH key import/export round-trip works.
  - Host defaults for `--key` and `--identity-file` affect connect dry-run as expected.
  - Backup create/restore succeeds with restore unlock using source-vault passphrase.
  - Completion install output is clean (no leaked `:0` / `:4` directive tokens).
  - `connect.start` and `connect.end` now increase for identity-mode connect executions.

## Commands run (v0.2.1 patch prep)

```bash
go test -race ./internal/config -run 'TestDefaultConfigEnablesConnectionLogging|TestLoadConfigAppliesSSHConfigAndAuditEnvOverrides'
go test -race ./internal/cli -run 'TestStatusShowsAuditHintWhenConnectionLoggingDisabled|TestConnectWithoutKeyRecordsSessionLifecycle|TestConnectWithKeyRegistersSessionLifecycle|TestConnectExecutionUsesCommandContextWithoutTimeout'
make build
go test -race ./...
go vet ./...
golangci-lint run ./...
go test -tags=integration -race ./internal/integration -count=1
go test -run='^$' -bench='Benchmark(VaultOpenCold|CLIRoundTrip|KeyDerivation)$' -benchmem ./internal/crypto ./internal/cli
go install golang.org/x/vuln/cmd/govulncheck@latest
"$(go env GOPATH)/bin/govulncheck" ./...
make completions && make man
# audit-default smoke in isolated temp dir:
#   init writes connection_logging=true
#   connect --dry-run emits no connect audit events
#   non-dry-run connect emits connect.start/connect.end
```

## v0.2.1 patch prep snapshot

- `connection_logging` now defaults to `true` in runtime defaults and init-generated config.
- `status` now prints an explicit remediation hint if connection logging is disabled.
- `connect --dry-run` help text explicitly documents that dry-run does not emit connect audit events.
- Full gate passes (`build`, `vet`, `race`, `lint`, `integration`, `bench`, `govulncheck`, completions/man generation).
