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
