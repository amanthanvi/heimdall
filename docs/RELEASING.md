# Releasing Heimdall

This runbook is the source of truth for cutting a Heimdall release and publishing Homebrew updates.

## 1) Preflight validation

Run from the repo root:

```bash
go test -race ./...
go vet ./...
go test -tags=integration -race ./internal/integration -count=1
```

## 2) Prepare and push release commit/tag

```bash
git status --short
git add <files>
git commit -m "<message>"
git push origin main
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

## 3) Publish via GoReleaser (clean clone required)

If your working tree has local/untracked files, run release from a clean temp clone:

```bash
REL_DIR=$(mktemp -d /tmp/heimdall-release-XXXXXX)
git clone https://github.com/amanthanvi/heimdall.git "$REL_DIR"
cd "$REL_DIR"
git checkout vX.Y.Z
GITHUB_TOKEN="$(gh auth token)" goreleaser release --clean
```

Expected outcomes:
- GitHub release is published under `vX.Y.Z`.
- Release assets include `heimdall-<os>-<arch>.tar.gz`.
- Homebrew tap cask `Casks/heimdall.rb` is pushed automatically.

## 4) Verify GitHub release and tap

```bash
gh release view vX.Y.Z --repo amanthanvi/heimdall --json url,tagName,isDraft,isPrerelease,publishedAt,assets
gh api 'repos/amanthanvi/homebrew-tap/commits?path=Casks/heimdall.rb&per_page=1'
```

## 5) Verify Homebrew install/upgrade

```bash
BREW_TAP_DIR=$(brew --repo amanthanvi/tap)
cd "$BREW_TAP_DIR"
git pull --ff-only
HOMEBREW_NO_AUTO_UPDATE=1 brew upgrade --cask amanthanvi/tap/heimdall || HOMEBREW_NO_AUTO_UPDATE=1 brew install --cask amanthanvi/tap/heimdall
heimdall version
```

## 6) Smoke-check the released binary

```bash
WORK=$(mktemp -d /tmp/heimdall-brew-verify-XXXXXX)
export HEIMDALL_HOME="$WORK/home"
CFG="$WORK/config.toml"
VAULT="$WORK/vault.db"
printf 'dev-pass\n' | heimdall --config "$CFG" --vault "$VAULT" init --yes --passphrase-stdin
printf 'dev-pass\n' | heimdall --config "$CFG" --vault "$VAULT" vault unlock --passphrase-stdin
heimdall --config "$CFG" --vault "$VAULT" host list
heimdall --config "$CFG" --vault "$VAULT" completion install --shell zsh --path "$WORK/_heimdall" --verify --overwrite
```
