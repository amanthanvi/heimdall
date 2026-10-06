#!/bin/bash
# X4 macOS: record facts about the candidate libraries (versions, API coverage, maintenance flags).
# Reads module/crate sources from the scratch caches populated by run.sh / go mod tidy / cargo fetch.
# Usage: bash library-survey.sh 2>&1 | sed -e "s#$SCR#<scratch>#g" -e "s#$HOME#<home>#g" > library-survey.log
set -u
SCR=/tmp/hm-r4/M00-T05-r4-x4-macos
echo "# X4 macOS library survey ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
echo "\$ curl https://proxy.golang.org/github.com/keybase/go-keychain/@v/list"
curl -sS https://proxy.golang.org/github.com/keybase/go-keychain/@v/list; echo "[exit=$?]"
echo "\$ curl https://proxy.golang.org/github.com/keybase/go-keychain/@latest"
curl -sS https://proxy.golang.org/github.com/keybase/go-keychain/@latest; echo
G=$SCR/gomod/github.com/keybase/go-keychain@v0.0.1
[ -d "$G" ] || (cd "$SCR/probe" && GOMODCACHE=$SCR/gomod GOFLAGS=-modcacherw go mod download github.com/keybase/go-keychain@v0.0.1)
echo "\$ ls go-keychain@v0.0.1"; ls "$G" | tr '\n' ' '; echo
echo "\$ grep -rn -i -E 'UseKeychain|MatchSearchList|SecKeychainOpen|SecKeychainCreate|UseDataProtectionKeychain|SecKeyCreate|TokenID' go-keychain@v0.0.1/*.go"
grep -rn -i -E 'UseKeychain|MatchSearchList|SecKeychainOpen|SecKeychainCreate|UseDataProtectionKeychain|SecKeyCreate|TokenID' "$G" --include='*.go'
echo "[grep exit=$? (1 = no match)]"
echo "\$ head -11 go-keychain@v0.0.1/macos.go"; head -11 "$G/macos.go"
echo "\$ curl https://proxy.golang.org/github.com/ebitengine/purego/@latest"
curl -sS https://proxy.golang.org/github.com/ebitengine/purego/@latest; echo
SF=$(echo "$SCR"/cargo-home/registry/src/*/security-framework-3.7.0)
echo "\$ security-framework 3.7.0 Cargo.toml [badges.maintenance]"; grep -A1 'badges.maintenance' "$SF/Cargo.toml"
echo "\$ security-framework 3.7.0 src/os/macos/passwords.rs:78-85 (SecKeychainItem::delete)"; sed -n 78,85p "$SF/src/os/macos/passwords.rs"
echo "\$ security-framework 3.7.0 src/key.rs (GenerateKeyOptions permanence)"; grep -n 'is_permanent = ' "$SF/src/key.rs"
echo "\$ crates.io index: newest published versions"
for c in se/cu/security-framework co/re/core-foundation; do
	curl -sS "https://index.crates.io/$c" | tail -1 | python3 -I -c "import json,sys; d=json.loads(sys.stdin.read()); print(d['name'], d['vers'], 'yanked' if d['yanked'] else 'not-yanked')"
done
