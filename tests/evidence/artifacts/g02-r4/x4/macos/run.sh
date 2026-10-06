#!/bin/bash
# G02 round-4 X4 (macOS): native secure storage + Secure Enclave + ad-hoc bundle spike, Go vs Rust.
# Disposable material only: a file keychain created under the scratch dir and deleted afterwards,
# ephemeral (non-permanent) Secure Enclave keys, no login keychain, no data-protection writes,
# no network listeners. Secrets are generated inside the spike binaries and never printed.
# Usage: bash run.sh 2>&1 | sed -e "s#$SCR#<scratch>#g" -e "s#$HOME#<home>#g" > transcript.log
set -u
unset SSH_AUTH_SOCK
HERE=$(cd "$(dirname "$0")" && pwd)
SCR=/tmp/hm-r4/M00-T05-r4-x4-macos
OUT=$SCR/out
rm -rf "$OUT"; mkdir -p "$OUT"
export GOCACHE=$SCR/gocache GOMODCACHE=$SCR/gomod GOPATH=$SCR/gopath GOTOOLCHAIN=local GOFLAGS=
export CARGO_HOME=$SCR/cargo-home
S=/usr/bin/security
ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
run() { # run <label> <cmd...>: indented output, real exit code
	local label=$1; shift
	echo "$(ts) \$ $label"
	"$@" 2>&1 | sed 's/^/    /'
	local rc=${PIPESTATUS[0]}
	echo "$(ts) [$label] exit=$rc"
	return "$rc"
}
TO() { perl -e '$t = shift; alarm $t; exec @ARGV or die "exec: $!"' 60 "$@"; } # 60 s guard against UI prompts
dig() { shasum -a 256 | cut -c1-16; }
size() { stat -f %z "$1"; }

echo "== 0. environment"
echo "$(ts) macOS $(sw_vers -productVersion) ($(sw_vers -buildVersion)) arch=$(uname -m) cpu=$(sysctl -n machdep.cpu.brand_string)"
echo "$(ts) $(go version) | $(rustc --version) | $(cargo --version) | SDK $(xcrun --show-sdk-version) | $(clang --version | head -1)"
L0=$($S list-keychains -d user | dig); D0=$($S default-keychain -d user | dig)
echo "$(ts) user keychain search list digest=$L0 default keychain digest=$D0 (contents not printed)"

echo "== 1. builds"
cd "$HERE/go" || exit 1
run "go build (cgo, default flags)" go build -trimpath -o "$OUT/hm-x4-go" .
run "go build (cgo, -ldflags=-s -w)" go build -trimpath -ldflags='-s -w' -o "$OUT/hm-x4-go.stripped" .
run "go build baseline hello" go build -trimpath -o "$OUT/hello-go" ./baseline-hello
run "go build baseline hello (-s -w)" go build -trimpath -ldflags='-s -w' -o "$OUT/hello-go.stripped" ./baseline-hello
run "go vet" go vet ./...
run "gofmt -l (empty = formatted)" gofmt -l .
run "go list cgo files" go list -f '{{.ImportPath}} CgoFiles={{.CgoFiles}}' ./...
run "go version -m (build settings)" sh -c "go version -m '$OUT/hm-x4-go' | grep -E 'CGO_ENABLED|GOOS|GOARCH|-trimpath'"
cd "$HERE/go-purego" || exit 1
run "go-purego build (CGO_ENABLED=0, default flags)" env CGO_ENABLED=0 go build -trimpath -o "$OUT/hm-x4-go-purego" .
run "go-purego build (CGO_ENABLED=0, -ldflags=-s -w)" env CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$OUT/hm-x4-go-purego.stripped" .
run "go-purego vet (CGO_ENABLED=0)" env CGO_ENABLED=0 go vet ./...
run "go-purego gofmt -l" gofmt -l .
run "go-purego go version -m" sh -c "go version -m '$OUT/hm-x4-go-purego' | grep -E 'dep|CGO_ENABLED|GOOS|GOARCH'"
cd "$HERE/rust" || exit 1
run "cargo build --release --locked" env CARGO_TARGET_DIR=$SCR/rust-target cargo build --release --locked
cp "$SCR/rust-target/release/hm-x4-rust" "$OUT/hm-x4-rust"
run "cargo build --release --locked (strip=symbols)" env CARGO_TARGET_DIR=$SCR/rust-target-strip CARGO_PROFILE_RELEASE_STRIP=symbols cargo build --release --locked
cp "$SCR/rust-target-strip/release/hm-x4-rust" "$OUT/hm-x4-rust.stripped"
run "cargo clippy --release --locked -D warnings" env CARGO_TARGET_DIR=$SCR/rust-target cargo clippy --release --locked -- -D warnings
run "cargo fmt --check" cargo fmt --check
run "cargo tree" env CARGO_TARGET_DIR=$SCR/rust-target cargo tree --locked -e normal
cd "$HERE/rust/baseline-hello" || exit 1
run "cargo build baseline hello" env CARGO_TARGET_DIR=$SCR/rust-hello-target cargo build --release --locked
cp "$SCR/rust-hello-target/release/hm-x4-rust-hello" "$OUT/hello-rust"
run "cargo build baseline hello (strip=symbols)" env CARGO_TARGET_DIR=$SCR/rust-hello-target-strip CARGO_PROFILE_RELEASE_STRIP=symbols cargo build --release --locked
cp "$SCR/rust-hello-target-strip/release/hm-x4-rust-hello" "$OUT/hello-rust.stripped"
cd "$HERE" || exit 1
for f in hm-x4-go hm-x4-go.stripped hm-x4-go-purego hm-x4-go-purego.stripped hello-go hello-go.stripped hm-x4-rust hm-x4-rust.stripped hello-rust hello-rust.stripped; do
	echo "$(ts) size $f bytes=$(size "$OUT/$f")"
done
for f in hm-x4-go hm-x4-go-purego hello-go hm-x4-rust hello-rust; do
	run "otool -L $f" sh -c "otool -L '$OUT/$f' | tail -n +2 | sed 's/ (compatibility.*//'"
	run "codesign -dv $f (signature as built)" sh -c "codesign -dv '$OUT/$f' 2>&1 | grep -E '^(Signature|CodeDirectory|TeamIdentifier)'"
done

echo "== 2. file keychain round trip (disposable keychain per run)"
kc_run() { # kc_run <label> <binary>
	local d kc pw rc
	d=$(mktemp -d "$SCR/kc.XXXXXX"); kc="$d/hm-x4.keychain-db"
	pw=$(od -An -tx1 -N24 /dev/urandom | tr -d ' \n')
	printf 'create-keychain -p %s %s\n' "$pw" "$kc" | $S -i >/dev/null 2>&1; rc=$?
	echo "$(ts) [$1] create-keychain (security -i, password via stdin) exit=$rc file_exists=$([ -e "$kc" ] && echo yes || echo no)"
	pw=""
	$S set-keychain-settings "$kc"; rc=$?; echo "$(ts) [$1] set-keychain-settings (no auto-lock) exit=$rc"
	echo "$(ts) [$1] keychain in user search list=$($S list-keychains -d user | grep -c "$d")"
	run "$1 keychain <disposable>" TO "$2" keychain "$kc"
	$S find-generic-password -s hm-x4-svc -a hm-x4-acct "$kc" >/dev/null 2>&1; rc=$?
	echo "$(ts) [$1] independent check: security find-generic-password after spike exit=$rc (44 = not found)"
	$S delete-keychain "$kc"; rc=$?; echo "$(ts) [$1] delete-keychain exit=$rc"
	rm -rf "$d"; echo "$(ts) [$1] keychain dir removed=$([ -e "$d" ] && echo no || echo yes)"
}
kc_run go-raw "$OUT/hm-x4-go"
kc_run go-purego-raw "$OUT/hm-x4-go-purego"
kc_run rust-raw "$OUT/hm-x4-rust"

echo "== 3. Secure Enclave ephemeral P-256 + data-protection probe (linker ad-hoc signed CLI)"
for l in go go-purego rust; do
	run "$l-raw se" TO "$OUT/hm-x4-$l" se
	run "$l-raw dpprobe (read-only)" TO "$OUT/hm-x4-$l" dpprobe
done

echo "== 4. signature removed entirely"
for l in go go-purego rust; do
	cp "$OUT/hm-x4-$l" "$OUT/hm-x4-$l.unsigned"
	run "codesign --remove-signature $l" codesign --remove-signature "$OUT/hm-x4-$l.unsigned"
	run "codesign -dv $l.unsigned" codesign -dv "$OUT/hm-x4-$l.unsigned"
	run "$l-unsigned se" TO "$OUT/hm-x4-$l.unsigned" se
done

echo "== 5. app-like bundle, ad-hoc signed (hardened runtime)"
LOGSTART=$(date '+%Y-%m-%d %H:%M:%S') # local time, as log(1) expects
for ent in none keychain-group; do
	for l in go go-purego rust; do
		case $l in go) Lc=Go ;; go-purego) Lc=GoPurego ;; rust) Lc=Rust ;; esac
		app="$OUT/bundles/$ent/HeimdallX4$Lc.app"; exe="hm-x4-$l"
		mkdir -p "$app/Contents/MacOS"
		sed -e "s/@LANG@/$l/g" -e "s/@EXE@/$exe/g" "$HERE/bundle/Info.plist.in" > "$app/Contents/Info.plist"
		cp "$OUT/hm-x4-$l" "$app/Contents/MacOS/$exe"
		run "codesign ad-hoc $l entitlements=$ent" codesign --force --sign - --options runtime --identifier "dev.heimdall.x4.$l" --entitlements "$HERE/bundle/entitlements-$ent.plist" "$app"
		run "codesign --verify --strict --deep $l/$ent" codesign --verify --strict --deep --verbose=2 "$app"
		run "codesign -dv $l/$ent" sh -c "codesign -dv '$app' 2>&1 | grep -E '^(Identifier|Format|CodeDirectory|Signature|Info.plist|TeamIdentifier|Runtime)'"
		run "codesign -d --entitlements $l/$ent" sh -c "codesign -d --entitlements - --xml '$app' 2>/dev/null | plutil -convert json -o - - 2>/dev/null; echo"
		run "spctl --assess --type execute $l/$ent" spctl --assess --type execute -vv "$app"
		run "bundle[$ent] $l se" TO "$app/Contents/MacOS/$exe" se
		run "bundle[$ent] $l dpprobe (read-only)" TO "$app/Contents/MacOS/$exe" dpprobe
		[ "$ent" = none ] && kc_run "bundle[$ent]-$l" "$app/Contents/MacOS/$exe"
	done
done
echo "$(ts) unified log since section 5 start (log timestamps are local time, UTC$(date +%z)): amfid lines naming the spike (max 9, truncated):"
log show --start "$LOGSTART" --style compact --predicate 'eventMessage CONTAINS "dev.heimdall.x4" OR eventMessage CONTAINS "hm-x4-"' 2>/dev/null \
	| grep -i -E 'amfi|entitlement|provision|signature' | cut -c1-300 | head -9 | sed 's/^/    /'

echo "== 6. cross-compilation on this host"
cd "$HERE/go" || exit 1
run "go spike GOARCH=amd64 CGO_ENABLED=1 (Apple clang)" env GOARCH=amd64 CGO_ENABLED=1 go build -trimpath -o "$OUT/hm-x4-go.amd64" .
[ -e "$OUT/hm-x4-go.amd64" ] && echo "$(ts) $(file -b "$OUT/hm-x4-go.amd64")"
run "go spike CGO_ENABLED=0 GOOS=darwin" env CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -o "$OUT/hm-x4-go.nocgo" .
run "go baseline hello CGO_ENABLED=0 GOOS=darwin GOARCH=amd64" env CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -o "$OUT/hello-go.nocgo.amd64" ./baseline-hello
run "go spike GOOS=linux" env CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o "$OUT/hm-x4-go.linux" .
cd "$HERE/go-purego" || exit 1
run "go-purego CGO_ENABLED=0 GOOS=darwin GOARCH=amd64" env CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -o "$OUT/hm-x4-go-purego.amd64" .
[ -e "$OUT/hm-x4-go-purego.amd64" ] && echo "$(ts) $(file -b "$OUT/hm-x4-go-purego.amd64")"
cd "$HERE" || exit 1
echo "$(ts) rust installed targets: $(rustup target list --installed | tr '\n' ' ')"

echo "== 7. lines of code (non-blank, non-comment-only lines) and unsafe/FFI surface"
loc() { grep -v -E '^\s*$|^\s*//|^\s*/\*|^\s*\*' "$1" | wc -l | tr -d ' '; }
for f in go/main.go go/native_darwin.go go-purego/main.go rust/src/main.rs; do echo "$(ts) loc $f=$(loc "$f") total_lines=$(wc -l < "$f" | tr -d ' ')"; done
c_lines=$(awk '/^\/\*$/{c=1;next} /^\*\/$/{c=0} c' go/native_darwin.go | grep -v -E '^\s*$|^\s*//' | wc -l | tr -d ' ')
echo "$(ts) go native_darwin.go embedded C (cgo preamble) loc=$c_lines"
echo "$(ts) go: unsafe.Pointer uses=$(grep -o 'unsafe.Pointer' go/*.go | wc -l | tr -d ' ') C.* references=$(grep -o -E '\bC\.[A-Za-z_]+' go/*.go | wc -l | tr -d ' ')"
echo "$(ts) go-purego: unsafe.Pointer uses=$(grep -o 'unsafe.Pointer' go-purego/main.go | wc -l | tr -d ' ') unsafe.* uses=$(grep -o -E 'unsafe\.[A-Za-z]+' go-purego/main.go | wc -l | tr -d ' ')"
echo "$(ts) rust: unsafe blocks=$(grep -o -E '\bunsafe *\{' rust/src/main.rs | wc -l | tr -d ' ')"

echo "== 8. cleanup check"
echo "$(ts) leftover disposable keychain dirs=$(find "$SCR" -maxdepth 1 -name 'kc.*' | wc -l | tr -d ' ')"
echo "$(ts) user search list unchanged=$([ "$($S list-keychains -d user | dig)" = "$L0" ] && echo yes || echo no) default keychain unchanged=$([ "$($S default-keychain -d user | dig)" = "$D0" ] && echo yes || echo no)"
echo "$(ts) done"
