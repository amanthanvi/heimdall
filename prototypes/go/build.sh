#!/bin/sh
# Build heimdall-proto (G02 Go prototype) for every contract target and write
# dist/manifest.json (docs/g02/slice-contract.md §7). POSIX sh; run from anywhere.
# Requires: go (the version pinned in go.mod), shasum or sha256sum, awk; on
# macOS, codesign (Xcode command line tools) for the darwin artifact.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 1
cd "$HERE" || exit 1
DIST="$HERE/dist"
rm -rf "$DIST"
mkdir -p "$DIST"

if ! command -v go >/dev/null 2>&1; then
	echo "build.sh: go not found on PATH" >&2
	exit 1
fi

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
	else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# JSON-escape stdin into a single JSON string literal (without quotes).
json_escape() {
	tr -d '\000-\010\013\014\016-\037' | awk 'BEGIN{ORS=""} {gsub(/\\/,"\\\\"); gsub(/"/,"\\\""); gsub(/\t/,"\\t"); if (NR>1) print "\\n"; print}'
}

entries=""
failed=0
for spec in darwin-arm64:darwin:arm64 linux-x64:linux:amd64 linux-arm64:linux:arm64 windows-x64:windows:amd64; do
	target=${spec%%:*}
	rest=${spec#*:}
	goos=${rest%%:*}
	goarch=${rest#*:}
	exe=heimdall-proto
	[ "$goos" = windows ] && exe=heimdall-proto.exe
	mkdir -p "$DIST/$target"
	errfile="$DIST/$target/.build-error"
	if CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch GOFLAGS=-mod=readonly \
		go build -trimpath -buildvcs=false -ldflags "-s -w" \
		-o "$DIST/$target/$exe" ./cmd/heimdall-proto 2>"$errfile"; then
		if [ "$goos" = darwin ]; then
			# Hardened runtime (ad-hoc identity): dyld then ignores
			# DYLD_INSERT_LIBRARIES and similar variables. Needs macOS codesign;
			# elsewhere the artifact keeps only the linker's ad-hoc signature.
			if command -v codesign >/dev/null 2>&1 && [ "$(uname -s)" = Darwin ]; then
				codesign --force --options runtime --sign - "$DIST/$target/$exe" 2>>"$errfile" ||
					echo "build.sh: WARNING: codesign failed for $target" >&2
				echo "signed $target: ad-hoc, hardened runtime" >&2
			else
				echo "build.sh: WARNING: codesign unavailable; $target is linker-signed only (DYLD_* variables honored)" >&2
			fi
		fi
		bytes=$(wc -c <"$DIST/$target/$exe" | tr -d ' ')
		sum=$(sha256 "$DIST/$target/$exe")
		entry="{\"target\":\"$target\",\"path\":\"$target/$exe\",\"bytes\":$bytes,\"sha256\":\"$sum\",\"built\":true,\"error\":null}"
		echo "built $target ($bytes bytes)" >&2
	else
		err=$(json_escape <"$errfile")
		entry="{\"target\":\"$target\",\"path\":\"$target/$exe\",\"bytes\":null,\"sha256\":null,\"built\":false,\"error\":\"$err\"}"
		echo "FAILED $target" >&2
		cat "$errfile" >&2
		failed=$((failed + 1))
	fi
	rm -f "$errfile"
	if [ -n "$entries" ]; then entries="$entries,"; fi
	entries="$entries$entry"
done

printf '{"candidate":"go","targets":[%s]}\n' "$entries" >"$DIST/manifest.json"
echo "wrote $DIST/manifest.json" >&2
# Exit 0 if at least darwin-arm64 built; failures are recorded in the manifest.
[ -f "$DIST/darwin-arm64/heimdall-proto" ] || exit 1
exit 0
