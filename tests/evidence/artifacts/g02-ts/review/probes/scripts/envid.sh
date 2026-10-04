B=/tmp/hm-review-root/prototypes/ts/dist/darwin-arm64/heimdall-proto
D=/tmp/hm-review-probes/envid
cd $D
I() { env -i PATH=/usr/bin:/bin HOME=$D "$@"; }
ran() { if [ -e $D/PRELOAD_RAN ]; then echo yes; else echo no; fi; rm -f $D/PRELOAD_RAN; }
rm -f PRELOAD_RAN
echo "== BUN_OPTIONS=--preload"; I BUN_OPTIONS="--preload $D/evil.js" $B version --json >/dev/null; echo "rc=$? preload_ran=$(ran)"
echo "== NODE_OPTIONS=--require"; I NODE_OPTIONS="--require $D/evil.js" $B version --json >/dev/null; echo "rc=$? preload_ran=$(ran)"
echo "== BUN_BE_BUN -e"; I BUN_BE_BUN=1 $B -e 'console.log("ARBITRARY_CODE", 6*7)'; echo "rc=$?"
echo "== BUN_BE_BUN <file>"; I BUN_BE_BUN=1 $B $D/evil.js >/dev/null 2>&1; echo "rc=$? file_ran=$(ran)"
echo "== bunfig.toml preload in cwd"; printf 'preload = ["./evil.js"]\n' > bunfig.toml; I $B version --json >/dev/null; echo "rc=$? preload_ran=$(ran)"; rm -f bunfig.toml
echo "== .env BUN_BE_BUN in cwd"; printf 'BUN_BE_BUN=1\n' > .env; I $B -e 'console.log(1)' >/dev/null 2>&1; echo "rc=$? (2=usage => .env ignored)"; rm -f .env
echo "== HEIMDALL_PROTO_FAULT present in artifact strings: $(grep -c HEIMDALL_PROTO_FAULT $B)"
