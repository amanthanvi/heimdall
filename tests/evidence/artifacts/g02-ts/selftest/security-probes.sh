#!/bin/sh
# Security/packaging probes for the TS G02 artifact (darwin-arm64). Disposable temp
# dirs only; no real agent, no network. Run from the repository root.
set -u
B="$PWD/prototypes/ts/dist/darwin-arm64/heimdall-proto"
F="$PWD/tests/fixtures/g02/profiles/homelab.toml"
W=$(mktemp -d /tmp/g02ts-sec.XXXXXX)
PTY="$W/pty.ts"
cat > "$PTY" <<'EOF'
// bun pty.ts <bin> <profile> <tmpdir> [extraEnvKey=val]... ; types q after first frame
const [bin, profile, tmp, ...kv] = process.argv.slice(2);
const env: Record<string, string> = { PATH: "/usr/bin:/bin", TERM: "xterm-256color", TMPDIR: tmp!, HOME: tmp! };
for (const x of kv) { const i = x.indexOf("="); env[x.slice(0, i)] = x.slice(i + 1); }
let out = "";
const p = Bun.spawn([bin!, "tui", "--file", profile!], { env, terminal: { cols: 80, rows: 10, data(_t: unknown, d: Uint8Array) { out += new TextDecoder().decode(d); } } } as any);
const t0 = performance.now();
while (!out.includes("filter:") && performance.now() - t0 < 4000 && p.exitCode === null) await Bun.sleep(10);
if (p.exitCode === null) (p as any).terminal.write("q");
const k = setTimeout(() => p.kill("SIGKILL"), 4000);
await p.exited; clearTimeout(k);
console.log(`tui exit=${p.exitCode} rendered=${out.includes("lab-server")}`);
EOF
echo "## 1. TUI run extracts the embedded native library into TMPDIR (contract §1: no writes outside named paths)"
mkdir -p "$W/t1/"; bun "$PTY" "$B" "$F" "$W/t1/"; ls -la "$W/t1" | grep '\.bun-' || echo "no extraction"
echo "## 2. Same-size, same-uid planted file at the predictable name is loaded without content verification"
f=$(ls "$W"/t1/.bun-* | head -1); sz=$(stat -f %z "$f"); head -c "$sz" /dev/zero > "$f"; chmod 600 "$f"
bun "$PTY" "$B" "$F" "$W/t1/"; echo "file after run is still all zeros: $( [ "$(tr -d '\000' < "$f" | wc -c | tr -d ' ')" = 0 ] && echo yes || echo no)"
echo "## 3. Different-size planted file is replaced (rewritten) and the TUI works"
printf 'garbage' > "$f"; bun "$PTY" "$B" "$F" "$W/t1/"; echo "size after run: $(stat -f %z "$f")"
echo "## 4. Sidecar library via OTUI_ASSET_ROOT: no TMPDIR extraction (also shows the env var is honored when inherited)"
mkdir -p "$W/side/@opentui/core-darwin-arm64" "$W/t4/"; cp "$PWD/prototypes/ts/node_modules/@opentui/core-darwin-arm64/libopentui.dylib" "$W/side/@opentui/core-darwin-arm64/"
bun "$PTY" "$B" "$F" "$W/t4/" "OTUI_ASSET_ROOT=$W/side"; ls -A "$W/t4" | grep . || echo "TMPDIR empty"
echo "## 5. BUN_BE_BUN=1 turns the shipped binary into a general Bun runtime"
env -i PATH=/usr/bin:/bin BUN_BE_BUN=1 "$B" -e 'console.log("BUN_BE_BUN: evaluated arbitrary code")'; echo "exit=$?"
echo "## 6. .env autoload: disabled in build.sh artifacts; enabled by default in a plain --compile build"
mkdir -p "$W/envdir"; printf 'G02_DOTENV_PROBE=loaded-from-dotenv\n' > "$W/envdir/.env"
(cd "$W/envdir" && env -i PATH=/usr/bin:/bin "$B" run -- /bin/sh -c 'echo "build.sh artifact sees: [${G02_DOTENV_PROBE:-}]"')
(cd "$PWD/prototypes/ts" && bun build --compile --target=bun-darwin-arm64 src/main.ts --outfile "$W/default-flags/heimdall-proto" >/dev/null 2>&1)
(cd "$W/envdir" && env -i PATH=/usr/bin:/bin "$W/default-flags/heimdall-proto" run -- /bin/sh -c 'echo "default --compile build sees: [${G02_DOTENV_PROBE:-}]"')
echo "## 7. Non-TUI commands do not touch TMPDIR"
mkdir -p "$W/t7/"; env -i PATH=/usr/bin:/bin TMPDIR="$W/t7/" "$B" profile show --file "$F" --json >/dev/null; env -i PATH=/usr/bin:/bin TMPDIR="$W/t7/" "$B" version --json >/dev/null; ls -A "$W/t7" | grep . || echo "TMPDIR empty"
rm -rf "$W"
