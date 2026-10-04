#!/bin/sh
# §9 alignment probes for the TS artifact on macOS (darwin-arm64). Disposable temp dirs
# only; no real agent, no network. Run from the repository root.
# Optional: OLD_BIN=<pre-alignment build> for the K6 negative control.
set -u
unset SSH_AUTH_SOCK
B="$PWD/prototypes/ts/dist/darwin-arm64/heimdall-proto"
F="$PWD/tests/fixtures/g02/profiles/homelab.toml"
W=$(mktemp -d /tmp/g02ts-k.XXXXXX)
echo "artifact sha256: $(shasum -a 256 "$B" | cut -d' ' -f1)"
echo "## K8: argv element 61 ff 62 (invalid UTF-8) as received by the child"
"$B" run -- /bin/sh -c 'printf %s "$1"' sh "$(printf 'a\377b')" | od -An -tx1
echo "## env value 61 ff 62 as received by the child (posix_spawn passes the C environ)"
env "G02_RAW=$(printf 'a\377b')" "$B" run -- /bin/sh -c 'printf %s "$G02_RAW"' | od -An -tx1
echo "## BUN_BE_BUN=1 still turns the artifact into a general Bun runtime"
env -i PATH=/usr/bin:/bin BUN_BE_BUN=1 "$B" -e 'console.log("BUN_BE_BUN: evaluated arbitrary code")'; echo "exit=$?"
echo "## .env autoload stays disabled"
mkdir -p "$W/envdir"; printf 'G02_DOTENV_PROBE=loaded-from-dotenv\n' > "$W/envdir/.env"
(cd "$W/envdir" && env -i PATH=/usr/bin:/bin "$B" run -- /bin/sh -c 'echo "artifact sees: [${G02_DOTENV_PROBE:-}]"')
echo "## Non-TUI commands and TUI write nothing to a fresh TMPDIR"
mkdir -p "$W/t/"
env -i PATH=/usr/bin:/bin TMPDIR="$W/t/" "$B" profile show --file "$F" --json >/dev/null; echo "profile exit=$?"
env -i PATH=/usr/bin:/bin TMPDIR="$W/t/" "$B" version --json >/dev/null; echo "version exit=$?"
env -i PATH=/usr/bin:/bin TMPDIR="$W/t/" "$B" run -- /usr/bin/true; echo "run exit=$?"
cat > "$W/tui.ts" <<'T'
const [bin, profile, tmp] = process.argv.slice(2);
let out = "";
const p = Bun.spawn([bin!, "tui", "--file", profile!], { env: { PATH: "/usr/bin:/bin", TERM: "xterm-256color", TMPDIR: tmp!, HOME: tmp! }, terminal: { cols: 80, rows: 10, data(_t: unknown, d: Uint8Array) { out += new TextDecoder().decode(d); } } } as any);
const t0 = performance.now();
while (!out.includes("filter:") && performance.now() - t0 < 5000 && p.exitCode === null) await Bun.sleep(10);
if (p.exitCode === null) (p as any).terminal.write("q");
const k = setTimeout(() => p.kill("SIGKILL"), 5000);
await p.exited; clearTimeout(k);
console.log(`tui exit=${p.exitCode} rendered=${out.includes("lab-server")}`);
T
bun "$W/tui.ts" "$B" "$F" "$W/t/"
echo "TMPDIR entries after all commands: $(ls -A "$W/t" | wc -l | tr -d ' ')"
echo "## K6: proto is the PTY foreground group; explicit kill -INT <proto pid>; INT count seen by the child"
cat > "$W/child.py" <<'P'
import os, signal, sys, time
log = sys.argv[1]
signal.signal(signal.SIGINT, lambda s, f: open(log, "a").write("INT\n"))
open(log, "a").write("ready\n")
while not os.path.exists(log + ".stop"): time.sleep(0.01)
P
cat > "$W/k6.ts" <<'T'
import { existsSync, readFileSync, writeFileSync, rmSync } from "node:fs";
const [bin, child, log] = process.argv.slice(2);
rmSync(log!, { force: true }); rmSync(log + ".stop", { force: true });
const lines = () => (existsSync(log!) ? readFileSync(log!, "utf8").trim().split("\n") : []);
const p = Bun.spawn([bin!, "run", "--", "/usr/bin/python3", child!, log!], { env: { PATH: "/usr/bin:/bin" }, terminal: { cols: 80, rows: 24, data() {} } } as any);
const t0 = performance.now();
while (!lines().includes("ready") && performance.now() - t0 < 5000) await Bun.sleep(10);
process.kill(p.pid, "SIGINT"); // exact PID we started
await Bun.sleep(1000);
writeFileSync(log + ".stop", "");
const k = setTimeout(() => p.kill("SIGKILL"), 5000);
await p.exited; clearTimeout(k);
console.log(`proto exit=${p.exitCode} child INT count=${lines().filter((l) => l === "INT").length} (want 1)`);
T
echo "new artifact:"; bun "$W/k6.ts" "$B" "$W/child.py" "$W/log"
if [ -n "${OLD_BIN:-}" ]; then echo "pre-alignment artifact (negative control) sha256 $(shasum -a 256 "$OLD_BIN" | cut -d' ' -f1):"; bun "$W/k6.ts" "$OLD_BIN" "$W/child.py" "$W/log"; fi
rm -rf "$W"
