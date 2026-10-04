// heimdall-proto CLI (G02 slice). Argument handling and process exit only; behavior
// lives in domain/ (pure) and platform/ (I/O), shared with the TUI.

import { realpathSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import pkg from "../package.json" with { type: "json" };
import { parseProfile } from "./domain/profile.ts";
import { cancelled, EXIT, fail, ok, serialize, type Result } from "./domain/result.ts";
import { probeAgent } from "./platform/agent-client.ts";
import { readBounded } from "./platform/files.ts";
import { runChild } from "./platform/run.ts";
import { writeAll } from "./platform/stdio.ts";

const USAGE = `usage:
  heimdall-proto profile show --file <path> [--json]
  heimdall-proto agent list --socket <path> [--timeout-ms N] [--json]
  heimdall-proto run [--meta-file <path>] -- <argv...>
  heimdall-proto tui --file <path>
  heimdall-proto version [--json]
`;

class UsageError extends Error {}

function emit(r: Result): never {
  writeAll(1, serialize(r));
  process.exit(EXIT[r.code]);
}

// Parse `--flag value` / `--flag` options. Unknown flags and stray positionals are usage errors.
function parseFlags(args: string[], valued: string[], bools: string[]): Record<string, string | true> {
  const out: Record<string, string | true> = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (valued.includes(a)) {
      const v = args[++i];
      if (v === undefined) throw new UsageError(`missing value for ${a}`);
      out[a] = v;
    } else if (bools.includes(a)) {
      out[a] = true;
    } else {
      throw new UsageError(a.startsWith("-") ? `unknown flag ${a}` : "unexpected argument");
    }
  }
  return out;
}

function need(flags: Record<string, string | true>, name: string): string {
  const v = flags[name];
  if (typeof v !== "string") throw new UsageError(`missing ${name}`);
  return v;
}

function profileShow(args: string[]): never {
  const f = parseFlags(args, ["--file"], ["--json"]);
  const path = need(f, "--file");
  const read = readBounded(path);
  if (read.kind === "too_large") emit(fail("INPUT_TOO_LARGE", null, "profile exceeds 1048576 bytes"));
  if (read.kind === "unreadable") emit(fail("USAGE_ERROR", null, "profile file is missing or unreadable"));
  emit(parseProfile(read.bytes).result);
}

async function agentList(args: string[]): Promise<never> {
  const f = parseFlags(args, ["--socket", "--timeout-ms"], ["--json"]);
  const socket = need(f, "--socket");
  let timeout = 5000;
  if (f["--timeout-ms"] !== undefined) {
    const t = String(f["--timeout-ms"]);
    if (!/^\d{1,9}$/.test(t) || Number(t) < 1) throw new UsageError("--timeout-ms must be a positive integer");
    timeout = Number(t);
  }
  const probe = probeAgent(socket, timeout);
  const onSig = () => {
    probe.abort();
    emit(cancelled());
  };
  process.on("SIGINT", onSig);
  if (process.platform === "win32") process.on("SIGBREAK", onSig);
  emit(await probe.done);
}

async function run(args: string[]): Promise<never> {
  const sep = args.indexOf("--");
  if (sep < 0) throw new UsageError("missing -- before command");
  const f = parseFlags(args.slice(0, sep), ["--meta-file"], []);
  const argv = args.slice(sep + 1);
  if (argv.length === 0 || argv[0] === "") throw new UsageError("empty command");
  const metaPath = typeof f["--meta-file"] === "string" ? f["--meta-file"] : null;
  const out = await runChild(argv);
  if (metaPath !== null) {
    try {
      writeFileSync(metaPath, serialize(out.meta));
    } catch {
      process.stderr.write("heimdall-proto: could not write meta file\n");
    }
  }
  process.exit(out.status);
}

async function tui(args: string[]): Promise<never> {
  const f = parseFlags(args, ["--file"], []);
  const path = need(f, "--file");
  if (!process.stdin.isTTY || !process.stdout.isTTY) throw new UsageError("tui requires a terminal on stdin and stdout");
  const read = readBounded(path);
  if (read.kind === "too_large") throw new UsageError("profile exceeds 1048576 bytes");
  if (read.kind === "unreadable") throw new UsageError("profile file is missing or unreadable");
  const parsed = parseProfile(read.bytes);
  if (!parsed.ok) {
    process.stderr.write(`heimdall-proto: invalid profile (${parsed.result.code})\n`);
    process.exit(EXIT[parsed.result.code]);
  }
  pinNativeAssets();
  // Lazy import: the native OpenTUI library is loaded only for `tui`.
  const { runTui } = await import("./tui/tui.ts");
  const res = await runTui(parsed.profile);
  switch (res.kind) {
    case "select":
      writeAll(1, `SELECTED ${res.alias}\n`);
      process.exit(0);
    case "quit":
      process.exit(0);
    case "cancel":
      process.exit(130);
    case "signal":
      process.exit(res.status);
    case "error":
      process.exit(1);
  }
}

// K11: the compiled executable ships OpenTUI's native library as a sidecar
// (<exe dir>/@opentui/core-<platform>-<arch>/<lib>, see build.sh) and loads it only from
// the directory of its own real path. Inherited OTUI_ASSET_ROOT / OPENTUI_LIBC values are
// overwritten or removed before OpenTUI is loaded, so nothing is extracted to TMPDIR and
// the environment cannot redirect the load. If the sidecar is missing, OpenTUI throws
// and the TUI exits 1 (it does not fall back). From source, node_modules is used.
function pinNativeAssets(): void {
  delete process.env.OPENTUI_LIBC;
  const compiled = Bun.main.startsWith("/$bunfs/") || /^[A-Za-z]:\\~BUN\\/.test(Bun.main);
  if (compiled) process.env.OTUI_ASSET_ROOT = dirname(realpathSync(process.execPath));
  else delete process.env.OTUI_ASSET_ROOT;
}

function version(args: string[]): never {
  parseFlags(args, [], ["--json"]);
  emit(ok("VERSION_OK", {
    name: "heimdall-proto",
    version: "0.0.0-g02",
    candidate: "ts",
    runtime: `bun ${Bun.version} (${Bun.revision.slice(0, 9)})`,
    tui_framework: "@opentui/core",
    tui_framework_version: pkg.dependencies["@opentui/core"],
  }));
}

export async function main(argv: string[]): Promise<never> {
  const json = (() => {
    const sep = argv.indexOf("--");
    return (sep < 0 ? argv : argv.slice(0, sep)).includes("--json");
  })();
  try {
    const [a, b, ...rest] = argv;
    if (a === "profile" && b === "show") return profileShow(rest);
    if (a === "agent" && b === "list") return await agentList(rest);
    if (a === "run") return await run(argv.slice(1));
    if (a === "tui") return await tui(argv.slice(1));
    if (a === "version") return version(argv.slice(1));
    throw new UsageError(a === undefined ? "missing subcommand" : "unknown subcommand");
  } catch (e) {
    if (e instanceof UsageError) {
      process.stderr.write(`heimdall-proto: ${e.message}\n${USAGE}`);
      if (json) emit(fail("USAGE_ERROR", null, e.message));
      process.exit(2);
    }
    process.stderr.write(`heimdall-proto: internal error\n`);
    if (json) emit(fail("INTERNAL", null, "internal error"));
    process.exit(1);
  }
}
