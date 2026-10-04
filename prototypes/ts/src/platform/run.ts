// `run` adapter (contract §4): launch argv without a shell, inherit stdio/cwd/env,
// forward signals, wait for the child, report status.
//
// Unix (ruling K6): the child runs in its own process group (posix-spawn.ts). When
// heimdall-proto is the terminal's foreground group, the terminal is handed to the
// child's group for the child's lifetime, so terminal-generated SIGINT/SIGQUIT/SIGWINCH
// reach only the child. Every signal heimdall-proto itself receives (for example an
// explicit `kill -INT <pid>`) is therefore forwarded exactly once, in every state.

import { constants as osConstants } from "node:os";
import { extname } from "node:path";
import { childExited, childLaunchFailed, exitStatusFor, quoteWindowsArg } from "../domain/run.ts";
import type { Result } from "../domain/result.ts";
import { foregroundTtyFd, giveTerminal, reclaimTerminal, spawnInOwnGroup, waitChild } from "./posix-spawn.ts";

const FORWARDED = ["SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT", "SIGWINCH"] as const;

export interface RunOutcome {
  status: number; // heimdall-proto's exit status
  meta: Result;
}

function signalNumber(name: string | null): number | null {
  if (!name) return null;
  const n = (osConstants.signals as Record<string, number>)[name];
  return typeof n === "number" ? n : null;
}

// Windows: quote with our CommandLineToArgvW quoter and pass verbatim. Bun resolves
// the executable from cmd[0] (PATH + PATHEXT) and uses `argv0` as the command-line
// token. Batch files are refused: cmd.exe re-parses the line (BatBadBut).
// Compile-checked only; not executed on Windows.
function windowsSpawnArgs(argv: string[]): { cmd: string[]; opts: Record<string, unknown> } | null {
  const resolved = Bun.which(argv[0]!);
  if (!resolved) return null;
  const ext = extname(resolved).toLowerCase();
  if (ext === ".bat" || ext === ".cmd") return null;
  const token0 = /[ \t]/.test(argv[0]!) ? `"${argv[0]}"` : argv[0]!;
  return {
    cmd: [resolved, ...argv.slice(1).map(quoteWindowsArg)],
    opts: { windowsVerbatimArguments: true, argv0: token0 },
  };
}

function launchFailed(code: string): RunOutcome {
  process.stderr.write(`heimdall-proto: cannot launch command (${code})\n`);
  return { status: 127, meta: childLaunchFailed() };
}

async function runWindows(argv: string[]): Promise<RunOutcome> {
  // The console delivers Ctrl-C/Break to the child itself; keep heimdall-proto alive.
  const noop = () => {};
  process.on("SIGINT", noop);
  process.on("SIGBREAK", noop);
  const cleanup = () => { process.off("SIGINT", noop); process.off("SIGBREAK", noop); };
  let child: ReturnType<typeof Bun.spawn>;
  try {
    const w = windowsSpawnArgs(argv);
    if (!w) { cleanup(); return launchFailed("ENOENT"); }
    child = Bun.spawn(w.cmd, { stdio: ["inherit", "inherit", "inherit"], ...w.opts });
  } catch (e) {
    cleanup();
    return launchFailed((e as { code?: string }).code ?? "error");
  }
  await child.exited;
  cleanup();
  const sig = signalNumber(child.signalCode as string | null);
  const exitCode = sig === null ? child.exitCode : null;
  return { status: exitStatusFor(exitCode, sig), meta: childExited(exitCode, sig) };
}

export async function runChild(argv: string[]): Promise<RunOutcome> {
  if (process.platform === "win32") return runWindows(argv);
  // Handlers are installed before spawning so heimdall-proto never dies before the child.
  let pid: number | null = null;
  const handlers = new Map<string, () => void>();
  for (const sig of FORWARDED) {
    const h = () => {
      if (pid === null) return;
      try { process.kill(pid, sig); } catch { /* child already gone */ }
    };
    handlers.set(sig, h);
    process.on(sig, h);
  }
  const cleanup = () => { for (const [sig, h] of handlers) process.off(sig as NodeJS.Signals, h); };

  // PATH lookup up front (execvp rules: executable regular file). posix_spawnp reports
  // exec failures itself on macOS and native linux-arm64, but in the emulated linux-x64
  // container it returned success and the child exited 127 (observed; cause not traced).
  const file = Bun.which(argv[0]!);
  if (file === null) {
    cleanup();
    return launchFailed("ENOENT");
  }
  const ttyFd = foregroundTtyFd();
  const spawned = spawnInOwnGroup(file, argv);
  if (!spawned.ok) {
    cleanup();
    return launchFailed(`errno ${spawned.errno}`);
  }
  pid = spawned.pid;
  const handedOff = ttyFd !== null && giveTerminal(ttyFd, pid);
  // Ctrl-Z stops only the child (it owns the terminal). Pass the stop on as a shell
  // expects: take the terminal back and stop heimdall-proto; when continued, hand the
  // terminal back and continue the child's group.
  const childPid = pid;
  const res = await waitChild(childPid, () => {
    if (!handedOff) return;
    reclaimTerminal(ttyFd!);
    process.kill(process.pid, "SIGSTOP");
    giveTerminal(ttyFd!, childPid);
    try { process.kill(-childPid, "SIGCONT"); } catch { /* group gone */ }
  });
  if (handedOff) reclaimTerminal(ttyFd!);
  cleanup();
  return { status: exitStatusFor(res.exitCode, res.signal), meta: childExited(res.exitCode, res.signal) };
}
