// Pure parts of `run` (contract §4): meta result and Windows command-line quoting.

import type { Result } from "./result.ts";

export function childExited(exitCode: number | null, signal: number | null): Result {
  return {
    schema_version: "1", state: "succeeded", code: "CHILD_EXITED",
    data: { launched: true, exit_code: exitCode, signal }, warnings: [], next: null,
  };
}

export function childLaunchFailed(): Result {
  return {
    schema_version: "1", state: "failed", code: "CHILD_LAUNCH_FAILED",
    data: { launched: false, exit_code: null, signal: null }, warnings: [], next: null,
  };
}

// Exit status of `heimdall-proto run`: child's code, or 128+N when killed by signal N.
export function exitStatusFor(exitCode: number | null, signal: number | null): number {
  if (signal !== null) return 128 + signal;
  return exitCode ?? 1;
}

// Quote one argument so CommandLineToArgvW / the MSVC CRT parser recovers it exactly.
// Rules: backslashes are literal unless they precede a double quote; 2n backslashes +
// quote => n backslashes + end/begin quote; 2n+1 backslashes + quote => n backslashes +
// literal quote. Arguments are always wrapped in quotes when they are empty or contain
// space, tab, newline, vertical tab or a quote.
// This does NOT make arguments safe for cmd.exe (.bat/.cmd); those are refused.
export function quoteWindowsArg(arg: string): string {
  if (arg.length > 0 && !/[ \t\n\v"]/.test(arg)) return arg;
  let out = '"';
  let backslashes = 0;
  for (const ch of arg) {
    if (ch === "\\") {
      backslashes++;
    } else if (ch === '"') {
      out += "\\".repeat(backslashes * 2 + 1) + '"';
      backslashes = 0;
    } else {
      out += "\\".repeat(backslashes) + ch;
      backslashes = 0;
    }
  }
  out += "\\".repeat(backslashes * 2) + '"';
  return out;
}

export function windowsCommandLine(argv: readonly string[]): string {
  return argv.map(quoteWindowsArg).join(" ");
}

// Reference decoder of the CommandLineToArgvW rules (post-2008 CRT behavior) used only
// by tests to check quoteWindowsArg round-trips. argv[0] parsing differs in the real
// API (no backslash processing); tests apply it to arguments after argv[0].
export function parseWindowsArgs(cmd: string): string[] {
  const args: string[] = [];
  let i = 0;
  const n = cmd.length;
  while (i < n) {
    while (i < n && (cmd[i] === " " || cmd[i] === "\t")) i++;
    if (i >= n) break;
    let cur = "";
    let inQuotes = false;
    while (i < n) {
      const c = cmd[i]!;
      if (!inQuotes && (c === " " || c === "\t")) break;
      if (c === "\\") {
        let bs = 0;
        while (i < n && cmd[i] === "\\") { bs++; i++; }
        if (cmd[i] === '"') {
          cur += "\\".repeat(Math.floor(bs / 2));
          if (bs % 2 === 1) { cur += '"'; i++; }
        } else {
          cur += "\\".repeat(bs);
        }
        continue;
      }
      if (c === '"') {
        if (inQuotes && cmd[i + 1] === '"') { cur += '"'; i += 2; continue; }
        inQuotes = !inQuotes;
        i++;
        continue;
      }
      cur += c;
      i++;
    }
    args.push(cur);
  }
  return args;
}
