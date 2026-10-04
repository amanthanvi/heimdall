// Shared test helpers. Tests run against the source entry by default, or against a
// compiled artifact when HEIMDALL_PROTO_BIN is set (used for the dist smoke run).

import Ajv2020 from "ajv/dist/2020.js";
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

export const ROOT = resolve(import.meta.dir, "../../..");
export const FIXTURES = join(ROOT, "tests/fixtures/g02/profiles");
export const PROTO_DIR = resolve(import.meta.dir, "..");

export const PROTO: string[] = process.env.HEIMDALL_PROTO_BIN
  ? [process.env.HEIMDALL_PROTO_BIN]
  : [process.execPath, join(PROTO_DIR, "src/main.ts")];

// Child environment: no real SSH agent, no inherited color preference.
export function cleanEnv(extra: Record<string, string> = {}): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v !== undefined && k !== "SSH_AUTH_SOCK" && k !== "NO_COLOR" && !k.startsWith("HEIMDALL_PROTO")) env[k] = v;
  }
  return { ...env, ...extra };
}

export interface Ran {
  code: number | null;
  signal: string | null;
  stdout: Uint8Array;
  stderr: string;
  stdoutText: string;
  ms: number;
}

export function proto(args: string[], opts: { stdin?: Uint8Array; env?: Record<string, string>; cwd?: string } = {}): Ran {
  const t0 = performance.now();
  const r = Bun.spawnSync([...PROTO, ...args], {
    stdin: opts.stdin ?? "ignore",
    stdout: "pipe",
    stderr: "pipe",
    env: opts.env ?? cleanEnv(),
    cwd: opts.cwd,
  });
  const stdout = r.stdout as Uint8Array;
  return {
    code: r.exitCode,
    signal: (r.signalCode as string | null) ?? null,
    stdout,
    stderr: new TextDecoder().decode(r.stderr as Uint8Array),
    stdoutText: new TextDecoder().decode(stdout),
    ms: performance.now() - t0,
  };
}

// Async variant: required when the test process itself hosts a fake endpoint.
export async function protoAsync(
  args: string[],
  opts: { env?: Record<string, string>; onStart?: (p: ReturnType<typeof Bun.spawn>) => void | Promise<void> } = {},
): Promise<Ran> {
  const t0 = performance.now();
  const p = Bun.spawn([...PROTO, ...args], { stdin: "ignore", stdout: "pipe", stderr: "pipe", env: opts.env ?? cleanEnv() });
  const outP = new Response(p.stdout as ReadableStream).arrayBuffer();
  const errP = new Response(p.stderr as ReadableStream).text();
  if (opts.onStart) await opts.onStart(p);
  await p.exited;
  const ms = performance.now() - t0;
  const stdout = new Uint8Array(await outP);
  return {
    code: p.exitCode, signal: (p.signalCode as string | null) ?? null, stdout,
    stderr: await errP, stdoutText: new TextDecoder().decode(stdout), ms,
  };
}

const schema = JSON.parse(readFileSync(join(ROOT, "schemas/g02/result.schema.json"), "utf8"));
const ajv = new Ajv2020({ strict: false, allErrors: true });
const validateFn = ajv.compile(schema);

// Exactly one JSON document followed by "\n", schema-valid, no ANSI escapes.
export function parseResult(stdoutText: string): Record<string, any> {
  if (!stdoutText.endsWith("\n")) throw new Error("stdout does not end with newline");
  const body = stdoutText.slice(0, -1);
  if (body.includes("\n")) throw new Error("stdout has more than one line");
  if (body.includes("\u001b")) throw new Error("stdout contains ESC");
  const doc: Record<string, any> = JSON.parse(body);
  if (!validateFn(doc)) throw new Error("schema invalid: " + JSON.stringify(validateFn.errors));
  return doc;
}

export function tempDir(): { dir: string; spaced: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "g02ts-"));
  const spaced = join(dir, "spaced dir ü");
  mkdirSync(spaced);
  return { dir, spaced, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

export const sleep = (ms: number) => Bun.sleep(ms);

export async function waitFor(pred: () => boolean, timeoutMs: number, stepMs = 10): Promise<boolean> {
  const end = performance.now() + timeoutMs;
  while (performance.now() < end) {
    if (pred()) return true;
    await Bun.sleep(stepMs);
  }
  return pred();
}
