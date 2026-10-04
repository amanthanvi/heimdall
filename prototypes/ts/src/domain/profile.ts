// Profile parsing and validation (contract §2). Pure: takes bytes, returns a Result.
// Error messages may name key paths but never values (canary rule).

import { parse, TomlError } from "smol-toml";
import { fail, ok, type Result } from "./result.ts";

export const MAX_PROFILE_BYTES = 1_048_576;

export interface Destination {
  id: string;
  alias: string;
  host: string;
  port: number;
  account: string;
  labels: string[];
}

export interface Profile {
  name: string;
  revision: number;
  destinations: Destination[];
}

const TOP_KEYS = new Set(["schema_version", "name", "revision", "meta", "destinations"]);
const DEST_KEYS = new Set(["id", "alias", "host", "port", "account", "labels"]);

class Invalid extends Error {
  constructor(readonly keyPath: string | null, message: string, readonly warnings: string[] = []) {
    super(message);
  }
}

function isTable(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v) && !(v instanceof Date);
}

// smol-toml is called with integersAsBigInt:true, so TOML integers are bigint and
// TOML floats are number. That is the only way to reject `revision = 1.0`.
function int(v: unknown, path: string, min: number, max: number): number {
  if (typeof v !== "bigint") throw new Invalid(path, `${path} must be an integer`);
  if (v < BigInt(min) || v > BigInt(max)) throw new Invalid(path, `${path} must be in ${min}..${max}`);
  return Number(v);
}

// K2: a string value outside [meta] containing a C0, DEL or C1 control code point is
// rejected; the message names the key, never the value.
function noControl(v: string, path: string): string {
  if (/[\u0000-\u001f\u007f-\u009f]/.test(v)) throw new Invalid(path, `${path} contains a control character`);
  return v;
}

function str(v: unknown, path: string): string {
  if (typeof v !== "string" || v.length === 0) throw new Invalid(path, `${path} must be a non-empty string`);
  return noControl(v, path);
}

function req(t: Record<string, unknown>, key: string, path: string): unknown {
  if (!Object.hasOwn(t, key)) throw new Invalid(path, `${path} is required`);
  return t[key];
}

function validate(doc: Record<string, unknown>): Profile {
  // Unknown keys first, so a forbidden key is reported even if other fields are bad.
  for (const k of Object.keys(doc)) {
    if (!TOP_KEYS.has(k)) throw new Invalid(k, `unknown key ${k}`);
  }
  if (!Object.hasOwn(doc, "schema_version")) throw new Invalid("schema_version", "schema_version is required");
  const sv = doc.schema_version;
  if (typeof sv !== "bigint" || sv !== 1n) {
    // Name the unsupported version only when it is an integer; a string value is
    // never echoed (it could carry secret material).
    const named = typeof sv === "bigint" ? `unsupported schema_version ${sv}` : "unsupported schema_version (not an integer)";
    throw new Invalid("schema_version", named, [`${named}; this build supports schema_version 1 only`]);
  }
  const name = str(req(doc, "name", "name"), "name");
  const revision = int(req(doc, "revision", "revision"), "revision", 1, Number.MAX_SAFE_INTEGER);
  if (Object.hasOwn(doc, "meta") && !isTable(doc.meta)) throw new Invalid("meta", "meta must be a table");

  const rawDests = Object.hasOwn(doc, "destinations") ? doc.destinations : [];
  if (!Array.isArray(rawDests)) throw new Invalid("destinations", "destinations must be an array of tables");

  const destinations: Destination[] = [];
  const ids = new Set<string>();
  const aliases = new Set<string>();
  rawDests.forEach((d, i) => {
    const p = `destinations[${i}]`;
    if (!isTable(d)) throw new Invalid(p, `${p} must be a table`);
    for (const k of Object.keys(d)) {
      if (!DEST_KEYS.has(k)) throw new Invalid(`${p}.${k}`, `unknown key ${p}.${k}`);
    }
    const id = str(req(d, "id", `${p}.id`), `${p}.id`);
    const alias = str(req(d, "alias", `${p}.alias`), `${p}.alias`);
    const host = str(req(d, "host", `${p}.host`), `${p}.host`);
    const account = str(req(d, "account", `${p}.account`), `${p}.account`);
    const port = Object.hasOwn(d, "port") ? int(d.port, `${p}.port`, 1, 65535) : 22;
    let labels: string[] = [];
    if (Object.hasOwn(d, "labels")) {
      const l = d.labels;
      if (!Array.isArray(l)) throw new Invalid(`${p}.labels`, `${p}.labels must be an array of strings`);
      labels = l.map((x, j) => {
        if (typeof x !== "string") throw new Invalid(`${p}.labels[${j}]`, `${p}.labels[${j}] must be a string`);
        return noControl(x, `${p}.labels[${j}]`);
      });
    }
    if (ids.has(id)) throw new Invalid(`${p}.id`, `duplicate id at ${p}.id`);
    if (aliases.has(alias)) throw new Invalid(`${p}.alias`, `duplicate alias at ${p}.alias`);
    ids.add(id);
    aliases.add(alias);
    destinations.push({ id, alias, host, port, account, labels });
  });
  return { name, revision, destinations };
}

export type ParseOutcome = { ok: true; profile: Profile; result: Result } | { ok: false; result: Result };

// Parse already-read bytes. Size is checked by the caller before reading where
// possible (so we never read an oversize file into memory); checked again here.
export function parseProfile(bytes: Uint8Array): ParseOutcome {
  if (bytes.byteLength > MAX_PROFILE_BYTES) {
    return { ok: false, result: fail("INPUT_TOO_LARGE", null, `profile exceeds ${MAX_PROFILE_BYTES} bytes`) };
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return { ok: false, result: fail("SCHEMA_INVALID", null, "profile is not valid UTF-8") };
  }
  let doc: unknown;
  try {
    doc = parse(text, { integersAsBigInt: true });
  } catch (e) {
    // TomlError.message contains a source excerpt (i.e. values). Emit position only.
    if (e instanceof TomlError) {
      return { ok: false, result: fail("SCHEMA_INVALID", null, `malformed TOML at line ${e.line}, column ${e.column}`) };
    }
    return { ok: false, result: fail("SCHEMA_INVALID", null, "malformed TOML") };
  }
  try {
    const profile = validate(doc as Record<string, unknown>);
    return { ok: true, profile, result: ok("PROFILE_OK", { profile }) };
  } catch (e) {
    if (e instanceof Invalid) return { ok: false, result: fail("SCHEMA_INVALID", e.keyPath, e.message, e.warnings) };
    throw e;
  }
}
