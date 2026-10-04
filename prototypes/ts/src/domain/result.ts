// Result envelope shared by every CLI operation (contract §1).
// Pure module: no I/O.

export type State = "succeeded" | "failed" | "cancelled";
export type Code =
  | "PROFILE_OK" | "AGENT_OK" | "VERSION_OK" | "CHILD_EXITED" | "CHILD_LAUNCH_FAILED"
  | "USAGE_ERROR" | "SCHEMA_INVALID" | "INPUT_TOO_LARGE"
  | "AGENT_UNAVAILABLE" | "AGENT_PROTOCOL_ERROR" | "AGENT_REFUSED"
  | "CANCELLED" | "INTERNAL";

export interface Result {
  schema_version: "1";
  state: State;
  code: Code;
  data: Record<string, unknown> | null;
  warnings: string[];
  next: Record<string, unknown> | null;
}

export const EXIT: Record<Code, number> = {
  PROFILE_OK: 0, AGENT_OK: 0, VERSION_OK: 0,
  USAGE_ERROR: 2, SCHEMA_INVALID: 2, INPUT_TOO_LARGE: 2,
  AGENT_UNAVAILABLE: 5, AGENT_PROTOCOL_ERROR: 5, AGENT_REFUSED: 5,
  CANCELLED: 130, INTERNAL: 1,
  // run's exit status is the child's; these are only used in the meta file.
  CHILD_EXITED: 0, CHILD_LAUNCH_FAILED: 127,
};

export function ok(code: Code, data: Record<string, unknown>, warnings: string[] = []): Result {
  return { schema_version: "1", state: "succeeded", code, data, warnings, next: null };
}

export function fail(code: Code, keyPath: string | null, message: string, warnings: string[] = []): Result {
  return {
    schema_version: "1",
    state: code === "CANCELLED" ? "cancelled" : "failed",
    code,
    data: code === "CANCELLED" ? null : { error: { key_path: keyPath, message } },
    warnings,
    next: null,
  };
}

export function cancelled(): Result {
  return { schema_version: "1", state: "cancelled", code: "CANCELLED", data: null, warnings: [], next: null };
}

// Replace every C0 (incl. TAB), DEL and C1 control code point with U+FFFD so no
// machine string can carry a terminal escape sequence (contract §1, ruling K1).
// JSON-escaping them is not enough: the decoded value would still contain them.
export const CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f]/g;
export function sanitize(s: string): string {
  return s.replace(CONTROL_CHARS, "\ufffd");
}

function deepSanitize(v: unknown): unknown {
  if (typeof v === "string") return sanitize(v);
  if (Array.isArray(v)) return v.map(deepSanitize);
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v)) out[k] = deepSanitize(x);
    return out;
  }
  return v;
}

export function serialize(r: Result): string {
  return JSON.stringify(deepSanitize(r)) + "\n";
}
