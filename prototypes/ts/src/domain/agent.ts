// SSH agent protocol (draft-miller-ssh-agent) request/response codec for the
// G02 probe (contract §3). Pure: no I/O. All lengths are checked against the
// bytes actually present before any slice/allocation.

import { createHash } from "node:crypto";
import { sanitize } from "./result.ts";

export const SSH_AGENT_FAILURE = 5;
export const SSH_AGENTC_REQUEST_IDENTITIES = 11;
export const SSH_AGENT_IDENTITIES_ANSWER = 12;
export const MAX_FRAME = 262_144;
export const MAX_KEYS = 1_024;

export interface Identity {
  key_type: string;
  fingerprint: string;
  comment: string;
}

export type FrameOutcome =
  | { kind: "identities"; identities: Identity[] }
  | { kind: "refused" }
  | { kind: "protocol_error"; message: string };

export function requestIdentitiesFrame(): Uint8Array {
  return new Uint8Array([0, 0, 0, 1, SSH_AGENTC_REQUEST_IDENTITIES]);
}

// Incremental framing: returns the declared body length once 4 bytes are present,
// or an error if it exceeds the bound. Never allocates from the untrusted length.
export type HeaderCheck = { state: "need_more" } | { state: "too_large" } | { state: "ok"; length: number };

export function checkHeader(buf: Uint8Array): HeaderCheck {
  if (buf.byteLength < 4) return { state: "need_more" };
  const len = new DataView(buf.buffer, buf.byteOffset, 4).getUint32(0, false);
  if (len > MAX_FRAME) return { state: "too_large" };
  return { state: "ok", length: len };
}

const utf8Lossy = new TextDecoder("utf-8", { fatal: false });
const text = (b: Uint8Array) => sanitize(utf8Lossy.decode(b));

class Reader {
  private off = 0;
  private view: DataView;
  constructor(private b: Uint8Array) {
    this.view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  }
  remaining(): number {
    return this.b.byteLength - this.off;
  }
  u8(): number {
    if (this.remaining() < 1) throw new ProtoErr("truncated frame");
    return this.b[this.off++]!;
  }
  u32(): number {
    if (this.remaining() < 4) throw new ProtoErr("truncated frame");
    const v = this.view.getUint32(this.off, false);
    this.off += 4;
    return v;
  }
  str(): Uint8Array {
    const n = this.u32();
    if (n > this.remaining()) throw new ProtoErr("string length exceeds remaining frame");
    const s = this.b.subarray(this.off, this.off + n);
    this.off += n;
    return s;
  }
}

class ProtoErr extends Error {}

export function fingerprint(blob: Uint8Array): string {
  return "SHA256:" + createHash("sha256").update(blob).digest("base64").replace(/=+$/, "");
}

// Parse a complete frame body (the bytes after the 4-byte length).
export function parseResponseBody(body: Uint8Array): FrameOutcome {
  try {
    const r = new Reader(body);
    const type = r.u8();
    if (type === SSH_AGENT_FAILURE) {
      if (r.remaining() !== 0) throw new ProtoErr("trailing bytes after failure message");
      return { kind: "refused" };
    }
    if (type !== SSH_AGENT_IDENTITIES_ANSWER) throw new ProtoErr(`unexpected message type ${type}`);
    const nkeys = r.u32();
    if (nkeys > MAX_KEYS) throw new ProtoErr(`nkeys exceeds ${MAX_KEYS}`);
    const identities: Identity[] = [];
    for (let i = 0; i < nkeys; i++) {
      const blob = r.str();
      const comment = r.str();
      const br = new Reader(blob);
      let keyType: Uint8Array;
      try {
        keyType = br.str();
      } catch {
        throw new ProtoErr(`key ${i}: malformed key blob`);
      }
      // K1: invalid UTF-8 and every C0/DEL/C1 control code point become U+FFFD.
      identities.push({ key_type: text(keyType), fingerprint: fingerprint(blob), comment: text(comment) });
    }
    if (r.remaining() !== 0) throw new ProtoErr("trailing bytes after last key");
    return { kind: "identities", identities };
  } catch (e) {
    if (e instanceof ProtoErr) return { kind: "protocol_error", message: e.message };
    throw e;
  }
}

// Parse a full response including its 4-byte length prefix. Used by tests and by
// the client once a complete frame has been buffered.
export function parseResponseFrame(frame: Uint8Array): FrameOutcome {
  const h = checkHeader(frame);
  if (h.state === "need_more") return { kind: "protocol_error", message: "truncated frame" };
  if (h.state === "too_large") return { kind: "protocol_error", message: `frame length exceeds ${MAX_FRAME}` };
  const total = 4 + h.length;
  if (frame.byteLength < total) return { kind: "protocol_error", message: "truncated frame" };
  if (frame.byteLength > total) return { kind: "protocol_error", message: "trailing bytes after frame" };
  return parseResponseBody(frame.subarray(4, total));
}
