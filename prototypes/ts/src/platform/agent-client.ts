// Agent endpoint I/O (contract §3). Unix: Unix-domain socket. Windows: named pipe
// path (\\.\pipe\...) through node:net, which Bun maps to libuv pipes.
// Windows path: compile-checked only (see REPORT.md).

import { connect, type Socket } from "node:net";
import { checkHeader, MAX_FRAME, parseResponseBody, requestIdentitiesFrame } from "../domain/agent.ts";
import { fail, ok, type Result } from "../domain/result.ts";

// `abort` closes the connection and leaves `done` unresolved (the caller reports CANCELLED).
export function probeAgent(path: string, timeoutMs: number): { done: Promise<Result>; abort: () => void } {
  let sock: Socket | null = null;
  let settled = false;
  let resolveFn!: (r: Result) => void;
  const done = new Promise<Result>((res) => (resolveFn = res));
  const finish = (r: Result) => {
    if (settled) return;
    settled = true;
    clearTimeout(timer);
    sock?.destroy();
    resolveFn(r);
  };
  const timer = setTimeout(
    () => finish(fail("AGENT_UNAVAILABLE", null, `no complete response within ${timeoutMs} ms`)),
    timeoutMs,
  );

  // Buffer is allocated only after the header has been validated against MAX_FRAME.
  const header = new Uint8Array(4);
  let headerHave = 0;
  let body: Uint8Array | null = null;
  let bodyHave = 0;
  let received = 0;

  try {
    sock = connect({ path });
  } catch {
    finish(fail("AGENT_UNAVAILABLE", null, "could not connect to agent endpoint"));
    return { done, abort: () => {} };
  }
  sock.on("connect", () => sock!.write(requestIdentitiesFrame()));
  sock.on("error", () => {
    finish(received > 0
      ? fail("AGENT_PROTOCOL_ERROR", null, "connection error mid-frame")
      : fail("AGENT_UNAVAILABLE", null, "could not connect to agent endpoint"));
  });
  sock.on("data", (chunk: Buffer) => {
    if (settled) return;
    received += chunk.byteLength;
    let off = 0;
    if (headerHave < 4) {
      const take = Math.min(4 - headerHave, chunk.byteLength);
      header.set(chunk.subarray(0, take), headerHave);
      headerHave += take;
      off = take;
      if (headerHave < 4) return;
      const h = checkHeader(header);
      if (h.state === "too_large") return finish(fail("AGENT_PROTOCOL_ERROR", null, `frame length exceeds ${MAX_FRAME}`));
      if (h.state !== "ok") return;
      body = new Uint8Array(h.length);
    }
    const rest = chunk.byteLength - off;
    const need = body!.byteLength - bodyHave;
    if (rest > need) return finish(fail("AGENT_PROTOCOL_ERROR", null, "trailing bytes after frame"));
    body!.set(chunk.subarray(off), bodyHave);
    bodyHave += rest;
    if (bodyHave === body!.byteLength) complete();
  });
  sock.on("end", () => {
    if (!settled) {
      finish(received > 0
        ? fail("AGENT_PROTOCOL_ERROR", null, "truncated frame")
        : fail("AGENT_UNAVAILABLE", null, "agent closed the connection without a response"));
    }
  });

  function complete() {
    const out = parseResponseBody(body!);
    if (out.kind === "identities") finish(ok("AGENT_OK", { identities: out.identities }));
    else if (out.kind === "refused") finish(fail("AGENT_REFUSED", null, "agent returned SSH_AGENT_FAILURE"));
    else finish(fail("AGENT_PROTOCOL_ERROR", null, out.message));
  }

  return {
    done,
    abort: () => {
      settled = true;
      clearTimeout(timer);
      sock?.destroy();
    },
  };
}
