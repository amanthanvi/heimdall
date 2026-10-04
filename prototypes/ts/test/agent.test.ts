import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createServer, type Server, type Socket } from "node:net";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fingerprint, MAX_FRAME, parseResponseFrame } from "../src/domain/agent.ts";
import { cleanEnv, parseResult, protoAsync, tempDir, waitFor } from "./helpers.ts";

// ---- wire helpers -------------------------------------------------------------
const u32 = (n: number) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, false); return b; };
const cat = (...xs: Uint8Array[]) => { const o = new Uint8Array(xs.reduce((a, x) => a + x.byteLength, 0)); let i = 0; for (const x of xs) { o.set(x, i); i += x.byteLength; } return o; };
const str = (b: Uint8Array | string) => { const v = typeof b === "string" ? new TextEncoder().encode(b) : b; return cat(u32(v.byteLength), v); };
const frame = (body: Uint8Array) => cat(u32(body.byteLength), body);
const answer = (keys: [Uint8Array, Uint8Array | string][]) => frame(cat(new Uint8Array([12]), u32(keys.length), ...keys.flatMap(([blob, c]) => [str(blob), str(c)])));
const fakeBlob = (type = "ssh-ed25519", extra = 32) => cat(str(type), str(new Uint8Array(extra).fill(7)));

describe("agent frame parser (domain, crafted frames)", () => {
  test("valid answer with two keys", () => {
    const b1 = fakeBlob("ssh-ed25519");
    const b2 = fakeBlob("ecdsa-sha2-nistp256", 65);
    const out = parseResponseFrame(answer([[b1, "one"], [b2, "two ü"]]));
    expect(out).toEqual({ kind: "identities", identities: [
      { key_type: "ssh-ed25519", fingerprint: fingerprint(b1), comment: "one" },
      { key_type: "ecdsa-sha2-nistp256", fingerprint: fingerprint(b2), comment: "two ü" },
    ] });
  });
  test("zero keys", () => expect(parseResponseFrame(answer([]))).toEqual({ kind: "identities", identities: [] }));
  test("invalid UTF-8 comment → U+FFFD", () => {
    const out = parseResponseFrame(answer([[fakeBlob(), new Uint8Array([0x61, 0xff, 0x62])]]));
    expect(out.kind === "identities" && out.identities[0]!.comment).toBe("a�b");
  });
  test("K1: C0 (incl. TAB, NUL, ESC), DEL and C1 in comment become U+FFFD", () => {
    const raw = cat(new TextEncoder().encode("a\x1b[31mb\tc\x00d\x7fe\u0085f\u009bg"), new Uint8Array([0xff]));
    const out = parseResponseFrame(answer([[fakeBlob(), raw]]));
    expect(out.kind === "identities" && out.identities[0]!.comment).toBe("a\ufffd[31mb\ufffdc\ufffdd\ufffde\ufffdf\ufffdg\ufffd");
  });
  test("K1: key_type with invalid UTF-8 and control chars → U+FFFD (not a protocol error)", () => {
    const blob = cat(str(cat(new TextEncoder().encode("ssh-\x1bx"), new Uint8Array([0xc3]))), str(new Uint8Array(32)));
    const out = parseResponseFrame(answer([[blob, "c"]]));
    expect(out.kind).toBe("identities");
    expect(out.kind === "identities" && out.identities[0]!.key_type).toBe("ssh-\ufffdx\ufffd");
  });
  test("SSH_AGENT_FAILURE → refused", () => expect(parseResponseFrame(frame(new Uint8Array([5])))).toEqual({ kind: "refused" }));
  const bad: [string, Uint8Array][] = [
    ["oversize length (MAX+1)", cat(u32(MAX_FRAME + 1), new Uint8Array(8))],
    ["oversize length 0xffffffff", u32(0xffffffff)],
    ["huge nkeys 0xffffffff", frame(cat(new Uint8Array([12]), u32(0xffffffff)))],
    ["nkeys 1025", frame(cat(new Uint8Array([12]), u32(1025)))],
    ["nkeys says 2, only 1 present", frame(cat(new Uint8Array([12]), u32(2), str(fakeBlob()), str("c")))],
    ["blob length exceeds remaining", frame(cat(new Uint8Array([12]), u32(1), u32(1000), new Uint8Array(10)))],
    ["comment length exceeds remaining", frame(cat(new Uint8Array([12]), u32(1), str(fakeBlob()), u32(50), new Uint8Array(3)))],
    ["key type length exceeds blob", frame(cat(new Uint8Array([12]), u32(1), str(cat(u32(999), new Uint8Array(4))), str("c")))],
    ["trailing bytes after last key (inside frame)", frame(cat(new Uint8Array([12]), u32(1), str(fakeBlob()), str("c"), new Uint8Array([0])))],
    ["trailing bytes after frame", cat(answer([]), new Uint8Array([0]))],
    ["truncated header", new Uint8Array([0, 0])],
    ["truncated body", cat(u32(100), new Uint8Array(10))],
    ["empty body", u32(0)],
    ["wrong type 6 (success)", frame(new Uint8Array([6]))],
    ["wrong type 14 (sign response)", frame(cat(new Uint8Array([14]), str("x")))],
    ["failure with payload", frame(new Uint8Array([5, 0]))],
  ];
  for (const [name, f] of bad) {
    test(`${name} → protocol_error`, () => expect(parseResponseFrame(f).kind).toBe("protocol_error"));
  }
  test("frame of exactly MAX_FRAME bytes is accepted", () => {
    const fixed = 1 + 4 + 4 + 4; // type + nkeys + blob len + comment len
    const blobHead = str("ssh-ed25519");
    const blob = cat(blobHead, new Uint8Array(MAX_FRAME - fixed - blobHead.byteLength - 10));
    const f = answer([[blob, "0123456789"]]);
    expect(f.byteLength).toBe(4 + MAX_FRAME);
    expect(parseResponseFrame(f).kind).toBe("identities");
  });
});

// ---- fake agent endpoint (Unix socket in a temp dir) ------------------------------
type Behavior = (sock: Socket, req: Uint8Array) => void;
let t: ReturnType<typeof tempDir>;
let server: Server;
let sockPath: string;
let behavior: Behavior = () => {};
let lastRequest: Uint8Array = new Uint8Array();
let connections = 0;

beforeAll(async () => {
  t = tempDir();
  sockPath = join(t.spaced, "agent ü.sock");
  server = createServer((sock) => {
    connections++;
    const chunks: Uint8Array[] = [];
    let fired = false;
    sock.on("data", (d: Buffer) => {
      chunks.push(new Uint8Array(d));
      lastRequest = cat(...chunks);
      if (!fired && lastRequest.byteLength >= 5) { fired = true; behavior(sock, lastRequest); }
    });
    sock.on("error", () => {});
  });
  await new Promise<void>((res) => server.listen(sockPath, res));
});
afterAll(() => { server.close(); t.cleanup(); });

const list = (extra: string[] = []) => protoAsync(["agent", "list", "--socket", sockPath, "--json", ...extra]);

describe("agent list against fake endpoint", () => {
  test("AGENT_OK; request is exactly one type-11 frame", async () => {
    const blob = fakeBlob();
    behavior = (s) => s.write(answer([[blob, "fixture ü"]]));
    const r = await list();
    expect(r.code).toBe(0);
    const doc = parseResult(r.stdoutText);
    expect(doc.code).toBe("AGENT_OK");
    expect(doc.data.identities).toEqual([{ key_type: "ssh-ed25519", fingerprint: fingerprint(blob), comment: "fixture ü" }]);
    expect(Array.from(lastRequest)).toEqual([0, 0, 0, 1, 11]);
  });
  test("K1: decoded JSON strings contain no C0/DEL/C1 code points", async () => {
    const blob = cat(str("ssh-ed25519\x07"), str(new Uint8Array(32)));
    behavior = (s) => s.write(answer([[blob, cat(new TextEncoder().encode("\x1b]0;pwn\x07 tab\t del\x7f c1\u0085"), new Uint8Array([0x80]))]]));
    const r = await list();
    expect(r.code).toBe(0);
    const doc = parseResult(r.stdoutText);
    const id = doc.data.identities[0];
    expect(id.key_type).toBe("ssh-ed25519\ufffd");
    expect(id.comment).toBe("\ufffd]0;pwn\ufffd tab\ufffd del\ufffd c1\ufffd\ufffd");
    expect(/[\u0000-\u001f\u007f-\u009f]/.test(id.comment + id.key_type)).toBe(false);
    expect(r.stdoutText).not.toContain("\\u00"); // not JSON-escaped either
  });
  test("K3: peer closes after reading the request, before any byte → AGENT_UNAVAILABLE", async () => {
    behavior = (s) => s.end();
    const r = await list();
    expect(r.code).toBe(5);
    expect(parseResult(r.stdoutText).code).toBe("AGENT_UNAVAILABLE");
  });
  test("K3: peer resets after reading the request, before any byte → AGENT_UNAVAILABLE", async () => {
    behavior = (s) => (s as any).resetAndDestroy();
    const r = await list();
    expect(r.code).toBe(5);
    expect(parseResult(r.stdoutText).code).toBe("AGENT_UNAVAILABLE");
  });
  test("K3: 1 byte then close → AGENT_PROTOCOL_ERROR; 1 byte then reset → AGENT_PROTOCOL_ERROR", async () => {
    behavior = (s) => { s.write(new Uint8Array([0])); setTimeout(() => s.end(), 20); };
    let r = await list();
    expect(r.code).toBe(5);
    expect(parseResult(r.stdoutText).code).toBe("AGENT_PROTOCOL_ERROR");
    behavior = (s) => { s.write(new Uint8Array([0])); setTimeout(() => (s as any).resetAndDestroy(), 20); };
    r = await list();
    expect(r.code).toBe(5);
    expect(parseResult(r.stdoutText).code).toBe("AGENT_PROTOCOL_ERROR");
  });
  test("K4: type-5 frame with a payload → AGENT_PROTOCOL_ERROR (not AGENT_REFUSED)", async () => {
    behavior = (s) => s.write(frame(new Uint8Array([5, 0])));
    const r = await list();
    expect(r.code).toBe(5);
    expect(parseResult(r.stdoutText).code).toBe("AGENT_PROTOCOL_ERROR");
  });
  test("response split into 1-byte writes is reassembled", async () => {
    const f = answer([[fakeBlob(), "c"]]);
    behavior = (s) => { let i = 0; const tick = () => { if (i < f.length) { s.write(f.subarray(i, ++i)); setTimeout(tick, 1); } }; tick(); };
    const r = await list();
    expect(parseResult(r.stdoutText).code).toBe("AGENT_OK");
  });
  test("SSH_AGENT_FAILURE → exit 5 AGENT_REFUSED", async () => {
    behavior = (s) => s.write(frame(new Uint8Array([5])));
    const r = await list();
    expect(r.code).toBe(5);
    expect(parseResult(r.stdoutText).code).toBe("AGENT_REFUSED");
  });
  test("oversize header → exit 5 AGENT_PROTOCOL_ERROR without waiting for body", async () => {
    behavior = (s) => s.write(u32(MAX_FRAME + 1)); // body never sent
    const r = await list(["--timeout-ms", "3000"]);
    expect(r.code).toBe(5);
    expect(parseResult(r.stdoutText).code).toBe("AGENT_PROTOCOL_ERROR");
    expect(r.ms).toBeLessThan(2500);
  });
  test("huge nkeys → AGENT_PROTOCOL_ERROR", async () => {
    behavior = (s) => s.write(frame(cat(new Uint8Array([12]), u32(0xffffffff))));
    expect(parseResult((await list()).stdoutText).code).toBe("AGENT_PROTOCOL_ERROR");
  });
  test("truncated frame then close → AGENT_PROTOCOL_ERROR", async () => {
    behavior = (s) => { s.write(cat(u32(100), new Uint8Array(10))); s.end(); };
    const r = await list();
    expect(r.code).toBe(5);
    expect(parseResult(r.stdoutText).code).toBe("AGENT_PROTOCOL_ERROR");
  });
  test("extra bytes after frame → AGENT_PROTOCOL_ERROR", async () => {
    behavior = (s) => s.write(cat(answer([]), new Uint8Array([1, 2, 3])));
    expect(parseResult((await list()).stdoutText).code).toBe("AGENT_PROTOCOL_ERROR");
  });
  test("unexpected type → AGENT_PROTOCOL_ERROR", async () => {
    behavior = (s) => s.write(frame(new Uint8Array([6])));
    expect(parseResult((await list()).stdoutText).code).toBe("AGENT_PROTOCOL_ERROR");
  });
  test("no response → AGENT_UNAVAILABLE after --timeout-ms", async () => {
    behavior = () => {};
    const r = await list(["--timeout-ms", "300"]);
    expect(r.code).toBe(5);
    expect(parseResult(r.stdoutText).code).toBe("AGENT_UNAVAILABLE");
    expect(r.ms).toBeGreaterThanOrEqual(290);
    expect(r.ms).toBeLessThan(2000);
  });
  test("missing socket → AGENT_UNAVAILABLE", async () => {
    const r = await protoAsync(["agent", "list", "--socket", join(t.spaced, "absent.sock"), "--json"]);
    expect(r.code).toBe(5);
    expect(parseResult(r.stdoutText).code).toBe("AGENT_UNAVAILABLE");
  });
  test("SIGINT while waiting → CANCELLED, exit 130 within 500 ms", async () => {
    behavior = () => {};
    const before = connections;
    let sentAt = 0;
    const r = await protoAsync(["agent", "list", "--socket", sockPath, "--timeout-ms", "10000", "--json"], {
      onStart: async (p) => {
        expect(await waitFor(() => connections > before && lastRequest.byteLength >= 5, 5000)).toBe(true);
        sentAt = performance.now();
        p.kill("SIGINT");
      },
    });
    const latency = performance.now() - sentAt;
    expect(r.code).toBe(130);
    const doc = parseResult(r.stdoutText);
    expect(doc.code).toBe("CANCELLED");
    expect(doc.state).toBe("cancelled");
    expect(latency).toBeLessThan(500);
    console.log(`[evidence] agent SIGINT→exit latency ${latency.toFixed(1)} ms`);
  });
  test("bad --timeout-ms → USAGE_ERROR JSON with --json", async () => {
    const r = await list(["--timeout-ms", "abc"]);
    expect(r.code).toBe(2);
    expect(parseResult(r.stdoutText).code).toBe("USAGE_ERROR");
  });
});

describe("agent list against disposable /usr/bin/ssh-agent fixture", () => {
  test("fingerprint and key type match ssh-keygen -l", async () => {
    const d = tempDir();
    const asock = join(d.spaced, "a.sock");
    const key = join(d.spaced, "id_fixture");
    const agent = Bun.spawn(["/usr/bin/ssh-agent", "-D", "-a", asock], { stdout: "ignore", stderr: "ignore", env: cleanEnv() });
    try {
      const kg = Bun.spawnSync(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "fixture comment ü", "-f", key], { env: cleanEnv() });
      expect(kg.exitCode).toBe(0);
      expect(await waitFor(() => { try { return Bun.spawnSync(["/bin/test", "-S", asock]).exitCode === 0; } catch { return false; } }, 3000)).toBe(true);
      const add = Bun.spawnSync(["/usr/bin/ssh-add", key], { env: cleanEnv({ SSH_AUTH_SOCK: asock }), stderr: "pipe" });
      expect(add.exitCode).toBe(0);
      const lf = new TextDecoder().decode(Bun.spawnSync(["/usr/bin/ssh-keygen", "-l", "-E", "sha256", "-f", key + ".pub"]).stdout as Uint8Array);
      const expectedFp = lf.split(" ")[1];
      const r = await protoAsync(["agent", "list", "--socket", asock, "--json"]);
      expect(r.code).toBe(0);
      const ids = parseResult(r.stdoutText).data.identities;
      expect(ids).toEqual([{ key_type: "ssh-ed25519", fingerprint: expectedFp, comment: "fixture comment ü" }]);
      expect(r.stdoutText).not.toContain(readFileSync(key + ".pub", "utf8").split(" ")[1]!); // no raw blob
    } finally {
      agent.kill("SIGTERM"); // exact child we spawned
      await agent.exited;
      d.cleanup();
    }
  });
});
