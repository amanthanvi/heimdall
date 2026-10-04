// End-to-end TUI tests under a real PTY (Bun.spawn terminal). The proto runs inside a
// /bin/sh wrapper that records `stty -g` before and after, so termios restoration is
// checked by the terminal driver itself.
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { cleanEnv, FIXTURES, proto, PROTO, tempDir, waitFor } from "./helpers.ts";
import { renderScreen, type ResizeMark } from "./vt.ts";

const HOMELAB = join(FIXTURES, "homelab.toml");
const LARGE = join(FIXTURES, "large-100.toml");
const KEYS: Record<string, string> = { ENTER: "\r", CTRLC: "\x03", ESC: "\x1b", BS: "\x7f", UP: "\x1b[A", DOWN: "\x1b[B" };

interface Session {
  out: () => string;
  len: () => number;
  write: (k: string) => void;
  resize: (c: number, r: number) => void;
  screen: () => string[];
  screenHas: (text: string) => boolean;
  protoPid: () => number | null;
  exited: Promise<number | null>;
  sttyBefore: () => string;
  sttyAfter: () => string;
  status: () => string;
  cleanup: () => void;
}

function startTui(file: string, opts: { cols?: number; rows?: number; env?: Record<string, string> } = {}): Session {
  const t = tempDir();
  const before = join(t.spaced, "before");
  const after = join(t.spaced, "after");
  const status = join(t.spaced, "status");
  const q = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;
  const cmd = [...PROTO, "tui", "--file", file].map(q).join(" ");
  const script = `stty -g > ${q(before)}; ${cmd}; echo $? > ${q(status)}; stty -g > ${q(after)}`;
  let buf = "";
  const decoder = new TextDecoder();
  const cols0 = opts.cols ?? 80;
  const rows0 = opts.rows ?? 10;
  const marks: ResizeMark[] = [];
  const sh = Bun.spawn(["/bin/sh", "-c", script], {
    env: cleanEnv({ TERM: "xterm-256color", ...(opts.env ?? {}) }),
    terminal: { cols: cols0, rows: rows0, data(_t: unknown, d: Uint8Array) { buf += decoder.decode(d, { stream: true }); } },
  } as any);
  const read = (p: string) => { try { return readFileSync(p, "utf8").trim(); } catch { return ""; } };
  return {
    out: () => buf,
    len: () => buf.length,
    write: (k) => (sh as any).terminal.write(KEYS[k] ?? k),
    resize: (c, r) => { marks.push({ pos: buf.length, cols: c, rows: r }); (sh as any).terminal.resize(c, r); },
    screen: () => renderScreen(buf, cols0, rows0, marks),
    screenHas: (text) => renderScreen(buf, cols0, rows0, marks).some((l) => l.includes(text)),
    protoPid: () => {
      // Exact PPID match on the wrapper shell we spawned (no name/pattern matching).
      const ps = new TextDecoder().decode(Bun.spawnSync(["/bin/ps", "-ax", "-o", "pid=,ppid="]).stdout as Uint8Array);
      for (const line of ps.trim().split("\n")) {
        const [pid, ppid] = line.trim().split(/\s+/).map(Number);
        if (ppid === sh.pid) return pid!;
      }
      return null;
    },
    exited: sh.exited.then(() => sh.exitCode),
    sttyBefore: () => read(before),
    sttyAfter: () => read(after),
    status: () => read(status),
    cleanup: () => { try { sh.kill("SIGKILL"); } catch {} t.cleanup(); },
  };
}

const ready = (s: Session) => waitFor(() => s.screenHas("filter:"), 8000);
const ALT_ON = "\x1b[?1049h";
const ALT_OFF = "\x1b[?1049l";
const CURSOR_HIDE = "\x1b[?25l";
const CURSOR_SHOW = "\x1b[?25h";
// Any SGR containing a color parameter (30-49, 90-107, 38/48 extended).
const COLOR_SGR = /\x1b\[(?:[0-9;:]*;)?(?:3[0-9]|4[0-9]|9[0-7]|10[0-7])(?:[;:][0-9;:]*)?m/;

async function finish(s: Session, timeoutMs = 5000): Promise<void> {
  const t = setTimeout(() => s.cleanup(), timeoutMs);
  await s.exited;
  clearTimeout(t);
}

function assertRestored(s: Session): void {
  const o = s.out();
  expect(o).toContain(ALT_ON);
  expect(o).toContain(CURSOR_HIDE);
  expect(o.lastIndexOf(ALT_OFF)).toBeGreaterThan(o.lastIndexOf(ALT_ON));
  expect(o.lastIndexOf(CURSOR_SHOW)).toBeGreaterThan(o.lastIndexOf(CURSOR_HIDE));
  expect(s.sttyBefore().length).toBeGreaterThan(0);
  expect(s.sttyAfter()).toBe(s.sttyBefore());
}

describe("tui under PTY", () => {
  test("select: j + Enter → SELECTED nas after leaving alt screen, exit 0, termios restored", async () => {
    const s = startTui(HOMELAB);
    try {
      expect(await ready(s)).toBe(true);
      expect(s.screen()[0]).toBe("> lab-server  aman@lab.example.internal:22");
      expect(s.screen()[9]).toBe("3/3 filter:");
      s.write("j");
      expect(await waitFor(() => s.screen()[1] === "> nas  admin@nas.example.internal:22", 2000)).toBe(true);
      expect(s.screen()[0]).toBe("  lab-server  aman@lab.example.internal:22");
      s.write("ENTER");
      await finish(s);
      expect(s.status()).toBe("0");
      const o = s.out();
      expect(o).toContain("SELECTED nas\r\n");
      expect(o.indexOf("SELECTED nas")).toBeGreaterThan(o.lastIndexOf(ALT_OFF));
      assertRestored(s);
    } finally { s.cleanup(); }
  });

  test("quit with q → exit 0, nothing selected", async () => {
    const s = startTui(HOMELAB);
    try {
      expect(await ready(s)).toBe(true);
      s.write("q");
      await finish(s);
      expect(s.status()).toBe("0");
      expect(s.out()).not.toContain("SELECTED");
      assertRestored(s);
    } finally { s.cleanup(); }
  });

  test("Ctrl-C → exit 130, restored", async () => {
    const s = startTui(HOMELAB);
    try {
      expect(await ready(s)).toBe(true);
      s.write("CTRLC");
      await finish(s);
      expect(s.status()).toBe("130");
      assertRestored(s);
    } finally { s.cleanup(); }
  });

  for (const [sig, code] of [["SIGTERM", "143"], ["SIGINT", "130"], ["SIGHUP", "129"]] as const) {
    test(`${sig} from outside → exit ${code}, restored`, async () => {
      const s = startTui(HOMELAB);
      try {
        expect(await ready(s)).toBe(true);
        const pid = s.protoPid();
        expect(pid).not.toBeNull();
        process.kill(pid!, sig);
        await finish(s);
        expect(s.status()).toBe(code);
        expect(s.out()).not.toContain("SELECTED"); // K10: no stdout on these paths
        assertRestored(s);
      } finally { s.cleanup(); }
    });
  }

  test("K10: terminal hangup (PTY master closed) → exit 129, no SELECTED", async () => {
    let out = "";
    const p = Bun.spawn([...PROTO, "tui", "--file", HOMELAB], {
      env: cleanEnv({ TERM: "xterm-256color" }),
      terminal: { cols: 80, rows: 10, data(_t: unknown, d: Uint8Array) { out += new TextDecoder().decode(d); } },
    } as any);
    try {
      expect(await waitFor(() => out.includes("filter:"), 8000)).toBe(true);
      (p as any).terminal.close();
      const k = setTimeout(() => p.kill("SIGKILL"), 5000);
      await p.exited;
      clearTimeout(k);
      expect(p.exitCode).toBe(129);
      expect(out).not.toContain("SELECTED");
    } finally {
      try { p.kill("SIGKILL"); } catch {}
    }
  });

  test("K10: bare terminal hangup (EOF/EIO only, no SIGHUP) → exit 129, no SELECTED", () => {
    // The session leader is not a shell and does not forward the hangup (bare_hangup.py).
    const r = Bun.spawnSync(["python3", join(import.meta.dir, "bare_hangup.py"), ...PROTO, "tui", "--file", HOMELAB], {
      env: cleanEnv({ TERM: "xterm-256color" }),
      stdout: "pipe",
      stderr: "pipe",
    });
    expect(r.exitCode).toBe(0);
    const res = JSON.parse(r.stdout.toString());
    expect(res.frame).toBe(true);
    expect(res.rc).toBe(129);
    expect(res.selected).toBe(false);
  }, 30000);

  test("exception inside the TUI (injected fault) → exit 1, restored", async () => {
    const s = startTui(HOMELAB, { env: { HEIMDALL_PROTO_FAULT: "tui-throw" } });
    try {
      expect(await ready(s)).toBe(true);
      s.write("!");
      await finish(s);
      expect(s.status()).toBe("1");
      expect(s.out()).not.toContain("SELECTED"); // K10
      assertRestored(s);
    } finally { s.cleanup(); }
  });

  test("filter: / + non-ASCII + Backspace + Esc clears", async () => {
    const s = startTui(HOMELAB);
    try {
      expect(await ready(s)).toBe(true);
      s.write("/");
      s.write("東");
      expect(await waitFor(() => s.screenHas("1/3 /東"), 2000)).toBe(true);
      expect(s.screen()[0]).toBe("> vps-東京  deploy@vps1.example.invalid:2222");
      s.write("BS");
      expect(await waitFor(() => s.screen()[9] === "3/3 /", 2000)).toBe(true);
      s.write("n");
      s.write("A");
      expect(await waitFor(() => s.screen()[9] === "2/3 /nA", 2000)).toBe(true); // lab (".internal") and nas
      s.write("S");
      expect(await waitFor(() => s.screen()[9] === "1/3 /nAS", 2000)).toBe(true);
      expect(s.screen()[0]).toBe("> nas  admin@nas.example.internal:22");
      s.write("ESC");
      expect(await waitFor(() => s.screen()[9] === "3/3 filter:", 2000)).toBe(true);
      // K9: the Esc clear selects the first shown row (nas was selected before it).
      expect(await waitFor(() => s.screen()[0] === "> lab-server  aman@lab.example.internal:22", 2000)).toBe(true);
      expect(s.screen()[1]).toBe("  nas  admin@nas.example.internal:22");
      s.write("q");
      await finish(s);
      expect(s.status()).toBe("0");
    } finally { s.cleanup(); }
  });

  test("100-destination fixture: filtering responds immediately", async () => {
    const s = startTui(LARGE, { rows: 24 });
    try {
      expect(await waitFor(() => s.screenHas("100/100"), 8000)).toBe(true);
      s.write("/");
      const t0 = performance.now();
      s.write("host-09");
      expect(await waitFor(() => s.screenHas("10/100 /host-09"), 2000, 2)).toBe(true);
      const ms = performance.now() - t0;
      console.log(`[evidence] TUI 100-destination filter redraw observed after ${ms.toFixed(1)} ms`);
      expect(ms).toBeLessThan(250);
      s.write("ENTER");
      s.write("ENTER");
      await finish(s);
      expect(s.out()).toContain("SELECTED host-090-lab");
    } finally { s.cleanup(); }
  });

  test("resize to 20x5 re-lays out within 100 ms (alias-only rows), no crash; back to 80x10", async () => {
    const s = startTui(HOMELAB);
    try {
      expect(await ready(s)).toBe(true);
      const t0 = performance.now();
      s.resize(20, 5);
      // Narrow layout: alias-only rows and the status line on row 5.
      const narrow = ["> lab-server", "  nas", "  vps-東京", "", "3/3 filter:"];
      expect(await waitFor(() => JSON.stringify(s.screen()) === JSON.stringify(narrow), 1000, 2)).toBe(true);
      const ms = performance.now() - t0;
      console.log(`[evidence] TUI resize 80x10→20x5 re-layout observed after ${ms.toFixed(1)} ms`);
      expect(ms).toBeLessThan(100);
      s.resize(80, 10);
      expect(await waitFor(() => s.screen()[0] === "> lab-server  aman@lab.example.internal:22" && s.screen()[9] === "3/3 filter:", 1000, 2)).toBe(true);
      for (const [c, r] of [[20, 5], [5, 2], [120, 40], [20, 5]] as const) { s.resize(c, r); await Bun.sleep(20); }
      s.write("q");
      await finish(s);
      expect(s.status()).toBe("0");
      assertRestored(s);
    } finally { s.cleanup(); }
  });

  test("NO_COLOR set → no color SGR at all; selection still marked with '> '", async () => {
    const s = startTui(HOMELAB, { env: { NO_COLOR: "1" } });
    try {
      expect(await ready(s)).toBe(true);
      expect(s.screen()[0]).toBe("> lab-server  aman@lab.example.internal:22");
      s.write("j");
      expect(await waitFor(() => s.screen()[1] === "> nas  admin@nas.example.internal:22", 2000)).toBe(true);
      s.write("q");
      await finish(s);
      expect(COLOR_SGR.test(s.out())).toBe(false);
      assertRestored(s);
    } finally { s.cleanup(); }
  });

  test("control: without NO_COLOR the renderer does emit color SGR", async () => {
    const s = startTui(HOMELAB);
    try {
      expect(await ready(s)).toBe(true);
      s.write("q");
      await finish(s);
      expect(COLOR_SGR.test(s.out())).toBe(true);
    } finally { s.cleanup(); }
  });

  test("no TTY → exit 2 USAGE_ERROR on stderr, nothing on stdout", () => {
    const r = proto(["tui", "--file", HOMELAB]);
    expect(r.code).toBe(2);
    expect(r.stdout.byteLength).toBe(0);
    expect(r.stderr).toContain("requires a terminal");
  });
});
