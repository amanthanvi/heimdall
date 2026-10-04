// OpenTUI adapter for the destination list (contract §5). All state transitions and
// line layout live in domain/listview.ts; this module only maps keys and draws.

import { createCliRenderer, TextAttributes, TextRenderable, type CliRenderer, type KeyEvent } from "@opentui/core";
import type { Profile } from "../domain/profile.ts";
import { SgrColorStripper } from "./nocolor.ts";
import { writeAll } from "../platform/stdio.ts";
import { initial, layout, reduce, type Key, type Outcome } from "../domain/listview.ts";

export type TuiExit = { kind: "select"; alias: string } | { kind: "quit" } | { kind: "cancel" } | { kind: "signal"; status: number } | { kind: "error" };

const STDIN_GONE = ["end", "close", "error"] as const;

function mapKey(k: KeyEvent): Key | null {
  if (k.ctrl && k.name === "c") return { kind: "ctrl_c" };
  switch (k.name) {
    case "up": return { kind: "up" };
    case "down": return { kind: "down" };
    case "return":
    case "enter":
    case "linefeed": return { kind: "enter" };
    case "escape": return { kind: "escape" };
    case "backspace": return { kind: "backspace" };
  }
  if (k.ctrl || k.meta) return null;
  const seq = k.sequence;
  if (seq && Array.from(seq).length === 1 && !/[\u0000-\u001f\u007f]/.test(seq)) return { kind: "char", ch: seq };
  return null;
}

export async function runTui(profile: Profile): Promise<TuiExit> {
  const noColor = (process.env.NO_COLOR ?? "") !== "";
  const state = initial(profile.destinations);

  // NO_COLOR workaround (see nocolor.ts): a stdout other than process.stdout makes
  // OpenTUI deliver frames through JS ("feed" mode) instead of native fd writes.
  // Frames go straight to fd 1: OpenTUI patches process.stdout.write to capture
  // console output, so calling it here would loop back into the renderer.
  let stdout: NodeJS.WriteStream = process.stdout;
  if (noColor) {
    const strip = new SgrColorStripper();
    const decoder = new TextDecoder("utf-8");
    const real = process.stdout;
    const write = (chunk: unknown, enc?: unknown, cb?: unknown) => {
      const done = typeof enc === "function" ? enc : cb;
      const text = typeof chunk === "string" ? chunk : decoder.decode(chunk as Uint8Array, { stream: true });
      writeAll(1, strip.push(text));
      if (typeof done === "function") process.nextTick(done as () => void);
      return true;
    };
    stdout = new Proxy(real, {
      get(target, prop) {
        if (prop === "write") return write;
        const v = Reflect.get(target, prop, target);
        return typeof v === "function" ? v.bind(target) : v;
      },
    });
  }

  // Exit paths are installed before the renderer exists so a signal or exception
  // during setup still ends in a restored terminal.
  let renderer: CliRenderer | null = null;
  let finished: (e: TuiExit) => void;
  const done = new Promise<TuiExit>((res) => (finished = res));
  let exited = false;
  const exit = (e: TuiExit) => {
    if (exited) return;
    exited = true;
    try {
      renderer?.destroy(); // leaves alt screen, shows cursor, setRawMode(false)
    } catch {
      /* best effort; process exit follows */
    }
    finished(e);
  };
  const onSigterm = () => exit({ kind: "signal", status: 143 });
  const onSighup = () => exit({ kind: "signal", status: 129 });
  // Terminal hangup without SIGHUP (K10): when the session leader does not forward the
  // hangup, the job only sees EOF/EIO on the tty, which Bun reports as stdin
  // "end"/"close" (or "error"). In raw mode Ctrl-D is a byte, so EOF means the terminal is gone.
  const onStdinGone = () => exit({ kind: "signal", status: 129 });
  const onSigint = () => exit({ kind: "cancel" }); // SIGINT from outside (raw mode turns ^C into a key)
  const onError = (err: unknown) => {
    exit({ kind: "error" });
    writeAll(2, `heimdall-proto: internal error: ${err instanceof Error ? err.name : "unknown"}\n`);
  };
  process.on("SIGTERM", onSigterm);
  process.on("SIGHUP", onSighup);
  process.on("SIGINT", onSigint);
  for (const ev of STDIN_GONE) process.stdin.on(ev, onStdinGone);
  process.on("uncaughtException", onError);
  process.on("unhandledRejection", onError);

  try {
    renderer = await createCliRenderer({
      stdout,
      exitOnCtrlC: false,
      exitSignals: [], // we own signal handling so every exit path restores the terminal
      screenMode: "alternate-screen",
      useMouse: false,
      useKittyKeyboard: null,
      consoleMode: "disabled",
      openConsoleOnError: false,
      debounceDelay: 1,
      targetFps: 60,
    });
  } catch (e) {
    onError(e);
  }
  if (exited || !renderer) return finishTui(await done);
  const r = renderer;

  const rows: TextRenderable[] = [];
  const status = new TextRenderable(r, { content: "", position: "absolute", left: 0, top: 0, wrapMode: "none" });
  r.root.add(status);

  const draw = () => {
    const w = r.terminalWidth;
    const h = r.terminalHeight;
    const frame = layout(state, w, h);
    while (rows.length < frame.rows.length) {
      const t = new TextRenderable(r, { content: "", position: "absolute", left: 0, top: rows.length, wrapMode: "none" });
      rows.push(t);
      r.root.add(t);
    }
    rows.forEach((t, i) => {
      const r = frame.rows[i];
      t.content = r ? r.text : "";
      t.visible = !!r;
      t.width = Math.max(1, w);
      t.attributes = r?.selected && !noColor ? TextAttributes.BOLD | TextAttributes.INVERSE : TextAttributes.NONE;
    });
    status.top = Math.max(0, h - 1);
    status.width = Math.max(1, w);
    status.content = frame.status;
    r.requestRender();
  };

  // OpenTUI catches exceptions thrown by keypress listeners, prints them over the
  // screen and keeps running; route them to the error exit path instead.
  r.keyInput.on("keypress", (k: KeyEvent) => {
    try {
      if (process.env.HEIMDALL_PROTO_FAULT === "tui-throw" && k.sequence === "!") {
        throw new Error("injected fault"); // test-only fault injection (REPORT.md)
      }
      const key = mapKey(k);
      if (!key) return;
      const out: Outcome = reduce(state, key);
      if (out.kind === "continue") return draw();
      exit(out);
    } catch (e) {
      onError(e);
    }
  });
  r.on("resize", () => {
    try {
      draw();
    } catch (e) {
      onError(e);
    }
  });
  draw();

  return finishTui(await done);

  function finishTui(result: TuiExit): TuiExit {
    process.off("SIGTERM", onSigterm);
    process.off("SIGHUP", onSighup);
    process.off("SIGINT", onSigint);
    for (const ev of STDIN_GONE) process.stdin.off(ev, onStdinGone);
    return result;
  }
}
