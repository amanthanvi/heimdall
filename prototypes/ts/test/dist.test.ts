// Ruling K11 checks against the compiled artifact (sidecar layout from build.sh).
// Uses HEIMDALL_PROTO_BIN if set, else dist/<host target>/heimdall-proto; run build.sh
// first. Disposable temp dirs only.
import { describe, expect, test } from "bun:test";
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { FIXTURES, PROTO_DIR, tempDir, waitFor } from "./helpers.ts";

const HOST = `${process.platform}-${process.arch}`;
const BIN = process.env.HEIMDALL_PROTO_BIN ?? join(PROTO_DIR, "dist", HOST, "heimdall-proto");
const LIB_REL = process.platform === "darwin" ? `@opentui/core-${HOST}/libopentui.dylib` : `@opentui/core-${HOST}/libopentui.so`;
const HOMELAB = join(FIXTURES, "homelab.toml");

// Run the TUI under a PTY with a minimal environment; press q after the first frame.
async function tuiOnce(bin: string, env: Record<string, string>, cwd: string): Promise<{ code: number | null; rendered: boolean }> {
  let out = "";
  const p = Bun.spawn([bin, "tui", "--file", HOMELAB], {
    cwd,
    env: { PATH: "/usr/bin:/bin", TERM: "xterm-256color", ...env },
    terminal: { cols: 80, rows: 10, data(_t: unknown, d: Uint8Array) { out += new TextDecoder().decode(d); } },
  } as any);
  await waitFor(() => out.includes("filter:") || p.exitCode !== null, 8000);
  if (p.exitCode === null) (p as any).terminal.write("q");
  const k = setTimeout(() => p.kill("SIGKILL"), 5000); // exact child we started
  await p.exited;
  clearTimeout(k);
  return { code: p.exitCode, rendered: out.includes("lab-server") };
}

const listing = (dir: string) => readdirSync(dir).sort();

describe("K11: native library sidecar (compiled artifact)", () => {
  test("artifact and sidecar exist", () => {
    expect(existsSync(BIN)).toBe(true);
    expect(existsSync(join(BIN, "..", LIB_REL))).toBe(true);
  });

  test("TUI writes nothing to a fresh empty TMPDIR, HOME or cwd", async () => {
    const t = tempDir();
    try {
      const tmp = join(t.dir, "tmp"), home = join(t.dir, "home"), cwd = join(t.dir, "cwd");
      for (const d of [tmp, home, cwd]) mkdirSync(d);
      const r = await tuiOnce(BIN, { TMPDIR: tmp + "/", HOME: home }, cwd);
      expect(r).toEqual({ code: 0, rendered: true });
      expect([listing(tmp), listing(home), listing(cwd)]).toEqual([[], [], []]);
    } finally { t.cleanup(); }
  });

  test("inherited OTUI_ASSET_ROOT and OPENTUI_LIBC are ignored; planted library is not loaded", async () => {
    const t = tempDir();
    try {
      const evil = join(t.dir, "evil");
      mkdirSync(join(evil, LIB_REL, ".."), { recursive: true });
      const real = readFileSync(join(BIN, "..", LIB_REL));
      writeFileSync(join(evil, LIB_REL), new Uint8Array(real.byteLength)); // same size, zero-filled
      const tmp = join(t.dir, "tmp");
      mkdirSync(tmp);
      const overrides: Record<string, string>[] = [{ OTUI_ASSET_ROOT: evil }, { OTUI_ASSET_ROOT: "relative/dir" }, { OPENTUI_LIBC: "musl" }];
      for (const extra of overrides) {
        const r = await tuiOnce(BIN, { TMPDIR: tmp, HOME: tmp, ...extra }, t.dir);
        expect(r).toEqual({ code: 0, rendered: true });
      }
      expect(listing(tmp)).toEqual([]);
    } finally { t.cleanup(); }
  });

  test("invoked through a symlink: the sidecar is found from the executable's real path", async () => {
    const t = tempDir();
    try {
      const link = join(t.spaced, "heimdall-proto");
      symlinkSync(BIN, link);
      mkdirSync(join(t.spaced, LIB_REL, ".."), { recursive: true });
      writeFileSync(join(t.spaced, LIB_REL), "not a library"); // next to the link: must be ignored
      const r = await tuiOnce(link, { TMPDIR: t.dir, HOME: t.dir }, t.dir);
      expect(r).toEqual({ code: 0, rendered: true });
    } finally { t.cleanup(); }
  });

  test("missing sidecar: TUI fails closed (exit 1), extracts nothing, no fallback", async () => {
    const t = tempDir();
    try {
      const lone = join(t.spaced, "heimdall-proto");
      copyFileSync(BIN, lone);
      Bun.spawnSync(["/bin/chmod", "755", lone]);
      const tmp = join(t.dir, "tmp");
      mkdirSync(tmp);
      const r = await tuiOnce(lone, { TMPDIR: tmp, HOME: tmp }, t.dir);
      expect(r.code).toBe(1);
      expect(listing(tmp)).toEqual([]);
    } finally { t.cleanup(); }
  });
});
