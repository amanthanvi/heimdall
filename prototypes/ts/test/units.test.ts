import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { applyFilter, initial, layout, reduce, type Key } from "../src/domain/listview.ts";
import { parseProfile } from "../src/domain/profile.ts";
import { parseWindowsArgs, quoteWindowsArg, windowsCommandLine } from "../src/domain/run.ts";
import { SgrColorStripper } from "../src/tui/nocolor.ts";
import { FIXTURES } from "./helpers.ts";

describe("Windows CommandLineToArgvW quoting (pure; native launch blocked: needs Windows)", () => {
  const vectors: [string, string][] = [
    ["plain", "plain"],
    ["", '""'],
    ["a b", '"a b"'],
    ['a"b', '"a\\"b"'],
    ["a\\b", "a\\b"],
    ["a\\\\b", "a\\\\b"],
    ["a b\\", '"a b\\\\"'],
    ['a\\"b', '"a\\\\\\"b"'],
    ["tab\there", '"tab\there"'],
    ["new\nline", '"new\nline"'],
    ["ü東京", "ü東京"],
    ["%PATH%", "%PATH%"],
  ];
  for (const [arg, quoted] of vectors) {
    test(`quote ${JSON.stringify(arg)}`, () => expect(quoteWindowsArg(arg)).toBe(quoted));
  }
  test("round-trip through reference CommandLineToArgvW parser", () => {
    const args = ["a b", 'q"uote', "it's", "$HOME", "a;b", "*", "", "\\", "\\\\", '\\"', 'x\\\\"y', "trail\\", "trail \\\\", '""', "ü東京", "a\tb", "&|<>^"];
    expect(parseWindowsArgs(windowsCommandLine(args))).toEqual(args);
  });
  test("MS documented examples parse as documented", () => {
    // learn.microsoft.com "Parsing C++ command-line arguments" table
    expect(parseWindowsArgs('"abc" d e')).toEqual(["abc", "d", "e"]);
    expect(parseWindowsArgs("a\\\\b d\"e f\"g h")).toEqual(["a\\\\b", "de fg", "h"]);
    expect(parseWindowsArgs('a\\\\\\"b c d')).toEqual(['a\\"b', "c", "d"]);
    expect(parseWindowsArgs('a\\\\\\\\"b c" d e')).toEqual(["a\\\\b c", "d", "e"]);
  });
});

describe("list view-model (shared by TUI)", () => {
  const dests = (() => { const o = parseProfile(new Uint8Array(readFileSync(join(FIXTURES, "homelab.toml")))); if (!o.ok) throw new Error(); return o.profile.destinations; })();
  const large = (() => { const o = parseProfile(new Uint8Array(readFileSync(join(FIXTURES, "large-100.toml")))); if (!o.ok) throw new Error(); return o.profile.destinations; })();
  const ch = (c: string): Key => ({ kind: "char", ch: c });

  test("rows, selection marker, status line", () => {
    const s = initial(dests);
    const f = layout(s, 80, 10);
    expect(f.rows.map((r) => r.text)).toEqual(["> lab-server  aman@lab.example.internal:22", "  nas  admin@nas.example.internal:22", "  vps-東京  deploy@vps1.example.invalid:2222"]);
    expect(f.status).toBe("3/3 filter: ");
  });
  test("width < 50 shows alias only; 49 vs 50 boundary", () => {
    const s = initial(dests);
    expect(layout(s, 49, 10).rows[0]!.text).toBe("> lab-server");
    expect(layout(s, 50, 10).rows[0]!.text).toContain("aman@");
  });
  test("20x5 keeps selection visible and never throws", () => {
    const s = initial(large);
    for (let i = 0; i < 30; i++) reduce(s, { kind: "down" });
    const f = layout(s, 20, 5);
    expect(f.rows.length).toBe(4);
    expect(f.rows.some((r) => r.selected && r.text.startsWith("> host-030"))).toBe(true);
    for (const [w, h] of [[1, 1], [0, 0], [20, 1], [200, 2]]) expect(() => layout(s, w!, h!)).not.toThrow();
  });
  test("j/k and arrows move, clamped", () => {
    const s = initial(dests);
    reduce(s, ch("k"));
    expect(s.selected).toBe(0);
    reduce(s, ch("j")); reduce(s, { kind: "down" }); reduce(s, ch("j"));
    expect(s.selected).toBe(2);
    reduce(s, { kind: "up" });
    expect(s.selected).toBe(1);
  });
  test("filter mode: case-insensitive alias/host, non-ASCII, backspace, Enter keeps, Esc clears", () => {
    const s = initial(dests);
    reduce(s, ch("/"));
    expect(s.filtering).toBe(true);
    reduce(s, ch("東"));
    expect(s.shown.map((d) => d.alias)).toEqual(["vps-東京"]);
    reduce(s, { kind: "backspace" });
    expect(s.filter).toBe("");
    for (const c of "NAS") reduce(s, ch(c));
    expect(s.shown.map((d) => d.alias)).toEqual(["nas"]);
    expect(layout(s, 80, 5).status).toBe("1/3 /NAS");
    reduce(s, { kind: "enter" });
    expect(s.filtering).toBe(false);
    expect(s.filter).toBe("NAS");
    expect(reduce(s, { kind: "enter" })).toEqual({ kind: "select", alias: "nas" });
    reduce(s, ch("/"));
    for (const c of "q") reduce(s, ch(c)); // q in filter mode is text, not quit
    expect(s.filter).toBe("NASq");
    reduce(s, { kind: "escape" });
    expect(s.filter).toBe("");
    expect(s.shown.length).toBe(3);
  });
  test("K9: append, Backspace and Esc each reset selection to the first shown row; Enter keeps it", () => {
    const s = initial(dests);
    reduce(s, ch("j")); // nas
    reduce(s, ch("/"));
    reduce(s, ch("a")); // all three match "a"; nas would still be visible
    expect(s.shown.length).toBe(3);
    expect(s.selected).toBe(0);
    reduce(s, { kind: "down" });
    expect(s.selected).toBe(1);
    reduce(s, { kind: "backspace" });
    expect(s.selected).toBe(0);
    reduce(s, ch("e")); reduce(s, { kind: "down" }); reduce(s, { kind: "down" }); // all three match "e"
    expect(s.selected).toBe(2);
    reduce(s, { kind: "escape" });
    expect([s.filtering, s.filter, s.selected]).toEqual([false, "", 0]);
    reduce(s, ch("/")); reduce(s, ch("a")); reduce(s, { kind: "down" }); reduce(s, { kind: "down" });
    reduce(s, { kind: "enter" }); // leaving filter mode with Enter keeps the selection
    expect([s.filtering, s.selected]).toEqual([false, 2]);
    expect(layout(s, 80, 10).rows[2]!.text.startsWith("> vps-東京")).toBe(true);
    const big = initial(large);
    for (let i = 0; i < 50; i++) reduce(big, { kind: "down" });
    layout(big, 80, 10);
    reduce(big, ch("/")); reduce(big, ch("h")); // all 100 match; top and selection back at row 0
    expect([big.selected, big.top]).toEqual([0, 0]);
    expect(layout(big, 80, 10).rows[0]!.text.startsWith("> host-000")).toBe(true);
  });
  test("host match: 'invalid' matches vps1.example.invalid", () => {
    expect(applyFilter(dests, "INVALID").map((d) => d.alias)).toEqual(["vps-東京"]);
  });
  test("q quits, Ctrl-C cancels, Enter on empty list does nothing", () => {
    expect(reduce(initial(dests), ch("q"))).toEqual({ kind: "quit" });
    expect(reduce(initial(dests), { kind: "ctrl_c" })).toEqual({ kind: "cancel" });
    const s = initial(dests);
    reduce(s, ch("/")); reduce(s, ch("z")); reduce(s, { kind: "enter" });
    expect(reduce(s, { kind: "enter" })).toEqual({ kind: "continue" });
  });
  test("100-destination filtering is immediate (<5 ms per keystroke)", () => {
    const s = initial(large);
    reduce(s, ch("/"));
    const t0 = performance.now();
    for (const c of "host-09") { reduce(s, ch(c)); layout(s, 80, 24); }
    const per = (performance.now() - t0) / 7;
    expect(s.shown.length).toBe(10);
    expect(per).toBeLessThan(5);
    console.log(`[evidence] listview filter+layout per keystroke over 100 destinations: ${per.toFixed(3)} ms`);
  });
});

describe("NO_COLOR SGR stripper", () => {
  const strip = (...chunks: string[]) => { const s = new SgrColorStripper(); return chunks.map((c) => s.push(c)).join(""); };
  test("removes truecolor/256/basic color, keeps reset/attributes/text", () => {
    expect(strip("\x1b[38;2;255;255;255m\x1b[49mhi\x1b[0m")).toBe("hi\x1b[0m");
    expect(strip("\x1b[1;38;5;196;48;2;1;2;3;7mX")).toBe("\x1b[1;7mX");
    expect(strip("\x1b[31m\x1b[42m\x1b[91m\x1b[103m\x1b[39;49mY")).toBe("Y");
    expect(strip("\x1b[38:2::1:2:3mZ")).toBe("Z");
    expect(strip("\x1b[m")).toBe("\x1b[m");
  });
  test("non-SGR sequences untouched (cursor, alt screen, DEC private)", () => {
    const s = "\x1b[?1049h\x1b[?25l\x1b[1;1H\x1b[>4;1m\x1b]0;\x07";
    expect(strip(s)).toBe(s);
  });
  test("sequences split across writes", () => {
    expect(strip("a\x1b", "[38;2;1", ";2;3mb\x1b[", "0m")).toBe("ab\x1b[0m");
  });
});
