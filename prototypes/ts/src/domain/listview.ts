// Destination list view-model for the TUI (contract §5). Pure state machine:
// no I/O, no rendering. The TUI adapter maps keys to these actions and renders
// the lines this module produces, so behavior is testable without a terminal.

import type { Destination } from "./profile.ts";

export type Key =
  | { kind: "up" } | { kind: "down" } | { kind: "enter" } | { kind: "escape" }
  | { kind: "backspace" } | { kind: "ctrl_c" } | { kind: "char"; ch: string };

export type Outcome = { kind: "continue" } | { kind: "select"; alias: string } | { kind: "quit" } | { kind: "cancel" };

export interface ViewState {
  readonly all: readonly Destination[];
  shown: Destination[];
  selected: number; // index into shown
  filter: string;
  filtering: boolean;
  top: number; // first visible row index into shown
}

export function initial(all: readonly Destination[]): ViewState {
  return { all, shown: [...all], selected: 0, filter: "", filtering: false, top: 0 };
}

export function applyFilter(all: readonly Destination[], filter: string): Destination[] {
  if (filter === "") return [...all];
  const f = filter.toLowerCase();
  return all.filter((d) => d.alias.toLowerCase().includes(f) || d.host.toLowerCase().includes(f));
}

// K9: every filter change (append, Backspace, Esc clear) selects the first shown row.
function refilter(s: ViewState): void {
  s.shown = applyFilter(s.all, s.filter);
  s.selected = 0;
  s.top = 0;
}

// Printable: one or more code points, none of them control characters.
function printable(ch: string): boolean {
  return ch.length > 0 && !/[\u0000-\u001f\u007f-\u009f]/.test(ch);
}

export function reduce(s: ViewState, k: Key): Outcome {
  if (k.kind === "ctrl_c") return { kind: "cancel" };
  if (s.filtering) {
    switch (k.kind) {
      case "enter":
        s.filtering = false;
        break;
      case "escape":
        s.filtering = false;
        s.filter = "";
        refilter(s);
        break;
      case "backspace":
        s.filter = Array.from(s.filter).slice(0, -1).join("");
        refilter(s);
        break;
      case "char":
        if (printable(k.ch)) {
          s.filter += k.ch;
          refilter(s);
        }
        break;
      case "up":
        move(s, -1);
        break;
      case "down":
        move(s, 1);
        break;
    }
    return { kind: "continue" };
  }
  switch (k.kind) {
    case "up":
      move(s, -1);
      break;
    case "down":
      move(s, 1);
      break;
    case "enter": {
      const d = s.shown[s.selected];
      if (d) return { kind: "select", alias: d.alias };
      break;
    }
    case "char":
      if (k.ch === "k") move(s, -1);
      else if (k.ch === "j") move(s, 1);
      else if (k.ch === "/") s.filtering = true;
      else if (k.ch === "q") return { kind: "quit" };
      break;
  }
  return { kind: "continue" };
}

function move(s: ViewState, delta: number): void {
  if (s.shown.length === 0) return;
  s.selected = Math.max(0, Math.min(s.shown.length - 1, s.selected + delta));
}

// Truncate to at most `width` code points (display width is approximated by
// code points; wide CJK glyphs may overflow, see REPORT.md).
function clip(text: string, width: number): string {
  const cps = Array.from(text);
  return cps.length <= width ? text : cps.slice(0, Math.max(0, width)).join("");
}

export interface Frame {
  rows: { text: string; selected: boolean }[];
  status: string;
}

// Produce exactly the lines to draw for a width x height viewport. The last line is
// the status line; the remaining height-1 lines are list rows.
export function layout(s: ViewState, width: number, height: number): Frame {
  const w = Math.max(1, width);
  const listHeight = Math.max(0, height - 1);
  if (s.selected < s.top) s.top = s.selected;
  if (listHeight > 0 && s.selected >= s.top + listHeight) s.top = s.selected - listHeight + 1;
  if (s.top > Math.max(0, s.shown.length - listHeight)) s.top = Math.max(0, s.shown.length - listHeight);
  const rows: Frame["rows"] = [];
  for (let i = s.top; i < Math.min(s.shown.length, s.top + listHeight); i++) {
    const d = s.shown[i]!;
    const body = width < 50 ? d.alias : `${d.alias}  ${d.account}@${d.host}:${d.port}`;
    const sel = i === s.selected;
    rows.push({ text: clip((sel ? "> " : "  ") + body, w), selected: sel });
  }
  const mode = s.filtering ? "/" : "filter: ";
  const status = clip(`${s.shown.length}/${s.all.length} ${mode}${s.filter}`, w);
  return { rows, status };
}
