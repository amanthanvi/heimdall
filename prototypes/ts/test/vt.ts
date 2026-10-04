// Minimal terminal screen model for tests: absolute/relative cursor addressing, erase,
// wide characters, and skipping of OSC/DCS/APC/other escapes. Enough to reconstruct
// what OpenTUI's differential renderer leaves on screen; not a general emulator.

export interface ResizeMark { pos: number; cols: number; rows: number }

export function renderScreen(stream: string, cols: number, rows: number, resizes: ResizeMark[] = []): string[] {
  let grid: string[][] = [];
  const blank = () => { grid = Array.from({ length: rows }, () => Array<string>(cols).fill(" ")); };
  blank();
  let r = 0, c = 0;
  const marks = [...resizes].sort((a, b) => a.pos - b.pos);
  let mi = 0;
  const clampCursor = () => { r = Math.max(0, Math.min(rows - 1, r)); c = Math.max(0, Math.min(cols - 1, c)); };
  let i = 0;
  while (i < stream.length) {
    while (mi < marks.length && marks[mi]!.pos <= i) {
      const m = marks[mi++]!;
      const old = grid;
      cols = m.cols; rows = m.rows;
      blank();
      for (let y = 0; y < Math.min(rows, old.length); y++) for (let x = 0; x < Math.min(cols, old[y]!.length); x++) grid[y]![x] = old[y]![x]!;
      clampCursor();
    }
    const ch = stream[i]!;
    if (ch === "\x1b") {
      const n = stream[i + 1];
      if (n === "[") {
        let j = i + 2;
        while (j < stream.length && /[0-9;:?<=>]/.test(stream[j]!)) j++;
        while (j < stream.length && /[ -\/]/.test(stream[j]!)) j++;
        const params = stream.slice(i + 2, j);
        const fin = stream[j];
        const nums = params.replace(/^[?<=>]/, "").split(";").map((x) => parseInt(x, 10));
        const p1 = Number.isFinite(nums[0]) ? nums[0]! : 0;
        switch (fin) {
          case "H": case "f": r = (p1 || 1) - 1; c = (Number.isFinite(nums[1]) ? nums[1]! || 1 : 1) - 1; clampCursor(); break;
          case "A": r -= p1 || 1; clampCursor(); break;
          case "B": r += p1 || 1; clampCursor(); break;
          case "C": c += p1 || 1; clampCursor(); break;
          case "D": c -= p1 || 1; clampCursor(); break;
          case "G": c = (p1 || 1) - 1; clampCursor(); break;
          case "J": if (p1 === 2 || p1 === 3) blank(); break;
          case "K": for (let x = p1 === 1 ? 0 : c; x < (p1 === 0 ? cols : p1 === 1 ? c + 1 : cols); x++) grid[r]![x] = " "; break;
          case "h": case "l": if (params === "?1049") { blank(); r = 0; c = 0; } break;
        }
        i = j + 1;
        continue;
      }
      if (n === "]" || n === "P" || n === "_" || n === "^" || n === "X") {
        // string sequences end at BEL or ST (ESC \)
        let j = i + 2;
        while (j < stream.length && stream[j] !== "\x07" && !(stream[j] === "\x1b" && stream[j + 1] === "\\")) j++;
        i = stream[j] === "\x07" ? j + 1 : j + 2;
        continue;
      }
      i += n === "(" || n === ")" || n === "#" ? 3 : 2;
      continue;
    }
    if (ch === "\r") { c = 0; i++; continue; }
    if (ch === "\n") { r = Math.min(rows - 1, r + 1); i++; continue; }
    if (ch < " ") { i++; continue; }
    const cp = String.fromCodePoint(stream.codePointAt(i)!);
    const w = Bun.stringWidth(cp);
    if (w > 0 && r < rows && c < cols) {
      grid[r]![c] = cp;
      if (w === 2 && c + 1 < cols) grid[r]![c + 1] = "";
      c = Math.min(cols, c + w);
      if (c >= cols) c = cols - 1;
    }
    i += cp.length;
  }
  return grid.map((row) => row.join("").replace(/\s+$/, ""));
}
