// M00-T05-r4-x2-xrev-T3-verify: replay a pty recording (pty_record.py JSON) into xterm.js headless
// and snapshot the screen after every key chunk.
// Usage: node xterm_replay.js <xterm-headless-dir> <recording.json> <out.json>
//   <xterm-headless-dir>: the directory that holds node_modules/@xterm/headless
// Snapshot per chunk: rows (right-trimmed), underline columns per row, cursor (0-based), and the raw
// cells of every non-blank row (chars, width, underline) so half-overwritten wide characters are visible.
'use strict';
const fs = require('fs');
const path = require('path');

const [, , xdir, recPath, outPath] = process.argv;
const { Terminal } = require(path.join(path.resolve(xdir), 'node_modules', '@xterm', 'headless'));
const xver = require(path.join(path.resolve(xdir), 'node_modules', '@xterm', 'headless', 'package.json')).version;

const rec = JSON.parse(fs.readFileSync(recPath, 'utf8'));
const [cols, rows] = rec.size.split('x').map(Number);
const term = new Terminal({ cols, rows, allowProposedApi: true, scrollback: 0 });

function snapshot(label) {
  const buf = term.buffer.active;
  const lines = [];
  const underline = {};
  const cells = {};
  for (let y = 0; y < rows; y++) {
    const line = buf.getLine(y);
    if (!line) { lines.push(''); continue; }
    lines.push(line.translateToString(true));
    const ul = [];
    const rawCells = [];
    for (let x = 0; x < cols; x++) {
      const c = line.getCell(x);
      if (!c) continue;
      const ch = c.getChars();
      const w = c.getWidth();
      if (c.isUnderline() && w > 0 && ch !== '') ul.push(x);
      if (ch !== '' || w === 0) rawCells.push([x, ch, w, c.isUnderline() ? 1 : 0]);
    }
    if (ul.length) underline[y] = ul;
    if (lines[y] !== '') cells[y] = rawCells;
  }
  return { label, lines, underline, cursor: [buf.cursorX, buf.cursorY], cells };
}

const out = { xterm_headless: xver, bin: rec.bin, sha256: rec.sha256, size: rec.size, term: rec.term,
  profile: rec.profile, keys: rec.keys, snapshots: [] };

(async () => {
  for (const ch of rec.chunks) {
    const data = Buffer.from(ch.b64, 'base64');
    await new Promise((resolve) => term.write(new Uint8Array(data), resolve));
    out.snapshots.push(snapshot(ch.key));
  }
  fs.writeFileSync(outPath, JSON.stringify(out, null, 1));
  const last = out.snapshots[out.snapshots.length - 1];
  console.log(path.basename(outPath), 'rows:', JSON.stringify(last.lines.filter((l) => l !== '')));
  term.dispose();
})();
