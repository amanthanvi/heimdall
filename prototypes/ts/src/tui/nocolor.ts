// Workaround for OpenTUI 0.5.14 not honoring NO_COLOR: its native renderer always
// emits truecolor SGR (e.g. ESC[38;2;255;255;255m). When NO_COLOR is set we route
// renderer output through this streaming filter, which removes color parameters
// (30-39, 40-49, 90-97, 100-107, 38/48/58 extended forms) from SGR sequences and
// keeps everything else byte-identical. Pure and incremental (escape sequences may
// be split across writes).

const ESC = "\u001b";

function filterSgr(params: string): string | null {
  if (params === "" || params === "0") return params; // reset is not a color
  const parts = params.split(";");
  const keep: string[] = [];
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i]!;
    const head = p.split(":")[0]!;
    const n = Number(head);
    if (head === "38" || head === "48" || head === "58") {
      if (p.includes(":")) continue; // colon form carries its own subparameters
      const mode = parts[i + 1];
      i += mode === "5" ? 2 : mode === "2" ? 4 : 1;
      continue;
    }
    if ((n >= 30 && n <= 39) || (n >= 40 && n <= 49) || (n >= 90 && n <= 97) || (n >= 100 && n <= 107) || n === 59) {
      continue;
    }
    keep.push(p);
  }
  return keep.length === 0 ? null : keep.join(";");
}

export class SgrColorStripper {
  private carry = "";

  push(chunk: string): string {
    const s = this.carry + chunk;
    this.carry = "";
    let out = "";
    let i = 0;
    while (i < s.length) {
      const esc = s.indexOf(ESC, i);
      if (esc < 0) {
        out += s.slice(i);
        break;
      }
      out += s.slice(i, esc);
      if (esc + 1 >= s.length) {
        this.carry = s.slice(esc);
        break;
      }
      if (s[esc + 1] !== "[") {
        out += ESC;
        i = esc + 1;
        continue;
      }
      // CSI: ESC [ params(0x30-0x3f)* intermediates(0x20-0x2f)* final(0x40-0x7e)
      let j = esc + 2;
      while (j < s.length && s.charCodeAt(j) >= 0x30 && s.charCodeAt(j) <= 0x3f) j++;
      const paramsEnd = j;
      while (j < s.length && s.charCodeAt(j) >= 0x20 && s.charCodeAt(j) <= 0x2f) j++;
      if (j >= s.length) {
        this.carry = s.slice(esc);
        break;
      }
      const final = s[j]!;
      const seq = s.slice(esc, j + 1);
      if (final === "m" && paramsEnd === j && !/[<=>?]/.test(s.slice(esc + 2, paramsEnd))) {
        const kept = filterSgr(s.slice(esc + 2, paramsEnd));
        if (kept !== null) out += `${ESC}[${kept}m`;
      } else {
        out += seq;
      }
      i = j + 1;
    }
    return out;
  }
}
