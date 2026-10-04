// Bounded file reading for profile input (contract §2): oversize files are rejected
// from stat and never read in full.

import { closeSync, fstatSync, openSync, readSync } from "node:fs";
import { MAX_PROFILE_BYTES } from "../domain/profile.ts";

export type ReadOutcome = { kind: "ok"; bytes: Uint8Array } | { kind: "too_large" } | { kind: "unreadable" };

export function readBounded(path: string): ReadOutcome {
  let fd: number;
  try {
    fd = openSync(path, "r");
  } catch {
    return { kind: "unreadable" };
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) return { kind: "unreadable" };
    if (st.size > MAX_PROFILE_BYTES) return { kind: "too_large" };
    // Read at most MAX+1 bytes in case the file grew after fstat.
    const buf = new Uint8Array(MAX_PROFILE_BYTES + 1);
    let have = 0;
    while (have < buf.byteLength) {
      const n = readSync(fd, buf, have, buf.byteLength - have, null);
      if (n === 0) break;
      have += n;
    }
    if (have > MAX_PROFILE_BYTES) return { kind: "too_large" };
    return { kind: "ok", bytes: buf.subarray(0, have) };
  } catch {
    return { kind: "unreadable" };
  } finally {
    closeSync(fd);
  }
}
