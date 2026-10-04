import { writeSync } from "node:fs";

// Synchronous, complete write to a file descriptor (stdout may be non-blocking).
export function writeAll(fd: number, s: string): void {
  const buf = Buffer.from(s, "utf8");
  let off = 0;
  while (off < buf.byteLength) {
    try {
      off += writeSync(fd, buf, off);
    } catch (e) {
      if ((e as { code?: string }).code === "EAGAIN") continue;
      throw e;
    }
  }
}
