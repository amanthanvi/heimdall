import { appendFileSync } from "node:fs";
const log = (m: string) => appendFileSync(process.env.PROBE_LOG!, m + "\n");
process.stdin.setRawMode(true);
process.stdin.on("data", (d) => log("data " + d.length));
for (const ev of ["end", "close", "error"]) process.stdin.on(ev, (e: any) => log(ev + (e ? " " + (e.code ?? e.name) : "")));
process.on("SIGHUP", () => { log("SIGHUP"); process.exit(129); });
process.stdin.resume();
log("ready");
setTimeout(() => { log("timeout-still-alive"); process.exit(3); }, 4000);
