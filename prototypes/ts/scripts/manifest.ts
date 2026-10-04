// Assemble dist/manifest.json (contract §7, sidecars per ruling K11) from build.sh status files.
// Exit 0 when at least one target built; 1 otherwise. Failed targets keep their real error.
import { createHash } from "node:crypto";
import { existsSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const [dist, ...targets] = process.argv.slice(2);
if (!dist) process.exit(2);

const entries = targets.map((target) => {
  const result = readFileSync(join(dist, ".status", `${target}.result`), "utf8").trim();
  const [state, rel, ...sidecarRels] = result.split(" ") as [string, string, ...string[]];
  const abs = join(dist, rel);
  const digest = (p: string) => ({ path: p, bytes: statSync(join(dist, p)).size, sha256: createHash("sha256").update(readFileSync(join(dist, p))).digest("hex") });
  if (state === "ok" && existsSync(abs) && sidecarRels.every((p) => existsSync(join(dist, p)))) {
    const exe = digest(rel);
    // Optional per-target sidecars (contract ruling K11): path relative to dist/.
    return { target, path: rel, bytes: exe.bytes, sha256: exe.sha256, built: true, error: null, sidecars: sidecarRels.map(digest) };
  }
  const log = readFileSync(join(dist, ".status", `${target}.log`), "utf8");
  // Keep the real error text, without ANSI color and with the local home path redacted.
  const error = log.replace(/\u001b\[[0-9;]*m/g, "").split(process.env.HOME ?? "\u0000").join("~").trim().slice(-2000);
  return { target, path: rel, bytes: null, sha256: null, built: false, error: error || "build failed with no output" };
});

writeFileSync(join(dist, "manifest.json"), JSON.stringify({ candidate: "ts", targets: entries }, null, 2) + "\n");
for (const e of entries) console.log(`${e.built ? "built " : "FAILED"} ${e.target} ${e.bytes ?? ""} ${e.sha256 ?? ""}`);
process.exit(entries.some((e) => e.built) ? 0 : 1);
