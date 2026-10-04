import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { FIXTURES, parseResult, proto } from "./helpers.ts";

describe("cli surface", () => {
  test("version --json", () => {
    const r = proto(["version", "--json"]);
    expect(r.code).toBe(0);
    const doc = parseResult(r.stdoutText);
    expect(doc.code).toBe("VERSION_OK");
    expect(doc.data).toMatchObject({ name: "heimdall-proto", version: "0.0.0-g02", candidate: "ts", tui_framework: "@opentui/core", tui_framework_version: "0.5.14" });
    expect(doc.data.runtime).toStartWith("bun 1.4.2");
  });

  const usage: string[][] = [
    [], ["bogus"], ["profile"], ["profile", "show"], ["profile", "show", "--file"],
    ["profile", "show", "--file", join(FIXTURES, "homelab.toml"), "--extra"],
    ["agent", "list"], ["agent", "list", "--socket", "/x", "--timeout-ms", "0"], ["version", "--nope"], ["tui"],
  ];
  for (const args of usage) {
    test(`usage error ${JSON.stringify(args)}: stderr only without --json, JSON with --json`, () => {
      const plain = proto(args);
      expect(plain.code).toBe(2);
      expect(plain.stdout.byteLength).toBe(0);
      expect(plain.stderr.length).toBeGreaterThan(0);
      const withJson = proto([...args, "--json"]);
      expect(withJson.code).toBe(2);
      const doc = parseResult(withJson.stdoutText);
      expect(doc.code).toBe("USAGE_ERROR");
      expect(doc.state).toBe("failed");
    });
  }

  test("no ANSI in stderr diagnostics either", () => {
    expect(proto(["bogus"]).stderr).not.toContain("\u001b");
  });
});
