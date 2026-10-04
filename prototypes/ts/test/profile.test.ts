import { describe, expect, test } from "bun:test";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { parseProfile } from "../src/domain/profile.ts";
import { FIXTURES, parseResult, proto, tempDir } from "./helpers.ts";

const enc = (s: string) => new TextEncoder().encode(s);
const HOMELAB = join(FIXTURES, "homelab.toml");
const SPACED = join(FIXTURES, "spaced dir ü", "prøfile homelab.toml");

describe("profile show: fixtures via CLI", () => {
  test("homelab.toml → PROFILE_OK, 3 destinations, port default applied", () => {
    const r = proto(["profile", "show", "--file", HOMELAB, "--json"]);
    expect(r.code).toBe(0);
    const doc = parseResult(r.stdoutText);
    expect(doc.code).toBe("PROFILE_OK");
    expect(doc.data.profile).toEqual({
      name: "homelab", revision: 3,
      destinations: [
        { id: "dst_lab_server", alias: "lab-server", host: "lab.example.internal", port: 22, account: "aman", labels: ["homelab", "fixed-auth"] },
        { id: "dst_nas", alias: "nas", host: "nas.example.internal", port: 22, account: "admin", labels: ["homelab"] },
        { id: "dst_vps_ünïcode", alias: "vps-東京", host: "vps1.example.invalid", port: 2222, account: "deploy", labels: [] },
      ],
    });
    expect(JSON.stringify(doc)).not.toContain("free-form"); // [meta] not echoed
    expect(doc.warnings).toEqual([]);
    expect(doc.next).toBeNull();
  });

  test("spaced/non-ASCII path → identical data to homelab.toml", () => {
    const a = parseResult(proto(["profile", "show", "--file", HOMELAB, "--json"]).stdoutText);
    const r = proto(["profile", "show", "--file", SPACED, "--json"]);
    expect(r.code).toBe(0);
    expect(parseResult(r.stdoutText)).toEqual(a);
  });

  test("large-100.toml → 100 destinations in file order", () => {
    const r = proto(["profile", "show", "--file", join(FIXTURES, "large-100.toml"), "--json"]);
    expect(r.code).toBe(0);
    const d = parseResult(r.stdoutText).data.profile.destinations;
    expect(d.length).toBe(100);
    expect(d.map((x: { id: string }) => x.id)).toEqual(Array.from({ length: 100 }, (_, i) => `dst_${String(i).padStart(3, "0")}`));
  });

  const negatives: [string, string | null][] = [
    ["invalid-forbidden-key.toml", "private_key"],
    ["invalid-unknown-dest-key.toml", "destinations[0].identity_file"],
    ["invalid-malformed.toml", null],
    ["invalid-schema-version.toml", "schema_version"],
    ["invalid-duplicate-alias.toml", "destinations[1].alias"],
    ["invalid-port.toml", "destinations[0].port"],
  ];
  for (const [file, keyPath] of negatives) {
    test(`${file} → exit 2 SCHEMA_INVALID, no canary/value leak`, () => {
      const path = join(FIXTURES, file);
      const r = proto(["profile", "show", "--file", path, "--json"]);
      expect(r.code).toBe(2);
      const doc = parseResult(r.stdoutText);
      expect(doc.code).toBe("SCHEMA_INVALID");
      expect(doc.state).toBe("failed");
      expect(doc.data.error.key_path).toBe(keyPath);
      const all = r.stdoutText + r.stderr;
      expect(all).not.toContain("HEIMDALL_CANARY_");
      // No string value from the file may appear in output (only key paths).
      const values = [...readFileSync(path, "utf8").matchAll(/=\s*"([^"\n]*)"/g)].map((m) => m[1]!).filter((v) => v.length >= 6); // shorter values collide with English words
      for (const v of values) expect(doc.data.error.message).not.toContain(v);
    });
  }

  test("schema_version 2 → warning names the unsupported version, not other values", () => {
    const doc = parseResult(proto(["profile", "show", "--file", join(FIXTURES, "invalid-schema-version.toml"), "--json"]).stdoutText);
    expect(doc.warnings.length).toBe(1);
    expect(doc.warnings[0]).toContain("schema_version 2");
    expect(doc.warnings[0]).not.toContain("homelab");
  });

  test("string schema_version is never echoed (canary)", () => {
    const out = parseProfile(enc('schema_version = "HEIMDALL_CANARY_sv"\nname = "n"\nrevision = 1\n'));
    expect(out.result.code).toBe("SCHEMA_INVALID");
    expect(JSON.stringify(out.result)).not.toContain("HEIMDALL_CANARY_");
  });

  test("oversize (>1 MiB) → exit 2 INPUT_TOO_LARGE; exactly 1 MiB is parsed", () => {
    const t = tempDir();
    try {
      const big = join(t.spaced, "oversize ü.toml");
      writeFileSync(big, "# " + "x".repeat(1_048_576) + "\n");
      const r = proto(["profile", "show", "--file", big, "--json"]);
      expect(r.code).toBe(2);
      expect(parseResult(r.stdoutText).code).toBe("INPUT_TOO_LARGE");
      const exact = join(t.spaced, "exact.toml");
      const head = 'schema_version = 1\nname = "n"\nrevision = 1\n#';
      writeFileSync(exact, head + "x".repeat(1_048_576 - head.length - 1) + "\n");
      const r2 = proto(["profile", "show", "--file", exact, "--json"]);
      expect(parseResult(r2.stdoutText).code).toBe("PROFILE_OK");
    } finally {
      t.cleanup();
    }
  });

  test("missing file → exit 2 USAGE_ERROR; directory → USAGE_ERROR", () => {
    const t = tempDir();
    try {
      const r = proto(["profile", "show", "--file", join(t.spaced, "nope.toml"), "--json"]);
      expect(r.code).toBe(2);
      expect(parseResult(r.stdoutText).code).toBe("USAGE_ERROR");
      const d = proto(["profile", "show", "--file", t.spaced, "--json"]);
      expect(d.code).toBe(2);
      expect(parseResult(d.stdoutText).code).toBe("USAGE_ERROR");
    } finally {
      t.cleanup();
    }
  });
});

describe("profile validation: domain unit cases", () => {
  const base = 'schema_version = 1\nname = "n"\nrevision = 1\n';
  const dest = (extra: string) => base + `[[destinations]]\nid = "a"\nalias = "a"\nhost = "h"\naccount = "u"\n${extra}`;
  const cases: [string, string, string | null][] = [
    ["float revision", 'schema_version = 1\nname = "n"\nrevision = 1.0\n', "revision"],
    ["revision 0", 'schema_version = 1\nname = "n"\nrevision = 0\n', "revision"],
    ["string schema_version", 'schema_version = "1"\nname = "n"\nrevision = 1\n', "schema_version"],
    ["missing name", "schema_version = 1\nrevision = 1\n", "name"],
    ["missing schema_version", 'name = "n"\nrevision = 1\n', "schema_version"],
    ["missing host", base + '[[destinations]]\nid = "a"\nalias = "a"\naccount = "u"\n', "destinations[0].host"],
    ["port 0", dest("port = 0\n"), "destinations[0].port"],
    ["port string", dest('port = "22"\n'), "destinations[0].port"],
    ["labels not array", dest('labels = "x"\n'), "destinations[0].labels"],
    ["label not string", dest("labels = [1]\n"), "destinations[0].labels[0]"],
    ["duplicate id", base + '[[destinations]]\nid="a"\nalias="x"\nhost="h"\naccount="u"\n[[destinations]]\nid="a"\nalias="y"\nhost="h"\naccount="u"\n', "destinations[1].id"],
    ["destinations as table", base + "[destinations]\nid = 1\n", "destinations"],
    ["meta not a table", base.replace("revision = 1\n", 'revision = 1\nmeta = "x"\n'), "meta"],
    ["unknown nested key in meta tolerated? no: unknown top key", base + "extra = 1\n", "extra"],
    ["duplicate key (TOML error)", base + "name = \"m\"\n", null],
  ];
  for (const [name, src, kp] of cases) {
    test(name, () => {
      const out = parseProfile(enc(src));
      expect(out.ok).toBe(false);
      expect(out.result.code).toBe("SCHEMA_INVALID");
      expect((out.result.data as any).error.key_path).toBe(kp);
    });
  }
  // K2: control code points in string values outside [meta] → SCHEMA_INVALID naming the key.
  const ctl: [string, string, string][] = [
    ["ESC in name (escape)", 'schema_version = 1\nname = "HEIMDALL_CANARY_\\u001b[31m"\nrevision = 1\n', "name"],
    ["literal TAB in host", dest("").replace('host = "h"', 'host = "HEIMDALL_CANARY_\th"'), "destinations[0].host"],
    ["NUL in id", dest("").replace('id = "a"', 'id = "HEIMDALL_CANARY_\\u0000"'), "destinations[0].id"],
    ["DEL in alias", dest("").replace('alias = "a"', 'alias = "HEIMDALL_CANARY_\\u007f"'), "destinations[0].alias"],
    ["C1 U+0085 in account", dest("").replace('account = "u"', 'account = "HEIMDALL_CANARY_\\u0085"'), "destinations[0].account"],
    ["C1 U+009B in a label", dest('labels = ["ok", "HEIMDALL_CANARY_\\u009b"]\n'), "destinations[0].labels[1]"],
  ];
  for (const [name, src, kp] of ctl) {
    test(`K2: ${name} → SCHEMA_INVALID, key_path ${kp}, value never echoed`, () => {
      const out = parseProfile(enc(src));
      expect(out.ok).toBe(false);
      expect(out.result.code).toBe("SCHEMA_INVALID");
      expect((out.result.data as any).error.key_path).toBe(kp);
      expect(JSON.stringify(out.result)).not.toContain("HEIMDALL_CANARY_");
    });
  }
  test("K2: via CLI: exit 2, no value in stdout/stderr; U+00A0 (not a control) still accepted", () => {
    const t = tempDir();
    try {
      const f = join(t.spaced, "ctl ü.toml");
      writeFileSync(f, 'schema_version = 1\nname = "HEIMDALL_CANARY_\\u001b]0;x\\u0007"\nrevision = 1\n');
      const r = proto(["profile", "show", "--file", f, "--json"]);
      expect(r.code).toBe(2);
      const doc = parseResult(r.stdoutText);
      expect(doc.code).toBe("SCHEMA_INVALID");
      expect(doc.data.error.key_path).toBe("name");
      expect(r.stdoutText + r.stderr).not.toContain("HEIMDALL_CANARY_");
      writeFileSync(f, 'schema_version = 1\nname = "nb\\u00a0sp"\nrevision = 1\n');
      expect(proto(["profile", "show", "--file", f, "--json"]).code).toBe(0);
    } finally {
      t.cleanup();
    }
  });
  test("K2: control characters inside [meta] are still tolerated and not echoed", () => {
    const out = parseProfile(enc(base + '[meta]\nnote = "HEIMDALL_CANARY_\\u001b\\u0085\tx"\n'));
    expect(out.ok).toBe(true);
    expect(JSON.stringify(out.result)).not.toContain("HEIMDALL_CANARY_");
  });
  test("meta content tolerated, including nested unknown keys", () => {
    const out = parseProfile(enc(base + "[meta]\nanything = { deep = [1, 2] }\nprivate_key = \"HEIMDALL_CANARY_meta\"\n"));
    expect(out.ok).toBe(true);
    expect(JSON.stringify(out.result)).not.toContain("HEIMDALL_CANARY_");
  });
  test("malformed TOML error message never contains source text", () => {
    const out = parseProfile(enc('schema_version = 1\nname = "HEIMDALL_CANARY_x\n'));
    expect(out.result.code).toBe("SCHEMA_INVALID");
    expect(JSON.stringify(out.result)).not.toContain("HEIMDALL_CANARY_");
  });
  test("invalid UTF-8 → SCHEMA_INVALID", () => {
    expect(parseProfile(new Uint8Array([0x6e, 0x3d, 0xff])).result.code).toBe("SCHEMA_INVALID");
  });
  test("empty destinations allowed; port default 22; labels default []", () => {
    const out = parseProfile(enc(dest("")));
    expect(out.ok && out.profile.destinations[0]).toEqual({ id: "a", alias: "a", host: "h", port: 22, account: "u", labels: [] });
    expect(parseProfile(enc(base)).ok).toBe(true);
  });
});
