import { describe, expect, test } from "bun:test";
import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { cleanEnv, parseResult, proto, PROTO, tempDir, waitFor } from "./helpers.ts";

const dec = (b: Uint8Array) => new TextDecoder().decode(b);

describe("run: argv, stdio, status", () => {
  test("argv passes through byte-for-byte without a shell", () => {
    const args = ["a b", 'q"uote', "it's", "$HOME", "a;b", "*", "new\nline", "ü東京", "", "  lead", "\\back\\", "-n", "--", "--json", "`id`", "$(id)"];
    const r = proto(["run", "--", "/bin/sh", "-c", 'for a in "$@"; do printf "%s\\0" "$a"; done', "sh", ...args]);
    expect(r.code).toBe(0);
    expect(dec(r.stdout).split("\0").slice(0, -1)).toEqual(args);
    expect(r.stderr).toBe("");
  });

  test("PATH lookup of argv[0]", () => {
    const r = proto(["run", "--", "printf", "%s", "via-path"]);
    expect(r.code).toBe(0);
    expect(r.stdoutText).toBe("via-path");
  });

  test("binary stdin→stdout passthrough (all byte values, NUL, invalid UTF-8)", () => {
    const data = new Uint8Array(256 * 64).map((_, i) => i % 256);
    const r = proto(["run", "--", "cat"], { stdin: data });
    expect(r.code).toBe(0);
    expect(Buffer.compare(Buffer.from(r.stdout), Buffer.from(data))).toBe(0);
  });

  test("binary stderr passthrough; heimdall-proto writes nothing to stdout", () => {
    const data = new Uint8Array([0, 255, 254, 10, 13, 27, 0x80]);
    const r = Bun.spawnSync([...PROTO, "run", "--", "/bin/sh", "-c", "cat >&2"], { stdin: data, stdout: "pipe", stderr: "pipe", env: cleanEnv() });
    expect(r.exitCode).toBe(0);
    expect((r.stdout as Uint8Array).byteLength).toBe(0);
    expect(Array.from(r.stderr as Uint8Array)).toEqual(Array.from(data));
  });

  test("exit code passthrough and meta file in a spaced/non-ASCII path", () => {
    const t = tempDir();
    try {
      const meta = join(t.spaced, "meta ü.json");
      const r = proto(["run", "--meta-file", meta, "--", "/bin/sh", "-c", "exit 42"]);
      expect(r.code).toBe(42);
      expect(r.stdout.byteLength).toBe(0);
      const doc = parseResult(readFileSync(meta, "utf8"));
      expect(doc.code).toBe("CHILD_EXITED");
      expect(doc.state).toBe("succeeded"); // K5: launch-and-wait succeeded whatever the child status
      expect(doc.data).toEqual({ launched: true, exit_code: 42, signal: null });
    } finally {
      t.cleanup();
    }
  });

  test("child killed by signal N → exit 128+N, meta signal N", () => {
    const t = tempDir();
    try {
      const meta = join(t.spaced, "m.json");
      for (const [sig, n] of [["TERM", 15], ["KILL", 9], ["SEGV", 11]] as const) {
        const r = proto(["run", "--meta-file", meta, "--", "/bin/sh", "-c", `kill -${sig} $$`]);
        expect(r.code).toBe(128 + n);
        const doc = parseResult(readFileSync(meta, "utf8"));
        expect(doc.state).toBe("succeeded"); // K5
        expect(doc.data).toEqual({ launched: true, exit_code: null, signal: n });
      }
    } finally {
      t.cleanup();
    }
  });

  test("launch failure (not found / not executable / directory) → exit 127, CHILD_LAUNCH_FAILED", () => {
    const t = tempDir();
    try {
      const meta = join(t.spaced, "m.json");
      const noexec = join(t.spaced, "noexec ü.sh");
      writeFileSync(noexec, "#!/bin/sh\necho hi\n");
      chmodSync(noexec, 0o644);
      for (const cmd of ["definitely-not-a-command-g02", noexec, t.spaced]) {
        const r = proto(["run", "--meta-file", meta, "--", cmd]);
        expect(r.code).toBe(127);
        expect(r.stdout.byteLength).toBe(0);
        expect(r.stderr).toContain("cannot launch");
        const doc = parseResult(readFileSync(meta, "utf8"));
        expect(doc.code).toBe("CHILD_LAUNCH_FAILED");
        expect(doc.state).toBe("failed"); // K5
        expect(doc.data).toEqual({ launched: false, exit_code: null, signal: null });
      }
    } finally {
      t.cleanup();
    }
  });

  test("usage: missing -- or empty argv → exit 2, stderr only", () => {
    for (const args of [["run"], ["run", "echo", "x"], ["run", "--"], ["run", "--meta-file"], ["run", "--bogus", "--", "true"]]) {
      const r = proto(args);
      expect(r.code).toBe(2);
      expect(r.stdout.byteLength).toBe(0);
      expect(r.stderr.length).toBeGreaterThan(0);
    }
  });

  test("cwd and environment inherited", () => {
    const t = tempDir();
    try {
      const r = proto(["run", "--", "/bin/sh", "-c", 'pwd -P; printf "%s" "$G02_MARK"'], { cwd: t.spaced, env: cleanEnv({ G02_MARK: "mark ü $x" }) });
      expect(r.code).toBe(0);
      const [cwd, mark] = r.stdoutText.split("\n");
      expect(cwd!.endsWith("spaced dir ü")).toBe(true);
      expect(mark).toBe("mark ü $x");
    } finally {
      t.cleanup();
    }
  });
});

// Child that records each forwarded signal and keeps running until told to stop.
const CHILD = `log="$1"
for s in INT TERM HUP QUIT WINCH; do trap "echo $s >> \\"$log\\"" $s; done
echo ready >> "$log"
while [ ! -f "$log.stop" ]; do sleep 0.02; done
echo done >> "$log"
exit 3
`;

// Python child: its SIGINT handler runs promptly (unlike sh traps, which are deferred
// while a foreground command runs and would coalesce a duplicate signal).
const PY_CHILD = `import os, signal, sys, time
log = sys.argv[1]
def rec(sig, frame):
    with open(log, "a") as f: f.write(signal.Signals(sig).name[3:] + "\\n")
signal.signal(signal.SIGINT, rec)
with open(log, "a") as f: f.write("ready\\n")
while not os.path.exists(log + ".stop"): time.sleep(0.01)
with open(log, "a") as f: f.write("done\\n")
sys.exit(3)
`;

// Python child recording every forwarded signal (K6 PTY test).
const PY_CHILD_ALL = `import os, signal, sys, time
log = sys.argv[1]
def rec(sig, frame):
    with open(log, "a") as f: f.write(signal.Signals(sig).name[3:] + "\\n")
for s in (signal.SIGINT, signal.SIGQUIT, signal.SIGWINCH, signal.SIGTERM, signal.SIGHUP):
    signal.signal(s, rec)
with open(log, "a") as f: f.write("ready\\n")
while not os.path.exists(log + ".stop"): time.sleep(0.01)
with open(log, "a") as f: f.write("done\\n")
sys.exit(3)
`;

function lines(path: string): string[] {
  return existsSync(path) ? readFileSync(path, "utf8").trim().split("\n") : [];
}

describe("run: signals", () => {
  test("SIGINT/TERM/HUP/QUIT/WINCH forwarded (no TTY); proto waits for child; no orphan", async () => {
    const t = tempDir();
    try {
      const script = join(t.spaced, "child.sh");
      const log = join(t.spaced, "log");
      const meta = join(t.spaced, "meta.json");
      writeFileSync(script, CHILD);
      const p = Bun.spawn([...PROTO, "run", "--meta-file", meta, "--", "/bin/sh", script, log], { stdin: "ignore", stdout: "pipe", stderr: "pipe", env: cleanEnv() });
      expect(await waitFor(() => lines(log).includes("ready"), 5000)).toBe(true);
      for (const sig of ["INT", "TERM", "HUP", "QUIT", "WINCH"]) {
        p.kill(`SIG${sig}` as NodeJS.Signals);
        expect(await waitFor(() => lines(log).includes(sig), 3000)).toBe(true);
      }
      await Bun.sleep(100);
      expect(p.exitCode).toBeNull(); // proto has not exited before the child
      writeFileSync(log + ".stop", "");
      await p.exited;
      expect(p.exitCode).toBe(3);
      expect(lines(log)).toEqual(["ready", "INT", "TERM", "HUP", "QUIT", "WINCH", "done"]);
      expect(parseResult(readFileSync(meta, "utf8")).data).toEqual({ launched: true, exit_code: 3, signal: null });
      // No orphan: no process still references the per-test script path.
      const ps = Bun.spawnSync(["/bin/ps", "-axo", "pid=,command="]);
      expect(dec(ps.stdout as Uint8Array)).not.toContain(script);
    } finally {
      t.cleanup();
    }
  });

  test("terminal Ctrl-C under a PTY reaches the child exactly once", async () => {
    const t = tempDir();
    try {
      const script = join(t.spaced, "child.py");
      const log = join(t.spaced, "log");
      writeFileSync(script, PY_CHILD);
      const p = Bun.spawn([...PROTO, "run", "--", "/usr/bin/python3", script, log], {
        env: cleanEnv(),
        terminal: { cols: 80, rows: 24, data() {} },
      } as any);
      expect(await waitFor(() => lines(log).includes("ready"), 5000)).toBe(true);
      (p as any).terminal.write("\x03");
      expect(await waitFor(() => lines(log).includes("INT"), 3000)).toBe(true);
      await Bun.sleep(300); // window for a duplicate forwarded SIGINT to arrive
      writeFileSync(log + ".stop", "");
      await p.exited;
      expect(p.exitCode).toBe(3);
      expect(lines(log).filter((l) => l === "INT").length).toBe(1);
    } finally {
      t.cleanup();
    }
  });

  // K6: under a PTY where heimdall-proto starts as the foreground group, terminal keys
  // and resizes reach the child once, explicit signals to heimdall-proto reach it once,
  // and the terminal's foreground group is given back afterwards.
  test("K6: PTY: terminal ^C/^\\/resize once each AND explicit kill INT/QUIT/WINCH/TERM/HUP to proto once each; fg group restored", async () => {
    const t = tempDir();
    try {
      const script = join(t.spaced, "child.py");
      const log = join(t.spaced, "log");
      const fgFile = join(t.spaced, "fg");
      writeFileSync(script, PY_CHILD_ALL);
      const q = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;
      const cmd = [...PROTO, "run", "--", "/usr/bin/python3", script, log].map(q).join(" ");
      // Non-interactive sh: heimdall-proto runs in the shell's (foreground) group.
      const wrapper = `${cmd}; echo $? > ${q(fgFile)}.status; /bin/ps -o tpgid=,pgid= -p $$ > ${q(fgFile)}`;
      const sh = Bun.spawn(["/bin/sh", "-c", wrapper], { env: cleanEnv(), terminal: { cols: 80, rows: 24, data() {} } } as any);
      const term = (sh as any).terminal;
      const count = (s: string) => lines(log).filter((l) => l === s).length;
      expect(await waitFor(() => lines(log).includes("ready"), 5000)).toBe(true);
      const protoPid = (() => {
        const ps = dec(Bun.spawnSync(["/bin/ps", "-ax", "-o", "pid=,ppid="]).stdout as Uint8Array);
        for (const l of ps.trim().split("\n")) { const [pid, ppid] = l.trim().split(/\s+/).map(Number); if (ppid === sh.pid) return pid!; }
        return null;
      })();
      expect(protoPid).not.toBeNull();
      term.write("\x03");
      expect(await waitFor(() => count("INT") === 1, 3000)).toBe(true);
      term.write("\x1c");
      expect(await waitFor(() => count("QUIT") === 1, 3000)).toBe(true);
      term.resize(100, 30);
      expect(await waitFor(() => count("WINCH") === 1, 3000)).toBe(true);
      await Bun.sleep(300); // window for duplicates of the terminal-generated signals
      expect([count("INT"), count("QUIT"), count("WINCH")]).toEqual([1, 1, 1]);
      for (const [sig, n] of [["INT", 2], ["QUIT", 2], ["WINCH", 2], ["TERM", 1], ["HUP", 1]] as const) {
        process.kill(protoPid!, `SIG${sig}`); // exact PID of the heimdall-proto we started
        expect(await waitFor(() => count(sig) === n, 3000)).toBe(true);
      }
      await Bun.sleep(300);
      writeFileSync(log + ".stop", "");
      await sh.exited;
      expect(readFileSync(fgFile + ".status", "utf8").trim()).toBe("3");
      expect([count("INT"), count("QUIT"), count("WINCH"), count("TERM"), count("HUP")]).toEqual([2, 2, 2, 1, 1]);
      const [tpgid, pgid] = readFileSync(fgFile, "utf8").trim().split(/\s+/);
      expect(tpgid).toBe(pgid); // the wrapper shell's group is the foreground group again
    } finally {
      try { writeFileSync(join(t.spaced, "log.stop"), ""); } catch {} // child exits even if an assertion failed
      await Bun.sleep(100);
      t.cleanup();
    }
  });

  test("K6 side effect: PTY Ctrl-Z stops the child, proto takes the terminal back and stops; SIGCONT resumes both", async () => {
    const t = tempDir();
    try {
      const script = join(t.spaced, "child.py");
      const log = join(t.spaced, "log");
      writeFileSync(script, PY_CHILD_ALL);
      const q = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;
      const cmd = [...PROTO, "run", "--", "/usr/bin/python3", script, log].map(q).join(" ");
      const sh = Bun.spawn(["/bin/sh", "-c", `${cmd}; echo $? > ${q(log)}.status`], { env: cleanEnv(), terminal: { cols: 80, rows: 24, data() {} } } as any);
      expect(await waitFor(() => lines(log).includes("ready"), 5000)).toBe(true);
      const ps = (args: string[]) => dec(Bun.spawnSync(["/bin/ps", ...args]).stdout as Uint8Array).trim();
      let protoPid = 0;
      for (const l of ps(["-ax", "-o", "pid=,ppid="]).split("\n")) { const [pid, ppid] = l.trim().split(/\s+/).map(Number); if (ppid === sh.pid) protoPid = pid!; }
      expect(protoPid).toBeGreaterThan(0);
      (sh as any).terminal.write("\x1a");
      expect(await waitFor(() => ps(["-o", "stat=", "-p", String(protoPid)]).startsWith("T"), 3000)).toBe(true);
      const [tpgid, pgid] = ps(["-o", "tpgid=,pgid=", "-p", String(protoPid)]).split(/\s+/);
      expect(tpgid).toBe(pgid); // terminal back with heimdall-proto's group
      process.kill(protoPid, "SIGCONT"); // exact PID of the heimdall-proto we started
      expect(await waitFor(() => !ps(["-o", "stat=", "-p", String(protoPid)]).startsWith("T"), 3000)).toBe(true);
      writeFileSync(log + ".stop", "");
      await sh.exited;
      expect(readFileSync(log + ".status", "utf8").trim()).toBe("3");
      expect(lines(log)).toEqual(["ready", "done"]); // no signal forwarded to the child
    } finally {
      try { writeFileSync(join(t.spaced, "log.stop"), ""); } catch {} // child exits even if an assertion failed
      await Bun.sleep(100);
      t.cleanup();
    }
  });

  test("K6: child runs in its own process group (no TTY)", () => {
    const r = proto(["run", "--", "/bin/sh", "-c", "/bin/ps -o pid=,pgid= -p $$"]);
    expect(r.code).toBe(0);
    const [pid, pgid] = r.stdoutText.trim().split(/\s+/);
    expect(pgid).toBe(pid);
  });

  test("SIGINT to proto when child does not trap it → child dies by SIGINT, exit 130", async () => {
    const p = Bun.spawn([...PROTO, "run", "--", "/bin/sleep", "5"], { stdin: "ignore", stdout: "pipe", stderr: "pipe", env: cleanEnv() });
    await Bun.sleep(300);
    p.kill("SIGINT");
    await p.exited;
    expect(p.exitCode).toBe(130);
  });
});
