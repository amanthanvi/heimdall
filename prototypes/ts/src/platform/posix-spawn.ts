// Unix child launch with job control (contract §4, ruling K6), via bun:ffi.
//
// Bun.spawn cannot put the child in its own process group (its only option is
// `detached`, i.e. setsid, which drops the controlling terminal). Without that, a
// terminal Ctrl-C reaches both heimdall-proto and the child, and heimdall-proto cannot
// tell it apart from an explicit `kill -INT <pid>` (Bun exposes no siginfo). So the
// child is launched with posix_spawnp + POSIX_SPAWN_SETPGROUP and, when heimdall-proto
// is the terminal's foreground group, the terminal is handed to the child's group.
// Terminal-generated signals then reach only the child; every signal heimdall-proto
// receives is forwarded exactly once.
//
// Native/unsafe boundary: libc calls with integer arguments, caller-owned buffers,
// and a NUL-terminated argv pointer array built here. Windows does not use this file.

import { dlopen, FFIType, ptr, read, type Pointer } from "bun:ffi";
import { constants as osConstants } from "node:os";

const isMac = process.platform === "darwin";
const SETPGROUP = 0x02;
const SETSIGDEF = 0x04;
const SETSIGMASK = 0x08;
const MAC_CLOEXEC_DEFAULT = 0x4000; // Apple extension: close every fd not named in file actions
const WNOHANG = 1;
const WUNTRACED = 2;
const SIG = osConstants.signals as Record<string, number>;

const P = FFIType.ptr;
const I32 = FFIType.i32;
const common = {
  posix_spawnattr_init: { args: [P], returns: I32 },
  posix_spawnattr_destroy: { args: [P], returns: I32 },
  posix_spawnattr_setflags: { args: [P, FFIType.i16], returns: I32 },
  posix_spawnattr_setpgroup: { args: [P, I32], returns: I32 },
  posix_spawnattr_setsigdefault: { args: [P, P], returns: I32 },
  posix_spawnattr_setsigmask: { args: [P, P], returns: I32 },
  posix_spawn_file_actions_init: { args: [P], returns: I32 },
  posix_spawn_file_actions_destroy: { args: [P], returns: I32 },
  sigfillset: { args: [P], returns: I32 },
  sigemptyset: { args: [P], returns: I32 },
  posix_spawnp: { args: [P, P, P, P, P, P], returns: I32 },
  waitpid: { args: [I32, P, I32], returns: I32 },
  tcgetpgrp: { args: [I32], returns: I32 },
  tcsetpgrp: { args: [I32, I32], returns: I32 },
  getpgrp: { args: [], returns: I32 },
  signal: { args: [I32, P], returns: P },
} as const;
const macOnly = {
  _NSGetEnviron: { args: [], returns: P },
  posix_spawn_file_actions_addinherit_np: { args: [P, I32], returns: I32 },
} as const;
const linuxOnly = { dlsym: { args: [P, FFIType.cstring], returns: P } } as const;

type Lib = ReturnType<typeof dlopen<typeof common & typeof macOnly & typeof linuxOnly>>["symbols"];
let lib: Lib | null = null;
function libc(): Lib {
  if (lib) return lib;
  const path = isMac ? "/usr/lib/libSystem.B.dylib" : "libc.so.6";
  lib = dlopen(path, { ...common, ...(isMac ? macOnly : linuxOnly) } as typeof common & typeof macOnly & typeof linuxOnly).symbols;
  return lib;
}

// The C `environ` as inherited (raw bytes, unlike process.env).
function environ(l: Lib): Pointer {
  if (isMac) return read.ptr(l._NSGetEnviron()!) as Pointer;
  const addr = l.dlsym(null, Buffer.from("environ\0"));
  if (!addr) throw new Error("environ not found");
  return read.ptr(addr) as Pointer;
}

// fd (0..2) of a terminal whose foreground process group is ours, or null. The first
// of fds 0..2 that is a terminal decides.
export function foregroundTtyFd(): number | null {
  const l = libc();
  const pg = l.getpgrp();
  for (const fd of [0, 1, 2]) {
    const fg = l.tcgetpgrp(fd);
    if (fg > 0) return fg === pg ? fd : null;
  }
  return null;
}

export type SpawnResult = { ok: true; pid: number } | { ok: false; errno: number };

// Launch `file` with `argv` in a new process group with default signal dispositions
// and an empty signal mask, inheriting fds 0..2, cwd and environ.
export function spawnInOwnGroup(file: string, argv: string[]): SpawnResult {
  const l = libc();
  const keep: Buffer[] = argv.map((a) => Buffer.from(a + "\0", "utf8"));
  const fileC = Buffer.from(file + "\0", "utf8");
  const argvPtrs = new BigUint64Array(keep.length + 1);
  keep.forEach((b, i) => (argvPtrs[i] = BigInt(ptr(b))));
  // Opaque libc objects: generously sized, caller-owned (glibc attr is 336 bytes,
  // sigset_t 128; Apple uses pointer-sized handles and a 4-byte sigset).
  const attr = new Uint8Array(1024);
  const fa = new Uint8Array(1024);
  const all = new Uint8Array(256);
  const none = new Uint8Array(256);
  const pid = new Int32Array(1);
  l.posix_spawnattr_init(attr);
  l.posix_spawn_file_actions_init(fa);
  try {
    l.sigfillset(all);
    l.sigemptyset(none);
    let flags = SETPGROUP | SETSIGDEF | SETSIGMASK;
    if (isMac) {
      flags |= MAC_CLOEXEC_DEFAULT;
      for (const fd of [0, 1, 2]) l.posix_spawn_file_actions_addinherit_np(fa, fd);
    }
    l.posix_spawnattr_setflags(attr, flags);
    l.posix_spawnattr_setpgroup(attr, 0);
    l.posix_spawnattr_setsigdefault(attr, all);
    l.posix_spawnattr_setsigmask(attr, none);
    const rc = l.posix_spawnp(pid, fileC, fa, attr, argvPtrs, environ(l));
    return rc === 0 ? { ok: true, pid: pid[0]! } : { ok: false, errno: rc };
  } finally {
    l.posix_spawn_file_actions_destroy(fa);
    l.posix_spawnattr_destroy(attr);
  }
}

// Give the terminal on `fd` to process group `pgid`. Returns false if refused.
export function giveTerminal(fd: number, pgid: number): boolean {
  return libc().tcsetpgrp(fd, pgid) === 0;
}

// Take the terminal back for our own group. We are a background group at this point,
// so SIGTTOU is ignored for the duration of the call (and only then: an ignored
// disposition would otherwise be inherited by later children).
export function reclaimTerminal(fd: number): void {
  const l = libc();
  const prev = l.signal(SIG.SIGTTOU!, 1 as Pointer); // SIG_IGN
  try {
    l.tcsetpgrp(fd, l.getpgrp());
  } finally {
    l.signal(SIG.SIGTTOU!, prev);
  }
}

export type WaitResult = { exitCode: number | null; signal: number | null };

// Poll waitpid until the child terminates. Stops by SIGTTIN/SIGTTOU (the child touched
// the terminal before it was handed over) are resumed with SIGCONT to its group; any
// other stop (e.g. Ctrl-Z) is passed to `onStop`.
export async function waitChild(pid: number, onStop: (sig: number) => void = () => {}, pollMs = 5): Promise<WaitResult> {
  const l = libc();
  const st = new Int32Array(1);
  for (;;) {
    const r = l.waitpid(pid, st, WNOHANG | WUNTRACED);
    if (r === pid) {
      const s = st[0]!;
      if ((s & 0x7f) === 0) return { exitCode: (s >> 8) & 0xff, signal: null };
      if ((s & 0xff) === 0x7f) {
        const stopSig = (s >> 8) & 0xff;
        if (stopSig === SIG.SIGTTIN || stopSig === SIG.SIGTTOU) {
          try { process.kill(-pid, "SIGCONT"); } catch { /* group gone */ }
        } else {
          onStop(stopSig);
        }
        continue;
      }
      return { exitCode: null, signal: s & 0x7f };
    }
    if (r < 0) return { exitCode: null, signal: null }; // not our child any more (should not happen)
    await Bun.sleep(pollMs);
  }
}
