# G02 round 4, X1d: post-fix linux-x64 artifacts on two Linux hosts without a Go or Rust toolchain

**Task:** `M00-T05-r5-x1d-linux-hosts`, run on 2026-10-31 (UTC).

**Why.** plan.md §3 G02 asks to "test release artifacts on clean Windows, macOS, and Linux machines without the
candidate's development toolchain". Until now, the Linux artifact runs used one of two setups:

- the pinned container (round 3, linux-arm64);
- the development hosts, with the toolchain only hidden from PATH.

X1 and X1c were in the second group: the WSL2 host has `go` and `gofmt` in `/usr/bin`, so only their empty-PATH runs
were free of a toolchain. X1d runs the same post-fix artifacts as X1c on two of the owner's Linux hosts that have
no Go or Rust toolchain installed at all. It uses X1c's method, adds checks of what a user of the single file needs,
and compares every check with X1c.

| | go `84c7665` | rust `001a791` |
|---|---|---|
| Summary records | `tests/evidence/g02-go-linux-x64-no-toolchain-hosts.json` | `tests/evidence/g02-rust-linux-x64-no-toolchain-hosts.json` |
| Record status / verdict | `verified` / **pass** | `verified` / **pass** |
| ubuntu2404-kvm: harness exit, pass/fail/error/skipped of 139 | 0, 139/0/0/0 | 0, 139/0/0/0 |
| debian13-x64: harness exit, pass/fail/error/skipped of 139 | 0, 139/0/0/0 | 0, 139/0/0/0 |
| go, gofmt, rustc, cargo, rustup on either host | none (`command -v` in a non-interactive and a login shell; file search) | same |
| No-toolchain commands (`notoolchain.sh`, 14 per host) | X1c's exit codes on both hosts | same |
| User checks (`user-checks.sh`) | all as expected on both hosts | same |
| Check outcomes and assertions vs X1c | identical on both hosts | identical on both hosts |

## The hosts: what they are and are not

Neither host is a clean machine in the strict sense. Both are the owner's long-lived servers, not fresh installs,
and both carry other software, including a C compiler. What they share is that no Go or Rust toolchain was ever
installed on either. Both were reached over SSH with the owner's SSH config, as a non-root user. Host names, user
names and addresses are not recorded; the hosts are named only by these labels.

| | ubuntu2404-kvm | debian13-x64 |
|---|---|---|
| Kind | KVM guest (`systemd-detect-virt`: kvm) | `systemd-detect-virt`: none |
| OS | Ubuntu 24.04.5 LTS | Debian GNU/Linux 13 (trixie) |
| Kernel | 6.8.0-147-generic, x86_64 | 6.12.107+deb13-amd64, x86_64 |
| glibc | 2.39 (Ubuntu GLIBC 2.39-0ubuntu8.9) | 2.41 (Debian GLIBC 2.41-12+deb13u4) |
| CPUs / RAM | 4 / 8 GB | 16 / 64 GB |
| bash / zsh | 5.2.21 / not installed | 5.2.37 / not installed |
| OpenSSH (harness's ssh-keygen) | 9.6p1 Ubuntu-3ubuntu13.20 | 10.0p2 Debian-7+deb13u4 |
| Python (harness) | 3.12.3, with venv/ensurepip | 3.13.5, **without ensurepip and pip** |
| coreutils | 9.4 | 9.7 |
| Locale | LANG=C.UTF-8 | LANG=C.UTF-8 |
| Load average during the harness (1/5/15) | ≤ 0.10 (idle) | 10.6 to 15.3 at the 1-minute figure (busy; first probe of the day: 29 to 32) |
| Other software (by category) | the owner's service in a container runtime; gcc, cc, make; Perl; Node.js in the user's `~/.local/bin`; tmux; strace | CPU-bound worker and headless-browser processes of the owner's projects; gcc, cc, make; Perl; bubblewrap; tmux |
| Toolchain leftovers | a Go module cache (`<home>/go/pkg`) and build cache (`<home>/.cache/go-build`) from earlier use, with no `go` executable | none |

**Toolchain absence** (`<label>/hostfacts-start.txt`, repeated in `hostfacts-end.txt`). Three searches found nothing
on either host:

- `command -v` for go, gofmt, rustc, cargo and rustup, in the non-interactive SSH shell;
- the same in a login shell (`bash -lc`, which reads the profile files);
- `find /usr/local /opt /usr/lib <home> -maxdepth 5 -type f -perm -u+x` for those names.

None of the usual toolchain directories (`/usr/local/go`, `/usr/lib/go`, `~/.cargo`, `~/.rustup`, `~/sdk`) exists.
`/usr/bin` holds `gcc` and `cc` on both hosts but no `go`, `gofmt` or `node`. So, unlike on X1c's host, the
`PATH=/usr/bin:/bin` runs are free of the Go and Rust toolchains too.

## Inputs and digests

| Input | sha256 |
|---|---|
| `prototypes/go/dist/linux-x64/heimdall-proto` (5,451,936 bytes, the only file in its directory) | `bfb668bb0f7045e3f50606ccd2acff444ed5c4e733400b997624519e0fc23c3b` |
| `prototypes/rust/dist/linux-x64/heimdall-proto` (887,072 bytes, the only file in its directory) | `7b1b3fcfc64031fe76625164c06c7181d800f3af1cf51cd0425688f95531769d` |
| `harness.tar`: `git archive` of `51413ebb` (HEAD at staging), `tests/g02` without `selftest-results`, `tests/fixtures/g02`, `tests/fixtures/fake-agent`, `schemas/g02`, `tests/evidence/record.schema.json` | `87b8124e…f0d5` (`inputs.sha256`) |
| `pyte-0.8.2-py3-none-any.whl`, `wcwidth-0.9.1-py3-none-any.whl` | equal to the `tests/g02/requirements.txt` pins (`inputs.sha256`) |

The artifact digests equal `artifact_digest` in X1c's records (`tests/evidence/g02-{go,rust}-conformance-linux-x64-x1b.json`).
They were checked on the Mac before staging and again by `sha256sum -c` on each host (`<label>/setup.txt`); each
copy made by `user-checks.sh` was hashed too. Nothing was rebuilt. For the harness files,
`git diff 772a6b1 51413ebb` is empty, so they are the files X1 and X1c ran. HEAD moved from `972321ce` to `51413ebb`
during the task, through an orchestrator commit outside these paths.

## Method

The scripts are in this directory; `commands.txt` lists every command with its exit code.

- `hostfacts.sh` records the host facts above at the start and the end. It prints named fields only, with no
  environment dump.
- `setup.sh` is X1c's setup with one fallback. On ubuntu2404-kvm, `python3 -m venv` and
  `pip install --require-hashes -r tests/g02/requirements.txt` worked as in X1c. On debian13-x64, `python3 -m venv`
  failed with exit 1 (`venv.log`: "ensurepip is not available ... install the python3-venv package"); no package may
  be installed and sudo is not allowed. The fallback:
  - on the Mac, pip downloaded the same two wheels in hash-checking mode (`pip download --require-hashes`);
  - on the host, `python3 -m venv --without-pip` created the venv in the scratch directory;
  - `wheel-install.py` checked each wheel's sha256 against the `requirements.txt` pin and accepted only pure-Python
    members without `..` or absolute paths, then unpacked both into the venv's site-packages (`debian13-x64/pip.log`);
  - pyte 0.8.2 and wcwidth 0.9.1 then import with those versions.
- `run-linux.sh <label>` is X1c's runner with these changes: scratch path, host label, `--build-commit 51413ebb`,
  case ids ending in `-x1d-<label>`, the `native_host` fields (virtualisation and glibc instead of WSL), and the
  harness under `nice -n 10`. It ran the full catalogue natively (no container), Go first and then Rust, detached
  (`setsid nohup`). The two hosts ran at the same time; they share no machine.
- `notoolchain.sh` is X1c's script except for the scratch path. It ran after each host's harness runs.
- `user-checks.sh` is new (next section). It ran after `notoolchain.sh`, also under `nice -n 10`.
- `redact.py`, `compare.py` and `make-records.py` handle redaction, the comparison with X1c, and the records.

## Results per host

Console logs: `<label>/console-{go,rust}.log`. Per-check artifacts: `<label>/arts-{go,rust}/`. Full harness records:
`<label>/g02-<c>-conformance-linux-x64-x1d-<label>.json`. Times and load: `<label>/run-linux.log`.

| | ubuntu2404-kvm go | ubuntu2404-kvm rust | debian13-x64 go | debian13-x64 rust |
|---|---|---|---|---|
| Harness exit / status / verdict | 0 / verified / pass | 0 / verified / pass | 0 / verified / pass | 0 / verified / pass |
| pass / fail / error / skipped | 139 / 0 / 0 / 0 | 139 / 0 / 0 / 0 | 139 / 0 / 0 / 0 | 139 / 0 / 0 / 0 |
| Duration | 182.7 s | 183.0 s | 182.0 s | 181.8 s |
| Load average start → end (harness) | 0.07 → 0.10 | 0.10 → 0.07 | 15.29 → 10.94 | 10.94 → 10.59 |
| K3a reset (before reply / after one byte) | ECONNRESET / ECONNRESET | same | same | same |
| K10 exit form (SIGTERM, SIGHUP, hangup ×2) | 143, 129, 129, 129 | same | same | same |
| K16 helper tripwire hits | none | none | none | none |
| `canary.no_canary_anywhere`, `harness.canary_selfcheck`, `common.no_stray_writes` (K11) | pass | pass | pass | pass |
| First TUI frame (X1c) | 41.3 ms (35.7) | 22.4 ms (17.6) | 37.8 ms (35.7) | 17.2 ms (17.6) |
| K17 filter p95, bound 100 ms (X1c) | 17.7 ms (17.4) | 2.6 ms (1.8) | 19.1 ms (17.4) | 2.7 ms (1.8) |
| Agent SIGINT exit latency (X1c) | 0.8, 0.8, 0.8 ms (1.4, 1.0, 0.9) | 5.6, 5.7, 5.8 ms (5.8, 5.7, 5.7) | 1.3, 0.9, 0.8 ms | 5.5, 5.5, 5.6 ms |
| Resize relayout median / max (X1c) | 15.2 / 16.1 ms (15.45 / 17.0) | 1.1 / 1.4 ms (0.8 / 1.1) | 15.25 / 17.2 ms | 0.85 / 1.4 ms |

Non-gating failed assertions are the same as X1c's:

- **Both candidates, both hosts:** the zsh forms of K6e (`harness precondition: /bin/zsh is executable`), because
  zsh is not installed.
- **Go only:** `[bash SIGSTOP] the stop notice word ... equal the direct-exec control's`. It also fails, non-gating,
  in X1c and the earlier Go records.

On debian13-x64 the harness added its own limitation, "Machine load was high during the run", since the load
exceeded 0.75 × CPUs. No timing-bound check failed there. Timing observations on that host come from a busy
machine, under `nice -n 10`.

## What a user without the toolchain needs

**One file, statically linked.** Each `dist/linux-x64` directory holds only `heimdall-proto`. On both hosts, `file`
reports "ELF 64-bit LSB executable, x86-64, ... statically linked, ... stripped" (Go also gives its build ids), and
`ldd` says "not a dynamic executable" (exit 1). The glibc version (2.39 vs 2.41) therefore plays no part.

**No-toolchain commands** (`<label>/notoolchain.txt`, X1c's commands). Each artifact ran under `env -i`, with
`PATH=/usr/bin:/bin` and with an empty PATH directory:

| Command | Both PATH forms, both hosts |
|---|---|
| `version --json` | 0 |
| `profile show` homelab / spaced | 0, `PROFILE_OK` |
| `profile show` forbidden-key | 2, `SCHEMA_INVALID`, 0 canary-prefix hits |
| `run -- /bin/sh -c 'exit 7'` | 7 |
| `agent list` on a missing socket | 5, `AGENT_UNAVAILABLE` |

`run -- true` gives 0 with `PATH=/usr/bin:/bin`. With the empty PATH directory it gives 127, with X1c's
per-candidate messages: Go "command not found", Rust "cannot launch command: NotFound". Every line matches X1c's
`notoolchain.txt` apart from the toolchain listing at the top: here `/usr/bin:/bin` holds only `cc` and `gcc`.

**User checks** (`<label>/user-checks.txt`). Each artifact was copied alone into
`<scratch>/u dir ü 東 spaced/<c> bin ü/`, with a copy of the spaced fixture profile named `prøfile homelab ü.toml`.
It ran from there with that directory as working directory, under `env -i PATH=<empty dir>` (no HOME, no TMPDIR).
The five commands were `version --json`, `profile show` of the local copy, `profile show` of the forbidden-key
fixture, `run -- /bin/sh -c 'exit 7'`, and `agent list` on a missing socket path in that directory. The expected
exits are 0, 0, 2, 7 and 5.

| Check | ubuntu2404-kvm (both candidates) | debian13-x64 (both candidates) |
|---|---|---|
| Absolute path and `./heimdall-proto`, from the spaced non-ASCII directory | 0, 0, 2, 7, 5 | 0, 0, 2, 7, 5 |
| HOME, TMPDIR and the working directory read-only (`chmod 555`; control write refused) | 0, 0, 2, 7, 5; no new entries | same |
| Write-class system calls (`strace -f`; raw logs in `strace-{go,rust}/`) | 0 for each command; the control `sh` write shows 1 | strace not installed |
| Whole file system read-only (`bwrap --ro-bind / / --dev /dev --proc /proc --unshare-pid`) | bwrap not installed | 0, 0, 2, 7, 5; controls: `/bin/true` 0, writes to `<scratch>`, `/tmp` and `<home>` fail with "Read-only file system" |

The strace scan covers:

- `open`, `openat` and `openat2` with a write, create, truncate or append flag;
- `creat`, `mkdir*`, `rename*`, `unlink*`, `rmdir`, `link*`, `symlink*`, `truncate`, `chmod*`, `chown*`,
  `utimensat`, `mknod*` and `bind`.

It follows children, so `run`'s `/bin/sh` is included. bwrap's `/dev` is its own minimal device tree, so writes to
devices are not tested there.

**What the harness already covers.** `common.no_stray_writes` (K11) checks that no invocation leaves a new file in
HOME, TMPDIR, the working directory or the `--meta-file` directory. Per the harness's own limitation, writes
elsewhere (a hard-coded `/tmp`, say) are not detected. The harness also covers:

- paths with spaces and non-ASCII characters for the profile, the agent socket, `--meta-file` and the working
  directory (`profile.spaced_unicode_path`, `agent.unicode_spaced_socket_path`, `cwd ü ro`);
- the canary scans.

It does not move the binary itself into such a directory, and it does not cover writes outside the sandbox. The two
X1d write checks close that gap only for the five commands above. They do not cover the TUI, `agent list` against a
live agent, or long-running `run` children.

## Comparison with X1c

All of this is in `compare.txt`. It compares each host with X1c (same artifacts, WSL2 Ubuntu 24.04.5, kernel
6.18.54.1) and the two hosts with each other.

1. **Check outcomes:** all 139 checks pass in all three runs, for both candidates.
2. **Assertions:** every check has the same assertion count and the same set of failed (non-gating) assertions as
   X1c, on both hosts and for both candidates.
3. **heimdall-proto invocations:** all 228 paired captures per comparison have the same exit code, timeout state
   and leftover-process state.

   As in X1c's comparison with X1, 17 stdout digests differ because the content is per run:
   - agent listings carry fingerprints of per-run generated keys (13 captures);
   - `run.argv_exact` and `run.cwd_env_inherited` contain the per-run `/tmp/hmg02-*` directory;
   - `run.k6a_inherited_ignore` (two captures) prints `/proc/self/status`. The recorded excerpt has the same 59
     field names in the same order on all three kernels; the values (PIDs, memory, context switches) and the
     length (1489 / 1533 / 1519 bytes) differ.

   The other differences:
   - **Go `agent.slow_timeout` [timeout-300], ubuntu2404-kvm only:** the message reads "read failed" instead of
     X1c's "read: no complete response within timeout"; debian13-x64 matches X1c. This is the deadline race
     X1c described for `agent.timeout_whole_response`. The connection deadline and the context timeout fall at the
     same instant, and the wording depends on which one is seen first. The round-3 linux-arm64 Go record already
     shows "read failed" in this check (timeout-1200), so it is not new. The check gates exit 5, `AGENT_UNAVAILABLE`
     and the elapsed time; both runs pass it.
   - **`run.k6a_inherited_ignore` [direct-yes-ignore] stderr, debian13-x64, both candidates:** the message reads
     "yes: standard output: Broken pipe" instead of "/usr/bin/yes: ...". This capture is the harness's direct-exec
     control, which runs `yes` without heimdall-proto. The difference comes from coreutils 9.7 against 9.4, not from
     the artifact.
4. **Observations:** apart from timing, the only differences are in the harness's own OS probe,
   `harness_os_probe_back_to_back_signal_merge`. It measures how the kernel merges two back-to-back signals from a
   harness wrapper, not heimdall-proto. Duplicates seen:

   | | X1c (WSL2 6.18) | ubuntu2404-kvm (6.8) | debian13-x64 (6.12, busy) |
   |---|---|---|---|
   | go run | 0/10 | 0/10 | 3/10 |
   | rust run | 3/10 | 0/10 | 5/10 |

   The harness writes its "K6 exactly-once" limitation in the form that matches the outcome, so that line differs
   too. Timings are in the same range as X1c (table above). Durations are 181.8 to 183.0 s against X1c's 181.3 and
   182.3 s.
5. **Harness limitation lines:** besides the signal probe line, debian13-x64 has the "Machine load was high" line.
   Nothing else differs (`compare.py` compares only the lines the harness wrote).

## Limitations

- **Not freshly installed machines.** Both hosts lack a Go and Rust toolchain but are long-lived and carry other
  software, including a C compiler. A static binary does not use the compiler; that it is not needed is shown by
  the static linking and the empty-PATH runs, not by its absence. ubuntu2404-kvm also keeps a Go module cache and
  build cache from earlier use, which the binaries do not read (no `go` executable exists to use them).
- **Busy host.** debian13-x64 ran the owner's workloads throughout (load 10.6 to 15.3 during the harness, 29 to 32
  earlier). No timing-bound check failed, but its timing observations are not idle-machine figures. Both hosts ran
  the harness at `nice -n 10`.
- **Modified venv method on debian13-x64.** pip did not run there. The same two hash-pinned wheels were unpacked by
  `wheel-install.py`, which does not run pip's install step (no RECORD rewrite, no entry points; neither package
  has entry points the harness uses).
- **Two distributions and kernels** (Ubuntu 24.04 with 6.8, Debian 13 with 6.12), both glibc-based and x86_64.
  musl-based distributions, older glibc releases, other kernels and arm64 hosts are not covered here. The binaries
  are static, so glibc is not loaded.
- **zsh is not installed** on either host, so the zsh K6e forms (non-gating) were not run; bash gated K6e.
- **Write checks:** strace on ubuntu2404-kvm and bwrap on debian13-x64, each for five commands only (see above). The
  first ubuntu user-check run deleted its raw strace logs, so it was re-run with the logs kept (`commands.txt`); both
  runs' text output is kept.
- **Artifact provenance** as in X1c: the bytes the X1b fix round built and its reviewers reproduced. That the
  committed `84c7665` / `001a791` trees reproduce them was not re-checked; nothing was rebuilt.
- **Not a K13 verdict platform.** linux-x64 does not decide K13; these records are G02 practical-distribution
  evidence.
- **One run per candidate per host.** Timing observations are single samples.
- **No independent review of this run.**

## Redaction

`redact.py` replaced each host's home directory with `<home>`. In the raw outputs, every hit of the remote user name
was inside that path: 666 hits on ubuntu2404-kvm and 661 on debian13-x64, 0 after the copy. The host names and SSH
aliases had 0 hits before and after.

A final scan of this directory and the two summary records found:

- no remote or Mac user name, and no host name or SSH alias;
- no `/Users/` or `/home/` path (the only hits are those words naming the scan patterns, here and in
  `commands.txt`);
- no IPv4 address (the only match is X1c's kernel version, 6.18.54.1);
- no full canary value.

The identifier values were kept in files outside the repository and deleted with the staging directory. The
harness's own canary checks passed in all four runs. The host records keep the harness's `started_at` with each
host's local UTC offset.

## Cleanup

- On both hosts, before removal: no process had its working directory in the scratch directory, no `heimdall-proto`
  process was running, and none of the PIDs this task started still existed. Then `<home>/hm-m00/M00-T05-r5-x1d`
  was removed. `~/hm-m00` did not exist before the task, so it was removed too (`rmdir`, exit 0).
- No bwrap control file and no `/tmp/hmg02-*` sandbox owned by the user was left on either host.
- The Mac staging directory under `/tmp` (stage, raw outputs, identifier files) was removed after the evidence was
  written.
- Nothing was built, so there are no build outputs to prune.

## Files

- **Per host** (`ubuntu2404-kvm/`, `debian13-x64/`):
  - `hostfacts-start.txt`, `hostfacts-end.txt`, `mkdir.txt`, `setup.txt`, `launch.txt`;
  - `pip.log` (on debian13-x64, the `wheel-install.py` output), `venv.log`;
  - `run-linux.log`, `console-{go,rust}.log`, `arts-{go,rust}/`;
  - `g02-{go,rust}-conformance-linux-x64-x1d-<label>.json` (the harness records, with evidence paths mapped and
    X1d limitation lines appended);
  - `notoolchain.txt`, `user-checks.txt`;
  - ubuntu2404-kvm only: `user-checks.first-run.txt` and `strace-{go,rust}/`.
- **Shared:** `inputs.sha256`, `compare.txt`, `commands.txt`, and the scripts named in Method.

## Reproduce

1. Stage `harness.tar` (the `git archive` above), the two `dist/linux-x64` artifacts as `art/<c>/heimdall-proto`,
   and the two wheels (`pip download --require-hashes`), with `inputs.sha256` and the scripts.
2. In `<home>/hm-m00/M00-T05-r5-x1d`, run `setup.sh`, then `run-linux.sh <label>`, then `notoolchain.sh` and
   `user-checks.sh`. Run `hostfacts.sh` before and after.
3. Run `redact.py copy`, then `compare.py`, then `make-records.py`.
