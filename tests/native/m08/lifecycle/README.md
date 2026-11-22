# Lifecycle journey (M08 U2a)

Install, update, roll back and uninstall from release archives (m08-plan §7.2, A31 journeys
1–3 and 6; ADR-0014 §3 and §4.3). **Provisional, to be integrated.**

| File | What it does |
|---|---|
| `install-selftest.sh` | Tests `tools/packaging/install.sh` with fake archives: no real executable is used or run, so it is safe on any host. 18 checks |
| `journey.sh` | The journey itself, run as a disposable account. `--build release` sets no test variable, refuses outside a container and refuses if any `HEIMDALL_TEST_*` is set; there is no override. `--build debug` exports and verifies all six scratch variables first; the debug journey itself is not written yet |
| `run-journey.sh` | Starts `journey.sh --build release` in the M08 container (no network, 2 CPUs, 2 GiB, an init process) |

## Runs

| Date | Archives | Result |
|---|---|---|
| 2026-11-22 | **Older:** Linux arm64, `m08/w0` at `c1a398cd` (product code = `main` at `de097dac`; newest state migration `0008_trusted_work`), sha256 `eb557652…2941f`. **Newer:** Linux arm64, the `m08/w0` tree at `8f1295f4` plus the uncommitted U2a files (newest migration `0012_remote_lift_acks`), sha256 `f60f72df…0e71a`. Both built with `--allow-dirty` (the older side with the current packaging scripts copied in), so both are rehearsal builds | **26 steps ok, 0 failed.** The update crosses migrations `0009_remote`, `0010_remote_widening`, `0011_remote_client_endpoints` and `0012_remote_lift_acks` |

| 2026-11-22 | the same two archives, with `--kill-before-update` | **28 steps ok, 0 failed.** Before the kill: main database file 4,096 bytes, the destination absent from it and present in the 1,462,632-byte write-ahead log. The runtime was ended with `SIGKILL`; the files were unchanged. After the update: `state.db.v8.backup`, 532,480 bytes, integrity ok, schema 8, 7 rows naming the destination. **The pre-migration backup held the work done before the unclean stop** |

What the first run showed:
- Both archives matched the external index before unpacking; the install used the archive's
  own script and edited no shell profile.
- An update was refused while the runtime ran and named `heimdall service stop`.
- After the update: the environment ID was unchanged, a login and a `connect` worked, the
  session held open since before the update was still alive, and a pre-migration backup
  `state.db.v8.backup` existed.
- After a rollback to the older executable: it did not serve the newer store, the
  environment ID was never different, and after rolling forward again the newer build
  served the same identity and access. **The refused rollback changed nothing.**
- After uninstall: the user's `~/.ssh/config` (with `Include`, a wildcard `Host` and a
  `Match` block of its own) was byte-identical to before setup, and an unrelated alias's
  effective configuration was unchanged.

**Two product observations from it, for the contract owner** (both are already planned
deltas in ADR-0014 §7; this is the evidence for them):
- **The older build does not say why it will not start on a newer store.** `heimdall
  connect` answered `SERVICE_UNAVAILABLE`, no reason, "the runtime did not become ready in
  time"; `status` said "no runtime is running"; `doctor` exited OK. Nothing told the user
  that the state is newer than the executable (H4).
- **Uninstall's list of what remains named the SSH configuration backup and the state
  store, and not the migration backup `state.db.v8.backup` or `heimdall.previous`** (H6).

**What this run does not cover:** a restore or a reset (not built); a corrupt store; Windows
and macOS; the WSL helper pair; an update with managed credentials, a paired environment or
the transport in use; a native (non-container) account.

**A harness defect found on the way:** the first two runs reported leftover `heimdall`
processes. They were zombies: the container had no init process to reap the older build's
failed start attempts. Both launchers now pass `--init`.
