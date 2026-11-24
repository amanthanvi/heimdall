# Secret-service probe, step (i): a release managed recipe in a container (2026-11-24)

A rehearsal on W2's build: the Linux arm64 release archive of `605f7286`, executable
`54ecd273…`. It counts toward no release row. The plan is m08-w3-plan W3-6 and W3-4, ruled
2026-11-24.

**The container:**
- Image `hm-m08-secret-service:1`, from `tools/benchmarks/m08/Dockerfile.secret-service`. Its
  image ID and every installed package are in `image.json` and `packages.txt`.
- The base is pinned by digest, and the packages named there by version.
- Run with `--network none`, 2 CPUs, 2 GiB, 512 processes and an init process.
- Inside, as the unprivileged account: `dbus-run-session`, and
  `gnome-keyring-daemon --unlock --components=secrets` fed a random password on stdin only.

**No test hook:** no `HEIMDALL_TEST_*` variable, and the scripts refuse if one is set.

**What is kept:**
- Codes, states, counts and permissions only.
- The CA ceremony's terminal transcript holds the backup passphrase. It stays in the container's
  own scratch and is shredded there.
- From it only the text after the last "written" prompt is read, and only its JSON envelope's
  fields are kept.
- Each run is a fresh container, removed at the end.

| Run | What it did | Result |
|---|---|---|
| `ss6` (`facts-fresh-ss6.ndjson`) | `issuer init` as the first owner command on a fresh install | The ceremony ran to the store write. It then exited 1, `INTERNAL_ERROR`, "this installation's environment is unknown". The backup file was written and the Secret Service held **1 orphan `heimdall-issuer` item** (0 before). A second `init` was refused before any prompt: exit 6, `CONFIG_CONFLICT`, "1 store item(s) no registration names exist". **This is finding M08-W3-F1** (a product defect in the issuer's approval path; fixed by the orchestrator's worker on `fix/issuer-init-fresh-install`) |
| `ss7` (`facts-prereq-ss7.ndjson`) | The benchmark world's prerequisites, one at a time, with `inspect environments` after each, then `issuer init`, a new runtime and `issuer unlock` | No environment record after `identity adopt`, `declare-interaction`, `destination add`, `setup apply` or `profile create`. **`access allow` writes it** (`native_session`, `automatic_activation` only). Then `issuer init` succeeded (CA `active`, 1 store item). After `service stop` and a new runtime, `issuer unlock` returned OK, so the CA key was loaded again from the container's Secret Service |

**Step (i) is answered yes:** a release build's managed recipe stores and reloads its CA key in a
real Secret Service inside the container, with no hook. That makes lane M feasible in this
image.

## Step (ii): issuer secret-store load under a slow Secret Service

`ss8` and `ss9` use the same image and executable as `ss7`. Each run:
1. follows the `access allow`-first order, then `issuer init` (CA `active`);
2. times three `issuer unlock` calls with the runtime on the real session bus;
3. restarts the runtime with its session bus behind `agent-delay.py`. The relay holds each
   request N ms, and its upstream is the bus socket, which is checked to belong to this account;
4. times three more unlocks;
5. runs `slow-store-keys.py`: bench.py's own `key_to_frame` (200 samples; timed when the
   screen shows the key's effect, absent before the key) while `issuer unlock` runs in a loop in
   the background.

Each unlock makes the runtime's issuer child load its CA from the store.

| Run | Relay delay | `issuer unlock`, real bus | `issuer unlock`, delayed bus | Background unlocks during the keys | `key_to_frame` quiet (P50 / P95) | `key_to_frame` under the slow store (P50 / P95) |
|---|---|---|---|---|---|---|
| `ss9` (`facts-slow-50ms-ss9.ndjson`, `slow-store-50ms-ss9.json`) | 50 ms | OK, 47 to 55 ms | **OK, 1574 to 1596 ms** | 5, all OK, P50 1583 ms | 0.74 / 0.90 ms, 0 missed | **0.74 / 0.87 ms**, 0 missed |
| `ss8` (`facts-slow-500ms-ss8.ndjson`, `slow-store-500ms-ss8.json`) | 500 ms | OK, 45 to 52 ms | **exit 4, `CAPABILITY_UNAVAILABLE`, about 9.07 s each** | 1, failed | 0.76 / 1.20 ms | 1.11 / 1.43 ms |

**What this shows:**
- **The delay is on a path the runtime waits on.** Each load through the delayed bus takes about
  30 times as long at 50 ms per request.
- **At 500 ms the store's per-operation bound ends the load.** The answer is
  `CAPABILITY_UNAVAILABLE`, so it fails closed: no fallback key and no plaintext.
- **TUI key handling is unaffected while those loads are in flight.** The P95 is within
  0.1 ms of the quiet run at 50 ms.

**The row, worded for the record:** "issuer secret-store load under a slow Secret Service". It
is not per-signature: a signature is in-memory work in the issuer child once its key is loaded.

**What it is not:**
- a release-row number: it is a rehearsal on W2's build, on the Mac's Docker (Linux arm64,
  supplementary);
- the candidate's measurement, which W3-6 repeats with the same method.

The background latency includes each CLI's process start and its pseudo-terminal.

**Earlier runs** (`ss1` to `ss5`) were harness tryouts and are not kept:
- the runtime started in the foreground;
- `time confirm` missing;
- the ceremony's diagnosis not yet recorded.
