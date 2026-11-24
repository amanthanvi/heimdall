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
image. Step (ii), the delaying relay in front of the session bus, follows.

**Earlier runs** (`ss1` to `ss5`) were harness tryouts and are not kept:
- the runtime started in the foreground;
- `time confirm` missing;
- the ceremony's diagnosis not yet recorded.
