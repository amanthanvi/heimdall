# H1 scripted CLI harness

H1 runs fixed task sequences through Heimdall's public CLI. It needs Python 3.9
or newer and uses the standard library. The fixture driver owns the scratch
runtime, fixture profiles, and cleanup.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -I -B examples/harnesses/cli/harness.py \
  --heimdall-bin "$debug_bin" --scratch-root "$scratch" \
  --profile "$covered_profile" --task discover --task covered --task release
```

Pass an absolute executable path and a private, absolute scratch root containing
separate `home`, `heimdall-home`, and `ssh-home` directories. `ssh-home/etc-ssh`
must be empty. Each call checks these directories and starts in the scratch root
with the fixture homes and fixed `PATH`, `LANG`, and `TERM`. The homes are checked
by their real paths and passed under the root as you gave it, so the calls reach
the runtime the driver started under that same path. The fixture driver starts a
ready debug runtime before the journey.

| Task | Fixture and result |
| --- | --- |
| `discover` | Reads `schema show codes` and the running fixture's `inspect capabilities`. |
| `covered` | Preapproved profile. One `access ensure` reaches `ACCESS_READY` and supplies the binding for `release`. |
| `approval` | Profile with a missing pair. `--approval-pair destination:account` enables the fixture-driver handoff. |
| `timeout` | A fresh profile with delayed preparation. After the 1 ms caller timeout, `operation wait` observes the original ensure reach `ACCESS_READY`. |
| `bind-run` | Preapproved profile. Supply an absolute scratch child executable and its arguments through `--child` at the end of the command. The child prints `h1-fixture-child` and exits 0. |
| `release` | Run `covered` earlier in the same invocation. `access release` drops its binding. |
| `capability-refusal` | Existing-access profile. `access ensure --require-unattended` must exit 4 with `CAPABILITY_UNAVAILABLE` and effect `none`. |

Repeat `--task` to execute tasks in order. Use separate invocations when the
profiles differ. `approval` and `bind-run` report that they need the U5h Rust
fixture driver when their fixture arguments are absent. For approval, H1 writes
one JSON handoff record with `operation_id` and `decision_ref` to stderr. The
driver handles approval in an attended fixture terminal and then writes
`continue` followed by a newline to H1's stdin. H1 resumes its operation-scoped
NDJSON subscription from the cursor captured before the handoff and observes
the result of the same operation.

Stdout contains one JSON summary. Calls and round trips count CLI subprocess
invocations. Discovery bytes count raw stdout bytes from the discovery calls.
Wall time excludes the approval handoff. The process exits 0 when all selected
tasks succeed and 1 when any selected task fails or is skipped.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -I -B -m unittest discover -s examples/harnesses/cli/tests
```

Set `HEIMDALL_HARNESS_SMOKE_BIN` to an absolute path to the built debug binary
to include the discovery smoke. It creates a fresh fixture root, checks the
real code table, and verifies that capabilities inspection reports
`SERVICE_UNAVAILABLE` with no runtime present.
