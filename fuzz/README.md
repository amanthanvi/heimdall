# Fuzz targets (M08 U1a)

Coverage-guided fuzzing of the parsers that take outside input (ADR-0014 §2). **Provisional,
to be integrated:** seventeen targets cover boundaries 1–12 of ADR-0014 §2.1; 13–15 wait for
M06 and M07. Boundary 12 is covered only in its pure part: the known-hosts file reader and
the `ssh -G` output reader take files and a child process, and have no target.

- **Not part of the workspace.** `fuzz/Cargo.toml` has its own empty `[workspace]` table and
  its own `Cargo.lock`. The product's toolchain pin and lock file are untouched.
- **Built and run only in a container** (`run-campaign.sh`): `debian:13-slim`, the pinned
  nightly, cargo-fuzz 0.13.2, libfuzzer-sys 0.4.13. The repository is mounted read-only; the
  nightly, the crates, the build directory and the corpus live in the Docker volume
  `hm-m08-fuzz`, removed with `run-campaign.sh clean`. `setup` uses the network; `run` has none.
- **A finding is not evidence until it is reproduced on the pinned stable toolchain** as a
  regression test under `tests/adversarial/`. Crash inputs are hostile bytes: copy them out
  with `run-campaign.sh crashes <dir>` into a directory of their own.
- **The stopping rule** is ADR-0014 §2.3: at least 2 CPU-hours per target, no new coverage in
  the last 30 minutes, no open finding; a ceiling of 8 CPU-hours.

| Target | Boundary | Entry points |
|---|---|---|
| `sshconf_parse` | 1 | `sshconf::parse::parse_file` |
| `gitedit_scan` | 2 | `sshconf::gitedit::{scan, find_blocks}` |
| `agent_reply` | 3 | `ipc::agent_client::parse_reply` |
| `control_frame` | 4 | `ipc::decode_frame` as `ClientMessage`, `ServerMessage` and a JSON value |
| `signing_request` | 5 | `ipc::signing::{classify, parse_sign_request, SessionBindRecord::parse}` |
| `userauth_request` | 6 | `credential::purpose::parse_userauth`, `credential::session_bind::parse` |
| `registry_hm1` | 7 | `registry::hm1::parse`, `registry::classify::HolderRecord::parse` |
| `project_manifest` | 10 | `project::manifest::parse_manifest`, `project::parse_bundle` |
| `runtime_config` | 11 | `runtime::config::Config::parse` |
| `runtime_instance` | 11 | `runtime::instance::InstanceInfo`, decoded as `read_file` does |
| `sshconf_eval` | 1 | `sshconf::eval::evaluate` over an in-memory root file and one included file |
| `frame_codec` | 4 | `ipc::session::BoundedFrameCodec`, fed in attacker-chosen chunk sizes |
| `registry_script` | 7 | `registry::script::{RegistryPath, Marker, RegistryLine, StepToken}::parse` |
| `registry_line` | 7 | `registry::line::{lines, marker_of, marker_ok, marker_lines, contains}` |
| `issuer_protocol` | 8 | `issuer::protocol::{Request::decode, Response::decode, split_frame}` |
| `issuer_backup` | 9 | `credential::cert::SecretCaKey::decrypt_openssh` (a fixed fixture passphrase), the recovery bundle's JSON, `issuer::backup::fingerprint_from_file_stem` |
| `known_hosts_match` | 12 | `localenv::known_hosts::{hosts_match, lookup_name}` (the pure part) |

Not reached by any target: the known-hosts file reader and the `ssh -G` output reader.

## Campaigns so far

| Date | Tree | Per target | Result |
|---|---|---|---|
| 2026-11-22 | `m08/w0` at `bd1a8c43` (product code = `main` at `de097dac`) | 300 s, all nine | exit 0 each; 0 findings; about 35 million executions in total. Coverage was still growing on most targets, so **the stopping rule is not met**; this run proves the harness |
| 2026-11-22 | the same | 3600 s more on `sshconf_parse`, `gitedit_scan`, `control_frame`, `project_manifest` (corpus kept from the first run) | exit 0 each; 0 findings; about 67 million executions. A new input was still being found in the last seconds of each, so **the stopping rule is not met** |

**Do not run a campaign while `check.sh` runs.** The second campaign overlapped a `check.sh`
run, and two timing-sensitive issuer tests in `e2e_cli_m03` failed under the load; they
passed three times out of three on a quiet machine, and the gate was rerun alone.

### After the merge of `main` at `6a087fbb` (tree `3b158d94`)

| Date | What | Result |
|---|---|---|
| 2026-11-22 | First 300 s on the seven newer targets (before the merge) | exit 0 each; 0 findings; about 22 million executions. `issuer_backup` showed no timeout |
| 2026-11-22 | Rebuild on the merged tree with the default linker | 14 of 16 built. `runtime_config` and `runtime_instance` failed to link: `relocation truncated to fit: R_AARCH64_CALL26`. The instrumented binary that links the runtime crate is about 250 MB with M06's code |
| 2026-11-22 | Rebuild with `lld` | **16 of 16 built** |
| 2026-11-22 | 2700 s on `agent_reply`, `signing_request`, `userauth_request`, `registry_hm1` | exit 0 each; 0 findings; about 277 million executions. `signing_request` has plateaued (its last new input was number 41 of 82 million) |

| 2026-11-22 to 2026-11-23 | Further batches of 3300 to 3600 s, two targets at a time, on all 17 targets | exit 0 each; 0 findings. Cumulative on 2026-11-23, before the batch then running: 6900 s `runtime_config`, `sshconf_eval`, `frame_codec`; 6600 s `agent_reply`, `signing_request`, `userauth_request`; 6300 s `registry_hm1`; 3900 s `sshconf_parse`, `gitedit_scan`, `control_frame`, `project_manifest`; 3600 s the other six. Most targets logged a new or reduced input close to their last execution, so **the stopping rule is not met for any target** |

**Cumulative time per target is printed by `run-campaign.sh report`,** with a
**stopping-rule column** (added 2026-11-23). It says `met` for a target only when all of
these hold, and `not met` otherwise:

- the target's last run was at least 1800 s, and the edge coverage (`cov`) libFuzzer printed
  when that run had loaded its corpus (`INITED`) equals the coverage at its end, so the whole
  last run found no new coverage. This is stricter than "the last 30 minutes" of a longer
  run, and it is read from one log with no timing estimate;
- the target's runs that exited 0 add up to at least 7200 s;
- its artifact directory holds no finding.

The rule is claimed per target from that column and from nothing else. A target whose
closing run still gains coverage runs on toward the 8 CPU-hour ceiling. The feature
count (`ft`) may still grow while `cov` is flat; the column reads `cov`, and the report
prints both.

No target has met the stopping rule yet. Results recorded before the merge are
from the older product code; the corpus carries over, the coverage figures do not.
