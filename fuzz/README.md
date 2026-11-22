# Fuzz targets (M08 U1a)

Coverage-guided fuzzing of the parsers that take outside input (ADR-0014 §2). **Provisional,
to be integrated:** this covers boundaries 1–7, 10 and 11 of ADR-0014 §2.1. Boundaries 8
(issuer protocol), 9 (backup and recovery files) and 12 (known-hosts and `ssh -G` output)
have no target yet; 13–15 wait for M06 and M07.

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

Not reached by these targets: include expansion and evaluation of an SSH configuration
(`sshconf::include`, `sshconf::eval`), the streaming frame codec, `registry::line`, and
`runtime::instance`. They are the next targets for boundaries 1, 4, 7 and 11.

## Campaigns so far

| Date | Tree | Per target | Result |
|---|---|---|---|
| 2026-11-22 | `m08/w0` at `bd1a8c43` (product code = `main` at `de097dac`) | 300 s, all nine | exit 0 each; 0 findings; about 35 million executions in total. Coverage was still growing on most targets, so **the stopping rule is not met**; this run proves the harness |
| 2026-11-22 | the same | 3600 s more on `sshconf_parse`, `gitedit_scan`, `control_frame`, `project_manifest` (corpus kept from the first run) | exit 0 each; 0 findings; about 67 million executions. A new input was still being found in the last seconds of each, so **the stopping rule is not met** |

**Do not run a campaign while `check.sh` runs.** The second campaign overlapped a `check.sh`
run, and two timing-sensitive issuer tests in `e2e_cli_m03` failed under the load; they
passed three times out of three on a quiet machine, and the gate was rerun alone.
