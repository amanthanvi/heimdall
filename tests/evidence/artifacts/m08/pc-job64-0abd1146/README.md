# PC job 64: U1b on Windows at `0abd1146` (2026-11-25)

The job file is `PC-M08-U1b.md`, run with the default TEMP throughout. The outputs are under
`logs/`, redacted by the orchestrator. All 10 captures exited 0, with 0 failures.

| Capture | Result | Verified on Windows |
|---|---|---|
| M06-F5: `an_inherited_unusable_program_data_starts_no_windows_client` | 1 passed | yes |
| M06-F6: the two ignored tests (`--ignored --exact`), which use the in-box `ssh.exe` | 2 passed | yes. This is the in-box client's F6 proof |
| M06-F6: `integration_route_m06 -- --exact each_host_pin_defeated_combination_is_refused_by_ssh_g` | 1 passed | yes, with **the `ssh` that PATH finds**: on this PC that is `C:\Program Files\OpenSSH` (OpenSSH_for_Windows 10.0p2), not the in-box 9.5p2. Giving this case the in-box path is a later change, not blocking |
| M06-F8: `the_fill_supplies_system_drive_and_program_data_without_the_callers_system_drive` | 1 passed | yes. `derived=1` is **asserted, not quoted**: the parent requires the child to exit 0 and print `openssh-fill-child: ok derived=1`, and the output appears only on failure |
| U2b-1's helper fix: `uninstall_cmd::tests` with the default TEMP | **67 passed**, including the four that failed in job 63 | yes. **This closes job 63's uninstall row on Windows** |
| `adversarial_alias_collision` | 5 passed | yes |
| `adversarial_stale_signing_handle` | 1 passed | yes |
| `adversarial_issuer_reservation_replay` | 2 passed | yes. **It left two `.tmp*` fixture directories in TEMP** (see below) |
| `adversarial_m08_fuzz_seeds` | 7 passed | yes |

**The owner's state:** Credential Manager held 173 items before and after, none of them
Heimdall's; DWM was unchanged. The PC agent's check found that every `ssh.exe` call passes
`-F <scratch>` or `-F none`. All of them are `-G`, except the jump leg's `-W 127.0.0.1:1`,
which went to loopback port 1 with scratch known-hosts, identity and agent. Nothing read the
account's `~/.ssh`.

**A test defect found by this job, fixed after it.**
- What happened: `tests/adversarial/issuer_reservation_replay.rs` left two `.tmp*` directories
  in TEMP. Each held a fixture `state.db` and a scratch store, with a passphrase file and a
  `.key`. The PC agent deleted both by exact path.
- The cause: `struct World` declared `dir: TempDir` first, and fields drop in declaration
  order. So the directory was removed while the store still held `state.db` open. Windows
  cannot delete an open file, and `TempDir`'s drop swallows the error.
- The fix: `dir` is now the last field. The other new test structs (`Scratch` in
  `store_generations_cli.rs` and `alias_collision.rs`) hold paths only, with no open handle.
- The proof is a later Windows run that leaves zero `.tmp*` directories. The orchestrator adds
  that check to the next PC job.
