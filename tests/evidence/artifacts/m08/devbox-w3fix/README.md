# Devbox steps for the W3 review fixes (Linux x86-64; 2026-11-25), at `a8641372`

`heimdall-runtime`'s library test binary was cross-built on the Mac, in a clean checkout at
`a8641372`. It used the zig shims, the glibc 2.31 floor and the `native-test` profile, and ran
through heavy-gate (`m02_cargo_build`).
- **Staged:** 132 MB.
- **The run:** in one `mktemp -d` scratch directory (shown as `<scratch>`), with `HOME` and
  `TMPDIR` inside it, no `SSH_AUTH_SOCK`, and `nice -n 10`. The script is `run.sh`; its output
  is `run-a8641372.txt`.
- **Free space:** 4,167,124 KiB before (the floor was 3 GB), 4,167,144 KiB after.
- **Cleanup:** the scratch directory was removed by its exact path, and its absence was checked.

| Finding | Test | Result |
|---|---|---|
| W3-R01 | `paired::adoption_window_tests::a_bridge_write_after_the_adoption_fence_is_refused_and_reaches_the_served_generation_by_the_marker` | passed |
| W3-R03 | `state_store::tests::platform_fs_pointer_rename_interrupted_then_restart_serves_only_the_pointers_generation` (8 cases over `PlatformFs` on Linux ext4) | passed |
