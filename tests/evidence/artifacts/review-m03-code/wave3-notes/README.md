# M03 wave 3: the integrator's working notes

These are the working files of the M03 wave-3 integrator (Opus 5.5, with two unit agents, U6 and U7, in its own worktree from `1b5c1758`): the shared brief, the readings and landed interfaces (including the U6 → U7 interface), the questions and escalations, and the worklog. They were archived on 2026-11-11 at the end of the wave, with only the dot prefix dropped from each file name; the worktree path is written `<worktree>` and the home directory `<home>`. The brief's per-package Windows clippy helper `.m03-wave3-xcheck-windows.sh` was a scratch copy of `tools/validation/clippy-windows.sh` taking package arguments, and was removed.

They are working notes, not rulings. Fixture-driver results stand in for U10's `drive_preparation`, and every test that needs a Linux-native, Windows-native or owner input is named as such; the native runs are the orchestrator's.

**Round 2 (review fixes, 2026-11-11).** The `m03-wave3-r2-*.md` files are the working notes of the fixes to ADR-0008 §17.20 (the wave-3 code and security reviews, `wave3.md` and `wave3-security.md`), made by two fix agents, F6 (adapter side) and F7 (connection side), and the integrator: the round-2 brief, the new questions (W3-R2-Q1 to Q3), and the worklog with every regression's revert proof. Redacted as above; the recreated helper `.m03-wave3-xcheck-windows.sh` was removed again.

**Round 3 (2026-11-11).** `m03-wave3-r3-worklog.md` is the worklog of the third round: the devbox's umask-002 anchor failure (item 1, integrator), and the re-check's W3-C01 (F7) and W3-C02 (F6), with their revert proofs and the disposable-container pre-check. Redacted as above.
