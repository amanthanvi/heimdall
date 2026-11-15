# M03 wave 5 round 15 — integrator worklog

Base `40a8d1d4`. Rulings for W5-I01 (to be ADR-0008 §17.38), F2 (§17.37 item 6), Windows coverage, devbox e2e_cli_m03 failures. No commits. Keep the Windows target warm. Devbox/linux-xcheck WAIT for the orchestrator (batch B shares target/x86_64-unknown-linux-gnu).
- [x] Grok final review archived verbatim: tests/evidence/artifacts/review-m03-code/wave5-final.md.
- [x] Items 1-3 done by P9 (P8 successor); passphrase test by K4.
- [x] Item 4 done by K4 (product bug: Linux signal_exact image unreadable; fixed; devbox 56/56).
- [x] Validation: check.sh every step 0 (3104 passed, 0 failed, 192 ignored), linux-xcheck 0, umask 002 all 0 (cli_m03 69p/3i, tui_m03 5p/1i, tui_m02 17p/1i, enroll 99p, ceremony 8p/2i, managed 16p, bin 251p). Archived.
- T3 server restart cancelled P8 and K4 mid-task (partial edits: purge_sweep/uninstall_cmd +370, issuer.rs +6, K4-DIAG in client.rs; K4 devbox run 1 state unknown). Both resumed with reconcile instructions; DONE-file handshake.
- K4 DONE (Linux signal_exact image-unreadable fix, 2 regressions + revert; passphrase test fix; devbox e2e_cli_m03 56/56; removed target/x86_64-unknown-linux-gnu). P8 interrupted twice (restart + API error); partial items 1-3 in tree (Windows clippy 101: read_with_wal dead on Windows). P8 resumed; foreground-only instruction.
- P9 (P8 successor) DONE: W5-I01 (marker binds copy dev/ino/size/sha256; copy check before marker; marker branch verifies binding + ops.check + recorded inodes; exception only for names absent from the record, never the db, size 0), F2, Windows un-gating + Windows hooks, RESIDUALS. 6 reverts 101->0. Integrator reviewed the marker branch (purge_sweep.rs ~1895-1925). Open: copy check runs inside Unit::delete after the trees are deleted (db kept).
