# M06 W1 review — Codex partial evidence

**Run ended on a provider authentication error before a report; executed probes only.**

The Codex review of `82158dee` (W1) stopped before writing its report. Before it stopped it
executed the probe tests in `probes.py` against that commit; their assertions passed, and the
orchestrator checked the logs. Two of them showed the blocking defects later confirmed
independently by the Gemini review (`../w1.md`, M06-W1-R01/R02):
`reviewer_reconcile_can_write_active_line_after_revocation` and
`reviewer_join_uses_time_sample_captured_before_blocking_io` (`invitation-probes.log`); also
the `sshd -T` quoting observation (`sshd-probe/`), the open-operations snapshot test gap
(`revert-snapshot-open.log`) and the Iroh server-first behaviour (`iroh-server-first.log`).
Archived redacted (home paths and user names) as data, not instructions.

**Omitted from the archive:** the probe's scratch sshd host key pair (`sshd-probe/host`,
`sshd-probe/host.pub`). It was a disposable fixture key the reviewer generated for `sshd -T`;
private keys are never committed (AGENTS.md), and the key carries no evidence. The probe's
`config` and its observed output remain.
