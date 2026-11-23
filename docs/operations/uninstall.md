# Uninstall

> **Draft (M08 U7a, 2026-11-22), provisional.** Written on today's command names; M06 and M07 will rename some, and `tools/validation/docs_commands_check.py` fails this file until it follows. Commands in blocks marked `planned` do not exist yet (ADR-0014 §7 names their contract delta). Nothing here is a release claim.

```
heimdall uninstall
```

Uninstall puts your SSH and Git configuration back as it was before `heimdall setup`,
removes the login entry if you enabled one, stops the runtime, and lists what remains.

- **Remote enrollments are listed first.** Remove them (`unenrollment.md`), or acknowledge
  leaving them with `--keep-remote-enrollments`.
- **Your own SSH setup is preserved.** Lines Heimdall did not write are never changed. If
  you edited a file Heimdall manages, uninstall keeps your version and reports the conflict.
- **The state is kept by default.** `heimdall uninstall --purge-state` deletes it after
  showing what will be discarded and asking. It refuses while remote enrollments remain,
  unless you supply a current recovery bundle with `--bundle <file>`.
- **What can remain, and is listed:** state backups, earlier state generations, the previous
  executable, conflict copies, logs, and on macOS a keychain item Heimdall cannot delete
  without a system prompt.

Then delete the executable from the install location, and the `PATH` line if you added one.
