# Remove Heimdall's access from a remote host

> **Draft (M08 U7a, 2026-11-22), provisional.** Written on today's command names; M06 and M07 will rename some, and `tools/validation/docs_commands_check.py` fails this file until it follows. Commands in blocks marked `planned` do not exist yet (ADR-0014 §7 names their contract delta). Nothing here is a release claim.

Enrolling a destination adds one marked line to an account's `authorized_keys` on that
host. Uninstalling Heimdall locally does not remove it. Remove it first, while the host is
reachable.

```
heimdall enroll status
heimdall enroll remove <enrollment>
```

- Heimdall removes only the line it added, identified by its marker. Lines you or anyone
  else added, before or since, are left byte for byte.
- If the host is unreachable, Heimdall cannot remove the line and says so. The enrollment
  stays listed until it is removed or you record that you removed it by hand.
- To remove it by hand, delete the line carrying the marker shown by `heimdall enroll status`.
- After the last enrollment under a CA is removed, `heimdall issuer retire <fingerprint>`
  retires that CA. Destroy its offline backup afterwards.

An already-issued certificate stays valid at a host until it expires, even after the line
is removed from another host or the device is gone. `heimdall enroll status` shows the
latest expiry.
