# Release note (M03 draft): macOS CA-key access after an update

**Applies to:** macOS releases built without a Developer ID signature (ad-hoc-signed), which
is every macOS build until the owner-blocked signing input arrives (ADR-0004 Q-F; ADR-0008
§17.28 items 6 and 7).

The issuer keeps its CA key (K_ca) in the login keychain, in an item whose access list trusts
the code identity of the Heimdall executable that created it. An ad-hoc signature's identity is
the build's exact code hash, so **an updated or rebuilt Heimdall may no longer be able to read
the CA key**. This release does not claim that the CA key stays usable across updates on macOS.

When that happens:

- `heimdall issuer status`, `heimdall issuer unlock`, a refused certificate activation and
  `heimdall doctor` (while the runtime is running) report `issuer_store_access_denied`
  (`CAPABILITY_UNAVAILABLE`, exit 4). It is not `issuer_store_locked`: the keychain is unlocked,
  and unlocking it again does not help.
- Run `heimdall issuer restore --backup <file>` with the CA's offline backup (the log-intact
  restore, ADR-0008 D5). The new build cannot read the old item, so the restore writes the CA key to
  a **new** store item (same service, account `<environment>#r<n>`), which you record by typing
  `yes`; the issuer then reloads the CA. You do not need to delete anything first. The restored key
  is the same CA, so the remote lines that trust it need no change.
- Then delete the old item in Keychain Access. `heimdall issuer status` lists it under orphan
  store items with its exact service and account. Heimdall never deletes it: the new build cannot
  delete it without a keychain prompt, and Heimdall never shows one.

Keep the offline backup file and its passphrase: on macOS they are the recovery after an update.

Separately, if Heimdall's executable is replaced while an issuer command is writing the CA key
(an update finishing mid-command), the command stores nothing and reports
`issuer_executable_changed` (`SERVICE_UNAVAILABLE`, exit 5): finish installing or updating
Heimdall, then run the command again.

A Developer ID signature gives the executable a stable identity that survives updates; this
note is withdrawn when macOS releases carry one.
