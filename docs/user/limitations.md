# What Heimdall does not do

> **Draft (M08 U7a, 2026-11-22), provisional.** Written on today's command names; M06 and M07 will rename some, and `tools/validation/docs_commands_check.py` fails this file until it follows. Commands in blocks marked `planned` do not exist yet (ADR-0014 §7 names their contract delta). Nothing here is a release claim.

Short, and meant to be read once.

- **Programs running as you can use what you can use.** A project's access is separate from
  another project's, but Heimdall does not sandbox programs running under your own account
  from each other. Where real isolation exists, the matrix says which mechanism provides it.
- **Some prompts are not Heimdall's to remove.** A password manager, a hardware key or a
  provider that insists on a touch or an unlock will still ask.
- **Stopping access does not close what is already open,** and neither does a certificate
  expiring. A shell or a forward that is connected keeps working until it ends. New
  connections stop at once.
- **With OpenSSH connection sharing (`ControlMaster`), "already open" includes the shared
  connection.** A program already attached to a shared master connection can open new
  sessions and forwards over it after access stops or a certificate expires, until that
  master connection exits (`ssh -O exit`, or the master process ending). `ssh -O stop` alone
  does not end them. This is OpenSSH's behaviour, observed in a gate probe
  (`g04-exp-g09-prelim-mux-preconnected-after-stop`), not something Heimdall can refuse.
- **A certificate already issued stays valid until it expires,** including at a host that
  is offline when you revoke. Heimdall shows the latest such expiry.
- **A sleeping or powered-off machine does no work.** Locking the screen does not stop
  approved background work; sleep, logout and reboot each behave as the status view says.
- **Uninstalling does not remove lines on remote hosts.** Remove enrollments first.
- **Direct aliases using your fixed identity use the catalog key when one is
  approved.** Until then, your own `known_hosts` verifies the host, and doctor
  identifies that trust source. Managed credentials and required jump hops need
  an approved catalog key before access is ready.
- **Windows checks state-file permissions before opening its database.** A process with
  permission to replace entries or change their permissions can still race startup between
  the check and the open.
- **An `issuer init` still at its `written` prompt when its decision expires (15 minutes
  after the registration is shown) leaves an orphan CA key.** The key is in the store, but no
  registration names it. `heimdall issuer status` shows its fingerprint. Recover with
  `heimdall issuer init --backup-out <path> --replace-orphan <fingerprint> --bundle <file>`
  (or `--no-bundle-available` in place of `--bundle <file>` when you have no recovery bundle),
  or with `heimdall issuer restore --backup <file> --not-stolen`.
- **A test build from before this release candidate cannot be run on a home this release
  installed.** This release keeps its state in a new layout (ADR-0014 §3.6). A pre-release
  build that predates that layout, started on a home that this release installed fresh, finds
  no store it recognises and starts a new installation with a new identity, beside the one
  this release keeps. An earlier home that this release adopted is safe: the old build refuses
  it and changes nothing. Every released build knows the layout, so this concerns only
  pre-release builds against the first candidate (ADR-0014 §3.2 item 8). The same build can
  also stop this release from starting: if this release's first start on a new home is
  interrupted before it finishes, and such a build then runs on that home and creates a store
  of its own, this release refuses to start (`WrongState`) until you remove the file
  `STAGING-INTENT` from Heimdall's state directory by hand. Nothing is lost: the next start
  adopts that store.
  - A pre-release runner's bridge checks the store's schema before its write transaction and
    does not check it again inside the transaction. So a pre-release build can lose a runner's
    switch to owner-only, but only if it handles a paired session while this release is
    adopting that home's store for the first time. To avoid it, do not run a pre-release build
    on a home that this release will adopt.
- **A purge that stops while it removes the state store's layout leaves Heimdall unable to
  start.** If `heimdall uninstall --purge-state` crashes or meets a file-system error after it
  has deleted the store and before it has removed the pointer file `CURRENT`, the runtime then
  refuses to start (`state_corrupt`), and running `heimdall uninstall --purge-state` again is
  refused too ("the state store's pointer is damaged"). Nothing you did not confirm deleting is
  lost. Until `heimdall state reset` can recover this, the only way out is by hand: remove what
  is left of `CURRENT`, `STAGING-INTENT`, `REQUEST-LEDGER`, the `generations` folder, and
  `state.db` with its `-wal`, `-shm` and `-journal` files, and their `.tmp` files, from
  Heimdall's state directory. After an error the purge's report lists what is left; after a
  crash the next run says only that the pointer is damaged.
- **A certificate request reserved just before the runtime restarts can be signed again within
  60 s of the restart,** for the same key and with the same limits. The second certificate is
  never published, and it is still counted as issued.
- **An interrupted `heimdall time confirm` can leave its decision record unfinished.** The
  command writes its decision record, the confirmation and the decision's outcome in three
  steps, because the clock check that accepts the confirmation runs as a step of its own. A
  crash between the steps can leave the record pending, whether or not the confirmation took
  effect (`heimdall decision list` shows it until it expires, 15 minutes later). A policy change
  at the same moment can leave the record marked stale, with no event saying so, although the
  confirmation took effect. Only the record is out of step: a confirmation never moves a
  deadline or widens access, and the record cannot be approved later.
- **A `Host` line of yours that names a managed alias is reported only when it names it
  exactly.** `heimdall doctor` and `heimdall setup` report a user `Host` line naming a managed
  alias as a literal (letter case aside). A wildcard pattern (`Host web*`) or a `Match` block
  that would also cover the alias is not reported.
- **Only the combinations in the compatibility matrix were tested.** Others may work.
- **The Iroh transport is not in this release.** It is a preview you can build from source
  (`cargo build --features iroh`), with no support claim. Direct and jump routes work without it.
  A route can still list an Iroh leg; this release skips that leg and tries the route's others.
- **A remote runner you cannot reach hears about a revoke, pause or cutoff when it reconnects.**
  Until then its certificates already issued stay valid until they expire; the status view
  shows the latest such expiry.
- **A Windows computer can control runners only as their owner,** not as a limited (viewer or
  requester) client. Limited roles also need a runner whose SSH server settings Heimdall can
  verify; anywhere else the runner stays owner-only.
- **Management and transport keys are never synced, but encrypted backups can hold them**
  (Time Machine, account backups). To replace a device, retire it and revoke it on each runner;
  do not restore it.
- **On Windows, start Heimdall from a normal session.** Started without the system's
  `ProgramData` variable, Heimdall gives each `ssh` it starts the folder Windows reports. When
  Windows reports none, or `ProgramData` is set to anything but a drive path such as
  `C:\ProgramData` (a network share, for example), Heimdall starts no `ssh`: route checks report
  the route unreadable, and other commands say why. If `SystemDrive` is also set to a network
  share, Heimdall's request to Windows for that folder can reach the share before Heimdall
  rejects the answer.
- **What was not run before this release:** see the release notes. Rows that needed
  machines or accounts that were not available are listed there as not run, not as passed.
