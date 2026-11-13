# M03 wave 5 round 4 — worker K4 (issuer reasons) worklog

Scope: ADR-0008 §17.28 items 5 (`issuer_executable_changed`) and 6 (`issuer_store_access_denied`).
Base 607160ff. No commits.

## Decisions
- Access denial travels as `StoreAvailability::AccessDenied` (wire `access_denied`, additive variant;
  heimdall-issuer/1 `store_unavailable` reason) → `refusal_reason` = `issuer_store_access_denied`, so the
  child load, client view/status, runtime unlock and CLI read-back all carry it without new plumbing.
- macOS: `errSecAuthFailed` on an item read is disambiguated by the keychain's lock status: unlocked →
  AccessDenied; locked or status unreadable → InteractionNotAllowed (`issuer_store_locked`, as before).
  `errSecInteractionNotAllowed` stays locked.
- Code for access denied: CAPABILITY_UNAVAILABLE (exit 4), like the other issuer store reasons: waiting
  does not help, the owner must act (restore). Executable changed: SERVICE_UNAVAILABLE (ruling).
- Doctor: no issuer-store section exists → new finding `issuer_store_access_denied` (contract addition).
  Source: the running runtime's `issuer.status` (never starting it; the doctor never reads K_ca, which only
  the issuer child and the owner-present ceremony may hold, ADR-0008 table row K_ca).

- FINDING (probe, round 4): after the access denial the new build can neither read nor delete the
  old item without UI (SecItemDelete → -25244 errSecInvalidOwnerEdit), so `issuer restore` alone
  loops (restore's put → read → access_denied). Guidance/help/note say: remove the old item in
  Keychain Access first, then restore. Regression proves recovery after removal (modelled by
  recreating the disposable keychain). Escalated as K4-Q1.
- Help: `after_help` attributes (doc comments made clap switch to the long layout: whole-file diff).

## Progress
- [x] contract reasons + finding + golden + ADR-0006 rows; issuer AccessDenied; macOS mapping;
      ceremony/app/driver/CLI/doctor mapping; help + goldens; release note; tests; reverts.
- [x] clippy host/windows, linux-xcheck, issuer:: x5 (+umask 002), release lib, cleanup. DONE.

## Commands (exit codes)
- build heimdall 0; issuer lib 0 (21); integration_issuer_store 0 (30); contract 0 (43+90);
  app units 0 (3); heimdall bin units 0 (6); help goldens regenerated (2 files, text only) 0.
- new e2e access_denied test 0 (restore probe: exit 4 access_denied; after removal exit 0, ready).
- Reverts (each restored, sha same): R1 ceremony ExecutableChanged arm → e2e replaced 101, unit 101;
  R2 macos AccessDenied arm → e2e 101 (status reason issuer_store_locked), unit 101; R3 mod.rs
  refusal arm → unit 101; R4 app issuer_failure arm → unit 101; R5 driver list → unit 101;
  R6 doctor push → e2e 101 (doctor assertion); R7 next_command → e2e 101.
- clippy host: issuer+contract+app --all-targets 0; heimdall bin + e2e_cli_m03 0; bin --profile test 0
  (after fixing one unwrap in the doctor unit test). clippy-windows.sh 0. linux-xcheck -p heimdall-issuer
  -p heimdall -p heimdall-contract 0. cargo test --release -p heimdall-issuer --lib 0 (20).
- e2e_cli_m03 issuer:: x5: all 0 (17 passed, 1 ignored = pty child entry); runs 4-5 at umask 002.
  Owner keychain search list/default digest unchanged across the runs.
- rustfmt on my 4 edited files only (L4's files untouched). Scratch /tmp/k4-rev removed.
- Shared ./target is 64G (all workers); not pruned by K4 (other workers building).

## §17.28 item 7 (K4-Q1 ruled): restore to a new item
- Trait: two **defaulted** methods on `SecretStore` (`get_item(&StoreItemRef)`, `put_new_item`); no
  existing signature changed, no implementor touched. macOS: account `<env>#r<n>`, lowest free n ≤ 99
  (existence from attributes, unreadable items count), add never overwrites; list/get_item/delete accept
  generation accounts of this installation only. Child reads the recorded item (`get_item`), else `get`.
- Ceremony restore: recorded item adopted if readable+listed; access denied → new item (or adopt an
  existing readable item of this installation with the key) → existing CAS RegisterIssuer + `yes`.
  resolve_displaced keeps an unreadable displaced item (delete reads first, so nothing touched) and
  prints service/account + Keychain Access instruction; status render says the same.
- Texts replaced (guidance/doctor/next, help after_help + goldens, release note, ADR-0006 row).
- New e2e `issuer_restore_after_access_denial_writes_a_new_item_and_lists_the_orphan` 0; reporting
  test kept (setup factored into `access_denied_rig`).
- Reverts (sha same each): restore_item→store_and_check 101 (no yes prompt); child read_key→get 101
  (unlock after restore exit 4); keep-arm → error 101.
- issuer lib 0 (22), --release 0 (21), integration_issuer_store 0 (30), contract 0 (43+90), app 0, help
  goldens 0 (2 files, after_help text only). clippy host 0/0/0, windows 0, linux-xcheck 0.
- e2e_cli_m03 issuer:: x5 all 0 (18 passed, 1 ignored pty child entry); runs 4-5 umask 002; owner keychain digest unchanged. /tmp/k4-rev removed.
