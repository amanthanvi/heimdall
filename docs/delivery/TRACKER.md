# Delivery Tracker — v0.2.0 Reconciliation

Status key: `todo` | `in_progress` | `done`

## Workstreams

- [x] `done` P0 CLI gap: wire `heimdall tui` + `heimdall ui` alias
- [x] `done` Completion hardening: zsh scripts skip leaked directive tokens
- [x] `done` Import UX fix: JSON identity metadata reported as skipped
- [x] `done` Connection audit fix: `connect.start`/`connect.end` now emitted for identity-file and managed-key connects
- [x] `done` Audit UX fix: default `connection_logging=true` for new/default configs and explicit status hint when disabled
- [x] `done` Dry-run UX fix: `connect --dry-run` help text explicitly states no connect audit events are emitted
- [x] `done` Homebrew UX fix: cask now removes quarantine xattr post-install (tap hotfix + `.goreleaser.yml` hook for future releases)
- [x] `done` Planning truth sync: `PLAN.md` reconciled with real backlog
- [x] `done` Spec truth sync: `SPEC.md` updated for current v0.2.1 behavior
- [x] `done` Docs refresh: `README.md` + `docs/RELEASING.md` updated
- [x] `done` GitHub cleanup: pruned pre-v0.2.0 releases and tags (kept `v0.2.0`)
- [x] `done` Full validation gate complete (`build`, `vet`, `race`, `lint`, `integration`, `bench`)

## Commit log (this run)

- `b21cb39` — `feat: expose tui command and harden zsh completions`
- `4539b2c` — `fix: report JSON import identity metadata as skipped`
- `ff92432` — `fix: record connect audit for identity sessions`
- `e7838b0` — `feat: default-enable connection audit logging`

## Remaining deliverables

- None for this reconciliation batch.
