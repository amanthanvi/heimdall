# Future Backlog

This file tracks intentionally deferred work. These items are not part of the
current reboot contract in [SPEC.md](/Users/amanthanvi/GitRepos/heimdall/SPEC.md).

## Deferred Product Surfaces

- Full TUI workflows and the public `tui` / `ui` command surface
- Public `import` and `export` commands
- Managed `ssh-config` commands and fragment syncing
- Templates and host templating workflows
- Compliance and reporting output
- Repair and salvage commands
- Daemonless operation
- Team and shared-vault workflows

## Deferred Host Model Work

- First-class persisted default forwards on hosts
- First-class persisted host-level secret bindings
- Richer jump-host graphs beyond a single `proxy_jump` string
- Explicit auth strategy enums instead of mutually exclusive string fields

## Deferred UX Work

- Guided onboarding beyond the current CLI-first init/unlock flow
- Richer doctor diagnostics and repair suggestions
- Human-friendly summaries for audit, backup, and passkey status
- Generated man pages and docs cleanup for archived command families

## Deferred Migration Work

- Importers for earlier Heimdall vault layouts
- Best-effort migration tooling for old host defaults stored in `env_refs`
- Portability helpers for legacy JSON transfer bundles

## Deferred Documentation Work

- Archive or rewrite historical `docs/v2/*` materials
- Remove or rewrite historical drift docs once the reboot settles
- Publish a short operator guide for the rebooted CLI surface
