# Copy of the X2 hidden task pack

Copied 2026-10-09 by the orchestrator (session heimdall-83) from the hidden pack directory
(`<home>/.local/share/heimdall-m00/r4-hidden/`), which implementers could not read: every
implementer transcript was audited for access to it (`x2/` audit notes in the round-4 report).

Left out:

- `bin/`: the base and seeded prototype builds the evaluators used (23 MB of binaries). They are
  rebuilt from the pinned commits in `BASE.json` with each prototype's `build.sh`; `bin-SHA256SUMS`
  lists the digests of the copies used.
- `seeded-trees/`: the T4 starting trees. Rebuild with `git archive <base> prototypes/<lang>` plus
  `seed/<lang>-<base>.patch`; `BASE.json` holds the tree digests that `make-workspace.sh` checks.

The copy was checked for home-directory paths (none) and canary values (only the bare
`HEIMDALL_CANARY_` prefix appears, in check code). `workspaces/` holds the per-cell manifests,
including the two moved-aside manifests of the excluded continuation attempts and of the T1-rust-opus1
rerun the host reboot interrupted.
