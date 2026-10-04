# Source snapshots (M00-T02-fix)

Each `Sxx.txt.gz` is the gzip of the normalized visible text of one spec section 19 source, as fetched on 2026-10-03T21:18Z by `docs/sources/tools/fetch_pins.py` (normalizer v1). It exists so that a later reader can see what a pin said when the live page has changed. The file is one line of text (no HTML, no scripts, no images), gzip with mtime 0, so a re-run on unchanged content produces identical bytes.

Scope. 27 sources have a snapshot: the non-git sources S01-S15, S20-S26, S28, S30-S33. The 7 GitHub sources (S16-S19, S27, S29, S34) have none because their pin is a commit permalink plus git blob sha1, which is immutable; the script re-fetches them at that commit.

Why not the Internet Archive instead. The availability API (read-only GET, no save requests) returned a snapshot for only 8 of the 27 sources, answered inconsistently between two passes, and every snapshot it found predates the pin. Only S03's archived text matches the pinned text (see `docs/sources/archive-lookups.json`). The archive URLs are recorded as hints, not as proof.

Verify one snapshot against the baseline (offline):
`python3 docs/sources/tools/fetch_pins.py verify --fetch-result docs/sources/fetch-baseline.json --id S26 --snapshot docs/sources/snapshots/S26.txt.gz`

Read one: `gzip -dc docs/sources/snapshots/S26.txt.gz | fold -w 120`

Copyright and licence. The text belongs to its publishers (OpenBSD project, openssh.org, 1Password, Microsoft, Smallstep, n0-computer, OpenAI, Mitchell Hashimoto, ratatui.rs). Only the visible text needed to check the claims in spec section 19 is stored, for internal verification, not for redistribution or reuse. Owner decision E8 in `docs/decisions/0003-source-pins.md`: keep, replace with hashes plus archive URLs, or remove before any publication of this repository.
