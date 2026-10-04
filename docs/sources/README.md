# docs/sources

| Path | What it is |
|---|---|
| `pins.json` | Source pins S01-S34 and candidate dependency pins. `pin_v2` is the reproducible pin; `pin` keeps the v1 date marker and the v1 hashes under `legacy_*` names. |
| `tools/fetch_pins.py` | Stdlib-only, GET-only fetch, normalization, archive lookup, compare and verify. Docstring defines the normalizer. |
| `fetch-baseline.json` | Output of `fetch_pins.py fetch` on 2026-10-03T21:18Z (hashes, sizes, headers, date markers). |
| `fetch-repeat.json` | Immediate second run, identical hashes and markers. |
| `archive-lookups.json` | Internet Archive availability lookups (two passes). |
| `snapshots/` | Compressed normalized text for the 27 non-git sources (see its README for scope and copyright). |
| `excerpts/notes.md` | Short quoted excerpts and fetch notes. |

Reproduce from the repository root (needs only `python3`, network GET):

    python3 docs/sources/tools/fetch_pins.py fetch --out /tmp/new.json
    python3 docs/sources/tools/fetch_pins.py compare docs/sources/fetch-baseline.json /tmp/new.json

Exit 0 means all 34 raw and normalized hashes and date markers are identical. Exit 2 lists drifted ids. A raw-hash-only difference on the 19 sources whose primary pin is `normalized_text_sha256` is expected page-chrome churn; a normalized difference is a content change.

Pins by kind. 15 sources have `primary: raw_body_sha256` because the raw hash reproduced about 21 h after the v1 retrieval. 19 have `primary: normalized_text_sha256` because raw bytes changed or no earlier raw hash exists. GitHub sources are fetched at the pinned commit.
