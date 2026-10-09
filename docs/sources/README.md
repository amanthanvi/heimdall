# docs/sources

Source pins for spec section 19 (S01-S34), auxiliary sources (A01-A04), and the G02 candidate dependency pins. Decision record: `docs/decisions/0003-source-pins.md` (ADR-0003).

| Path | What it is |
|---|---|
| `pins.json` | `sources` S01-S34 and `auxiliary_sources` A01-A04: `pin_v2` is the reproducible pin (primary hash kind, raw and normalized sha256, markers, snapshot). `pin` keeps the v1 marker; v1 hashes appear only under `legacy_*` names. `candidates`: dependency versions, licences, heads. `tag_pins`: release tags resolved to commit ids. `escalations`, `reopen_conditions`, `reproducibility`. |
| `tools/fetch_pins.py` | Stdlib-only, GET-only fetch, normalization, compare, verify, upstream drift, tag resolution, excerpt check, self-test, archive lookup. The docstring defines the normalizer, the compare classes and every exit code. |
| `fetch-baseline.json` | `fetch` output for S01-S34 on 2026-10-03T21:18Z (hashes, sizes, headers, date markers). |
| `fetch-repeat.json` | Immediate second run, identical hashes and markers. |
| `fetch-baseline-aux.json` | `fetch --set aux` output for A01-A04 on 2026-10-09 (a second run was identical). |
| `archive-lookups.json` | Internet Archive availability lookups (two passes). |
| `snapshots/` | Compressed normalized text for the 27 non-git spec sources and A01-A04 (see its README for scope and copyright). |
| `excerpts/notes.md` | Short quoted excerpts and fetch notes. |

## Reproduce (repository root, `python3` only, network GET)

    python3 -I docs/sources/tools/fetch_pins.py selftest
    python3 -I docs/sources/tools/fetch_pins.py fetch --out /tmp/new.json
    python3 -I docs/sources/tools/fetch_pins.py compare docs/sources/fetch-baseline.json /tmp/new.json
    python3 -I docs/sources/tools/fetch_pins.py fetch --set aux --out /tmp/aux.json
    python3 -I docs/sources/tools/fetch_pins.py compare docs/sources/fetch-baseline-aux.json /tmp/aux.json
    python3 -I docs/sources/tools/fetch_pins.py upstream
    python3 -I docs/sources/tools/fetch_pins.py tags
    python3 -I docs/sources/tools/fetch_pins.py excerpts --set all --fetch-git

## Reading `compare`

Each source gets one class. The first file is the reference.

| Class | Meaning | Drift? |
|---|---|---|
| `IDENTICAL` | raw bytes, normalized text and date markers equal | no |
| `RAW_ONLY` | text and markers equal, raw bytes differ (page chrome, site rebuild) | no, if `primary_same=yes`; for a raw-primary source (`primary_same=no`) the text is still identical, so check the snapshot before calling it drift |
| `MARKER_ONLY` | text equal, a date marker moved (HTTP Last-Modified, embedded dateModified); raw may differ | no |
| `CONTENT` | normalized text differs: the visible text changed; or a GitHub body's blob sha1 is not the pinned blob (`blob_mismatch=yes`) | yes, read the snapshot and the live page. S28 fires on live counters (crate count, stars) |
| `FETCH_FAILED` | either side not HTTP 200 or a network error (for example a bot-challenge 403); hashes not compared | unknown, re-run |
| `MISSING` / `EXTRA` | id absent from the second / first file | `MISSING` counts as a failure |

`primary_same` says whether the second file still matches the `pin_v2` primary hash in `pins.json`. `compare` needs a readable `--pins` (default `docs/sources/pins.json`, relative to the current directory) unless `--no-pins` is given.

Exit codes: `0` all identical; `4` text identical everywhere, only raw bytes or markers moved; `3` a fetch failed and no content change was seen; `2` at least one `CONTENT` or `MISSING`; `1` unreadable input (pins file, result file, empty reference); `64` usage error. Other subcommands: `upstream` 0 no drift, 4 drift with every quoted fragment still present, 2 a fragment lost, 3 fetch failure; `tags` 0 all equal, 2 moved or missing, 3 fetch failure or invalid advertisement, 4 unpinned; `excerpts` 0 all checked and found, 2 a fragment not found, 3 a source unchecked (GitHub sources need `--fetch-git`); `verify` 0 or 3; `fetch` 0, or 1 on any non-200 or GitHub blob mismatch. Every request is a GET over https, also after redirects. Between 2026-10-03 and 2026-10-09 the raw bytes of the 1Password, Microsoft, Smallstep and Iroh pages changed while their text did not, so `4` is the expected result when no cited text has changed. On 2026-10-09 the result was `2` (S26 page edit, S28 counters).

## Pin kinds and their limits

- Primary kind (`pin_v2.primary`), since M00-T02-fix2: `raw_body_sha256` for the 7 GitHub permalinks (S16-S19, S27, S29, S34) and the 7 OpenBSD/OpenSSH pages (S01-S05, S10, S30), whose raw hash held from 2026-10-02 to 2026-10-09; `normalized_text_sha256` for the other 20 spec sources and for A01-A04. S23 moved from raw to normalized in fix2 (ADR-0003).
- GitHub sources are pinned at a commit. `fetch` reads that commit, so `compare` never sees later changes on the branch the spec URL names (`main` or the default branch). Use `upstream` for that: on 2026-10-09 S16, S17, S18 and S34 had drifted on `main` with all quoted fragments still present (exit 4).
- Release tags are mutable refs. `tag_pins` records the commit each tag pointed to on 2026-10-09, and `tags` re-checks them. Release asset digests (MSI, zip, binaries) are not recorded.
- Normalized hashes depend on the Python `html.parser` and `unicodedata` versions; the baseline used Python 3.14.8.

## Support matrix

The baseline/support matrix half of M00-T02 lives in `docs/compatibility/matrix.md` (v0 by M00-T06, refreshed to v1 by M00-T02-fix2). Each matrix row names the source ids it relies on (S01-S34 and A01-A04 here, G03-Sxx in `tests/evidence/artifacts/g03/sources/source-pins.json`) and the candidate or tag pins (`pins.json` `candidates.*`, `tag_pins`). Version floors stay `blocked` until the G01 clean-machine tests (ADR-0001 section 5).
