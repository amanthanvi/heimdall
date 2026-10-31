# docs/sources

Source pins for spec section 19 (S01-S34), auxiliary sources (A01-A04), and the G02 candidate dependency pins. Decision record: `docs/decisions/0003-source-pins.md` (ADR-0003).

| Path | What it is |
|---|---|
| `pins.json` | `sources` S01-S34 and `auxiliary_sources` A01-A04: `pin_v2` is the reproducible pin (primary hash kind, raw and normalized sha256, markers, snapshot). `pin` keeps the v1 marker; v1 hashes appear only under `legacy_*` names. `upstream` (the 7 GitHub sources): the raw branch URL and ref that `upstream` GETs. `candidates`: dependency versions, licences, heads. `tag_pins`: release tags resolved to commit ids. `escalations`, `reopen_conditions`, `reproducibility`. |
| `tools/fetch_pins.py` | Stdlib-only, GET-only fetch, normalization, compare, verify, upstream drift, tag resolution, excerpt check, self-test, archive lookup. The docstring defines the normalizer, the compare classes and every exit code (table below). |
| `fetch-baseline.json` | `fetch` output for S01-S34 on 2026-10-03T21:18Z (hashes, sizes, headers, date markers). |
| `fetch-repeat.json` | Immediate second run, identical hashes and markers. |
| `fetch-baseline-aux.json` | `fetch --set aux` output for A01-A04 on 2026-10-09 (a second run was identical). |
| `archive-lookups.json` | Internet Archive availability lookups (two passes). |
| `snapshots/` | Compressed normalized text for the 27 non-git spec sources and A01-A04 (see its README for scope and copyright). |
| `excerpts/notes.md` | Short quoted excerpts and fetch notes. |
| `drift-2026-10-31.md` | Dated source-to-gate ledger of the drift found on 2026-10-31 against the 2026-10-03 baseline: one row per changed source, the gates and documents that cite it, whether each cited claim still holds, and a disposition. The record that ADR-0003 "Reopen conditions" asks for. |

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
| `RAW_ONLY` | text and markers equal, raw bytes differ (page chrome, site rebuild) | no. With `primary_same=no` (a raw-primary source whose bytes moved) the text still equals the pin: pin maintenance, see the off-pin rule |
| `MARKER_ONLY` | text equal, a date marker moved (HTTP Last-Modified, embedded dateModified); raw may differ | no |
| `CONTENT` | normalized text differs: the visible text changed; or a GitHub body's blob sha1 is not the pinned blob (`blob_mismatch=yes`) | yes, read the snapshot and the live page. S28 fires on live counters (crate count, stars) |
| `GONE` | the reference was HTTP 200 and the second file is HTTP 404 or 410: the cited page was removed or moved | yes, after one confirming re-run |
| `FETCH_FAILED` | either side not HTTP 200 (other than the `GONE` case), a network error, or the per-source deadline (for example a bot-challenge 403); hashes not compared | unknown, re-run. If the same source fails on runs at least 24 h apart, treat it as `GONE` and investigate |
| `MISSING` / `EXTRA` | id absent from the second / first file | `MISSING` counts as a failure |

Off-pin rule (the one rule; ADR-0003 "Reopen conditions" and `pins.json` `reopen_conditions` say the same). `primary_same` says whether the second file still matches the `pin_v2` primary hash in `pins.json`; `primary_same=no` is the off-pin flag. `compare` always prints an off-pin line (also without `--all`), counts it in the header as `off_pin=N`, and exits 5 when nothing worse was found. Against the baseline, an off-pin line with class `RAW_ONLY` or `MARKER_ONLY` means the text equals the pin and only the raw bytes of a raw-primary source moved: that is pin maintenance (run `verify`, then re-pin with a dated note), not drift and not a gate reopen. An off-pin normalized-primary source is `CONTENT`, so it is drift. When the first file is not the baseline (for example two fresh runs), exit 5 only says that the live pages no longer match the pins; compare against the baseline to classify them. `compare` needs a readable `--pins` (default `docs/sources/pins.json`, relative to the current directory) unless `--no-pins` is given, which turns the off-pin check off.

## Exit codes

| Subcommand | Codes |
|---|---|
| any | `1` unreadable input (pins file, result file, empty reference file, a `pins.json` `upstream.url` that differs from the URL the tool builds); `64` usage error |
| `fetch` | `0` every source HTTP 200 and every GitHub blob equal to its pin; `2` a GitHub body whose blob sha1 is not the pinned blob (integrity failure, the condition `compare` calls `CONTENT`); `3` some source was not HTTP 200, had a network error or exceeded the deadline. Before M00-T02-fix3 every one of these was exit `1` |
| `compare` | first match wins: `2` at least one `CONTENT`, `GONE` or `MISSING`; `3` at least one `FETCH_FAILED`; `5` off-pin and nothing above; `4` only `RAW_ONLY` / `MARKER_ONLY`, every one on-pin; `0` all `IDENTICAL` and none off-pin |
| `upstream` | `0` no drift; `4` drifted, quotes intact (claim not re-read); `2` a drifted source lost a quoted fragment or has none to check, or its file is gone (404 or 410); `3` fetch failure and nothing scored `2` |
| `tags` | `0` all equal; `2` moved or missing; `3` fetch failure or invalid advertisement; `4` unpinned |
| `excerpts` | `0` all checked and found; `2` a fragment not found; `3` a source unchecked (GitHub sources need `--fetch-git`) |
| `verify` | `0` match, `3` mismatch |
| `selftest` | `0` pass, `1` fail |

Every request is a GET over https, also after redirects, with an overall deadline per source (120 s, `fetch --deadline`); output is line-buffered. Between 2026-10-03 and 2026-10-09 the raw bytes of the 1Password, Microsoft, Smallstep and Iroh pages changed while their text did not. Those sources are normalized-primary, so `4` is the expected result when no cited text has changed (`5` if the moved bytes belong to a raw-primary source). On 2026-10-09 the result was `2` (S26 page edit, S28 counters).

Exit 4 of `upstream` says that the file on the branch changed and every quoted fragment is still there. It does not say that the claim still holds, and no gate reopens by itself. The re-read policy for a drifted source cited by a still-open gate is in ADR-0003 "Reopen conditions". A recorded disposition (the ledger, and the source's `note`) closes the question for people, not for the tool: S29 keeps exiting 2 while its quoted Zig line is absent from `HEAD`, and that standing exit is accepted in `drift-2026-10-31.md`.

## Pin kinds and their limits

- Primary kind (`pin_v2.primary`), since M00-T02-fix2: `raw_body_sha256` for the 7 GitHub permalinks (S16-S19, S27, S29, S34) and the 7 OpenBSD/OpenSSH pages (S01-S05, S10, S30), whose raw hash held from 2026-10-02 to 2026-10-09; `normalized_text_sha256` for the other 20 spec sources and for A01-A04. S23 moved from raw to normalized in fix2 (ADR-0003).
- GitHub sources are pinned at a commit. `fetch` reads that commit, so `compare` never sees later changes on the branch the spec URL names (`main` or the default branch). Use `upstream` for that: on 2026-10-09 S16, S17, S18 and S34 had drifted on `main` with all quoted fragments still present (exit 4, drifted with quotes intact, claims not re-read). The URL `upstream` GETs for each of the 7 sources is recorded in `pins.json` (`upstream.url`; S19, S27 and S29 use `HEAD`, the others the branch in the spec URL), and `upstream` and `selftest` check it against the URL the code builds.
- Release tags are mutable refs. `tag_pins` records the commit each tag pointed to on 2026-10-09, and `tags` re-checks them. Release asset digests (MSI, zip, binaries) are not recorded.
- Normalized hashes depend on the Python `html.parser` and `unicodedata` versions; the baseline used Python 3.14.8.
- The normalizer ends a `<head>` at `</head>`. For a document that has a `<head>` and no `</head>` at all, it ends the head, as an HTML parser's implied `</head><body>` would, at the first start tag that cannot be in a head (`<body>` included) or at the first character data other than HTML whitespace outside `<title>` and outside an open script, style, noscript or template element (that text is kept; fix4, R3-1: `<head><title>T</title>Hello</html>` is `Hello`). Before fix3 such a page normalized to the empty string. Output is unchanged for every other document, so `NORMALIZER_VERSION` stays 1. The rule: bump it for any change that could move a pinned hash or alter a document the old rule normalized correctly; keep it for a change that only repairs documents the old rule dropped or truncated and leaves every pinned source's text as it was (no pinned source has an unclosed head: every HTML source has at least 2202 normalized characters, and the old and new normalizer gave identical text for all 38 sources as served on 2026-10-31: `tests/evidence/artifacts/review-sources/fix3/40_*.out`, `55_*.out`; fix4 repeated it for the committed 3622c56 normalizer, fix3 and fix4 on today's 38 bodies: `tests/evidence/artifacts/review-sources/fix4/20_normalizer_fix3_vs_fix4.out`). `fetch` warns on stderr when a 200 response normalizes to fewer than 200 characters.
- Environment: on 2026-10-31, Python 3.15.2 with OpenSSL 4.1.0 could not fetch the 7 OpenBSD/OpenSSH sources (S01-S05, S10, S30: `man.openbsd.org` and `www.openssh.org`; the record says `error` `URLError`, and a direct urllib probe showed `TLSV1_ALERT_DECODE_ERROR`); the fetch tool of 3622c56 failed the same way. Python 3.13.18 with OpenSSL 3.5.9 fetched all seven. Run `fetch` with an interpreter that can reach them, or `compare` will report them `FETCH_FAILED`.
- `excerpts` matches whole words: a fragment must start and end on word boundaries in its source's copy.

## Support matrix

The baseline/support matrix half of M00-T02 lives in `docs/compatibility/matrix.md` (v0 by M00-T06, refreshed to v1 by M00-T02-fix2). Each matrix row names the source ids it relies on (S01-S34 and A01-A04 here, G03-Sxx in `tests/evidence/artifacts/g03/sources/source-pins.json`) and the candidate or tag pins (`pins.json` `candidates.*`, `tag_pins`). Version floors stay `blocked` until the G01 clean-machine tests (ADR-0001 section 5).
