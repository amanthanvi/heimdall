# Errata for the round-3c workflow results

- `conf3c-ts.json` gives the TS linux-arm64 artifact sha256 as
  `ac48d2a6c789bb07fcf1…`, which is wrong after the first 16 hex digits. The
  authoritative value is in `tests/evidence/g02-ts-conformance-linux.json`
  and `prototypes/ts/dist/manifest.json`: `ac48d2a6c789bb073168…`. Found by
  `review-adr-0002/review-2.md` (e1). The archived agent result is kept
  unedited.
