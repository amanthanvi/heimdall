# Generate the compatibility matrix

The row list in [matrix-rows.json](matrix-rows.json) contains the existing
provider, client, environment and mechanism combinations and the clean-machine
and fresh-account archive rows in [M08 plan §4](../../docs/architecture/m08-plan.md#4-the-declared-release-matrix-and-the-clean-machine-proof).

```sh
python3 -I -B tools/release/matrix.py --write
python3 -I -B tools/release/matrix.py --check
```

The draft uses `draft` bindings and `historical_records` from
[tests/evidence](../../tests/evidence). The older baseline rows retain their
original `draft_gate` assessment. The draft keeps the original introduction
and observations in [the repository matrix](../../docs/compatibility/matrix.md).
The packaged copy keeps the placeholder required by the artifact verifier.

For the candidate, add a `candidate` list of bindings to each row covered by
the candidate's exit records. Each binding names the evidence JSON file in
`record`. If it reports several platforms or configurations, use `platform`
with a prefix that identifies exactly one entry in `observed_result.rows`.
List the relevant `provider_versions` prefixes in `versions`. These match
string entries or the `name` of object entries, whose `version` is copied.
A binding can select a zero-based `limitation` entry from its record. The
matrix includes the selected evidence's `blocked_on` where present. It otherwise
uses the row's matching bullet in [limitations.md](../../docs/user/limitations.md)
or the general note about rows that did not run.

Set `candidate_label` only after reviewing the bound exit evidence against
spec §3.3. A support label of `verified` or `supported-with-limitations`
requires each selected observation to be verified. A clean-machine row needs
both static verification and the first journey. The Linux x86-64 row covers
both distributions in the plan. A fresh-account run belongs to its own row.
Rows without candidate records keep `not-tested`.

```sh
python3 -I -B tools/release/matrix.py --write --candidate <full-build-sha>
python3 -I -B tools/release/matrix.py --check --candidate <full-build-sha>
```

Candidate mode writes only the packaging slot and removes its placeholder.
It requires each citation in that slot to validate against the record schema
and name the exact candidate build. The repository page remains the historical
draft. The normal gate checks that page and validates the packaged slot in its
current draft or candidate mode. Prepare the other candidate materials
required by [the packaging checklist](../packaging/README.md#payload-and-candidates)
before building the candidate archive.
