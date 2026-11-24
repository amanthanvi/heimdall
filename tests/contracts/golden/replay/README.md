# The replay corpus (ADR-0013 §1.3; docs/architecture/u0-plan.md §5)

Real prior-version rows: each directory holds the scratch stores one exit build wrote while
running the short fixed journey of `tests/contracts/replay_journey.py`, as SQL text dumps
(`<home>.sql`) with a `manifest.json` (the store's `user_version`, row counts per table, and
every step with its real exit code and code). `hand/` holds hand-authored rows for the
historical shapes no journey writes. `stored_samples_replay_through_revision_7_readers`
(`cargo test -p heimdall-store --test contracts_replay`) rebuilds each dump, migrates it with
the production migrations and reads every row of every table of the migrated schema back
through its reader, except the tables and `meta` keys under "Stored, not read" below: the
store's public readers (methods of `heimdall_store::Txn`), each event also through revision
7's `EventPayload`, each controller pin (`remote_environment_pins`) also through revision 7's
`RemoteEnvironmentPin`, and each `meta` row through the reader of its key class
(`META_RECOVERY`). For every table the rows read must equal the rows stored. A table of the
migrated schema, or a `META_RECOVERY` key class, that is neither read nor listed below fails
the test.

Every dump is fixture data from scratch homes under the debug test configuration (the fake
adapter; no SSH, agent, key store or network). The fake adapter's synthetic credential
reference is replaced by `replay_fixture_credential_ref`, scratch paths by `/scratch`, and
the driver refuses a dump holding a home path, the account's user name, a canary or key
armor (self-test: `tests/contracts/test_replay_journey.py`, a `check.sh` step).

## Builds, and why each is genuine

Each old SHA was exported with `git archive` (every file then touched, so no artifact of
another SHA counts as fresh) and built with `cargo build --locked -p heimdall` (debug) in the
worktree's one `target/`. A build is genuine when cargo compiled every workspace crate in that
SHA's `heimdall` build graph (normal and build edges, from `cargo metadata --offline` on the
export); a dump whose build did not is discarded and rebuilt. Every binary's SHA-256 differs.

| Dump | Build | SHA | Store version | Crates in the graph = crates compiled | Binary SHA-256 |
|---|---|---|---|---|---|
| `m02/` | M02 exit | `e4f43f847af1b3a7396298f5a39af6d859b080d1` | 5 | 12, equal | `c062d0eedcec676c6e8e2ad27f4443787c094ef795669c9fd9a49582aa56c4d8` |
| `m03/` | M03 exit (E9) | `2b79aac1b6bea72f886cef2331c9e3b5d0a123e8` | 6 | 16, equal | `45897fae778d38c9e5391af6b4b2ff7ae5a83ab62ad464d6ac37d83b55023ba5` |
| `m0405/` | M04/M05 exit | `50dbc86b29df42b052071eae040bc074d148e81e` | 8 | 18, equal | `afb9b517f9f6cfbd083e5cf8a5bc17d3161c26207f5471e32e12ceb98da857eb` |
| `m06/` | M06 exit | `9399e768ddd5c78f2591dc8b77784804d7f6000a` | 13 | 20, equal | `6e59ac100862098edfa129d342af065cf83737cc6be7aaacd7046cb205afb36d` |
| — | HEAD after the M06 build (`723c4cd8`, worktree sources touched) | — | 14 | 20, equal | `18ec7f15d4f57a26518cff2697e9ca6a29e63aa8fb1a56a89ece4a488ce18e2e` |
| — | HEAD after the first three builds (`a0cd29f2`, worktree sources touched) | — | 14 | 20, equal | `8425422fd8e4cde3ae9f5c560270732b384ec568ea0e470911dda708c9abce18` |

The M06 dump comes from exit build 2 (`9399e768`); M06's build of record is exit build 4
(`aa87c34c`). `git diff --stat 9399e768 aa87c34c -- crates` touches only
`crates/testkit/src/sshd.rs` and a `#[cfg(test)]` block in `crates/localenv/src/sys/openssh_env.rs`,
so the product code that wrote these rows is identical to exit build 4's.

Workspace members outside the `heimdall` graph (not built by `-p heimdall`): none at M02, M03
and M04/M05; `heimdall-stategen` and `heimdall-support` at M06 and at HEAD.

### The crates compiled, per build

- **M02 exit:** `heimdall`, `heimdall-adapters`, `heimdall-app`, `heimdall-contract`, `heimdall-domain`, `heimdall-ipc`, `heimdall-launch`, `heimdall-localenv`, `heimdall-runtime`, `heimdall-sshconf`, `heimdall-store`, `heimdall-testkit`
- **M03 exit (E9):** `heimdall`, `heimdall-adapters`, `heimdall-app`, `heimdall-contract`, `heimdall-credential`, `heimdall-domain`, `heimdall-enroll`, `heimdall-ipc`, `heimdall-issuer`, `heimdall-launch`, `heimdall-localenv`, `heimdall-registry`, `heimdall-runtime`, `heimdall-sshconf`, `heimdall-store`, `heimdall-testkit`
- **M04/M05 exit:** `heimdall`, `heimdall-adapters`, `heimdall-app`, `heimdall-contract`, `heimdall-credential`, `heimdall-domain`, `heimdall-enroll`, `heimdall-ipc`, `heimdall-issuer`, `heimdall-launch`, `heimdall-localenv`, `heimdall-project`, `heimdall-registry`, `heimdall-runtime`, `heimdall-sshconf`, `heimdall-store`, `heimdall-testkit`, `heimdall-wsl`
- **M06 exit, and HEAD (both builds):** `heimdall`, `heimdall-adapters`, `heimdall-app`, `heimdall-contract`, `heimdall-credential`, `heimdall-domain`, `heimdall-enroll`, `heimdall-ipc`, `heimdall-issuer`, `heimdall-launch`, `heimdall-localenv`, `heimdall-project`, `heimdall-registry`, `heimdall-remote`, `heimdall-runtime`, `heimdall-sshconf`, `heimdall-store`, `heimdall-testkit`, `heimdall-transport-iroh`, `heimdall-wsl`

## The journeys

The M02, M03 and M04/M05 journeys ran with `PATH=/usr/bin:/bin`, so each runtime ran the real
`/usr/bin/ssh -V` at start (it reads nothing under `~/.ssh`). The driver now puts a guard first
on `PATH` (fake OpenSSH programs that log their arguments and exit 1) and records the calls in
the manifest's `ssh_guard_calls`. The M06 journey ran with that guard, inside a sandbox that
denies writes under the account's real `~/.ssh`: each home's runtime called only `ssh -V`, once,
and no OpenSSH program ran.

- **m02/main** (version 5): service run 0; ensure (ready) 0; ensure (replay) 0; ensure (conflict) 6; ensure (pending) 3; ensure (to deny) 3; decision deny (attended) 0; ensure (to approve) 3; decision approve (attended) 0; access pause 0; access resume (pending) 3; access resume (attended) 0; access cutoff 0; access cutoff --clear (pending) 3; inspect bindings 0; access release 0; access revoke 0; operation events 0; service stop 0.
- **m02/slow** (version 5): service run 0; ensure --async 0; operation cancel 0; service stop 0.
- **m02/lost** (version 5): service run 0; ensure (outcome unknown) 7; ensure (same key retry) 0; service stop 0.
- **m03/main** (version 6): service run 0; ensure (ready) 0; ensure (replay) 0; ensure (conflict) 6; ensure (pending) 3; ensure (to deny) 3; decision deny (attended) 0; ensure (to approve) 3; decision approve (attended) 0; access pause 0; access resume (pending) 3; access resume (attended) 0; access cutoff 0; access cutoff --clear (pending) 3; access lock-behavior 0; inspect bindings 0; access release 0; access revoke 0; operation events 0; service stop 0.
- **m03/slow** (version 6): service run 0; ensure --async 0; operation cancel 0; service stop 0.
- **m03/lost** (version 6): service run 0; ensure (outcome unknown) 7; ensure (same key retry) 0; service stop 0.
- **m0405/main** (version 8): service run 0; ensure (ready) 0; ensure (replay) 0; ensure (conflict) 6; ensure (pending) 3; ensure (to deny) 3; decision deny (attended) 0; ensure (to approve) 3; decision approve (attended) 0; access pause 0; access resume (pending) 3; access resume (attended) 0; access cutoff 0; access cutoff --clear (pending) 3; access lock-behavior 0; access default-profile 0; inspect bindings 0; access release 0; access revoke 0; access stop --work 0; operation events 0; service stop 0.
- **m0405/slow** (version 8): service run 0; ensure --async 0; operation cancel 0; service stop 0.
- **m0405/lost** (version 8): service run 0; ensure (outcome unknown) 7; ensure (same key retry) 0; service stop 0.
- **m06/main** (version 13): service run 0; ensure (ready) 0; ensure (replay) 0; ensure (conflict) 6; ensure (pending) 3; ensure (to deny) 3; decision deny (attended) 0; ensure (to approve) 3; decision approve (attended) 0; access pause 0; access resume (pending) 3; access resume (attended) 0; access cutoff 0; access cutoff --clear (pending) 3; access lock-behavior 0; access default-profile 0; inspect bindings 0; access release 0; access revoke 0; access stop --work 0; operation events 0; service stop 0.
- **m06/slow** (version 13): service run 0; ensure --async 0; operation cancel 0; service stop 0.
- **m06/lost** (version 13): service run 0; ensure (outcome unknown) 7; ensure (same key retry) 0; service stop 0.

## Stored, not read

No reader an integration test can reach (neither a public reader of the store nor a revision 7
typed reader). The test's `NOT_READ` and `META_NOT_READ` list the same, with the same reasons,
and it counts these rows as stored, not read.

- `request_fences`: no reader: migration 0014 creates it; its writer and reader are U2b's.
- `meta` key `restore_epoch`: no public reader: `Store::open` refuses a missing or non-canonical value, and no method returns it.
- `meta` key `remote_revocation_claim_seq`: no reader: only `next_remote_claim_seq`, which reads it to advance it (a writer).
- `meta` key `cleanup_intent_version`: no reader: only `record_cleanup_intent`, which reads it to advance it (a writer).

