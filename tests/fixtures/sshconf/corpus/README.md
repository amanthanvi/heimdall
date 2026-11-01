# `tests/fixtures/sshconf/corpus`: inert OpenSSH client configurations

Owner: M02-U1 (m02-plan U1). Users: U1's `model_sshconf_parse` (static checks below),
and U3's `integration_sshconf_vs_ssh_g::corpus_*`, `corpus_identity_list_matches_ssh_g`,
`include_state_is_restored_after_included_file` and `bom_and_crlf_acceptance`, which run
`ssh -G -F <root> <alias>` per target client and compare with the static evaluator.

## Rules every file follows

* The first line is `# inert, ssh -G only` (after the BOM in `bom.conf`).
* Nothing executes: no `Match exec`, `ProxyCommand`, `LocalCommand`, `PermitLocalCommand`
  or `KnownHostsCommand`. No `Match localnetwork`, `canonical` or `final`, and no
  `CanonicalizeHostname`, so `ssh -G` needs no DNS. `model_sshconf_parse` checks this.
* No real material: host names are under `.example` (RFC 2606), addresses in
  192.0.2.0/24 (RFC 5737), and every key, certificate or socket path is under
  `/nonexistent/hm-corpus` (or a `//./pipe/hm-corpus…` name). `ssh -G` prints these
  values and opens none of them.
* Every `Include` is `"@CORPUS_DIR@/include/…"`. The harness copies the corpus into a
  scratch directory and replaces `@CORPUS_DIR@` with that copy's absolute path (with
  `/` separators) before running anything. A relative `Include` would resolve under the
  account's `~/.ssh` (ssh_config(5) `Include`), which tests never read. Unreplaced, the
  placeholder is a relative path that matches nothing.

## Files

Roots (pass to `-F`) are the top-level `*.conf` files; `include/**` is only included.

| Root | Covers | Aliases |
|---|---|---|
| `basic.conf` | Host and Match patterns, wildcards, negation, `=` forms, first obtained value (F1) | `alpha`, `x.corpus.example`, `bad.corpus.example`, `beta`, `gamma1`, `gamma-excluded`, `delta`, `-l corpus-explicit <any>` |
| `identity.conf` | additive IdentityFile/CertificateFile (F2), IdentitiesOnly, IdentityAgent incl. `//./pipe/` (F14), `%%` (F7, F15), spaced and non-ASCII paths, `none` | `ident-one`, `ident-spaced`, `ident-percent`, `ident-pipe`, `ident-pipe-quoted`, `ident-agent-none`, `ident-files-none` |
| `nested.conf` | three include levels and a glob whose members load in bytewise order (F3): `nested-glob` gets HostName `first.corpus.example` and User `corpus-upper` only under bytewise order | `nested-after`, `nested-level1`, `nested-glob`, `nested-deep` |
| `include-state.conf` | the including file's section state is restored after the include (ADR-0007 §3 `[I]`): `state-alpha` gets Port 2501 only if it is | `state-alpha`, `state-other` |
| `unsupported.conf` | an unknown keyword under IgnoreUnknown; S01's deprecated alias and former name | `unsupported` |
| `retired.conf` | obsolete spellings outside the pinned manual (`directive::ALIASES` Inferred, `directive::OBSOLETE`), `[I]` until a client loads the file | `retired` |
| `bom.conf` | a UTF-8 BOM before line 1 (ADR-0007 §4): upstream OpenSSH does not skip it | `bom-check` |
| `crlf.conf` | CRLF line endings (ADR-0007 §4) | `crlf-check` |
| `lexer.conf` | argument splitting (`crate::lex`): `#` inside a token, quotes, one `=` skipped, escapes, and `RemoteCommand` taken as the raw rest of the line | `lex-hash`, `lex-quote`, `lex-equals`, `lex-escape`, `lex-unknown-escape`, `lex-command` |

The expected values are whatever `ssh -G` prints on each client; this table only says what
each file is meant to discriminate.
