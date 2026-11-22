# Reference configuration (M08 U7a)

- `config.toml`: every runtime setting at its default, with what each does.
- `heimdall.toml`: an example project manifest. In a repository it is named `.heimdall.toml`.
  It requests a profile; it grants nothing.
- `check.py`: validates both against the published schemas and checks that `config.toml`
  states every default the schema declares. `python3 -I examples/reference-config/check.py`.

Provisional: the files follow `main`'s schemas and change with them. They are packaged in
the release archive (ADR-0014 §4.2).
