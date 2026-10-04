# Dependency licenses — Go G02 prototype

Generated 2026-10-03 (UTC) with **go-licenses v2.0.1**
(`github.com/google/go-licenses/v2`, module sum
`h1:ti+9bi5o7DKbeeg5eBb/uZTgsaPNoJaLCh93cRcXsW8=`, built with go1.27.1),
command run from `prototypes/go`:

```sh
GOOS=<darwin|linux|windows> GOARCH=<arm64|amd64> go-licenses report ./cmd/heimdall-proto
```

All three runs exited 0. Round 2 (2026-10-03) correction: the "Linked on"
column was checked against `go version -m` of each built artifact
(`tests/evidence/artifacts/g02-go/selftest/round2-20261003/go-version-m.txt`);
x/termios is not linked into the windows artifact, and colorprofile is now a
direct dependency (same version). Raw output:
`tests/evidence/artifacts/g02-go/selftest/go-licenses-report.txt`. The table is
the union over the three OS builds (go-licenses reports per package; packages
of the same module are merged here). The prototype's own packages report
`Unknown` because the prototype has no license file (license selection is an
explicit release decision, spec §15.3).

| Module | Version | License | Direct? | Linked on |
|---|---|---|---|---|
| charm.land/bubbletea/v2 | v2.0.10 | MIT | direct | all |
| github.com/BurntSushi/toml | v1.6.0 | MIT | direct | all |
| github.com/Microsoft/go-winio | v0.6.2 | MIT | direct | windows only |
| github.com/charmbracelet/x/ansi | v0.11.8 | MIT | direct | all |
| github.com/charmbracelet/x/term | v0.2.2 | MIT | direct | all |
| golang.org/x/sys (unix, windows) | v0.46.0 | BSD-3-Clause | direct | unix / windows |
| github.com/charmbracelet/colorprofile | v0.4.3 | MIT | direct (round 2: color profile detection without `tmux info`, K16) | all |
| github.com/charmbracelet/ultraviolet | v0.0.0-20260703014108-f5a850f9c2b7 (untagged) | MIT | transitive | all |
| github.com/charmbracelet/x/termios | v0.1.1 | MIT | transitive | darwin, linux (not windows) |
| github.com/charmbracelet/x/windows | v0.2.2 | MIT | transitive | all (package compiled on every OS) |
| github.com/clipperhouse/displaywidth | v0.11.0 | MIT | transitive | all |
| github.com/clipperhouse/uax29/v2 | v2.7.0 | MIT | transitive | all |
| github.com/lucasb-eyer/go-colorful | v1.4.0 | MIT | transitive | all |
| github.com/mattn/go-runewidth | v0.0.24 | MIT | transitive | all |
| github.com/muesli/cancelreader | v0.2.2 | MIT | transitive | all |
| github.com/rivo/uniseg | v0.4.7 | MIT | transitive | all |
| github.com/xo/terminfo | v0.0.0-20220910002029-abceb7e1c41e | MIT | transitive | all |
| golang.org/x/sync (errgroup) | v0.21.0 | BSD-3-Clause | transitive | all |
| Go standard library + runtime | go1.27.1 | BSD-3-Clause | (toolchain) | all — statically linked into every artifact; not listed by go-licenses |

Test-only / build-graph-only modules (in `go.sum`, not linked into the
artifact): `github.com/charmbracelet/x/exp/golden`, `github.com/aymanbagabas/go-udiff`,
`golang.org/x/exp` (pulled by Bubble Tea's own tests). Not license-audited here.

Notes:

- All linked licenses are permissive (MIT, BSD-3-Clause). Both require
  reproducing the copyright notice and license text in binary distributions;
  the prototype artifacts do **not** currently embed or ship those notices.
  A release would need a NOTICE/third-party file (spec §15.3, plan §7.4).
- No copyleft, no native (C) libraries, no cgo (`CGO_ENABLED=0`).
- Tooling used only at build/audit time and not shipped: go-licenses v2.0.1
  (Apache-2.0), govulncheck v1.8.0 (BSD-3-Clause).
