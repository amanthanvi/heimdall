# Source excerpt notes (M00-T02, revised by M00-T02-fix and M00-T02-fix2)

Short quotes only. Normalized text of the 27 non-git spec sources and of the auxiliary sources A01-A04 is stored compressed in `docs/sources/snapshots/` (see its README). Each `pins.json` source carries `pin_v2` with raw and normalized sha256 produced by `docs/sources/tools/fetch_pins.py`. The v1 `text_sha256` values of the 28 HTML and GitHub sources are not reproducible and are not drift detectors; for the 6 `.md` sources the v1 value is the raw `.md` body hash and was reproduced (see Fetch notes). `fetch_pins.py excerpts --set all --fetch-git` checks that every quoted fragment in `pins.json` occurs in its own source's pinned copy.

## S07 (1Password SSH authorization), relevant to spec line 323
- "Until 1Password locks (default): Every time 1Password locks, your key approvals are wiped from the agent's memory ..."
- "For a set amount of time: You can choose from 4, 12, or 24 hours. ... your key approvals will remain in the agent's memory for that duration, even when 1Password is locked. ... but you'll be prompted to unlock 1Password so the SSH agent can access your private key."
- Reading: the spec sentence (remembered approvals do not keep private keys available after lock) is accurate as written. The gap is that the spec does not say key approvals themselves can outlive a lock under the timed option. E1 is a suggested clarification, not a contradiction.

## S22 (Iroh JavaScript)
- "macOS: arm64 (no Intel build)"; Linux x86_64/aarch64 (glibc+musl), armv7; Windows x86_64/aarch64; Android aarch64/armv7. Node.js 20.3.0+.
- npm @number0/iroh 1.1.0 optionalDependencies match this list (11 platform packages, no darwin-x64).
- "Endpoint.bind applies the n0 preset (public discovery + default relays) by default."

## S26 (OpenAI latest-model guide)
- Sections "Initiative and follow-through" and "Testing and verification".
- "unclear or conflicting guidance in a skill file may cause the model to pause and block work early. Make the priority of user instructions and skills explicit."
- "complete all the necessary work until the intended outcome is fulfilled."
- Correction: the v1 excerpt also listed "Be very specific about your end goal". That sentence is on S31, not S26.

## S31 (OpenAI reasoning best practices)
- "**Be very specific about your end goal**: In your instructions, try to give very specific parameters for a successful response ..."

## S32 (OpenAI evaluation best practices)
- "OpenAI is deprecating the Evals platform. ... read-only for existing users on October 31, 2026, and the platform is scheduled to shut down on November 30, 2026."

## S27 (Bubble Tea)
- README imports `tea "charm.land/bubbletea/v2"`; docs link pkg.go.dev/charm.land/bubbletea/v2. License MIT.
- Pin commit 96d69d2 is main head at retrieval; tag v2.0.10 is d5bfd5c (Go module proxy origin).

## S19 (Pigeons README at 7800c52)
- Integration: "`pigeons add` writes a `Host` entry to your SSH config whose `ProxyCommand` runs `pigeons fly --stdio`".
- Telemetry: "Nothing is sent unless it is `true`."; counters "sampled once a minute and pushed to [iroh-services]"; "the sending endpoint ID is visible to the collector".
- Service: "pigeons service install" for Linux (systemd), macOS (launchd), Windows (SCM); "a roost installed with `pigeons service install` runs as root".
- SSH config: example output "Pigeon route 'my-server' added to ~/.ssh/config".
- Security model: "anyone holding the endpoint ID can reach your SSH port"; dedicated `.ssh/pigeons_ed25519` keypair.

## Win32-OpenSSH (PowerShell/Win32-OpenSSH README at 39d8050 and PowerShell/openssh-portable LICENCE at e581929)
- "As of Nov 1st 2016, active development on "Windows for OpenSSH" is being done in https://github.com/PowerShell/openssh-portable."
- LICENCE: "all components are under a BSD licence, or a licence more free than that." and "OpenSSH contains no GPL code."

## Win32-OpenSSH clients observed on Windows (G03, 2026-10-06; facts for owner item E6, not a decision)
- Inbox `C:\WINDOWS\System32\OpenSSH\ssh.exe`: "OpenSSH_for_Windows_9.5p2, LibreSSL 3.8.2", file version 9.5.6.3 (Windows 11 Pro build 26300.9550; `tests/evidence/g03-win-env-inventory.json`).
- GitHub MSI `C:\Program Files\OpenSSH\ssh.exe`: "OpenSSH_for_Windows_10.0p2 Win32-OpenSSH-GitHub, LibreSSL 3.8.2", file version 10.0.0.0, first on PATH.
- The LICENCE above covers the openssh-portable source tree; the licence of the LibreSSL 3.8.2 built into both binaries is not recorded here.

## Iroh bindings and platforms (auxiliary sources A01-A04, fetched 2026-10-09)
- A01 (docs.iroh.computer/languages): table rows "C Official Raw FFI via iroh-c-ffi, build from source" and "Go Community FFI bindings via iroh-ffi"; "“Community” bindings are built and maintained by community members rather than the number0 team. They aren’t covered by official support, may lag behind iroh releases, and cover fewer platforms".
- A02 (languages/go): "iroh-go is still considered experimental but ready for testing"; "Platform Architectures Linux x86_64, aarch64 (musl)"; "We’re aiming to publish a stable tag once we see more usage and adoption of the Go bindings."; `go get git.coopcloud.tech/decentral1se/iroh-go`. The words "highly experimental" and "cgo" are not on A01 or A02 (escalation E9).
- A03 (languages/c): "Platform Architectures Linux x86_64 (glibc) macOS arm64 Windows x86_64"; "There are no prebuilt binaries; you build the static/shared library from source and link against it."
- A04 (compatibility): "iroh supports all major operating systems." Table: Linux, macOS, Windows, Android, iOS, WebAssembly (browser), FreeRTOS: Yes.

## Drift on the GitHub branch (not on the pins)
- `fetch_pins.py upstream`, 2026-10-09T05:36Z and 06:14Z: S16, S17, S18 and S34 changed on `main` after their pinned commits (blobs in each source's `note`); every quoted fragment still occurs on `main`. S19, S27 and S29 READMEs on the default branch equal the pinned blobs.

## Fetch notes
- 1Password pages report an embedded dateModified that tracks site rebuilds (S06, S09, S12 share 2026-10-02T14:06:52Z); rely on the normalized-text hash.
- OpenAI and learn.chatgpt.com pages (S24, S25, S26, S31, S32, S33) are fetched from their `.md` variants (same site, text/markdown) because the HTML is large and script-heavy. Their Last-Modified headers read 2026-10-03T20:04-20:43Z, after the v1 retrieval, yet the bytes did not change: the v1 `text_sha256` of each of the 6 equals its v2 raw-body sha256 (v1 hashed the raw `.md` body; relabelled `legacy_raw_body_sha256_v1` by M00-T02-fix2). Last-Modified on these pages moves without a content change; `compare` reports that as MARKER_ONLY.
- S23 (mitchellh.com) was rebuilt between 2026-10-03T21:18Z and 2026-10-09T05:17Z (46148 to 45864 bytes) with identical normalized text; its primary pin is now the normalized hash (M00-T02-fix2).
- S28 (ratatui.rs) shows live counters (crates, stars, downloads), so its normalized text changes without a change to the cited sentence; `compare` reports CONTENT for it.
- Man pages: the pin is the "OpenBSD-current <date>" footer from man.openbsd.org; the server returns no Last-Modified and the page exposes no $Mdocdate$.

## G03-S12 (1Password SSH agent): socket paths and `agent.toml` location not available offline (M02-W0, 2026-11-01)
- m02-plan U0 asks for the pinned excerpts of the 1Password agent socket paths and the `agent.toml` location, taken from the agent/config and get-started pages that G03-S12 pins by hash (`tests/evidence/artifacts/g03/sources/source-pins.json`: `op/ssh_agent_config.md` sha256 `f233e25f…`, `op/ssh_get-started.md` sha256 `f18aebc9…`, retrieved 2026-10-03).
- Those pins record hashes only ("content not committed"). The committed G03 excerpts (`tests/evidence/artifacts/g03/sources/excerpts.txt`) quote neither a socket path nor the `agent.toml` location, and the spec pins (S06, S07, S09, S12 snapshots) do not contain them either. So the excerpts cannot be produced from repository content, and a fresh fetch of these mutable vendor pages would not verify against the 2026-10-03 hashes.
- Consequence (ADR-0007 §7; m02-plan U0, U6): no 1Password path is hardcoded. Detection uses `SSH_AUTH_SOCK` and `IdentityAgent` references in the configuration only, until a later task fetches the two pages, pins them again and quotes the paths here. Escalated in the M02-W0-skeleton report.
