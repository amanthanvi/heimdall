# Source excerpt notes (M00-T02, revised by M00-T02-fix)

Short quotes only. Normalized text of the 27 non-git sources is stored compressed in `docs/sources/snapshots/` (see its README). Each `pins.json` source carries `pin_v2` with raw and normalized sha256 produced by `docs/sources/tools/fetch_pins.py`; the v1 `text_sha256` values are not reproducible and are not drift detectors.

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

## Fetch notes
- 1Password pages report an embedded dateModified that tracks site rebuilds (S06, S09, S12 share 2026-10-02T14:06:52Z); rely on the normalized-text hash.
- OpenAI and learn.chatgpt.com pages (S24, S25, S26, S31, S32, S33) are fetched from their `.md` variants (same site, text/markdown) because the HTML is large and script-heavy. Their Last-Modified headers read 2026-10-03T20:04-20:43Z, after the v1 retrieval; whether content changed is not known because v1 stored no raw hash for them.
- Man pages: the pin is the "OpenBSD-current <date>" footer from man.openbsd.org; the server returns no Last-Modified and the page exposes no $Mdocdate$.
