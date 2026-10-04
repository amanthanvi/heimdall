# Licenses: TypeScript + OpenTUI G02 prototype

Disposable G02 evidence. This is not a release license review. The project's own license
is an open release decision (spec §15.3). The prototype's `package.json` is `private`,
which license-checker reports as `UNLICENSED`.

## How this was generated

- Tool: `license-checker-rseidelsohn@5.0.1` (BSD-3-Clause), run with
  `bunx --bun license-checker-rseidelsohn@5.0.1 --json [--production] --start prototypes/ts`
  on 2026-10-03 (UTC). Exit code was 0 for both runs.
- Raw output (home path redacted):
  `tests/evidence/artifacts/g02-ts/selftest/licenses-all.json` has 30 packages, and
  `licenses-production.json` has 21.
- Input: `prototypes/ts/bun.lock` (lockfileVersion 2), installed with
  `bun install --frozen-lockfile --os='*' --cpu='*'` so that every platform's native
  package is present.
- "Shipped" below comes from the bundler metafile (`bun build --metafile`) plus inspection
  of `@opentui/core`'s dist. OpenTUI pre-bundles `marked`, `diff`, `string-width`,
  `strip-ansi`, and `bun-ffi-structs` into its own chunks, so their code ships even though
  the metafile does not list them. Each compiled artifact embeds only its own target's
  native library (checked with `strings` on the darwin-arm64 artifact).
- Updated 2026-10-03 (§9 alignment, ruling K11): no OpenTUI native library is embedded any
  more. `build.sh` builds with `--external '@opentui/core-*'` and ships the target's library
  as a sidecar file, `dist/<target>/@opentui/core-<platform>/<lib>`, listed in
  `dist/manifest.json`. Inference from sizes: the earlier linux artifacts embedded the musl
  library as well as the glibc one (each linux executable shrank by about the sum of both:
  linux-x64 by 12,607,488 bytes vs 6,314,816 + 6,294,480).

## npm packages (direct and transitive)

| Package | Version | License | Shipped in artifact? |
|---|---|---|---|
| @opentui/core | 0.5.14 | MIT | yes (direct dependency) |
| @opentui/core-darwin-arm64 | 0.5.14 | MIT (+ bundled third-party, below) | yes, darwin-arm64 only, as sidecar `libopentui.dylib` |
| @opentui/core-linux-x64 | 0.5.14 | MIT (+ bundled third-party) | yes, linux-x64 only, as sidecar `libopentui.so` |
| @opentui/core-linux-arm64 | 0.5.14 | MIT (+ bundled third-party) | yes, linux-arm64 only, as sidecar `libopentui.so` |
| @opentui/core-win32-x64 | 0.5.14 | MIT (+ bundled third-party) | yes, windows-x64 only, as sidecar `opentui.dll` |
| @opentui/core-darwin-x64, -linux-*-musl, -win32-arm64 | 0.5.14 | MIT | installed for completeness; not shipped since the 2026-10-03 rebuild (the earlier linux artifacts appear to have embedded the musl libraries too, see above) |
| smol-toml | 1.9.0 | BSD-3-Clause | yes (direct dependency) |
| web-tree-sitter | 0.25.10 | MIT | yes (peer of OpenTUI; runtime + `tree-sitter.wasm` embedded) |
| marked | 17.0.1 | MIT | yes (inlined in OpenTUI dist) |
| diff | 9.0.0 | BSD-3-Clause | yes (inlined in OpenTUI dist) |
| string-width | 7.2.0 | MIT | yes (inlined in OpenTUI dist) |
| strip-ansi | 7.1.2 | MIT | yes (inlined in OpenTUI dist) |
| ansi-regex | 6.4.0 | MIT | yes (via strip-ansi) |
| emoji-regex | 10.6.0 | MIT | yes (via string-width) |
| get-east-asian-width | 1.7.0 | MIT | yes (via string-width) |
| bun-ffi-structs | 0.3.1 | MIT | yes (inlined in OpenTUI dist) |
| typescript | 5.9.3 | Apache-2.0 | no (type-only peer of bun-ffi-structs; also our typecheck devDependency) |
| ajv | 8.20.0 | MIT | no (test only: JSON Schema validation) |
| fast-deep-equal | 3.1.3 | MIT | no (ajv) |
| fast-uri | 3.1.8 | BSD-3-Clause | no (ajv) |
| json-schema-traverse | 1.0.0 | MIT | no (ajv) |
| require-from-string | 2.0.2 | MIT | no (ajv) |
| @types/bun | 1.4.2 | MIT | no (types) |
| bun-types | 1.4.2 | MIT | no (types) |
| @types/node | 26.6.4 | MIT | no (types) |
| undici-types | 8.9.0 | MIT | no (types) |

OpenTUI also embeds tree-sitter grammar WASM files and highlight queries (JavaScript,
TypeScript, Markdown, Markdown-inline, Zig) as package assets. The bundler includes them
in every artifact even though this prototype never uses syntax highlighting. They ship
inside `@opentui/core` (MIT). I did not verify the upstream licenses of the individual
grammars separately; they need a check before release.

## Third-party code inside the OpenTUI native library

License files shipped next to `libopentui.*` in `@opentui/core-<platform>@0.5.14`:

| Component | License file | License |
|---|---|---|
| Ghostty (terminal code) | LICENSE-GHOSTTY | MIT |
| Little CMS 2 | LICENSE-LCMS2 | MIT |
| libwebp | LICENSE-LIBWEBP + PATENTS-LIBWEBP + AUTHORS-LIBWEBP | BSD-3-Clause + Google patent grant |
| stb | LICENSE-STB | MIT or Unlicense (public domain), at the user's choice |
| Wuffs | LICENSE-WUFFS | Apache-2.0 |

Image, audio, and color-management code ships in the native library even though this
prototype only draws text.

## Bun runtime (embedded in every compiled artifact)

Source: Bun `LICENSE.md` at tag `bun-v1.4.2` (fetched from github.com/oven-sh/bun).

- Bun itself: MIT.
- **JavaScriptCore/WebKit: LGPL-2 (WebCore files LGPL-2), statically linked.** Bun's
  LICENSE.md quotes the LGPL obligation to provide the application in an object form that
  lets a user relink against a modified library. Every `bun build --compile` artifact
  carries this obligation. Any distribution decision for this stack must meet it.
- **tinycc: LGPL-2.1**, statically linked (it backs `bun:ffi` cc).
- Others are statically linked under permissive or dual licenses: BoringSSL (several),
  brotli (MIT), libarchive (several), lol-html (BSD-3), ls-hpack/ls-qpack/lsquic (MIT,
  partly BSD-3), mimalloc (MIT), picohttpparser (Perl or MIT), zstd (BSD or GPLv2,
  dual), simdutf (Apache-2.0), uSockets/uWebSockets fork (Apache-2.0), zlib-ng (zlib),
  c-ares (MIT), ICU 78 (ICU license), libbase64 (BSD-2), libuv on Windows (MIT),
  libdeflate (MIT), libjpeg-turbo (BSD-3/IJG/zlib), libspng (BSD-2), libwebp (BSD-3),
  highway (Apache-2.0), uucode (MIT), TigerBeetle IO excerpts (Apache-2.0), and LLVM
  libc++abi excerpt (Apache-2.0 with LLVM exception). Node polyfills (MIT) are also
  embedded.

## Not shipped, evaluated only

- `@number0/iroh@1.1.0`: MIT OR Apache-2.0 (napi-rs bindings from n0-computer/iroh-ffi).
  Probed in a scratch directory outside this prototype; not a dependency here.
- `license-checker-rseidelsohn@5.0.1`: BSD-3-Clause. Run through `bunx`; not in the lockfile.

## Summary for the G02 licensing gate

- No copyleft license appears in the npm dependency tree.
- The runtime embedding is the licensing cost. Every artifact statically links LGPL-2
  JavaScriptCore/WebCore and LGPL-2.1 tinycc, which brings LGPL relinking/notice
  obligations. Whether the release can meet them is an owner decision; nothing here
  was legally reviewed.
- Notices: a distributable needs the MIT/BSD/Apache notices of the npm packages, the
  OpenTUI native third-party notices (including the libwebp PATENTS file), and Bun's
  embedded-library notices. The prototype's `dist/` does not ship any notice file yet,
  which is a known gap.
