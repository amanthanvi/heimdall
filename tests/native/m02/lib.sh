# shellcheck shell=bash
# Local helpers for the M02 native harnesses (m02-plan U11, §4), sourced on the build host
# by run-linux.sh, run-windows.sh, run-macos.sh and run-wsl-distro.sh, and by
# tools/validation/native-harness-selftest.sh. Generalized from tests/native/m01/run-*.sh.
# Bash 3.2 compatible (macOS /bin/bash); no `set -e` assumptions.
#
# Conventions:
#   * Build output stays in the workspace ./target (AGENTS.md): no CARGO_TARGET_DIR, no
#     --target-dir. Shims and staging live in the caller's mktemp directory ($shim),
#     removed by the caller's EXIT trap.
#   * Nothing here prints a home path, user name or host name: saved logs go through
#     m02_redact first, and m02_leak_scan checks the result.
#   * Each line of commands.txt carries the real exit code of the command it names.

# m02_record FILE CMD RC: one "exit RC: CMD" line.
m02_record() { echo "exit $3: $2" >>"$1"; }

# m02_valid_alias NAME: 0 for an ssh host alias of [A-Za-z0-9._-] that does not start
# with '-' (so it is never read as an option).
m02_valid_alias() {
    case "$1" in
        '' | -* | *[!A-Za-z0-9._-]*) return 1 ;;
    esac
    return 0
}

# m02_random_hex BYTES: lowercase hex from /dev/urandom.
m02_random_hex() { od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'; }

# m02_write_shims DIR: the M01 zig cc/ar/dlltool shims for both cross targets.
m02_write_shims() {
    local d=$1
    cat >"$d/zigcc-linux.sh" <<'EOF'
#!/usr/bin/env bash
# zig cc for x86_64-unknown-linux-gnu, glibc 2.31 floor. Drops the triple cc-rs and
# rustc pass (zig has its own -target), keeps everything else.
args=()
for a in "$@"; do
  case "$a" in
    --target=*|-m64) ;;
    *) args+=("$a") ;;
  esac
done
exec zig cc -target x86_64-linux-gnu.2.31 "${args[@]}"
EOF
    cat >"$d/zigcc-win.sh" <<'EOF'
#!/usr/bin/env bash
# zig cc as the x86_64-pc-windows-gnu linker (same filtering idea as cargo-zigbuild).
# winapi 0.3 (crossterm, under the TUI) links its own import archives as
# -lwinapi_<dll>, which zig's -Bdynamic search refuses; zig's MinGW import library for
# the same system DLL is used instead. `synchronization` (WaitOnAddress and friends) has
# no import library of that name in zig's MinGW set: the Windows SDK's synchronization.lib
# imports from the API set DLL below, whose definition zig does ship.
args=()
for a in "$@"; do
  case "$a" in
    -lwinapi_synchronization) args+=("-lapi-ms-win-core-synch-l1-2-0") ;;
    -lwinapi_*) args+=("-l${a#-lwinapi_}") ;;
    -lgcc_eh) args+=("-lunwind") ;;
    -lgcc_s|-lgcc|-l:libpthread.a|-lwindows|-lmsvcrt|-Wl,--disable-auto-image-base|-fno-use-linker-plugin|-nodefaultlibs|-nostartfiles) ;;
    */self-contained/crt2.o|*/self-contained/dllcrt2.o|*rsbegin.o|*rsend.o) ;;
    *) args+=("$a") ;;
  esac
done
exec zig cc -target x86_64-windows-gnu "${args[@]}"
EOF
    cat >"$d/zigcc-win-cc.sh" <<'EOF'
#!/usr/bin/env bash
# zig cc as the C compiler for x86_64-pc-windows-gnu (bundled SQLite via cc-rs).
args=()
for a in "$@"; do
  case "$a" in
    --target=*|-m64|-mthreads) ;;
    *) args+=("$a") ;;
  esac
done
exec zig cc -target x86_64-windows-gnu "${args[@]}"
EOF
    printf '#!/usr/bin/env bash\nexec zig dlltool "$@"\n' >"$d/x86_64-w64-mingw32-dlltool"
    printf '#!/usr/bin/env bash\nexec zig ar "$@"\n' >"$d/zigar.sh"
    chmod +x "$d/zigcc-linux.sh" "$d/zigcc-win.sh" "$d/zigcc-win-cc.sh" \
        "$d/x86_64-w64-mingw32-dlltool" "$d/zigar.sh"
}

# m02_cargo_build TRIPLE SHIM BUILD_LOG: `cargo test [--target TRIPLE] --workspace
# --no-run --locked`, through the zig shims for a cross target. JSON messages go to
# SHIM/build.json, diagnostics to BUILD_LOG. Returns cargo's exit code. TRIPLE "host"
# builds for the build host.
m02_cargo_build() {
    local triple=$1 shim=$2 log=$3
    case "$triple" in
        host)
            cargo test --workspace --no-run --locked \
                --message-format=json-render-diagnostics >"$shim/build.json" 2>"$log" ;;
        x86_64-unknown-linux-gnu)
            CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="$shim/zigcc-linux.sh" \
            CC_x86_64_unknown_linux_gnu="$shim/zigcc-linux.sh" \
            AR_x86_64_unknown_linux_gnu="$shim/zigar.sh" \
                cargo test --target "$triple" --workspace --no-run --locked \
                --message-format=json-render-diagnostics >"$shim/build.json" 2>"$log" ;;
        x86_64-pc-windows-gnu)
            PATH="$shim:$PATH" CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER="$shim/zigcc-win.sh" \
            CC_x86_64_pc_windows_gnu="$shim/zigcc-win-cc.sh" AR_x86_64_pc_windows_gnu="$shim/zigar.sh" \
                cargo test --target "$triple" --workspace --no-run --locked \
                --message-format=json-render-diagnostics >"$shim/build.json" 2>"$log" ;;
        *) echo "unsupported triple" >&2; return 2 ;;
    esac
}

# m02_artifacts SHIM: from SHIM/build.json write SHIM/all.tsv (name<TAB>executable for
# every test executable; lib/bin unit tests are "<crate>-unit"), SHIM/cli.txt (the
# heimdall binary) and SHIM/hook.txt (hm-fixture-hook). Returns 1 when either binary
# is missing.
m02_artifacts() {
    local s=$1
    jq -r 'select(.reason == "compiler-artifact" and .profile.test == true and .executable != null)
           | [(if (.target.kind | index("test")) then .target.name else .target.name + "-unit" end), .executable] | @tsv' \
        "$s/build.json" | sort -u >"$s/all.tsv"
    jq -r 'select(.reason == "compiler-artifact" and .profile.test == false and .executable != null
                  and .target.name == "heimdall" and (.target.kind | index("bin"))) | .executable' \
        "$s/build.json" | sort -u | head -1 >"$s/cli.txt"
    jq -r 'select(.reason == "compiler-artifact" and .profile.test == false and .executable != null
                  and .target.name == "hm-fixture-hook" and (.target.kind | index("bin"))) | .executable' \
        "$s/build.json" | sort -u | head -1 >"$s/hook.txt"
    [ -s "$s/all.tsv" ] && [ -s "$s/cli.txt" ] && [ -f "$(cat "$s/cli.txt")" ] &&
        [ -s "$s/hook.txt" ] && [ -f "$(cat "$s/hook.txt")" ]
}

# m02_plan HERE PLATFORM SHIM OUT: the run plan for PLATFORM from the case index's
# build_host_paths: SHIM/run.tsv (the targets to copy and run), SHIM/skips.tsv
# (target<TAB>exact test name to --skip) and OUT/skipped.txt (every skip, its reason).
m02_plan() {
    local here=$1 platform=$2 s=$3 out=$4
    python3 -I "$here/m02-evidence.py" --skip-plan "$platform" \
        --case-index "$here/case-index.json" --targets "$s/all.tsv" \
        --run-out "$s/run.tsv" --skips-out "$s/skips.tsv" --report-out "$out/skipped.txt"
}

# m02_hashes SHIM OUT SUFFIX: the sha256 of every binary of the run, into OUT/build.txt.
m02_hashes() {
    local s=$1 out=$2 sfx=$3 name exe
    while IFS=$'\t' read -r name exe; do
        echo "$name$sfx sha256: $(shasum -a 256 "$exe" | cut -d' ' -f1)" >>"$out/build.txt"
    done <"$s/run.tsv"
    echo "heimdall$sfx (CLI for the e2e suites, HEIMDALL_E2E_BIN) sha256: $(shasum -a 256 "$(cat "$s/cli.txt")" | cut -d' ' -f1)" >>"$out/build.txt"
    echo "hm-fixture-hook$sfx (HM_FIXTURE_HOOK) sha256: $(shasum -a 256 "$(cat "$s/hook.txt")" | cut -d' ' -f1)" >>"$out/build.txt"
}

# m02_stage SHIM SUFFIX: SHIM/stage/ with a link <target><SUFFIX> to every binary of the
# run, heimdall<SUFFIX>, hm-fixture-hook<SUFFIX> and a copy of skips.tsv, for one
# `tar -h` stream (tar dereferences the links).
m02_stage() {
    local s=$1 sfx=$2 name exe
    rm -rf "$s/stage"
    mkdir "$s/stage" || return 1
    while IFS=$'\t' read -r name exe; do
        ln -s "$exe" "$s/stage/$name$sfx" || return 1
    done <"$s/run.tsv"
    ln -s "$(cat "$s/cli.txt")" "$s/stage/heimdall$sfx" &&
        ln -s "$(cat "$s/hook.txt")" "$s/stage/hm-fixture-hook$sfx" &&
        cp "$s/skips.tsv" "$s/stage/skips.tsv"
}

# m02_redact SRC DST [[--word] VALUE LABEL]...: replace every VALUE (and its
# doubled-backslash and forward-slash forms, and /mnt/<drive>/... for a Windows path) with
# LABEL, case-insensitively, longest first. A pair after `--word` (host names: ADR-0007
# §12.32 item 10) is replaced only as a whole word, never inside another word (a short host
# name inside "macOS" or a crate name stays); every other value is replaced wherever it
# occurs. Domain SIDs and non-loopback IPv4 addresses are masked too. Values shorter than
# two characters are ignored.
m02_redact() {
    python3 -I - "$@" <<'PY'
import re, sys
src, dst, rest = sys.argv[1], sys.argv[2], sys.argv[3:]
pairs = []
i = 0
while i < len(rest):
    word = rest[i] == "--word"
    if word:
        i += 1
    if i + 1 >= len(rest):
        sys.exit("m02_redact: VALUE without LABEL")
    pairs.append((rest[i], rest[i + 1], word))
    i += 2
text = open(src, encoding="utf-8", errors="replace").read()
forms = []
for value, label, word in pairs:
    if not value or len(value) < 2:
        continue
    for form in {value, value.replace("\\", "\\\\"), value.replace("\\", "/")}:
        forms.append((form, label, word))
    if len(value) > 2 and value[1] == ":" and value[0].isalpha():
        forms.append(("/mnt/" + value[0].lower() + value[2:].replace("\\", "/"), label, word))
for form, label, word in sorted(forms, key=lambda p: len(p[0]), reverse=True):
    pattern = re.escape(form)
    if word:
        pattern = r"(?<![A-Za-z0-9_])" + pattern + r"(?![A-Za-z0-9_])"
    text = re.sub(pattern, lambda m: label, text, flags=re.IGNORECASE)
text = re.sub(r"S-1-5-21(-\d+){2,4}", "S-1-5-21-<redacted>", text)
def addr(m):
    a = m.group(0)
    if a.startswith("127.") or a == "0.0.0.0":
        return a
    # A four-part version number is not an address: `wsl --version` prints
    # "WSL version: 2.6.1.0" (ADR-0007 §12.51 item 9).
    if re.search(r"(?i)\bversion:?\s*$", m.string[max(0, m.start() - 16):m.start()]):
        return a
    return "<addr>"
text = re.sub(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", addr, text)
open(dst, "w", encoding="utf-8").write(text)
PY
}

# m02_canary_scan OUT: count HEIMDALL_CANARY_ occurrences in every saved artifact under
# OUT (binary files too) and write OUT/canary-scan.txt. Prints the count.
m02_canary_scan() {
    local out=$1 hits
    hits=$(find "$out" -type f ! -name canary-scan.txt -exec grep -a -o 'HEIMDALL_CANARY_' {} + 2>/dev/null | wc -l | tr -d ' ')
    echo "canary-prefix occurrences in saved output: $hits" >"$out/canary-scan.txt"
    echo "$hits"
}

# m02_leak_scan OUT [[--word] VALUE]...: print the number of saved artifacts under OUT
# that still contain one of the VALUEs (home paths, user and host names of two characters
# or more), case-insensitively, never the value itself. A VALUE after `--word` counts only
# as a whole word, as m02_redact replaces it. Returns 0 only when that number is 0.
m02_leak_scan() {
    python3 -I - "$@" <<'PY'
import os, re, sys
out, rest = sys.argv[1], sys.argv[2:]
values = []
i = 0
while i < len(rest):
    word = rest[i] == "--word"
    if word:
        i += 1
    if i < len(rest):
        values.append((rest[i], word))
    i += 1
pats = []
for v, word in values:
    if len(v) < 2:
        continue
    p = re.escape(v.encode("utf-8", "surrogateescape"))
    if word:
        p = rb"(?<![A-Za-z0-9_])" + p + rb"(?![A-Za-z0-9_])"
    pats.append(re.compile(p, re.IGNORECASE))
n = 0
for dp, _, fns in os.walk(out):
    for f in fns:
        try:
            data = open(os.path.join(dp, f), "rb").read()
        except OSError:
            continue
        n += sum(1 for p in pats if p.search(data))
print(n)
sys.exit(0 if n == 0 else 1)
PY
}

# M02_REPO_DIRS: the repository directories the tests read through HM_REPO_ROOT (ADR-0007
# §12.32 item 3; heimdall_testkit::repo): the schemas and examples, the contract golden
# files, the decision records, the fixtures, and the crates (the sources the static scans
# read and the TUI snapshots). Every *.rs under tests/ goes too (the testkit's scan that no
# test reads the compile-time root), the evidence artifacts excepted. M03 wave 1 (native
# run): the model goldens (tests/model/golden: model_managed_domain's transition table and
# recovery paths) and the architecture plans that test reads (docs/architecture/m03-plan.md).
M02_REPO_DIRS="crates schemas docs/decisions docs/architecture tests/contracts tests/fixtures tests/model"

# m02_stage_repo ROOT DIR: DIR/repo, a tree of symbolic links to the regular files of
# M02_REPO_DIRS under ROOT and to every *.rs under ROOT/tests (never a `target`, `.git`,
# `node_modules` or `tests/evidence` directory, never a symbolic link), for one `tar -h`
# stream next to the binaries. Prints the number of files. The native harnesses set
# HM_REPO_ROOT to where it lands on the target.
m02_stage_repo() {
    # shellcheck disable=SC2086  # M02_REPO_DIRS is a fixed word list
    python3 -I - "$1" "$2" $M02_REPO_DIRS <<'PY'
import os, sys
root, dest, dirs = sys.argv[1], sys.argv[2], sys.argv[3:]
skip = {"target", ".git", "node_modules", "__pycache__"}
files = set()
def walk(rel, only_rs=False):
    base = os.path.join(root, rel)
    for dp, dns, fns in os.walk(base):
        dns[:] = sorted(d for d in dns if d not in skip
                        and os.path.relpath(os.path.join(dp, d), root) != os.path.join("tests", "evidence")
                        and not os.path.islink(os.path.join(dp, d)))
        for f in fns:
            p = os.path.join(dp, f)
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            if only_rs and not f.endswith(".rs"):
                continue
            files.add(os.path.relpath(p, root))
for d in dirs:
    walk(d)
walk("tests", only_rs=True)
if not files:
    sys.exit("m02_stage_repo: nothing to stage")
for rel in sorted(files):
    link = os.path.join(dest, "repo", rel)
    os.makedirs(os.path.dirname(link), exist_ok=True)
    os.symlink(os.path.join(root, rel), link)
print(len(files))
PY
}
