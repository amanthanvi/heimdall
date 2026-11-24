# shellcheck shell=bash
# Local helpers for the M02 native harnesses (m02-plan U11, §4), sourced on the build host
# by run-linux.sh, run-windows.sh, run-macos.sh and run-wsl-distro.sh, and by
# tools/validation/native-harness-selftest.sh. Generalized from tests/native/m01/run-*.sh.
# Bash 3.2 compatible (macOS /bin/bash); no `set -e` assumptions.
#
# Conventions:
#   * Build output stays in the workspace ./target (AGENTS.md): no CARGO_TARGET_DIR, no
#     --target-dir. Staging lives in the caller's mktemp directory ($shim), removed by the
#     caller's EXIT trap. ⟨M03 wave 6, ADR-0009 §2.7⟩ The zig shims live at one stable
#     path under ./target (m02_shim_dir), so the linker and CC values cargo and cc-rs see
#     never change between runs and the cross builds stay incremental; cross builds use
#     the lean `native-test` profile (Cargo.toml), so every binary fits a small host.
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

# m02_shim_dir REPO: the stable shim directory, REPO/target/hm-zig-shims, or
# HM_SHIM_DIR when set (the self-tests point it into their own temporary tree).
m02_shim_dir() { echo "${HM_SHIM_DIR:-$1/target/hm-zig-shims}"; }

# m02_install_file SRC DST MODE: move SRC to DST (mode MODE) only when DST is absent or
# differs, by an atomic rename, so a concurrent build that is executing DST never sees a
# partly written file; otherwise SRC is removed and DST (and its mtime) stays as it was.
m02_install_file() {
    if [ -f "$2" ] && cmp -s "$1" "$2"; then
        rm -f -- "$1"
    else
        chmod "$3" "$1" && mv -f -- "$1" "$2"
    fi
}

# m02_write_shims DIR: the M01 zig cc/ar/dlltool shims for both cross targets, written
# into DIR (created if absent; ⟨M03 wave 6⟩ normally m02_shim_dir, a stable path) only
# where a file is missing or differs. Sets M02_SHIMS=DIR for m02_cargo_build.
m02_write_shims() {
    local d=$1 t f
    mkdir -p -- "$d" || return 1
    t=$(mktemp -d "$d/.new.XXXXXX") || return 1
    m02_shim_contents "$t" || { rm -rf -- "$t"; return 1; }
    for f in zigcc-linux.sh zigcc-win.sh zigcc-win-cc.sh x86_64-w64-mingw32-dlltool zigar.sh; do
        m02_install_file "$t/$f" "$d/$f" 755 || { rm -rf -- "$t"; return 1; }
    done
    rmdir -- "$t"
    M02_SHIMS=$d
}

# m02_shim_contents DIR: write the shims into DIR (m02_write_shims installs them).
m02_shim_contents() {
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
}

# m02_cargo_build TRIPLE WORK BUILD_LOG: `cargo test [--target TRIPLE] --workspace
# --no-run --locked`, through the zig shims (M02_SHIMS, from m02_write_shims; WORK when
# unset) for a cross target. JSON messages go to WORK/build.json, diagnostics to
# BUILD_LOG. Returns cargo's exit code. TRIPLE "host" builds for the build host with the
# dev profile (check.sh's build). ⟨M03 wave 6, ADR-0009 §2.7⟩ A cross target builds with
# the profile HM_CARGO_PROFILE (default `native-test`: line tables only, Cargo.toml).
# ⟨M06 W5⟩ m02_cargo_build TRIPLE WORK BUILD_LOG JSON SELECT...: the same build with SELECT
# (cargo's package, feature and target selection) in place of `--workspace`, its JSON
# messages in WORK/JSON (m02_feature_build). Without them nothing changes.
m02_cargo_build() {
    local triple=$1 work=$2 log=$3 s=${M02_SHIMS:-$2} profile=${HM_CARGO_PROFILE:-native-test}
    local json=build.json sel
    sel=(--workspace)
    if [ $# -gt 4 ]; then
        json=$4
        shift 4
        sel=("$@")
    fi
    case "$profile" in '' | *[!a-z0-9-]*) echo "bad HM_CARGO_PROFILE" >&2; return 2 ;; esac
    case "$triple" in
        host)
            cargo test "${sel[@]}" --no-run --locked \
                --message-format=json-render-diagnostics >"$work/$json" 2>"$log" ;;
        x86_64-unknown-linux-gnu)
            CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="$s/zigcc-linux.sh" \
            CC_x86_64_unknown_linux_gnu="$s/zigcc-linux.sh" \
            AR_x86_64_unknown_linux_gnu="$s/zigar.sh" \
                cargo test --target "$triple" --profile "$profile" "${sel[@]}" --no-run --locked \
                --message-format=json-render-diagnostics >"$work/$json" 2>"$log" ;;
        x86_64-pc-windows-gnu)
            # ⟨M03 wave 6⟩ lld writes no COFF symbol table, so a Windows binary without debug
            # information has no Rust symbols, and platform-tests.py could not see which tests
            # it contains. The lean profile keeps limited debug information (function names)
            # for this target: line tables alone name none of the workspace's functions.
            local lt=()
            [ "$profile" = native-test ] && lt=(CARGO_PROFILE_NATIVE_TEST_DEBUG=limited)
            env ${lt[@]+"${lt[@]}"} \
            PATH="$s:$PATH" CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER="$s/zigcc-win.sh" \
            CC_x86_64_pc_windows_gnu="$s/zigcc-win-cc.sh" AR_x86_64_pc_windows_gnu="$s/zigar.sh" \
                cargo test --target "$triple" --profile "$profile" "${sel[@]}" --no-run --locked \
                --message-format=json-render-diagnostics >"$work/$json" 2>"$log" ;;
        *) echo "unsupported triple" >&2; return 2 ;;
    esac
}

# ⟨M06 W5⟩ m02_feature_targets FEATURE: "<package><TAB><target>" for every Cargo test target of
# the workspace whose required-features name FEATURE (m06-plan U7: the `iroh` targets, which
# the workspace build above never builds), sorted. Returns nonzero when the name or the
# metadata is unusable.
m02_feature_targets() {
    case "$1" in '' | *[!a-z0-9-]*) echo "bad feature name" >&2; return 2 ;; esac
    cargo metadata --locked --no-deps --format-version 1 |
        jq -r --arg f "$1" '.packages[] | .name as $p | .targets[]
            | select((.kind | index("test")) and ((.["required-features"] // []) | index($f)))
            | [$p, .name] | @tsv' | LC_ALL=C sort -u |
        awk -F'\t' '$1 !~ /^[A-Za-z0-9_-]+$/ || $2 !~ /^[A-Za-z0-9_-]+$/ { bad = 1 } { print } END { exit bad }'
}

# ⟨M06 W5⟩ m02_feature_build TRIPLE WORK BUILD_LOG FEATURE: after m02_cargo_build and
# m02_artifacts, build the test targets that require FEATURE, one `cargo test -p <package>
# --features FEATURE --test <target>... --no-run` per package (same triple, profile and shims).
#   * Cargo writes the `heimdall` binary of both builds to one path. So the default-feature
#     CLI is first copied to WORK/cli-default/ (WORK/cli.txt then names the copy: every other
#     target keeps running against the build it was written for), and the feature build's CLI
#     to WORK/cli-feature/ (WORK/feature-cli.txt; empty when no selected package builds it).
#   * WORK/feature.tsv: name<TAB>executable of the feature targets built, also merged into
#     WORK/all.tsv so the run plan, the hashes and the staging cover them. WORK/feature.json:
#     the builds' JSON messages (for platform-tests.py).
#   * WORK/feature-blocked.tsv: target<TAB>reason for every feature target that did not build
#     (cargo's real exit code and its first error line in the reason). A target that does not
#     build is never dropped silently: the harness writes each as a `feature-blocked-<target>`
#     host fact, which the evidence generator turns into a blocked row.
#   * ⟨M06 W5c⟩ M02_FEATURE_UNIT (comma-separated package names; the harnesses set it from
#     HM_FEATURE_UNIT) also builds each named package's own unit tests with FEATURE
#     (`cargo test -p <package> --features FEATURE --lib --no-run`): tests that exist only
#     under the feature (heimdall-transport-iroh's) run nowhere else. The executable replaces
#     the default-feature `<crate>-unit` row of WORK/all.tsv, so the one name holds the feature
#     build's tests on every platform. A package that does not build is blocked like any other
#     feature target, and its default-feature row is taken out of the plan: a build without
#     the feature never runs under a name recorded as blocked.
# M02_FEATURE_SKIP (comma-separated target names) leaves those targets out: only
# refresh-inventory.sh sets it, from HM_SKIP_TARGETS; a run harness never skips a target.
# The build log is appended to BUILD_LOG. Returns 0 when every target built, 6 when some are
# blocked, 2 when no target requires FEATURE or the selection is unusable.
# shellcheck disable=SC2013  # package and target names are [A-Za-z0-9_-] (m02_feature_targets)
m02_feature_build() {
    local triple=$1 work=$2 log=$3 feature=$4 pkg t rc first exe ext
    : >"$work/feature.tsv"
    : >"$work/feature-blocked.tsv"
    : >"$work/feature-cli.txt"
    : >"$work/feature.json"
    m02_feature_targets "$feature" >"$work/feature-targets.tsv" || { echo "the $feature-feature targets could not be listed" >&2; return 2; }
    if [ -n "${M02_FEATURE_SKIP:-}" ]; then
        # refresh-inventory.sh only (HM_SKIP_TARGETS: targets the commit does not contain yet).
        awk -F'\t' -v skip=",${M02_FEATURE_SKIP}," 'index(skip, "," $2 ",") == 0' "$work/feature-targets.tsv" >"$work/feature-targets.kept" &&
            mv -f -- "$work/feature-targets.kept" "$work/feature-targets.tsv"
    fi
    [ -s "$work/feature-targets.tsv" ] || { echo "no test target requires feature $feature" >&2; return 2; }
    if [ -s "$work/cli.txt" ]; then
        exe=$(cat "$work/cli.txt")
        rm -rf -- "$work/cli-default"
        mkdir "$work/cli-default" && cp -- "$exe" "$work/cli-default/$(basename "$exe")" || return 2
        echo "$work/cli-default/$(basename "$exe")" >"$work/cli.txt"
    fi
    for pkg in $(cut -f1 "$work/feature-targets.tsv" | LC_ALL=C sort -u); do
        set --
        for t in $(awk -F'\t' -v p="$pkg" '$1 == p { print $2 }' "$work/feature-targets.tsv"); do
            set -- "$@" --test "$t"
        done
        m02_cargo_build "$triple" "$work" "$work/feature-build.log" feature-build.json -p "$pkg" --features "$feature" "$@"
        rc=$?
        { echo "== cargo test -p $pkg --features $feature $* --no-run (exit $rc)"; cat "$work/feature-build.log"; } >>"$log"
        if [ "$rc" != 0 ]; then
            first=$(grep -m1 -E '^error' "$work/feature-build.log" | tr '\t\r' '  ' | cut -c1-240)
            for t in $(awk -F'\t' -v p="$pkg" '$1 == p { print $2 }' "$work/feature-targets.tsv"); do
                printf '%s\tthe %s-feature build of %s failed (cargo exit %s): %s\n' "$t" "$feature" "$pkg" "$rc" \
                    "${first:-no error line in the build log}" >>"$work/feature-blocked.tsv"
            done
            continue
        fi
        cat "$work/feature-build.json" >>"$work/feature.json"
        jq -r 'select(.reason == "compiler-artifact" and .profile.test == true and .executable != null
                      and (.target.kind | index("test"))) | [.target.name, .executable] | @tsv' \
            "$work/feature-build.json" | LC_ALL=C sort -u >>"$work/feature.tsv"
        exe=$(jq -r 'select(.reason == "compiler-artifact" and .profile.test == false and .executable != null
                      and .target.name == "heimdall" and (.target.kind | index("bin"))) | .executable' \
            "$work/feature-build.json" | LC_ALL=C sort -u | head -1)
        if [ -n "$exe" ] && [ -f "$exe" ]; then
            ext=""
            case "$exe" in *.exe) ext=.exe ;; esac
            rm -rf -- "$work/cli-feature"
            mkdir "$work/cli-feature" && cp -- "$exe" "$work/cli-feature/heimdall$ext" || return 2
            echo "$work/cli-feature/heimdall$ext" >"$work/feature-cli.txt"
        fi
    done
    # A target cargo reported no executable for is blocked too, never assumed built.
    while IFS=$'\t' read -r pkg t; do
        cut -f1 "$work/feature.tsv" "$work/feature-blocked.tsv" | grep -qxF -- "$t" ||
            printf '%s\tthe %s-feature build of %s produced no test executable for it\n' "$t" "$feature" "$pkg" >>"$work/feature-blocked.tsv"
    done <"$work/feature-targets.tsv"
    # ⟨M06 W5c⟩ The named packages' own unit tests, built with the feature.
    : >"$work/feature-unit.tsv"
    : >"$work/feature-unit-names.txt"
    case "${M02_FEATURE_UNIT:-}" in *[!a-z0-9,-]*) echo "bad feature unit package list" >&2; return 2 ;; esac
    for pkg in $(printf '%s' "${M02_FEATURE_UNIT:-}" | tr ',' ' '); do
        t="$(printf '%s' "$pkg" | tr '-' '_')-unit"
        echo "$t" >>"$work/feature-unit-names.txt"
        m02_cargo_build "$triple" "$work" "$work/feature-build.log" feature-build.json -p "$pkg" --features "$feature" --lib
        rc=$?
        { echo "== cargo test -p $pkg --features $feature --lib --no-run (exit $rc)"; cat "$work/feature-build.log"; } >>"$log"
        if [ "$rc" != 0 ]; then
            first=$(grep -m1 -E '^error' "$work/feature-build.log" | tr '\t\r' '  ' | cut -c1-240)
            printf '%s\tthe %s-feature build of %s failed (cargo exit %s): %s\n' "$t" "$feature" "$pkg" "$rc" \
                "${first:-no error line in the build log}" >>"$work/feature-blocked.tsv"
            continue
        fi
        exe=$(jq -r --arg n "${t%-unit}" 'select(.reason == "compiler-artifact" and .profile.test == true and .executable != null
                      and .target.name == $n and (.target.kind | index("lib"))) | .executable' \
            "$work/feature-build.json" | LC_ALL=C sort -u | head -1)
        if [ -z "$exe" ]; then
            printf '%s\tthe %s-feature build of %s produced no test executable for it\n' "$t" "$feature" "$pkg" >>"$work/feature-blocked.tsv"
            continue
        fi
        cat "$work/feature-build.json" >>"$work/feature.json"
        printf '%s\t%s\n' "$t" "$exe" >>"$work/feature-unit.tsv"
    done
    cat "$work/feature-unit.tsv" >>"$work/feature.tsv"
    touch "$work/all.tsv"
    # The unit rows named above leave the plan input first (the default-feature build's), then
    # the feature build's rows come in: a blocked one is therefore in neither.
    awk -F'\t' 'FILENAME == ARGV[1] { drop[$1] = 1; next } !($1 in drop)' "$work/feature-unit-names.txt" "$work/all.tsv" |
        cat - "$work/feature.tsv" | LC_ALL=C sort -u >"$work/all.tsv.new" && mv -f -- "$work/all.tsv.new" "$work/all.tsv"
    [ ! -s "$work/feature-blocked.tsv" ] || return 6
    return 0
}

# ⟨M06 W5⟩ m02_feature_facts WORK FEATURE: the host facts of a feature build (key=value lines,
# for host.txt): what was built, which CLI the feature targets run against, and one
# `feature-blocked-<target>=<reason>` per target that did not build.
m02_feature_facts() {
    local work=$1 feature=$2 t reason
    echo "feature-targets=$feature: $(cut -f1 "$work/feature.tsv" | tr '\n' ' ' | sed 's/ $//')"
    if [ -s "$work/feature-cli.txt" ]; then
        echo "feature-cli=the $feature-feature heimdall (HEIMDALL_E2E_BIN for those targets only)"
    else
        echo "feature-cli=none built (no selected package builds the heimdall binary)"
    fi
    while IFS=$'\t' read -r t reason; do
        echo "feature-blocked-$t=$reason"
    done <"$work/feature-blocked.tsv"
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
# HERE holds case-index.json and the generator M02_EVIDENCE (default m02-evidence.py;
# ⟨M03 wave 6⟩ tests/native/m03 sets m03-evidence.py).
m02_plan() {
    local here=$1 platform=$2 s=$3 out=$4
    python3 -I "$here/${M02_EVIDENCE:-m02-evidence.py}" --skip-plan "$platform" \
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
# ⟨M03 wave 6, W6-R06⟩ A contaminated artifact never keeps the secret: each canary value
# (the prefix and the token after it) is masked in place, as `<canary-value-masked>`,
# before the harness exits, so a failed run keeps only its nonsecret failure record. Masked
# markers count too, so a second scan reports the same number.
m02_canary_scan() {
    python3 -I - "$1" <<'PY2'
import os, re, sys
out = sys.argv[1]
value = re.compile(rb"HEIMDALL_CANARY_[A-Za-z0-9_]*")
mask = b"<canary-value-masked>"
hits = 0
for dp, _, fns in os.walk(out):
    for f in fns:
        if f == "canary-scan.txt":
            continue
        p = os.path.join(dp, f)
        if os.path.islink(p) or not os.path.isfile(p):
            continue
        try:
            data = open(p, "rb").read()
        except OSError:
            continue
        found = data.count(b"HEIMDALL_CANARY_")
        hits += found + data.count(mask)
        if found:
            with open(p, "wb") as w:
                w.write(value.sub(mask, data))
with open(os.path.join(out, "canary-scan.txt"), "w", encoding="utf-8") as w:
    w.write("canary-prefix occurrences in saved output: %d%s\n"
            % (hits, " (values masked in place before the artifact was kept)" if hits else ""))
print(hits)
PY2
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
