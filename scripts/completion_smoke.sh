#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/heimdall-completion-smoke.XXXXXX")"
bin_dir="${work_dir}/bin"
completion_dir="${work_dir}/completions"

cleanup() {
	rm -rf "${work_dir}"
}
trap cleanup EXIT

mkdir -p "${bin_dir}" "${completion_dir}"

for shell_name in bash zsh fish; do
	if ! command -v "${shell_name}" >/dev/null 2>&1; then
		echo "missing required shell: ${shell_name}" >&2
		exit 1
	fi
done

echo "building nofido2 completion smoke binary"
(
	cd "${repo_root}"
	CGO_ENABLED=0 go build -tags nofido2 -trimpath -o "${bin_dir}/heimdall" ./cmd/heimdall
)

"${bin_dir}/heimdall" completion bash > "${completion_dir}/heimdall.bash"
"${bin_dir}/heimdall" completion zsh > "${completion_dir}/_heimdall"
"${bin_dir}/heimdall" completion fish > "${completion_dir}/heimdall.fish"

echo "bash completion smoke"
PATH="${bin_dir}:${PATH}" bash -lc '
set -euo pipefail
source "$1"
__heimdall_compopt -o nospace
COMP_WORDS=(heimdall connect prod --known-hosts-policy a)
COMP_CWORD=4
COMP_LINE="heimdall connect prod --known-hosts-policy a"
COMP_POINT=${#COMP_LINE}
__start_heimdall
printf "%s\n" "${COMPREPLY[@]}"
' bash "${completion_dir}/heimdall.bash" | grep -qx 'accept-new'

echo "zsh completion smoke"
PATH="${bin_dir}:${PATH}" zsh -fc '
set -euo pipefail
compdef() { :; }
source "$1"
whence -w _heimdall | grep -q "function"
' zsh "${completion_dir}/_heimdall"

echo "fish completion smoke"
PATH="${bin_dir}:${PATH}" fish -c '
source $argv[1]
complete -C "heimdall connect prod --known-hosts-policy a"
' "${completion_dir}/heimdall.fish" | grep -qx 'accept-new'

echo "completion smoke ok"
