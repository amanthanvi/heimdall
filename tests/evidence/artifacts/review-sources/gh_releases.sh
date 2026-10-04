#!/bin/bash
# read-only gh api GET
for r in charmbracelet/bubbletea ratatui/ratatui crossterm-rs/crossterm anomalyco/opentui n0-computer/iroh n0-computer/iroh-ffi n0-computer/pigeons PowerShell/Win32-OpenSSH smallstep/certificates smallstep/cli; do
  echo "== $r"
  gh api "repos/$r" --jq '[.default_branch,(.license.spdx_id//"null"),.pushed_at]|@tsv'
  gh api "repos/$r/releases/latest" --jq '[.tag_name,.published_at,.prerelease]|@tsv' 2>&1 | head -2
done
echo "== Win32 releases first 5"; gh api "repos/PowerShell/Win32-OpenSSH/releases?per_page=5" --jq '.[]|[.tag_name,.published_at,.prerelease]|@tsv'
echo "== Win32 LICENSE"; gh api repos/PowerShell/Win32-OpenSSH/contents/LICENSE 2>&1 | head -c 200; echo; gh api repos/PowerShell/Win32-OpenSSH/contents --jq '.[].name' | tr '\n' ' '
