#!/bin/bash
# read-only gh api GET checks
while read -r id repo path; do
  echo "== $id $repo $path"
  gh api "repos/$repo/contents/$path" --jq '.sha'
  gh api "repos/$repo/commits?path=$path&per_page=2" --jq '.[]|[.sha,.commit.committer.date]|@tsv'
  gh api "repos/$repo/commits?per_page=1" --jq '.[0]|[.sha,.commit.committer.date]|@tsv'
done <<'L'
S16 pingdotgg/t3code docs/internals/remote.md
S18 pingdotgg/t3code docs/internals/t3-connect.md
S34 pingdotgg/t3code docs/internals/environment-auth.md
S19 n0-computer/pigeons README.md
S27 charmbracelet/bubbletea README.md
S29 anomalyco/opentui README.md
L
