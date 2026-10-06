#!/bin/sh
# Collect public GitHub metadata for a list of repos. Writes TSV to stdout.
# Usage: repo_meta.sh <outdir> owner/repo ...
out="$1"; shift
mkdir -p "$out"
printf 'repo\tarchived\tpushed_at\tstars\tlicense\tlatest_release\trelease_date\tcontributors_approx\tcommits_52w\tdefault_branch_last_commit\n'
for r in "$@"; do
  f="$out/$(echo "$r" | tr '/' '_')"
  gh api "repos/$r" > "$f.repo.json" 2>/dev/null; e1=$?
  if [ $e1 -ne 0 ]; then printf '%s\tAPI_ERROR(exit %s)\n' "$r" "$e1"; continue; fi
  arch=$(jq -r .archived "$f.repo.json"); pushed=$(jq -r .pushed_at "$f.repo.json")
  stars=$(jq -r .stargazers_count "$f.repo.json"); lic=$(jq -r '.license.spdx_id // "none"' "$f.repo.json")
  br=$(jq -r .default_branch "$f.repo.json")
  gh api "repos/$r/releases/latest" > "$f.rel.json" 2>/dev/null
  if [ $? -eq 0 ]; then rel=$(jq -r .tag_name "$f.rel.json"); reld=$(jq -r .published_at "$f.rel.json"); else rel="none"; reld="-"; fi
  # contributors: count via Link header last page with per_page=1 (anon=1 includes anonymous)
  last=$(gh api -i "repos/$r/contributors?per_page=1&anon=1" 2>/dev/null | grep -i '^link:' | sed -n 's/.*[?&]page=\([0-9]*\)>; rel="last".*/\1/p')
  [ -z "$last" ] && last="(<=1 page or error)"
  # weekly commit counts for last 52 weeks (stats may need a retry)
  c52="-"
  for i in 1 2 3 4; do
    gh api "repos/$r/stats/participation" > "$f.part.json" 2>/dev/null
    if jq -e '.all|length>0' "$f.part.json" >/dev/null 2>&1; then c52=$(jq '[.all[]]|add' "$f.part.json"); break; fi
    sleep 3
  done
  lc=$(gh api "repos/$r/commits/$br" --jq .commit.committer.date 2>/dev/null)
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$r" "$arch" "$pushed" "$stars" "$lic" "$rel" "$reld" "$last" "$c52" "$lc"
done
