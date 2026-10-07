#!/usr/bin/env bash
#
# churn.sh — rank freshly-churned directories and files in a git repo.
#
# critlover stage 1 (scope & scout). READ-ONLY recon: runs `git log` over a
# recent window and tallies activity. No network, no fetch, no writes, no
# checkout changes. Churn is a proxy for the *least-swept* surface — code
# merged in the last few months has had the fewest eyes, which is exactly
# where un-deduped crits tend to hide (STRATEGY §3a, §3c). Hunt the top of
# the list first; cross it with the incomplete-fix and pre-auth veins.
#
# Usage:
#   churn.sh [repo] [days]
#   churn.sh [--days N] [repo]
#
#   repo     Path to a git working tree (default: current directory).
#   days     Look-back window in days (default: 90). Also accepted as --days N.
#
# Env:
#   DEPTH    Collapse directories to their first N path components
#            (e.g. DEPTH=2 => "src/net"). Default 0 = the full directory of
#            each changed file (most actionable for a surface map).
#   TOP      Max rows to print per section (default: 25).
#   REF      Git revision range / ref to walk (default: current HEAD).
#
# Output: (1) directories ranked by the number of commits that touched them
# in the window; (2) individual files ranked the same way. Feed the result
# into templates/PROGRESS.md.
#
# This is plumbing with no judgment — it only surfaces *where the activity
# is*. Deciding what is reachable and in-scope happens at stage 4, by hand.
#
set -eu

prog=${0##*/}

usage() {
  cat <<EOF
$prog — rank freshly-churned directories and files in a git repo (critlover stage 1).

READ-ONLY: walks 'git log' over a recent window; no network, no writes, no checkout change.
Churn marks the least-swept surface (STRATEGY §3a/§3c) — hunt the top of the list first.

Usage:
  $prog [repo] [days]
  $prog [--days N] [repo]

  repo   git work tree to analyze   (default: current directory)
  days   look-back window in days   (default: 90; also --days N)

Env:
  DEPTH  collapse dirs to first N path components (0 = full dir of each file; default 0)
  TOP    max rows per section       (default: 25)
  REF    revision/ref to walk       (default: HEAD)

Output: (1) directories by number of commits that touched them in the window;
        (2) individual files, same ranking. Feed into templates/PROGRESS.md.
EOF
}

die() { printf '%s: %s\n' "$prog" "$1" >&2; exit "${2:-2}"; }

# clip: keep the top $top rows, or ALL rows when TOP<=0 (0 = unlimited, like authz MAX=0)
clip() { if [ "${top:-0}" -gt 0 ]; then head -n "$top"; else cat; fi; }

# --- arg parse (supports both positional days and --days N) ---------------
repo=""
days=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)   usage; exit 0 ;;
    -d|--days)   shift; [ $# -gt 0 ] || die "--days needs a value"; days=$1; shift ;;
    --days=*)    days=${1#*=}; shift ;;
    --)          shift; break ;;
    -*)          die "unknown option: $1" ;;
    *)           break ;;
  esac
done
[ $# -gt 0 ] && { repo=$1; shift; }
[ $# -gt 0 ] && [ -z "$days" ] && { days=$1; shift; }
[ $# -gt 0 ] && die "unexpected extra argument: $1"

repo=${repo:-.}
days=${days:-90}
top=${TOP:-25}
depth=${DEPTH:-0}
ref=${REF:-HEAD}

# --- validate -------------------------------------------------------------
case "$days"  in ''|*[!0-9]*) die "days must be a non-negative integer (got: $days)" ;; esac
case "$top"   in ''|*[!0-9]*) die "TOP must be a non-negative integer (got: $top)" ;; esac
case "$depth" in ''|*[!0-9]*) die "DEPTH must be a non-negative integer (got: $depth)" ;; esac
[ -d "$repo" ] || die "not a directory: $repo"
git -C "$repo" rev-parse --is-inside-work-tree >/dev/null 2>&1 \
  || die "not a git work tree: $repo"

since="${days} days ago"
head_sha=$(git -C "$repo" rev-parse --short "$ref" 2>/dev/null || echo '?')

printf '# churn — %s\n' "$repo"
printf '#   window: last %s days (--since "%s")   ref: %s (%s)\n' "$days" "$since" "$ref" "$head_sha"
printf '#   depth: %s   top: %s   (read-only; HEAD unchanged)\n' \
  "$([ "$depth" -eq 0 ] && echo 'full dir' || echo "$depth comp")" "$top"

# --- 1. directories by commit count --------------------------------------
# One commit that touches N files in a dir counts once for that dir (dedup
# within the commit), so the number is "commits that touched this dir".
printf '\n== directories by commit count (last %s days) ==\n' "$days"
dirs=$(
  git -C "$repo" -c core.quotePath=false log "$ref" --since="$since" \
      --no-merges --name-only --pretty=format:'#%H' 2>/dev/null \
  | awk -v depth="$depth" '
      function flush(   d) { for (d in seen) counts[d]++; split("", seen) }
      /^#[0-9a-fA-F]+$/ { flush(); next }
      NF == 0 { next }
      {
        p = $0
        if (p ~ /\//) { dir = p; sub(/\/[^/]*$/, "", dir) } else { dir = "." }
        if (depth + 0 > 0 && dir != ".") {
          m = split(dir, c, "/"); dir = c[1]
          for (i = 2; i <= depth && i <= m; i++) dir = dir "/" c[i]
        }
        seen[dir] = 1
      }
      END { flush(); for (d in counts) printf "%7d  %s\n", counts[d], d }
    ' \
  | sort -rn | clip
)
if [ -n "$dirs" ]; then printf '%s\n' "$dirs"; else printf '   (no file-changing commits in window)\n'; fi

# --- 2. top changed files -------------------------------------------------
printf '\n== top changed files (by commit count, last %s days) ==\n' "$days"
files=$(
  git -C "$repo" -c core.quotePath=false log "$ref" --since="$since" \
      --no-merges --name-only --pretty=format: 2>/dev/null \
  | sed '/^[[:space:]]*$/d' \
  | sort | uniq -c | sort -rn | clip
)
if [ -n "$files" ]; then printf '%s\n' "$files"; else printf '   (no file-changing commits in window)\n'; fi

printf '\n# next: record the freshest surface in templates/PROGRESS.md, then bias\n'
printf '#       stage-2 buckets toward it. Churn != reachability — verify by hand.\n'
