#!/usr/bin/env bash
#
# patch-variant.sh — read a fix commit, then hunt the siblings it missed.
#
# critlover stage 1 (incomplete-fix / variant analysis) — the single highest-EV
# source-review move (STRATEGY §3c; dup-check-notes.md §5). READ-ONLY on a LOCAL
# git checkout: it shows a fix commit's stat + diff, lists the files it touched
# (flagging the regression tests among them — the test reveals exactly which path
# the maintainer considered closed, and by omission which they did NOT), extracts
# the changed symbol names best-effort, then greps that same sink shape across the
# SIBLING files the fix did NOT touch. The unpatched sibling is the finding.
#
# No network, no writes, HEAD unchanged. The diff-rendering `git show` calls use
# --no-textconv so a malicious repo-local diff driver (diff.<drv>.textconv in an
# attacker-supplied .git/config) cannot execute when you point this at an untrusted
# checkout. A patch usually closes ONE call path, not
# the root cause's siblings — so the other caller of the same sink, the adjacent
# function with the identical bounds mistake, or the fix applied to sync but not
# async / read but not write, is a NEW finding (incomplete fix of the CVE).
#
# Usage:
#   patch-variant.sh <repo> <commit-ish> [sink-regex]
#
#   repo         path to a LOCAL git work tree of the in-scope target     (required)
#   commit-ish   the fix commit (sha / tag / ref) — the patched CVE's fix (required)
#   sink-regex   an ERE for the sink shape to hunt in siblings. Omit to use the
#                symbols extracted from the diff (best-effort; refine with your own).
#
# Env:
#   CONTEXT=N     diff context lines for 'git show -U'           (default: 3)
#   MAX_SYMS=N    cap auto-extracted symbols fed to the hunt     (default: 40)
#   NO_IGNORE=1   also scan .gitignored / vendored paths (rg backend only)  (default: respect)
#
set -eu

prog=${0##*/}
die() { printf '%s: %s\n' "$prog" "$1" >&2; exit "${2:-2}"; }

usage() {
  cat <<EOF
$prog — read a fix commit, then hunt the siblings it missed (critlover stage 1, §3c).

READ-ONLY on a LOCAL git checkout: shows the fix's stat + diff, lists touched files (+ the
regression tests among them), extracts changed symbols, then greps that sink shape across the
SIBLING files the fix did NOT touch. No network, no writes, HEAD unchanged.

Usage:
  $prog <repo> <commit-ish> [sink-regex]

  repo         local git work tree of the in-scope target            (required)
  commit-ish   the fix commit (sha / tag / ref)                      (required)
  sink-regex   ERE for the sink shape to hunt   (omit => use symbols from the diff)

Env:
  CONTEXT=N    diff context lines for git show -U                    (default: 3)
  MAX_SYMS=N   cap auto-extracted symbols fed to the hunt            (default: 40)
  NO_IGNORE=1  also scan .gitignored / vendored paths (rg only)      (default: respect)
EOF
}

# --- -h/--help ------------------------------------------------------------
for a in "$@"; do case "$a" in -h|--help) usage; exit 0 ;; esac; done

# --- arg parse ------------------------------------------------------------
[ $# -ge 2 ] || { usage; exit 2; }
repo=$1; commitish=$2; shift 2
sink_re=${1:-}
[ $# -gt 1 ] && die "unexpected extra argument: $2 (sink-regex must be ONE quoted ERE)"

context=${CONTEXT:-3}
max_syms=${MAX_SYMS:-40}
case "$context"  in ''|*[!0-9]*) die "CONTEXT must be a non-negative integer (got: $context)" ;; esac
case "$max_syms" in ''|*[!0-9]*) die "MAX_SYMS must be a non-negative integer (got: $max_syms)" ;; esac

# --- validate the checkout ------------------------------------------------
command -v git >/dev/null 2>&1 || die "git not found on PATH"
[ -d "$repo" ] || die "not a directory: $repo"
git -C "$repo" rev-parse --is-inside-work-tree >/dev/null 2>&1 \
  || die "not a git work tree: $repo"
if ! sha=$(git -C "$repo" rev-parse --verify --quiet "${commitish}^{commit}" 2>/dev/null); then
  die "cannot resolve commit-ish in $repo: $commitish"
fi
short=$(git -C "$repo" rev-parse --short "$sha" 2>/dev/null || echo '?')
repo_norm=${repo%/}; [ -n "$repo_norm" ] || repo_norm="/"

# --- backend: ripgrep preferred, git grep fallback ------------------------
have_rg=0
if command -v rg >/dev/null 2>&1; then have_rg=1; fi

# scratch for the touched-file list (never written into the repo)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/patch-variant.XXXXXX") || die "mktemp -d failed"
trap 'rm -rf "$tmp"' EXIT INT TERM
touched="$tmp/touched.lst"

printf '# patch-variant — %s @ %s   backend: %s   (read-only; STRATEGY §3c / dup-check-notes.md §5)\n' \
  "$repo" "$short" "$([ "$have_rg" -eq 1 ] && echo ripgrep || echo 'git grep')"

# --- 1. the fix commit: header + stat + diff ------------------------------
printf '\n== fix commit ==\n'
git -C "$repo" show -s \
  --format='   commit %H%n   author %an <%ae>%n   date   %ad%n   title  %s' "$sha" 2>/dev/null || true

printf '\n== files touched (stat) ==\n'
git -C "$repo" show --stat --format= "$sha" 2>/dev/null | sed '/^[[:space:]]*$/d' || true

printf '\n== fix diff (git show -U%s) ==\n' "$context"
git -C "$repo" show --no-textconv --format= "-U${context}" "$sha" 2>/dev/null || true

# --- 2. touched files + regression tests among them -----------------------
git -C "$repo" show --name-only --format= "$sha" 2>/dev/null | sed '/^[[:space:]]*$/d' | sort -u > "$touched" || true

printf '\n== files the fix touched (EXCLUDED from the sibling hunt below) ==\n'
if [ -s "$touched" ]; then sed 's/^/   /' "$touched"; else
  printf '   (no files — a merge commit or empty diff? pick the real fix commit)\n'
fi

printf '\n== regression tests among them (READ THESE — they mark the path considered closed) ==\n'
tests=$(grep -Ei '(^|/)(tests?|testing|spec|__tests__)(/|$)|(_test|_spec|\.test|\.spec)\.|(^|/)test_[^/]*\.|(^|/)conftest\.py$' "$touched" 2>/dev/null || true)
if [ -n "$tests" ]; then printf '%s\n' "$tests" | sed 's/^/   /'; else
  printf '   (none — the fix shipped without a visible regression test; the closed path is less certain)\n'
fi

# --- 3. changed symbols (best-effort, from the diff) ----------------------
printf '\n== changed symbols (best-effort, from the diff) ==\n'
symbols=$(
  git -C "$repo" show --no-textconv --format= -U0 "$sha" 2>/dev/null \
    | grep -E '^[+-]' \
    | grep -Ev '^(\+\+\+|---)' \
    | grep -Eo '((def|function|func|fn|class|struct|interface|sub|method)[[:space:]]+[A-Za-z_][A-Za-z0-9_]*|[A-Za-z_][A-Za-z0-9_]{2,}[[:space:]]*\()' \
    | sed -E 's/^(def|function|func|fn|class|struct|interface|sub|method)[[:space:]]+//; s/[[:space:]]*\(.*$//' \
    | grep -Eiv '^(if|for|while|switch|return|sizeof|catch|with|elif|else|and|or|not|in|is|new|do|case|typeof|await|async|yield|print|println|printf|fprintf|sprintf|assert|range|len|int|str|list|dict|set|self|super|this|null|true|false)$' \
    | sort -u | head -n "$max_syms" || true
)
if [ -n "$symbols" ]; then printf '%s\n' "$symbols" | sed 's/^/   /'; else
  printf '   (none extracted — pass an explicit [sink-regex])\n'
fi

# --- 4. the sibling hunt: same shape, files the fix did NOT touch ---------
# choose the pattern: an explicit sink-regex wins; else the extracted symbols.
pat=""; pat_src=""
if [ -n "$sink_re" ]; then
  pat=$sink_re; pat_src="sink-regex (yours)"
elif [ -n "$symbols" ]; then
  joined=$(printf '%s\n' "$symbols" | tr '\n' '|' | sed 's/|$//')
  pat='(^|[^[:alnum:]_])('"$joined"')([^[:alnum:]_]|$)'
  pat_src="auto symbols (word-bounded)"
fi

sibling_scan() {  # sibling_scan PATTERN -> repo-relative file:line:text
  _p=$1
  if [ "$have_rg" -eq 1 ]; then
    _args="--no-heading --line-number --with-filename --color=never"
    [ "${NO_IGNORE:-0}" = "1" ] && _args="$_args --no-ignore"
    # shellcheck disable=SC2086
    rg $_args -e "$_p" -- "$repo" 2>/dev/null \
      | awk -v p="$repo_norm/" 'index($0,p)==1{$0=substr($0,length(p)+1)} 1' || true
  else
    git -C "$repo" grep -nI -E -e "$_p" 2>/dev/null || true
  fi
}

printf '\n== unpatched siblings (same shape, in files the fix did NOT touch) ==\n'
if [ -z "$pat" ]; then
  printf '   (skipped: no sink-regex and no symbols extracted — re-run with an explicit [sink-regex])\n'
else
  printf '   shape : %s\n' "$pat"
  printf '   source: %s\n' "$pat_src"
  raw=$(sibling_scan "$pat")
  # drop any hit whose file is one the fix already touched (field 1, split on ':')
  sib=$(printf '%s\n' "$raw" | awk -F: -v tf="$touched" '
    BEGIN { while ((getline l < tf) > 0) t[l]=1 }
    NF && !($1 in t) { print }
  ' 2>/dev/null || true)
  if [ -n "$sib" ]; then
    n=$(printf '%s\n' "$sib" | wc -l | tr -d ' ')
    printf '   hits  : %s (outside the touched files)\n' "$n"
    printf '%s\n' "$sib"
  else
    printf '   (no sibling matches outside the touched files — loosen/retarget the sink-regex,\n'
    printf '    or the fix may actually be complete for this shape)\n'
  fi
fi

printf '\n# read it as: a hit in a file the fix did NOT touch is the lead — open it and confirm\n'
printf '#   the SAME root cause is reachable there from an in-scope actor (Gate A).\n'
printf '# a sibling the fix missed is a NEW finding (cite the CVE), not a dup — but still\n'
printf '#   dup-check the variant itself (dup-check-notes.md §5).\n'
printf '# next: dup-scan.sh <owner/repo> <sibling-symbol> (Gate B), then re-score vs the rubric.\n'
