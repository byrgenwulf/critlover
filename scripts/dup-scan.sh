#!/usr/bin/env bash
#
# dup-scan.sh — enumerate prior disclosures for the Gate-B dup-check.
#
# critlover stage 4, Gate B (dup-check). READ-ONLY recon: pulls the target's
# PUBLIC disclosure records — published security advisories, open + merged/closed
# PRs, and open + closed issues — into a small local TSV cache, then (optionally)
# greps that cache for your candidate's strongest tokens. It ENUMERATES; it does
# NOT decide dup-ness. Mechanizes dup-check-notes.md §2-§3; the judgment in §1
# (same root cause vs. sibling vs. novel) stays yours. No exploitation, no probing
# a live system, no contacting maintainers — only reads of public GitHub records.
#
# Needs `gh` (GitHub CLI; preconfigured in this harness). If `gh` is absent this
# prints the equivalent read-only commands for you to run by hand and exits 0 —
# it never fails just because the CLI is missing.
#
# Usage:
#   dup-scan.sh <owner/repo> [keyword ...]
#
#   owner/repo   the in-scope target slug, e.g. huggingface/transformers   (required)
#   keyword ...  tokens to match against the cache — your candidate's SYMBOL, its
#                CWE/class word (deserialization, ssrf, path traversal, oob,
#                use-after-free), and its subsystem. Omit to just build the cache.
#
# Env:
#   OUT=<dir>    write the TSV cache here (created if needed; default: a mktemp -d).
#                NEVER point this inside the repo under review.
#   LIMIT=N      max PRs / issues to pull per list                  (default: 300)
#
# Cache files: $OUT/advisories.tsv   (ghsa_id  cve_id  summary)
#              $OUT/known.tsv        (PR|ISS   number  state  title)
#
# This covers the repo-level rows of §2-§3. The global Advisory DB / OSV (§2a),
# silent-fix commits (§2d) and release notes (§2e) need a package name/ecosystem
# or a local checkout — run those by hand; they still have to pass.
#
set -eu

prog=${0##*/}
die() { printf '%s: %s\n' "$prog" "$1" >&2; exit "${2:-2}"; }

usage() {
  cat <<EOF
$prog — enumerate prior disclosures for the Gate-B dup-check (critlover stage 4).

READ-ONLY: reads PUBLIC GitHub records (advisories, PRs, issues) into a TSV cache, then
greps it for your candidate's tokens. It enumerates; YOU decide same-root-cause vs. sibling
vs. novel (dup-check-notes.md §1). No probing a live system. Mechanizes dup-check-notes.md §2-§3.

Usage:
  $prog <owner/repo> [keyword ...]

  owner/repo   in-scope target slug, e.g. huggingface/transformers   (required)
  keyword ...  match tokens: SYMBOL, CWE/class word, subsystem   (omit => just build cache)

Env:
  OUT=<dir>    write the cache here (never inside the repo under review)  (default: mktemp -d)
  LIMIT=N      max PRs / issues pulled per list                          (default: 300)

Needs gh (GitHub CLI). If gh is absent, prints the equivalent commands and exits 0.
EOF
}

# --- -h/--help ------------------------------------------------------------
for a in "$@"; do case "$a" in -h|--help) usage; exit 0 ;; esac; done

# --- arg parse ------------------------------------------------------------
[ $# -ge 1 ] || { usage; exit 2; }
slug=$1; shift
case "$slug" in
  -*)     die "unknown option: $slug" ;;
  */*/*)  die "expected <owner/repo>, got a longer path: $slug" ;;
  */*)    : ;;
  *)      die "expected <owner/repo> (exactly one slash), got: $slug" ;;
esac
owner=${slug%%/*}; repo=${slug#*/}
{ [ -n "$owner" ] && [ -n "$repo" ]; } || die "empty owner or repo in: $slug"

# remaining args are match keywords -> an ERE alternation for grep -iE
kw_re=""
for k in "$@"; do
  [ -n "$k" ] || continue
  if [ -z "$kw_re" ]; then kw_re=$k; else kw_re="$kw_re|$k"; fi
done

limit=${LIMIT:-300}
case "$limit" in ''|*[!0-9]*) die "LIMIT must be a non-negative integer (got: $limit)" ;; esac

# --- degrade gracefully when gh is missing --------------------------------
if ! command -v gh >/dev/null 2>&1; then
  pdir=${OUT:-.}
  grep_pat=${kw_re:-'<symbol>|<subsystem>|<class-word>'}
  cat <<EOF
# $prog: gh (GitHub CLI) not found on PATH.
# Printing the equivalent READ-ONLY commands (dup-check-notes.md §2-§3). Run these by
# hand (or install gh: https://cli.github.com), then grep the cache as shown. Exit 0.

# a) published security advisories -> advisories.tsv
gh api repos/$owner/$repo/security-advisories --paginate \\
  --jq '.[] | [.ghsa_id, (.cve_id // "-"), .summary] | @tsv'  > "$pdir/advisories.tsv"

# b) open + merged/closed PRs  (silent fixes land here before any advisory) -> known.tsv
gh pr    list --repo $slug --state all --limit $limit --json number,title,state \\
  --jq '.[] | ["PR",  (.number|tostring), .state, .title] | @tsv'  >  "$pdir/known.tsv"
# c) open + closed issues  (reports, and wontfix/by-design verdicts) -> known.tsv
gh issue list --repo $slug --state all --limit $limit --json number,title,state,labels \\
  --jq '.[] | ["ISS", (.number|tostring), .state, .title] | @tsv'  >> "$pdir/known.tsv"

# match your candidate's strongest tokens against the cache:
grep -iE '$grep_pat' "$pdir/advisories.tsv" "$pdir/known.tsv"

# reminder: a hit is a LEAD TO READ, not an auto-dup; no hit lowers the odds but is
#   not proof of novelty — match root cause + reachability (dup-check-notes.md §1).
EOF
  exit 0
fi

# --- scratch dir (honor OUT, else mktemp) — NEVER the repo under review ----
if [ -n "${OUT:-}" ]; then
  mkdir -p "$OUT" || die "cannot create OUT dir: $OUT"
  out=$OUT
else
  out=$(mktemp -d "${TMPDIR:-/tmp}/dup-scan.XXXXXX") || die "mktemp -d failed"
fi
adv="$out/advisories.tsv"
known="$out/known.tsv"
: > "$adv"
: > "$known"

nlines() { if [ -s "$1" ]; then wc -l < "$1" | tr -d ' '; else echo 0; fi; }

# --- a) published security advisories (§2a / §3) --------------------------
adv_err=0
if gh api "repos/$owner/$repo/security-advisories" --paginate \
     --jq '.[] | [.ghsa_id, (.cve_id // "-"), .summary] | @tsv' > "$adv" 2>/dev/null
then :; else : > "$adv"; adv_err=1; fi

# --- b) open + merged/closed PRs, c) open + closed issues (§2b/§2c / §3) ---
pr_err=0; iss_err=0
if gh pr list --repo "$slug" --state all --limit "$limit" --json number,title,state \
     --jq '.[] | ["PR", (.number|tostring), .state, .title] | @tsv' >> "$known" 2>/dev/null
then :; else pr_err=1; fi
if gh issue list --repo "$slug" --state all --limit "$limit" --json number,title,state,labels \
     --jq '.[] | ["ISS", (.number|tostring), .state, .title] | @tsv' >> "$known" 2>/dev/null
then :; else iss_err=1; fi

n_adv=$(nlines "$adv")
n_pr=$(grep -c '^PR	' "$known" 2>/dev/null || true); n_pr=${n_pr:-0}
n_iss=$(grep -c '^ISS	' "$known" 2>/dev/null || true); n_iss=${n_iss:-0}

printf '# dup-scan — %s   (read-only; Gate B / dup-check-notes.md §2-§3)\n' "$slug"
printf '#   cache: %s\n' "$out"
printf '#          advisories.tsv (%s)   known.tsv (PR %s, ISS %s)\n' "$n_adv" "$n_pr" "$n_iss"
[ "$adv_err" -eq 1 ] && printf '#   note : advisories unreadable (none published, or no access) — see §2a for the global DB / OSV\n'
[ "$pr_err"  -eq 1 ] && printf '#   note : PR list failed — re-run or check the slug/scope\n'
[ "$iss_err" -eq 1 ] && printf '#   note : issue list failed — re-run or check the slug/scope\n'

# --- published advisories: always shown in full (the top dup source) ------
printf '\n== published security advisories == (%s)\n' "$n_adv"
printf '   cols: ghsa_id <tab> cve_id <tab> summary   (the vendor-own DB; also eyeball the Security tab + SECURITY.md, and huntr/ZDI listings)\n'
if [ "$n_adv" -gt 0 ]; then cat "$adv"; else printf '   (none published for this repo)\n'; fi

printf '\n== open + merged/closed PRs and open + closed issues == (PR %s, ISS %s)\n' "$n_pr" "$n_iss"
printf '   cached in known.tsv (cols: PR|ISS <tab> number <tab> state <tab> title)\n'
if [ "$kw_re" = "" ]; then
  printf '   (pass keywords to filter, or: grep -iE '\''<symbol>|<subsystem>|<class-word>'\'' %s %s)\n' "$adv" "$known"
fi

# --- keyword match across the cache (§3) ----------------------------------
if [ -n "$kw_re" ]; then
  printf '\n== keyword hits (grep -iE '\''%s'\'' over the cache) ==\n' "$kw_re"
  hits=$(grep -iEnH -- "$kw_re" "$adv" "$known" 2>/dev/null || true)
  if [ -n "$hits" ]; then
    n=$(printf '%s\n' "$hits" | wc -l | tr -d ' ')
    printf '   %s line%s matched:\n' "$n" "$([ "$n" = 1 ] || printf s)"
    printf '%s\n' "$hits"
  else
    printf '   (no cache line matched — but read §2d silent-fix commits and §5 incomplete-fix before claiming novelty)\n'
  fi
fi

printf '\n# read it as: a hit is a LEAD TO READ, not an auto-dup; no hit lowers the odds\n'
printf '#   but is not proof of novelty — match root cause + reachability (dup-check-notes.md §1).\n'
printf '# still owed by hand: the global Advisory DB / OSV (§2a), silent-fix commits on main\n'
printf '#   (§2d: git log -S/-G <symbol>), and release notes (§2e). Then record the dup-check\n'
printf '#   trail (every query + result) in templates/PROGRESS.md and carry it into SUBMISSION.md.\n'
