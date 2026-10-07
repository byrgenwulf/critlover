#!/usr/bin/env bash
#
# clone.sh — blobless + sparse clone of a large repo for source review.
#
# critlover stage 1 (scope & scout). READ-ONLY w.r.t. the remote: fetches a
# blobless checkout (--filter=blob:none; blobs arrive on demand) and, when you
# name subpaths, a SPARSE working tree — so you read HEAD of a huge repo fast
# without hauling the whole object store. Prints the pinned HEAD sha to cite.
#
# Authorized, in-scope targets ONLY. Treat the checkout as untrusted data:
# review it; do not run its build or scripts just to look around.
#
# Usage:
#   clone.sh <repo-url> [dest] [subpath ...]
#
#   repo-url   https/ssh URL of the in-scope target            (required)
#   dest       local directory to create    (default: basename of the URL)
#   subpath    repo-relative dirs for a SPARSE checkout; omit for the full
#              (still blobless) tree. Needs a dest to disambiguate.
#
# Env:
#   REF=<branch|tag|sha>   check out this ref after clone  (default: remote HEAD)
#   DEPTH=N                shallow to N commits            (default: full, blobless)
#
set -eu

prog=${0##*/}
die() { printf '%s: %s\n' "$prog" "$1" >&2; exit "${2:-2}"; }

usage() {
  cat <<EOF
$prog — blobless + sparse clone of a large repo for source review (critlover stage 1).

READ-ONLY w.r.t. the remote. Blobless (--filter=blob:none); sparse when you name subpaths.
Authorized, in-scope targets only. Treat the checkout as untrusted data.

Usage:
  $prog <repo-url> [dest] [subpath ...]

  repo-url   https/ssh URL of the in-scope target        (required)
  dest       local dir to create     (default: basename of the URL)
  subpath    repo-relative dirs for a SPARSE checkout (needs a dest; omit => full tree)

Env:
  REF=<branch|tag|sha>  check out this ref after clone  (default: remote HEAD)
  DEPTH=N               shallow to N commits            (default: full, blobless)
EOF
}

for a in "$@"; do case "$a" in -h|--help) usage; exit 0 ;; esac; done
[ $# -ge 1 ] || { usage; exit 2; }
command -v git >/dev/null 2>&1 || die "git not found on PATH"

url=$1; shift
dest=${1:-}
[ $# -gt 0 ] && shift
if [ -z "$dest" ]; then base=${url##*/}; dest=${base%.git}; fi
[ -n "$dest" ] || die "could not derive a destination directory from: $url"
[ -e "$dest" ] && die "destination already exists: $dest (refusing to overwrite)"
subpaths="$*"

depth_args=""
if [ -n "${DEPTH:-}" ]; then
  case "$DEPTH" in ''|*[!0-9]*) die "DEPTH must be a positive integer (got: $DEPTH)" ;; esac
  depth_args="--depth $DEPTH"
fi

printf '# clone — %s -> %s   (blobless%s%s)\n' "$url" "$dest" \
  "$([ -n "$subpaths" ] && printf ' + sparse' || true)" \
  "$([ -n "$depth_args" ] && printf ' + depth %s' "$DEPTH" || true)"

if [ -n "$subpaths" ]; then
  # shellcheck disable=SC2086
  git clone --filter=blob:none --sparse $depth_args -- "$url" "$dest"
  # shellcheck disable=SC2086
  git -C "$dest" sparse-checkout set -- $subpaths
else
  # shellcheck disable=SC2086
  git clone --filter=blob:none $depth_args -- "$url" "$dest"
fi

if [ -n "${REF:-}" ]; then
  git -C "$dest" checkout --quiet "$REF" || die "could not check out ref: $REF"
fi

sha=$(git -C "$dest" rev-parse HEAD 2>/dev/null || echo '?')
ref_now=$(git -C "$dest" rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')

printf '\n# cloned.\n'
printf '#   path : %s\n' "$dest"
printf '#   ref  : %s\n' "$ref_now"
printf '#   HEAD : %s   <-- PIN THIS: every file:line you cite must hold at this sha\n' "$sha"
if [ -n "$subpaths" ]; then printf '#   sparse: %s\n' "$subpaths"; fi
printf '#   next : record target @ %s in templates/PROGRESS.md, then: churn.sh %s 90\n' "$sha" "$dest"
