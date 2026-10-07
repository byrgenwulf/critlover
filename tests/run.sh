#!/usr/bin/env bash
#
# run.sh — self-test for critlover's READ-ONLY recon greppers.
#
# This exercises the scripts in ../scripts against the tiny SYNTHETIC fixtures in
# ./fixtures (fake, non-exploitable code that exists only to be grepped) and asserts
# each script's ACTUAL output. It tests the GREPPERS, not any real application: a
# PASS means only "the recon script still finds / labels what we expect". The
# fixtures are not imported, served, or executed — they are grep bait.
#
# Usage:         bash tests/run.sh      (runs from anywhere — it locates its own root)
# Dependencies:  bash, git, grep, and the scripts themselves (ripgrep used if present).
# Exit status:   0 if every check PASS/SKIP, 1 if any check FAILs.
#
set -eu

# --- locate the repo root relative to THIS script, so it runs from anywhere ---
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/.." && pwd)
scripts="$root/scripts"
fixtures="$here/fixtures"

SINK="$scripts/sink-grep.sh"
AUTHZ="$scripts/authz-census.sh"
CHURN="$scripts/churn.sh"
ENTRY="$scripts/entrypoints.sh"   # added in parallel this round — may not exist yet

pass=0; fail=0; skip=0
ok()  { printf 'PASS: %s\n' "$1"; pass=$((pass + 1)); }
no()  { printf 'FAIL: %s\n' "$1"; fail=$((fail + 1)); }
skp() { printf 'SKIP: %s\n' "$1"; skip=$((skip + 1)); }

# desc, fixed-string needle, haystack
has()   { if printf '%s\n' "$3" | grep -qF -- "$2"; then ok "$1"; else no "$1"; fi; }
hasnt() { if printf '%s\n' "$3" | grep -qF -- "$2"; then no "$1"; else ok "$1"; fi; }
# desc, ERE, haystack
rhas()  { if printf '%s\n' "$3" | grep -Eq -- "$2"; then ok "$1"; else no "$1"; fi; }

printf '# critlover grepper self-test (synthetic fixtures under %s)\n\n' "$fixtures"

# --- sink-grep.sh: deser + native via `all`, then exec ----------------------
if [ -f "$SINK" ]; then
  out_all=$(bash "$SINK" "$fixtures" all 2>&1) || true
  has  "sink-grep all: deser finds pickle.loads in app.py"  "pickle.loads"            "$out_all"
  rhas "sink-grep all: native finds memcpy in buf.c"        'buf\.c:[0-9]+:.*memcpy'  "$out_all"

  out_exec=$(bash "$SINK" "$fixtures" exec 2>&1) || true
  has  "sink-grep exec: finds the eval( sink"               "eval("                   "$out_exec"
else
  skp "sink-grep.sh: not found at $SINK"
fi

# --- authz-census.sh: both routes, then ONLY_NONE blank-guard subset --------
if [ -f "$AUTHZ" ]; then
  out_py=$(bash "$AUTHZ" "$fixtures" py 2>&1) || true
  has "authz py: lists the guarded GET route"    "@app.get("  "$out_py"
  has "authz py: lists the unguarded POST route" "@app.post(" "$out_py"

  out_none=$(ONLY_NONE=1 bash "$AUTHZ" "$fixtures" py 2>&1) || true
  has   "authz ONLY_NONE=1: surfaces the unguarded POST" "@app.post(" "$out_none"
  hasnt "authz ONLY_NONE=1: hides the guarded GET"       "@app.get("  "$out_none"
else
  skp "authz-census.sh: not found at $AUTHZ"
fi

# --- entrypoints.sh: SKIP gracefully if absent, else assert it surfaces -----
# the POST route or a listener. (Added in parallel this round; CLI not yet known,
# so the match is deliberately lenient.)
if [ -f "$ENTRY" ]; then
  out_entry=$(bash "$ENTRY" "$fixtures" 2>&1) || true
  rhas "entrypoints.sh: surfaces the POST route or a listener" \
       '@app\.post\(|/items|[Ll]isten|LISTEN|\.serve|bind\(|uvicorn|host=' "$out_entry"
else
  skp "entrypoints.sh: not present yet (added in parallel this round)"
fi

# --- churn.sh: needs a git work tree, so build a throwaway copy -------------
if [ ! -f "$CHURN" ]; then
  skp "churn.sh: not found at $CHURN"
elif ! command -v git >/dev/null 2>&1; then
  skp "churn.sh: git not available"
else
  tmp=$(mktemp -d "${TMPDIR:-/tmp}/critlover-churn.XXXXXX")
  trap 'rm -rf "$tmp"' EXIT
  cp "$fixtures/app.py" "$fixtures/buf.c" "$tmp/" 2>/dev/null || true
  (
    cd "$tmp"
    git init -q
    git -c user.email=selftest@example.invalid -c user.name='critlover selftest' add app.py buf.c
    git -c user.email=selftest@example.invalid -c user.name='critlover selftest' \
        commit -q -m 'synthetic fixtures for churn self-test'
  ) >/dev/null 2>&1 || true
  out_churn=$(bash "$CHURN" "$tmp" 2>&1) || true
  rhas "churn.sh: ranks app.py in a throwaway git tree" 'app\.py' "$out_churn"
  rm -rf "$tmp"; trap - EXIT
fi

# --- tally ------------------------------------------------------------------
printf '\n== %d passed, %d failed, %d skipped ==\n' "$pass" "$fail" "$skip"
[ "$fail" -eq 0 ] || exit 1
exit 0
