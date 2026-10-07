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
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH='' cd -- "$here/.." && pwd)
scripts="$root/scripts"
fixtures="$here/fixtures"

SINK="$scripts/sink-grep.sh"
AUTHZ="$scripts/authz-census.sh"
CHURN="$scripts/churn.sh"
ENTRY="$scripts/entrypoints.sh"

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

# --- entrypoints.sh: SKIP gracefully if absent, else assert it surfaces ------
# the POST route or a listener (match is deliberately lenient — channels vary).
if [ -f "$ENTRY" ]; then
  out_entry=$(bash "$ENTRY" "$fixtures" 2>&1) || true
  rhas "entrypoints.sh: surfaces the POST route or a listener" \
       '@app\.post\(|/items|[Ll]isten|LISTEN|\.serve|bind\(|uvicorn|host=' "$out_entry"
else
  skp "entrypoints.sh: not found at $ENTRY"
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

# --- multi-language sink coverage (regression: the Python+C-only gap) -------
if [ -f "$SINK" ]; then
  out_deser=$(bash "$SINK" "$fixtures" deser 2>&1) || true
  has  "sink-grep deser: catches JS node-serialize unserialize" "unserialize"    "$out_deser"
  out_execjs=$(bash "$SINK" "$fixtures" exec 2>&1) || true
  has  "sink-grep exec: catches JS child_process"               "child_process"  "$out_execjs"
  out_native=$(bash "$SINK" "$fixtures" native 2>&1) || true
  has  "sink-grep native: catches Rust from_raw_parts"          "from_raw_parts" "$out_native"
  # context must NOT change the hit count (regression: inflated count when CONTEXT>0)
  c0=$(bash "$SINK" "$fixtures" deser 2>&1 | grep -oE '\([0-9]+ hit' | grep -oE '[0-9]+' | head -1)
  c3=$(CONTEXT=3 bash "$SINK" "$fixtures" deser 2>&1 | grep -oE '\([0-9]+ hit' | grep -oE '[0-9]+' | head -1)
  if [ "${c0:-x}" = "${c3:-y}" ]; then ok "sink-grep: CONTEXT=3 hit count == CONTEXT=0 ($c0)"; else no "sink-grep: context inflates count ($c0 vs $c3)"; fi
fi

# --- authz: a non-auth Depends() is NOT a guard (regression #5) -------------
if [ -f "$AUTHZ" ]; then
  out_na=$(ONLY_NONE=1 bash "$AUTHZ" "$fixtures" py 2>&1) || true
  has "authz ONLY_NONE: surfaces the non-auth-Depends /transfer route" "/transfer"        "$out_na"
  has "authz ONLY_NONE: header uses the blank-guard count format"      "with a blank guard" "$out_na"
fi

# --- patch-variant: a malicious diff.textconv must NOT execute (regression #1) -
PV="$scripts/patch-variant.sh"
if [ -f "$PV" ] && command -v git >/dev/null 2>&1; then
  ev=$(mktemp -d "${TMPDIR:-/tmp}/critlover-textconv.XXXXXX")
  mark="$ev/PWNED_TEXTCONV"
  (
    cd "$ev" || exit 0
    git init -q
    printf 'def a(): pass\n' > m.py
    git -c user.email=t@t.invalid -c user.name=t add -A
    git -c user.email=t@t.invalid -c user.name=t commit -qm init
    printf 'def b(): bad()\n' >> m.py
    git -c user.email=t@t.invalid -c user.name=t add -A
    git -c user.email=t@t.invalid -c user.name=t commit -qm fix
    git config diff.evil.textconv "sh -c 'touch \"$mark\"; cat'"
    printf '*.py diff=evil\n' > .gitattributes
  ) >/dev/null 2>&1 || true
  bash "$PV" "$ev" HEAD >/dev/null 2>&1 || true
  if [ -f "$mark" ]; then no "patch-variant: malicious diff.textconv EXECUTED (RCE)"; else ok "patch-variant: --no-textconv blocks a malicious diff driver"; fi
  rm -rf "$ev"
fi

# --- grep-fallback path: scripts must work WITHOUT ripgrep (regression) -----
# A PATH shim that omits rg forces `command -v rg` to fail and scan() to use grep -r.
if command -v grep >/dev/null 2>&1; then
  shim=$(mktemp -d "${TMPDIR:-/tmp}/critlover-nobin.XXXXXX")
  for t in bash sh grep egrep fgrep sed awk gawk git wc sort uniq tr head cat mktemp dirname basename env test; do
    p=$(command -v "$t" 2>/dev/null) && ln -sf "$p" "$shim/$t"
  done   # deliberately NO rg
  if [ -f "$SINK" ]; then
    fb=$(PATH="$shim" bash "$SINK" "$fixtures" all 2>&1) || true
    has "fallback: sink-grep runs on the grep -r backend" "backend: grep -r" "$fb"
    has "fallback: sink-grep still finds pickle.loads"    "pickle.loads"      "$fb"
    has "fallback: sink-grep still finds memcpy"          "memcpy"            "$fb"
  fi
  if [ -f "$AUTHZ" ]; then
    fa=$(PATH="$shim" ONLY_NONE=1 bash "$AUTHZ" "$fixtures" py 2>&1) || true
    has "fallback: authz ONLY_NONE still surfaces /transfer" "/transfer" "$fa"
  fi
  rm -rf "$shim"
fi

# --- dup-scan: degrades gracefully when gh is absent (regression) -----------
DS="$scripts/dup-scan.sh"
if [ -f "$DS" ]; then
  nogh=$(mktemp -d "${TMPDIR:-/tmp}/critlover-nogh.XXXXXX")
  for t in bash sh grep sed awk tr head cat mktemp env test; do
    p=$(command -v "$t" 2>/dev/null) && ln -sf "$p" "$nogh/$t"
  done   # deliberately NO gh
  dsout=$(PATH="$nogh" bash "$DS" acme/widget pickle 2>&1) && dsrc=0 || dsrc=$?
  if [ "${dsrc:-1}" -eq 0 ]; then ok "dup-scan: exits 0 when gh is absent"; else no "dup-scan: non-zero exit ($dsrc) with gh absent"; fi
  has "dup-scan: prints the equivalent gh commands when gh absent" "gh api" "$dsout"
  rm -rf "$nogh"
fi

# --- patch-variant: flags an unpatched sibling the fix didn't touch (regression) -
if [ -f "$PV" ] && command -v git >/dev/null 2>&1; then
  sv=$(mktemp -d "${TMPDIR:-/tmp}/critlover-sibling.XXXXXX")
  (
    cd "$sv" || exit 0
    git init -q
    printf 'def handler(x):\n    danger_sink(x)\n' > a.py
    printf 'def other(x):\n    danger_sink(x)\n' > b.py
    git -c user.email=t@t.invalid -c user.name=t add -A
    git -c user.email=t@t.invalid -c user.name=t commit -qm init
    printf 'def handler(x):\n    if ok(x):\n        danger_sink(x)\n' > a.py
    git -c user.email=t@t.invalid -c user.name=t add -A
    git -c user.email=t@t.invalid -c user.name=t commit -qm fix
  ) >/dev/null 2>&1 || true
  pvout=$(bash "$PV" "$sv" HEAD 'danger_sink' 2>&1) || true
  has "patch-variant: flags the unpatched sibling b.py" "b.py" "$pvout"
  rm -rf "$sv"
fi

# --- entrypoints: surfaces a route/listener channel (regression) ------------
if [ -f "$ENTRY" ]; then
  epout=$(bash "$ENTRY" "$fixtures" 2>&1) || true
  rhas "entrypoints: lists an HTTP route from the fixtures" '/items|/pay|@app\.(get|post)|\.post\(' "$epout"
fi

# --- tally ------------------------------------------------------------------
printf '\n== %d passed, %d failed, %d skipped ==\n' "$pass" "$fail" "$skip"
[ "$fail" -eq 0 ] || exit 1
exit 0
