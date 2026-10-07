#!/usr/bin/env bash
#
# authz-census.sh — best-effort route-to-guard table for web backends.
#
# critlover stages 2-4 (bucket design / fan-out / grading), authz-RBAC vein.
# READ-ONLY recon: finds route/endpoint declarations and, for each, lists the
# auth decorators / middleware attached to THAT route's own block, so a human
# can scan for a STATE-CHANGING route that is missing an admin gate.
#
# IT IS NOT A PARSER. A blank guard column does NOT mean "unauthenticated" —
# the route may still be gated by a router-level FastAPI `dependencies=[...]`,
# a globally-mounted Express middleware (`app.use(auth)`), a class-level mixin,
# or a decorator this heuristic didn't recognize. Treat "(none)" as a prompt
# to READ THE CODE, never as a finding. Mutating verbs (POST/PUT/PATCH/DELETE)
# are flagged [MUTATING] because that is where a missing gate matters most.
#
# How the guard column is built (bounded to the route's own block, so guards
# never bleed in from a neighbouring route):
#   py       — contiguous decorator lines ABOVE the route + the route decorator
#              and the function signature BELOW it, up to the `):` that ends it.
#              Catches @login_required, dependencies=[...], and `= Depends(...)`
#              params in either decorator order.
#   express  — the route call's own argument list (its middleware), up to the
#              handler (`=>` / `function`) or the closing `)`.
#
# Frameworks:
#   py        FastAPI / Flask / Starlette decorators (@app.get, @bp.route, ...)
#   express   Express / Koa (app.get / router.post / .use)
#   django    urls.py url-conf entries (path/re_path/url) — LISTED ONLY; Django
#             guards live on the VIEW, so follow each entry to its view.
#
# Usage:
#   authz-census.sh [repo] [framework ...]
#
#   repo           path to scan                     (default: current directory)
#   framework ...  py | express | django | all      (default: all)
#
# Env:
#   MAX=N         cap routes printed per framework (0 = no cap)     (default: 0)
#   NO_IGNORE=1   also scan .gitignored / vendored paths            (default: respect .gitignore)
#   ONLY_NONE=1   print only routes whose guard column is blank —
#                 the unauth / missing-gate subset (still READ THE CODE)   (default: 0)
#
set -eu
set -f  # the glob strings below are regex/file-glob LITERALS for rg/grep — never shell-expand them

prog=${0##*/}
die() { printf '%s: %s\n' "$prog" "$1" >&2; exit "${2:-2}"; }

usage() {
  cat <<EOF
$prog — best-effort route-to-guard table for web backends (critlover authz vein).

READ-ONLY. For each route it lists the auth decorators/middleware on THAT route's own block.
NOT a parser: a blank guard means "read the code" (a router-level dependencies=, a global
app.use(auth), or a class mixin may still gate it) — never a finding on its own.
Mutating verbs are flagged [MUTATING]: that is where a missing admin gate matters.

Usage:
  $prog [repo] [framework ...]

  repo           path to scan                  (default: current directory)
  framework ...  py | express | django | all   (default: all)

Env:
  MAX=N        cap routes per framework, 0 = no cap     (default: 0)
  NO_IGNORE=1  also scan .gitignored / vendored paths   (default: respect .gitignore)
  ONLY_NONE=1  print only routes with a blank guard (unauth / missing-gate subset)  (default: 0)
EOF
}

# --- arg parse ------------------------------------------------------------
for a in "$@"; do case "$a" in -h|--help) usage; exit 0 ;; esac; done

repo="."
if [ $# -gt 0 ]; then
  case "$1" in
    py|express|django|all) : ;;   # first arg is a framework -> repo stays cwd
    *) repo=$1; shift ;;
  esac
fi
fws="$*"
[ -n "$fws" ] || fws="all"

[ -d "$repo" ] || die "not a directory: $repo (usage: $prog [repo] [framework ...])"
max=${MAX:-0}
case "$max" in ''|*[!0-9]*) die "MAX must be a non-negative integer (got: $max)" ;; esac

# --- backend: ripgrep preferred, grep -r fallback ------------------------
have_rg=0
if command -v rg >/dev/null 2>&1; then have_rg=1; fi

scan() {  # scan PATTERN GLOB... -> file:line:text
  pat=$1; shift
  globs=( "$@" ); g=""
  if [ "$have_rg" -eq 1 ]; then
    args=( --no-heading --line-number --with-filename --color=never )
    [ "${NO_IGNORE:-0}" = "1" ] && args+=( --no-ignore )
    for g in "${globs[@]}"; do args+=( -g "$g" ); done
    rg "${args[@]}" -e "$pat" -- "$repo" 2>/dev/null || true
  else
    args=()
    for g in "${globs[@]}"; do args+=( "--include=$g" ); done
    grep -rEnI "${args[@]}" -e "$pat" -- "$repo" 2>/dev/null || true
  fi
}

# capture MODE FILE LINE -> prints only the route's own block (guard candidates)
capture() {
  awk -v rl="$3" -v mode="$2" '
    { L[NR]=$0 }
    END {
      if (rl < 1 || rl > NR) exit
      if (mode == "py") {
        i = rl - 1
        while (i >= 1 && L[i] ~ /^[[:space:]]*@/) { print L[i]; i-- }   # stacked decorators above
        print L[rl]                                                     # the route decorator
        j = rl + 1; cap = 0
        while (j <= NR && cap < 15) {                                   # down to the signature end
          print L[j]
          if (L[j] ~ /\)[[:space:]]*(->[^:]*)?:[[:space:]]*(#.*)?$/) break
          j++; cap++
        }
      } else {                                                          # express: route call args only
        print L[rl]
        if (L[rl] !~ /(=>|function|\)[[:space:]]*;?[[:space:]]*$)/) {
          j = rl + 1; cap = 0
          while (j <= NR && cap < 6) {
            print L[j]
            if (L[j] ~ /(=>|function|\{|\)[[:space:]]*;?[[:space:]]*$)/) break
            j++; cap++
          }
        }
      }
    }
  ' "$1" 2>/dev/null || true
}

want()   { case " $fws " in *" all "*|*" $1 "*) return 0 ;; *) return 1 ;; esac; }
plural() { [ "$1" = 1 ] || printf s; }

# census LABEL MODE ROUTE_RE GUARD_RE GLOB...  — route + its adjacent guards
census() {
  label=$1; mode=$2; route_re=$3; guard_re=$4; shift 4
  hits=$(scan "$route_re" "$@")
  [ "$max" -gt 0 ] && [ -n "$hits" ] && hits=$(printf '%s\n' "$hits" | head -n "$max")
  n=0; [ -n "$hits" ] && n=$(printf '%s\n' "$hits" | wc -l | tr -d ' ')
  printf '\n== %s == (%s route%s)\n' "$label" "$n" "$(plural "$n")"
  if [ -z "$hits" ]; then printf '   (no routes matched)\n'; return 0; fi
  printf '%s\n' "$hits" | while IFS= read -r hit; do
    f=${hit%%:*}; rest=${hit#*:}; ln=${rest%%:*}; txt=${rest#*:}
    case "$ln" in ''|*[!0-9]*) continue ;; esac
    guards=$(capture "$f" "$mode" "$ln" | grep -Eo "$guard_re" 2>/dev/null | sort -u | tr '\n' ' ' | sed 's/ *$//' || true)
    mut=""
    case "$txt" in
      *'.post('*|*'.put('*|*'.patch('*|*'.delete('*|*POST*|*PUT*|*PATCH*|*DELETE*) mut=" [MUTATING]" ;;
    esac
    # ONLY_NONE=1 => show only the blank-guard (unauth / missing-gate) subset.
    if [ "${ONLY_NONE:-0}" = "1" ] && [ -n "$guards" ]; then continue; fi
    printf '%s:%s%s\n' "$f" "$ln" "$mut"
    printf '    route : %s\n' "$(printf '%s' "$txt" | sed 's/^[[:space:]]*//')"
    if [ -n "$guards" ]; then
      printf '    guard : %s\n' "$guards"
    else
      printf '    guard : (none on this route — READ THE CODE; may be gated by a router/global/mixin)\n'
    fi
  done
  return 0
}

# listroutes LABEL ROUTE_RE NOTE GLOB...  — list only (guards not adjacent)
listroutes() {
  label=$1; route_re=$2; note=$3; shift 3
  hits=$(scan "$route_re" "$@")
  [ "$max" -gt 0 ] && [ -n "$hits" ] && hits=$(printf '%s\n' "$hits" | head -n "$max")
  n=0; [ -n "$hits" ] && n=$(printf '%s\n' "$hits" | wc -l | tr -d ' ')
  printf '\n== %s == (%s route%s)\n' "$label" "$n" "$(plural "$n")"
  if [ -n "$note" ]; then printf '   note: %s\n' "$note"; fi
  if [ -n "$hits" ]; then printf '%s\n' "$hits"; else printf '   (no routes matched)\n'; fi
}

PY="*.py"
JS="*.js *.ts *.mjs *.cjs *.jsx *.tsx"
URLS="urls.py **/urls.py"

GUARD_PY='Depends\([^)]*\)|dependencies[[:space:]]*=|login_required|admin_required|roles?_required|permission_required|permission_classes|IsAuthenticated|IsAdminUser|current_user|get_current_[[:alnum:]_]+|requires?_[[:alnum:]_]+|verify_[[:alnum:]_]+|@[[:alnum:]_]*[Aa]uth[[:alnum:]_]*|@[[:alnum:]_]*[Ll]ogin[[:alnum:]_]*|@[[:alnum:]_]*[Aa]dmin[[:alnum:]_]*|@[[:alnum:]_]*[Pp]ermission[[:alnum:]_]*'
GUARD_JS='requires?Auth|isAuthenticated|ensureAuth|ensureLoggedIn|ensureAdmin|require(Admin|Role|Permission)[[:alnum:]_]*|authorize[[:alnum:]_]*|authenticate[[:alnum:]_]*|passport\.authenticate\([^)]*\)|verify(Token|Jwt|JWT)|check(Auth|Role|Permission)|isAdmin|has(Role|Permission)|[[:alnum:]_]*[Aa]uth(Middleware|Guard)|jwt[[:alnum:]_]*|csrf[[:alnum:]_]*'

printf '# authz-census — %s   frameworks: %s   backend: %s   (read-only)\n' \
  "$repo" "$fws" "$([ "$have_rg" -eq 1 ] && echo ripgrep || echo 'grep -r')"

if want py; then
  census "Python routes (FastAPI / Flask / Starlette)" py \
    '@[[:alnum:]_.]+\.(get|post|put|patch|delete|options|head|route|websocket|api_route)[[:space:]]*\(' \
    "$GUARD_PY" \
    $PY
fi

if want express; then
  census "Express / Koa routes" express \
    '(^|[^.[:alnum:]_])(app|router|api|routes?)\.(get|post|put|patch|delete|options|head|all|use)[[:space:]]*\(' \
    "$GUARD_JS" \
    $JS
fi

if want django; then
  listroutes "Django url-conf entries (urls.py)" \
    '(^|[^.[:alnum:]_])(path|re_path|url)[[:space:]]*\(' \
    "Django guards live on the VIEW, not the url-conf. For each entry, open the view and confirm @login_required / LoginRequiredMixin / DRF permission_classes. A url-conf alone proves nothing about auth." \
    $URLS
fi

printf '\n# read it as: find a [MUTATING] route whose guard is blank or weaker than its\n'
printf '#   siblings, then CONFIRM by reading the code (router-level / global / mixin gates\n'
printf '#   do not show here). A real missing-gate on an in-scope, reachable, state-changing\n'
printf '#   route is the finding — dup-check (dup-check-notes.md) and re-score before filing.\n'
