#!/usr/bin/env bash
#
# entrypoints.sh — census of where UNtrusted input ENTERS, grouped by channel.
#
# critlover stage 1 (scope & scout), reachability vein. READ-ONLY recon: a ripgrep
# pass (falls back to grep -r) that lists candidate entry points as file:line:text,
# grouped by the CHANNEL an attacker would use. Reachability is half of severity —
# an endpoint reached *before* authentication (a webhook receiver, an open metrics
# port, a health check that parses a body, a login path that touches a deserializer)
# turns a mid bug into a crit, because "who can trigger it" drops to anyone on the
# network (STRATEGY §3b). This finds where input ARRIVES; it does NOT prove any path
# is reachable, attacker-controlled, or a bug. Every hit is a lead for the surface map.
#
# Channels:
#   listeners   network listeners / binds  — listen(/bind(/socket(/0.0.0.0/make_server/serve(
#   routes      HTTP route / handler decls — reuses authz-census.sh's route shapes
#   rpc         RPC / gRPC servers         — add_*Servicer*_to_server / grpc server / serve(
#   mq          message-queue consumers    — consume/subscribe/recv (recv + load = §3d vein)
#   parsers     file / stream parsers      — open(/load(s)/parse(  (NOISY; read the caller)
#   config      port / config surface      — argparse/add_argument, os.environ/getenv,
#                                             process.env, --port  (ties reachability to config)
#
# Usage:
#   entrypoints.sh <repo> [lang ...]
#
#   repo       path to scan                     (required)
#   lang ...   py | js | c | all                (default: all)
#
# Env:
#   NO_IGNORE=1   also scan .gitignored / vendored paths   (default: respect .gitignore)
#   CONTEXT=N     print N lines of context around each hit (default: 0)
#
set -eu
set -f  # the glob strings below are file-glob LITERALS for rg/grep — never shell-expand them

prog=${0##*/}
die() { printf '%s: %s\n' "$prog" "$1" >&2; exit "${2:-2}"; }

usage() {
  cat <<EOF
$prog — census of where UNtrusted input ENTERS, grouped by channel (critlover stage 1, §3b).

READ-ONLY: ripgrep (or grep -r) listing entry points as file:line:text, grouped by the CHANNEL an
attacker uses. Reachability is half of severity — pre-auth surface weights heaviest. It finds where
input ARRIVES; it does NOT judge reachability. Every hit is a lead for the surface map, not a finding.

Usage:
  $prog <repo> [lang ...]

  repo       path to scan              (required)
  lang ...   py | js | c | all         (default: all)

Env:
  NO_IGNORE=1   also scan .gitignored / vendored paths   (default: respect .gitignore)
  CONTEXT=N     lines of context around each hit         (default: 0)

Channels: listeners | routes | rpc | mq | parsers | config  (all are printed)
EOF
}

# --- -h/--help ------------------------------------------------------------
for a in "$@"; do case "$a" in -h|--help) usage; exit 0 ;; esac; done

# --- arg parse ------------------------------------------------------------
[ $# -ge 1 ] || { usage; exit 2; }
repo=$1; shift
langs="$*"; [ -n "$langs" ] || langs="all"
for l in $langs; do
  case "$l" in
    py|js|c|all) : ;;
    *) die "unknown lang: $l (want: py | js | c | all)" ;;
  esac
done

[ -d "$repo" ] || die "not a directory: $repo (usage: $prog <repo> [lang ...])"
context=${CONTEXT:-0}
case "$context" in ''|*[!0-9]*) die "CONTEXT must be a non-negative integer (got: $context)" ;; esac

# --- backend: ripgrep preferred, grep -r fallback ------------------------
have_rg=0
if command -v rg >/dev/null 2>&1; then have_rg=1; fi

scan() {  # scan PATTERN GLOB... -> file:line:text (no match => empty, exit 0)
  pat=$1; shift
  globs=( "$@" ); g=""
  if [ "$have_rg" -eq 1 ]; then
    args=( --no-heading --line-number --with-filename --color=never )
    [ "$context" -gt 0 ] && args+=( -C "$context" )
    [ "${NO_IGNORE:-0}" = "1" ] && args+=( --no-ignore )
    for g in "${globs[@]}"; do args+=( -g "$g" ); done
    rg "${args[@]}" -e "$pat" -- "$repo" 2>/dev/null || true
  else
    args=()
    for g in "${globs[@]}"; do args+=( "--include=$g" ); done
    [ "$context" -gt 0 ] && args+=( -C "$context" )
    grep -rEnI "${args[@]}" -e "$pat" -- "$repo" 2>/dev/null || true
  fi
}

want() { case " $langs " in *" all "*|*" $1 "*) return 0 ;; *) return 1 ;; esac; }

PY="*.py"
JS="*.js *.ts *.mjs *.cjs *.jsx *.tsx"
C_GLOBS="*.c *.h *.cc *.cpp *.cxx *.hpp *.hh *.hxx *.c++ *.cu"

# gsel LANG... -> glob strings for the langs that are BOTH applicable here AND selected
gsel() {
  _o=""
  for _l in "$@"; do
    want "$_l" || continue
    case "$_l" in
      py) _o="$_o $PY" ;;
      js) _o="$_o $JS" ;;
      c)  _o="$_o $C_GLOBS" ;;
    esac
  done
  printf '%s' "$_o"
}

report() {  # report TITLE NOTE PATTERN GLOB...
  title=$1; note=$2; pat=$3; shift 3
  if [ $# -eq 0 ]; then
    printf '\n== %s ==\n' "$title"
    printf '   (no selected language applies to this channel)\n'
    return 0
  fi
  out=$(scan "$pat" "$@")
  # count only match lines (file:line:text); drop rg context rows (file-line-text) and -- separators
  if [ -n "$out" ]; then n=$(printf '%s\n' "$out" | grep -cE ':[0-9]+:' || true); else n=0; fi
  printf '\n== %s == (%s hit%s)\n' "$title" "$n" "$([ "$n" = 1 ] || printf s)"
  if [ -n "$note" ]; then printf '   note: %s\n' "$note"; fi
  if [ -n "$out" ]; then printf '%s\n' "$out"; else printf '   (none)\n'; fi
}

# --- channel patterns -----------------------------------------------------
PAT_LISTEN='(^|[^.[:alnum:]_])(listen|bind|socket)[[:space:]]*\(|0\.0\.0\.0|(^|[^.[:alnum:]_])make_server[[:space:]]*\(|(^|[^.[:alnum:]_])serve([[:alnum:]_]+)?[[:space:]]*\('
PAT_ROUTE='@[[:alnum:]_.]+\.(get|post|put|patch|delete|options|head|route|websocket|api_route)[[:space:]]*\(|(^|[^.[:alnum:]_])(app|router|api|routes?)\.(get|post|put|patch|delete|options|head|all|use)[[:space:]]*\('
PAT_RPC='(^|[^.[:alnum:]_])add_[[:alnum:]_]*[Ss]ervicer[[:alnum:]_]*|grpc[[:alnum:]_.]*\.server|(^|[^.[:alnum:]_])serve[[:space:]]*\('
PAT_MQ='(^|[^.[:alnum:]_])(consume|basic_consume|subscribe|recv|recv_pyobj|recvfrom|on_message)[[:space:]]*\('
PAT_PARSE='(^|[^.[:alnum:]_])(open|fopen|loads?|parse[[:alnum:]_]*)[[:space:]]*\('
PAT_CONFIG='(^|[^.[:alnum:]_])(getenv|add_argument|getopt|getopt_long)[[:space:]]*\(|os\.environ|os\.getenv|process\.env|(^|[^.[:alnum:]_])(argparse|yargs|commander)[[:alnum:]_.]*|--port([^[:alnum:]_]|$)|(^|[^.[:alnum:]_])PORT([^[:alnum:]_]|$)'

printf '# entrypoints — %s   langs: %s   backend: %s   (read-only)\n' \
  "$repo" "$langs" "$([ "$have_rg" -eq 1 ] && echo ripgrep || echo 'grep -r')"

# shellcheck disable=SC2046
report "network listeners / binds" \
  "the bind ADDRESS (0.0.0.0 vs 127.0.0.1) decides who can reach it — read it. 'serve' is broad; confirm it is a server start." \
  "$PAT_LISTEN" $(gsel py js c)

# shellcheck disable=SC2046
report "HTTP route / handler decls" \
  "reuses authz-census.sh's route shapes. Each route is an entry; cross with authz-census.sh to find the ones with no gate (pre-auth = §3b)." \
  "$PAT_ROUTE" $(gsel py js)

# shellcheck disable=SC2046
report "RPC / gRPC servers" \
  "add_*Servicer*_to_server / grpc server / serve(). The service methods are the entry points; their request args are attacker-shaped." \
  "$PAT_RPC" $(gsel py js)

# shellcheck disable=SC2046
report "message-queue consumers" \
  "consume/subscribe/recv(): a queue or socket an attacker may put bytes on. recv + a native-object load() is the §3d deserialization vein." \
  "$PAT_MQ" $(gsel py js c)

# shellcheck disable=SC2046
report "file / stream parsers" \
  "open()/load(s)/parse() are NOISY by design. The entry is real only when the PATH or BYTES come from an in-scope actor (upload, request body, queue) — read the caller." \
  "$PAT_PARSE" $(gsel py js c)

# shellcheck disable=SC2046
report "port / config (argparse / env)" \
  "argparse/add_argument, os.environ/getenv, process.env, --port: shows what's operator-configurable (a default bind addr, a listener on by default) — ties reachability to config." \
  "$PAT_CONFIG" $(gsel py js c)

printf '\n# triage: group the surface by CHANNEL, then for each ask "who can put bytes here?"\n'
printf '#   — reachable by anyone on the network (pre-auth) weights heaviest (STRATEGY §3b).\n'
printf '# entry points are LEADS for the surface map (stage 1), not findings; an unproven\n'
printf '#   path from an in-scope actor is not a finding (Gate A).\n'
printf '# next: record the pre-auth surface in templates/PROGRESS.md; cross listeners+routes\n'
printf '#   with authz-census.sh (the gates) and sink-grep.sh (what the input then reaches).\n'
