#!/usr/bin/env bash
#
# sink-grep.sh — grep a repo for dangerous sinks, grouped by class.
#
# critlover stages 2-3 (bucket design / fan-out). READ-ONLY recon: a ripgrep
# pass (falls back to grep -r) that lists candidate sinks as file:line:text,
# grouped by bug class. It finds *where the matches are*; it does NOT decide
# whether anything is reachable, attacker-controlled, or a bug. Every hit is
# a lead for stage-4 verification, never a finding.
#
# Classes (languages in parens):
#   deser     unsafe deserialization  — py pickle/cloudpickle/recv_pyobj/torch.load/
#             yaml.load/marshal; js node-serialize/unserialize; java readObject/
#             ObjectInputStream/XMLDecoder/XStream; ruby Marshal.load/Oj.load; php
#             unserialize; go gob               (py/js/java/ruby/php/go)
#   exec      code-exec sinks         — py exec/eval/compile/os.system/os.popen/
#             subprocess/pty.spawn; js child_process/.exec/new Function; java
#             Runtime.exec/ProcessBuilder; go exec.Command; ruby+php system/exec/
#             passthru/shell_exec               (py/js/java/go/ruby/php)
#   ssti      template injection      — py render_template_string/Template/.from_string/
#             .render; js handlebars/nunjucks/lodash/ejs/pug   (py/js)
#   native    memory sinks            — C memcpy/memmove/alloca/strcpy/strcat/sprintf/
#             gets; Rust unsafe{/transmute/from_raw_parts/copy_nonoverlapping/
#             get_unchecked                     (c/c++/rust)
#
# Usage:
#   sink-grep.sh [repo] [class ...]
#
#   repo       path to scan                (default: current directory)
#   class ...  one or more of: deser exec ssti native all   (default: all)
#
# Env:
#   NO_IGNORE=1   also scan .gitignored / vendored paths (default: respect .gitignore)
#   CONTEXT=N     print N lines of context around each hit (default: 0)
#
# honest-grading reminder (STRATEGY §5): a sink with no proven path from an
# in-scope actor is not a finding. For each hit, in order: source-verify
# reachability -> dup-check (dup-check-notes.md) ->
# recalibrate severity vs the vendor rubric. Default-skeptical of every CRIT.
#
set -eu
set -f  # the glob strings below are regex/file-glob LITERALS for rg/grep — never shell-expand them

prog=${0##*/}
die() { printf '%s: %s\n' "$prog" "$1" >&2; exit "${2:-2}"; }

usage() {
  cat <<EOF
$prog — grep a repo for dangerous sinks, grouped by class (critlover stage 2-3).

READ-ONLY: ripgrep (or grep -r) listing candidate sinks as file:line:text. It finds matches;
it does NOT judge reachability or severity. Every hit is a stage-4 lead, not a finding.

Usage:
  $prog [repo] [class ...]

  repo       path to scan                        (default: current directory)
  class ...  deser | exec | ssti | native | all  (default: all)

Env:
  NO_IGNORE=1   also scan .gitignored / vendored paths (default: respect .gitignore)
  CONTEXT=N     lines of context around each hit        (default: 0)

Classes (multi-language):
  deser   py/js/java/ruby/php/go native-object deserializers  (network-reachable = §3d vein)
  exec    py/js/java/go/ruby/php command/code execution (exec/eval/system/spawn/Runtime.exec…)
  ssti    py/js attacker-controlled template TEXT (render_template_string, from_string, handlebars…)
  native  C/C++ memcpy/strcpy/sprintf… + Rust unsafe{/transmute/from_raw_parts  (length/index is MANUAL)
EOF
}

# --- arg parse ------------------------------------------------------------
for a in "$@"; do case "$a" in -h|--help) usage; exit 0 ;; esac; done

repo="."
if [ $# -gt 0 ]; then
  case "$1" in
    deser|exec|ssti|native|all) : ;;   # first arg is a class -> repo stays cwd
    *) repo=$1; shift ;;
  esac
fi
classes="$*"
[ -n "$classes" ] || classes="all"

[ -d "$repo" ] || die "not a directory: $repo (usage: $prog [repo] [class ...])"
context=${CONTEXT:-0}
case "$context" in ''|*[!0-9]*) die "CONTEXT must be a non-negative integer" ;; esac

# --- backend: ripgrep preferred, grep -r fallback ------------------------
have_rg=0
if command -v rg >/dev/null 2>&1; then have_rg=1; fi

# scan PATTERN GLOB... -> prints file:line:text (no match => empty, exit 0)
scan() {
  pat=$1; shift
  globs=( "$@" )
  g=""
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

report() {
  # report TITLE NOTE PATTERN GLOB...
  title=$1; note=$2; pat=$3; shift 3
  out=$(scan "$pat" "$@")
  # count only match lines (file:line:text); drop rg context rows (file-line-text) and -- separators
  if [ -n "$out" ]; then n=$(printf '%s\n' "$out" | grep -cE ':[0-9]+:' || true); else n=0; fi
  printf '\n== %s == (%s hit%s)\n' "$title" "$n" "$([ "$n" = 1 ] || printf s)"
  if [ -n "$note" ]; then printf '   note: %s\n' "$note"; fi
  if [ -n "$out" ]; then printf '%s\n' "$out"; else printf '   (none)\n'; fi
}

want() { case " $classes " in *" all "*|*" $1 "*) return 0 ;; *) return 1 ;; esac; }

PY="*.py"
JS="*.js *.ts *.mjs *.cjs *.jsx *.tsx"
C_GLOBS="*.c *.h *.cc *.cpp *.cxx *.hpp *.hh *.hxx *.c++ *.cu"
RS="*.rs"
GO="*.go"
JAVA="*.java"
RUBY="*.rb"
PHP="*.php"

printf '# sink-grep — %s   classes: %s   backend: %s   (read-only)\n' \
  "$repo" "$classes" "$([ "$have_rg" -eq 1 ] && echo ripgrep || echo 'grep -r')"

if want deser; then
  # the glob LISTS below ($PY $JS …) are meant to word-split into separate -g args; set -f guards globbing
  # shellcheck disable=SC2086
  report "deserialization sinks (py/js/java/ruby/php/go)" \
    "Safe forms exist per language (yaml.safe_load, JSON, Loader=SafeLoader) — confirm which. §3d: a native-object deserializer fed from a network-reachable channel is the recurring crit vein." \
    'pickle\.loads?\(|cPickle\.loads?\(|_pickle\.loads?\(|cloudpickle|recv_pyobj\(|torch\.load\(|yaml\.load\(|marshal\.loads?\(|node-serialize|(^|[^.[:alnum:]_])unserialize[[:space:]]*\(|readObject[[:space:]]*\(|readUnshared[[:space:]]*\(|ObjectInputStream|XMLDecoder|XStream|Marshal\.load[[:space:]]*\(|Oj\.load[[:space:]]*\(|gob\.NewDecoder[[:space:]]*\(' \
    $PY $JS $JAVA $RUBY $PHP $GO
fi

if want exec; then
  # the glob LISTS below ($PY $JS …) are meant to word-split into separate -g args; set -f guards globbing
  # shellcheck disable=SC2086
  report "code-exec sinks (py/js/java/go/ruby/php)" \
    "re.compile()/str.format()/regex.exec() are benign common matches — filter them. The crit is attacker-controlled bytes reaching exec/eval or a shell." \
    '(^|[^.[:alnum:]_])(exec|eval|compile)[[:space:]]*\(|shell[[:space:]]*=[[:space:]]*True|os\.(system|popen)[[:space:]]*\(|subprocess\.(run|call|check_output|check_call|Popen)[[:space:]]*\(|pty\.spawn[[:space:]]*\(|__import__[[:space:]]*\(|child_process|\.execSync[[:space:]]*\(|\.exec[[:space:]]*\(|spawnSync[[:space:]]*\(|new[[:space:]]+Function[[:space:]]*\(|Runtime\.getRuntime|ProcessBuilder[[:space:]]*\(|exec\.Command[[:space:]]*\(|(^|[^.[:alnum:]_])(system|passthru|shell_exec|proc_open|popen)[[:space:]]*\(' \
    $PY $JS $JAVA $GO $RUBY $PHP
fi

if want ssti; then
  # the glob LISTS below ($PY $JS) are meant to word-split into separate -g args; set -f guards globbing
  # shellcheck disable=SC2086
  report "template-injection (SSTI) sinks (py/js)" \
    ".render(/Template( are noisy (string.Template and fixed templates are fine). SSTI = attacker-controlled template TEXT, not template data. from_string(user_input) is the classic." \
    'render_template_string[[:space:]]*\(|(^|[^.[:alnum:]_])Template[[:space:]]*\(|\.from_string[[:space:]]*\(|\.render[[:space:]]*\(|handlebars\.compile[[:space:]]*\(|nunjucks\.|_\.template[[:space:]]*\(|ejs\.render|pug\.(compile|render)' \
    $PY $JS
fi

if want native; then
  # the glob LISTS below ($C_GLOBS $RS) are meant to word-split into separate -g args; set -f guards globbing
  # shellcheck disable=SC2086
  report "native memory sinks (C/C++ + Rust unsafe)" \
    "Lists the CALLS / unsafe sites only. Whether the length/size/index is attacker-controlled (guest/network) is a MANUAL check — that delta is the whole finding. C: see also strcat/sprintf/gets. Rust: audit the unsafe block's invariants." \
    '(^|[^.[:alnum:]_])(memcpy|memmove|alloca|strcpy|strcat|sprintf|gets)[[:space:]]*\(|(^|[^.[:alnum:]_])unsafe[[:space:]]*\{|transmute[[:space:]]*(::<[^>]*>)?[[:space:]]*\(|from_raw_parts|copy_nonoverlapping|get_unchecked|slice::from_raw' \
    $C_GLOBS $RS
fi

printf '\n# triage: hits are candidates, not bugs. For each -> (1) prove an in-scope actor\n'
printf '#         can reach it, (2) dup-check (dup-check-notes.md), (3) re-score vs the\n'
printf '#         vendor rubric. Capped by a documented carve-out? downgrade, never inflate.\n'
