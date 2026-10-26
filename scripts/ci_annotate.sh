#!/usr/bin/env bash
# Runs one command for a CI step, mirrors its output, and exits with its code:
# the bash counterpart of ci_annotate.ps1. When the command fails, each failing
# Rust test (its name and the first lines of its panic) and each compiler error
# becomes a GitHub annotation, at most 10. Anyone can read annotations through
# the API, even where a job's log needs a sign-in.
#
# Usage: bash scripts/ci_annotate.sh [--] command [arguments...]
[ "${1-}" = -- ] && shift
if [ $# -eq 0 ]; then
    echo "usage: $0 [--] command [arguments...]" >&2
    exit 2
fi
log=$(mktemp "${TMPDIR:-/tmp}/ci-annotate.XXXXXXXX") || exit 1
trap 'rm -f "$log"' EXIT
"$@" 2>&1 | tee "$log"
code=${PIPESTATUS[0]}
[ "$code" -eq 0 ] && exit 0

# Workflow-command escaping: a message escapes %, CR and LF; a property such
# as the title also escapes : and ,.
escape() {
    local text=$1
    text=${text//'%'/%25}
    text=${text//$'\r'/%0D}
    text=${text//$'\n'/%0A}
    if [ "${2-}" = property ]; then
        text=${text//:/%3A}
        text=${text//,/%2C}
    fi
    printf '%s' "$text"
}

# CARGO_TERM_COLOR=always colors compiler errors, so lines are matched, and
# reported, without their terminal escapes; the mirrored output keeps them.
mapfile -t lines < <(sed -e $'s/\x1b\\[[0-9;]*[A-Za-z]//g' -e $'s/\r$//' "$log")
stdout_block='^---- (.+) stdout ----$'
compile_error='^error(\[E[0-9]+\])?: '
found=0
for ((i = 0; i < ${#lines[@]} && found < 10; i++)); do
    line=${lines[i]}
    if [[ $line =~ $stdout_block ]]; then
        title=${BASH_REMATCH[1]}
    elif [[ $line == 'error: test failed'* ]]; then
        # Cargo's own line, which names the test target to rerun.
        title='tests failed'
    elif [[ $line =~ $compile_error ]]; then
        title='compile error'
    else
        continue
    fi
    message=
    kept=0
    for ((j = i; j <= i + 12 && j < ${#lines[@]} && kept < 10; j++)); do
        body=${lines[j]}
        [ -z "$body" ] && continue
        [[ $body == 'note: run with'* ]] && continue
        message+=${message:+$'\n'}$body
        kept=$((kept + 1))
    done
    message=${message:0:1500}
    printf '::error title=%s::%s\n' "$(escape "$title" property)" "$(escape "$message")"
    found=$((found + 1))
done
if [ "$found" -eq 0 ]; then
    start=$((${#lines[@]} > 15 ? ${#lines[@]} - 15 : 0))
    tail=$(printf '%s\n' "${lines[@]:start}")
    printf '::error title=%s::%s\n' "$(escape "$1 failed ($code)" property)" "$(escape "$tail")"
fi
exit "$code"
