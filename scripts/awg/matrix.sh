#!/bin/sh
# matrix.sh - the GitHub Actions build matrix for the OpenWrt AmneziaWG packages, from targets.txt.
#
# packaging/awg/targets.txt is the only list of what gets built: one line per SDK build,
# `<release> <target>/<subtarget> [smoke]`. A branch push builds the `smoke` lines, a tag or the
# weekly schedule builds every line. This prints that list as the JSON object a workflow passes to
# `strategy.matrix` through fromJSON(), so the workflow carries no second copy of it.
#
# Usage: matrix.sh <smoke|full> [kmod|e2e]
#   kmod (default)  every selected line:          {"include":[{"release","target","id"},...]}
#   e2e             the selected lines QEMU boots: x86/64 (kmod + userspace cases, 256 MiB) and
#                   malta/le (kmod + userspace cases, 64 MiB - the small-RAM router), plus "mem","cases"
# The path to targets.txt can be overridden with AWG_TARGETS (used by the self-test fixtures).
#
# Refuses (exit 2) a malformed line, an unknown flag or a duplicate build, and (exit 1) a selection
# that comes out empty: an empty matrix makes GitHub skip the job, which reads as green.
set -eu

usage() { echo "usage: matrix.sh <smoke|full> [kmod|e2e]" >&2; exit 2; }
[ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage
scope="$1"
kind="${2:-kmod}"
case "$scope" in smoke|full) ;; *) usage ;; esac
case "$kind" in kmod|e2e) ;; *) usage ;; esac

here="$(cd "$(dirname "$0")" && pwd)"
list="${AWG_TARGETS:-$here/../../packaging/awg/targets.txt}"
[ -f "$list" ] || { echo "matrix.sh: $list is missing" >&2; exit 2; }

seen=" "
out=""
n=0
lineno=0
# The last line may lack a newline; `|| [ -n "$line" ]` still reads it.
while IFS= read -r line || [ -n "$line" ]; do
  lineno=$((lineno + 1))
  line="$(printf '%s' "$line" | tr -d '\r')"
  case "$line" in ''|\#*) continue ;; esac
  # shellcheck disable=SC2086  # the line is split into its fields on purpose
  set -- $line
  [ "$#" -ge 2 ] && [ "$#" -le 3 ] || { echo "matrix.sh: $list:$lineno: expected '<release> <target>/<subtarget> [smoke]': $line" >&2; exit 2; }
  rel="$1"; tgt="$2"; flag="${3:-}"
  printf '%s\n' "$rel" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' \
    || { echo "matrix.sh: $list:$lineno: release '$rel' is not MAJOR.MINOR.PATCH" >&2; exit 2; }
  printf '%s\n' "$tgt" | grep -Eq '^[a-z0-9_-]+/[a-z0-9_-]+$' \
    || { echo "matrix.sh: $list:$lineno: target '$tgt' is not <target>/<subtarget>" >&2; exit 2; }
  case "$flag" in ''|smoke) ;; *) echo "matrix.sh: $list:$lineno: unknown flag '$flag'" >&2; exit 2 ;; esac
  id="$rel-$(printf '%s' "$tgt" | tr '/' '-')"
  case "$seen" in *" $id "*) echo "matrix.sh: $list:$lineno: duplicate build $rel $tgt" >&2; exit 2 ;; esac
  seen="$seen$id "
  [ "$scope" = full ] || [ "$flag" = smoke ] || continue
  if [ "$kind" = e2e ]; then
    case "$tgt" in
      x86/64)   extra=',"mem":"256","cases":"kmod userspace"' ;;
      malta/le) extra=',"mem":"64","cases":"kmod userspace"' ;;
      *) continue ;;
    esac
  else
    extra=""
  fi
  item="{\"release\":\"$rel\",\"target\":\"$tgt\",\"id\":\"$id\"$extra}"
  out="${out:+$out,}$item"
  n=$((n + 1))
done < "$list"

[ "$n" -gt 0 ] || { echo "matrix.sh: no $kind build selected for scope '$scope' in $list" >&2; exit 1; }
printf '{"include":[%s]}\n' "$out"
