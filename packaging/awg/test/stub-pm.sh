#!/bin/sh
# stub-pm.sh -- a stand-in package manager for run.sh (AWG_INSTALL_PKG). It answers the apk or
# opkg subcommands install-awg.sh uses, with the output shapes of the real tools (checked against
# apk-tools 3.0.2 on OpenWrt 25.12.0 and opkg 2024-10-16 on OpenWrt 24.10.4), over a small text
# database in $AWG_STUB_DIR:
#   kind          apk | opkg
#   arch          the architecture print-architecture reports
#   installed     "name version" per installed package
#   available     "name version" a feed would install
#   deps          "name dependency dependency-version": install pulls the dependency in (listed in
#                 "auto"), remove refuses a package another installed package depends on (like
#                 opkg), and apk's del also removes a pulled-in dependency nothing needs any more
#   update_rc     exit code of `update` (default 0)
#   fail_install  when present, install stops with an error after the first package
#   slow_install  when present, install sleeps that many seconds first (for interrupt tests)
#   files         "name path": install writes $AWG_INSTALL_ROOT<path> ("name version"), remove
#                 deletes it -- the payload file a test cares about (the netifd proto handler)
#   log           every call, one line each (appended)
S="${AWG_STUB_DIR:?AWG_STUB_DIR is not set}"
kind="$(cat "$S/kind")"
echo "$*" >> "$S/log"
inst="$S/installed"
[ -f "$inst" ] || : > "$inst"

iv() { awk -v n="$1" '$1 == n { print $2; exit }' "$inst"; }
av() { awk -v n="$1" '$1 == n { print $2; exit }' "$S/available" 2>/dev/null; }
set_inst() { # name version (empty version = remove)
  awk -v n="$1" '$1 != n' "$inst" > "$inst.t"
  [ -n "$2" ] && echo "$1 $2" >> "$inst.t"
  mv "$inst.t" "$inst"
}
vcmp() { # a b -> < = >
  awk -v a="$1" -v b="$2" 'BEGIN {
    na = split(a, x, /[^0-9A-Za-z]+/); nb = split(b, y, /[^0-9A-Za-z]+/); n = (na > nb ? na : nb)
    for (i = 1; i <= n; i++) {
      p = x[i]; q = y[i]
      if (p == q) continue
      if (p ~ /^[0-9]+$/ && q ~ /^[0-9]+$/) { print (p + 0 < q + 0 ? "<" : ">"); exit }
      print (p < q ? "<" : ">"); exit
    }
    print "="
  }'
}
payload() { # name version (empty = remove)
  awk -v n="$1" '$1 == n { print $2 }' "$S/files" 2>/dev/null | while read -r f; do
    if [ -n "$2" ]; then mkdir -p "$AWG_INSTALL_ROOT${f%/*}"; echo "$1 $2" > "$AWG_INSTALL_ROOT$f"
    else rm -f "$AWG_INSTALL_ROOT$f"; fi
  done
}
do_install() {
  [ -f "$S/slow_install" ] && sleep "$(cat "$S/slow_install")"
  for p in "$@"; do
    v="$(av "$p")"
    [ -n "$v" ] || { echo "Unknown package '$p'."; return 255; }
    awk -v n="$p" '$1 == n { print $2, $3 }' "$S/deps" 2>/dev/null | while read -r d dv; do
      [ -n "$(iv "$d")" ] || { set_inst "$d" "$dv"; echo "$d" >> "$S/auto"; }
    done
    set_inst "$p" "$v"
    payload "$p" "$v"
    if [ -f "$S/fail_install" ]; then echo "simulated failure after $p"; return 1; fi
  done
}
do_remove() {
  rc=0
  for p in "$@"; do
    [ -n "$(iv "$p")" ] || continue
    needed="$(awk -v n="$p" '$2 == n { print $1 }' "$S/deps" 2>/dev/null | while read -r x; do
      [ -n "$(iv "$x")" ] && printf ' %s' "$x"; done)"
    if [ -n "$needed" ]; then echo "cannot remove $p: needed by$needed"; rc=1; continue; fi
    set_inst "$p" ""
    payload "$p" ""
    # apk removes a dependency it pulled in once nothing needs it any more; opkg does not.
    if [ "$kind" = apk ]; then
      awk -v n="$p" '$1 == n { print $2 }' "$S/deps" 2>/dev/null | while read -r d; do
        grep -qx "$d" "$S/auto" 2>/dev/null || continue
        still="$(awk -v n="$d" '$2 == n { print $1 }' "$S/deps" | while read -r x; do [ -n "$(iv "$x")" ] && echo "$x"; done)"
        [ -z "$still" ] && set_inst "$d" ""
      done
    fi
  done
  return "$rc"
}

case "$kind:$1" in
  opkg:status)
    v="$(iv "$2")"
    [ -n "$v" ] && printf 'Package: %s\nVersion: %s\nStatus: install user installed\nArchitecture: %s\n\n' "$2" "$v" "$(cat "$S/arch")"
    exit 0 ;;
  opkg:list-installed) awk '{ print $1 " - " $2 }' "$inst"; exit 0 ;;
  opkg:print-architecture) printf 'arch all 1\narch noarch 1\narch %s 10\n' "$(cat "$S/arch")"; exit 0 ;;
  opkg:update|apk:update) exit "$(cat "$S/update_rc" 2>/dev/null || echo 0)" ;;
  opkg:install) shift; do_install "$@"; exit $? ;;
  opkg:remove) shift; do_remove "$@"; exit $? ;;
  opkg:compare-versions)
    r="$(vcmp "$2" "$4")"
    case "$3" in
      '>=') [ "$r" != "<" ] ;;
      '<<') [ "$r" = "<" ] ;;
      *) exit 2 ;;
    esac
    exit $? ;;
  apk:list)
    shift
    [ "${1:-}" = --manifest ] && shift
    [ "${1:-}" = -I ] && shift
    if [ $# -eq 0 ]; then cat "$inst"; else for p in "$@"; do v="$(iv "$p")"; [ -n "$v" ] && echo "$p $v"; done; fi
    exit 0 ;;
  apk:add) shift; [ "${1:-}" = -u ] && shift; do_install "$@"; exit $? ;;
  apk:del) shift; do_remove "$@"; exit $? ;;
  apk:version) [ "$2" = -t ] && vcmp "$3" "$4"; exit 0 ;;
  apk:adbdump) cat "$2"; exit $? ;;   # the fixture feed's packages.adb is already the dump text
esac
echo "stub-pm: unsupported call: $*" >&2
exit 99
