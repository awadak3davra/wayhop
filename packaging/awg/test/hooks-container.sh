#!/bin/sh
# hooks-container.sh -- runs INSIDE a container (docker.sh starts it): the real installer from a fake
# tarball directory, with and without --with-awg, and a stub install-awg.sh that records how it was
# called. openwrt = packaging/openwrt/install.sh in an OpenWrt rootfs; entware = packaging/install.sh
# in Alpine with an /opt. The --no-start runs really install WayHop into the throwaway container.
#
# Usage (in the container): sh hooks-container.sh openwrt|entware   (repository mounted at /repo)
set -u
kind="$1"
fails=0; passes=0
ok() { passes=$((passes + 1)); }
no() { fails=$((fails + 1)); echo "  FAIL  $kind: $1"; [ -n "${2:-}" ] && sed 's/^/        | /' "$2" | tail -n 8; }
check() { ck_d="$1"; shift; if "$@"; then ok; else no "$ck_d" /tmp/out; fi; }

T=/tmp/tarball
fresh() { # a clean tarball directory and no state from an earlier run
  rm -rf "$T" /tmp/awg.log /etc/wayhop /opt/etc/wayhop /opt/var/wayhop /var/lib/wayhop 2>/dev/null
  mkdir -p "$T"
  if [ "$kind" = openwrt ]; then
    cp /repo/packaging/openwrt/install.sh /repo/packaging/openwrt/wayhop.keep /repo/packaging/openwrt/wayhop.init \
      /repo/packaging/openwrt/uninstall.sh "$T/"
  else
    mkdir -p /opt
    cp /repo/packaging/install.sh /repo/packaging/uninstall.sh /repo/packaging/S99wayhop "$T/"
  fi
  cp /repo/packaging/identity-match.sh /repo/packaging/retire-iptv.sh /repo/packaging/harden-state.sh "$T/"
  printf '#!/bin/sh\necho "wayhop 0.0.0 (000000000000, 2026-01-01T00:00:00Z)"\n' > "$T/wayhop-amd64"
  # shellcheck disable=SC2016  # expanded when the stub runs
  printf '#!/bin/sh\necho "$*" >> /tmp/awg.log\nexit "${STUB_AWG_RC:-0}"\n' > "$T/install-awg.sh"
  chmod +x "$T/wayhop-amd64"
}
inst() { sh "$T/install.sh" "$@" < /dev/null > /tmp/out 2>&1; RC=$?; }

fresh; inst --dry-run
check "dry run without --with-awg exits $RC" test "$RC" = 0
check "install-awg.sh ran without --with-awg" test ! -e /tmp/awg.log

fresh; inst --dry-run --with-awg=userspace
check "dry run --with-awg exits $RC" test "$RC" = 0
check "dry run passed '$(cat /tmp/awg.log 2>/dev/null)'" test "$(cat /tmp/awg.log 2>/dev/null)" = "--mode userspace --yes --dry-run"

fresh; inst --no-start -y --with-awg
check "install --no-start --with-awg exits $RC" test "$RC" = 0
check "install passed '$(cat /tmp/awg.log 2>/dev/null)'" test "$(cat /tmp/awg.log 2>/dev/null)" = "--mode auto --yes"
if [ "$kind" = openwrt ]; then check "WayHop was not installed first" test -x /usr/sbin/wayhop
else check "WayHop was not installed first" test -x /opt/sbin/wayhop; fi

fresh; STUB_AWG_RC=2; export STUB_AWG_RC; inst --no-start -y --with-awg; unset STUB_AWG_RC
check "a refused AmneziaWG exits $RC, want 2" test "$RC" = 2
check "the refusal is not explained" grep -q 'AmneziaWG NOT installed: refused' /tmp/out

fresh; STUB_AWG_RC=1; export STUB_AWG_RC; inst --no-start -y --with-awg; unset STUB_AWG_RC
check "a failed AmneziaWG exits $RC, want 1" test "$RC" = 1

fresh; rm -f "$T/install-awg.sh"; inst --dry-run --with-awg
check "no install-awg.sh and no network exits $RC, want 1" test "$RC" = 1

echo "  $kind: $passes checks passed, $fails failed"
[ "$fails" = 0 ]
