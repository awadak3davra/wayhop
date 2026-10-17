#!/bin/sh
# qemu-guest.sh - the in-guest half of scripts/awg/qemu-e2e.sh. Runs on the OpenWrt VM (busybox ash),
# fetched from the runner's test HTTP server, one phase per call. Every result is one
# `E2E <key>=<value>` line on stdout; the host side decides PASS/FAIL from those lines, so this
# script reports and does not judge. State between phases lives in /tmp/awg-e2e.*.
#
# Usage: sh qemu-guest.sh <base-url> <phase> [args]
#   prep                             parameters, the throwaway feed keys, a snapshot of what is
#                                    installed and configured (the uninstall must return to it)
#   install <tag> <mode> [flags]     install-awg.sh --mode <mode> --feed <base>/feed --yes --json [flags]
#   configure                        a netifd amneziawg interface with every 3.1 option, then a
#                                    network reload (not a restart)
#   restart                          /etc/init.d/network restart
#   tunnel <tag>                     link, handshake, the options the interface really carries
#                                    (awg showconf), ping through it, which engine runs it, memory
#   uninstall <tag> [flags]          install-awg.sh --uninstall --yes --json [flags], then what is
#                                    left compared with the prep snapshot
#   userspace-start                  amneziawg-go started by hand: link + UAPI socket
# Files under <base-url>: e2e/params.env (made by the host for this run), e2e/usign.pub and
# e2e/apk.pem.pub (the throwaway keys that signed the test feed), feed/ (feed-layout.sh output).
set -u

BASE="${1:?base url}"
PHASE="${2:?phase}"
shift 2
FEED="$BASE/feed"
ENVF=/tmp/awg-e2e.env

say() { echo "E2E $1=$2"; }
fetch() { wget -q -O "$2" "$1"; }

if [ "$PHASE" = prep ]; then
  fetch "$BASE/e2e/params.env" "$ENVF" || { say error "cannot fetch params.env"; exit 1; }
fi
# shellcheck disable=SC1090  # written by the host for this run
. "$ENVF"
# shellcheck disable=SC1091
. /etc/openwrt_release
if command -v apk >/dev/null 2>&1 && [ -d /etc/apk ]; then PM=apk; else PM=opkg; fi

mem() {
  say "${1}_mem_available_kib" "$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)"
  fs=/; [ -d /overlay ] && fs=/overlay
  say "${1}_flash_free_kib" "$(df -k "$fs" | awk 'NR==2{print $4}')"
}

# Everything an install may add and an uninstall must take away again: packages, the package
# manager's own state, feed lines and keys, and the files the AmneziaWG packages ship.
snapshot() {
  {
    if [ "$PM" = apk ]; then
      apk info 2>/dev/null | sed 's/^/pkg /' | sort
      sed 's/^/world /' /etc/apk/world
      ls /etc/apk/keys | sed 's/^/key /'
      for f in /etc/apk/repositories /etc/apk/repositories.d/*; do [ -f "$f" ] && sed "s#^#repo $f #" "$f"; done
    else
      opkg list-installed 2>/dev/null | awk '{ print "pkg " $1 }' | sort
      ls /etc/opkg/keys | sed 's/^/key /'
      for f in /etc/opkg/customfeeds.conf /etc/opkg/distfeeds.conf; do [ -f "$f" ] && sed "s#^#repo $f #" "$f"; done
    fi
    for f in /usr/bin/awg /usr/bin/amneziawg-go /lib/netifd/proto/amneziawg.sh \
      /www/luci-static/resources/protocol/amneziawg.js /etc/modules.d/amneziawg; do
      [ -e "$f" ] && echo "file $f"
    done
    find /lib/modules -name amneziawg.ko 2>/dev/null | sed 's/^/file /'
  } > "$1"
}

run_installer() { # <tag> <args...>
  tag="$1"; shift
  fetch "$FEED/awg/install-awg.sh" /tmp/install-awg.sh || { say "${tag}_rc" 127; say "${tag}_json" "no-installer"; return; }
  t0=$(date +%s)
  sh /tmp/install-awg.sh --feed "$FEED" --yes --json "$@" > /tmp/awg-install.log 2>&1
  rc=$?
  sed 's/^/| /' /tmp/awg-install.log
  say "${tag}_rc" "$rc"
  say "${tag}_json" "$(tail -n 1 /tmp/awg-install.log)"
  say "${tag}_seconds" "$(( $(date +%s) - t0 ))"
}

kmod_loaded() { if grep -q '^amneziawg ' /proc/modules; then echo yes; else echo no; fi; }

case "$PHASE" in
prep)
  say distrib_release "$DISTRIB_RELEASE"
  say distrib_target "$DISTRIB_TARGET"
  say kernel "$(uname -r)"
  say pkg_manager "$PM"
  say mem_total_kib "$(awk '/^MemTotal:/{print $2}' /proc/meminfo)"
  if [ -d /www/luci-static ]; then say luci_present yes; else say luci_present no; fi
  # The test feed is signed with throwaway keys (scripts/awg/qemu-feed-sign.sh). Trust them here,
  # the way a router trusts WayHop's real keys; the installer still adds the real keys itself.
  if [ "$PM" = apk ]; then
    fetch "$BASE/e2e/apk.pem.pub" /etc/apk/keys/wayhop-test.pem || { say error "cannot fetch the apk key"; exit 1; }
  else
    if ! { fetch "$BASE/e2e/usign.pub" /tmp/wayhop-test.pub && opkg-key add /tmp/wayhop-test.pub >/dev/null; }; then
      say error "cannot install the usign key"; exit 1
    fi
  fi
  snapshot /tmp/awg-e2e.before
  say snapshot_lines "$(wc -l < /tmp/awg-e2e.before)"
  mem before
  ;;

install)
  tag="$1"; mode="$2"; shift 2
  run_installer "$tag" --mode "$mode" "$@"
  say "${tag}_kmod_loaded" "$(kmod_loaded)"
  say "${tag}_awg_version" "$(awg --version 2>&1 | head -n 1)"
  if [ -e /www/luci-static/resources/protocol/amneziawg.js ]; then say "${tag}_luci_proto" yes; else say "${tag}_luci_proto" no; fi
  if [ -e /lib/netifd/proto/amneziawg.sh ]; then say "${tag}_proto_handler" yes; else say "${tag}_proto_handler" no; fi
  ;;

configure)
  uci -q delete network.awg0
  uci -q delete network.awgpeer
  uci batch <<EOF
set network.awg0=interface
set network.awg0.proto='amneziawg'
set network.awg0.private_key='$GUEST_PRIV'
add_list network.awg0.addresses='$GUEST_ADDR/24'
set network.awg0.awg_jc='$AWG_JC'
set network.awg0.awg_jmin='$AWG_JMIN'
set network.awg0.awg_jmax='$AWG_JMAX'
set network.awg0.awg_s1='$AWG_S1'
set network.awg0.awg_s2='$AWG_S2'
set network.awg0.awg_s3='$AWG_S3'
set network.awg0.awg_s4='$AWG_S4'
set network.awg0.awg_h1='$AWG_H1'
set network.awg0.awg_h2='$AWG_H2'
set network.awg0.awg_h3='$AWG_H3'
set network.awg0.awg_h4='$AWG_H4'
set network.awg0.awg_i1='$AWG_I1'
set network.awg0.awg_header_protection_key='$AWG_HPK'
set network.awg0.awg_random_trailers='$AWG_RANDOM_TRAILERS'
set network.awg0.awg_disable_cookies='$AWG_DISABLE_COOKIES'
set network.awgpeer=amneziawg_awg0
set network.awgpeer.public_key='$PEER_PUB'
add_list network.awgpeer.allowed_ips='$PEER_ADDR/32'
set network.awgpeer.endpoint_host='$PEER_HOST'
set network.awgpeer.endpoint_port='$PEER_PORT'
set network.awgpeer.persistent_keepalive='5'
EOF
  uci commit network
  # The tunnel joins the lan zone so the peer may ping into it.
  if ! uci -q get 'firewall.@zone[0].network' | grep -qw awg0; then
    uci add_list 'firewall.@zone[0].network=awg0'
    uci commit firewall
  fi
  /etc/init.d/firewall reload >/dev/null 2>&1
  # A reload, deliberately: whether it is enough depends on netifd already knowing the protocol.
  /etc/init.d/network reload
  i=0
  while ! ip link show awg0 >/dev/null 2>&1 && [ "$i" -lt 10 ]; do i=$((i + 1)); sleep 1; done
  if ip link show awg0 >/dev/null 2>&1; then say link_after_reload yes; else say link_after_reload no; fi
  ;;

restart)
  /etc/init.d/network restart
  ;;

tunnel)
  tag="$1"
  i=0
  while ! ip link show awg0 >/dev/null 2>&1 && [ "$i" -lt 30 ]; do i=$((i + 1)); sleep 1; done
  if ip link show awg0 >/dev/null 2>&1; then say "${tag}_link" yes; else say "${tag}_link" no; fi
  hs=0; i=0
  while [ "$i" -lt 45 ]; do
    hs=$(awg show awg0 latest-handshakes 2>/dev/null | awk '{print $2}' | head -n 1)
    [ -n "$hs" ] && [ "$hs" != 0 ] && break
    i=$((i + 1)); sleep 1
  done
  say "${tag}_handshake" "${hs:-0}"
  say "${tag}_handshake_wait" "$i"
  # What the interface really carries, read back from the engine, against what uci was given.
  awg showconf awg0 2>/dev/null | grep -v '^PrivateKey' > /tmp/awg-e2e.conf
  sed 's/^/| /' /tmp/awg-e2e.conf
  bad=""
  for kv in "Jc=$AWG_JC" "Jmin=$AWG_JMIN" "Jmax=$AWG_JMAX" "S1=$AWG_S1" "S2=$AWG_S2" "S3=$AWG_S3" \
    "S4=$AWG_S4" "H1=$AWG_H1" "H2=$AWG_H2" "H3=$AWG_H3" "H4=$AWG_H4" "I1=$AWG_I1" \
    "HeaderProtectionKey=$AWG_HPK" "RandomTrailers=on" "DisableCookies=on"; do
    k="${kv%%=*}"; want="${kv#*=}"
    got="$(awk -v k="$k" 'index($0, k " = ") == 1 { print substr($0, length(k) + 4); exit }' /tmp/awg-e2e.conf)"
    [ "$got" = "$want" ] || bad="$bad $k"
  done
  bad="${bad# }"
  say "${tag}_conf_mismatch" "${bad:-none}"
  # Bound to awg0: the peer's address also lives on the runner, and QEMU user networking would
  # answer a ping sent the ordinary way without the tunnel being involved at all.
  if ping -I awg0 -c 3 -W 3 "$PEER_ADDR" >/tmp/awg-ping.log 2>&1; then say "${tag}_ping" ok; else say "${tag}_ping" fail; fi
  sed 's/^/| /' /tmp/awg-ping.log
  say "${tag}_transfer" "$(awg show awg0 transfer 2>/dev/null | awk '{ print "rx=" $2 " tx=" $3; exit }')"
  say "${tag}_kmod_loaded" "$(kmod_loaded)"
  if pidof amneziawg-go >/dev/null 2>&1; then say "${tag}_go_running" yes; else say "${tag}_go_running" no; fi
  if [ -S /var/run/amneziawg/awg0.sock ]; then say "${tag}_go_socket" /var/run/amneziawg/awg0.sock; else say "${tag}_go_socket" none; fi
  logread 2>/dev/null | grep -iE 'amneziawg|netifd' | tail -n 8 | sed 's/^/| /'
  mem "$tag"
  ;;

uninstall)
  tag="$1"; shift
  run_installer "$tag" --uninstall "$@"
  snapshot /tmp/awg-e2e.after
  extra="$(awk 'NR == FNR { a[$0] = 1; next } !($0 in a) { printf "+%s;", $0 }' /tmp/awg-e2e.before /tmp/awg-e2e.after)"
  gone="$(awk 'NR == FNR { a[$0] = 1; next } !($0 in a) { printf "-%s;", $0 }' /tmp/awg-e2e.after /tmp/awg-e2e.before)"
  say "${tag}_residue" "${extra}${gone}"
  say "${tag}_kmod_loaded" "$(kmod_loaded)"
  if ip link show awg0 >/dev/null 2>&1; then say "${tag}_link" yes; else say "${tag}_link" no; fi
  if pidof amneziawg-go >/dev/null 2>&1; then say "${tag}_go_running" yes; else say "${tag}_go_running" no; fi
  mem "$tag"
  ;;

userspace-start)
  if command -v amneziawg-go >/dev/null 2>&1; then
    say go_version "$(amneziawg-go --version 2>&1 | head -n 1)"
    amneziawg-go awgu0 > /tmp/awgu0.log 2>&1
    sleep 3
    if ip link show awgu0 >/dev/null 2>&1; then say go_link yes; else say go_link no; fi
    sock=""
    for d in /var/run/amneziawg /tmp/wayhop/amneziawg; do
      [ -S "$d/awgu0.sock" ] && { sock="$d/awgu0.sock"; break; }
    done
    say go_socket "${sock:-none}"
    ip link del awgu0 2>/dev/null
    sleep 1
    killall amneziawg-go 2>/dev/null
  else
    say go_version none
  fi
  ;;

*)
  say error "unknown phase $PHASE"; exit 2 ;;
esac
exit 0
