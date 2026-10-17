#!/bin/sh
# qemu-e2e.sh - AmneziaWG 3.1 end to end on a real OpenWrt in QEMU, from WayHop's own feed.
#
# Boots the official OpenWrt image of <release> for <target/sub> (downloaded from downloads.openwrt.org
# and checked against that release's sha256sums), points the guest at a locally served copy of the
# feed (feed-layout.sh output, signed with the throwaway keys of qemu-feed-sign.sh) and drives
# install-awg.sh through a whole life cycle. Each case is one fresh VM:
#
#   kmod       install --mode kmod (no --restart-network): installed through the kernel path, the
#              module loaded, `awg --version` the pinned tools version, the LuCI page where the image
#              has LuCI, and netifd_restart_needed reported. An `amneziawg` netifd interface with every
#              3.1 option (Jc/Jmin/Jmax, S1-S4, H1-H4 ranges, I1, HeaderProtectionKey, RandomTrailers,
#              DisableCookies) is configured and the network restarted by hand, as the installer says;
#              the interface must then carry exactly those options (awg showconf), handshake with a peer
#              on this host and pass pings both ways. Uninstall (no residue against a snapshot taken
#              before the install), install again WITH --restart-network (the interface must come up
#              with no hand restart), and uninstall with --restart-network (no residue).
#   userspace  install --mode userspace --restart-network: amneziawg-go starts by hand, and the same
#              netifd interface comes up on amneziawg-go (no kernel module present) with the same
#              checks; then uninstall, no residue.
#
# The peer is the userspace amneziawg-go (+ awg) for amd64 running HERE, in this network namespace;
# QEMU user networking shows this host to the guest as 10.0.2.2, so the guest's UDP reaches the peer
# on 127.0.0.1 and the guest's HTTP reaches the feed server on 127.0.0.1. Needs root (the peer makes a
# TUN device), qemu-system-x86_64 / qemu-system-mipsel, python3, iproute2. KVM is used when /dev/kvm
# is usable, otherwise TCG. scripts/awg/qemu-docker.sh runs this inside a pinned container.
#
# Usage: qemu-e2e.sh <feedroot> <release> <target/subtarget>     (x86/64 or malta/le)
# Env:   AWG_E2E_KEYS         dir with usign.pub + apk.pem.pub that signed the feed (required)
#        AWG_E2E_PEER_DIR     dir with amneziawg-go + awg for this host (default dist/awg/userspace/amd64)
#        AWG_E2E_CACHE        image cache dir (default ${XDG_CACHE_HOME:-~/.cache}/wayhop-awg-e2e)
#        AWG_E2E_OUT          where logs and the summary are kept (default: the work dir)
#        AWG_E2E_CASES        default "kmod userspace"
#        AWG_E2E_MEM          guest RAM in MiB (default 256 on x86/64, 64 on malta/le)
#        AWG_E2E_EXPECT_TOOLS expected `awg --version` (default AWG_TOOLS_TAG of packaging/awg/VERSIONS)
#        AWG_E2E_SUMMARY      file to append the summary to (e.g. $GITHUB_STEP_SUMMARY)
# Exit:  0 every check passed, 1 a check failed, 2 usage/environment.
set -eu

die() { echo "qemu-e2e: $*" >&2; exit 2; }
[ "$#" -eq 3 ] || die "usage: qemu-e2e.sh <feedroot> <release> <target/subtarget>"
FEED="$1"; REL="$2"; TGT="$3"
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
# shellcheck disable=SC1091  # the pins file is POSIX-sh by contract
. "$repo/packaging/awg/VERSIONS"

printf '%s\n' "$REL" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || die "release '$REL' is not MAJOR.MINOR.PATCH"
case "$TGT" in
  x86/64)   QEMU=qemu-system-x86_64; cases_default="kmod userspace"; mem_default=256 ;;
  malta/le) QEMU=qemu-system-mipsel; cases_default="kmod userspace"; mem_default=64 ;;
  *) die "no QEMU recipe for target '$TGT' (x86/64 and malta/le are supported)" ;;
esac
CASES="${AWG_E2E_CASES:-$cases_default}"
MEM="${AWG_E2E_MEM:-$mem_default}"
EXPECT_TOOLS="${AWG_E2E_EXPECT_TOOLS:-${AWG_TOOLS_TAG#v}}"
PEER_DIR="${AWG_E2E_PEER_DIR:-$repo/dist/awg/userspace/amd64}"
KEYS="${AWG_E2E_KEYS:-}"
CACHE="${AWG_E2E_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/wayhop-awg-e2e}"
PORT="${AWG_E2E_PORT:-8080}"
PEER_PORT="${AWG_E2E_PEER_PORT:-51820}"
BASE="http://10.0.2.2:$PORT"

[ "$(id -u)" = 0 ] || die "must run as root: the peer creates a TUN device"
for t in "$QEMU" python3 ip ping gzip sha256sum; do
  command -v "$t" >/dev/null 2>&1 || die "$t is required"
done
if command -v curl >/dev/null 2>&1; then dl() { curl -fsSL --retry 3 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then dl() { wget -q -O "$2" "$1"; }
else die "curl or wget is required"; fi
[ -x "$PEER_DIR/amneziawg-go" ] && [ -x "$PEER_DIR/awg" ] || die "$PEER_DIR must hold executable amneziawg-go and awg (the peer)"
[ -n "$KEYS" ] && [ -s "$KEYS/usign.pub" ] && [ -s "$KEYS/apk.pem.pub" ] || die "AWG_E2E_KEYS must hold usign.pub and apk.pem.pub"
FEED="$(cd "$FEED" && pwd)"
[ -d "$FEED/awg/openwrt/$REL/$TGT" ] || die "$FEED has no awg/openwrt/$REL/$TGT - nothing to install from"
[ -s "$FEED/awg/install-awg.sh" ] || die "$FEED/awg/install-awg.sh is missing"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/awg-e2e.XXXXXX")"
OUT="${AWG_E2E_OUT:-$WORK}"
mkdir -p "$OUT" "$CACHE"
RES="$WORK/results"
: > "$RES"
qpid=""; hpid=""; ppid_peer=""

cleanup() {
  st=$?
  [ -z "$qpid" ] || kill "$qpid" 2>/dev/null || :
  [ -z "$hpid" ] || kill "$hpid" 2>/dev/null || :
  [ -z "$ppid_peer" ] || kill "$ppid_peer" 2>/dev/null || :
  ip link del awgp0 2>/dev/null || :
  if [ "$OUT" != "$WORK" ]; then
    cp "$WORK"/*.log "$WORK"/*.out "$WORK/summary.txt" "$OUT/" 2>/dev/null || :
  fi
  rm -rf "$WORK/www" "$WORK"/*.img "$WORK"/*.elf 2>/dev/null || :
  [ "$OUT" = "$WORK" ] || rm -rf "$WORK"
  exit "$st"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

record() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$RES"; printf '  %-5s %-9s %-34s %s\n' "$1" "$2" "$3" "$4"; }
pass() { record PASS "$@"; }
fail() { record FAIL "$@"; }
note() { record NOTE "$@"; }
check() {  # <case> <name> <detail-if-pass> <detail-if-fail> <test...>
  c_="$1"; n_="$2"; ok_="$3"; ko_="$4"; shift 4
  if "$@"; then pass "$c_" "$n_" "$ok_"; else fail "$c_" "$n_" "$ko_"; fi
}
now() { date +%s; }

# --- official image, verified ---------------------------------------------------------------------
tdash="$(printf '%s' "$TGT" | tr '/' '-')"
case "$TGT" in
  x86/64)   files="openwrt-$REL-x86-64-generic-ext4-combined.img.gz" ;;
  malta/le) files="openwrt-$REL-malta-le-vmlinux.elf openwrt-$REL-malta-le-rootfs-ext4.img.gz" ;;
esac
idir="$CACHE/$REL/$tdash"
mkdir -p "$idir"
url="https://downloads.openwrt.org/releases/$REL/targets/$TGT"
if dl "$url/sha256sums" "$idir/sha256sums.part"; then mv "$idir/sha256sums.part" "$idir/sha256sums"
elif [ ! -s "$idir/sha256sums" ]; then die "cannot fetch $url/sha256sums"; fi
for f in $files; do
  want="$(awk -v f="*$f" '$2 == f || $2 == substr(f, 2) { print $1 }' "$idir/sha256sums")"
  [ -n "$want" ] || die "$f is not listed in $url/sha256sums"
  if [ ! -f "$idir/$f" ] || [ "$(sha256sum "$idir/$f" | cut -d' ' -f1)" != "$want" ]; then
    dl "$url/$f" "$idir/$f.part" || die "download failed: $url/$f"
    [ "$(sha256sum "$idir/$f.part" | cut -d' ' -f1)" = "$want" ] || { rm -f "$idir/$f.part"; die "$f does not match sha256sums"; }
    mv "$idir/$f.part" "$idir/$f"
  fi
  note image "$f" "sha256=$want"
done

unpack() {  # OpenWrt's .img.gz carry trailing padding, which gzip reports as exit 2 after a full decode
  rc=0; gzip -dc "$1" > "$2" || rc=$?
  [ "$rc" = 0 ] || [ "$rc" = 2 ] || die "cannot unpack $1"
}

# --- test HTTP server: the feed, the guest script, the throwaway public keys, this run's parameters --
mkdir -p "$WORK/www/e2e"
ln -s "$FEED" "$WORK/www/feed"
cp "$here/qemu-guest.sh" "$WORK/www/e2e/guest.sh"
cp "$KEYS/usign.pub" "$WORK/www/e2e/usign.pub"
cp "$KEYS/apk.pem.pub" "$WORK/www/e2e/apk.pem.pub"

# --- the peer: userspace amneziawg-go on this host --------------------------------------------------
AWG="$PEER_DIR/awg"
mkdir -p /var/run/amneziawg
# WayHop's amneziawg-go keeps its UAPI socket in /tmp/wayhop/amneziawg unless AWG_SOCKET_DIR moves it;
# the link puts it where `awg` looks either way.
if [ ! -e /tmp/wayhop/amneziawg ]; then mkdir -p /tmp/wayhop && ln -s /var/run/amneziawg /tmp/wayhop/amneziawg; fi
umask 077
PEER_PRIV="$("$AWG" genkey)"; PEER_PUB="$(printf '%s\n' "$PEER_PRIV" | "$AWG" pubkey)"
GUEST_PRIV="$("$AWG" genkey)"; GUEST_PUB="$(printf '%s\n' "$GUEST_PRIV" | "$AWG" pubkey)"
HPK="$("$AWG" genpsk)"
umask 022
PEER_ADDR=10.66.0.1; GUEST_ADDR=10.66.0.2
AWG_JC=4; AWG_JMIN=40; AWG_JMAX=70
# With HeaderProtectionKey set, both engines refuse any S below 12 (the header-cipher nonce size).
AWG_S1=15; AWG_S2=68; AWG_S3=24; AWG_S4=16
AWG_H1=100000-150000; AWG_H2=200000-250000; AWG_H3=300000-350000; AWG_H4=400000-450000
# Only tags both engines parse: the kmod also knows <c>, amneziawg-go 3.1.20260828 refuses it.
AWG_I1='<b 0xf6ab3267fa><t><r 10><rc 6><rd 4>'
cat > "$WORK/www/e2e/params.env" <<EOF
GUEST_PRIV='$GUEST_PRIV'
GUEST_ADDR='$GUEST_ADDR'
PEER_PUB='$PEER_PUB'
PEER_ADDR='$PEER_ADDR'
PEER_HOST='10.0.2.2'
PEER_PORT='$PEER_PORT'
AWG_JC='$AWG_JC'
AWG_JMIN='$AWG_JMIN'
AWG_JMAX='$AWG_JMAX'
AWG_S1='$AWG_S1'
AWG_S2='$AWG_S2'
AWG_S3='$AWG_S3'
AWG_S4='$AWG_S4'
AWG_H1='$AWG_H1'
AWG_H2='$AWG_H2'
AWG_H3='$AWG_H3'
AWG_H4='$AWG_H4'
AWG_I1='$AWG_I1'
AWG_HPK='$HPK'
AWG_RANDOM_TRAILERS='1'
AWG_DISABLE_COOKIES='1'
EOF
cat > "$WORK/peer.conf" <<EOF
[Interface]
PrivateKey = $PEER_PRIV
ListenPort = $PEER_PORT
Jc = $AWG_JC
Jmin = $AWG_JMIN
Jmax = $AWG_JMAX
S1 = $AWG_S1
S2 = $AWG_S2
S3 = $AWG_S3
S4 = $AWG_S4
H1 = $AWG_H1
H2 = $AWG_H2
H3 = $AWG_H3
H4 = $AWG_H4
I1 = $AWG_I1
HeaderProtectionKey = $HPK
RandomTrailers = on
DisableCookies = on

[Peer]
PublicKey = $GUEST_PUB
AllowedIPs = $GUEST_ADDR/32
EOF
chmod 600 "$WORK/peer.conf"
ip link del awgp0 2>/dev/null || :
LOG_LEVEL=verbose AWG_SOCKET_DIR=/var/run/amneziawg "$PEER_DIR/amneziawg-go" -f awgp0 > "$WORK/peer.log" 2>&1 &
ppid_peer=$!
i=0
while [ ! -S /var/run/amneziawg/awgp0.sock ] && [ "$i" -lt 50 ]; do sleep 0.2; i=$((i + 1)); done
[ -S /var/run/amneziawg/awgp0.sock ] || { cat "$WORK/peer.log" >&2; die "the peer amneziawg-go did not start"; }
"$AWG" setconf awgp0 "$WORK/peer.conf" || { cat "$WORK/peer.log" >&2; die "the peer rejected the 3.1 configuration"; }
ip addr add "$PEER_ADDR/24" dev awgp0
ip link set awgp0 up
note peer "amneziawg-go" "$("$PEER_DIR/amneziawg-go" --version | head -n 1); $("$AWG" --version 2>&1 | head -n 1)"

python3 -m http.server --bind 127.0.0.1 --directory "$WORK/www" "$PORT" > "$WORK/http.log" 2>&1 &
hpid=$!
i=0
until python3 -c "import urllib.request,sys; urllib.request.urlopen(sys.argv[1], timeout=2)" \
  "http://127.0.0.1:$PORT/e2e/params.env" 2>/dev/null; do
  i=$((i + 1)); [ "$i" -lt 50 ] || die "the test HTTP server did not start"; sleep 0.2
done

# --- VM plumbing ------------------------------------------------------------------------------------
ACCEL="tcg"
if [ "$QEMU" = qemu-system-x86_64 ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then ACCEL="kvm"; fi
con() { python3 "$here/qemu-console.py" --sock "$WORK/console.sock" "$@"; }
guest() { t="$1"; shift; con run --timeout "$t" -- "$@"; }
val() { sed -n "s/^E2E $1=//p" "$2" | tail -n 1; }

boot_vm() {
  c="$1"
  rm -f "$WORK/console.sock"
  set -- -m "$MEM" -nodefaults -display none -no-reboot -monitor none \
    -chardev "socket,id=con0,path=$WORK/console.sock,server=on,wait=off,logfile=$WORK/console-$c.log" \
    -serial chardev:con0 -netdev user,id=n0
  if [ "$QEMU" = qemu-system-x86_64 ]; then
    unpack "$idir/openwrt-$REL-x86-64-generic-ext4-combined.img.gz" "$WORK/disk.img"
    if [ "$ACCEL" = kvm ]; then set -- "$@" -enable-kvm -cpu host; else set -- "$@" -accel tcg; fi
    set -- "$@" -smp 2 -drive "file=$WORK/disk.img,format=raw,if=virtio" -device virtio-net-pci,netdev=n0
  else
    unpack "$idir/openwrt-$REL-malta-le-rootfs-ext4.img.gz" "$WORK/disk.img"
    set -- "$@" -M malta -kernel "$idir/openwrt-$REL-malta-le-vmlinux.elf" \
      -append "root=/dev/sda rootfstype=ext4 rootwait console=ttyS0,115200" \
      -drive "file=$WORK/disk.img,format=raw,if=ide" -device pcnet,netdev=n0
  fi
  "$QEMU" "$@" > "$WORK/qemu-$c.log" 2>&1 &
  qpid=$!
}

stop_vm() {
  con poweroff --timeout 60 >/dev/null 2>&1 || :
  i=0
  while kill -0 "$qpid" 2>/dev/null && [ "$i" -lt 30 ]; do sleep 1; i=$((i + 1)); done
  kill "$qpid" 2>/dev/null || :
  wait "$qpid" 2>/dev/null || :
  qpid=""
}

# One guest phase: its output is kept per phase and appended to the case log.
phase() {  # <case> <timeout> <phase args...>
  c="$1"; t="$2"; shift 2
  out="$WORK/phase.out"
  guest "$t" "sh /tmp/g.sh $BASE $*" > "$out" 2>&1 || :
  { echo "### phase: $*"; cat "$out"; } >> "$WORK/guest-$c.out"
}

# An installer JSON line against what this step expects; "-" means any value.
judge_json() {  # <json> <results> <path> <netifd_restart_needed> <network_restarted> <must-have-package>
  python3 - "$@" <<'PY'
import json, sys
js, results, path, needed, restarted, pkg = sys.argv[1:7]
try:
    j = json.loads(js)
except Exception as e:
    print(f"not JSON ({e}): {js[:120]}"); sys.exit(1)
bad = []
if j.get("result") not in results.split(","): bad.append(f"result={j.get('result')}")
if path != "-" and j.get("path") != path: bad.append(f"path={j.get('path')}")
for k, want in (("netifd_restart_needed", needed), ("network_restarted", restarted)):
    if want != "-" and str(j.get(k)).lower() != want: bad.append(f"{k}={j.get(k)}")
pkgs = j.get("packages") or []
if pkg != "-" and pkg not in pkgs: bad.append(f"no {pkg} in packages")
print(("MISMATCH " + " ".join(bad) + " | " if bad else "")
      + f"result={j.get('result')} path={j.get('path')} profile={j.get('profile')} "
      + f"needed={j.get('netifd_restart_needed')} restarted={j.get('network_restarted')} "
      + f"packages={','.join(pkgs)}" + (f" reason={j.get('reason')}" if j.get('reason') else ""))
sys.exit(1 if bad else 0)
PY
}

judge_installer() {  # <case> <tag> <label> <results> <path> <needed> <restarted> <pkg>
  c="$1"; tag="$2"; label="$3"; shift 3
  rc="$(val "${tag}_rc" "$WORK/phase.out")"; js="$(val "${tag}_json" "$WORK/phase.out")"
  secs="$(val "${tag}_seconds" "$WORK/phase.out")"
  if detail="$(judge_json "$js" "$@")" && [ "$rc" = 0 ]; then pass "$c" "$label" "exit 0 in ${secs}s, $detail"
  else fail "$c" "$label" "exit ${rc:-?}, ${detail:-$js}"; fi
}

# The tunnel from the guest's side (link, handshake, options read back, ping) and from the peer's.
judge_tunnel() {  # <case> <tag> <engine kmod|go> <host epoch before the phase>
  c="$1"; tag="$2"; engine="$3"; since="$4"; o="$WORK/phase.out"
  check "$c" "$tag: netifd link" "awg0 up" "no awg0" [ "$(val "${tag}_link" "$o")" = yes ]
  hs="$(val "${tag}_handshake" "$o")"
  ok=no; [ -n "$hs" ] && [ "$hs" != 0 ] && ok=yes
  check "$c" "$tag: guest handshake" "after $(val "${tag}_handshake_wait" "$o")s" "latest-handshakes is ${hs:-empty}" [ "$ok" = yes ]
  mm="$(val "${tag}_conf_mismatch" "$o")"
  check "$c" "$tag: 3.1 options on awg0" "Jc..Jmax S1-S4 H1-H4 I1 HPK RandomTrailers DisableCookies as configured" \
    "differ: ${mm:-no showconf}" [ "$mm" = none ]
  check "$c" "$tag: ping guest->peer" "$PEER_ADDR via awg0, $(val "${tag}_transfer" "$o")" "$PEER_ADDR unreachable through awg0" \
    [ "$(val "${tag}_ping" "$o")" = ok ]
  kl="$(val "${tag}_kmod_loaded" "$o")"; gr="$(val "${tag}_go_running" "$o")"; gs="$(val "${tag}_go_socket" "$o")"
  ok=no
  if [ "$engine" = kmod ]; then
    [ "$kl" = yes ] && [ "$gr" = no ] && ok=yes
    check "$c" "$tag: engine" "kernel module (amneziawg loaded, no amneziawg-go)" "kmod=$kl amneziawg-go=$gr" [ "$ok" = yes ]
  else
    [ "$kl" = no ] && [ "$gr" = yes ] && [ "$gs" = /var/run/amneziawg/awg0.sock ] && ok=yes
    check "$c" "$tag: engine" "amneziawg-go, socket $gs, no kernel module" "kmod=$kl amneziawg-go=$gr socket=$gs" [ "$ok" = yes ]
  fi
  phs="$("$AWG" show awgp0 latest-handshakes 2>/dev/null | awk -v k="$GUEST_PUB" '$1 == k { print $2 }')"
  check "$c" "$tag: peer handshake" "fresh ($(( ${phs:-0} - since ))s into the phase)" "none since the phase began (${phs:-0})" \
    [ "${phs:-0}" -ge "$since" ]
  # The route to the guest's tunnel address exists only through awgp0, so a reply here crossed it.
  if ping -c 3 -W 3 "$GUEST_ADDR" > "$WORK/ping-peer-$c-$tag.log" 2>&1; then
    pass "$c" "$tag: ping peer->guest" "$GUEST_ADDR, peer $("$AWG" show awgp0 transfer | awk '{ print "rx=" $2 " tx=" $3; exit }')"
  else fail "$c" "$tag: ping peer->guest" "$GUEST_ADDR unreachable"; fi
}

judge_residue() {  # <case> <tag>
  c="$1"; tag="$2"; o="$WORK/phase.out"
  r="$(val "${tag}_residue" "$o")"
  check "$c" "$tag: no residue" "packages, world, feed lines, keys, files as before the install" "left: $r" [ -z "$r" ]
  # Nothing may keep running on the removed packages: no amneziawg link, no amneziawg-go, and the
  # module unloaded - or, when it cannot be, the result saying why and naming the generation left.
  ln="$(val "${tag}_link" "$o")"; gr="$(val "${tag}_go_running" "$o")"
  ok=no; [ "$ln" = no ] && [ "$gr" = no ] && ok=yes
  check "$c" "$tag: nothing left running" "no awg0, no amneziawg-go" "awg0 link $ln, amneziawg-go running $gr" [ "$ok" = yes ]
  kl="$(val "${tag}_kmod_loaded" "$o")"
  js="$(val "${tag}_json" "$o")"
  gen="$(printf '%s' "$js" | sed -n 's/.*"generation":"\([^"]*\)".*/\1/p')"
  why="$(printf '%s' "$js" | sed -n 's/.*"reason":"\([^"]*\)".*/\1/p')"
  ok=no
  if [ "$kl" = no ] && [ "$gen" = none ]; then ok=yes
  elif [ "$kl" = yes ] && [ "$gen" != none ] && [ -n "$why" ]; then ok=yes; fi
  check "$c" "$tag: module" "loaded: $kl, generation $gen${why:+, reason: $why}" \
    "loaded: $kl but generation '$gen'${why:+, reason: $why}" [ "$ok" = yes ]
  note "$c" "$tag: memory" "MemAvailable $(val "${tag}_mem_available_kib" "$o") KiB after the uninstall"
}

run_case() {
  c="$1"
  t0="$(now)"
  : > "$WORK/guest-$c.out"
  boot_vm "$c"
  if ! con wait-shell --timeout "${AWG_E2E_BOOT_TIMEOUT:-900}" >/dev/null; then
    fail "$c" boot "no shell within ${AWG_E2E_BOOT_TIMEOUT:-900}s (see console-$c.log)"; stop_vm; return
  fi
  pass "$c" boot "$(( $(now) - t0 ))s ($ACCEL, ${MEM} MiB)"
  guest 30 "dmesg -n 1" >/dev/null || :
  # The image's lan has a static 192.168.50.1; under QEMU user networking it takes DHCP instead.
  guest 120 "uci set network.lan.proto=dhcp; uci -q delete network.lan.ipaddr; uci -q delete network.lan.netmask; uci -q delete network.lan.ip6assign; uci commit network; /etc/init.d/network reload" >/dev/null || :
  if guest 200 "i=0; until wget -q -O /dev/null $BASE/e2e/params.env; do i=\$((i+1)); [ \$i -ge 60 ] && exit 1; sleep 2; done; wget -q -O /tmp/g.sh $BASE/e2e/guest.sh" >/dev/null; then
    pass "$c" network "guest reaches the runner at 10.0.2.2"
  else
    fail "$c" network "guest cannot reach $BASE"; stop_vm; return
  fi
  phase "$c" 120 prep
  o="$WORK/phase.out"
  luci="$(val luci_present "$o")"
  note "$c" guest "OpenWrt $(val distrib_release "$o") $(val distrib_target "$o"), kernel $(val kernel "$o"), $(val pkg_manager "$o"), LuCI $luci, MemTotal $(val mem_total_kib "$o") KiB, MemAvailable $(val before_mem_available_kib "$o") KiB"
  [ "$(val snapshot_lines "$o")" -gt 0 ] 2>/dev/null || { fail "$c" prep "no snapshot taken"; stop_vm; return; }

  if [ "$c" = kmod ]; then
    want_luci="-"
    if [ "$luci" = yes ]; then want_luci="luci-proto-amneziawg"; fi
    phase "$c" 900 install i1 kmod
    judge_installer "$c" i1 "install --mode kmod" installed kmod true false "$want_luci"
    check "$c" "i1: module loaded" "amneziawg in /proc/modules" "not loaded after the install" [ "$(val i1_kmod_loaded "$o")" = yes ]
    v="$(val i1_awg_version "$o")"
    ok=no; case "$v" in *"$EXPECT_TOOLS"*) ok=yes ;; esac
    check "$c" "i1: awg --version" "$v" "want $EXPECT_TOOLS, got '${v:-nothing}'" [ "$ok" = yes ]
    if [ "$luci" = yes ]; then
      check "$c" "i1: LuCI page" "protocol/amneziawg.js installed" "LuCI is present and the page is not" [ "$(val i1_luci_proto "$o")" = yes ]
    else note "$c" "i1: LuCI page" "the image has no LuCI"; fi
    phase "$c" 120 configure
    note "$c" "reload only" "awg0 after a network reload without restart: $(val link_after_reload "$o")"
    s="$(now)"; phase "$c" 120 restart
    phase "$c" 300 tunnel t1
    judge_tunnel "$c" t1 kmod "$s"
    note "$c" "t1: memory" "MemAvailable $(val t1_mem_available_kib "$o") KiB, flash free $(val t1_flash_free_kib "$o") KiB"
    phase "$c" 600 uninstall u1
    judge_installer "$c" u1 "uninstall" removed - true false -
    judge_residue "$c" u1
    s="$(now)"; phase "$c" 900 install i2 kmod --restart-network
    judge_installer "$c" i2 "install --restart-network" installed kmod false true "$want_luci"
    phase "$c" 300 tunnel t2
    judge_tunnel "$c" t2 kmod "$s"
    note "$c" "t2: memory" "MemAvailable $(val t2_mem_available_kib "$o") KiB"
    phase "$c" 600 uninstall u2 --restart-network
    judge_installer "$c" u2 "uninstall --restart-network" removed - false true -
    judge_residue "$c" u2
  else
    phase "$c" 900 install i1 userspace --restart-network
    judge_installer "$c" i1 "install --mode userspace" installed userspace false true -
    check "$c" "i1: no kernel module" "the userspace path installed none" "amneziawg is loaded" [ "$(val i1_kmod_loaded "$o")" = no ]
    phase "$c" 120 userspace-start
    gv="$(val go_version "$o")"; gl="$(val go_link "$o")"; gs="$(val go_socket "$o")"
    ok=no; case "$gv" in amneziawg-go*) [ "$gl" = yes ] && [ -n "$gs" ] && [ "$gs" != none ] && ok=yes ;; esac
    check "$c" "amneziawg-go by hand" "$gv: link up, socket $gs" "version '$gv', link $gl, socket $gs" [ "$ok" = yes ]
    s="$(now)"; phase "$c" 120 configure
    phase "$c" 300 tunnel t1
    judge_tunnel "$c" t1 go "$s"
    note "$c" "t1: memory" "MemAvailable $(val t1_mem_available_kib "$o") KiB, flash free $(val t1_flash_free_kib "$o") KiB"
    phase "$c" 600 uninstall u1 --restart-network
    judge_installer "$c" u1 "uninstall --restart-network" removed - false true -
    judge_residue "$c" u1
  fi
  stop_vm
  note "$c" time "$(( $(now) - t0 ))s total"
}

echo "=== AmneziaWG 3.1 e2e: OpenWrt $REL $TGT (accel $ACCEL, ${MEM} MiB, cases: $CASES) ==="
T0="$(now)"
for c in $CASES; do
  case "$c" in kmod|userspace) run_case "$c" ;; *) die "unknown case '$c'" ;; esac
done

npass=$(grep -c '^PASS' "$RES" || true)
nfail=$(grep -c '^FAIL' "$RES" || true)
{
  echo "AmneziaWG 3.1 e2e - OpenWrt $REL $TGT - accel $ACCEL - ${MEM} MiB - $(( $(now) - T0 ))s"
  awk -F '\t' '{ printf "%-5s %-9s %-34s %s\n", $1, $2, $3, $4 }' "$RES"
  if [ "$nfail" = 0 ] && [ "$npass" -gt 0 ]; then echo "RESULT: PASS ($npass checks)"; else echo "RESULT: FAIL ($nfail of $((npass + nfail)) checks failed)"; fi
} > "$WORK/summary.txt"
echo; cat "$WORK/summary.txt"
[ -z "${AWG_E2E_SUMMARY:-}" ] || { echo '```'; cat "$WORK/summary.txt"; echo '```'; } >> "$AWG_E2E_SUMMARY"
[ "$nfail" = 0 ] && [ "$npass" -gt 0 ]
