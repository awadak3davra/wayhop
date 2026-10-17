#!/bin/sh
# memory-userspace.sh - the memory stand behind docs/AWG_LOWMEM.md (development repository): peak
# resident memory (VmHWM) and throughput of amneziawg-go on the "router" end of an AmneziaWG 3.1
# tunnel, per set of runtime settings.
#
# Two amneziawg-go peers in two network namespaces joined by a veth pair, inside one privileged
# container. The router side runs with the settings under test, pinned to one CPU so that its CPU is
# the bottleneck, as a router's is; the server side runs with none, on other CPUs. Both are
# configured with the static awg (awg setconf over the UAPI socket) with a full 3.1 set: Jc/Jmin/Jmax,
# S1-S4, H1-H4 ranges, I1 and a HeaderProtectionKey. Tunnel MTU 1280, WayHop's default.
#
# Per profile: idle RSS after the handshake, then for each load the peak RSS (VmHWM, reset through
# /proc/<pid>/clear_refs before the load) and the throughput iperf3 reports:
#   tcp-up    iperf3 TCP, 4 streams, router -> server
#   tcp-down  the same, server -> router (-R)
#   udp-up    iperf3 UDP flood (-b 0, 1200-byte datagrams), 4 streams, router -> server
#   udp-down  the same, server -> router
#
# Usage: scripts/awg/memory-userspace.sh <bins-dir> <outfile> ["label|binary|ENV=v ENV=v" ...]
#   <bins-dir> holds amneziawg-go (the build under test), awg (static), and optionally
#   amneziawg-go-upstream (unpatched, for the baseline). binary is "patched" or "upstream".
#   Without profiles the full grid of docs/AWG_LOWMEM.md (development repository) runs.
#   AWG_MEM_SECS=30        seconds per load
#   AWG_MEM_CPU_BASE=0     first CPU of the 5+N this stand pins to (run stands side by side)
#   AWG_MEM_CLI_NCPU=1     CPUs the router side gets (N)
#   AWG_MEM_SHARD=i/n      run every n-th profile starting at the i-th (0-based), for side-by-side stands
#   AWG_DOCKER_PREFIX=<p>  container name prefix (default: wayhop)
#   --inside ...           the stand itself, as run in the container
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"

grid() {
  echo "upstream-default|upstream|"
  echo "wayhop-0.5.7|patched|GOGC=25"
  for b in 512 1024 2048; do
    echo "cap$b-q1024-g25|patched|AWG_GO_BUFFERS_PER_POOL=$b GOGC=25 GOMAXPROCS=1"
  done
  for b in 512 1024 2048; do
    for q in 128 256 1024; do
      for l in 16 24 32; do
        for g in 25 50; do
          echo "cap$b-q$q-l$l-g$g|patched|AWG_GO_BUFFERS_PER_POOL=$b AWG_GO_QUEUE_SIZE=$q GOMEMLIMIT=${l}MiB GOGC=$g GOMAXPROCS=1"
        done
      done
    done
  done
}

inside() {
  bins="$1"; out="$2"; profiles="$3"
  secs="${AWG_MEM_SECS:-30}"
  base="${AWG_MEM_CPU_BASE:-0}"
  n="${AWG_MEM_CLI_NCPU:-1}"
  cpu_cli="$base-$((base + n - 1))"
  cpu_srv="$((base + n))-$((base + n + 1))"
  cpu_ips="$((base + n + 2))"
  cpu_ipc="$((base + n + 3))-$((base + n + 4))"
  awg="$bins/awg"
  hpk="$("$awg" genkey)"
  ks="$("$awg" genkey)"; kc="$("$awg" genkey)"
  ps="$(echo "$ks" | "$awg" pubkey)"; pc="$(echo "$kc" | "$awg" pubkey)"
  obf="Jc = 4
Jmin = 40
Jmax = 70
S1 = 40
S2 = 50
S3 = 20
S4 = 16
H1 = 100000-200000
H2 = 300000-400000
H3 = 500000-600000
H4 = 700000-800000
I1 = <b 0xc0ff00><r 16><t>
HeaderProtectionKey = $hpk"
  printf '[Interface]\nPrivateKey = %s\nListenPort = 51820\n%s\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.88.0.2/32\n' "$ks" "$obf" "$pc" > /tmp/srv.conf
  printf '[Interface]\nPrivateKey = %s\n%s\n\n[Peer]\nPublicKey = %s\nEndpoint = 10.99.0.1:51820\nAllowedIPs = 10.88.0.1/32\n' "$kc" "$obf" "$ps" > /tmp/cli.conf

  printf 'label\tidle_kib\ttcp_up_kib\ttcp_up_mbit\ttcp_down_kib\ttcp_down_mbit\tudp_up_kib\tudp_up_mbit\tudp_up_loss\tudp_down_kib\tudp_down_mbit\tudp_down_loss\tpeak_kib\teffective\n' > "$out"
  while IFS= read -r spec <&3; do
    [ -n "$spec" ] || continue
    label="${spec%%|*}"; rest="${spec#*|}"; kind="${rest%%|*}"; envs="${rest#*|}"
    bin="$bins/amneziawg-go"; [ "$kind" = upstream ] && bin="$bins/amneziawg-go-upstream"
    pkill -x iperf3 2>/dev/null || :
    pkill -f "amneziawg-go" 2>/dev/null || :
    sleep 0.5
    ip netns del srv 2>/dev/null || :; ip netns del cli 2>/dev/null || :
    rm -rf /tmp/wayhop
    ip netns add srv; ip netns add cli
    ip link add vs netns srv type veth peer name vc netns cli
    ip -n srv addr add 10.99.0.1/24 dev vs; ip -n srv link set vs up; ip -n srv link set lo up
    ip -n cli addr add 10.99.0.2/24 dev vc; ip -n cli link set vc up; ip -n cli link set lo up

    ip netns exec srv env -i PATH="$PATH" WG_PROCESS_FOREGROUND=1 taskset -c "$cpu_srv" "$bins/amneziawg-go" -f awgs > /tmp/srv.log 2>&1 &
    srv=$!
    # shellcheck disable=SC2086  # the profile's variables are separate words on purpose
    ip netns exec cli env -i PATH="$PATH" WG_PROCESS_FOREGROUND=1 $envs taskset -c "$cpu_cli" "$bin" -f awgc > /tmp/cli.log 2>&1 &
    cli=$!
    n=0
    while [ ! -S /tmp/wayhop/amneziawg/awgs.sock ] || [ ! -S /tmp/wayhop/amneziawg/awgc.sock ]; do
      n=$((n + 1)); [ "$n" -lt 50 ] || break; sleep 0.1
    done
    "$awg" setconf awgs /tmp/srv.conf && "$awg" setconf awgc /tmp/cli.conf || { echo "$label: setconf failed" >&2; cat /tmp/cli.log >&2; continue; }
    ip -n srv addr add 10.88.0.1/24 dev awgs; ip -n srv link set awgs mtu 1280 up
    ip -n cli addr add 10.88.0.2/24 dev awgc; ip -n cli link set awgc mtu 1280 up
    if ! ip netns exec cli ping -c 3 -i 0.3 -W 2 10.88.0.1 >/dev/null; then
      echo "$label: no handshake" >&2; tail -5 /tmp/cli.log >&2; continue
    fi
    ip netns exec srv taskset -c "$cpu_ips" iperf3 -s -p 5201 -D
    sleep 2
    idle="$(awk '/^VmRSS/{print $2}' "/proc/$cli/status")"
    row="$label	$idle"
    peak=0
    for load in tcp-up tcp-down udp-up udp-down; do
      case "$load" in
        tcp-up) flags="" ;; tcp-down) flags="-R" ;;
        udp-up) flags="-u -b 0 -l 1200" ;; udp-down) flags="-R -u -b 0 -l 1200" ;;
      esac
      echo 5 > "/proc/$cli/clear_refs"
      # shellcheck disable=SC2086  # flags are separate words
      ip netns exec cli taskset -c "$cpu_ipc" iperf3 -c 10.88.0.1 -p 5201 -t "$secs" -P 4 $flags -J > /tmp/load.json 2>/dev/null || :
      if [ -d "/proc/$cli" ]; then
        hwm="$(awk '/^VmHWM/{print $2}' "/proc/$cli/status")"
      else
        hwm="died"
      fi
      mbit="$(jq -r '((.end.sum_received.bits_per_second // .end.sum.bits_per_second // 0) / 1e6 | floor)' /tmp/load.json 2>/dev/null || echo 0)"
      row="$row	$hwm	$mbit"
      case "$load" in udp-*)
        row="$row	$(jq -r '(.end.sum.lost_percent // 0) | floor' /tmp/load.json 2>/dev/null || echo -)" ;;
      esac
      [ "$hwm" = died ] || [ "$hwm" -le "$peak" ] || peak="$hwm"
      sleep 1
    done
    eff="$(grep -o 'buffers_per_pool=.*' /tmp/cli.log | head -n1 || :)"
    printf '%s\t%s\t%s\n' "$row" "$peak" "${eff:-upstream values}" | tee -a "$out"
    kill "$srv" "$cli" 2>/dev/null || :
    wait "$srv" "$cli" 2>/dev/null || :
  done 3< "$profiles"
}

if [ "${1:-}" = "--inside" ]; then
  [ "$#" -eq 4 ] || { echo "usage: memory-userspace.sh --inside <bins> <outfile> <profiles-file>" >&2; exit 2; }
  inside "$2" "$3" "$4"
  exit 0
fi

[ "$#" -ge 2 ] || { echo "usage: memory-userspace.sh <bins-dir> <outfile> [profile...]" >&2; exit 2; }
BINS="$(cd "$1" && pwd)"; OUTF="$2"; shift 2
# shellcheck source=packaging/awg/VERSIONS
. "$repo/packaging/awg/VERSIONS"
BUILD_IMAGE="${AWG_BUILD_IMAGE:-debian:12@sha256:813017f3d62be4b5891a7acca6a01bdcd4b8513daa81b1ab99d3a50385b26931}"
hostpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s\n' "$1"; fi; }
mkdir -p "$(dirname "$OUTF")"
outdir="$(cd "$(dirname "$OUTF")" && pwd)"
out="$(basename "$OUTF")"
shard="${AWG_MEM_SHARD:-0/1}"
if [ "$#" -gt 0 ]; then printf '%s\n' "$@"; else grid; fi |
  awk -v i="${shard%/*}" -v n="${shard#*/}" '(NR - 1) % n == i' > "$outdir/$out.profiles"
name="${AWG_DOCKER_PREFIX:-wayhop}-awg-mem-$$"
MSYS_NO_PATHCONV=1 docker run --rm --name "$name" --privileged --device /dev/net/tun \
  -e AWG_MEM_SECS="${AWG_MEM_SECS:-30}" -e AWG_MEM_CPU_BASE="${AWG_MEM_CPU_BASE:-0}" \
  -e AWG_MEM_CLI_NCPU="${AWG_MEM_CLI_NCPU:-1}" \
  -v "$(hostpath "$repo"):/repo:ro" -v "$(hostpath "$BINS"):/in:ro" -v "$(hostpath "$outdir"):/out" \
  "$BUILD_IMAGE" sh -euc "
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null
    apt-get install -y -qq --no-install-recommends iproute2 iperf3 iputils-ping jq procps >/dev/null 2>&1
    mkdir -p /bins && cp /in/* /bins/ && chmod 0755 /bins/*
    sh /repo/scripts/awg/memory-userspace.sh --inside /bins /out/$out /out/$out.profiles"
