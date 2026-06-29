package keenetic

import (
	"fmt"
	"sort"
	"strings"

	"wakeroute/internal/model"
	"wakeroute/internal/pbr"
)

// kpbr.go is the Keenetic kernel-PBR ORCHESTRATION: it turns a compiled pbr.Plan + the profile
// into the on-device artifacts that replace keen-pbr's LIST routing — a per-group failover cron
// (the urltest equivalent, kernel-driven) that elects each routing table's live egress, plus the
// member resolution the cron needs. The ipset/iptables/dnsmasq rendering lives in pbr
// (render_ipset.go); this file adds the failover keen-pbr's urltest outbounds provided.
//
// Design: each non-WAN egress is a routing TABLE whose default route the cron flips to the first
// reachable member, in the group's configured order, falling through to WAN last (the user's
// no-kill-switch choice). Probe method mirrors the live S89hy_failover (proven on this device):
// a temporary /32 route via the candidate iface + a curl, so even proxy-fronted tunnels are
// reachability-tested without ICMP.

// memberToken maps a group member (endpoint id / "direct" / "block") to a failover token the
// cron understands: a kernel iface name, "WAN", or "BLOCK". Returns "" for a member with no
// kernel representation (a userspace proxy endpoint) so the caller can skip it.
func memberToken(p *model.Profile, member string) string {
	switch member {
	case model.OutboundDirect, "":
		return "WAN"
	case model.OutboundBlock:
		return "BLOCK"
	}
	if e := p.EndpointByID(member); e != nil {
		if ifc := pbr.KernelIface(e); ifc != "" {
			return ifc
		}
	}
	return ""
}

// ResolveEgressMembers returns the ordered failover tokens (iface / WAN / BLOCK) for an egress
// tag: a group expands to its members in order (skipping userspace-only members); a bare
// endpoint is a single-member list. A trailing WAN/BLOCK is the terminal fallback.
func ResolveEgressMembers(p *model.Profile, tag string) []string {
	if g := p.GroupByID(tag); g != nil {
		var out []string
		for _, m := range g.Members {
			if t := memberToken(p, m); t != "" {
				out = append(out, t)
			}
		}
		return out
	}
	if t := memberToken(p, tag); t != "" {
		return []string{t}
	}
	return nil
}

// FailoverCronScript renders the 1-minute failover cron: for each routing table (one per
// non-WAN egress) it elects the first reachable member and `ip route replace`s the table's
// default. WAN/BLOCK members are terminal (no probe). Idempotent + side-effect-free except the
// table routes it owns. wanGw/wanIf are the discovered WAN nexthop for the WAN fallback.
func FailoverCronScript(plan *pbr.Plan, p *model.Profile, wanGw, wanIf string) string {
	var b strings.Builder
	b.WriteString("#!/opt/bin/sh\n")
	b.WriteString("# WakeRoute list-routing failover (keen-pbr urltest equivalent). Auto-generated.\n")
	b.WriteString("# Elects each routing table's live egress in order; falls through to WAN last.\n")
	fmt.Fprintf(&b, "WAN_GW=%q; WAN_IF=%q; PROBE=1.1.1.1; TMO=5; HS_MAX=180\n", wanGw, wanIf)
	// Single-flight lock (PID-based, self-clearing if stale): under heavy load a probe can take
	// several seconds, so a run may outlast the 1-min cron tick — without this two elections
	// could race the same table. TMO=5 gives a delayed ICMP reply time to arrive under CPU load
	// (sing-box's gvisor TUN saturating the A53 starves the probe → false "down").
	b.WriteString("LK=/tmp/wr-fo.lock\n")
	b.WriteString("if [ -f \"$LK\" ] && kill -0 \"$(cat \"$LK\" 2>/dev/null)\" 2>/dev/null; then exit 0; fi\n")
	b.WriteString("echo $$ > \"$LK\"; trap 'rm -f \"$LK\"' EXIT INT TERM\n")
	// Load-independent liveness — the fix for the ICMP-probe flapping that demoted censored lists
	// (Telegram) off their VPN under CPU load. The old probe was a single `ping -I $iface`; under
	// heavy load (sing-box's gvisor TUN saturating the A53 while the family torrents) the ICMP echo
	// is starved past $TMO → a false "down". Primary signal now: did the iface pass RX traffic since
	// the last run? Reading a kernel byte counter is CPU-cheap and is TRUE precisely under the load
	// that starves ICMP — the active egress is the one carrying that traffic, so it is never falsely
	// demoted. Then a best-effort WG-handshake age (idle-but-up tunnels), then ICMP last. None of
	// these mutate the main routing table (the old `ip route replace $PROBE dev …` could orphan a
	// 1.1.1.1 host route pinning a DoH resolver to a tunnel if the cron was interrupted mid-probe).
	b.WriteString(`sample_rx() { # $1=iface — snapshot RX once per run (rotate prev<-cur)
  f="/tmp/wr-rx-$1"
  c=$(cat "/sys/class/net/$1/statistics/rx_bytes" 2>/dev/null || echo 0)
  [ -f "$f.cur" ] && mv -f "$f.cur" "$f.prev"
  echo "$c" > "$f.cur"
}
rx_advanced() { # $1=iface -> 0 if RX grew between the prev and cur samples (read-only, idempotent)
  c=$(cat "/tmp/wr-rx-$1.cur" 2>/dev/null || echo 0)
  p=$(cat "/tmp/wr-rx-$1.prev" 2>/dev/null || echo 0)
  case "$c$p" in ''|*[!0-9]*) return 1 ;; esac
  [ "$c" -gt "$p" ]
}
wg_alive() { # $1=iface -> 0 if a WG/AmneziaWG handshake occurred within $HS_MAX seconds
  ts=$( { awg show "$1" latest-handshakes 2>/dev/null || wg show "$1" latest-handshakes 2>/dev/null; } \
        | awk '{if($NF+0>m)m=$NF+0} END{print m+0}' )
  case "$ts" in ''|*[!0-9]*) return 1 ;; esac
  [ "$ts" -gt 0 ] || return 1
  now=$(date +%s); [ $((now - ts)) -lt "$HS_MAX" ]
}
probe() { # $1=iface -> 0 alive. Cheap load-independent signals first; ICMP only as last resort.
  rx_advanced "$1" && return 0
  wg_alive "$1" && return 0
  ping -c3 -W "$TMO" -I "$1" "$PROBE" >/dev/null 2>&1
}
set_table() { # $1=table; rest=ordered members
  T="$1"; shift; ST="/tmp/wr-fo-$T"
  # L1 stickiness: if the currently-installed TUNNEL default is still a healthy member, KEEP it and
  # stop — NEVER preemptively fail back to a recovered higher-priority member, because that
  # zero-debounce up-switch tears down live calls (the top call-drop cause on Keenetic). We re-elect
  # ONLY when the current egress is down, is no longer a member, or is the WAN/blackhole fallback
  # (which we DO want to leave the moment a tunnel recovers).
  cur=$(ip route show default table "$T" 2>/dev/null | awk '{for(i=1;i<NF;i++)if($i=="dev"){print $(i+1);exit}}')
  if [ -n "$cur" ] && [ "$cur" != "$WAN_IF" ]; then
    case " $* " in *" $cur "*) if probe "$cur"; then echo 0 > "$ST"; return; fi;; esac
  fi
  # Re-elect the first reachable member in preference order. Falling to the terminal WAN/BLOCK needs
  # 3 CONSECUTIVE all-tunnels-down runs (the -ge 3 hysteresis) so a single transient probe miss under
  # a CPU-load spike does NOT flap the list onto the WAN for ~3 minutes. ip route replace is skipped
  # when it would re-install the current egress (idempotent; no needless route churn).
  for m in "$@"; do
    case "$m" in
      WAN) n=$(cat "$ST" 2>/dev/null || echo 0); n=$((n+1)); echo "$n" > "$ST"
           # #5: WAN_GW/WAN_IF can be empty if gateway discovery failed -- an empty "via"/"dev" arg is
           # an iproute2 error, so the fallback would error every run and never install (black-holing
           # all-tunnels-down traffic). Require WAN_IF; use via only when WAN_GW is set, else a dev-only
           # default (correct for a point-to-point WAN like ppp0).
           if [ "$n" -ge 3 ] && [ "$cur" != "$WAN_IF" ] && [ -n "$WAN_IF" ]; then
             if [ -n "$WAN_GW" ]; then ip route replace default via "$WAN_GW" dev "$WAN_IF" table "$T"
             else ip route replace default dev "$WAN_IF" table "$T"; fi
           fi
           return;;
      BLOCK) n=$(cat "$ST" 2>/dev/null || echo 0); n=$((n+1)); echo "$n" > "$ST"
             [ "$n" -ge 3 ] && ip route replace blackhole default table "$T"; return;;
      *) if probe "$m"; then [ "$m" != "$cur" ] && ip route replace default dev "$m" table "$T"; echo 0 > "$ST"; return; fi;;
    esac
  done
}
`)
	// One set_table line per non-WAN egress, in stable (table) order.
	var egs []pbr.Egress
	for _, e := range plan.Egresses {
		if e.Kind != pbr.EgressWAN {
			egs = append(egs, e)
		}
	}
	sort.Slice(egs, func(i, j int) bool { return egs[i].Table < egs[j].Table })

	// Resolve every table's members first, collecting the unique candidate ifaces so their RX can
	// be snapshotted once, up front — rx_advanced is then a read-only compare even when several
	// tables share an iface (without this, the 2nd table to probe an iface would see no delta).
	var ifaces []string
	seenIf := map[string]bool{}
	var lines []string
	for _, e := range egs {
		members := ResolveEgressMembers(p, e.Tag)
		if len(members) == 0 {
			continue
		}
		for _, m := range members {
			if m != "WAN" && m != "BLOCK" && !seenIf[m] {
				seenIf[m] = true
				ifaces = append(ifaces, m)
			}
		}
		lines = append(lines, fmt.Sprintf("set_table %d %s   # %s", e.Table, strings.Join(members, " "), e.Tag))
	}
	if len(ifaces) > 0 {
		fmt.Fprintf(&b, "for i in %s; do sample_rx \"$i\"; done\n", strings.Join(ifaces, " "))
		// NAT persistence backstop: re-assert the tunnel MASQUERADE every run (idempotent -C||-A).
		// The netfilter.d hook already re-adds it after an NDM firewall rebuild, but the nat table is
		// flushed+rebuilt out-of-band by NDM; this 1-min belt-and-suspenders bounds any worst-case
		// forwarded-traffic black-hole on a family-critical path to <=60s even if a hook event is
		// ever missed. (BuildKernelPlan installs the same rule on the same ifaces.)
		fmt.Fprintf(&b, "for i in %s; do iptables -t nat -C POSTROUTING -o \"$i\" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o \"$i\" -j MASQUERADE; done\n", strings.Join(ifaces, " "))
	}
	for _, l := range lines {
		b.WriteString(l + "\n")
	}
	return b.String()
}
