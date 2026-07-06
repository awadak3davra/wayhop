package keenetic

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"wayhop/internal/generator"
	"wayhop/internal/model"
)

// FallbackOptions tune the sing-box fallback (per-endpoint TUN device naming + addressing).
// Defaults match the live Hopper SE reference (singtun/vlesstun: mtu 1400, /30 host
// addresses, gvisor stack, auto_route off — NDM owns the routing/metric tiers).
type FallbackOptions struct {
	TunBaseName string // TUN device prefix → wrtun0, wrtun1… (default "wrtun")
	BaseSocks   int    // first local SOCKS port (default 11800)
	BaseTunNet  string // base /30 network for the host addresses (default "172.19.8.0")
	MTU         int    // TUN MTU (default 1400)
}

func (o *FallbackOptions) defaults() {
	if o.TunBaseName == "" {
		o.TunBaseName = "wrtun"
	}
	if o.BaseSocks == 0 {
		o.BaseSocks = 11800
	}
	if o.BaseTunNet == "" {
		o.BaseTunNet = "172.19.8.0" // distinct from the live singtun/vlesstun 172.19.0.x
	}
	if o.MTU == 0 {
		o.MTU = 1400
	}
}

// FallbackPlan is the sing-box config WayHop runs on Entware for the NON-native endpoints,
// plus the endpoint→TUN-device map the routing renderer uses (`ip route <cidr> <tun-iface>`).
type FallbackPlan struct {
	Config   map[string]any    // sing-box config (inbounds/outbounds/route) — written to /opt/etc/sing-box
	IfaceFor map[string]string // endpoint ID → TUN device name (wrtunN)
	Warnings []string          //
}

// SingboxFallback builds the sing-box fallback for non-native endpoints. Each endpoint gets:
// a `tun` inbound (interface_name=wrtunN, a /30 host address, mtu, auto_route:false,
// strict_route:false, stack:gvisor — sing-box provides ONLY the device; KeeneticOS adds the
// routes/metrics), a matching `socks` inbound (for health probes / chaining), its protocol
// outbound (reused from the generator), and a route rule tun+socks→outbound. Mirrors the
// validated live structure (tun-hy2→singtun / tun-vless→vlesstun). Pure.
func SingboxFallback(endpoints []*model.Endpoint, opt FallbackOptions) (*FallbackPlan, error) {
	opt.defaults()
	plan := &FallbackPlan{IfaceFor: map[string]string{}}

	inbounds := []map[string]any{}
	outbounds := []map[string]any{{"type": "direct", "tag": model.OutboundDirect}}
	var rules []map[string]any

	for i, e := range endpoints {
		tunIface := fmt.Sprintf("%s%d", opt.TunBaseName, i)
		tunTag := "tun-" + e.ID
		socksTag := "socks-" + e.ID
		socksPort := opt.BaseSocks + i
		addr, err := tunHostAddr(opt.BaseTunNet, i)
		if err != nil {
			return nil, fmt.Errorf("fallback %q: %w", e.ID, err)
		}
		ob, err := generator.OutboundFor(e)
		if err != nil {
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("endpoint %q: %v (skipped from fallback)", e.ID, err))
			continue
		}
		ob["tag"] = e.ID // route rule references the endpoint ID deterministically

		inbounds = append(inbounds,
			map[string]any{
				"type": "tun", "tag": tunTag, "interface_name": tunIface,
				"address": []string{addr}, "mtu": opt.MTU,
				"auto_route": false, "strict_route": false, "stack": "gvisor",
			},
			map[string]any{"type": "socks", "tag": socksTag, "listen": "127.0.0.1", "listen_port": socksPort},
		)
		outbounds = append(outbounds, ob)
		rules = append(rules, map[string]any{"inbound": []string{tunTag, socksTag}, "outbound": e.ID})
		plan.IfaceFor[e.ID] = tunIface
	}

	plan.Config = map[string]any{
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"route": map[string]any{
			"rules":                 rules,
			"final":                 model.OutboundDirect,
			"auto_detect_interface": true,
		},
	}
	return plan, nil
}

// tunHostAddr returns the i-th sequential /30 host address from base (base+i*4+1, /30) —
// matching the live 172.19.0.1/30, .5/30, … layout. Carries across octets correctly.
func tunHostAddr(base string, i int) (string, error) {
	a, err := netip.ParseAddr(base)
	if err != nil || !a.Is4() {
		return "", fmt.Errorf("bad base network %q", base)
	}
	b4 := a.As4()
	n := binary.BigEndian.Uint32(b4[:]) + uint32(i)*4 + 1
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], n)
	return netip.AddrFrom4(out).String() + "/30", nil
}
