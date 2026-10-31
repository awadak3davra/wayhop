package keenetic

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"

	"wayhop/internal/generator"
	"wayhop/internal/model"
)

// FallbackOptions tune the sing-box fallback (per-endpoint TUN device naming + addressing).
// Defaults match the live reference router reference (singtun/vlesstun: mtu 1400, /30 host
// addresses, gvisor stack, auto_route off — NDM owns the routing/metric tiers).
type FallbackOptions struct {
	TunBaseName string // TUN device prefix → wrtun0, wrtun1… (default "wrtun")
	BaseSocks   int    // first local SOCKS port (default 11800)
	BaseTunNet  string // base /30 network for the host addresses (default "172.19.8.0")
	MTU         int    // TUN MTU (default 1400)

	// ProbePort and ClashSecret give this core the probe inbound the per-exit service check asks
	// through (generator/probe.go), from the same two settings the generated core takes them from.
	// Without it every exit here reads "Apply once" on KeeneticOS however often it is Applied.
	ProbePort   int
	ClashSecret string
	// CoreVersion is the detected sing-box, for the options only some versions carry (Hysteria2's
	// gecko and Realm need 1.14). Empty is "unknown", as everywhere in the generator.
	CoreVersion string
}

func (o *FallbackOptions) defaults() {
	if o.TunBaseName == "" {
		o.TunBaseName = "wrtun"
	}
	if o.BaseSocks == 0 {
		o.BaseSocks = 11800
	}
	if o.BaseTunNet == "" {
		o.BaseTunNet = "172.19.8.0" // distinct from the live singtun/vlesstun 172.31.3.x
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
// validated live structure (tun-hy2→singtun / tun-vless→vlesstun). With opt.ProbePort the config
// also carries the generator's probe inbound over every outbound, direct included. Pure.
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
		ob, err := generator.OutboundForCore(e, opt.CoreVersion)
		if err != nil {
			return nil, fmt.Errorf("endpoint %q cannot be materialized by the sing-box compatibility addon: %w", e.ID, err)
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

	// One probe user per outbound, its rules first like the generator's. Not when the port lands in
	// the SOCKS block above: two listeners on one port stop the core - and then said, because the
	// service check would otherwise ask the operator to Apply again, which changes nothing.
	probeIn, probeRules := generator.ProbeFor(opt.ProbePort, opt.ClashSecret, outbounds, nil)
	switch {
	case probeIn == nil:
	case opt.ProbePort >= opt.BaseSocks && opt.ProbePort < opt.BaseSocks+len(endpoints):
		plan.Warnings = append(plan.Warnings, fmt.Sprintf("the service check's probe port %d falls among the "+
			"connections' local SOCKS ports (%d-%d), so the check cannot ask through these connections; "+
			"change the mixed port in Settings", opt.ProbePort, opt.BaseSocks, opt.BaseSocks+len(endpoints)-1))
	default:
		inbounds = append(inbounds, probeIn)
		rules = append(probeRules, rules...)
	}

	plan.Config = map[string]any{
		// The generator's level. With no log block sing-box logs at trace, and its info lines alone
		// name every connection's destination: measured on 1.13.21, one proxied request wrote
		// "inbound connection to <ip>:80" and three more lines - a router's CPU, and a record of
		// where every client went, in the daemon's log.
		"log":       map[string]any{"level": "warn", "timestamp": true},
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

// FallbackDatapath is the part of a fallback core that NDM routes into, as SingboxFallback built it:
// per connection, its TUN device (the wrtunN that IfaceFor names and the plan's routes target), the
// local SOCKS inbound beside it, and the rule that sends both to the connection's outbound.
//
// A core override (config.Config.CoreOverride) is applied to this core too, and it can only replace
// `inbounds` and `route.rules` wholesale. An override written for the generated config does exactly
// that, and without this the devices NDM routes into would be gone, or routing (auto_route), while
// `sing-box check` passes and the fail-safe, which pings outside the core, sees nothing. So it is
// captured before the override and re-asserted after it: WayHop's datapath fields always win, and an
// override whose shape cannot keep them is refused rather than written.
type FallbackDatapath struct {
	inbounds []map[string]any // the TUN and SOCKS inbounds, copied, in the core's order
	rules    []map[string]any // each connection's rule, copied
	tunTags  map[string]bool
}

// fallbackTUNFields are the fields of a connection's TUN that NDM's routes depend on: the device and
// its address, and a core that leaves the routing to NDM. The stack is the one SingboxFallback chose
// (and FitTUNToCore kept). The MTU and the rest are the operator's to tune.
var fallbackTUNFields = []string{"interface_name", "address", "stack"}

// CaptureFallbackDatapath reads the datapath out of a fallback core, built or decoded from JSON, and
// checks it against the plan: each connection's TUN must be on the device IfaceFor routes it to.
func CaptureFallbackDatapath(cfg map[string]any, ifaceFor map[string]string) (*FallbackDatapath, error) {
	inbounds, err := objectList(cfg["inbounds"], "inbounds")
	if err != nil {
		return nil, err
	}
	d := &FallbackDatapath{tunTags: map[string]bool{}}
	for _, in := range inbounds {
		switch in["type"] {
		case "tun":
			tag, _ := in["tag"].(string)
			d.tunTags[tag] = true
			d.inbounds = append(d.inbounds, cloneMap(in))
		case "socks":
			d.inbounds = append(d.inbounds, cloneMap(in))
		}
	}
	for _, id := range sortedKeys(ifaceFor) {
		for _, in := range d.inbounds {
			if in["tag"] == "tun-"+id && in["interface_name"] != ifaceFor[id] {
				return nil, fmt.Errorf("the fallback core puts connection %q on %v, but the plan routes it to %s", id, in["interface_name"], ifaceFor[id])
			}
		}
	}
	route, _ := cfg["route"].(map[string]any)
	rules, err := objectList(route["rules"], "route.rules")
	if err != nil {
		return nil, err
	}
	for _, r := range rules {
		if d.namesTUN(r) {
			d.rules = append(d.rules, cloneMap(r))
		}
	}
	return d, nil
}

// Reassert puts the datapath back into cfg after a core override:
//
//   - each TUN and SOCKS inbound the override dropped comes back as it was built;
//   - one it restated (same tag) gets the datapath fields back - a TUN its device, address and
//     stack, with auto_route, auto_redirect and strict_route off; a SOCKS inbound its loopback
//     listen and port - and keeps the rest of what the override wrote;
//   - a connection's rule comes back, after the override's own, when no route rule names its TUN.
//
// Refused, because no re-assertion can make them right: a restated datapath inbound of another
// type or written twice, a TUN of the override's own that routes (auto_route or auto_redirect: on
// KeeneticOS NDM owns the routing, and this core only provides devices) or that takes a datapath
// device, another inbound on a datapath SOCKS port, and an override that deletes or replaces
// `inbounds` or `route` with something that is not a list or an object.
func (d *FallbackDatapath) Reassert(cfg map[string]any) error {
	if d == nil {
		return nil
	}
	inbounds, err := objectList(cfg["inbounds"], "inbounds")
	if err != nil {
		return fmt.Errorf("core override: %w", err)
	}
	owned := map[string]map[string]any{} // datapath tag -> the generated inbound
	devices, ports := map[string]string{}, map[string]string{}
	for _, want := range d.inbounds {
		tag, _ := want["tag"].(string)
		owned[tag] = want
		if dev, _ := want["interface_name"].(string); dev != "" {
			devices[dev] = tag
		}
		if port := want["listen_port"]; port != nil {
			ports[fmt.Sprint(port)] = tag
		}
	}
	seen := map[string]bool{}
	for _, in := range inbounds {
		tag, _ := in["tag"].(string)
		want, isOwned := owned[tag]
		if !isOwned {
			if err := checkForeignInbound(in, devices, ports); err != nil {
				return err
			}
			continue
		}
		if seen[tag] {
			return fmt.Errorf("core override: inbound %q appears twice; it is a KeeneticOS connection's own, so write it once", tag)
		}
		seen[tag] = true
		if in["type"] != want["type"] {
			return fmt.Errorf("core override: inbound %q is a KeeneticOS connection's %v inbound, which NDM's routes depend on; it cannot become %v", tag, want["type"], in["type"])
		}
		if want["type"] == "tun" {
			for _, k := range fallbackTUNFields {
				if v, ok := want[k]; ok {
					in[k] = v
				} else {
					delete(in, k)
				}
			}
			in["auto_route"], in["strict_route"] = false, false
			delete(in, "auto_redirect") // off when absent, as SingboxFallback leaves it
			continue
		}
		in["listen"], in["listen_port"] = want["listen"], want["listen_port"]
	}
	for _, want := range d.inbounds {
		if tag, _ := want["tag"].(string); !seen[tag] {
			inbounds = append(inbounds, cloneMap(want))
		}
	}
	cfg["inbounds"] = inbounds
	return d.reassertRules(cfg)
}

// reassertRules gives back each connection's rule that no route rule names the TUN of any more.
func (d *FallbackDatapath) reassertRules(cfg map[string]any) error {
	if len(d.rules) == 0 {
		return nil
	}
	route, ok := cfg["route"].(map[string]any)
	if !ok {
		return fmt.Errorf("core override: this KeeneticOS router's connection core routes each connection by a route rule, so the override cannot delete or replace route")
	}
	rules, err := objectList(route["rules"], "route.rules")
	if err != nil {
		return fmt.Errorf("core override: %w", err)
	}
	named := map[string]bool{} // the datapath TUNs some rule after the override still names
	for _, r := range rules {
		for _, tag := range inboundTags(r) {
			named[tag] = d.tunTags[tag]
		}
	}
	for _, want := range d.rules {
		lost := true
		for _, tag := range inboundTags(want) {
			lost = lost && !named[tag]
		}
		if lost {
			rules = append(rules, cloneMap(want))
		}
	}
	route["rules"] = rules
	return nil
}

// namesTUN reports whether a rule matches inbounds and names one of the datapath TUNs.
func (d *FallbackDatapath) namesTUN(r map[string]any) bool {
	for _, tag := range inboundTags(r) {
		if d.tunTags[tag] {
			return true
		}
	}
	return false
}

func inboundTags(r map[string]any) []string {
	switch in := r["inbound"].(type) {
	case string:
		return []string{in}
	case []string:
		return in
	case []any:
		out := make([]string, 0, len(in))
		for _, v := range in {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// checkForeignInbound refuses an inbound of the override's own that would fight the datapath.
func checkForeignInbound(in map[string]any, devices, ports map[string]string) error {
	name, _ := in["tag"].(string)
	if name == "" {
		name = fmt.Sprintf("%v", in["type"])
	}
	if in["type"] == "tun" {
		if in["auto_route"] == true || in["auto_redirect"] == true {
			return fmt.Errorf("core override: inbound %q is a TUN that routes (auto_route); on this KeeneticOS router NDM routes "+
				"the connections and this core only provides their devices, so remove it or turn auto_route off", name)
		}
		if dev, _ := in["interface_name"].(string); devices[dev] != "" {
			return fmt.Errorf("core override: inbound %q takes device %s, which NDM routes a connection into through inbound %q", name, dev, devices[dev])
		}
		return nil
	}
	if port := in["listen_port"]; port != nil && ports[fmt.Sprint(port)] != "" {
		return fmt.Errorf("core override: inbound %q takes port %v, the local SOCKS port of inbound %q", name, port, ports[fmt.Sprint(port)])
	}
	return nil
}

// objectList reads a list of objects, built or decoded from JSON; absent is empty.
func objectList(v any, what string) ([]map[string]any, error) {
	switch l := v.(type) {
	case nil:
		return nil, nil
	case []map[string]any:
		return l, nil
	case []any:
		out := make([]map[string]any, 0, len(l))
		for i, item := range l {
			m, ok := item.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%s item %d is not an object", what, i+1)
			}
			out = append(out, m)
		}
		return out, nil
	}
	return nil, fmt.Errorf("%s is not a list", what)
}

func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// tunHostAddr returns the i-th sequential /30 host address from base (base+i*4+1, /30) —
// matching the live 172.31.3.1/30, .5/30, … layout. Carries across octets correctly.
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
