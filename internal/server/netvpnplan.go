package server

import (
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"strings"

	"wayhop/internal/model"
	"wayhop/internal/netvpn"
	"wayhop/internal/platform"
)

// netvpnplan.go turns a model endpoint into the AmneziaWG interface WayHop wants /etc/config/network
// to hold, and serves the resulting uci plan read-only.
//
// This is the write direction; endpointFromDiscovered in vpndiscover.go is the read one. Both
// translations live here rather than in internal/netvpn so that package stays about the device.
//
// The awkward part is not the mapping but the SHAPE of what it maps from. Endpoint.Params is
// map[string]any, and a profile that has been through the store has been through JSON: every number
// arrives as float64 and every list as []any. A converter written against what the importer produces
// in memory works perfectly on a freshly imported endpoint and fails on every saved one — so each
// reader below accepts both, and the tests round-trip through JSON rather than testing the shape the
// importer happens to leave behind.

// awgInterfaceFromEndpoint keeps the compatibility helper used by focused conversion tests.
func awgInterfaceFromEndpoint(e model.Endpoint, ifname string) (netvpn.AWGInterface, error) {
	return netvpn.InterfaceFromEndpoint(e, ifname, netvpn.ProtoAmneziaWG)
}

// writableProto maps a model protocol onto the native protocol that would carry it, and reports
// whether this writer can express the endpoint at all. Only the WireGuard family has a native
// OpenWrt representation: vless/vmess/trojan/shadowsocks/hysteria2/tuic/anytls are proxy protocols
// with no uci `proto=` of any kind, and olcRTC is a userspace SOCKS plugin. Saying so here, once,
// keeps the refusal message accurate instead of "the uci writer is for amneziawg".
func writableProto(p model.Protocol) (netvpn.Proto, bool) {
	return netvpn.ProtoForModel(p)
}

// validUCIName rejects anything that is not a legal uci section name. The name reaches a shell as
// part of `uci set network.<name>=interface`, so this is a boundary, not a nicety.
func validUCIName(s string) error {
	if s == "" {
		return fmt.Errorf("no interface name given")
	}
	if len(s) > 15 {
		return fmt.Errorf("interface name %q is longer than the 15 characters a kernel interface can carry", s)
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
		default:
			return fmt.Errorf("interface name %q contains %q; uci section names allow only letters, digits and underscore", s, string(r))
		}
	}
	return nil
}

// handleNetvpnPlan serves GET /api/netvpn/plan — the exact uci commands that would create or update
// an endpoint's AmneziaWG interface, and nothing else. It reads the router's current configuration
// and renders a plan; it runs no command that changes anything.
//
// buildNetvpnPlan turns a request into the plan it describes, or into the status and message that
// says why it cannot. Shared by the preview and the apply so the two cannot drift: the whole point
// of pinning an apply to a reviewed plan is lost if the two endpoints build it differently.
func (s *Server) buildNetvpnPlan(r *http.Request) (netvpn.Plan, int, error) {
	q := r.URL.Query()
	id := strings.TrimSpace(q.Get("endpoint"))
	if id == "" {
		return netvpn.Plan{}, http.StatusBadRequest, fmt.Errorf("endpoint id required")
	}
	prof := s.store.Profile()
	var ep *model.Endpoint
	for i := range prof.Endpoints {
		if prof.Endpoints[i].ID == id {
			ep = &prof.Endpoints[i]
			break
		}
	}
	if ep == nil {
		return netvpn.Plan{}, http.StatusNotFound, fmt.Errorf("no endpoint with id %s", id)
	}
	proto, ok := writableProto(ep.Protocol)
	if !ok {
		return netvpn.Plan{}, http.StatusUnprocessableEntity, fmt.Errorf(
			"endpoint %q is %s, which has no native OpenWrt protocol — only the WireGuard family "+
				"(wireguard, amneziawg) can be written to /etc/config/network; this endpoint is carried "+
				"by sing-box", ep.Name, ep.Protocol)
	}

	// The section name is DERIVED, not chosen. A caller may state it, but only the derived one is
	// accepted: the routing plane derives the same name independently (pbr.kernelIface), and nothing
	// records a chosen one — so any other value produces a tunnel that is configured, visible in
	// LuCI, and has no route pointing at it. Recording the choice instead would work, but it would
	// also change the profile and therefore the applied-revision hash, reporting "unapplied changes"
	// the moment a native apply succeeded.
	derived := defaultIfaceName(*ep)
	ifname := strings.TrimSpace(q.Get("iface"))
	if ifname == "" {
		ifname = derived
	} else if ifname != derived {
		return netvpn.Plan{}, http.StatusUnprocessableEntity, fmt.Errorf(
			"interface name %q cannot be used for endpoint %s: the routing plane derives %q for it, "+
				"and a tunnel written under any other name would carry no routes", ifname, ep.ID, derived)
	}
	// Written up to the generation the Apply's capture would compile with (awgkernel.go): the 3.x
	// settings the module and the netifd handler carry are written, and those they do not are refused.
	intended, err := netvpn.InterfaceFromEndpointFor(*ep, ifname, proto, s.awgKernelGeneration())
	if err != nil {
		return netvpn.Plan{}, http.StatusUnprocessableEntity, err
	}

	read := s.uciReader
	if read == nil {
		read = readUCI
	}
	netOut, fwOut, err := read()
	if err != nil {
		// Not an empty plan. A plan built from an unreadable router would look exactly like a plan
		// for a router with nothing configured, and the difference is whether applying it would
		// overwrite somebody's tunnel.
		return netvpn.Plan{}, http.StatusServiceUnavailable,
			fmt.Errorf("cannot read the router's uci configuration: %w", err)
	}

	// The router's own netifd handler set decides which protocol may actually be written. Without it
	// a WireGuard endpoint on a live AX3000T would be written as proto='wireguard' on a box
	// that has no wireguard.sh — visible in LuCI, never brought up. With it the plan either falls
	// back to a protocol the router does carry and says so, or refuses and names the package.
	plan, err := netvpn.BuildPlanFor(intended, s.routerProtos(), strings.TrimSpace(q.Get("zone")), netOut, fwOut)
	if err != nil {
		if errors.Is(err, netvpn.ErrRouterProtosUnprobed) {
			return netvpn.Plan{}, http.StatusServiceUnavailable, err
		}
		return netvpn.Plan{}, http.StatusUnprocessableEntity, err
	}
	return plan, http.StatusOK, nil
}

// routerProtos answers "which netifd protocol handlers does this box have". nil is production (ask
// the platform probe); tests inject, because no development host has /lib/netifd/proto at all. A nil
// answer fails closed with 503: native writes are unavailable until support can be proven.
func (s *Server) routerProtos() netvpn.RouterProtos {
	if s.netifdProtosOf != nil {
		return s.netifdProtosOf()
	}
	return netvpn.RouterProtos(platform.DetectCapabilities().NetifdProtos)
}

func (s *Server) handleNetvpnPlan(w http.ResponseWriter, r *http.Request) {
	plan, code, err := s.buildNetvpnPlan(r)
	if err != nil {
		writeErr(w, code, err.Error())
		return
	}
	ep := strings.TrimSpace(r.URL.Query().Get("endpoint"))
	ifname := plan.Iface

	read := s.uciReader
	if read == nil {
		read = readUCI
	}
	netOut, fwOut, rerr := read()
	if rerr != nil {
		writeErr(w, http.StatusServiceUnavailable, "cannot read the router's uci configuration: "+rerr.Error())
		return
	}
	removal, remErr := netvpn.BuildRemovalPlan(ifname, netOut, fwOut)
	removalCmds := []string{}
	if remErr == nil {
		removalCmds = append(append([]string{}, removal.Commands...), removal.Commit...)
	}

	warnings := plan.Warnings
	if warnings == nil {
		warnings = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"endpoint": ep,
		// plan_hash is what an apply must echo back in If-Match. It covers the staged commands AND
		// the commit tail, so "I reviewed this" is a checkable claim rather than a courtesy.
		"plan_hash": planHash(plan),
		"iface":     plan.Iface,
		"exists":    plan.Expected.Name != "",
		"zone":      plan.Zone,
		"zone_ref":  plan.ZoneRef,
		"commands":  plan.Commands,
		"commit":    plan.Commit,
		"removal":   removalCmds,
		"warnings":  warnings,
	})
}

// defaultIfaceName is the uci section name a natively-written AmneziaWG tunnel gets.
//
// It is the SAME identity the rest of the daemon uses — `util.AWGIface(id)` — with its hyphen
// changed to an underscore, because uci will not take a hyphen in a section name (measured on
// OpenWrt 24.10: `uci set network.wr-1a2b3c4d=interface` answers "Invalid argument"; the underscore
// form is accepted, and Linux is happy to carry either as a device name).
//
// The first version invented its own scheme, `wh_` plus a sanitised endpoint id, without noticing
// that pbr.kernelIface already derives a name for the same endpoint. The two disagreed completely,
// so the routing plane installed `dev wr-1a2b3c4d` for a tunnel the writer had created as
// `wh_ep_awg_1`: present in LuCI, configured, and carrying nothing. Sharing the identity function
// is what stops that recurring; the apply path then RECORDS the result on the endpoint so nothing
// has to derive it twice at all.
func defaultIfaceName(e model.Endpoint) string {
	return uciSafeIface(netvpn.InterfaceName(e))
}

// uciSafeIface is now the identity: util.AWGIface already emits a uci-legal name. Kept as the one
// place that would change if that ever stopped being true.
func uciSafeIface(s string) string { return s }

// uciReader lets a test drive the handler on a host with no uci, and — more to the point — on one
// where reading FAILS, which is the case whose answer must not resemble "the router has nothing
// configured". nil means the real reader.
type uciReadFunc func() (network, firewall string, err error)

// readUCI takes both snapshots at the same moment, because a plan built from a network config read
// now and a firewall config read later describes a router that never existed.
func readUCI() (network, firewall string, err error) {
	if _, err := exec.LookPath("uci"); err != nil {
		return "", "", fmt.Errorf("uci is not available on this host")
	}
	out := make([]string, 2)
	for i, cfg := range []string{"network", "firewall"} {
		b, err := exec.Command("uci", "show", cfg).CombinedOutput()
		if err != nil {
			return "", "", fmt.Errorf("uci show %s: %w", cfg, err)
		}
		out[i] = string(b)
	}
	return out[0], out[1], nil
}
