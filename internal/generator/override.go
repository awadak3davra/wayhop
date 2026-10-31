package generator

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strings"
)

// The operator's core override (config.Config.CoreOverride; competitor gap 11: nikki merges its
// mixin.yaml into the profile it generates, any key overwriting, and its nikki-proxies,
// nikki-proxy-groups and nikki-rules go in front of the generated lists). It is JSON text:
//
//	{ ...an RFC 7396 merge patch...,
//	  "prepend": { "outbounds": [...], "route.rules": [...], "dns.rules": [...], "dns.servers": [...] } }
//
// Generate applies it LAST, after every schema fit, so it is the final word on what the core reads:
// first each prepend array goes in front of the generated array at its path, then the rest merges as
// a JSON merge patch - objects merge key by key, null deletes a key, and anything else, an array
// included, replaces what was there. Prepend exists because a merge patch can only replace an array:
// without it, one rule ahead of the generated ones would mean restating every generated rule, and
// the restated copy would silently stop following the profile.
//
// "In front" of route.rules means in front of every rule the profile makes - its rules, then its
// routing lists - but AFTER WayHop's guard rules, which lead the list: the probe users' rules (no
// other rule may see a probe, or the per-exit service check measures the routing instead of the
// exit), the TUN's sniff action, and the bypass that sends each tunnel's own server address direct.
// A broad prepended rule ahead of that bypass would send a tunnel's handshake into a tunnel, its own
// included, and nothing would say so. The guards match only WayHop's own traffic (sniff matches all
// of it but routes none), so behind them a prepended rule still decides every connection the
// profile would; and because the sniff is ahead of it, a domain rule for TUN traffic works without a
// sniff of its own. The KeeneticOS connection core has only the probe rules as guards. WayHop emits
// no guard DNS rules, so prepended dns.rules, like outbounds and dns.servers, go first.
//
// Whether the result is a working sing-box config is mostly not judged here. Apply runs `sing-box
// check` on the patched bytes, the same bytes it then writes, and the fail-safe window covers what
// check cannot. What check cannot is measured, on 1.12.17, 1.13.21 and 1.14.4: it refuses a misspelt
// key or an unknown type, but passes a rule, a selector member or route.final naming an outbound the
// config does not have. A missing route.final then stops the core at start, which Apply sees; with a
// rule to a missing outbound the core runs, and each connection the rule matches fails ("router:
// outbound not found", 1.14.4 on Linux) - no check and no window would say so. That one case is
// judged here, for the override's own rules: an override written against one config meets another
// (the KeeneticOS per-connection core has none of the generated groups), and a tag that exists in
// the first is exactly the mistake nobody would see.

// CoreOverrideMaxBytes bounds the override. Generous for hand-written JSON (a dozen rules and a few
// outbounds are a few KiB) while keeping config.json, which the daemon rewrites on every Settings
// save, small on a router's flash.
const CoreOverrideMaxBytes = 64 << 10

// coreOverridePrependKey is the override's one key that is not part of the merge patch.
const coreOverridePrependKey = "prepend"

// coreOverridePrependPaths are the arrays prepend may add to, in the order they are applied. All four
// are lists sing-box evaluates first-match or by tag, which is why going in front is what an operator
// asks for; anything else is reachable through the merge patch.
var coreOverridePrependPaths = []string{"outbounds", "dns.servers", "dns.rules", "route.rules"}

// CoreOverride is a parsed override. Apply hands its values to the config it patches, so parse once
// per config: two configs patched from one CoreOverride would share, and could edit, the same maps.
type CoreOverride struct {
	patch   map[string]any
	prepend map[string][]any
}

// ParseCoreOverride reads the override text. Blank text is no override (nil, nil). The errors name
// what to fix, because config.Validate shows them as the reason a Settings save was refused.
func ParseCoreOverride(text string) (*CoreOverride, error) {
	if strings.TrimSpace(text) == "" {
		return nil, nil
	}
	if len(text) > CoreOverrideMaxBytes {
		return nil, fmt.Errorf("core override is %d bytes; the limit is %d", len(text), CoreOverrideMaxBytes)
	}
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber() // numbers reach the core exactly as written, not via float64
	var root any
	if err := dec.Decode(&root); err != nil {
		return nil, fmt.Errorf("core override is not valid JSON: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("core override has text after its JSON object")
	}
	patch, ok := root.(map[string]any)
	if !ok {
		return nil, errors.New("core override must be a JSON object (the keys of the sing-box config to change)")
	}
	o := &CoreOverride{patch: patch}
	raw, has := patch[coreOverridePrependKey]
	if !has {
		return o, nil
	}
	delete(patch, coreOverridePrependKey)
	pre, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("core override: prepend must be an object naming %s", prependPathList())
	}
	o.prepend = make(map[string][]any, len(pre))
	for path, v := range pre {
		if !isPrependPath(path) {
			return nil, fmt.Errorf("core override: prepend %q is not supported; prepend takes only %s", path, prependPathList())
		}
		items, ok := v.([]any)
		if !ok {
			return nil, fmt.Errorf("core override: prepend %q must be an array", path)
		}
		for i, it := range items {
			if _, ok := it.(map[string]any); !ok {
				return nil, fmt.Errorf("core override: prepend %q item %d must be a JSON object", path, i+1)
			}
		}
		// The merge patch runs second, so a patch that also sets this array (or deletes or replaces
		// what holds it) would discard the prepended items without a word. Refuse the pair instead.
		if at := patchShadows(patch, strings.Split(path, ".")); at != "" {
			return nil, fmt.Errorf("core override: prepend %q would be discarded, because the merge patch also sets %s; keep those entries in one place", path, at)
		}
		o.prepend[path] = items
	}
	return o, nil
}

func isPrependPath(path string) bool {
	for _, p := range coreOverridePrependPaths {
		if p == path {
			return true
		}
	}
	return false
}

func prependPathList() string {
	return strings.Join(coreOverridePrependPaths, ", ")
}

// patchShadows returns the dotted key at which the merge patch replaces or deletes something on path,
// or "" when it leaves the array at path to the prepend.
func patchShadows(patch map[string]any, path []string) string {
	node := patch
	for i, key := range path {
		v, ok := node[key]
		if !ok {
			return ""
		}
		next, isObject := v.(map[string]any)
		if i == len(path)-1 || !isObject {
			return strings.Join(path[:i+1], ".")
		}
		node = next
	}
	return ""
}

// ApplyCoreOverride parses text and applies it to cfg, then refuses the result when one of the
// override's own route rules sends to an outbound cfg does not have. Blank text leaves cfg alone.
// routeGuards is how many of cfg's leading route rules are WayHop's guards (see the top of this
// file); prepended route rules go right after them.
func ApplyCoreOverride(cfg map[string]any, text string, routeGuards int) error {
	o, err := ParseCoreOverride(text)
	if err != nil {
		return err
	}
	o.Apply(cfg, routeGuards)
	return o.checkRuleOutbounds(cfg)
}

// checkRuleOutbounds is the reference check `sing-box check` does not make (see the top of this
// file), for the route rules the override wrote: the prepended ones and a route.rules list the patch
// replaced. Generated rules are the generator's to keep consistent, and its tests do.
func (o *CoreOverride) checkRuleOutbounds(cfg map[string]any) error {
	if o == nil {
		return nil
	}
	rules := o.prepend["route.rules"]
	if route, ok := o.patch["route"].(map[string]any); ok {
		replaced, _ := route["rules"].([]any)
		rules = append(append([]any(nil), rules...), replaced...)
	}
	if len(rules) == 0 {
		return nil
	}
	tags := map[string]bool{}
	for _, key := range []string{"outbounds", "endpoints"} {
		forEachObject(cfg[key], func(m map[string]any) {
			if t, _ := m["tag"].(string); t != "" {
				tags[t] = true
			}
		})
	}
	for i, r := range rules {
		rule, _ := r.(map[string]any)
		if tag, _ := rule["outbound"].(string); tag != "" && !tags[tag] {
			return fmt.Errorf("core override: route rule %d sends to outbound %q, which this config does not have "+
				"(sing-box would start, and fail every connection the rule matches)", i+1, tag)
		}
	}
	return nil
}

// forEachObject calls fn for every object in a generated ([]map[string]any) or decoded ([]any) list.
func forEachObject(list any, fn func(map[string]any)) {
	switch l := list.(type) {
	case []map[string]any:
		for _, m := range l {
			fn(m)
		}
	case []any:
		for _, v := range l {
			if m, ok := v.(map[string]any); ok {
				fn(m)
			}
		}
	}
}

// Apply patches cfg in place: the prepend arrays first, then the merge patch. Prepended route rules
// go after the first routeGuards rules, WayHop's guards; every other prepend goes first.
func (o *CoreOverride) Apply(cfg map[string]any, routeGuards int) {
	if o == nil || cfg == nil {
		return
	}
	for _, path := range coreOverridePrependPaths {
		if items, ok := o.prepend[path]; ok {
			at := 0
			if path == "route.rules" {
				at = routeGuards
			}
			prependAt(cfg, strings.Split(path, "."), items, at)
		}
	}
	for k, v := range o.patch {
		if v == nil {
			delete(cfg, k)
			continue
		}
		cfg[k] = mergePatch(cfg[k], v)
	}
}

// prependAt puts items into the array at path, ahead of everything from index at on (at is clamped
// to the array), creating the objects on the way when the generated config has none (no DNS plane,
// say): a prepended list then is the whole list.
func prependAt(cfg map[string]any, path []string, items []any, at int) {
	parent := cfg
	for _, key := range path[:len(path)-1] {
		next, ok := parent[key].(map[string]any)
		if !ok {
			next = map[string]any{}
		} else {
			next = cloneObject(next)
		}
		parent[key] = next
		parent = next
	}
	last := path[len(path)-1]
	clamp := func(n int) int { return max(0, min(at, n)) }
	switch cur := parent[last].(type) {
	case []map[string]any:
		// Keep the generated element type: code after Generate type-asserts these lists, and every
		// prepended item is an object (ParseCoreOverride refuses anything else).
		i := clamp(len(cur))
		out := make([]map[string]any, 0, len(items)+len(cur))
		out = append(out, cur[:i]...)
		for _, it := range items {
			out = append(out, it.(map[string]any))
		}
		parent[last] = append(out, cur[i:]...)
	case []any:
		i := clamp(len(cur))
		out := make([]any, 0, len(items)+len(cur))
		out = append(append(append(out, cur[:i]...), items...), cur[i:]...)
		parent[last] = out
	default:
		parent[last] = items
	}
}

// mergePatch is RFC 7396 MergePatch. Objects are copied before they are changed, so a map the
// generator shares between configs is never edited through this one.
func mergePatch(target, patch any) any {
	p, ok := patch.(map[string]any)
	if !ok {
		return patch
	}
	t, _ := target.(map[string]any)
	out := cloneObject(t)
	for k, v := range p {
		if v == nil {
			delete(out, k)
			continue
		}
		out[k] = mergePatch(out[k], v)
	}
	return out
}

func cloneObject(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// Keys lists the top-level config keys the override touches, sorted: the merge patch's own keys and
// the first segment of each prepend path. The Apply review and the change list show these rather
// than the override itself, which may carry an outbound's credentials.
func (o *CoreOverride) Keys() []string {
	if o == nil {
		return nil
	}
	seen := map[string]bool{}
	for k := range o.patch {
		seen[k] = true
	}
	for path := range o.prepend {
		root, _, _ := strings.Cut(path, ".")
		seen[root] = true
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// OpenListeners names every listener the override sets that is not on loopback: an inbound in a
// replaced `inbounds` list, a service in `services` (ssm-api, derp, resolved: each listens like an
// inbound, and an ssm-api manages the users of a Shadowsocks inbound), and the Clash API controller.
// WayHop's own inbounds and its controller all listen on 127.0.0.1 and it emits no services, so a
// listener anywhere else is the override's, and anyone who can reach that address can use it - an
// open proxy, or a remote control for the core, on the LAN or the WAN.
//
// An inbound or service without `listen` is on loopback: measured with `sing-box run`, an inbound
// with only listen_port bound 127.0.0.1 on 1.13.21 and 1.14.4, and so did an ssm-api service on
// 1.14.4 (with listen 0.0.0.0 it bound 0.0.0.0). A TUN inbound has no socket to listen on.
func (o *CoreOverride) OpenListeners() []string {
	if o == nil {
		return nil
	}
	var out []string
	for _, list := range []struct{ key, kind string }{{"inbounds", "inbound"}, {"services", "service"}} {
		items, _ := o.patch[list.key].([]any)
		for i, v := range items {
			in, ok := v.(map[string]any)
			if !ok || in["type"] == "tun" {
				continue
			}
			listen, _ := in["listen"].(string)
			if listen == "" || isLoopbackHost(listen) {
				continue
			}
			name, _ := in["tag"].(string)
			if name == "" {
				name = fmt.Sprintf("#%d", i+1)
			}
			typ, _ := in["type"].(string)
			out = append(out, fmt.Sprintf("%s %s (%s) on %s", list.kind, name, typ, listenAddr(listen, in["listen_port"])))
		}
	}
	exp, _ := o.patch["experimental"].(map[string]any)
	clash, _ := exp["clash_api"].(map[string]any)
	if ctl, _ := clash["external_controller"].(string); ctl != "" {
		host, _, err := net.SplitHostPort(ctl)
		if err != nil || !isLoopbackHost(host) {
			out = append(out, "Clash API controller on "+ctl)
		}
	}
	return out
}

// DaemonUse is what the daemon itself reaches the core through, for DaemonLosses: the Clash API at
// ClashAddr with ClashSecret (an empty ClashAddr: the generated core has no Clash API to lose), and
// the probe inbound when Probe.
type DaemonUse struct {
	ClashAddr, ClashSecret string
	Probe                  bool
}

// DaemonLossKind says which of the daemon's ways into the core a DaemonLoss takes.
type DaemonLossKind int

const (
	LossClashAPI   DaemonLossKind = iota + 1 // experimental.clash_api, or its controller or secret
	LossProbe                                // the probe inbound
	LossInbounds                             // the generated inbounds, restated or deleted
	LossRouteRules                           // the generated route rules, the guards among them
)

// DaemonLoss is one way an override takes from the daemon what it runs the core through. Item says
// what the override does, in the config's own key names, never with a value: a secret is a value.
type DaemonLoss struct {
	Kind DaemonLossKind
	Item string
}

// DaemonLosses lists what the override takes from the daemon's own use of the core. The core runs
// without any of it and `sing-box check` passes, so nothing else would say it; the features that use
// the core through it just stop. Listed:
//
//   - experimental or experimental.clash_api deleted or replaced, or its controller or secret set to
//     anything but what WayHop asks with. A controller on WayHop's port with no host or an unspecified
//     one (":9090", "0.0.0.0:9090") still answers on loopback, so it is no loss here (it is an open
//     listener, which OpenListeners names).
//   - inbounds replaced or deleted, and the probe inbound when the replacement does not restate it.
//   - route deleted or replaced, or route.rules replaced: the generated rules, guards included.
func (o *CoreOverride) DaemonLosses(use DaemonUse) []DaemonLoss {
	if o == nil {
		return nil
	}
	var out []DaemonLoss
	if use.ClashAddr != "" {
		for _, item := range o.clashAPILosses(use) {
			out = append(out, DaemonLoss{LossClashAPI, item})
		}
	}
	if v, ok := o.patch["inbounds"]; ok {
		item := "inbounds replaced"
		if v == nil {
			item = "inbounds deleted"
		}
		out = append(out, DaemonLoss{LossInbounds, item})
		if use.Probe && !listHasTag(v, ProbeInboundTag) {
			out = append(out, DaemonLoss{LossProbe, "inbound " + ProbeInboundTag + " dropped"})
		}
	}
	if v, ok := o.patch["route"]; ok {
		route, isObject := v.(map[string]any)
		_, rules := route["rules"]
		switch {
		case v == nil:
			out = append(out, DaemonLoss{LossRouteRules, "route deleted"})
		case !isObject:
			out = append(out, DaemonLoss{LossRouteRules, "route replaced"})
		case rules:
			out = append(out, DaemonLoss{LossRouteRules, "route.rules replaced"})
		}
	}
	return out
}

func (o *CoreOverride) clashAPILosses(use DaemonUse) []string {
	v, ok := o.patch["experimental"]
	exp, isObject := v.(map[string]any)
	switch {
	case !ok:
		return nil
	case v == nil:
		return []string{"experimental deleted"}
	case !isObject:
		return []string{"experimental replaced"}
	}
	v, ok = exp["clash_api"]
	clash, isObject := v.(map[string]any)
	switch {
	case !ok:
		return nil
	case v == nil:
		return []string{"experimental.clash_api deleted"}
	case !isObject:
		return []string{"experimental.clash_api replaced"}
	}
	var out []string
	if v, ok := clash["external_controller"]; ok {
		if ctl, _ := v.(string); !sameController(ctl, use.ClashAddr) {
			out = append(out, "experimental.clash_api.external_controller changed")
		}
	}
	if v, ok := clash["secret"]; ok {
		if s, isString := v.(string); (v != nil && !isString) || s != use.ClashSecret {
			out = append(out, "experimental.clash_api.secret changed")
		}
	}
	return out
}

// sameController reports whether a controller listening on ctl still answers at want: the same
// address, or want's port on every address (no host, 0.0.0.0, ::).
func sameController(ctl, want string) bool {
	if ctl == want {
		return true
	}
	host, port, err := net.SplitHostPort(ctl)
	_, wantPort, wantErr := net.SplitHostPort(want)
	if err != nil || wantErr != nil || port != wantPort {
		return false
	}
	a, err := netip.ParseAddr(host)
	return host == "" || (err == nil && a.IsUnspecified())
}

func listHasTag(list any, tag string) bool {
	found := false
	forEachObject(list, func(m map[string]any) {
		found = found || m["tag"] == tag
	})
	return found
}

// isLoopbackHost reports whether host is a loopback IP literal. A name is not: sing-box takes an
// address there, and a name cannot be proved to stay on loopback.
func isLoopbackHost(host string) bool {
	a, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil && a.IsLoopback()
}

func listenAddr(listen string, port any) string {
	if port == nil {
		return listen
	}
	return net.JoinHostPort(listen, fmt.Sprint(port))
}
