package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"wayhop/internal/generator"
	"wayhop/internal/pbr"
)

// handoffcore.go is the sing-box half of the overlap hand-off (pbr/handoff.go): a TUN the kernel
// routes overlapping addresses into, and route rules that decide by the sniffed name.

const (
	handoffInbound  = "wr-handoff-in"
	handoffBackTag  = "wr-handoff-back"
	handoffTagPrefx = "wr-handoff-"
)

// handoffOutbound is a direct outbound whose connections the kernel routes by mark. The wildcard bind
// addresses are what keep sing-box from binding it to the default interface (auto_detect_interface):
// bound to the WAN device, a connection marked for a tunnel would leave by the WAN anyway
// (sing-box common/dialer/default.go: only bind_interface or an inet4/inet6 bind address disables
// the default bind; routing_mark does not).
func handoffOutbound(tag string, mark uint32) map[string]any {
	return map[string]any{
		"type": "direct", "tag": tag, "routing_mark": mark,
		"inet4_bind_address": "0.0.0.0", "inet6_bind_address": "::",
	}
}

// injectHandoffCore adds the hand-off to a core config: the TUN inbound, one outbound per domain list
// (its egress's mark) and one back to the kernel (HandoffReturnBit), and route rules ahead of every
// other rule, which only the hand-off inbound can match.
func injectHandoffCore(config []byte, h pbr.Handoff, coreVersion string) ([]byte, error) {
	if !h.Active() {
		return config, nil
	}
	var cfg map[string]any
	if err := json.Unmarshal(config, &cfg); err != nil {
		return nil, fmt.Errorf("core config: %w", err)
	}
	inbounds, _ := cfg["inbounds"].([]any)
	for _, in := range inbounds {
		if m, ok := in.(map[string]any); ok && m["tag"] == handoffInbound {
			return nil, fmt.Errorf("core config already has an inbound %q", handoffInbound)
		}
	}
	cfg["inbounds"] = append(inbounds, map[string]any{
		"type": "tun", "tag": handoffInbound, "interface_name": pbr.HandoffIfaceDefault,
		"address": []string{pbr.HandoffAddr}, "mtu": 1400,
		"auto_route": false, "strict_route": false, "stack": "gvisor",
	})
	outbounds, _ := cfg["outbounds"].([]any)
	in := []string{handoffInbound}
	rules := []any{map[string]any{"inbound": in, "action": "sniff"}}
	for _, r := range h.Routes {
		tag := handoffTagPrefx + strings.TrimPrefix(r.Zone, "list_")
		outbounds = append(outbounds, handoffOutbound(tag, r.Mark))
		rules = append(rules, map[string]any{"inbound": in, "domain_suffix": r.Domains, "action": "route", "outbound": tag})
	}
	outbounds = append(outbounds, handoffOutbound(handoffBackTag, pbr.HandoffReturnBit))
	rules = append(rules, map[string]any{"inbound": in, "action": "route", "outbound": handoffBackTag})
	cfg["outbounds"] = outbounds
	route, _ := cfg["route"].(map[string]any)
	if route == nil {
		route = map[string]any{}
		cfg["route"] = route
	}
	existing, _ := route["rules"].([]any)
	route["rules"] = append(rules, existing...)
	generator.FitTUNToCore(cfg, coreVersion)
	return json.MarshalIndent(cfg, "", "  ")
}

// handoffRouteKeeper puts the route into the hand-off TUN back whenever the device (re)appears: the
// program's own route is best-effort, and a TUN created after it, or re-created by a core restart,
// starts with an empty table. Until then the stronger list routes the overlap, which is the fallback.
type handoffRouteKeeper struct {
	ifindex string
}

func (k *handoffRouteKeeper) tick(ctx context.Context, plan *pbr.Plan, artifact executionKernelIpsetArtifactV1) {
	script := string(artifact.Script)
	table := pbr.HandoffTable(pbr.Options{})
	line := fmt.Sprintf("ip route replace default dev %s table %d 2>/dev/null || true\n", pbr.HandoffIfaceDefault, table)
	if plan == nil || !strings.Contains(script, line) {
		k.ifindex = ""
		return
	}
	idx, err := os.ReadFile("/sys/class/net/" + pbr.HandoffIfaceDefault + "/ifindex")
	if err != nil {
		k.ifindex = "" // the core is down: the table is empty and the stronger list routes
		return
	}
	if string(idx) == k.ifindex {
		return
	}
	adapter, err := newExactKeeneticKernelAdapter(artifact)
	if err != nil {
		return
	}
	if err := adapter.runProgram(ctx, artifact, line); err == nil {
		k.ifindex = string(idx)
	}
}
