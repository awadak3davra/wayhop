package server

import (
	"context"
	"encoding/base64"
	"errors"
	"slices"
	"sort"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"

	"wayhop/internal/config"
	"wayhop/internal/model"
	"wayhop/internal/platform"
)

// fakeNDM stands in for KeeneticOS behind the production ndmc runner: it takes the one-line commands
// exactKeeneticNDMCRunner flattens a batch into, keeps the interfaces and routes they describe, and
// prints them back the way KeeneticOS 5.1.8 prints its own WireGuard interfaces:
// settings indented four spaces in the router's own order, a peer's settings eight, `!` closing each
// context, and no key of any kind. Like NDM it merges a re-sent block into what is there. It refuses
// a peer setting given at the interface level; that the router does the same, and takes the
// one-line `interface X wireguard peer K <setting>` form, has not been tried on a router.
type fakeNDM struct {
	order  []string
	ifaces map[string]*fakeNDMIface
	routes []string
	calls  []string // every command ndmc was asked to run, in order
	saved  bool
	refuse func(line string) bool
	ignore func(line string) bool
	// unreadableConfig / unreadableListing make `show running-config` / `show interface` fail.
	unreadableConfig, unreadableListing bool
}

type fakeNDMIface struct {
	lines []string            // the interface's own settings, in the order they were added
	peers map[string][]string // `wireguard peer <key>` line -> that peer's settings
}

func newFakeNDM() *fakeNDM { return &fakeNDM{ifaces: map[string]*fakeNDMIface{}} }

func (ndm *fakeNDM) adapter() *exactKeeneticNativeAdapter {
	return &exactKeeneticNativeAdapter{
		runner:         &exactKeeneticNDMCRunner{run: ndm.run},
		readConfig:     ndm.readConfig,
		readInterfaces: ndm.readInterfaces,
	}
}

func (ndm *fakeNDM) readConfig(context.Context) (string, error) {
	if ndm.unreadableConfig {
		return "", errors.New("ndmc: no answer")
	}
	return ndm.render(), nil
}

func (ndm *fakeNDM) readInterfaces(context.Context) (string, error) {
	if ndm.unreadableListing {
		return "", errors.New("ndmc: no answer")
	}
	return ndm.renderInterfaces(), nil
}

// renderInterfaces prints `show interface` as that router does for a WireGuard interface: keys
// right-aligned on one colon column, the interface's own public key in its `wireguard:` block and
// the peer's a level deeper, wrapped onto the next line.
func (ndm *fakeNDM) renderInterfaces() string {
	var b strings.Builder
	b.WriteString("Interface, name = \"ISP\"\n               id: ISP\n   interface-name: ISP\n             type: Ethernet\n")
	for _, name := range ndm.order {
		iface := ndm.ifaces[name]
		if iface == nil {
			continue
		}
		b.WriteString("Interface, name = \"" + name + "\"\n")
		b.WriteString("               id: " + name + "\n")
		b.WriteString("   interface-name: " + name + "\n")
		b.WriteString("             type: Wireguard\n")
		b.WriteString("        wireguard: \n")
		for _, line := range iface.lines {
			if private, ok := strings.CutPrefix(line, "wireguard private-key "); ok {
				raw, _ := base64.StdEncoding.DecodeString(private)
				if public, err := curve25519.X25519(raw, curve25519.Basepoint); err == nil {
					b.WriteString("           public-key: " + base64.StdEncoding.EncodeToString(public) + "\n")
				}
			}
		}
		for _, line := range iface.lines {
			if peer, ok := strings.CutPrefix(line, "wireguard peer "); ok {
				b.WriteString("             peer: \n               public-key: \n                                 " + peer + "\n")
			}
		}
	}
	return b.String()
}

func (ndm *fakeNDM) run(_ context.Context, stdin, name string, args ...string) (string, error) {
	if stdin != "" || name != exactKeeneticNDMCPath || len(args) != 2 || args[0] != "-c" {
		return "", errors.New("unexpected ndmc invocation")
	}
	line := args[1]
	ndm.calls = append(ndm.calls, line)
	if ndm.refuse != nil && ndm.refuse(line) {
		return "Command::Base error: refused", nil
	}
	if ndm.ignore != nil && ndm.ignore(line) {
		return "", nil // accepted and not applied
	}
	if !ndm.apply(line) {
		return "no such command: " + line, nil
	}
	return "", nil
}

var fakeNDMPeerSettings = map[string]bool{
	"endpoint": true, "keepalive-interval": true, "preshared-key": true, "allow-ips": true, "connect": true,
}

func (ndm *fakeNDM) apply(line string) bool {
	tokens := strings.Fields(line)
	switch {
	case line == exactKeeneticSaveCommand:
		ndm.saved = true
		return true
	case len(tokens) >= 3 && tokens[0] == "no" && tokens[1] == "interface":
		delete(ndm.ifaces, tokens[2])
		return true
	case len(tokens) >= 3 && tokens[0] == "no" && (tokens[1] == "ip" || tokens[1] == "ipv6"):
		key := strings.Join(tokens[1:], " ")
		kept := ndm.routes[:0]
		for _, route := range ndm.routes {
			if route != key && !strings.HasPrefix(route, key+" ") {
				kept = append(kept, route)
			}
		}
		ndm.routes = kept
		return true
	case len(tokens) >= 2 && (tokens[0] == "ip" || tokens[0] == "ipv6") && tokens[1] == "route":
		route := strings.Join(tokens, " ")
		for _, existing := range ndm.routes {
			if existing == route {
				return true
			}
		}
		ndm.routes = append(ndm.routes, route)
		return true
	case len(tokens) >= 2 && tokens[0] == "interface":
		return ndm.applyInterface(tokens[1], tokens[2:])
	}
	return false
}

func (ndm *fakeNDM) applyInterface(name string, rest []string) bool {
	iface := ndm.ifaces[name]
	if iface == nil {
		iface = &fakeNDMIface{peers: map[string][]string{}}
		ndm.ifaces[name] = iface
		if !slices.Contains(ndm.order, name) {
			ndm.order = append(ndm.order, name)
		}
	}
	if len(rest) == 0 {
		return true
	}
	if len(rest) >= 3 && rest[0] == "wireguard" && rest[1] == "peer" {
		peer := strings.Join(rest[:3], " ")
		if _, ok := iface.peers[peer]; !ok {
			iface.peers[peer] = nil
			iface.lines = append(iface.lines, peer)
		}
		if len(rest) > 3 {
			iface.peers[peer] = fakeNDMMerge(iface.peers[peer], strings.Join(rest[3:], " "))
		}
		return true
	}
	if fakeNDMPeerSettings[rest[0]] {
		return false // a peer's setting is not a command of the interface context
	}
	setting := strings.Join(rest, " ")
	if strings.HasPrefix(setting, "ip global ") {
		for i, existing := range iface.lines {
			if strings.HasPrefix(existing, "ip global ") {
				iface.lines[i] = setting
				return true
			}
		}
	}
	iface.lines = fakeNDMMerge(iface.lines, setting)
	return true
}

func fakeNDMMerge(lines []string, setting string) []string {
	for _, existing := range lines {
		if existing == setting {
			return lines
		}
	}
	return append(lines, setting)
}

// edit lets a test stand in for the operator changing an interface in KeeneticOS.
func (ndm *fakeNDM) edit(name string, change func(lines []string) []string) {
	ndm.ifaces[name].lines = change(ndm.ifaces[name].lines)
}

func (ndm *fakeNDM) has(name string) bool { return ndm.ifaces[name] != nil }

// The order KeeneticOS prints an interface's settings in, whatever order they were given in, and
// the order of a peer's: read from the five WireGuard interfaces of a KeeneticOS 5.1.8 router (values
// elided). A setting not seen there sorts just before `wireguard asc`.
var (
	fakeNDMSettingOrder = []string{"description ", "security-level ", "ip address ", "ip mtu ", "ip global ",
		"ip access-group ", "ip tcp adjust-mss ", "ipv6 address ", "", "wireguard listen-port ", "wireguard asc ",
		"wireguard peer ", "up", "down"}
	fakeNDMPeerOrder = []string{"endpoint ", "keepalive-interval ", "preshared-key ", "allow-ips ", "connect"}
)

func fakeNDMRank(order []string, line string) int {
	unknown := 0
	for i, prefix := range order {
		if prefix == "" {
			unknown = i
		} else if line == strings.TrimSpace(prefix) || strings.HasPrefix(line, prefix) {
			return i
		}
	}
	return unknown
}

func fakeNDMSorted(order []string, lines []string) []string {
	sorted := append([]string(nil), lines...)
	sort.SliceStable(sorted, func(i, j int) bool { return fakeNDMRank(order, sorted[i]) < fakeNDMRank(order, sorted[j]) })
	return sorted
}

// fakeNDMSecret is what `show running-config` leaves out: that router prints no private key for
// any WireGuard interface and no pre-shared key under any peer.
func fakeNDMSecret(line string) bool {
	return strings.HasPrefix(line, "wireguard private-key ") || strings.HasPrefix(line, "preshared-key ")
}

func (ndm *fakeNDM) render() string {
	var b strings.Builder
	b.WriteString("interface ISP\n    description WAN\n    ip global 1000\n!\n")
	for _, name := range ndm.order {
		iface := ndm.ifaces[name]
		if iface == nil {
			continue
		}
		b.WriteString("interface " + name + "\n")
		for _, line := range fakeNDMSorted(fakeNDMSettingOrder, iface.lines) {
			if fakeNDMSecret(line) {
				continue
			}
			b.WriteString("    " + line + "\n")
			if settings, peer := iface.peers[line]; peer {
				for _, setting := range fakeNDMSorted(fakeNDMPeerOrder, settings) {
					if !fakeNDMSecret(setting) {
						b.WriteString("        " + setting + "\n")
					}
				}
				b.WriteString("    !\n")
			}
		}
		b.WriteString("!\n")
	}
	for _, route := range ndm.routes {
		b.WriteString(route + "\n")
	}
	return b.String()
}

// keeneticCreateTuple is one WayHop-owned AmneziaWG endpoint that KeeneticOS's own WireGuard carries,
// on a Keenetic with nothing of WayHop's on it yet; rules is the profile's rule list.
func keeneticCreateTuple(t *testing.T, rules []model.Rule, more ...model.Endpoint) (DesiredSnapshot, HostSnapshotV1, executionNativeCaptureV1) {
	t.Helper()
	cfg := *config.Default()
	cfg.RoutingMode = "mixed"
	cfg.Offload = "auto"
	desired, err := newDesiredSnapshot(cfg, model.Profile{
		Endpoints: append([]model.Endpoint{executionAWGEndpoint("native")}, more...), Rules: rules,
	}, 9)
	if err != nil {
		t.Fatal(err)
	}
	probe := hostTestProbe(desired)
	probe.Platform = string(platform.Keenetic)
	probe.RawCapabilities.Platform = string(platform.Keenetic)
	probe.RawCapabilities.Native = map[string]bool{"amneziawg": true, "wireguard": true}
	probe.RawCapabilities.NetifdProtos = nil
	probe.NativeOperations = keeneticProductionNativeOperations()
	host, err := newHostSnapshot(desired, probe, nil)
	if err != nil {
		t.Fatal(err)
	}
	return desired, host, executionNativeCaptureV1{
		OccupiedInterfaces: map[string]bool{},
		GlobalPriorities:   map[string]int{"ISP": 1000},
		KeeneticConfigRev:  strings.Repeat("a", 64),
	}
}

// QA-121. The compiler indents a WireGuard peer's own settings under its `wireguard peer` line, and
// the exact adapter's command validator refused any line with leading spaces, so every native
// create was refused as an invalid plan before a single command was sent. The block here is the
// one the compiler produces, run through the production ndmc runner into a stand-in NDM.
func TestKeeneticNativeCreateRunsTheCompiledBlock(t *testing.T) {
	for name, rules := range map[string][]model.Rule{
		"no default route": nil,
		// The ladder then raises the new interface above the WAN, so the block's own `ip global` is
		// no longer what the router reads back for it.
		"default route through the tunnel": {{ID: "default", Default: true, Outbound: "native"}},
	} {
		t.Run(name, func(t *testing.T) {
			desired, host, capture := keeneticCreateTuple(t, rules)
			m, _, err := materialize(materializeInput{desired: desired, host: ExecutionHostFactsV1{Host: host}, native: &capture})
			if err != nil {
				t.Fatalf("materialize: %v", err)
			}
			if m.Native == nil {
				t.Fatal("no native plan")
			}
			reconcile := m.Native.Delta.Reconcile
			target := *reconcile.Target
			if len(target.Keenetic.Interfaces) != 1 {
				t.Fatalf("interface blocks = %d, want 1", len(target.Keenetic.Interfaces))
			}
			block := target.Keenetic.Interfaces[0]
			indented := 0
			for _, line := range block {
				if strings.HasPrefix(line, " ") {
					indented++
				}
			}
			if indented == 0 {
				t.Fatalf("the compiled block has no indented peer settings; this test lost its trigger: %q", block)
			}
			if rules != nil && len(target.Keenetic.GlobalPriority) == 0 {
				t.Fatal("the default rule compiled to no ladder; this case lost its trigger")
			}

			ndm := newFakeNDM()
			adapter := ndm.adapter()
			if err := adapter.prepare(context.Background(), target); err != nil {
				t.Fatalf("prepare refused the compiled block: %v", err)
			}
			iface := strings.TrimPrefix(block[0], "interface ")
			if !ndm.has(iface) {
				t.Fatalf("prepare did not create %s", iface)
			}
			// The block carries keys and the router never prints them back; verification that
			// expected them deleted every tunnel it had just created.
			if !slices.ContainsFunc(block, func(line string) bool { return strings.HasPrefix(line, "wireguard private-key ") }) ||
				strings.Contains(ndm.render(), "private-key") || strings.Contains(ndm.render(), "preshared-key") {
				t.Fatal("the block has no private key, or the stand-in prints a key the router does not; this test lost its trigger")
			}
			// Each peer setting reached NDM under its peer's path, which is the only place NDM takes it.
			peerPath := ""
			for _, line := range block {
				if strings.HasPrefix(line, "wireguard peer ") {
					peerPath = block[0] + " " + line + " "
				}
			}
			for _, line := range block {
				if !strings.HasPrefix(line, " ") {
					continue
				}
				want := peerPath + strings.TrimSpace(line)
				found := false
				for _, call := range ndm.calls {
					found = found || call == want
				}
				if !found {
					t.Errorf("peer setting %q was not sent as %q", strings.Fields(line)[0], strings.Fields(want)[:4])
				}
			}
			if err := adapter.commit(context.Background(), reconcile); err != nil {
				t.Fatalf("commit: %v", err)
			}
			if err := adapter.postcheck(context.Background(), target, reconcile.KeeneticTeardown, reconcile.KeeneticPriorityRestore); err != nil {
				t.Fatalf("postcheck: %v", err)
			}
			if err := adapter.persist(context.Background(), reconcile); err != nil || !ndm.saved {
				t.Fatalf("persist: %v (saved %v)", err, ndm.saved)
			}
			if !ndm.has(iface) {
				t.Fatalf("%s is gone after a successful Apply", iface)
			}
		})
	}
}

// The validator still refuses every other kind of padding: the exception is exactly the compiler's
// four-space indentation, directly under a `wireguard peer` line of an interface block.
func TestExactKeeneticCommandsAcceptOnlyTheCompilersPeerIndentation(t *testing.T) {
	block := []string{
		"interface Wireguard10", "description wayhop", "wireguard peer AAAA=",
		"    endpoint 192.0.2.10:443", "    allow-ips 0.0.0.0 0.0.0.0", "    connect", "up",
	}
	if !validExactKeeneticCommands(block, false) {
		t.Fatal("the compiler's peer block was refused")
	}
	for name, commands := range map[string][]string{
		"indented outside a peer":     {"interface Wireguard10", "    description wayhop", "up"},
		"indented after the peer":     {"interface Wireguard10", "wireguard peer AAAA=", "    connect", "up", "    endpoint 192.0.2.10:443"},
		"peer outside a block":        {"wireguard peer AAAA=", "    connect"},
		"indented route":              {"ip route 203.0.113.0 255.255.255.0 ISP", "    ip route 198.51.100.0 255.255.255.0 ISP"},
		"two spaces":                  {"interface Wireguard10", "wireguard peer AAAA=", "  connect"},
		"five spaces":                 {"interface Wireguard10", "wireguard peer AAAA=", "     connect"},
		"tab":                         {"interface Wireguard10", "wireguard peer AAAA=", "\tconnect"},
		"indentation only":            {"interface Wireguard10", "wireguard peer AAAA=", "    "},
		"trailing space":              {"interface Wireguard10", "wireguard peer AAAA=", "    connect "},
		"leading space on a command":  {" interface Wireguard10", "up"},
		"embedded newline":            {"interface Wireguard10", "wireguard peer AAAA=", "    connect\nno interface ISP"},
		"duplicate indented settings": {"interface Wireguard10", "wireguard peer AAAA=", "    connect", "    connect"},
	} {
		if validExactKeeneticCommands(commands, false) {
			t.Errorf("%s: accepted %q", name, commands)
		}
	}
	if validExactKeeneticCommands([]string{"no interface Wireguard10", "    no ip route 192.0.2.0 255.255.255.0 ISP"}, true) {
		t.Error("an indented teardown command was accepted")
	}
}
