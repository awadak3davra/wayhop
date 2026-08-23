package server

import (
	"reflect"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/platform"
)

// The components page decides two things with this answer: whether removing the core breaks
// anything, and whether "not installed" is the normal state on this router. Both are wrong if the
// list is padded or if it silently drops a dependency.
func TestCoreDependents(t *testing.T) {
	caps := platform.Capabilities{SingboxRequired: []string{"vless", "vmess", "trojan", "hysteria2", "tuic", "anytls"}}

	t.Run("native-only profile needs nothing", func(t *testing.T) {
		// The state this router is actually in: WireGuard tunnels the kernel carries, no core.
		// Anything but an empty list here would put a permanent "install this" on a working router.
		prof := model.Profile{Endpoints: []model.Endpoint{
			{ID: "wg1", Name: "Yerevan", Protocol: "wireguard", Enabled: true},
			{ID: "wg2", Name: "Berlin", Protocol: "amneziawg", Enabled: true},
		}}
		if got := coreDependents(prof, caps); len(got) != 0 {
			t.Fatalf("coreDependents = %v, want none — nothing here needs the core", got)
		}
	})

	t.Run("names the proxy exits, sorted", func(t *testing.T) {
		prof := model.Profile{Endpoints: []model.Endpoint{
			{ID: "wg1", Name: "Yerevan", Protocol: "wireguard", Enabled: true},
			{ID: "v2", Name: "Tokyo VLESS", Protocol: "vless", Enabled: true},
			{ID: "h1", Name: "Amsterdam Hy2", Protocol: "hysteria2", Enabled: true},
		}}
		want := []string{"Amsterdam Hy2", "Tokyo VLESS"}
		if got := coreDependents(prof, caps); !reflect.DeepEqual(got, want) {
			t.Fatalf("coreDependents = %v, want %v", got, want)
		}
	})

	// A disabled proxy exit is not carrying traffic, so it must not read as a live dependency — but
	// dropping it entirely would answer "nothing uses this" one click before enabling it does.
	t.Run("a disabled exit is named as off", func(t *testing.T) {
		prof := model.Profile{Endpoints: []model.Endpoint{
			{ID: "v2", Name: "Tokyo VLESS", Protocol: "vless", Enabled: false},
		}}
		want := []string{"Tokyo VLESS (off)"}
		if got := coreDependents(prof, caps); !reflect.DeepEqual(got, want) {
			t.Fatalf("coreDependents = %v, want %v", got, want)
		}
	})

	// An unnamed endpoint still has to be identifiable, or the operator is told something they own
	// depends on the core without being told which thing.
	t.Run("falls back to the id when unnamed", func(t *testing.T) {
		prof := model.Profile{Endpoints: []model.Endpoint{{ID: "tuic-7", Protocol: "tuic", Enabled: true}}}
		if got := coreDependents(prof, caps); !reflect.DeepEqual(got, []string{"tuic-7"}) {
			t.Fatalf("coreDependents = %v, want the id", got)
		}
	})

	// Encrypted DNS is core-only and is not a connection, which is exactly why it was missed: the
	// DNS page offers it, the capability probe marks it MISSING_BINARY, and nothing joined the two.
	t.Run("encrypted DNS counts, plaintext does not", func(t *testing.T) {
		prof := model.Profile{DNS: &model.DNSSettings{Enabled: true, Servers: []model.DNSServer{
			{Tag: "cloudflare-doh", Type: "https", Enabled: true},
			{Tag: "isp", Type: "udp", Enabled: true},
			{Tag: "unused-dot", Type: "tls", Enabled: false},
		}}}
		want := []string{"encrypted DNS (cloudflare-doh)"}
		if got := coreDependents(prof, caps); !reflect.DeepEqual(got, want) {
			t.Fatalf("coreDependents = %v, want %v", got, want)
		}
	})

	// The whole DNS plane being off makes its servers irrelevant, however they are typed.
	t.Run("DNS disabled contributes nothing", func(t *testing.T) {
		prof := model.Profile{DNS: &model.DNSSettings{Enabled: false, Servers: []model.DNSServer{
			{Tag: "cloudflare-doh", Type: "https", Enabled: true},
		}}}
		if got := coreDependents(prof, caps); len(got) != 0 {
			t.Fatalf("coreDependents = %v, want none", got)
		}
	})

	// The protocol list belongs to the platform probe, not to this file: a router that grows a native
	// path for a protocol must stop reporting a dependency on the core for it.
	t.Run("a protocol with a native path is not a dependency", func(t *testing.T) {
		prof := model.Profile{Endpoints: []model.Endpoint{{ID: "v2", Name: "Tokyo", Protocol: "vless", Enabled: true}}}
		if got := coreDependents(prof, platform.Capabilities{SingboxRequired: []string{"tuic"}}); len(got) != 0 {
			t.Fatalf("coreDependents = %v, want none — this platform carries vless itself", got)
		}
	})
}
