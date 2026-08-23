package server

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/health"
	"wayhop/internal/model"
	"wayhop/internal/store"
	"wayhop/internal/updater"
)

func bindTestServer(t *testing.T, profile model.Profile, via string) *Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Replace(profile); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Updater.DownloadVia = via
	// A real monitor with nothing measured yet: every member reads as not-alive, which is the state a
	// router is in before the first health round and the one the fallback below has to survive.
	return &Server{cfg: cfg, store: st, monitor: health.NewMonitor(nil, st, nil, false)}
}

func adopted(id, iface string, enabled bool) model.Endpoint {
	return model.Endpoint{
		ID: id, Name: id, Engine: model.EngineExternal, Protocol: model.ProtoWireGuard,
		Enabled: enabled, Params: map[string]any{"interface": iface},
	}
}

func proxied(id string) model.Endpoint {
	return model.Endpoint{
		ID: id, Name: id, Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
		Server: "de.example.com", Port: 443, Enabled: true,
		Params: map[string]any{"uuid": "11111111-2222-3333-4444-555555555555"},
	}
}

// The whole point of the setting: a router whose ordinary path to the release is blocked can still
// fetch one through a tunnel. The saved tag has to resolve to the kernel link the socket binds to.
func TestUpdaterDownloadIfaceResolvesTheChosenOutbound(t *testing.T) {
	profile := model.Profile{Endpoints: []model.Endpoint{
		adopted("external-nwg3", "nwg3", true),
		adopted("external-nwg5", "nwg5", true),
	}}
	s := bindTestServer(t, profile, "external-nwg5")
	if got := s.updaterDownloadIface(); got != "nwg5" {
		t.Fatalf("resolved %q, want nwg5", got)
	}
}

// A group binds to a member only while that member is HEALTHY. Nothing measured yet means nothing is
// known to be alive, and binding a download to a link that may be dead is the exact failure this
// setting exists to avoid — so it falls back to the ordinary path, which the page then reports.
func TestUpdaterDownloadIfaceWaitsForAHealthyMember(t *testing.T) {
	profile := model.Profile{
		Endpoints: []model.Endpoint{
			proxied("vless-de"),
			adopted("external-nwg5", "nwg5", true),
		},
		Groups: []model.Group{{ID: "grp", Name: "Main", Type: model.GroupFallback,
			Members: []string{"vless-de", "external-nwg5"}}},
	}
	s := bindTestServer(t, profile, "grp")
	if got := s.updaterDownloadIface(); got != "" {
		t.Fatalf("resolved %q with no member known alive, want the ordinary path", got)
	}
}

// kernelIfaceByEndpoint is the candidate set both elections run over — this one and the routing-list
// failover loop. An endpoint with no kernel link is not a candidate however healthy it looks: a proxy
// endpoint is carried by an engine, and SO_BINDTODEVICE has nothing to point at.
func TestKernelIfaceByEndpointKeepsOnlyBindableEndpoints(t *testing.T) {
	profile := model.Profile{
		Endpoints: []model.Endpoint{
			proxied("vless-de"),
			adopted("external-nwg3", "nwg3", true),
			adopted("external-nwg5", "nwg5", false),
		},
		Groups: []model.Group{{ID: "grp", Name: "Main", Type: model.GroupFallback,
			Members: []string{"vless-de", "external-nwg3"}}},
	}
	got := kernelIfaceByEndpoint(&profile)
	// A disabled endpoint keeps its link here: the map answers "which link is this endpoint", and
	// whether it may be USED is the election's question, decided by health. Validation already stops a
	// disabled endpoint from being a group member.
	want := map[string]string{"external-nwg3": "nwg3", "external-nwg5": "nwg5"}
	if len(got) != len(want) || got["external-nwg3"] != want["external-nwg3"] || got["external-nwg5"] != want["external-nwg5"] {
		t.Fatalf("candidates = %v, want %v", got, want)
	}
	if _, ok := got["vless-de"]; ok {
		t.Fatalf("a proxy endpoint became a bind candidate: %v", got)
	}
}

// A choice that no longer exists must fall back to the ordinary path rather than binding to nothing:
// a deleted or disabled tunnel would otherwise leave the section unable to fetch anything at all,
// which is a worse failure than taking the path the operator was trying to avoid. The page says which
// path is actually in force, so the fallback is visible.
func TestUpdaterDownloadIfaceFallsBackToTheOrdinaryPath(t *testing.T) {
	profile := model.Profile{Endpoints: []model.Endpoint{adopted("external-nwg3", "nwg3", true)}}
	for _, via := range []string{"", "direct", "external-gone", "grp-gone"} {
		s := bindTestServer(t, profile, via)
		if got := s.updaterDownloadIface(); got != "" {
			t.Fatalf("via %q resolved to %q, want the ordinary path", via, got)
		}
	}
	// A tunnel that exists but is switched off is not a path either.
	off := model.Profile{Endpoints: []model.Endpoint{adopted("external-nwg3", "nwg3", false)}}
	s := bindTestServer(t, off, "external-nwg3")
	if got := s.updaterDownloadIface(); got != "" {
		t.Fatalf("a disabled tunnel resolved to %q", got)
	}
}

// A proxy endpoint has no kernel link to bind to — binding is a socket option, not a routing rule, so
// there is nothing to point it at.
func TestUpdaterDownloadIfaceIgnoresAProxyEndpoint(t *testing.T) {
	profile := model.Profile{Endpoints: []model.Endpoint{proxied("vless-de")}}
	s := bindTestServer(t, profile, "vless-de")
	if got := s.updaterDownloadIface(); got != "" {
		t.Fatalf("a proxy endpoint resolved to %q", got)
	}
}

// The page offers what the DAEMON says can carry a download, because the page was wrong about it in
// both directions: opened cold it had no profile and offered nothing but the ordinary path, and with
// a profile it offered proxy endpoints that have no kernel link to bind to.
func TestDownloadPathChoicesOffersOnlyWhatCanCarryADownload(t *testing.T) {
	profile := model.Profile{
		Endpoints: []model.Endpoint{
			adopted("external-nwg3", "nwg3", true),
			adopted("external-nwg5", "nwg5", true),
			adopted("external-off", "nwg9", false), // switched off — not a path today
			proxied("vless-de"),                    // carried by an engine — nothing to bind to
		},
		Groups: []model.Group{{ID: "grp", Name: "Main", Type: model.GroupFallback,
			Members: []string{"external-nwg3", "external-nwg5"}}},
	}
	s := bindTestServer(t, profile, "")
	got := s.downloadPathChoices()

	byID := map[string]downloadPath{}
	for _, p := range got {
		byID[p.ID] = p
	}
	if _, ok := byID["vless-de"]; ok {
		t.Errorf("a proxy endpoint was offered as a download path: %+v", byID["vless-de"])
	}
	if _, ok := byID["external-off"]; ok {
		t.Errorf("a disabled tunnel was offered as a download path")
	}
	if p := byID["external-nwg3"]; p.Iface != "nwg3" || p.Name != "external-nwg3" {
		t.Errorf("native tunnel offered as %+v, want iface nwg3", p)
	}
	// A group is always offered: it is a standing choice, and its member health changes under it. With
	// nothing measured yet it resolves to no interface, and the page says the choice is not in force
	// rather than hiding it.
	g, ok := byID["grp"]
	if !ok || !g.Group {
		t.Fatalf("the group was not offered: %+v", got)
	}
	if g.Iface != "" {
		t.Errorf("group resolved to %q with no member known alive", g.Iface)
	}
	if len(got) != 3 {
		t.Errorf("offered %d paths, want 3 (two tunnels + one group): %+v", len(got), got)
	}
}

// A group whose members are ALL carried by an engine can never resolve to a link, so it is not a
// choice — the same emptiness as offering one of those members directly, one level up. Found on the
// demo fixture, where every exit is a proxy and ten such groups were offered.
func TestDownloadPathChoicesSkipsGroupsNothingCanBind(t *testing.T) {
	profile := model.Profile{
		Endpoints: []model.Endpoint{proxied("vless-de"), proxied("vless-nl"), adopted("external-nwg3", "nwg3", true)},
		Groups: []model.Group{
			{ID: "proxy-only", Name: "Proxies", Type: model.GroupFallback, Members: []string{"vless-de", "vless-nl"}},
			{ID: "mixed", Name: "Mixed", Type: model.GroupFallback, Members: []string{"vless-de", "external-nwg3"}},
		},
	}
	s := bindTestServer(t, profile, "")
	var ids []string
	for _, p := range s.downloadPathChoices() {
		ids = append(ids, p.ID)
	}
	for _, id := range ids {
		if id == "proxy-only" {
			t.Fatalf("a group nothing can bind to was offered: %v", ids)
		}
	}
	// The mixed group stays: one member has a link, so the choice can take effect.
	found := false
	for _, id := range ids {
		if id == "mixed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("a group with one bindable member was dropped: %v", ids)
	}
}

// When the release source cannot be reached, the message names the path the fetch was bound to.
//
// Measured on a live Keenetic: version checks bound to a group answered "3 source(s) tried,
// all failed" for twelve seconds, while the same request over the ordinary path succeeded at once.
// The setting that made the difference appeared nowhere in the failure, and an operator has no way to
// remember it from an error about GitHub.
func TestReleaseFailureNamesTheBoundDownloadPath(t *testing.T) {
	profile := model.Profile{Endpoints: []model.Endpoint{adopted("external-nwg3", "nwg3", true)}}
	s := bindTestServer(t, profile, "external-nwg3")
	s.updater = updater.New(t.TempDir(), "arm64", nil)
	s.updater.BindVia(s.updaterDownloadIface)

	// Asserted through the message callers actually send, not the fragment: a helper that callers may
	// or may not append is a helper they will forget, which is exactly what the mutation check showed.
	full := s.releaseSourceUnreachable("could not reach the release source: ", errors.New("3 source(s) tried"))
	if !strings.Contains(full, "3 source(s) tried") {
		t.Fatalf("message %q lost the underlying error", full)
	}
	suffix := full
	if !strings.Contains(suffix, "external-nwg3") || !strings.Contains(suffix, "nwg3") {
		t.Fatalf("suffix %q names neither the choice nor the interface", suffix)
	}
	if !strings.Contains(suffix, "ordinary path") {
		t.Errorf("suffix %q does not say what to change it to", suffix)
	}

	// The ordinary path has no extra suspect to name, so the message stays as it was.
	plain := bindTestServer(t, profile, "")
	plain.updater = updater.New(t.TempDir(), "arm64", nil)
	plain.updater.BindVia(plain.updaterDownloadIface)
	plainMsg := plain.releaseSourceUnreachable("lead: ", errors.New("boom"))
	if plainMsg != "lead: boom" {
		t.Fatalf("an unbound download added %q to the failure", plainMsg)
	}
}
