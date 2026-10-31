package generator

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"wayhop/internal/importer"
	"wayhop/internal/model"
)

const quicTestUUID = "2dd61d93-75d8-4da4-ac0e-6aece7eac365"

// quicTuningProfile: a tuned Hysteria2 (both fields, Chrome parrot off), a TUIC with path MTU discovery
// off, a TUIC with both fields, and an untuned Hysteria2.
func quicTuningProfile() *model.Profile {
	tls := func(sni string) *model.TLS { return &model.TLS{Enabled: true, Type: "tls", SNI: sni} }
	return &model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "hy-tuned", Name: "hy-tuned", Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoHysteria2,
				Server: "192.0.2.4", Port: 8443, TLS: tls("hy.example.com"),
				Params: map[string]any{"password": "pw", "disable_chrome_parrot": true,
					model.ParamQUICInitialPacketSize: 1232, model.ParamQUICDisablePMTUD: true}},
			{ID: "tuic-nopmtud", Name: "tuic-nopmtud", Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoTUIC,
				Server: "192.0.2.5", Port: 8443, TLS: tls("tuic.example.com"),
				Params: map[string]any{"uuid": quicTestUUID, "password": "pw", "congestion_control": "bbr",
					model.ParamQUICDisablePMTUD: true}},
			{ID: "tuic-sized", Name: "tuic-sized", Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoTUIC,
				Server: "192.0.2.6", Port: 8443, TLS: tls("tuic2.example.com"),
				Params: map[string]any{"uuid": quicTestUUID, "password": "pw",
					model.ParamQUICInitialPacketSize: 1300, model.ParamQUICDisablePMTUD: true}},
			{ID: "hy-plain", Name: "hy-plain", Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoHysteria2,
				Server: "192.0.2.7", Port: 8443, TLS: tls("hy2.example.com"), Params: map[string]any{"password": "pw"}},
		},
		Rules: []model.Rule{{ID: "a", DomainSuffix: []string{"a.example.com"}, Outbound: "tuic-nopmtud"},
			{ID: "b", DomainSuffix: []string{"b.example.com"}, Outbound: "tuic-sized"},
			{ID: "c", DomainSuffix: []string{"c.example.com"}, Outbound: "hy-plain"},
			{ID: "def", Default: true, Outbound: "hy-tuned"}},
	}
}

func quicOutbounds(cfg map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, ob := range cfg["outbounds"].([]map[string]any) {
		if ob["type"] == "hysteria2" || ob["type"] == "tuic" {
			out[ob["tag"].(string)] = ob
		}
	}
	return out
}

// TestQUICTuningGatedByCore: the fields reach a 1.14+ core (a pre-release counts as its minor) and
// nothing older or unknown, which would refuse them, and an untuned connection never carries them.
func TestQUICTuningGatedByCore(t *testing.T) {
	for _, ver := range []string{"", "1.12.17", "1.13.21", "1.14.4", "1.15.0-alpha.13"} {
		res, err := Generate(quicTuningProfile(), Options{MixedPort: 7890, CoreVersion: ver, CacheFile: filepath.Join(t.TempDir(), "cache.db")})
		if err != nil {
			t.Fatalf("%q: tuning must never fail the config: %v", ver, err)
		}
		obs := quicOutbounds(res.Config)
		modern := coreMinor(ver) >= 14
		hy, tu := obs["hy-tuned"], obs["tuic-nopmtud"]
		if modern {
			if hy["initial_packet_size"] != 1232 || hy["disable_path_mtu_discovery"] != true {
				t.Errorf("%s: tuned hysteria2 = %v", ver, hy)
			}
			if tu["disable_path_mtu_discovery"] != true || tu["initial_packet_size"] != nil {
				t.Errorf("%s: tuic with discovery off = %v", ver, tu)
			}
			if ts := obs["tuic-sized"]; ts["initial_packet_size"] != 1300 || ts["disable_path_mtu_discovery"] != true {
				t.Errorf("%s: tuic with both = %v", ver, ts)
			}
		} else {
			for tag, ob := range obs {
				if ob["initial_packet_size"] != nil || ob["disable_path_mtu_discovery"] != nil {
					t.Errorf("%q: %s carries QUIC fields this core refuses: %v", ver, tag, ob)
				}
			}
		}
		if ob := obs["hy-plain"]; ob["initial_packet_size"] != nil || ob["disable_path_mtu_discovery"] != nil {
			t.Errorf("%q: hy-plain must render untuned: %v", ver, ob)
		}
	}
	p := quicTuningProfile()
	if !QUICTuningNeedsNewerCore(&p.Endpoints[0], "1.13.21") || !QUICTuningNeedsNewerCore(&p.Endpoints[1], "sing-box version 1.12.17") ||
		!QUICTuningNeedsNewerCore(&p.Endpoints[2], "1.13.21") ||
		QUICTuningNeedsNewerCore(&p.Endpoints[0], "1.14.4") || QUICTuningNeedsNewerCore(&p.Endpoints[0], "") ||
		QUICTuningNeedsNewerCore(&p.Endpoints[3], "1.13.21") {
		t.Error("QUICTuningNeedsNewerCore must flag only a usable setting on a known pre-1.14 core")
	}
}

// A size outside 1200..1452 is refused at save (model.QUICTuningProblem), which Generate runs first; one
// that reaches the generator another way is still never written, so the core cannot run with another.
func TestQUICTuningOutOfRangeSize(t *testing.T) {
	p := quicTuningProfile()
	p.Endpoints[2].Params[model.ParamQUICInitialPacketSize] = 9000
	if _, err := Generate(p, Options{MixedPort: 7890, CoreVersion: "1.14.4"}); err == nil || !strings.Contains(err.Error(), "initial_packet_size") {
		t.Fatalf("Generate with a 9000-byte size: err = %v, want the size refused", err)
	}
	ob, err := OutboundForCore(&p.Endpoints[2], "1.14.4")
	if err != nil || ob["initial_packet_size"] != nil || ob["disable_path_mtu_discovery"] != true {
		t.Fatalf("fallback outbound with a 9000-byte size = %v, %v", ob, err)
	}
}

// From 1.14 a Hysteria2 that parrots Chrome's handshake starts at Chrome's size whatever it sets, so the
// review names a size set there; the parrot switched off, a TUIC, or a core that gets no size, it does not.
func TestQUICSizeReplacedByChrome(t *testing.T) {
	p := quicTuningProfile()
	hy := p.Endpoints[0]
	if QUICSizeReplacedByChrome(&hy, "1.14.4") {
		t.Error("parrot off: the size applies")
	}
	hy.Params = map[string]any{"password": "pw", model.ParamQUICInitialPacketSize: 1232}
	if !QUICSizeReplacedByChrome(&hy, "1.14.4") || !QUICSizeReplacedByChrome(&hy, "1.15.0-alpha.13") {
		t.Error("parrot on, 1.14+: the size is replaced by Chrome's")
	}
	if QUICSizeReplacedByChrome(&hy, "1.13.21") || QUICSizeReplacedByChrome(&hy, "") {
		t.Error("a core that gets no size has nothing replaced")
	}
	hy.Params = map[string]any{"password": "pw", model.ParamQUICDisablePMTUD: true}
	if QUICSizeReplacedByChrome(&hy, "1.14.4") {
		t.Error("path MTU discovery is not part of the parrot")
	}
	if QUICSizeReplacedByChrome(&p.Endpoints[2], "1.14.4") {
		t.Error("TUIC has no Chrome parrot")
	}
}

// The KeeneticOS fallback core builds its outbounds through OutboundForCore, which carries the tuning
// on the same terms.
func TestOutboundForCoreCarriesQUICTuning(t *testing.T) {
	e := quicTuningProfile().Endpoints[0]
	ob, err := OutboundForCore(&e, "1.14.4")
	if err != nil || ob["initial_packet_size"] != 1232 || ob["disable_path_mtu_discovery"] != true {
		t.Fatalf("1.14 fallback outbound = %v, %v", ob, err)
	}
	ob, err = OutboundForCore(&e, "1.13.21")
	if err != nil || ob["initial_packet_size"] != nil || ob["disable_path_mtu_discovery"] != nil {
		t.Fatalf("1.13 fallback outbound = %v, %v", ob, err)
	}
}

// A connection whose settings the generator leaves out renders byte for byte as one that never had
// them: keys holding nothing usable, and a tuned connection on a core that cannot carry it.
func TestQUICTuningAbsentRendersIdentically(t *testing.T) {
	strip := func(p *model.Profile) *model.Profile {
		for i := range p.Endpoints {
			delete(p.Endpoints[i].Params, model.ParamQUICInitialPacketSize)
			delete(p.Endpoints[i].Params, model.ParamQUICDisablePMTUD)
		}
		return p
	}
	inert := func(p *model.Profile) *model.Profile {
		p = strip(p)
		for i := range p.Endpoints {
			p.Endpoints[i].Params[model.ParamQUICDisablePMTUD] = false
			p.Endpoints[i].Params[model.ParamQUICInitialPacketSize] = 0
		}
		return p
	}
	render := func(p *model.Profile, ver string) []byte {
		res, err := Generate(p, Options{MixedPort: 7890, CoreVersion: ver, CacheFile: "/opt/var/wayhop/cache.db"})
		if err != nil {
			t.Fatalf("%q: %v", ver, err)
		}
		b, _ := json.MarshalIndent(res.Config, "", "  ")
		return b
	}
	for _, ver := range []string{"", "1.12.17", "1.13.21", "1.14.4", "1.15.0-alpha.13"} {
		base := render(strip(quicTuningProfile()), ver)
		if got := render(inert(quicTuningProfile()), ver); !bytes.Equal(got, base) {
			t.Errorf("%q: inert QUIC keys changed the config", ver)
		}
		if coreMinor(ver) < 14 {
			if got := render(quicTuningProfile(), ver); !bytes.Equal(got, base) {
				t.Errorf("%q: tuning the core cannot carry changed the config", ver)
			}
		}
	}
}

// A config WayHop wrote for a 1.14 core reads back with the same tuning and renders the same outbounds.
func TestQUICTuningRoundTrip(t *testing.T) {
	opts := Options{MixedPort: 7890, CoreVersion: "1.14.4"}
	first, err := Generate(quicTuningProfile(), opts)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(first.Config)
	back, errs := importer.ParseSingbox(string(raw))
	if len(errs) > 0 {
		t.Fatalf("ParseSingbox: %v", errs)
	}
	byName := map[string]model.Endpoint{}
	for i := range back {
		back[i].ID, back[i].Enabled = back[i].Name, true
		byName[back[i].Name] = back[i]
	}
	for _, e := range quicTuningProfile().Endpoints {
		got := byName[e.ID]
		ws, wo := model.QUICTuningOf(&e)
		gs, gotOff := model.QUICTuningOf(&got)
		if ws != gs || wo != gotOff {
			t.Errorf("%s: read back (%d, %v), want (%d, %v)", e.ID, gs, gotOff, ws, wo)
		}
	}
	p := quicTuningProfile()
	p.Endpoints = back
	second, err := Generate(p, opts)
	if err != nil {
		t.Fatal(err)
	}
	a, b := quicOutbounds(first.Config), quicOutbounds(second.Config)
	for tag, ob := range a {
		x, _ := json.Marshal(ob)
		y, _ := json.Marshal(b[tag])
		if !bytes.Equal(x, y) {
			t.Errorf("%s changed over the round trip:\n%s\n%s", tag, x, y)
		}
	}
}

// TestQUICTuningSingBoxCheck runs the real core: the config rendered for the version WR_SINGBOX reports
// passes `sing-box check` with no deprecation warning, carrying the fields on 1.14+ and leaving them out
// before. On an older core it also proves the gate is needed: a TUIC-only config rendered for 1.14 -
// nothing in it but the QUIC fields is new in 1.14 - is refused there at decode, naming a QUIC field.
func TestQUICTuningSingBoxCheck(t *testing.T) {
	bin := os.Getenv("WR_SINGBOX")
	if bin == "" {
		t.Skip("WR_SINGBOX not set — set it to a sing-box binary for a real `check`")
	}
	ver := singboxVersionOf(t, bin)
	name := strings.SplitN(ver, "\n", 2)[0]
	check := func(p *model.Profile, tuned, coreVersion string) (string, error) {
		res, err := Generate(p, Options{MixedPort: 7890, CoreVersion: coreVersion, CacheFile: filepath.Join(t.TempDir(), "cache.db")})
		if err != nil {
			t.Fatalf("generate for %s: %v", coreVersion, err)
		}
		ob := quicOutbounds(res.Config)[tuned]
		if carries := ob["disable_path_mtu_discovery"] == true; carries != (coreMinor(coreVersion) >= 14) {
			t.Fatalf("rendered for %s: %s carries the QUIC fields = %v: %v", coreVersion, tuned, carries, ob)
		}
		data, _ := json.MarshalIndent(res.Config, "", "  ")
		f := filepath.Join(t.TempDir(), "quic.json")
		if err := os.WriteFile(f, data, 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(bin, "check", "-c", f).CombinedOutput()
		return string(out), err
	}
	out, err := check(quicTuningProfile(), "hy-tuned", ver)
	if err != nil {
		t.Fatalf("%s: sing-box check rejected the QUIC-tuned config: %v\n%s", name, err, out)
	}
	if strings.Contains(out, "deprecated") {
		t.Fatalf("%s: sing-box warned about a deprecated field:\n%s", name, out)
	}
	tuicOnly := quicTuningProfile()
	tuicOnly.Endpoints = tuicOnly.Endpoints[2:3]
	tuicOnly.Rules = []model.Rule{{ID: "def", Default: true, Outbound: "tuic-sized"}}
	out, err = check(tuicOnly, "tuic-sized", ver)
	if err != nil {
		t.Fatalf("%s: sing-box check rejected the TUIC-only config: %v\n%s", name, err, out)
	}
	if coreMinor(ver) < 14 {
		out, err := check(tuicOnly, "tuic-sized", "1.14.4")
		if err == nil || !strings.Contains(out, "unknown field") ||
			!(strings.Contains(out, "initial_packet_size") || strings.Contains(out, "disable_path_mtu_discovery")) {
			t.Fatalf("%s: the TUIC-only config rendered for 1.14 was not refused over a QUIC field (err=%v):\n%s", name, err, out)
		}
		t.Logf("%s refuses the 1.14 render: %s", name, strings.TrimSpace(out))
	}
}
