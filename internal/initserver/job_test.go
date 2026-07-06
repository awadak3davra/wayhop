package initserver

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestJobSequencing(t *testing.T) {
	m := NewJobManager()
	j := m.New("provision", "srv-x")
	if got, ok := m.Get(j.ID()); !ok || got != j {
		t.Fatal("manager did not register the job")
	}
	j.Start("Connect")
	j.OK("port open")
	j.Start("Install")
	j.Fail("apt failed", "check the mirror")
	j.Finish(false, map[string]any{"added_endpoints": []string{}})

	v := j.Snapshot()
	if v.ID != j.ID() || v.Kind != "provision" || v.ServerID != "srv-x" {
		t.Fatalf("snapshot meta wrong: %+v", v)
	}
	if len(v.Steps) != 2 {
		t.Fatalf("steps = %d, want 2", len(v.Steps))
	}
	if v.Steps[0].State != StepOK || v.Steps[1].State != StepError {
		t.Fatalf("step states wrong: %+v", v.Steps)
	}
	if v.Steps[1].Hint != "check the mirror" {
		t.Fatalf("hint missing: %+v", v.Steps[1])
	}
	if !v.Done || v.OK {
		t.Fatalf("done=%v ok=%v, want done=true ok=false", v.Done, v.OK)
	}
	if len(v.Console) == 0 {
		t.Fatal("console should have lines")
	}
}

func TestExtractConfigsMultiple(t *testing.T) {
	awg := "[Interface]\nPrivateKey = x\n[Peer]\nEndpoint = 1.2.3.4:51820"
	out := "noise\nWR_CLIENT_CONFIG_B64=" + base64.StdEncoding.EncodeToString([]byte(awg)) + "\n" +
		"more noise\nWR_CLIENT_CONFIG=vless://uuid@1.2.3.4:443?x=y#srv\n"
	got := ExtractConfigs(out)
	if len(got) != 2 {
		t.Fatalf("expected 2 configs, got %d: %v", len(got), got)
	}
	if !strings.Contains(got[0], "[Interface]") {
		t.Errorf("first config not the awg conf: %q", got[0])
	}
	if !strings.HasPrefix(got[1], "vless://") {
		t.Errorf("second config not the vless link: %q", got[1])
	}
	if ExtractConfig(out) != got[0] {
		t.Error("ExtractConfig should return the first config")
	}
}

func TestExtractTaggedPairsByMarkerNotIndex(t *testing.T) {
	// Reversed vs catalog order + a leading non-config protocol: pairing must follow
	// the WR_PROTO marker, never the position (the bug this guards against).
	out := "log\nWR_PROTO=vless-reality\nWR_CLIENT_CONFIG=vless://u@1.2.3.4:443?x=y#s\n" +
		"more\nWR_PROTO=amneziawg\nWR_CLIENT_CONFIG_B64=" + base64.StdEncoding.EncodeToString([]byte("[Interface]\nPrivateKey=x")) + "\n"
	tagged := ExtractTagged(out)
	if len(tagged) != 2 {
		t.Fatalf("expected 2 tagged configs, got %d", len(tagged))
	}
	if tagged[0].Proto != "vless-reality" || !strings.HasPrefix(tagged[0].Config, "vless://") {
		t.Errorf("first = %+v", tagged[0])
	}
	if tagged[1].Proto != "amneziawg" || !strings.Contains(tagged[1].Config, "[Interface]") {
		t.Errorf("second = %+v", tagged[1])
	}
	// Missing marker -> fall back to payload detection.
	noMarker := "WR_CLIENT_CONFIG=vless://u@1.2.3.4:443#s\n"
	tg := ExtractTagged(noMarker)
	if len(tg) != 1 || tg[0].Proto != "vless-reality" {
		t.Fatalf("detect fallback failed: %+v", tg)
	}
}

func TestCatalogDrivenScript(t *testing.T) {
	// BuildScript is registry-driven: each option contributes its tagged fragment.
	s := BuildScript([]string{"vless-reality", "amneziawg"}, "203.0.113.1")
	if !strings.Contains(s, "WR_PROTO=vless-reality") || !strings.Contains(s, "WR_PROTO=amneziawg") {
		t.Error("script missing WR_PROTO markers")
	}
	if !strings.Contains(s, "bbr") {
		t.Error("script missing BBR tuning from header")
	}
	for _, o := range Options() {
		if o.Script == "" || o.Detect == nil {
			t.Errorf("option %q must carry a Script and Detect to be registry-complete", o.ID)
		}
	}
}

func TestHardenScripts(t *testing.T) {
	ks := HardenKeysScript("deploy")
	for _, want := range []string{"ssh-keygen -t ed25519", "authorized_keys", "WR_SSH_PUB=", "WR_SSH_KEY_B64=", `TARGET_USER="deploy"`} {
		if !strings.Contains(ks, want) {
			t.Errorf("keys script missing %q", want)
		}
	}
	if !strings.Contains(HardenLockdownScript, "PasswordAuthentication no") {
		t.Error("lockdown script must disable password auth")
	}

	// Round-trip the printed key markers.
	priv := "PRIVATE-KEY-BODY"
	out := "log line\nWR_SSH_PUB=ssh-ed25519 AAAAC3Nz wayhop\nWR_SSH_KEY_B64=" + base64.StdEncoding.EncodeToString([]byte(priv)) + "\n"
	gotPriv, gotPub := ExtractSSHKey(out)
	if gotPriv != priv {
		t.Errorf("priv = %q, want %q", gotPriv, priv)
	}
	if !strings.HasPrefix(gotPub, "ssh-ed25519") {
		t.Errorf("pub = %q", gotPub)
	}
	if !LockdownConfirmed("...\nWR_HARDEN_OK=1\n") || LockdownConfirmed("nope") {
		t.Error("LockdownConfirmed logic wrong")
	}
}

func TestOptionsCatalog(t *testing.T) {
	opts := Options()
	if len(opts) < 2 {
		t.Fatalf("expected at least 2 options, got %d", len(opts))
	}
	if !ValidOption(ProtoAmneziaWG) || !ValidOption(ProtoReality) {
		t.Error("known protocols should be valid options")
	}
	if ValidOption("nonsense") {
		t.Error("unknown option should be invalid")
	}
	if OptionName(ProtoReality) != "VLESS-Reality" {
		t.Errorf("OptionName(reality) = %q", OptionName(ProtoReality))
	}
	for _, o := range opts {
		if o.Name == "" || o.Summary == "" || len(o.Details) == 0 {
			t.Errorf("option %q is missing presentation detail", o.ID)
		}
	}
}
