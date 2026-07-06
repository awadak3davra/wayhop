package initserver

import (
	"encoding/base64"
	"strings"
	"testing"
)

// kbinitserver_indexOf returns the byte index of sub in s, or -1.
func kbinitserver_indexOf(s, sub string) int { return strings.Index(s, sub) }

// kbinitserver_b64 base64-encodes a string the way the install script does.
func kbinitserver_b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// --- BuildScript -----------------------------------------------------------

// TestBuildScriptHeaderAlwaysPresent confirms the common header (shebang, BBR /
// sysctl tuning block, and the OpenVZ/LXC virtualization guard) is emitted even
// for an empty protocol list.
func TestBuildScriptHeaderAlwaysPresent(t *testing.T) {
	s := BuildScript(nil, "")
	for _, want := range []string{
		"#!/bin/sh",
		"set -e",
		"systemd-detect-virt",                 // virt detection
		"openvz|lxc)",                         // the OpenVZ/LXC guard arm
		"/etc/sysctl.d/99-wayhop.conf",        // sysctl drop-in
		"net.core.default_qdisc=fq",           // fair queueing
		"net.ipv4.tcp_congestion_control=bbr", // BBR
		"net.core.rmem_max=16777216",          // larger UDP buffers
		`log "done"`,                          // trailer
	} {
		if !strings.Contains(s, want) {
			t.Errorf("header/trailer missing %q", want)
		}
	}
}

// TestBuildScriptSingleProtocolAmneziaWG checks the AmneziaWG fragment is present
// (with its WR_PROTO marker) and the Reality fragment is NOT.
func TestBuildScriptSingleProtocolAmneziaWG(t *testing.T) {
	s := BuildScript([]string{ProtoAmneziaWG}, "")
	for _, want := range []string{
		"# ---- AmneziaWG ----",
		"awg genkey",
		"add-apt-repository -y ppa:amnezia/ppa",
		"ListenPort = 51820",
		"WR_PROTO=amneziawg",
		"WR_CLIENT_CONFIG_B64=",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("AmneziaWG-only script missing %q", want)
		}
	}
	for _, notWant := range []string{
		"# ---- sing-box VLESS-Reality ----",
		"sing-box generate reality-keypair",
		"WR_PROTO=vless-reality",
	} {
		if strings.Contains(s, notWant) {
			t.Errorf("AmneziaWG-only script unexpectedly contains %q", notWant)
		}
	}
}

// TestBuildScriptSingleProtocolReality checks the Reality fragment + marker, and
// the AmneziaWG fragment absent.
func TestBuildScriptSingleProtocolReality(t *testing.T) {
	s := BuildScript([]string{ProtoReality}, "")
	for _, want := range []string{
		"# ---- sing-box VLESS-Reality ----",
		"sing-box generate reality-keypair",
		"sing-box generate uuid",
		"server_name",
		"WR_PROTO=vless-reality",
		"WR_CLIENT_CONFIG=vless://",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("Reality-only script missing %q", want)
		}
	}
	if strings.Contains(s, "awg genkey") || strings.Contains(s, "WR_PROTO=amneziawg") {
		t.Error("Reality-only script unexpectedly contains AmneziaWG fragment")
	}
}

// TestBuildScriptMultipleProtocolsOrdered verifies BOTH fragments are present and
// their WR_PROTO markers appear in the SAME order the protocols were selected.
func TestBuildScriptMultipleProtocolsOrdered(t *testing.T) {
	// amnezia first, then reality
	s := BuildScript([]string{ProtoAmneziaWG, ProtoReality}, "")
	iA := kbinitserver_indexOf(s, "WR_PROTO=amneziawg")
	iR := kbinitserver_indexOf(s, "WR_PROTO=vless-reality")
	if iA < 0 || iR < 0 {
		t.Fatalf("missing a marker: amnezia=%d reality=%d", iA, iR)
	}
	if iA > iR {
		t.Errorf("markers out of order: amnezia at %d should precede reality at %d", iA, iR)
	}

	// reverse the selection order; markers must follow.
	s2 := BuildScript([]string{ProtoReality, ProtoAmneziaWG}, "")
	jR := kbinitserver_indexOf(s2, "WR_PROTO=vless-reality")
	jA := kbinitserver_indexOf(s2, "WR_PROTO=amneziawg")
	if jR < 0 || jA < 0 {
		t.Fatalf("missing a marker in reversed order: reality=%d amnezia=%d", jR, jA)
	}
	if jR > jA {
		t.Errorf("reversed markers out of order: reality at %d should precede amnezia at %d", jR, jA)
	}
}

// TestBuildScriptUnknownProtocolIgnored confirms an unknown protocol id contributes
// no fragment — the script equals the header+trailer-only build.
func TestBuildScriptUnknownProtocolIgnored(t *testing.T) {
	baseline := BuildScript(nil, "")
	withJunk := BuildScript([]string{"not-a-real-proto", "totally-unknown"}, "")
	if withJunk != baseline {
		t.Errorf("unknown protocols changed the script.\nbaseline len=%d junk len=%d", len(baseline), len(withJunk))
	}
	// And a mix: only the known one contributes.
	mixed := BuildScript([]string{"bogus", ProtoReality, "alsobogus"}, "")
	if !strings.Contains(mixed, "WR_PROTO=vless-reality") {
		t.Error("known protocol in a mix with junk should still contribute")
	}
	if strings.Contains(mixed, "WR_PROTO=amneziawg") {
		t.Error("junk protocols should not introduce other fragments")
	}
}

// TestBuildScriptPublicHostOverride confirms a non-empty publicHost is injected as
// a PUBLIC_IP override right after the header (before any protocol fragment), and
// that an empty publicHost injects nothing.
func TestBuildScriptPublicHostOverride(t *testing.T) {
	s := BuildScript([]string{ProtoReality}, "203.0.113.7")
	if !strings.Contains(s, `PUBLIC_IP="203.0.113.7"`) {
		t.Error("publicHost not injected as PUBLIC_IP override")
	}
	// override must come AFTER the header's auto-detect default but BEFORE the
	// protocol fragment that consumes $PUBLIC_IP.
	iOverride := kbinitserver_indexOf(s, `PUBLIC_IP="203.0.113.7"`)
	iFragment := kbinitserver_indexOf(s, "# ---- sing-box VLESS-Reality ----")
	iHeaderDefault := kbinitserver_indexOf(s, "PUBLIC_IP=\"${WR_PUBLIC_IP:")
	if iHeaderDefault < 0 || iHeaderDefault > iOverride {
		t.Errorf("override (%d) should follow the header default (%d)", iOverride, iHeaderDefault)
	}
	if iOverride > iFragment {
		t.Errorf("override (%d) should precede the protocol fragment (%d)", iOverride, iFragment)
	}

	empty := BuildScript([]string{ProtoReality}, "")
	if strings.Contains(empty, `PUBLIC_IP="`) && strings.Contains(empty, `PUBLIC_IP=""`) {
		t.Error("empty publicHost should not inject a literal PUBLIC_IP override")
	}
	// Specifically, no quoted-literal override line should exist when host empty.
	if strings.Contains(empty, "PUBLIC_IP=\"203") {
		t.Error("empty build must not contain the host override")
	}
}

// --- HardenKeysScript ------------------------------------------------------

// TestHardenKeysScriptEmbedsUser confirms the chosen target user is embedded and
// the ssh-keygen + marker lines are present.
func TestHardenKeysScriptEmbedsUser(t *testing.T) {
	s := HardenKeysScript("deploy")
	for _, want := range []string{
		"#!/bin/sh",
		`TARGET_USER="deploy"`,
		"ssh-keygen -t ed25519",
		"authorized_keys",
		"WR_SSH_PUB=",
		"WR_SSH_KEY_B64=",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("HardenKeysScript(deploy) missing %q", want)
		}
	}
}

// TestHardenKeysScriptDefaultsToRoot confirms an empty user defaults to root.
func TestHardenKeysScriptDefaultsToRoot(t *testing.T) {
	s := HardenKeysScript("")
	if !strings.Contains(s, `TARGET_USER="root"`) {
		t.Errorf("empty user should default to root; got script:\n%s", s)
	}
}

// TestHardenKeysScriptQuotesUser confirms the user is %q-quoted, so a value with
// spaces/quotes can't break out of the shell assignment.
func TestHardenKeysScriptQuotesUser(t *testing.T) {
	s := HardenKeysScript(`weird user"`)
	if !strings.Contains(s, `TARGET_USER="weird user\""`) {
		t.Errorf("user not safely %%q-quoted; got fragment around TARGET_USER")
	}
}

// --- HardenLockdownScript --------------------------------------------------

// TestHardenLockdownDisablesPasswordAuth checks the destructive lockdown script
// turns off password auth, enforces pubkey auth, tests the config, and signals OK.
func TestHardenLockdownDisablesPasswordAuth(t *testing.T) {
	s := HardenLockdownScript
	for _, want := range []string{
		"PasswordAuthentication no",
		"PubkeyAuthentication yes",
		"/etc/ssh/sshd_config",
		"sshd -t",        // validates before reload
		"WR_HARDEN_OK=1", // success signal LockdownConfirmed looks for
	} {
		if !strings.Contains(s, want) {
			t.Errorf("HardenLockdownScript missing %q", want)
		}
	}
	if strings.Contains(s, "PasswordAuthentication yes") {
		t.Error("lockdown script must not enable PasswordAuthentication")
	}
}

// TestLockdownConfirmed pairs with the script's success marker.
func TestLockdownConfirmed(t *testing.T) {
	if !LockdownConfirmed("foo\nWR_HARDEN_OK=1\nbar") {
		t.Error("LockdownConfirmed should be true when WR_HARDEN_OK=1 present")
	}
	if LockdownConfirmed("WR_HARDEN_ERR=sshd config test failed") {
		t.Error("LockdownConfirmed should be false on error output")
	}
	if LockdownConfirmed("") {
		t.Error("LockdownConfirmed should be false on empty output")
	}
}

// --- ExtractSSHKey ---------------------------------------------------------

// TestExtractSSHKeyRoundTrip confirms a base64 private key and a plaintext public
// key are both recovered from marker lines.
func TestExtractSSHKeyRoundTrip(t *testing.T) {
	priv := "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"
	pub := "ssh-ed25519 AAAAC3Nz wayhop-managed"
	out := "[wayhop-harden] installing\n" +
		"WR_SSH_PUB=" + pub + "\n" +
		"WR_SSH_KEY_B64=" + kbinitserver_b64(priv) + "\n" +
		"[wayhop-harden] done\n"
	gotPriv, gotPub := ExtractSSHKey(out)
	if gotPriv != priv {
		t.Errorf("priv = %q, want %q", gotPriv, priv)
	}
	if gotPub != pub {
		t.Errorf("pub = %q, want %q", gotPub, pub)
	}
}

// TestExtractSSHKeyMissingMarkers confirms missing markers yield empty strings and
// invalid base64 is ignored (priv stays empty) rather than producing garbage.
func TestExtractSSHKeyMissingMarkers(t *testing.T) {
	if p, q := ExtractSSHKey("nothing here\njust logs"); p != "" || q != "" {
		t.Errorf("no markers should give empty,empty; got %q,%q", p, q)
	}
	// pub present, key marker has invalid base64 -> priv empty, pub set.
	out := "WR_SSH_PUB=ssh-ed25519 KEY\nWR_SSH_KEY_B64=!!!not base64!!!\n"
	p, q := ExtractSSHKey(out)
	if p != "" {
		t.Errorf("invalid base64 priv should stay empty; got %q", p)
	}
	if q != "ssh-ed25519 KEY" {
		t.Errorf("pub = %q, want 'ssh-ed25519 KEY'", q)
	}
}

// --- ExtractTagged / ExtractConfigs ----------------------------------------

// TestExtractTaggedMultipleWithMarkers confirms multiple configs are each tagged
// with the protocol from the WR_PROTO marker that precedes them, in order.
func TestExtractTaggedMultipleWithMarkers(t *testing.T) {
	awgConf := "[Interface]\nPrivateKey = k\n[Peer]\nEndpoint = 1.2.3.4:51820"
	vless := "vless://uuid@1.2.3.4:443?security=reality#wayhop"
	out := strings.Join([]string{
		"[wayhop-init] installing AmneziaWG...",
		"WR_PROTO=amneziawg",
		"WR_CLIENT_CONFIG_B64=" + kbinitserver_b64(awgConf),
		"[wayhop-init] installing sing-box...",
		"WR_PROTO=vless-reality",
		"WR_CLIENT_CONFIG=" + vless,
		"[wayhop-init] done",
	}, "\n")
	tagged := ExtractTagged(out)
	if len(tagged) != 2 {
		t.Fatalf("got %d tagged configs, want 2: %+v", len(tagged), tagged)
	}
	if tagged[0].Proto != ProtoAmneziaWG || tagged[0].Config != awgConf {
		t.Errorf("first tagged = %+v, want amneziawg + decoded conf", tagged[0])
	}
	if tagged[1].Proto != ProtoReality || tagged[1].Config != vless {
		t.Errorf("second tagged = %+v, want vless-reality + link", tagged[1])
	}

	// ExtractConfigs flattens to the configs in order.
	cs := ExtractConfigs(out)
	if len(cs) != 2 || cs[0] != awgConf || cs[1] != vless {
		t.Errorf("ExtractConfigs = %v, want [awgConf, vless]", cs)
	}
}

// TestExtractTaggedFallbackDetect confirms a config WITHOUT a preceding WR_PROTO
// marker is attributed via the catalog detectors (DetectProto fallback).
func TestExtractTaggedFallbackDetect(t *testing.T) {
	awgConf := "[Interface]\nPrivateKey = k"
	out := "log\nWR_CLIENT_CONFIG_B64=" + kbinitserver_b64(awgConf) + "\n" +
		"WR_CLIENT_CONFIG=vless://uuid@h:443#x\n"
	tagged := ExtractTagged(out)
	if len(tagged) != 2 {
		t.Fatalf("got %d, want 2: %+v", len(tagged), tagged)
	}
	if tagged[0].Proto != ProtoAmneziaWG {
		t.Errorf("first (no marker) proto = %q, want amneziawg via detect", tagged[0].Proto)
	}
	if tagged[1].Proto != ProtoReality {
		t.Errorf("second (no marker) proto = %q, want vless-reality via detect", tagged[1].Proto)
	}
}

// TestExtractTaggedMarkerConsumed confirms a WR_PROTO marker applies only to the
// NEXT config; a second config with no marker of its own falls back to detection
// rather than reusing the stale marker.
func TestExtractTaggedMarkerConsumed(t *testing.T) {
	vless := "vless://uuid@h:443#x"
	awgConf := "[Interface]\nPrivateKey = k"
	out := "WR_PROTO=vless-reality\n" +
		"WR_CLIENT_CONFIG=" + vless + "\n" +
		"WR_CLIENT_CONFIG_B64=" + kbinitserver_b64(awgConf) + "\n"
	tagged := ExtractTagged(out)
	if len(tagged) != 2 {
		t.Fatalf("got %d, want 2", len(tagged))
	}
	if tagged[0].Proto != ProtoReality {
		t.Errorf("first proto = %q, want vless-reality (from marker)", tagged[0].Proto)
	}
	// marker was consumed; second has no marker -> detector says amneziawg.
	if tagged[1].Proto != ProtoAmneziaWG {
		t.Errorf("second proto = %q, want amneziawg (marker consumed, detector used)", tagged[1].Proto)
	}
}

// TestExtractTaggedGarbageAndMissing confirms garbage / missing markers produce no
// configs and never panic.
func TestExtractTaggedGarbageAndMissing(t *testing.T) {
	for _, in := range []string{
		"",
		"just plain logs with no markers at all",
		"WR_PROTO=amneziawg\n(no config follows the marker)", // dangling marker
		"WR_CLIENT_CONFIG_B64=%%%not-base64%%%",              // undecodable b64 -> dropped
		"WR_PROTOX=amneziawg\nWR_CLIENT_CONFIGZ=vless://x",   // near-miss prefixes
	} {
		got := ExtractTagged(in)
		if len(got) != 0 {
			t.Errorf("input %q: got %d tagged, want 0 (%+v)", in, len(got), got)
		}
	}
	// ExtractConfigs on garbage -> empty, non-nil slice.
	cs := ExtractConfigs("garbage")
	if cs == nil {
		t.Error("ExtractConfigs should return a non-nil empty slice, not nil")
	}
	if len(cs) != 0 {
		t.Errorf("ExtractConfigs(garbage) = %v, want empty", cs)
	}
}

// TestExtractTaggedTrimsWhitespace confirms leading/trailing whitespace around
// marker lines is tolerated (scripts may indent or pad output).
func TestExtractTaggedTrimsWhitespace(t *testing.T) {
	vless := "vless://uuid@h:443#x"
	out := "   WR_PROTO=vless-reality   \n\t WR_CLIENT_CONFIG=" + vless + " \n"
	tagged := ExtractTagged(out)
	if len(tagged) != 1 {
		t.Fatalf("got %d, want 1: %+v", len(tagged), tagged)
	}
	if tagged[0].Proto != ProtoReality || tagged[0].Config != vless {
		t.Errorf("tagged = %+v, want vless-reality + trimmed link", tagged[0])
	}
}

// --- OneLiner --------------------------------------------------------------

// TestOneLinerKeyVsPassword confirms the manual command reflects key vs password
// auth and the resolved port.
func TestOneLinerKeyVsPassword(t *testing.T) {
	keyLine := OneLiner(Creds{Host: "h.example", Port: 2222, User: "bob", Key: "PRIVATEKEY"})
	if !strings.Contains(keyLine, "ssh -i <your-key>") {
		t.Errorf("key one-liner should reference an identity file; got %q", keyLine)
	}
	if !strings.Contains(keyLine, "-p 2222") || !strings.Contains(keyLine, "bob@h.example") {
		t.Errorf("key one-liner port/user wrong: %q", keyLine)
	}
	if strings.Contains(keyLine, "PRIVATEKEY") {
		t.Errorf("one-liner must NOT embed the private key material: %q", keyLine)
	}

	pwLine := OneLiner(Creds{Host: "h.example", Port: 22, User: "root", Password: "secret"})
	if strings.Contains(pwLine, "ssh -i") {
		t.Errorf("password one-liner should not reference an identity file: %q", pwLine)
	}
	if !strings.Contains(pwLine, "sshpass") {
		t.Errorf("password one-liner should mention sshpass: %q", pwLine)
	}
	if strings.Contains(pwLine, "secret") {
		t.Errorf("one-liner must NOT embed the password: %q", pwLine)
	}
}

// TestOneLinerDefaultPort confirms a zero port resolves to 22 in both branches.
func TestOneLinerDefaultPort(t *testing.T) {
	key := OneLiner(Creds{Host: "h", User: "u", Key: "k"})
	if !strings.Contains(key, "-p 22 ") {
		t.Errorf("zero port should default to 22 (key branch): %q", key)
	}
	pw := OneLiner(Creds{Host: "h", User: "u"})
	if !strings.Contains(pw, "-p 22 ") {
		t.Errorf("zero port should default to 22 (password branch): %q", pw)
	}
}
