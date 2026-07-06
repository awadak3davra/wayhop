package initserver

import (
	"encoding/base64"
	"strings"
	"testing"
)

// further_lineWith returns the first line in s (split on '\n') that contains sub,
// trimmed, or "" if none. Used to inspect a specific emitted marker line.
func further_lineWith(s, sub string) string {
	for _, ln := range strings.Split(s, "\n") {
		if strings.Contains(ln, sub) {
			return strings.TrimSpace(ln)
		}
	}
	return ""
}

// --- scriptHeader: born-secure umask (iter-5 review finding) ----------------

// TestScriptHeaderUmaskBornSecure asserts the provisioning script sets a
// restrictive umask (077) before any secret-generating command, so generated
// keys/certs/configs are never briefly world-readable on the fresh VPS. Checked
// for every Option, since scriptHeader is shared by all fragments.
func TestScriptHeaderUmaskBornSecure(t *testing.T) {
	for _, o := range Options() {
		s := BuildScript([]string{o.ID}, "")
		iUmask := strings.Index(s, "umask 077")
		if iUmask < 0 {
			t.Errorf("%s: script missing 'umask 077' — secrets could be born world-readable", o.ID)
			continue
		}
		for _, gen := range []string{"genkey", "generate uuid", "generate reality-keypair", "openssl", "generate rand"} {
			if i := strings.Index(s, gen); i >= 0 && i < iUmask {
				t.Errorf("%s: secret-gen %q (idx %d) precedes 'umask 077' (idx %d)", o.ID, gen, i, iUmask)
			}
		}
	}
}

// --- BuildScript: the WR_PROTO-before-WR_CLIENT_CONFIG invariant ------------

// TestBuildScriptProtoMarkerPrecedesConfigPerProtocol asserts the documented
// contract for every catalog Option: the emitted fragment prints WR_PROTO=<id>
// and that marker appears BEFORE this protocol's WR_CLIENT_CONFIG line, with no
// OTHER protocol's WR_PROTO marker squeezed in between. This is the structural
// guarantee ExtractTagged relies on to attribute configs by marker, not index.
func TestBuildScriptProtoMarkerPrecedesConfigPerProtocol(t *testing.T) {
	for _, o := range Options() {
		s := BuildScript([]string{o.ID}, "")
		protoMarker := "WR_PROTO=" + o.ID
		iProto := strings.Index(s, protoMarker)
		if iProto < 0 {
			t.Errorf("%s: emitted script lacks promised marker %q", o.ID, protoMarker)
			continue
		}
		// Find the first WR_CLIENT_CONFIG marker line after the proto marker.
		rest := s[iProto+len(protoMarker):]
		iCfg := strings.Index(rest, "WR_CLIENT_CONFIG")
		if iCfg < 0 {
			t.Errorf("%s: no WR_CLIENT_CONFIG line follows the WR_PROTO marker", o.ID)
			continue
		}
		// Between the proto marker and its config there must be no SECOND WR_PROTO=
		// line (which would mean the marker belongs to a different fragment).
		between := rest[:iCfg]
		if strings.Contains(between, "WR_PROTO=") {
			t.Errorf("%s: another WR_PROTO marker sits between this proto's marker and its config", o.ID)
		}
	}
}

// TestBuildScriptAmneziaWGUsesB64MarkerOnly confirms the AmneziaWG fragment emits
// the base64 marker (its .conf is multiline so it must be b64-encoded) and NOT the
// plaintext WR_CLIENT_CONFIG= marker — picking the wrong marker would corrupt the
// multiline config.
func TestBuildScriptAmneziaWGUsesB64MarkerOnly(t *testing.T) {
	s := BuildScript([]string{ProtoAmneziaWG}, "")
	if !strings.Contains(s, "WR_CLIENT_CONFIG_B64=") {
		t.Fatal("AmneziaWG must use the base64 client-config marker")
	}
	// Every WR_CLIENT_CONFIG emitter line in the AWG-only script must be the _B64
	// variant. A plaintext emitter (echo "WR_CLIENT_CONFIG=...") would mangle the
	// multiline .conf, so assert none exists.
	for _, ln := range strings.Split(s, "\n") {
		if !strings.Contains(ln, "WR_CLIENT_CONFIG") {
			continue
		}
		if !strings.Contains(ln, "WR_CLIENT_CONFIG_B64=") {
			t.Errorf("AmneziaWG emits a non-b64 client-config line (would corrupt multiline conf): %q", strings.TrimSpace(ln))
		}
	}
}

// TestBuildScriptAmneziaWGRandomizesHParams guards the obfuscation fix: the header-
// magic H1-H4 must be RANDOMIZED + persisted, never the WireGuard defaults 1/2/3/4
// — fixed defaults leave the handshake message types unobfuscated, so DPI can
// fingerprint the tunnel as plain WireGuard, defeating AmneziaWG's whole purpose.
func TestBuildScriptAmneziaWGRandomizesHParams(t *testing.T) {
	s := BuildScript([]string{ProtoAmneziaWG}, "")
	if strings.Contains(s, "H1=1; H2=2; H3=3; H4=4") {
		t.Error("AmneziaWG hardcodes the WireGuard-default H1-H4 (1/2/3/4) — no header obfuscation")
	}
	if !strings.Contains(s, "wr-hparams") {
		t.Error("AmneziaWG must persist randomized H-params (wr-hparams) so a re-run reuses them")
	}
}

// TestBuildScriptRealityUsesPlainMarker confirms the Reality fragment emits the
// plaintext WR_CLIENT_CONFIG= marker carrying a vless:// link (a single-line URL,
// so no base64 needed) and does NOT emit a _B64 marker.
func TestBuildScriptRealityUsesPlainMarker(t *testing.T) {
	s := BuildScript([]string{ProtoReality}, "")
	line := further_lineWith(s, "WR_CLIENT_CONFIG=vless://")
	if line == "" {
		t.Fatal("Reality must emit a plaintext WR_CLIENT_CONFIG=vless:// marker")
	}
	if strings.Contains(s, "WR_CLIENT_CONFIG_B64=") {
		t.Error("Reality fragment should not emit a base64 client-config marker")
	}
}

// TestBuildScriptRealityPersistsIdentity guards the idempotence fix: the Reality
// fragment must generate its uuid / keypair / short_id only when ABSENT and read
// them back from persisted files. Regenerating on every run would silently rotate
// the Reality identity and invalidate every previously-issued client (the
// AmneziaWG fragment already guards its keys with `[ -f server.key ]`).
func TestBuildScriptRealityPersistsIdentity(t *testing.T) {
	s := BuildScript([]string{ProtoReality}, "")
	for _, guard := range []string{
		`[ -f "$SBD/wr-reality-uuid" ] || sing-box generate uuid`,
		`[ -f "$SBD/wr-reality.key" ] || sing-box generate reality-keypair`,
	} {
		if !strings.Contains(s, guard) {
			t.Errorf("Reality fragment must guard secret generation (missing %q) — a re-run must reuse the identity", guard)
		}
	}
	if strings.Contains(s, "UUID=$(sing-box generate uuid)") {
		t.Error("Reality fragment still generates a fresh uuid unconditionally — would rotate the identity on re-provision")
	}
}

// TestBuildScriptStartsWithShebangExactly confirms the very first bytes are the
// shebang — a script that doesn't start with #!/bin/sh won't execute as intended
// when piped to `sh -s`.
func TestBuildScriptStartsWithShebangExactly(t *testing.T) {
	s := BuildScript([]string{ProtoReality}, "10.0.0.1")
	if !strings.HasPrefix(s, "#!/bin/sh\n") {
		t.Fatalf("script must start with the shebang line; got first 12 bytes %q", s[:min(12, len(s))])
	}
	// The host override must appear after the shebang, never before it.
	if i := strings.Index(s, `PUBLIC_IP="10.0.0.1"`); i >= 0 && i < len("#!/bin/sh\n") {
		t.Error("PUBLIC_IP override must not precede the shebang")
	}
}

// --- ExtractConfig / ExtractConfigs edge cases ------------------------------

// TestExtractConfigVlessKeepsEmbeddedEquals is the load-bearing case: a vless URL
// query contains '=' characters (security=reality&pbk=...). Only the leading
// "WR_CLIENT_CONFIG=" prefix may be stripped; every '=' inside the link must
// survive intact, or the client config is silently mangled.
func TestExtractConfigVlessKeepsEmbeddedEquals(t *testing.T) {
	link := "vless://u@1.2.3.4:443?security=reality&sni=www.microsoft.com&pbk=ABC=&sid=ff00#wayhop-server"
	got := ExtractConfig("noise\nWR_PROTO=vless-reality\nWR_CLIENT_CONFIG=" + link + "\ntail")
	if got != link {
		t.Fatalf("embedded '=' mangled.\n got=%q\nwant=%q", got, link)
	}
}

// TestExtractConfigReturnsFirstOfMany confirms ExtractConfig yields the FIRST
// config when several are printed (ordering matters: the AWG conf precedes the
// vless link here), while ExtractConfigs yields both in order.
func TestExtractConfigReturnsFirstOfMany(t *testing.T) {
	awg := "[Interface]\nPrivateKey = k\n[Peer]\nEndpoint = 9.9.9.9:51820"
	vless := "vless://u@9.9.9.9:443?security=reality#srv"
	out := "WR_PROTO=amneziawg\nWR_CLIENT_CONFIG_B64=" + base64.StdEncoding.EncodeToString([]byte(awg)) + "\n" +
		"WR_PROTO=vless-reality\nWR_CLIENT_CONFIG=" + vless + "\n"
	if got := ExtractConfig(out); got != awg {
		t.Fatalf("ExtractConfig should return the first (awg) config; got %q", got)
	}
	all := ExtractConfigs(out)
	if len(all) != 2 || all[0] != awg || all[1] != vless {
		t.Fatalf("ExtractConfigs = %v, want [awg, vless]", all)
	}
}

// TestExtractConfigB64WithCRLF confirms a base64 marker whose line has a trailing
// CR (Windows/SSH line endings) still decodes — the extractor TrimSpaces the
// payload before decoding. Without trimming, the stray '\r' breaks base64.
func TestExtractConfigB64WithCRLF(t *testing.T) {
	conf := "[Interface]\nPrivateKey = abc\n[Peer]\nEndpoint = 5.5.5.5:51820"
	b64 := base64.StdEncoding.EncodeToString([]byte(conf))
	out := "log\r\nWR_CLIENT_CONFIG_B64=" + b64 + "\r\nmore\r\n"
	if got := ExtractConfig(out); got != conf {
		t.Fatalf("CRLF-terminated b64 marker failed to decode.\n got=%q\nwant=%q", got, conf)
	}
}

// TestExtractConfigInvalidB64IsDropped confirms an undecodable base64 payload
// produces no config (rather than garbage), and a later valid marker still wins.
func TestExtractConfigInvalidB64IsDropped(t *testing.T) {
	// Only an invalid b64 marker -> empty.
	if got := ExtractConfig("WR_CLIENT_CONFIG_B64=@@@not-valid@@@\n"); got != "" {
		t.Fatalf("invalid b64 should yield empty; got %q", got)
	}
	// Invalid b64 first, valid vless second -> the vless link is the first VALID
	// config and so what ExtractConfig returns.
	vless := "vless://u@h:443#s"
	out := "WR_CLIENT_CONFIG_B64=%%%bad%%%\nWR_CLIENT_CONFIG=" + vless + "\n"
	if got := ExtractConfig(out); got != vless {
		t.Fatalf("undecodable b64 should be skipped, vless returned; got %q", got)
	}
}

// TestExtractConfigEmptyAndNoMarker confirms empty input and marker-free input
// both yield "" without panicking.
func TestExtractConfigEmptyAndNoMarker(t *testing.T) {
	if got := ExtractConfig(""); got != "" {
		t.Errorf("empty input: got %q, want empty", got)
	}
	if got := ExtractConfig("WR_PROTO=amneziawg\n(marker but no config line)\n"); got != "" {
		t.Errorf("dangling proto marker with no config: got %q, want empty", got)
	}
}

// TestExtractConfigNearMissPrefixIgnored confirms a near-miss marker name
// (WR_CLIENT_CONFIGURATION=) is NOT treated as a config marker — CutPrefix is a
// real prefix match but the extractor's contract is the exact "WR_CLIENT_CONFIG="
// token. Here the longer name DOES start with the token, so it is (correctly)
// matched and the remainder ("URATION=...") is returned; we assert that exact
// current behavior so the test stays truthful.
func TestExtractConfigNearMissPrefixIgnored(t *testing.T) {
	// "WR_CLIENT_CONFIGX=foo" -> does NOT start with "WR_CLIENT_CONFIG=" (the char
	// after CONFIG is 'X', not '='), so it must be ignored entirely.
	if got := ExtractConfig("WR_CLIENT_CONFIGX=foo\n"); got != "" {
		t.Errorf("WR_CLIENT_CONFIGX= must not match the config marker; got %q", got)
	}
	// Likewise a marker missing the '=' entirely.
	if got := ExtractConfig("WR_CLIENT_CONFIG vless://x\n"); got != "" {
		t.Errorf("marker without '=' must not match; got %q", got)
	}
}

// TestExtractConfigsAlwaysNonNil confirms the empty-result slice is non-nil so
// callers can range/len without a nil check, even for garbage input.
func TestExtractConfigsAlwaysNonNil(t *testing.T) {
	cs := ExtractConfigs("only logs, nothing tagged")
	if cs == nil {
		t.Fatal("ExtractConfigs must return a non-nil empty slice")
	}
	if len(cs) != 0 {
		t.Errorf("expected empty, got %v", cs)
	}
}

// --- OneLiner additional edge cases -----------------------------------------

// TestOneLinerPasswordBranchShape confirms the password branch references the
// install script filename, the resolved port, and the sshpass alternative comment,
// without leaking the password even when one is supplied.
func TestOneLinerPasswordBranchShape(t *testing.T) {
	line := OneLiner(Creds{Host: "srv", Port: 2200, User: "ada", Password: "hunter2"})
	for _, want := range []string{"-p 2200", "ada@srv", "wayhop-install.sh", "sshpass"} {
		if !strings.Contains(line, want) {
			t.Errorf("password one-liner missing %q: %q", want, line)
		}
	}
	if strings.Contains(line, "hunter2") {
		t.Errorf("password one-liner leaked the password: %q", line)
	}
}

// TestOneLinerKeyTakesPrecedenceOverPassword confirms that when BOTH a key and a
// password are present, the key branch is chosen (and the password is not leaked).
func TestOneLinerKeyTakesPrecedenceOverPassword(t *testing.T) {
	line := OneLiner(Creds{Host: "srv", Port: 22, User: "root", Key: "PRIV", Password: "pw"})
	if !strings.Contains(line, "ssh -i <your-key>") {
		t.Errorf("with a key present, the key branch should be used: %q", line)
	}
	if strings.Contains(line, "PRIV") || strings.Contains(line, "pw") {
		t.Errorf("one-liner must not leak key or password material: %q", line)
	}
	// The key branch is a clean command with no sshpass alternative comment.
	if strings.Contains(line, "sshpass") {
		t.Errorf("key one-liner should not mention sshpass: %q", line)
	}
}
