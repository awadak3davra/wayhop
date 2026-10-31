package generator

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"wayhop/internal/importer"
	"wayhop/internal/initserver"
	"wayhop/internal/model"
	"wayhop/internal/testsh"
)

// Invented identities for the installer's fragments, with the characters its links escape.
const (
	setupTrojanPass = "Tj+pass/word="
	setupHy2Pass    = "Hy+pass/word="
	setupHy2Obfs    = "Ob+fs/pass="
	setupVMessUUID  = "11111111-2222-3333-4444-555555555555"
	setupTUICUUID   = "11111111-2222-3333-4444-666666666666"
	setupTUICPass   = "Tu+pass/word="
	setupAnyTLSPass = "At+pass/word="
)

// setupVars sets them as the fragments name them.
const setupVars = "TJPASS='" + setupTrojanPass + "'; HY2PASS='" + setupHy2Pass + "'; HY2OBFS='" + setupHy2Obfs + "'\n" +
	"VMUUID=" + setupVMessUUID + "; VMPATH=/wayhop; TUUUID=" + setupTUICUUID + "; TUPASS='" + setupTUICPass + "'; ATPASS='" + setupAnyTLSPass + "'\n"

// setupInbound is the sing-box inbound Set up Server writes for proto (initserver's fragments), with
// tls in place of its certificate paths; udp says whether it listens on UDP only.
func setupInbound(proto model.Protocol, tls map[string]any) (ib map[string]any, udp bool) {
	switch proto {
	case model.ProtoTrojan:
		return map[string]any{"type": "trojan", "users": []any{map[string]any{"password": setupTrojanPass}}, "tls": tls}, false
	case model.ProtoHysteria2:
		return map[string]any{"type": "hysteria2", "users": []any{map[string]any{"password": setupHy2Pass}},
			"obfs": map[string]any{"type": "salamander", "password": setupHy2Obfs}, "tls": tls}, true
	case model.ProtoVMess:
		return map[string]any{"type": "vmess", "users": []any{map[string]any{"uuid": setupVMessUUID, "alterId": 0}},
			"transport": map[string]any{"type": "ws", "path": "/wayhop"}, "tls": tls}, false
	case model.ProtoTUIC:
		t := map[string]any{"alpn": []any{"h3"}}
		for k, v := range tls {
			t[k] = v
		}
		return map[string]any{"type": "tuic", "users": []any{map[string]any{"uuid": setupTUICUUID, "password": setupTUICPass}},
			"congestion_control": "bbr", "tls": t}, true
	case model.ProtoAnyTLS:
		return map[string]any{"type": "anytls", "users": []any{map[string]any{"name": "wayhop", "password": setupAnyTLSPass}}, "tls": tls}, false
	}
	return nil, false
}

// TestServerSetupPinSingBoxRuntime follows QA-138 end to end. Set up Server's own fragments run under
// sh with the real openssl (the certificate fragment, the pin snippet and what each TLS fragment
// prints once its server is up), and their output goes through ExtractTagged, the importer and
// ApplyPins as the provisioning job takes it. Each of the five TLS connections that come out renders
// certificate_public_key_sha256 from 1.13 and certificate_sha256 from 1.15, with insecure left out,
// and so does each with its public-key pin removed (as the connection form's Remove does), from 1.15
// with the whole-certificate pin alone. The config passes `check` on the core WR_SINGBOX names. Then
// the core runs: a sing-box server presenting the installer's certificate is reached on every version
// (before a pin is checked, through insecure, as before pins), and one presenting another certificate
// is refused from 1.13 with both pins, and from 1.15 with the whole-certificate pin alone: the
// router's own connection no longer accepting any certificate.
func TestServerSetupPinSingBoxRuntime(t *testing.T) {
	bin := os.Getenv("WR_SINGBOX")
	if bin == "" {
		t.Skip("WR_SINGBOX not set — set it to a sing-box binary to run the core")
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Fatalf("this test runs the installer's certificate fragment, which needs openssl on PATH: %v", err)
	}
	sh, err := testsh.Find()
	if err != nil {
		t.Fatal(err)
	}
	ver := strings.SplitN(singboxVersionOf(t, bin), "\n", 2)[0]
	minor := coreMinor(ver)
	dir := t.TempDir()

	type variant struct {
		ep       model.Endpoint
		certOnly bool
	}
	var vs []variant
	for _, proto := range []string{initserver.ProtoTrojan, initserver.ProtoHysteria2, initserver.ProtoVMess, initserver.ProtoTUIC, initserver.ProtoAnyTLS} {
		out := setupFragmentOutput(t, sh, dir, proto)
		tagged := initserver.ExtractTagged(out)
		if len(tagged) != 1 || tagged[0].Proto != proto || tagged[0].PubKeyPin == "" {
			t.Fatalf("%s: installer output gave %+v\n%s", proto, tagged, out)
		}
		ep, err := importer.Parse(tagged[0].Config)
		if err != nil {
			t.Fatalf("%s: %v", proto, err)
		}
		tagged[0].ApplyPins(ep)
		ep.Enabled = true
		certOnly := *ep
		certOnly.ID += "-cert-only"
		tl := *ep.TLS
		tl.PinPubKeySHA256 = nil
		certOnly.TLS = &tl
		vs = append(vs, variant{*ep, false}, variant{certOnly, true})
	}
	certPin, keyPin := setupCertPins(t, filepath.Join(dir, "wr-tls.crt"))

	// The render, for each version that changes it, whatever the binary.
	for _, c := range []struct {
		ver       string
		cert, key bool
	}{{"1.12.17", false, false}, {"1.13.0", false, true}, {"1.14.4", false, true}, {"1.15.0", true, true}, {ver, minor >= pinCertMinMinor, minor >= pinPubKeyMinMinor}} {
		for i := range vs {
			ob, err := OutboundForCore(&vs[i].ep, c.ver)
			if err != nil {
				t.Fatal(err)
			}
			wantCert, wantKey := c.cert, c.key && !vs[i].certOnly
			tl, _ := ob["tls"].(map[string]any)
			gotCert, gotKey := tl["certificate_sha256"], tl["certificate_public_key_sha256"]
			if wantCert != (gotCert != nil) || wantKey != (gotKey != nil) ||
				(wantCert && !reflect.DeepEqual(gotCert, []string{certPin})) || (wantKey && !reflect.DeepEqual(gotKey, []string{keyPin})) {
				t.Errorf("%s on %s: tls %v, want certificate_sha256 %v (%s) and certificate_public_key_sha256 %v (%s)",
					vs[i].ep.ID, c.ver, tl, wantCert, certPin, wantKey, keyPin)
			}
			if wantInsecure := !wantCert && !wantKey; (tl["insecure"] == true) != wantInsecure {
				t.Errorf("%s on %s: insecure = %v, want %v", vs[i].ep.ID, c.ver, tl["insecure"], wantInsecure)
			}
		}
	}
	prof := &model.Profile{Rules: []model.Rule{{ID: "def", Default: true, Outbound: vs[0].ep.ID}}}
	for _, v := range vs {
		prof.Endpoints = append(prof.Endpoints, v.ep)
	}
	res, err := Generate(prof, Options{MixedPort: 7890, CoreVersion: ver, CacheFile: filepath.Join(t.TempDir(), "cache.db")})
	if err != nil {
		t.Fatal(err)
	}
	echCheck(t, bin, "server-setup-pins.json", res.Config, true)

	// The core: the installer's certificate, and an impostor's.
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "setup-pin-ok") }))
	defer page.Close()
	otherCert, otherKey := muxTestCert(t, t.TempDir())
	servers := []struct {
		name              string
		certFile, keyFile string
		impostor          bool
	}{
		{"installer's certificate", filepath.Join(dir, "wr-tls.crt"), filepath.Join(dir, "wr-tls.key"), false},
		{"another certificate", otherCert, otherKey, true},
	}
	for _, srv := range servers {
		for i := 0; i < len(vs); i += 2 { // one server per protocol, both variants against it
			ib, udp := setupInbound(vs[i].ep.Protocol, map[string]any{"enabled": true, "server_name": "wayhop.local",
				"certificate_path": srv.certFile, "key_path": srv.keyFile})
			srvPort := muxFreePort(t)
			ib["tag"], ib["listen"], ib["listen_port"] = "in", "127.0.0.1", srvPort
			server := map[string]any{"log": map[string]any{"level": "info"}, "inbounds": []any{ib},
				"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}}
			stopS, logS := pinRunCore(t, bin, filepath.Join(dir, fmt.Sprintf("server-%d.json", srvPort)), server, srvPort, udp)
			for _, v := range vs[i : i+2] {
				e := v.ep
				e.Port = srvPort
				ob, err := OutboundForCore(&e, ver)
				if err != nil {
					t.Fatal(err)
				}
				cliPort := muxFreePort(t)
				client := map[string]any{"log": map[string]any{"level": "warn"},
					"inbounds":  []any{map[string]any{"type": "mixed", "tag": "mixed", "listen": "127.0.0.1", "listen_port": cliPort}},
					"outbounds": []any{ob}}
				stopC, logC := pinRunCore(t, bin, filepath.Join(dir, fmt.Sprintf("client-%d.json", cliPort)), client, cliPort, false)
				body, ferr := muxFetch(cliPort, page.URL)
				stopC()
				checked := minor >= pinPubKeyMinMinor
				if v.certOnly {
					checked = minor >= pinCertMinMinor
				}
				want := !srv.impostor || !checked
				if reached := ferr == nil && body == "setup-pin-ok"; reached != want {
					t.Errorf("%s, %s, %s: reached = %v (%v), want %v\nclient tls: %v\nclient:\n%s\nserver:\n%s",
						ver, e.ID, srv.name, reached, ferr, want, ob["tls"], logC(), pinTail(logS(), 6))
				} else {
					t.Logf("%s, %s, %s: reached=%v", ver, e.ID, srv.name, reached)
				}
			}
			stopS()
		}
	}
}

// setupFragmentOutput runs, under sh in dir, the parts of Set up Server's script for proto that make
// and hash the certificate and print the client config, exactly as BuildScript emits them; what
// installs and starts sing-box on a server is left out.
func setupFragmentOutput(t *testing.T, sh, dir, proto string) string {
	t.Helper()
	s := initserver.BuildScript([]string{proto}, "127.0.0.1")
	const sbd, call, unit = "\nSBD=/etc/sing-box\n", "\nwr_tls_pins\n", "systemctl restart sing-box 2>/dev/null || true\n"
	i, j := strings.Index(s, sbd), strings.Index(s, call)
	k, e := strings.LastIndex(s, unit), strings.LastIndex(s, "\nlog \"done\"")
	if i < 0 || j < i || k < j || e < k {
		t.Fatalf("%s: the script no longer has its certificate, pin and link parts where this test looks (%d %d %d %d)", proto, i, j, k, e)
	}
	script := "set -e\numask 077\nlog() { echo \"[wayhop-init] $*\"; }\nSBD='" + filepath.ToSlash(dir) + "'\nPUBLIC_IP=127.0.0.1\n" +
		setupVars + s[i+len(sbd):j+len(call)] + s[k+len(unit):e] + "\n"
	cmd := exec.Command(sh)
	cmd.Stdin = strings.NewReader(script)
	cmd.Env = append(os.Environ(), "MSYS_NO_PATHCONV=1", "MSYS2_ARG_CONV_EXCL=*")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s: sh: %v\n%s\n%s", proto, err, stdout.String(), stderr.String())
	}
	return stdout.String()
}

// setupCertPins is what sing-box decodes for certFile: the whole certificate's SHA-256 and its
// public key's (x509.MarshalPKIXPublicKey), each as standard base64.
func setupCertPins(t *testing.T, certFile string) (cert, key string) {
	t.Helper()
	b, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		t.Fatalf("%s holds no PEM block", certFile)
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(c.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	cs, ks := sha256.Sum256(blk.Bytes), sha256.Sum256(spki)
	return base64.StdEncoding.EncodeToString(cs[:]), base64.StdEncoding.EncodeToString(ks[:])
}
