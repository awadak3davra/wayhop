package generator

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"wayhop/internal/model"
)

// TestCertificatePinSingBoxCheck renders certificate pins on every TLS protocol, with and without a
// uTLS fingerprint and certificate checks, for the version WR_SINGBOX reports, and runs the real
// check on it: each kind of pin is written exactly where the core takes it (a public-key pin from
// 1.13, a whole-certificate pin from 1.15) and nowhere else. The negative controls are what the
// generator keeps out: either field on a core older than its version (an unknown field, which stops
// the whole config), a hash that is not base64, and a pin beside a pinned CA certificate.
func TestCertificatePinSingBoxCheck(t *testing.T) {
	bin := os.Getenv("WR_SINGBOX")
	if bin == "" {
		t.Skip("WR_SINGBOX not set — set it to a sing-box binary for a real `check`")
	}
	ver := singboxVersionOf(t, bin)
	minor := coreMinor(ver)
	pins := func(e *model.Endpoint) {
		e.TLS.PinCertSHA256, e.TLS.PinPubKeySHA256 = []string{pinCertHex}, []string{pinKeyB64}
	}
	with := func(fs ...func(*model.Endpoint)) func(*model.Endpoint) {
		return func(e *model.Endpoint) {
			for _, f := range fs {
				f(e)
			}
		}
	}
	insecure := func(e *model.Endpoint) { e.TLS.Insecure = true }
	chrome := func(e *model.Endpoint) { e.TLS.Fingerprint = "chrome" }
	prof := &model.Profile{
		Endpoints: []model.Endpoint{
			pinTestEndpoint("vless-pins", model.ProtoVLESS, pins),
			pinTestEndpoint("vless-pins-utls", model.ProtoVLESS, with(pins, chrome, insecure)),
			pinTestEndpoint("vmess-ws-pins", model.ProtoVMess, with(pins, func(e *model.Endpoint) {
				e.Params["security"] = "auto"
				e.Transport = &model.Transport{Type: "ws", Path: "/p"}
			})),
			pinTestEndpoint("trojan-pins-insecure", model.ProtoTrojan, with(pins, insecure)),
			pinTestEndpoint("trojan-key-only", model.ProtoTrojan, func(e *model.Endpoint) { e.TLS.PinPubKeySHA256 = []string{pinKeyB64} }),
			pinTestEndpoint("anytls-pins", model.ProtoAnyTLS, with(pins, chrome)),
			pinTestEndpoint("hy2-legacy", model.ProtoHysteria2, with(insecure, func(e *model.Endpoint) { e.Params[model.ParamLegacyPin] = pinCertHex })),
			pinTestEndpoint("hy2-pins", model.ProtoHysteria2, pins),
			pinTestEndpoint("tuic-pins", model.ProtoTUIC, with(pins, insecure)),
			pinTestEndpoint("https-pins", model.ProtoHTTP, pins),
			// A Reality link's pins: kept, never rendered beside reality.
			pinTestEndpoint("reality-pins", model.ProtoVLESS, with(pins, func(e *model.Endpoint) {
				e.TLS.Type, e.TLS.PublicKey = "reality", "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"
			})),
		},
		Rules: []model.Rule{{ID: "def", Default: true, Outbound: "vless-pins"}},
	}
	res, err := Generate(prof, Options{MixedPort: 7890, CoreVersion: ver, CacheFile: filepath.Join(t.TempDir(), "cache.db")})
	if err != nil {
		t.Fatalf("generate for %s: %v", strings.SplitN(ver, "\n", 2)[0], err)
	}
	for _, ob := range res.Config["outbounds"].([]map[string]any) {
		id, _ := ob["tag"].(string)
		tl, _ := ob["tls"].(map[string]any)
		if tl == nil {
			continue
		}
		reality := id == "reality-pins"
		wantCert := minor >= pinCertMinMinor && !reality && id != "trojan-key-only"
		wantKey := minor >= pinPubKeyMinMinor && !reality && id != "hy2-legacy"
		if (tl["certificate_sha256"] != nil) != wantCert || (tl["certificate_public_key_sha256"] != nil) != wantKey {
			t.Errorf("sing-box %s, %s: tls = %v", strings.SplitN(ver, "\n", 2)[0], id, tl)
		}
		if (wantCert || wantKey) && tl["insecure"] != nil {
			t.Errorf("%s: insecure beside a rendered pin: %v", id, tl)
		}
	}
	echCheck(t, bin, "pins.json", res.Config, true)

	raw := func(tls map[string]any) map[string]any {
		m := map[string]any{"enabled": true, "server_name": "example.com"}
		for k, v := range tls {
			m[k] = v
		}
		return map[string]any{"outbounds": []map[string]any{{"type": "trojan", "tag": "x", "server": "192.0.2.21",
			"server_port": 443, "password": "pw", "tls": m}}}
	}
	echCheck(t, bin, "raw-key.json", raw(map[string]any{"certificate_public_key_sha256": []string{pinKeyB64}}), minor >= pinPubKeyMinMinor)
	echCheck(t, bin, "raw-cert.json", raw(map[string]any{"certificate_sha256": []string{pinCertB64}}), minor >= pinCertMinMinor)
	// The field decodes base64 and checks no length: what is not base64 stops the whole config, and 64
	// hex digits pass as 48 bytes that never match (the generator writes base64 of 32 bytes only).
	echCheck(t, bin, "raw-not-b64.json", raw(map[string]any{"certificate_public_key_sha256": []string{"not*base64!"}}), false)
	echCheck(t, bin, "raw-hex.json", raw(map[string]any{"certificate_public_key_sha256": []string{pinCertHex}}), minor >= pinPubKeyMinMinor)
	// A pin beside a pinned CA: refused where the pin exists (and as an unknown field before).
	ca, _ := pinTestCertPEM(t)
	echCheck(t, bin, "raw-ca.json", raw(map[string]any{"certificate_public_key_sha256": []string{pinKeyB64},
		"certificate": strings.Split(strings.TrimSpace(ca), "\n")}), false)
}

// TestCertificatePinSingBoxRuntime runs the core: a sing-box Trojan (TCP) and Hysteria2 (QUIC) server
// on loopback with a self-signed certificate, and a client whose outbound is the one WayHop renders
// for the version WR_SINGBOX reports (OutboundForCore). The right pin reaches the server and a wrong
// one is refused, also beside "insecure" (the pin replaces it), for a public-key pin from 1.13 and a
// whole-certificate pin from 1.15, with and without a uTLS fingerprint. Where the core cannot check a
// kind, the pin is left out and the connection behaves as before pinning existed: with certificate
// checks on it is refused (fail closed), with them off it connects.
func TestCertificatePinSingBoxRuntime(t *testing.T) {
	bin := os.Getenv("WR_SINGBOX")
	if bin == "" {
		t.Skip("WR_SINGBOX not set — set it to a sing-box binary to run the core")
	}
	ver := strings.SplitN(singboxVersionOf(t, bin), "\n", 2)[0]
	minor := coreMinor(ver)
	dir := t.TempDir()
	certFile, keyFile := muxTestCert(t, dir)
	certDER := pinReadDER(t, certFile)
	cs := sha256.Sum256(certDER)
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ks := sha256.Sum256(spki)
	rightCert, rightKey := hex.EncodeToString(cs[:]), base64.StdEncoding.EncodeToString(ks[:])
	// Wrong pins: the right hashes of another certificate's bytes.
	wrongCert, wrongKey := pinCertHex, pinKeyB64

	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "pin-ok") }))
	defer page.Close()
	tlsIn := map[string]any{"enabled": true, "server_name": "example.com", "certificate_path": certFile, "key_path": keyFile}

	type server struct {
		name    string
		proto   model.Protocol
		udp     bool
		inbound map[string]any
	}
	servers := []server{
		{"trojan", model.ProtoTrojan, false, map[string]any{"type": "trojan", "users": []any{map[string]any{"password": "pw"}}, "tls": tlsIn}},
		{"hysteria2", model.ProtoHysteria2, true, map[string]any{"type": "hysteria2", "users": []any{map[string]any{"password": "pw"}}, "tls": tlsIn}},
	}
	type tc struct {
		name     string
		cert     []string
		key      []string
		insecure bool
		utls     bool
		reaches  bool
	}
	cases := []tc{
		{"no pin, checks on (self-signed)", nil, nil, false, false, false},
		{"no pin, insecure", nil, nil, true, false, true},
		{"right key pin", nil, []string{rightKey}, false, false, minor >= pinPubKeyMinMinor},
		{"wrong key pin, insecure", nil, []string{wrongKey}, true, false, minor < pinPubKeyMinMinor},
		{"right cert pin", []string{rightCert}, nil, false, false, minor >= pinCertMinMinor},
		{"wrong cert pin, insecure", []string{wrongCert}, nil, true, false, minor < pinCertMinMinor},
		{"wrong cert pin, right key pin", []string{wrongCert}, []string{rightKey}, false, false, minor >= pinPubKeyMinMinor},
		{"utls: right key pin", nil, []string{rightKey}, false, true, minor >= pinPubKeyMinMinor},
		{"utls: wrong key pin, insecure", nil, []string{wrongKey}, true, true, minor < pinPubKeyMinMinor},
		{"utls: right cert pin", []string{rightCert}, nil, false, true, minor >= pinCertMinMinor},
		{"utls: wrong cert pin, insecure", []string{wrongCert}, nil, true, true, minor < pinCertMinMinor},
	}
	for _, s := range servers {
		srvPort := muxFreePort(t)
		ib := map[string]any{"tag": "in", "listen": "127.0.0.1", "listen_port": srvPort}
		for k, v := range s.inbound {
			ib[k] = v
		}
		server := map[string]any{"log": map[string]any{"level": "info"}, "inbounds": []any{ib},
			"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}}
		stopS, logS := pinRunCore(t, bin, filepath.Join(dir, s.name+"-server.json"), server, srvPort, s.udp)
		for _, c := range cases {
			if c.utls && s.proto != model.ProtoTrojan {
				continue // uTLS is a TCP ClientHello; sing-box takes none over QUIC
			}
			e := model.Endpoint{ID: "out", Name: "out", Enabled: true, Engine: model.EngineSingBox, Protocol: s.proto,
				Server: "127.0.0.1", Port: srvPort, Params: map[string]any{"password": "pw"},
				TLS: &model.TLS{Enabled: true, Type: "tls", SNI: "example.com", Insecure: c.insecure,
					PinCertSHA256: c.cert, PinPubKeySHA256: c.key}}
			if c.utls {
				e.TLS.Fingerprint = "chrome"
			}
			ob, err := OutboundForCore(&e, ver)
			if err != nil {
				t.Fatalf("%s, %s: %v", s.name, c.name, err)
			}
			cliPort := muxFreePort(t)
			client := map[string]any{"log": map[string]any{"level": "warn"},
				"inbounds":  []any{map[string]any{"type": "mixed", "tag": "mixed", "listen": "127.0.0.1", "listen_port": cliPort}},
				"outbounds": []any{ob}}
			stopC, logC := pinRunCore(t, bin, filepath.Join(dir, fmt.Sprintf("%s-client-%d.json", s.name, cliPort)), client, cliPort, false)
			body, ferr := muxFetch(cliPort, page.URL)
			stopC()
			reached := ferr == nil && body == "pin-ok"
			if reached != c.reaches {
				t.Errorf("%s, %s, %s: reached = %v (%v), want %v\nclient tls: %v\nclient:\n%s\nserver:\n%s",
					ver, s.name, c.name, reached, ferr, c.reaches, ob["tls"], logC(), pinTail(logS(), 6))
			} else {
				t.Logf("%s, %s, %s: reached=%v", ver, s.name, c.name, reached)
			}
		}
		stopS()
	}
}

// pinRunCore is muxRunCore for a server that may listen on UDP only: it waits for the core to log
// that it started (the config's log level must be info) instead of dialing a TCP port.
func pinRunCore(t *testing.T, bin, file string, cfg map[string]any, port int, udp bool) (stop func(), logs func() string) {
	t.Helper()
	if !udp {
		return muxRunCore(t, bin, file, cfg, port)
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	out := &pinLog{}
	cmd := exec.CommandContext(ctx, bin, "run", "-c", file)
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	stop = func() { cancel(); <-exited }
	for deadline := time.Now().Add(10 * time.Second); !strings.Contains(out.String(), "sing-box started"); {
		select {
		case <-exited:
			t.Fatalf("sing-box exited on %s:\n%s\n%s", filepath.Base(file), out.String(), data)
		case <-time.After(100 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			stop()
			t.Fatalf("sing-box never started on %s:\n%s", filepath.Base(file), out.String())
		}
	}
	// The log line comes once the inbound is listening; the UDP socket answers from then on.
	if c, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
		_ = c.Close()
	}
	return stop, out.String
}

// pinLog is a bytes.Buffer safe to read while the core writes to it.
type pinLog struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *pinLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *pinLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func pinTail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func pinReadDER(t *testing.T, certFile string) []byte {
	t.Helper()
	b, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		t.Fatalf("%s holds no PEM block", certFile)
	}
	return blk.Bytes
}

// pinTestCertPEM is a fresh self-signed certificate as PEM, for the negative control.
func pinTestCertPEM(t *testing.T) (certPEM string, der []byte) {
	t.Helper()
	certFile, _ := muxTestCert(t, t.TempDir())
	der = pinReadDER(t, certFile)
	b, _ := os.ReadFile(certFile)
	return string(b), der
}
