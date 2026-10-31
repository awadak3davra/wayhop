package generator

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wayhop/internal/model"
)

// TestMultiplexSingBoxRuntime runs the core: a sing-box server on loopback and a client whose outbound
// is the one WayHop's generator renders (OutboundFor), then fetches a page through them. A multiplexed
// client reaches a server whose inbound has multiplex on, over each capable protocol and transport and
// with Vision; the same client fails, and fails fast, against a server without it, which shows the
// connection really went through sing-mux; a client without multiplex still reaches a server with it
// on (what the Set up Server inbounds rely on); and a server that requires padding refuses a client
// without it. TCP Brutal is left out: it needs the tcp-brutal kernel module on the server.
func TestMultiplexSingBoxRuntime(t *testing.T) {
	bin := os.Getenv("WR_SINGBOX")
	if bin == "" {
		t.Skip("WR_SINGBOX not set — set it to a sing-box binary to run the core")
	}
	ver := strings.SplitN(singboxVersionOf(t, bin), "\n", 2)[0]
	dir := t.TempDir()
	cert, key := muxTestCert(t, dir)
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "mux-ok") }))
	defer page.Close()

	const uuid = "00000000-0000-4000-8000-000000000021"
	ssKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x21}, 32))
	tlsIn := map[string]any{"enabled": true, "server_name": "example.com", "certificate_path": cert, "key_path": key}
	tlsOut := &model.TLS{Enabled: true, Type: "tls", SNI: "example.com", Insecure: true}
	on := map[string]any{"enabled": true}

	type side struct {
		inbound func(mux map[string]any) map[string]any
		ep      func(m *model.Multiplex) model.Endpoint
	}
	ep := func(p model.Protocol, params map[string]any, tl *model.TLS, tr *model.Transport) func(*model.Multiplex) model.Endpoint {
		return func(m *model.Multiplex) model.Endpoint {
			pp := map[string]any{}
			for k, v := range params {
				pp[k] = v
			}
			return model.Endpoint{ID: "out", Name: "out", Engine: model.EngineSingBox, Protocol: p, Server: "127.0.0.1",
				Enabled: true, Params: pp, TLS: tl, Transport: tr, Multiplex: m}
		}
	}
	in := func(typ string, extra map[string]any) func(map[string]any) map[string]any {
		return func(mux map[string]any) map[string]any {
			ib := map[string]any{"type": typ, "tag": "in", "listen": "127.0.0.1"}
			for k, v := range extra {
				ib[k] = v
			}
			if mux != nil {
				ib["multiplex"] = mux
			}
			return ib
		}
	}
	trojan := side{in("trojan", map[string]any{"users": []any{map[string]any{"password": "pw"}}, "tls": tlsIn}),
		ep(model.ProtoTrojan, map[string]any{"password": "pw"}, tlsOut, nil)}
	vision := side{in("vless", map[string]any{"users": []any{map[string]any{"uuid": uuid, "flow": "xtls-rprx-vision"}}, "tls": tlsIn}),
		ep(model.ProtoVLESS, map[string]any{"uuid": uuid, "flow": "xtls-rprx-vision"}, tlsOut, nil)}
	vmessWS := side{in("vmess", map[string]any{"users": []any{map[string]any{"uuid": uuid}}, "tls": tlsIn,
		"transport": map[string]any{"type": "ws", "path": "/m"}}),
		ep(model.ProtoVMess, map[string]any{"uuid": uuid, "security": "auto"}, tlsOut, &model.Transport{Type: "ws", Path: "/m"})}
	ss := side{in("shadowsocks", map[string]any{"method": "2022-blake3-aes-256-gcm", "password": ssKey}),
		ep(model.ProtoShadowsocks, map[string]any{"method": "2022-blake3-aes-256-gcm", "password": ssKey}, nil, nil)}

	cases := []struct {
		name    string
		s       side
		server  map[string]any // the inbound's multiplex block; nil = none
		client  *model.Multiplex
		reaches bool
	}{
		{"trojan h2mux pool", trojan, on, &model.Multiplex{Enabled: true, MaxConnections: 4, MinStreams: 4}, true},
		{"vless vision smux", vision, on, &model.Multiplex{Enabled: true, Protocol: "smux"}, true},
		{"vmess ws yamux", vmessWS, on, &model.Multiplex{Enabled: true, Protocol: "yamux", MaxStreams: 8}, true},
		{"shadowsocks h2mux", ss, on, &model.Multiplex{Enabled: true, Protocol: "h2mux", MaxConnections: 2}, true},
		{"server without multiplex", trojan, nil, &model.Multiplex{Enabled: true}, false},
		{"client without multiplex", trojan, on, nil, true},
		{"padding both sides", trojan, map[string]any{"enabled": true, "padding": true}, &model.Multiplex{Enabled: true, Padding: true}, true},
		{"server requires padding", trojan, map[string]any{"enabled": true, "padding": true}, &model.Multiplex{Enabled: true}, false},
	}
	for _, c := range cases {
		e := c.s.ep(c.client)
		srvPort, cliPort := muxFreePort(t), muxFreePort(t)
		e.Port = srvPort
		ob, err := OutboundFor(&e)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if _, has := ob["multiplex"]; has != (c.client != nil) {
			t.Fatalf("%s: the generated outbound's multiplex is %v", c.name, ob["multiplex"])
		}
		ib := c.s.inbound(c.server)
		ib["listen_port"] = srvPort
		server := map[string]any{"log": map[string]any{"level": "warn"}, "inbounds": []any{ib},
			"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}}
		client := map[string]any{"log": map[string]any{"level": "warn"},
			"inbounds":  []any{map[string]any{"type": "mixed", "tag": "mixed", "listen": "127.0.0.1", "listen_port": cliPort}},
			"outbounds": []any{ob}}
		stopS, logS := muxRunCore(t, bin, filepath.Join(dir, fmt.Sprintf("s%d.json", srvPort)), server, srvPort)
		stopC, logC := muxRunCore(t, bin, filepath.Join(dir, fmt.Sprintf("c%d.json", cliPort)), client, cliPort)
		start := time.Now()
		body, ferr := muxFetch(cliPort, page.URL)
		took := time.Since(start)
		stopC()
		stopS()
		switch {
		case c.reaches && (ferr != nil || body != "mux-ok"):
			t.Errorf("%s, %s: fetch = %q, %v\nclient:\n%s\nserver:\n%s", ver, c.name, body, ferr, logC(), logS())
		case !c.reaches && ferr == nil && body == "mux-ok":
			t.Errorf("%s, %s: the fetch got through, so the connection did not go through sing-mux", ver, c.name)
		case !c.reaches && took > 5*time.Second:
			t.Errorf("%s, %s: refused only after %v; it should fail at once", ver, c.name, took)
		default:
			t.Logf("%s, %s: reached=%v in %v", ver, c.name, ferr == nil, took.Round(time.Millisecond))
		}
	}
}

// muxFetch fetches url through the client's mixed inbound, as an HTTP proxy.
func muxFetch(port int, target string) (string, error) {
	proxy, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	cl := &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}}
	resp, err := cl.Get(target)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return string(b), fmt.Errorf("status %s", resp.Status)
	}
	return string(b), err
}

// muxRunCore writes cfg, runs the core on it and waits until port answers. stop kills it; logs is what
// it printed.
func muxRunCore(t *testing.T, bin, file string, cfg map[string]any, port int) (stop func(), logs func() string) {
	t.Helper()
	data, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, "run", "-c", file)
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	stop = func() { cancel(); <-exited }
	for deadline := time.Now().Add(10 * time.Second); ; {
		if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond); err == nil {
			_ = c.Close()
			break
		}
		select {
		case <-exited:
			t.Fatalf("sing-box exited on %s:\n%s\n%s", filepath.Base(file), out.String(), data)
		case <-time.After(100 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			stop()
			t.Fatalf("sing-box never listened on %d:\n%s", port, out.String())
		}
	}
	return stop, func() string { return out.String() }
}

func muxFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// muxTestCert writes a self-signed certificate for example.com and its key, PEM.
func muxTestCert(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(21), Subject: pkix.Name{CommonName: "example.com"},
		DNSNames: []string{"example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}
