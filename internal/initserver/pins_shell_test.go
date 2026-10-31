package initserver

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"

	"wayhop/internal/importer"
	"wayhop/internal/testsh"
)

// pinShell returns a POSIX shell and confirms openssl is on PATH, which the installer's pin snippet
// needs (it installs openssl on the server when absent; a test does not).
func pinShell(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not on PATH — the installer's pin snippet cannot run here")
	}
	sh, err := testsh.Find()
	if err != nil {
		t.Fatalf("openssl is here but no POSIX shell: %v", err)
	}
	return sh
}

// runPinScript runs body under sh the way the installer does (set -e, umask 077, its log helper)
// with SBD at dir, and returns stdout. Git for Windows' sh rewrites arguments that look like paths
// ("/CN=wayhop.local") before a native openssl sees them, unless told not to.
func runPinScript(t *testing.T, sh, dir, body string) string {
	t.Helper()
	script := "set -e\numask 077\nlog() { echo \"[wayhop-init] $*\"; }\nSBD='" + filepath.ToSlash(dir) + "'\n" + body
	cmd := exec.Command(sh)
	cmd.Stdin = strings.NewReader(script)
	cmd.Env = append(os.Environ(), "MSYS_NO_PATHCONV=1", "MSYS2_ARG_CONV_EXCL=*")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("sh: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}
	return stdout.String()
}

// snippetPins runs the certificate fragment and the pin snippet exactly as the installer embeds them,
// after prelude, and returns the two pins they computed.
func snippetPins(t *testing.T, sh, dir, prelude string) (cert, key, out string) {
	t.Helper()
	out = runPinScript(t, sh, dir, prelude+scriptTLSCert+scriptTLSPins+"printf 'CERT=%s\\nKEY=%s\\n' \"$WR_PIN_CERT\" \"$WR_PIN_KEY\"\n")
	for _, ln := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(ln, "CERT="); ok {
			cert = v
		}
		if v, ok := strings.CutPrefix(ln, "KEY="); ok {
			key = v
		}
	}
	return cert, key, out
}

// goPins hashes dir/wr-tls.crt with Go's crypto: the whole certificate's DER as hex, and its public
// key as sing-box hashes it (x509.MarshalPKIXPublicKey, common/tls VerifyPublicKeySHA256) as base64.
func goPins(t *testing.T, dir string) (cert, key string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "wr-tls.crt"))
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		t.Fatal("wr-tls.crt holds no PEM block")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(c.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(spki, c.RawSubjectPublicKeyInfo) {
		t.Fatal("re-encoded public key differs from the certificate's own SubjectPublicKeyInfo")
	}
	cs, ks := sha256.Sum256(blk.Bytes), sha256.Sum256(spki)
	return hex.EncodeToString(cs[:]), base64.StdEncoding.EncodeToString(ks[:])
}

// The installer's pin snippet, run under sh with the real openssl against the certificate the
// installer's own fragment generates, gives the same pins as Go's crypto: on the first run, on a
// re-run that reuses the certificate, and with new pins after the certificate is regenerated. It
// reads the hash from every dgst output format, falls back to `openssl rsa` without pkey, and prints
// no pin, never a wrong one, when a step fails.
func TestTLSPinSnippetMatchesGo(t *testing.T) {
	sh := pinShell(t)
	dir := t.TempDir()

	cert1, key1, _ := snippetPins(t, sh, dir, "")
	wantCert, wantKey := goPins(t, dir)
	if cert1 != wantCert || key1 != wantKey {
		t.Fatalf("first run: snippet cert %q key %q, Go cert %q key %q", cert1, key1, wantCert, wantKey)
	}
	crt1, _ := os.ReadFile(filepath.Join(dir, "wr-tls.crt"))

	// A re-run keeps the certificate, and with it the pins.
	if c, k, _ := snippetPins(t, sh, dir, ""); c != cert1 || k != key1 {
		t.Errorf("re-run changed the pins: %q %q", c, k)
	}
	if crt, _ := os.ReadFile(filepath.Join(dir, "wr-tls.crt")); !bytes.Equal(crt, crt1) {
		t.Error("re-run regenerated a certificate that was there")
	}

	// Files deleted: the certificate is generated again and the pins are its own, not the old ones.
	for _, gone := range [][]string{{"wr-tls.crt", "wr-tls.key"}, {"wr-tls.key"}, {"wr-tls.crt"}} {
		for _, f := range gone {
			if err := os.Remove(filepath.Join(dir, f)); err != nil {
				t.Fatal(err)
			}
		}
		c, k, _ := snippetPins(t, sh, dir, "")
		gc, gk := goPins(t, dir)
		if c != gc || k != gk || c == cert1 || k == key1 {
			t.Errorf("after deleting %v: snippet %q %q, Go %q %q, first run %q %q", gone, c, k, gc, gk, cert1, key1)
		}
		cert1, key1 = c, k
	}
	wantCert, wantKey = cert1, key1

	// dgst's text output across openssl releases, upper-case hex included. The wrapper is a shell
	// function, which sh finds before the openssl on PATH; `command openssl` is the real one.
	for _, format := range []string{"(stdin)= %s", "SHA2-256(stdin)= %s", "SHA256(stdin)= %s", "%s *stdin", "%s", "(stdin)=%s", "SHA256(stdin)= %s | upper"} {
		upper := strings.HasSuffix(format, " | upper")
		f := strings.TrimSuffix(format, " | upper")
		conv := ""
		if upper {
			conv = " | tr a-f A-F"
		}
		wrapper := `openssl() {
  if [ "$1" = dgst ] && [ "$3" != -binary ]; then
    __h=$(command openssl dgst -sha256 -r | cut -d' ' -f1` + conv + `)
    printf '` + f + `\n' "$__h"
  else
    command openssl "$@"
  fi
}
`
		if c, k, _ := snippetPins(t, sh, dir, wrapper); c != wantCert || k != wantKey {
			t.Errorf("dgst prints %q: cert %q key %q, want %q %q", format, c, k, wantCert, wantKey)
		}
	}

	// No pkey (openssl before 1.0.0): rsa converts the same key.
	noPkey := `openssl() {
  case "$1" in pkey) echo "openssl:Error: 'pkey' is an invalid command." >&2; return 1;; esac
  command openssl "$@"
}
`
	if c, k, _ := snippetPins(t, sh, dir, noPkey); c != wantCert || k != wantKey {
		t.Errorf("without pkey: cert %q key %q, want %q %q", c, k, wantCert, wantKey)
	}

	// Neither converts the key: no public-key pin, rather than the hash of empty input, and a log line.
	neither := `openssl() {
  case "$1" in pkey|rsa) echo "openssl:Error: '$1' is an invalid command." >&2; return 1;; esac
  command openssl "$@"
}
`
	if c, k, out := snippetPins(t, sh, dir, neither); c != wantCert || k != "" || !strings.Contains(out, "could not compute every pin") {
		t.Errorf("without pkey and rsa: cert %q key %q, want %q and none\n%s", c, k, wantCert, out)
	}

	// A conversion that "succeeds" with no output feeds dgst nothing: the hash of empty input is a
	// well-formed pin of no certificate, and is refused by value.
	emptyDER := `openssl() {
  case "$*" in *"-outform der"*) cat >/dev/null; return 0;; esac
  command openssl "$@"
}
`
	if c, k, out := snippetPins(t, sh, dir, emptyDER); c != "" || k != "" || !strings.Contains(out, "could not compute every pin") {
		t.Errorf("conversions printing nothing: cert %q key %q, want none\n%s", c, k, out)
	}

	// dgst failing, or printing no hash at all: no pins.
	noDgst := `openssl() {
  case "$1" in dgst) echo "openssl:Error: 'dgst' is an invalid command." >&2; return 1;; esac
  command openssl "$@"
}
`
	if c, k, _ := snippetPins(t, sh, dir, noDgst); c != "" || k != "" {
		t.Errorf("without dgst: cert %q key %q, want none", c, k)
	}

	// A certificate openssl cannot read: no pins, rather than the hashes of empty input.
	bad := t.TempDir()
	for _, f := range []string{"wr-tls.crt", "wr-tls.key"} {
		if err := os.WriteFile(filepath.Join(bad, f), []byte("not a certificate\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	empty := sha256.Sum256(nil)
	if c, k, _ := snippetPins(t, sh, bad, ""); c != "" || k != "" {
		t.Errorf("unreadable certificate: cert %q key %q (the hash of nothing is %x)", c, k, empty)
	}
}

// Two provisioning jobs against one server can overlap (a double start, two routers set up against
// one VPS). Several shells running the installer's certificate and pin fragments at once, in a loop,
// against one certificate, must each print that certificate's pins every time: never another value,
// the hash of empty input included, and never none. The snippet once staged the DER in a fixed temp
// file, which a parallel run deleted and rewrote under it (QA-138 review: wrong pins in ~1 run of 4).
func TestTLSPinSnippetConcurrentRuns(t *testing.T) {
	sh := pinShell(t)
	dir := t.TempDir()
	snippetPins(t, sh, dir, "") // the certificate, made once as on a server that has it
	wantCert, wantKey := goPins(t, dir)
	const workers, rounds = 4, 15
	loop := scriptTLSCert + scriptTLSPins + `__i=0
while [ "$__i" -lt ` + strconv.Itoa(rounds) + ` ]; do
  wr_tls_pins
  echo "PINS $WR_PIN_CERT $WR_PIN_KEY"
  __i=$((__i + 1))
done
`
	outs := make([]string, workers)
	var wg sync.WaitGroup
	for w := range outs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			outs[w] = runPinScriptQuiet(sh, dir, loop)
		}()
	}
	wg.Wait()
	bad, n := 0, 0
	for _, out := range outs {
		for _, ln := range strings.Split(out, "\n") {
			if !strings.HasPrefix(ln, "PINS") {
				continue
			}
			n++
			if ln != "PINS "+wantCert+" "+wantKey {
				bad++
				if bad <= 3 {
					t.Errorf("a parallel run printed %q, want the certificate's own pins", ln)
				}
			}
		}
	}
	if n != workers*rounds || bad > 0 {
		t.Errorf("%d of %d parallel runs printed wrong or no pins (%d runs reported)", bad, workers*rounds, n)
	}
}

// runPinScriptQuiet is runPinScript for a goroutine: it returns what the shell printed, an error
// included, instead of failing the test from outside its goroutine.
func runPinScriptQuiet(sh, dir, body string) string {
	cmd := exec.Command(sh)
	cmd.Stdin = strings.NewReader("set -e\numask 077\nlog() { echo \"[wayhop-init] $*\"; }\nSBD='" + filepath.ToSlash(dir) + "'\n" + body)
	cmd.Env = append(os.Environ(), "MSYS_NO_PATHCONV=1", "MSYS2_ARG_CONV_EXCL=*")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out) + "\nsh: " + err.Error()
	}
	return string(out)
}

// The empty-input hashes the snippet refuses are what Go computes for nothing.
func TestEmptyInputPinConstants(t *testing.T) {
	sum := sha256.Sum256(nil)
	if emptySHA256Hex != hex.EncodeToString(sum[:]) || emptySHA256B64 != base64.StdEncoding.EncodeToString(sum[:]) {
		t.Fatalf("empty-input constants %q %q are not the SHA-256 of nothing", emptySHA256Hex, emptySHA256B64)
	}
	if !strings.Contains(scriptTLSPins, `"`+emptySHA256Hex+`")`) || !strings.Contains(scriptTLSPins, `"`+emptySHA256B64+`")`) {
		t.Error("the pin snippet does not refuse both empty-input hashes")
	}
}

// fragmentTail is what a TLS fragment runs after its server is up: the link built and the lines
// printed, exactly as BuildScript emits them.
func fragmentTail(t *testing.T, proto string) string {
	t.Helper()
	s := BuildScript([]string{proto}, "198.51.100.7")
	const unit = "systemctl restart sing-box 2>/dev/null || true\n"
	i, j := strings.LastIndex(s, unit), strings.LastIndex(s, "\nlog \"done\"")
	if i < 0 || j < i {
		t.Fatalf("%s: the fragment no longer ends with the service restart and the link", proto)
	}
	return s[i+len(unit) : j]
}

// fragmentVars are the invented identities a TLS fragment would have generated on the server.
const fragmentVars = `PUBLIC_IP=198.51.100.7
VMUUID=11111111-2222-3333-4444-555555555555; VMPATH=/wayhop
TJPASS='Tj+pass/word='; HY2PASS='Hy+pass/word='; HY2OBFS='Ob+fs/pass='
TUUUID=11111111-2222-3333-4444-666666666666; TUPASS='Tu+pass/word='; ATPASS='At+pass/word='
`

// Each TLS fragment's printed output, run under sh after the real certificate and pin fragments,
// imports through ExtractTagged and the importer into a connection pinned by both of the server's
// pins as Go computes them, insecure=1 still in the link for other clients. When the pins cannot be
// computed, the same output imports with no pins and insecure, as before.
func TestTLSFragmentsPrintPinnedLinks(t *testing.T) {
	sh := pinShell(t)
	dir := t.TempDir()
	for _, proto := range []string{ProtoVMess, ProtoTrojan, ProtoHysteria2, ProtoTUIC, ProtoAnyTLS} {
		out := runPinScript(t, sh, dir, fragmentVars+scriptTLSCert+scriptTLSPins+fragmentTail(t, proto))
		wantCert, wantKey := goPins(t, dir)
		tagged := ExtractTagged(out)
		if len(tagged) != 1 || tagged[0].Proto != proto || tagged[0].PubKeyPin != wantKey || tagged[0].Dropped != nil {
			t.Fatalf("%s: tagged %+v, want the public-key pin %q\n%s", proto, tagged, wantKey, out)
		}
		tc := tagged[0]
		link := tc.Config
		if body, ok := strings.CutPrefix(link, "vmess://"); ok {
			raw, _ := base64.StdEncoding.DecodeString(body)
			link = string(raw)
		}
		if !strings.Contains(link, "&insecure=1&") && !strings.Contains(link, `"allowInsecure":"1"`) {
			t.Errorf("%s: the link lost insecure=1: %q", proto, link)
		}
		ep, err := importer.Parse(tc.Config)
		if err != nil {
			t.Fatalf("%s: %v\n%s", proto, err, tc.Config)
		}
		tc.ApplyPins(ep)
		if !reflect.DeepEqual(ep.TLS.PinCertSHA256, []string{wantCert}) || !reflect.DeepEqual(ep.TLS.PinPubKeySHA256, []string{wantKey}) ||
			!ep.TLS.Insecure || ep.TLS.SNI != "wayhop.local" || ep.Server != "198.51.100.7" {
			t.Errorf("%s: imported %s:%d tls %+v, want cert %q key %q", proto, ep.Server, ep.Port, ep.TLS, wantCert, wantKey)
		}
		if pw, _ := ep.Params["password"].(string); proto != ProtoVMess && !strings.Contains(pw, "+pass/word=") {
			t.Errorf("%s: password %q did not survive the link", proto, pw)
		}
	}

	// No certificate openssl can read: no pins printed, the link as before pins.
	bad := t.TempDir()
	for _, f := range []string{"wr-tls.crt", "wr-tls.key"} {
		if err := os.WriteFile(filepath.Join(bad, f), []byte("not a certificate\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, proto := range []string{ProtoVMess, ProtoTrojan, ProtoHysteria2, ProtoTUIC, ProtoAnyTLS} {
		out := runPinScript(t, sh, bad, fragmentVars+scriptTLSCert+scriptTLSPins+fragmentTail(t, proto))
		tagged := ExtractTagged(out)
		if len(tagged) != 1 || tagged[0].PubKeyPin != "" || strings.Contains(out, PubKeyPinMarker) {
			t.Fatalf("%s: %+v\n%s", proto, tagged, out)
		}
		ep, err := importer.Parse(tagged[0].Config)
		if err != nil {
			t.Fatalf("%s: %v", proto, err)
		}
		if len(ep.TLS.PinCertSHA256) != 0 || !ep.TLS.Insecure {
			t.Errorf("%s: %+v", proto, ep.TLS)
		}
	}
}
