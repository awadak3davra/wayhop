package model

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// sshTestKeys makes the key material at run time, so no key text sits in the tree: an Ed25519 key in
// the OpenSSH format (plain and encrypted), the same key as PKCS#8, and its public host key line.
func sshTestKeys(t *testing.T) (plain, encrypted, pkcs8, hostLine string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	plain = string(pem.EncodeToMemory(b))
	b, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("fixture-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	encrypted = string(pem.EncodeToMemory(b))
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8 = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	hostLine = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp)))
	return
}

func TestSSHEndpointValidation(t *testing.T) {
	plain, encrypted, pkcs8, host := sshTestKeys(t)
	hostData := strings.Fields(host)[1]
	ep := func(params map[string]any) *Endpoint {
		return &Endpoint{ID: "s", Enabled: true, Engine: EngineSingBox, Protocol: ProtoSSH, Server: "192.0.2.10", Port: 22, Params: params}
	}
	for _, tc := range []struct {
		name   string
		params map[string]any
		want   string // a substring of EndpointParamProblem, "" for none
	}{
		{"password only", map[string]any{"password": "pw"}, ""},
		{"no credential", map[string]any{"user": "root"}, "missing required password or private_key"},
		{"blank credential", map[string]any{"password": "  ", "private_key": " "}, "missing required password or private_key"},
		{"openssh key", map[string]any{"private_key": plain}, ""},
		{"key as sing-box lines", map[string]any{"private_key": strings.Split(strings.TrimSpace(plain), "\n")}, ""},
		{"crlf key", map[string]any{"private_key": strings.ReplaceAll(plain, "\n", "\r\n")}, ""},
		{"pkcs8 key", map[string]any{"private_key": pkcs8}, ""},
		{"encrypted key with passphrase", map[string]any{"private_key": encrypted, "private_key_passphrase": "x"}, ""},
		{"encrypted key without passphrase", map[string]any{"private_key": encrypted}, "encrypted: enter its passphrase"},
		{"passphrase on a plain key", map[string]any{"private_key": plain, "private_key_passphrase": "x"}, "not encrypted"},
		{"passphrase on pkcs8", map[string]any{"private_key": pkcs8, "private_key_passphrase": "x"}, "not encrypted"},
		{"passphrase without key (unused, as in sing-box)", map[string]any{"password": "pw", "private_key_passphrase": "x"}, ""},
		{"not pem", map[string]any{"private_key": "AAAA"}, "not a PEM private key"},
		{"unknown pem type", map[string]any{"private_key": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}}))}, "unsupported key type"},
		{"encrypted pkcs8", map[string]any{"private_key": string(pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{1}}))}, "ssh-keygen -p"},
		{"truncated openssh", map[string]any{"private_key": string(pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: []byte("openssh-key-v1\x00\x00\x00\x00\x09no")}))}, "not a valid OpenSSH"},
		{"host key", map[string]any{"password": "pw", "host_key": []any{host}}, ""},
		{"host key with comment", map[string]any{"password": "pw", "host_key": []string{host + " root@box"}}, ""},
		{"ssh-keyscan lines", map[string]any{"password": "pw", "host_key": "# 192.0.2.10:22 SSH-2.0-OpenSSH_9.6\n192.0.2.10 " + host + "\n\n"}, ""},
		{"host key without type", map[string]any{"password": "pw", "host_key": []any{hostData}}, "want \"<type> <base64>\""},
		{"host key not base64", map[string]any{"password": "pw", "host_key": []any{"ssh-ed25519 !!!"}}, "not base64"},
		{"host key type mismatch", map[string]any{"password": "pw", "host_key": []any{"ecdsa-sha2-nistp256 " + hostData}}, "not a whole ecdsa-sha2-nistp256 key"},
		// A key cut short when copied from a terminal: the type name at its head is intact, the rest
		// is not, and sing-box answers "no key found" at every Apply.
		{"host key cut short", map[string]any{"password": "pw", "host_key": []any{"ssh-ed25519 " + hostData[:40]}}, "not a whole ssh-ed25519 key"},
		{"user with a line break", map[string]any{"password": "pw", "user": "us\ner"}, "user must not contain"},
		{"user with a tab", map[string]any{"password": "pw", "user": "us\ter"}, "user must not contain"},
		{"user with DEL", map[string]any{"password": "pw", "user": "us\x7fer"}, "user must not contain"},
		{"unicode user", map[string]any{"password": "pw", "user": "пользователь"}, ""},
		{"host key unknown type", map[string]any{"password": "pw", "host_key": []any{"x509v3-sign-rsa " + hostData}}, "unsupported key type"},
		{"host key not a list", map[string]any{"password": "pw", "host_key": 7}, "want a list of strings"},
		{"client version", map[string]any{"password": "pw", "client_version": "SSH-2.0-OpenSSH_9.6"}, ""},
		{"bad client version", map[string]any{"password": "pw", "client_version": "OpenSSH_9.6"}, "SSH-2.0 identification"},
		{"client version with newline", map[string]any{"password": "pw", "client_version": "SSH-2.0-x\r\nSSH-2.0-y"}, "SSH-2.0 identification"},
		{"cipher list", map[string]any{"password": "pw", "cipher": []any{"aes128-ctr"}}, ""},
		{"cipher not a list", map[string]any{"password": "pw", "cipher": map[string]any{}}, "cipher: want a list"},
	} {
		got := EndpointParamProblem(ep(tc.params))
		if (tc.want == "") != (got == "") || !strings.Contains(got, tc.want) {
			t.Errorf("%s: problem = %q, want %q", tc.name, got, tc.want)
		}
		for _, secret := range []string{plain, encrypted, pkcs8, "fixture-passphrase"} {
			if got != "" && strings.Contains(got, strings.TrimSpace(secret)) {
				t.Errorf("%s: the problem quotes a secret: %q", tc.name, got)
			}
		}
	}
	// A disabled draft is not judged; an enabled one fails Validate with the same words.
	p := &Profile{Endpoints: []Endpoint{*ep(map[string]any{"user": "root"})}}
	p.Endpoints[0].Enabled = false
	if err := p.Validate(); err != nil {
		t.Fatalf("disabled draft: %v", err)
	}
	p.Endpoints[0].Enabled = true
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "password or private_key") {
		t.Fatalf("enabled without a credential: %v", err)
	}
}

// The structural key check agrees with golang.org/x/crypto/ssh, which sing-box parses the key with:
// whatever it calls loadable, ParsePrivateKey(WithPassphrase) loads, and the other way round.
func TestSSHPrivateKeyCheckMatchesXCrypto(t *testing.T) {
	plain, encrypted, pkcs8, _ := sshTestKeys(t)
	legacyEncrypted := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY",
		Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-128-CBC,00000000000000000000000000000001"},
		Bytes:   make([]byte, 32)}))
	for _, key := range []string{plain, encrypted, pkcs8, legacyEncrypted} {
		for _, pass := range []string{"", "fixture-passphrase"} {
			var err error
			if pass == "" {
				_, err = ssh.ParsePrivateKey([]byte(key))
			} else {
				_, err = ssh.ParsePrivateKeyWithPassphrase([]byte(key), []byte(pass))
			}
			problem := sshPrivateKeyProblem(key, pass != "")
			// The legacy block's body is not a real key, so x/crypto fails on it with a passphrase
			// too; the structural check can only say the passphrase is there, which is all it claims.
			if key == legacyEncrypted && pass != "" {
				if problem != "" {
					t.Errorf("legacy encrypted with a passphrase: %q", problem)
				}
				continue
			}
			if (err == nil) != (problem == "") {
				t.Errorf("key %q... passphrase %v: x/crypto err %v, check %q", key[:20], pass != "", err, problem)
			}
		}
	}
}

// The host keys sing-box gets parse with x/crypto's ParseAuthorizedKey as the same key, and the
// offered algorithms follow the pinned types.
func TestSSHHostKeysAndAlgorithms(t *testing.T) {
	_, _, _, host := sshTestKeys(t)
	want, _, _, _, err := ssh.ParseAuthorizedKey([]byte(host))
	if err != nil {
		t.Fatal(err)
	}
	e := &Endpoint{Params: map[string]any{"host_key": "192.0.2.10 " + host + " comment\n# banner\n"}}
	keys, err := SSHHostKeys(e)
	if err != nil || len(keys) != 1 {
		t.Fatalf("keys = %v, %v", keys, err)
	}
	got, _, _, _, err := ssh.ParseAuthorizedKey([]byte(keys[0].String()))
	if err != nil || string(got.Marshal()) != string(want.Marshal()) {
		t.Fatalf("canonical %q does not parse as the pinned key: %v", keys[0], err)
	}
	if a := SSHHostKeyAlgorithms(keys); strings.Join(a, ",") != "ssh-ed25519" {
		t.Errorf("algorithms = %v", a)
	}
	rsa := SSHHostKey{Type: "ssh-rsa"}
	ec := SSHHostKey{Type: "ecdsa-sha2-nistp256"}
	if a := SSHHostKeyAlgorithms([]SSHHostKey{keys[0], rsa, ec}); strings.Join(a, ",") !=
		"ecdsa-sha2-nistp256,rsa-sha2-256,rsa-sha2-512,ssh-rsa,ssh-ed25519" {
		t.Errorf("algorithms = %v", a)
	}
	if a := SSHHostKeyAlgorithms(nil); a != nil {
		t.Errorf("no keys: %v", a)
	}
	// A blob whose length prefix overruns it is refused, not read past its end.
	bad := "ssh-ed25519 " + base64.StdEncoding.EncodeToString([]byte{0, 0, 0, 0x7f, 's'})
	if _, err := ParseSSHHostKey(bad); err == nil {
		t.Error("an overrunning blob was accepted")
	}
}

// ParseSSHHostKey accepts a host key line exactly when x/crypto's ParseAuthorizedKey, which sing-box
// reads host_key with, does: for a whole key of every supported type, for every prefix of it (a key
// cut short in a terminal, down to the type name alone), with bytes appended, and for the field
// values x/crypto itself refuses. One deliberate difference is checked at the end.
func TestSSHHostKeyBlobMatchesXCrypto(t *testing.T) {
	type wireRSA struct {
		Name string
		E, N *big.Int
	}
	type wireDSA struct {
		Name       string
		P, Q, G, Y *big.Int
	}
	type wireEC struct {
		Name, Curve string
		Point       []byte
	}
	type wireEd struct {
		Name string
		Key  []byte
	}
	pub := func(k any) []byte {
		sp, err := ssh.NewPublicKey(k)
		if err != nil {
			t.Fatal(err)
		}
		return sp.Marshal()
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	type sample struct {
		name, typ string
		blob      []byte
	}
	samples := []sample{{"ed25519", "ssh-ed25519", pub(edPub)}}
	for _, c := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		k, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		b := pub(&k.PublicKey)
		samples = append(samples, sample{c.Params().Name, mustParsePub(t, b).Type(), b})
	}
	// RSA and DSA keys are not generated (slow, and x/crypto checks no more than their layout and the
	// exponent and prime size): the numbers only need the right sizes.
	n := new(big.Int).Lsh(big.NewInt(1), 2047)
	n.Add(n, big.NewInt(1))
	p1024 := new(big.Int).Lsh(big.NewInt(1), 1023)
	p1024.Add(p1024, big.NewInt(1))
	p2048 := new(big.Int).Lsh(big.NewInt(1), 2047)
	samples = append(samples,
		sample{"rsa", "ssh-rsa", pub(&rsa.PublicKey{N: n, E: 65537})},
		sample{"rsa e=3", "ssh-rsa", ssh.Marshal(wireRSA{"ssh-rsa", big.NewInt(3), n})},
		sample{"rsa e even", "ssh-rsa", ssh.Marshal(wireRSA{"ssh-rsa", big.NewInt(65536), n})},
		sample{"rsa e=1", "ssh-rsa", ssh.Marshal(wireRSA{"ssh-rsa", big.NewInt(1), n})},
		sample{"rsa e 25 bits", "ssh-rsa", ssh.Marshal(wireRSA{"ssh-rsa", big.NewInt(1<<24 + 1), n})},
		sample{"rsa e negative", "ssh-rsa", ssh.Marshal(wireRSA{"ssh-rsa", big.NewInt(-65537), n})},
		sample{"dsa", "ssh-dss", ssh.Marshal(wireDSA{"ssh-dss", p1024, big.NewInt(7), big.NewInt(2), big.NewInt(5)})},
		sample{"dsa 2048", "ssh-dss", ssh.Marshal(wireDSA{"ssh-dss", p2048, big.NewInt(7), big.NewInt(2), big.NewInt(5)})},
		sample{"ed25519 31 bytes", "ssh-ed25519", ssh.Marshal(wireEd{"ssh-ed25519", make([]byte, 31)})},
		sample{"ed25519 33 bytes", "ssh-ed25519", ssh.Marshal(wireEd{"ssh-ed25519", make([]byte, 33)})},
	)
	// ECDSA points that are not on the curve, compressed, or the point at infinity.
	ec := samples[1]
	var w wireEC
	if err := ssh.Unmarshal(ec.blob, &w); err != nil {
		t.Fatal(err)
	}
	off := append([]byte(nil), w.Point...)
	off[len(off)-1] ^= 1
	samples = append(samples,
		sample{"p256 off the curve", ec.typ, ssh.Marshal(wireEC{ec.typ, "nistp256", off})},
		sample{"p256 compressed", ec.typ, ssh.Marshal(wireEC{ec.typ, "nistp256", append([]byte{2}, w.Point[1:33]...)})},
		sample{"p256 infinity", ec.typ, ssh.Marshal(wireEC{ec.typ, "nistp256", []byte{0}})},
		sample{"unknown curve", ec.typ, ssh.Marshal(wireEC{ec.typ, "nistp999", w.Point})},
	)

	agree := func(label, typ string, blob []byte) {
		t.Helper()
		line := typ + " " + base64.StdEncoding.EncodeToString(blob)
		_, _, _, _, xerr := ssh.ParseAuthorizedKey([]byte(line))
		_, err := ParseSSHHostKey(line)
		if (xerr == nil) != (err == nil) {
			t.Errorf("%s: x/crypto err %v, ParseSSHHostKey err %v", label, xerr, err)
		}
	}
	valid := 0
	for _, s := range samples {
		agree(s.name, s.typ, s.blob)
		if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s.typ + " " + base64.StdEncoding.EncodeToString(s.blob))); err != nil {
			continue
		}
		valid++
		for i := 0; i < len(s.blob); i++ {
			agree(s.name+" cut to "+strconv.Itoa(i)+" bytes", s.typ, s.blob[:i])
		}
		agree(s.name+" plus a byte", s.typ, append(append([]byte(nil), s.blob...), 0))
		agree(s.name+" plus an empty string", s.typ, append(append([]byte(nil), s.blob...), 0, 0, 0, 0))
	}
	// ed25519, three curves, rsa, rsa e=3 and dsa are whole keys; the rest must be refusals.
	if valid != 7 {
		t.Errorf("%d samples are whole keys to x/crypto, want 7", valid)
	}
	// The ed25519 key is exactly 51 bytes: the length and name, the length and 32 key bytes.
	if len(samples[0].blob) != 51 {
		t.Errorf("ed25519 blob is %d bytes", len(samples[0].blob))
	}

	// Stricter than x/crypto: an ECDSA blob whose curve is not its type's reads there as a key of the
	// other curve, which the pinned type would misdescribe; it is refused.
	k384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var w384 wireEC
	if err := ssh.Unmarshal(pub(&k384.PublicKey), &w384); err != nil {
		t.Fatal(err)
	}
	mixed := "ecdsa-sha2-nistp256 " + base64.StdEncoding.EncodeToString(ssh.Marshal(wireEC{"ecdsa-sha2-nistp256", "nistp384", w384.Point}))
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(mixed)); err != nil {
		t.Logf("x/crypto now refuses a mixed-curve key too: %v", err)
	}
	if _, err := ParseSSHHostKey(mixed); err == nil {
		t.Error("an ecdsa-sha2-nistp256 key holding a P-384 point was accepted")
	}
}

func mustParsePub(t *testing.T, b []byte) ssh.PublicKey {
	t.Helper()
	k, err := ssh.ParsePublicKey(b)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
