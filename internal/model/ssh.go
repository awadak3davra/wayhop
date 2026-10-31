package model

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"unicode"
)

// An SSH exit (ProtoSSH) is sing-box's ssh outbound: every connection routed to it is a TCP
// forwarding request on one SSH session to the server, so any VPS that lets its user log in and
// forward ports is an exit with nothing installed on it. Params:
//
//	user                    the login; sing-box uses root when it is empty
//	password                password authentication
//	private_key             a PEM private key (OpenSSH, PKCS#1, PKCS#8, SEC1 or DSA), the text itself
//	private_key_passphrase  the key's passphrase, when it is encrypted
//	host_key                the server's host keys, "<type> <base64>" each (a list, or one per line);
//	                        empty means any key is accepted
//	client_version          the identification string sent to the server ("SSH-2.0-..."); sing-box
//	                        picks a random OpenSSH 7.x/8.x one when it is empty
//	cipher, mac,            the sing-box 1.14 restrictions of the negotiated algorithms (lists); no
//	kex_algorithm           form field sets them, an import or the API does
//
// sing-box parses the key and the host keys when it builds the outbound, which `sing-box check`
// does too: one malformed value fails the shared config and with it every exit. Validate therefore
// refuses what sing-box would refuse (sshParamProblem) before an Apply gets that far.

// sshHostKeyTypes are the host key types golang.org/x/crypto/ssh (which sing-box's ssh outbound
// uses) can verify a server with: its defaultHostKeyAlgos, certificates aside. A security-key type
// (sk-...) is a user key, never a host key, and is refused rather than pinned to no effect.
var sshHostKeyTypes = map[string]bool{
	"ssh-ed25519": true, "ecdsa-sha2-nistp256": true, "ecdsa-sha2-nistp384": true,
	"ecdsa-sha2-nistp521": true, "ssh-rsa": true, "ssh-dss": true,
}

// SSHHostKey is one pinned host key.
type SSHHostKey struct {
	Type string // e.g. "ssh-ed25519"
	Data string // the base64 key blob
}

// String is the key as sing-box's host_key wants it, which is how ssh-keyscan prints it minus the
// host name.
func (k SSHHostKey) String() string { return k.Type + " " + k.Data }

// ParseSSHHostKey reads one host key line: "<type> <base64> [comment]", or the same with a host name
// in front - the form ssh-keyscan and known_hosts use, which is what an operator has at hand.
func ParseSSHHostKey(line string) (SSHHostKey, error) {
	f := strings.Fields(line)
	if len(f) >= 3 && !sshHostKeyTypes[f[0]] && sshHostKeyTypes[f[1]] {
		f = f[1:]
	}
	if len(f) < 2 {
		return SSHHostKey{}, errors.New(`host key: want "<type> <base64>", one per line, as ssh-keyscan prints it`)
	}
	typ := f[0]
	if !sshHostKeyTypes[typ] {
		return SSHHostKey{}, fmt.Errorf("host key: unsupported key type %q", typ)
	}
	blob, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil {
		return SSHHostKey{}, fmt.Errorf("host key: the %s key is not base64", typ)
	}
	// sing-box would refuse a blob that is not one whole key at load, failing every exit with it.
	if !sshKeyBlobOK(typ, blob) {
		return SSHHostKey{}, fmt.Errorf("host key: the data is not a whole %s key; copy the whole line again", typ)
	}
	return SSHHostKey{Type: typ, Data: f[1]}, nil
}

// sshECDHCurves are the curves of the ECDSA host key types, for checking that a key's point is one.
var sshECDHCurves = map[string]ecdh.Curve{
	"ecdsa-sha2-nistp256": ecdh.P256(), "ecdsa-sha2-nistp384": ecdh.P384(), "ecdsa-sha2-nistp521": ecdh.P521(),
}

// sshKeyBlobOK reports whether blob is one whole public key of type typ in the SSH wire format, with
// nothing after it: what x/crypto's ParsePublicKey (behind the ParseAuthorizedKey sing-box reads
// host_key with) accepts. Checking only the type name at the head let through a key cut short when
// copied out of a terminal, or with bytes appended; it was saved and then failed every Apply with
// "no key found". The layouts are RFC 4253 section 6.6 (ssh-rsa, ssh-dss), RFC 5656 section 3.1
// (ECDSA) and RFC 8709 section 4 (Ed25519), with x/crypto's own checks on top: an RSA exponent of 3
// to 24 bits and odd, a 1024-bit DSA prime, an ECDSA point on its curve. Stricter than x/crypto in
// one place: an ECDSA blob whose curve is not the one its type names is refused (x/crypto reads it
// as a key of the other curve, which the pinned type would then misdescribe). Not done with
// x/crypto/ssh itself, which the daemon does not otherwise link: it adds 128 KiB to the router
// binary (linux/arm64 and mipsle, measured) for this one check, which the tests compare against it.
func sshKeyBlobOK(typ string, blob []byte) bool {
	w := sshWire{b: blob, ok: true}
	if string(w.next()) != typ {
		return false
	}
	ok := false
	switch typ {
	case "ssh-ed25519":
		ok = len(w.next()) == ed25519.PublicKeySize
	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		// crypto/ecdh takes exactly the uncompressed point on the curve that elliptic.Unmarshal,
		// which x/crypto uses, takes: 0x04 then both coordinates, 65, 97 or 133 bytes.
		if string(w.next()) == strings.TrimPrefix(typ, "ecdsa-sha2-") {
			_, err := sshECDHCurves[typ].NewPublicKey(w.next())
			ok = err == nil
		}
	case "ssh-rsa":
		e := sshMPInt(w.next())
		w.next() // the modulus: x/crypto takes any mpint
		ok = e.BitLen() <= 24 && e.Cmp(big.NewInt(3)) >= 0 && e.Bit(0) == 1
	case "ssh-dss":
		p := sshMPInt(w.next())
		w.next() // q
		w.next() // g
		w.next() // y
		ok = p.BitLen() == 1024
	}
	return ok && w.ok && len(w.b) == 0
}

// sshWire reads SSH strings (a uint32 length, then the bytes) off b. After the first read that does
// not fit, ok is false and every read returns nil.
type sshWire struct {
	b  []byte
	ok bool
}

func (w *sshWire) next() []byte {
	if !w.ok || len(w.b) < 4 || uint64(binary.BigEndian.Uint32(w.b)) > uint64(len(w.b)-4) {
		w.ok = false
		return nil
	}
	n := binary.BigEndian.Uint32(w.b)
	s := w.b[4 : 4+n]
	w.b = w.b[4+n:]
	return s
}

// sshMPInt reads an SSH mpint the way x/crypto does: two's complement, big-endian, so a set top bit
// is a negative number (which no exponent or prime may be).
func sshMPInt(b []byte) *big.Int {
	n := new(big.Int)
	if len(b) > 0 && b[0]&0x80 != 0 {
		inv := make([]byte, len(b))
		for i := range b {
			inv[i] = ^b[i]
		}
		return n.SetBytes(inv).Add(n, big.NewInt(1)).Neg(n)
	}
	return n.SetBytes(b)
}

// SSHHostKeys returns e's pinned host keys. Blank lines and # comments are skipped (ssh-keyscan
// prints its banner as one), so a pasted ssh-keyscan output is taken as it is.
func SSHHostKeys(e *Endpoint) ([]SSHHostKey, error) {
	lines, err := ParamLines(e.Params, "host_key")
	if err != nil {
		return nil, fmt.Errorf("host_key: %v", err)
	}
	var keys []SSHHostKey
	for _, l := range lines {
		if l = strings.TrimSpace(l); l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		k, err := ParseSSHHostKey(l)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// SSHHostKeyAlgorithms is the host key algorithms to offer for pinned keys, in x/crypto's own
// preference order. Without it the client offers every algorithm it knows, ECDSA first and Ed25519
// last, and a server that has both keys answers with the ECDSA one: pin only the Ed25519 line
// (ssh-keyscan -t ed25519) and every connection failed with "host key mismatch". An RSA key is
// offered with its SHA-2 signatures first; plain ssh-rsa stays last for servers older than
// OpenSSH 7.2, which sign with nothing else.
func SSHHostKeyAlgorithms(keys []SSHHostKey) []string {
	have := map[string]bool{}
	for _, k := range keys {
		have[k.Type] = true
	}
	order := []struct{ keyType, algo string }{
		{"ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256"},
		{"ecdsa-sha2-nistp384", "ecdsa-sha2-nistp384"},
		{"ecdsa-sha2-nistp521", "ecdsa-sha2-nistp521"},
		{"ssh-rsa", "rsa-sha2-256"},
		{"ssh-rsa", "rsa-sha2-512"},
		{"ssh-rsa", "ssh-rsa"},
		{"ssh-dss", "ssh-dss"},
		{"ssh-ed25519", "ssh-ed25519"},
	}
	var out []string
	for _, o := range order {
		if have[o.keyType] {
			out = append(out, o.algo)
		}
	}
	return out
}

// SSHPrivateKey is e's private key text. An imported sing-box config may hold it as a list of
// lines (its private_key is "listable"), which are joined the way sing-box joins them.
func SSHPrivateKey(e *Endpoint) string {
	lines, _ := ParamLines(e.Params, "private_key")
	return strings.TrimSpace(strings.ReplaceAll(strings.Join(lines, "\n"), "\r\n", "\n"))
}

// ParamLines reads a list param: a list of strings, or one string holding a line per entry (what a
// textarea sends). Absent is empty; anything else is an error.
func ParamLines(p map[string]any, key string) ([]string, error) {
	switch v := p[key].(type) {
	case nil:
		return nil, nil
	case string:
		if strings.TrimSpace(v) == "" {
			return nil, nil
		}
		return strings.Split(strings.ReplaceAll(v, "\r\n", "\n"), "\n"), nil
	case []string:
		return v, nil
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			s, ok := x.(string)
			if !ok {
				return nil, errors.New("want a list of strings")
			}
			out = append(out, s)
		}
		return out, nil
	}
	return nil, errors.New("want a list of strings")
}

// sshMissingAuth reports an SSH endpoint with neither a password nor a private key. sing-box loads
// it, and the server then refuses every login: nothing could ever make it work, so it is refused
// when saved rather than left as an exit that never comes up.
func sshMissingAuth(e *Endpoint) bool {
	pw, _ := e.Params["password"].(string)
	return strings.TrimSpace(pw) == "" && SSHPrivateKey(e) == ""
}

// sshParamProblem names what sing-box would refuse in an SSH endpoint's present params, or a client
// version no server would answer (it is sent as the first line of every handshake), or "". None of
// the messages quote a key or the passphrase. A passphrase with no key is left alone: sing-box reads
// it only with a key, and the generator writes it only then.
func sshParamProblem(e *Endpoint) string {
	if _, err := SSHHostKeys(e); err != nil {
		return err.Error()
	}
	if key := SSHPrivateKey(e); key != "" {
		pass, _ := e.Params["private_key_passphrase"].(string)
		if p := sshPrivateKeyProblem(key, pass != ""); p != "" {
			return p
		}
	}
	// The user goes into the login request as it is: a line break or another control character in it
	// (an ssh://us%0Aer@ link decodes to one) is no name any server has, so it is refused like the
	// client version's, rather than saved as an exit that can never log in.
	if u, ok := e.Params["user"].(string); ok && strings.IndexFunc(u, unicode.IsControl) >= 0 {
		return "user must not contain a line break or other control character"
	}
	if v, ok := e.Params["client_version"].(string); ok && v != "" {
		if !strings.HasPrefix(v, "SSH-2.0-") || len(v) > 253 || strings.IndexFunc(v, func(r rune) bool { return r < 0x20 || r > 0x7e }) >= 0 {
			return `client_version must be an SSH-2.0 identification string, e.g. "SSH-2.0-OpenSSH_9.6"`
		}
	}
	for _, k := range []string{"cipher", "mac", "kex_algorithm"} {
		if _, err := ParamLines(e.Params, k); err != nil {
			return k + ": " + err.Error()
		}
	}
	return ""
}

// sshPrivateKeyProblem checks a private key the way golang.org/x/crypto/ssh reads it (sing-box's
// ParsePrivateKey, or ParsePrivateKeyWithPassphrase when a passphrase is set), without decrypting
// it: the PEM types it parses, and the passphrase present exactly when the key is encrypted. Both
// mismatches are load errors there ("passphrase missing" / "key is not password protected"), so
// they would fail every exit. A wrong passphrase, or a corrupt key body, can only be found by
// decrypting; Apply's sing-box check finds those.
func sshPrivateKeyProblem(key string, havePassphrase bool) string {
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		return "private_key is not a PEM private key (-----BEGIN ... PRIVATE KEY-----)"
	}
	var encrypted bool
	switch block.Type {
	case "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY", "PRIVATE KEY":
		encrypted = strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED")
	case "OPENSSH PRIVATE KEY":
		enc, ok := openSSHKeyEncrypted(block.Bytes)
		if !ok {
			return "private_key is not a valid OpenSSH private key"
		}
		encrypted = enc
	case "ENCRYPTED PRIVATE KEY":
		return "private_key: an encrypted PKCS#8 key cannot be read; save it in the OpenSSH format with ssh-keygen -p -f <key file>"
	default:
		return fmt.Sprintf("private_key: unsupported key type %q", block.Type)
	}
	if encrypted && !havePassphrase {
		return "private_key is encrypted: enter its passphrase"
	}
	if !encrypted && havePassphrase {
		return "private_key_passphrase is set, but the key is not encrypted: clear the passphrase"
	}
	return ""
}

// openSSHKeyEncrypted reads the cipher and KDF names at the head of an openssh-key-v1 blob (the
// PROTOCOL.key layout: magic, then the cipher name and the KDF name as SSH strings). ok is false
// when the blob is not one.
func openSSHKeyEncrypted(b []byte) (encrypted, ok bool) {
	const magic = "openssh-key-v1\x00"
	if len(b) < len(magic) || string(b[:len(magic)]) != magic {
		return false, false
	}
	w := sshWire{b: b[len(magic):], ok: true}
	cipher, kdf := string(w.next()), string(w.next())
	if !w.ok {
		return false, false
	}
	return cipher != "none" || kdf != "none", true
}
