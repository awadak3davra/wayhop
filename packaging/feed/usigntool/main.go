// Command usigntool generates and uses signify/usign-compatible Ed25519 keys, so the feed
// pipeline can sign the opkg `Packages` index without depending on the `usign` C tool being
// installed on the CI runner. The on-device verifier (OpenWrt's `usign -V`, used by opkg) accepts
// these because the file formats are byte-identical to OpenBSD signify / OpenWrt usign:
//
//	pubkey  = base64( "Ed" | keynum[8] | pub[32] )
//	seckey  = base64( "Ed" | "BK" | kdfrounds[4]=0 | salt[16] | checksum[8] | keynum[8] | priv[64] )
//	sig     = base64( "Ed" | keynum[8] | sig[64] )
//
// kdfrounds=0 means the secret key is stored in cleartext (no bcrypt_pbkdf), which is what usign
// uses for unattended signing. checksum = SHA-512(priv)[:8]. Go's ed25519 private key is
// seed||pub (64 bytes) — exactly signify's seckey layout — and its public key is the 32-byte half.
//
// Usage:
//
//	usigntool genkey -comment "WayHop feed" -pub wayhop.pub -sec wayhop.sec
//	usigntool fingerprint -pub wayhop.pub                 # prints the 16-hex key id (feed key filename)
//	usigntool sign   -sec wayhop.sec -m Packages -out Packages.sig
//	usigntool verify -pub wayhop.pub -m Packages -sig Packages.sig
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
)

const pkalg = "Ed"

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "usigntool: "+format+"\n", a...)
	os.Exit(1)
}

// writeB64File writes a 2-line signify file: a comment line + the base64 blob.
func writeB64File(path, comment string, blob []byte) error {
	body := "untrusted comment: " + comment + "\n" + base64.StdEncoding.EncodeToString(blob) + "\n"
	return os.WriteFile(path, []byte(body), 0o600)
}

// readB64File returns the decoded blob from a signify 2-line file (the comment line is ignored).
func readB64File(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "untrusted comment:") {
			continue
		}
		return base64.StdEncoding.DecodeString(line)
	}
	return nil, fmt.Errorf("%s: no base64 payload line", path)
}

func genkey(args []string) {
	fs := flag.NewFlagSet("genkey", flag.ExitOnError)
	comment := fs.String("comment", "wayhop feed", "comment line written into both files")
	pubPath := fs.String("pub", "", "output public key path")
	secPath := fs.String("sec", "", "output secret key path")
	_ = fs.Parse(args)
	if *pubPath == "" || *secPath == "" {
		die("genkey needs -pub and -sec")
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		die("ed25519 keygen: %v", err)
	}
	keynum := make([]byte, 8)
	if _, err := rand.Read(keynum); err != nil {
		die("keynum: %v", err)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		die("salt: %v", err)
	}
	cksum := sha512.Sum512(priv)

	// secret blob: "Ed" | "BK" | rounds[4]=0 | salt[16] | checksum[8] | keynum[8] | priv[64]
	sec := make([]byte, 0, 2+2+4+16+8+8+64)
	sec = append(sec, pkalg...)
	sec = append(sec, "BK"...)
	sec = append(sec, make([]byte, 4)...) // kdfrounds = 0 (cleartext key)
	sec = append(sec, salt...)
	sec = append(sec, cksum[:8]...)
	sec = append(sec, keynum...)
	sec = append(sec, priv...)

	// public blob: "Ed" | keynum[8] | pub[32]
	pb := make([]byte, 0, 2+8+32)
	pb = append(pb, pkalg...)
	pb = append(pb, keynum...)
	pb = append(pb, pub...)

	if err := writeB64File(*secPath, *comment+" (secret)", sec); err != nil {
		die("write sec: %v", err)
	}
	if err := writeB64File(*pubPath, *comment, pb); err != nil {
		die("write pub: %v", err)
	}
	fmt.Println(hex.EncodeToString(keynum)) // fingerprint = feed key id / filename
}

func fingerprint(args []string) {
	fs := flag.NewFlagSet("fingerprint", flag.ExitOnError)
	pubPath := fs.String("pub", "", "public key path")
	_ = fs.Parse(args)
	blob, err := readB64File(*pubPath)
	if err != nil {
		die("read pub: %v", err)
	}
	if len(blob) != 2+8+32 || string(blob[:2]) != pkalg {
		die("not an Ed25519 usign public key")
	}
	fmt.Println(hex.EncodeToString(blob[2:10]))
}

func sign(args []string) {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	secPath := fs.String("sec", "", "secret key path")
	msgPath := fs.String("m", "", "message file to sign")
	outPath := fs.String("out", "", "output signature path")
	_ = fs.Parse(args)
	if *secPath == "" || *msgPath == "" || *outPath == "" {
		die("sign needs -sec, -m and -out")
	}
	blob, err := readB64File(*secPath)
	if err != nil {
		die("read sec: %v", err)
	}
	if len(blob) != 2+2+4+16+8+8+64 || string(blob[:2]) != pkalg {
		die("not an Ed25519 usign secret key")
	}
	if r := binary.BigEndian.Uint32(blob[4:8]); r != 0 {
		die("secret key is passphrase-protected (kdfrounds=%d); this tool only handles cleartext keys", r)
	}
	keynum := blob[2+2+4+16+8 : 2+2+4+16+8+8]
	priv := ed25519.PrivateKey(blob[2+2+4+16+8+8:])

	msg, err := os.ReadFile(*msgPath)
	if err != nil {
		die("read message: %v", err)
	}
	sig := ed25519.Sign(priv, msg)

	out := make([]byte, 0, 2+8+64)
	out = append(out, pkalg...)
	out = append(out, keynum...)
	out = append(out, sig...)
	if err := writeB64File(*outPath, "signed by wayhop feed key "+hex.EncodeToString(keynum), out); err != nil {
		die("write sig: %v", err)
	}
}

func verify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	pubPath := fs.String("pub", "", "public key path")
	msgPath := fs.String("m", "", "message file")
	sigPath := fs.String("sig", "", "signature path")
	_ = fs.Parse(args)
	pubBlob, err := readB64File(*pubPath)
	if err != nil {
		die("read pub: %v", err)
	}
	sigBlob, err := readB64File(*sigPath)
	if err != nil {
		die("read sig: %v", err)
	}
	if len(pubBlob) != 42 || len(sigBlob) != 74 {
		die("malformed pub/sig")
	}
	if string(pubBlob[2:10]) != string(sigBlob[2:10]) {
		die("verification failed: signature key id does not match the public key")
	}
	msg, err := os.ReadFile(*msgPath)
	if err != nil {
		die("read message: %v", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pubBlob[10:]), msg, sigBlob[10:]) {
		die("verification failed: bad signature")
	}
	fmt.Println("OK")
}

func main() {
	if len(os.Args) < 2 {
		die("usage: usigntool genkey|fingerprint|sign|verify ...")
	}
	switch os.Args[1] {
	case "genkey":
		genkey(os.Args[2:])
	case "fingerprint":
		fingerprint(os.Args[2:])
	case "sign":
		sign(os.Args[2:])
	case "verify":
		verify(os.Args[2:])
	default:
		die("unknown subcommand %q", os.Args[1])
	}
}
