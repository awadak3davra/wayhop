//go:build ignore

// keygen writes a THROWAWAY apk-tools v3 signing key pair (ECDSA P-256, the same key type as
// packaging/feed/keys/wayhop-apk.pem.pub and OpenWrt's own apk keys) for the package lifecycle
// gate scripts/check-awg-install.sh. Neither the OpenWrt rootfs images nor the pinned alpine image
// carry an openssl CLI, and the gate must not install one, so the key is made here instead.
//
// Test only: the keys it writes sign nothing that leaves the test run.
//
// Usage: go run ./packaging/awg/test/keygen.go <private.pem> <public.pem>
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: keygen <private.pem> <public.pem>")
		os.Exit(2)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fail(err)
	}
	priv, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		fail(err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		fail(err)
	}
	if err := os.WriteFile(os.Args[1], pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv}), 0o600); err != nil {
		fail(err)
	}
	if err := os.WriteFile(os.Args[2], pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}), 0o644); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "keygen:", err)
	os.Exit(1)
}
