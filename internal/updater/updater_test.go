package updater

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestParseVersion(t *testing.T) {
	cases := map[string]string{
		"sing-box version 1.10.1\nenv: go1.22": "1.10.1",
		"Xray 1.8.4 (Xray, Penetrates...)":     "1.8.4",
		"Mihomo Meta v1.18.0 linux arm64":      "1.18.0",
		"no version here":                      "",
	}
	for in, want := range cases {
		if got := parseVersion(in); got != want {
			t.Errorf("parseVersion(%q)=%q want %q", in, got, want)
		}
	}
}

func TestMatchAsset(t *testing.T) {
	type c struct {
		name, arch string
		want       bool
	}
	for _, tc := range []c{
		{"sing-box-1.10.1-linux-mipsle.tar.gz", "mipsle", true},
		{"sing-box-1.10.1-linux-mipsle.tar.gz", "mips", false},
		{"sing-box-1.10.1-linux-amd64.tar.gz", "amd64", true},
		{"sing-box-1.10.1-linux-armv7.tar.gz", "arm", true},
		{"sing-box-1.10.1-linux-arm64.tar.gz", "arm", false},
		{"sing-box-1.10.1-linux-arm64.tar.gz", "arm64", true},
		{"Xray-linux-64.zip", "amd64", true},
		{"Xray-linux-arm64-v8a.zip", "arm64", true},
		{"Xray-linux-mips32le.zip", "mipsle", true},
		{"mihomo-linux-arm64-v1.18.0.gz", "arm64", true},
		{"mihomo-linux-arm64-v1.18.0.gz", "arm", false},
		{"hysteria-linux-mipsle", "mipsle", true},
		{"sing-box-1.10.1-linux-amd64.tar.gz.sha256", "amd64", false}, // checksum file excluded
		{"sing-box-1.10.1-windows-amd64.zip", "amd64", false},         // not linux
	} {
		if got := matchAsset(tc.name, tc.arch); got != tc.want {
			t.Errorf("matchAsset(%q,%q)=%v want %v", tc.name, tc.arch, got, tc.want)
		}
	}
}

func TestExtractGz(t *testing.T) {
	payload := []byte("FAKEBINARY")
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(payload)
	zw.Close()
	got, err := extractBinary("mihomo-linux-amd64-v1.0.0.gz", buf.Bytes(), "mihomo")
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("gz extract: %v / %q", err, got)
	}
}

func TestExtractTarGz(t *testing.T) {
	payload := []byte("SINGBOX")
	var tb bytes.Buffer
	zw := gzip.NewWriter(&tb)
	tw := tar.NewWriter(zw)
	tw.WriteHeader(&tar.Header{Name: "sing-box-1.0.0-linux-amd64/sing-box", Mode: 0o755, Size: int64(len(payload)), Typeflag: tar.TypeReg})
	tw.Write(payload)
	tw.Close()
	zw.Close()
	got, err := extractBinary("sing-box-1.0.0-linux-amd64.tar.gz", tb.Bytes(), "sing-box")
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("tar.gz extract: %v / %q", err, got)
	}
}

func TestExtractZip(t *testing.T) {
	payload := []byte("XRAYBIN")
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	w, _ := zw.Create("xray")
	w.Write(payload)
	zw.Close()
	got, err := extractBinary("Xray-linux-64.zip", zb.Bytes(), "xray")
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("zip extract: %v / %q", err, got)
	}
}

func TestVerifyDigest(t *testing.T) {
	data := []byte("hello")
	sum := sha256.Sum256(data)
	good := "sha256:" + hex.EncodeToString(sum[:])
	if err := verifyDigest(data, good); err != nil {
		t.Fatalf("good digest rejected: %v", err)
	}
	if err := verifyDigest(data, "sha256:deadbeef"); err == nil {
		t.Fatal("bad digest accepted")
	}
	if err := verifyDigest(data, ""); err != nil {
		t.Fatal("empty digest should be skipped (nil)")
	}
}
