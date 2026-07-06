package initserver

import (
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

// A real (but throwaway) OpenSSH ed25519 host-key blob, base64-encoded — the second
// field of a known_hosts entry. Its exact bytes don't matter for the test; we only
// assert the fingerprint matches the manual SHA256(decoded) computation.
const sampleEd25519Blob = "AAAAC3NzaC1lZDI1NTE5AAAAIGb9ECWmEzf8FYYmqQRyDjHrFW8L4G+0kqYtL3a1Wd9Z"

func TestSSHFingerprintSHA256(t *testing.T) {
	fp, ok := sshFingerprintSHA256(sampleEd25519Blob)
	if !ok {
		t.Fatal("expected ok=true for a valid base64 blob")
	}
	raw, err := base64.StdEncoding.DecodeString(sampleEd25519Blob)
	if err != nil {
		t.Fatalf("test fixture is not valid base64: %v", err)
	}
	sum := sha256.Sum256(raw)
	want := "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
	if fp != want {
		t.Fatalf("fingerprint = %q, want %q", fp, want)
	}

	// A different blob must produce a different fingerprint.
	const otherBlob = "AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	other, ok := sshFingerprintSHA256(otherBlob)
	if !ok {
		t.Fatal("expected ok=true for the second valid base64 blob")
	}
	if other == fp {
		t.Fatal("distinct host-key blobs produced the same fingerprint")
	}

	// Garbage (invalid base64) must report ok=false, empty fp.
	if got, ok := sshFingerprintSHA256("!!! not base64 !!!"); ok || got != "" {
		t.Fatalf("garbage blob: got (%q, %v), want (\"\", false)", got, ok)
	}
}

func TestHostKeyFingerprint(t *testing.T) {
	const blob22 = sampleEd25519Blob
	const blob2200 = "AAAAC3NzaC1lZDI1NTE5AAAAIBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

	dir := t.TempDir()
	kh := filepath.Join(dir, "ssh_known_hosts")
	content := "# a comment line\n" +
		"1.2.3.4 ssh-ed25519 " + blob22 + "\n" +
		"[1.2.3.4]:2200 ssh-ed25519 " + blob2200 + "\n"
	if err := os.WriteFile(kh, []byte(content), 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}

	// port 22 → bare-host token → the first line's key.
	keytype, fp, ok := hostKeyFingerprint(kh, "1.2.3.4", 22)
	if !ok {
		t.Fatal("expected to find the port-22 entry")
	}
	if keytype != "ssh-ed25519" {
		t.Errorf("keytype = %q, want ssh-ed25519", keytype)
	}
	if want, _ := sshFingerprintSHA256(blob22); fp != want {
		t.Errorf("port-22 fp = %q, want %q", fp, want)
	}

	// port 2200 → "[host]:port" token → the second line's key (a DIFFERENT key).
	keytype2, fp2200, ok := hostKeyFingerprint(kh, "1.2.3.4", 2200)
	if !ok {
		t.Fatal("expected to find the [host]:2200 entry")
	}
	if keytype2 != "ssh-ed25519" {
		t.Errorf("keytype = %q, want ssh-ed25519", keytype2)
	}
	if want, _ := sshFingerprintSHA256(blob2200); fp2200 != want {
		t.Errorf("port-2200 fp = %q, want %q", fp2200, want)
	}
	if fp == fp2200 {
		t.Error("port-22 and port-2200 entries must yield different fingerprints")
	}

	// Absent host → ok=false.
	if _, _, ok := hostKeyFingerprint(kh, "9.9.9.9", 22); ok {
		t.Error("expected ok=false for an absent host")
	}

	// A non-22 port that has no [host]:port entry → ok=false (must NOT match the bare line).
	if _, _, ok := hostKeyFingerprint(kh, "1.2.3.4", 9999); ok {
		t.Error("expected ok=false: the bare-host line must not match a non-22 port query")
	}

	// Missing file → ok=false, no panic.
	if _, _, ok := hostKeyFingerprint(filepath.Join(dir, "does-not-exist"), "1.2.3.4", 22); ok {
		t.Error("expected ok=false for a missing known_hosts file")
	}
}

func TestProvisionSSHArgs(t *testing.T) {
	const kh = "/opt/etc/wayhop/ssh_known_hosts"

	// With KnownHostsFile set: the pinning options must be present.
	withKH := provisionSSHArgs(Creds{Host: "1.2.3.4", Port: 22, User: "root", KnownHostsFile: kh})
	if !hasOptPair(withKH, "-o", "UserKnownHostsFile="+kh) {
		t.Errorf("expected -o UserKnownHostsFile=%s in args: %v", kh, withKH)
	}
	if !hasOptPair(withKH, "-o", "HashKnownHosts=no") {
		t.Errorf("expected -o HashKnownHosts=no in args: %v", withKH)
	}

	// Without KnownHostsFile (backward-compat): the pinning options must be ABSENT.
	noKH := provisionSSHArgs(Creds{Host: "1.2.3.4", Port: 22, User: "root"})
	for _, a := range noKH {
		if a == "HashKnownHosts=no" || len(a) >= len("UserKnownHostsFile=") && a[:len("UserKnownHostsFile=")] == "UserKnownHostsFile=" {
			t.Errorf("KnownHostsFile empty but pinning option present: %q in %v", a, noKH)
		}
	}

	// Both forms must carry the common options + user@host + `sh -s`.
	for name, args := range map[string][]string{"withKH": withKH, "noKH": noKH} {
		if !hasOptPair(args, "-o", "StrictHostKeyChecking=accept-new") {
			t.Errorf("%s: missing StrictHostKeyChecking=accept-new: %v", name, args)
		}
		if !hasOptPair(args, "-o", "ConnectTimeout=15") {
			t.Errorf("%s: missing ConnectTimeout=15: %v", name, args)
		}
		if !contains(args, "root@1.2.3.4") {
			t.Errorf("%s: missing user@host: %v", name, args)
		}
		if !contains(args, "sh -s") {
			t.Errorf("%s: missing `sh -s`: %v", name, args)
		}
	}

	// Default port 22 when Port==0, and the non-22 token form is NOT used in argv
	// (the port is passed via -p, not user@host).
	dflt := provisionSSHArgs(Creds{Host: "1.2.3.4", User: "root"})
	if !hasOptPair(dflt, "-p", "22") {
		t.Errorf("expected default -p 22 when Port==0: %v", dflt)
	}

	// Defense-in-depth: a "--" end-of-options marker must immediately precede the user@host
	// destination so a leading-hyphen user/host can never be reparsed by ssh as an option (CWE-88).
	for name, args := range map[string][]string{"withKH": withKH, "noKH": noKH, "dflt": dflt} {
		guarded := false
		for i := 1; i < len(args); i++ {
			if args[i] == "root@1.2.3.4" && args[i-1] == "--" {
				guarded = true
				break
			}
		}
		if !guarded {
			t.Errorf("%s: destination not preceded by a `--` end-of-options marker: %v", name, args)
		}
	}
}

func hasOptPair(args []string, flag, val string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == val {
			return true
		}
	}
	return false
}

func contains(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}
