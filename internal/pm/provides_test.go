package pm

import (
	"context"
	"testing"
)

// Verbatim `opkg whatprovides sing-box` from the Keenetic. The indentation and the header line are
// the parser's whole job; a trimmed sample would test the trimming rather than the format.
const whatProvidesOut = "What provides sing-box\n    sing-box-go\n"

func TestResolve_Opkg_FindsTheProvidingPackage(t *testing.T) {
	f := &fakeRunner{out: whatProvidesOut}
	m := Manager{Kind: Opkg, Runner: f}
	got, found, err := m.Resolve(context.Background(), "sing-box")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !found || got != "sing-box-go" {
		t.Fatalf("Resolve = (%q, %v), want (sing-box-go, true)", got, found)
	}
	if want := []string{"opkg", "whatprovides", "sing-box"}; !equal(f.argv, want) {
		t.Fatalf("argv = %v, want %v", f.argv, want)
	}
}

// A provider identical to the name asked about is the same package, not a redirect. Reporting it as
// one would make the caller believe it had learned something and swap a name for itself.
func TestResolve_SelfIsNotAResolution(t *testing.T) {
	f := &fakeRunner{out: "What provides curl\n    curl\n"}
	m := Manager{Kind: Opkg, Runner: f}
	got, found, err := m.Resolve(context.Background(), "curl")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if found || got != "" {
		t.Fatalf("Resolve = (%q, %v), want no resolution", got, found)
	}
}

func TestResolve_NothingProvidesIt(t *testing.T) {
	f := &fakeRunner{out: "What provides zzz-nothing\n"}
	m := Manager{Kind: Opkg, Runner: f}
	_, found, err := m.Resolve(context.Background(), "zzz-nothing")
	if err != nil || found {
		t.Fatalf("Resolve = (found %v, err %v), want (false, nil)", found, err)
	}
}

// apk has the same trap, and both of these are verbatim from the AX3000T.
//
// A VIRTUAL name: `apk list libustream-openssl` is empty while the package exists under another
// name, so a feed-existence check refuses an install apk can perform.
func TestResolve_Apk_ResolvesAVirtualName(t *testing.T) {
	f := &fakeRunner{out: "libustream-openssl20201210-2026.03.01~99f1c0db-r1\n"}
	m := Manager{Kind: Apk, Runner: f}
	got, found, err := m.Resolve(context.Background(), "libustream-openssl")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !found || got != "libustream-openssl20201210" {
		t.Fatalf("Resolve = (%q, %v), want the providing package", got, found)
	}
	if want := []string{"apk", "search", "--exact", "libustream-openssl"}; !equal(f.argv, want) {
		t.Fatalf("argv = %v, want %v", f.argv, want)
	}
}

// `--exact` is NOT exact. `apk search --exact sing-box` returns sing-box AND sing-box-tiny on the
// device, so "take the first line" would hand back a different package whenever the alphabet put a
// sibling first. A name that appears among the results under its own bare name is REAL and needs no
// resolution — that is the rule that survives both samples.
func TestResolve_Apk_ARealNameIsNotResolvedAway(t *testing.T) {
	f := &fakeRunner{out: "sing-box-1.12.17-r1\nsing-box-tiny-1.12.17-r1\n"}
	m := Manager{Kind: Apk, Runner: f}
	got, found, err := m.Resolve(context.Background(), "sing-box")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if found || got != "" {
		t.Fatalf("Resolve = (%q, %v) — a real package was redirected to a sibling", got, found)
	}
}

// And the sibling ordering reversed, so the test cannot pass merely because the real one came first.
func TestResolve_Apk_RealNameFoundEvenWhenNotFirst(t *testing.T) {
	f := &fakeRunner{out: "sing-box-tiny-1.12.17-r1\nsing-box-1.12.17-r1\n"}
	m := Manager{Kind: Apk, Runner: f}
	_, found, err := m.Resolve(context.Background(), "sing-box")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if found {
		t.Fatal("a real package was redirected because a sibling was listed first")
	}
}

func TestResolve_Apk_NothingAtAll(t *testing.T) {
	f := &fakeRunner{out: ""}
	m := Manager{Kind: Apk, Runner: f}
	_, found, err := m.Resolve(context.Background(), "zzz-no-such-package")
	if err != nil || found {
		t.Fatalf("Resolve = (found %v, err %v), want a clean no-answer", found, err)
	}
}

func TestResolve_RefusesUnsafeName(t *testing.T) {
	f := &fakeRunner{}
	m := Manager{Kind: Opkg, Runner: f}
	if _, _, err := m.Resolve(context.Background(), "../etc/passwd"); err == nil {
		t.Fatal("an unsafe name was accepted")
	}
	if f.argv != nil {
		t.Fatalf("an unsafe name reached the runner: %v", f.argv)
	}
}
