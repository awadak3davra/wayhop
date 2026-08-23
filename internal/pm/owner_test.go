package pm

import "testing"

// The inputs are verbatim `apk info --who-owns` answers from the OpenWrt 25.12.2 test box, not
// invented shapes — the naming rule is the thing under test and a made-up sample would only prove
// the rule against itself.
func TestSplitApkOwner_RealDeviceOutput(t *testing.T) {
	cases := []struct{ owner, name, version string }{
		{"busybox-1.37.0-r6", "busybox", "1.37.0-r6"},
		{"sing-box-1.12.17-r1", "sing-box", "1.12.17-r1"},
		{"nftables-json-1.1.6-r1", "nftables-json", "1.1.6-r1"},
		{"curl-8.19.0-r1", "curl", "8.19.0-r1"},
		// A name whose own segment ends in a digit: the dash before "proxy2" is followed by a
		// letter, so the version still starts at "-2.1.5".
		{"dnscrypt-proxy2-2.1.5-r1", "dnscrypt-proxy2", "2.1.5-r1"},
		// Already bare.
		{"wayhop", "wayhop", ""},
	}
	for _, c := range cases {
		n, v := SplitApkOwner(c.owner)
		if n != c.name || v != c.version {
			t.Errorf("SplitApkOwner(%q) = (%q, %q), want (%q, %q)", c.owner, n, v, c.name, c.version)
		}
		if !ValidPkgName(n) {
			t.Errorf("SplitApkOwner(%q) produced %q, which would be refused as a package name", c.owner, n)
		}
	}
}

// The two naive splits, spelled out so a future edit cannot quietly adopt one: cutting at the last
// dash keeps the version in the name, cutting at the first loses half the name.
func TestSplitApkOwner_RejectsTheObviousWrongRules(t *testing.T) {
	n, _ := SplitApkOwner("sing-box-1.12.17-r1")
	if n == "sing-box-1.12.17" {
		t.Fatal("cut at the last dash: the version is still in the package name")
	}
	if n == "sing" {
		t.Fatal("cut at the first dash: half the package name was lost")
	}
}

func TestPackageName_OnlyApkNeedsTheSplit(t *testing.T) {
	if got := (Manager{Kind: Apk}).PackageName("sing-box-1.12.17-r1"); got != "sing-box" {
		t.Fatalf("apk PackageName = %q", got)
	}
	// opkg's `search` already answers with a bare name; splitting it would corrupt a name that
	// legitimately ends in a digit group.
	if got := (Manager{Kind: Opkg}).PackageName("sing-box"); got != "sing-box" {
		t.Fatalf("opkg PackageName = %q", got)
	}
}
