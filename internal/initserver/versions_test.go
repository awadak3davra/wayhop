package initserver

import (
	"strings"
	"testing"
)

func TestExtractVersions(t *testing.T) {
	out := "some preamble\n" +
		"WR_ARCH=x86_64\n" +
		"WR_INSTALLED_SINGBOX=sing-box version 1.12.17 (go1.22)\n" +
		"WR_INSTALLED_AWG=1.0.20240306\n" +
		"WR_VERCHECK_DONE=1\n"
	m := ExtractVersions(out)
	if m["arch"] != "x86_64" {
		t.Errorf("arch = %q, want x86_64", m["arch"])
	}
	if m["singbox"] != "sing-box version 1.12.17 (go1.22)" {
		t.Errorf("singbox raw = %q", m["singbox"])
	}
	if m["awg"] != "1.0.20240306" {
		t.Errorf("awg = %q", m["awg"])
	}
	if !VerCheckRan(out) {
		t.Error("VerCheckRan should be true when WR_VERCHECK_DONE printed")
	}
	// a server with only sing-box present -> awg absent from the map (not "")
	only := "WR_ARCH=aarch64\nWR_INSTALLED_SINGBOX=1.12.0\nWR_VERCHECK_DONE=1\n"
	m2 := ExtractVersions(only)
	if _, ok := m2["awg"]; ok {
		t.Error("awg must be absent when not installed, not empty-string")
	}
	if VerCheckRan("ssh died mid-stream") {
		t.Error("VerCheckRan must be false without the done marker")
	}
}

func TestUpdateConfirmed(t *testing.T) {
	ok, v := UpdateConfirmed("downloading...\nWR_UPDATE_OK=sing-box version 1.13.0\ndone\n")
	if !ok || v != "sing-box version 1.13.0" {
		t.Errorf("UpdateConfirmed = (%v, %q)", ok, v)
	}
	if ok, _ := UpdateConfirmed("WR_UPDATE_ERR=download failed\n"); ok {
		t.Error("an error output must not confirm success")
	}
	if ok, _ := UpdateConfirmed(""); ok {
		t.Error("empty output must not confirm")
	}
}

func TestUpdateScriptFor(t *testing.T) {
	sb, ok := UpdateScriptFor("singbox", "1.12.17")
	if !ok || !strings.Contains(sb, "1.12.17") || !strings.Contains(sb, "SagerNet/sing-box") {
		t.Error("singbox script should embed the version + the official repo URL")
	}
	if !strings.Contains(sb, ".wayhop.bak") {
		t.Error("singbox update must back up the old binary")
	}
	awg, ok := UpdateScriptFor("awg", "")
	if !ok || !strings.Contains(awg, "apt-get install") {
		t.Error("awg script should run an apt upgrade")
	}
	if _, ok := UpdateScriptFor("mihomo", "1.0.0"); ok {
		t.Error("unknown binary must return ok=false")
	}
}
