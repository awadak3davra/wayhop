package initserver

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestBuildScriptAmneziaWG(t *testing.T) {
	s := BuildScript([]string{ProtoAmneziaWG}, "")
	for _, want := range []string{"#!/bin/sh", "awg genkey", "amneziawg", "apt-get", "WR_CLIENT_CONFIG_B64="} {
		if !strings.Contains(s, want) {
			t.Errorf("AmneziaWG script missing %q", want)
		}
	}
}

func TestBuildScriptReality(t *testing.T) {
	s := BuildScript([]string{ProtoReality}, "1.2.3.4")
	for _, want := range []string{"sing-box generate reality-keypair", "WR_CLIENT_CONFIG=vless://", `PUBLIC_IP="1.2.3.4"`} {
		if !strings.Contains(s, want) {
			t.Errorf("Reality script missing %q", want)
		}
	}
}

func TestBuildScriptBoth(t *testing.T) {
	s := BuildScript([]string{ProtoAmneziaWG, ProtoReality}, "")
	if !strings.Contains(s, "awg genkey") || !strings.Contains(s, "sing-box generate") {
		t.Fatal("combined script missing one protocol")
	}
}

func TestExtractConfig(t *testing.T) {
	link := "vless://uuid@1.2.3.4:443?security=reality#velinx"
	if got := ExtractConfig("log line\nWR_CLIENT_CONFIG=" + link + "\nmore"); got != link {
		t.Fatalf("vless extract=%q", got)
	}
	conf := "[Interface]\nPrivateKey = k\n[Peer]\nEndpoint = 1.2.3.4:51820"
	b64 := base64.StdEncoding.EncodeToString([]byte(conf))
	if got := ExtractConfig("log\nWR_CLIENT_CONFIG_B64=" + b64 + "\n"); got != conf {
		t.Fatalf("awg extract=%q", got)
	}
	if got := ExtractConfig("just logs, no marker"); got != "" {
		t.Fatalf("no-marker extract=%q, want empty", got)
	}
}
