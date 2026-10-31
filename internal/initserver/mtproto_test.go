package initserver

import (
	"encoding/hex"
	"strings"
	"testing"
)

// The installer fetches the pinned telemt build, refuses one that does not match its published
// digest, keeps the secret across re-runs, and prints the link with the fake-TLS secret.
func TestScriptMTProto(t *testing.T) {
	s := BuildScript([]string{ProtoMTProto}, "198.51.100.9")
	for _, want := range []string{
		"releases/download/" + TelemtVersion + "/telemt-${TMA}-linux-musl.tar.gz",
		"TMSUM=" + telemtSHA256["x86_64"], "TMSUM=" + telemtSHA256["aarch64"],
		`sha256sum -c -`, "refusing it",
		"[ -f /etc/telemt/wr-secret ] ||",
		"port = " + mtprotoPort, `tls_domain = "` + mtprotoCover + `"`, "tls = true", "enabled = false",
		"User=telemt", "systemctl is-active --quiet telemt",
		"WR_PROTO=mtproto", ShareLinkMarker + "tg://proxy?server=$PUBLIC_IP&port=" + mtprotoPort + "&secret=ee${TMSEC}${TMHEX}",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q", want)
		}
	}
	if strings.Contains(s, "WR_CLIENT_CONFIG") {
		t.Error("an MTProto run must not hand back a client config to import")
	}
	// Someone's own telemt is left alone: the check comes before anything stops or overwrites it.
	guard, stop := strings.Index(s, "not installed by WayHop"), strings.Index(s, "systemctl stop telemt")
	if guard < 0 || stop < 0 || guard > stop || !strings.Contains(s, "Description=telemt MTProto proxy (WayHop)") {
		t.Errorf("foreign-telemt guard at %d, stop at %d", guard, stop)
	}
	for arch, sum := range telemtSHA256 {
		if b, err := hex.DecodeString(sum); err != nil || len(b) != 32 {
			t.Errorf("%s digest is not a sha256: %q", arch, sum)
		}
	}
	if o := optionByID(ProtoMTProto); o == nil || o.Port != 8449 || !o.Detect("tg://proxy?server=x&port=1&secret=ee00") {
		t.Errorf("catalog entry = %+v", o)
	}
}

// Links are read with their protocol, and only tg:// links are taken.
func TestExtractShareLinks(t *testing.T) {
	out := strings.Join([]string{
		"[install] telemt ok",
		"WR_PROTO=mtproto",
		ShareLinkMarker + "tg://proxy?server=198.51.100.9&port=8449&secret=ee00ff",
		"WR_PROTO=vless-reality",
		"WR_CLIENT_CONFIG=vless://u@h:443#x",
		ShareLinkMarker + "https://example.com/not-a-telegram-link",
	}, "\n")
	got := ExtractShareLinks(out)
	if len(got) != 1 || got[0].Proto != ProtoMTProto || got[0].Link != "tg://proxy?server=198.51.100.9&port=8449&secret=ee00ff" {
		t.Errorf("links = %+v", got)
	}
	if cfgs := ExtractTagged(out); len(cfgs) != 1 || cfgs[0].Proto != "vless-reality" {
		t.Errorf("client configs = %+v (the share link must not be one)", cfgs)
	}
	// The fake-TLS secret is "ee" + the 16-byte secret + the cover domain in hex.
	if hex.EncodeToString([]byte(mtprotoCover)) != "7777772e62696e672e636f6d" {
		t.Error("cover domain hex changed; the demo link and docs quote it")
	}
}
