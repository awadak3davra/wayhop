package server

import (
	"strings"
	"testing"

	"wayhop/internal/initserver"
)

// An MTProto proxy comes back as a link for the phone: in the job result, never imported as a
// connection, and a run that produced only that link is a success, not "no client config".
func TestProvisionDemoMTProtoReturnsALinkNotAConnection(t *testing.T) {
	s := provision_newServer(t)
	job := s.jobs.New("provision", "")
	b := provisionReq{Name: "edge", Host: "203.0.113.7", Port: 22, User: "root",
		Protocols: []string{initserver.ProtoMTProto}}
	s.runProvision(job, b)

	v := provision_waitDone(t, job)
	if !v.OK {
		t.Fatalf("an MTProto-only run must succeed: %+v", v)
	}
	if n := len(s.store.Profile().Endpoints); n != 0 {
		t.Errorf("a tg://proxy link was imported as %d connection(s)", n)
	}
	links, _ := v.Result["share_links"].([]map[string]string)
	if len(links) != 1 || links[0]["proto"] != initserver.ProtoMTProto ||
		!strings.HasPrefix(links[0]["link"], "tg://proxy?server=203.0.113.7&port=8449&secret=ee") {
		t.Fatalf("share_links = %v", v.Result["share_links"])
	}
	if !strings.HasPrefix(links[0]["qr_svg"], "<svg") {
		t.Errorf("the link must come with its QR code for the phone's camera: %.40q", links[0]["qr_svg"])
	}
	if p, _ := v.Result["provisioned_protocols"].([]string); len(p) != 1 || p[0] != initserver.ProtoMTProto {
		t.Errorf("provisioned_protocols = %v", v.Result["provisioned_protocols"])
	}
}

// The link carries the proxy's secret, so the console echo drops it like a client config.
func TestRedactSecretsShareLink(t *testing.T) {
	out := redactSecrets("WR_PROTO=mtproto\n" + initserver.ShareLinkMarker + "tg://proxy?server=x&port=8449&secret=eeSECRET")
	if strings.Contains(out, "eeSECRET") || !strings.Contains(out, initserver.ShareLinkMarker+"<redacted>") {
		t.Errorf("share link not redacted:\n%s", out)
	}
}
