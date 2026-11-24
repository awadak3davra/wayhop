package server

import (
	"errors"
	"strings"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/nativedns"
	"wayhop/internal/pbr"
)

func TestKeeneticFastDNSEnabled(t *testing.T) {
	plan := &pbr.Plan{Zones: []pbr.Zone{{Name: "list_alpha", Domains: []string{"alpha.example"}}}}
	if !keeneticFastDNSEnabled(config.Config{}, plan) {
		t.Fatal("fast DNS enforcement is not on by default for a named plan")
	}
	off := false
	if keeneticFastDNSEnabled(config.Config{FastDNSEnforce: &off}, plan) {
		t.Fatal("fast_dns_enforce=false did not disable enforcement")
	}
	if keeneticFastDNSEnabled(config.Config{}, &pbr.Plan{}) {
		t.Fatal("an IP-only plan enabled DNS enforcement")
	}
}

func TestKeeneticFastResolverProblem(t *testing.T) {
	if got := keeneticFastResolverProblem(nil, nativedns.Answering{Process: "dnsmasq"}); got != "" {
		t.Fatalf("dnsmasq was rejected: %s", got)
	}
	if got := keeneticFastResolverProblem(nil, nativedns.Answering{Process: "sing-box"}); !strings.Contains(got, "not Entware dnsmasq") {
		t.Fatalf("wrong resolver problem: %q", got)
	}
	if got := keeneticFastResolverProblem(errors.New("missing binary"), nativedns.Answering{}); !strings.Contains(got, "missing binary") {
		t.Fatalf("usability problem was lost: %q", got)
	}
}

func TestKeeneticFastDNSArtifactRoundTrip(t *testing.T) {
	plan := &pbr.Plan{Mask: 0x00ff0000, Zones: []pbr.Zone{{
		Name: "list_alpha", Domains: []string{"alpha.example"}, Mark: 0x00020000,
	}}}
	io := keeneticPBROptions("eth3")
	io.DynamicDomainSets = true
	io.FastDNSEnforce = true
	io.LANIfaces = []string{"br1", "br0"}
	artifact, err := buildKeeneticKernelIpsetArtifact(plan, exactKernelOptions(), io, keeneticPBRTestTools())
	if err != nil {
		t.Fatal(err)
	}
	if !artifact.FastDNSEnforce || !strings.Contains(string(artifact.Script), "-i br1 -p udp --dport 53 -j REDIRECT") {
		t.Fatalf("fast enforcement missing from artifact:\n%s", artifact.Script)
	}
	whole := executionKernelArtifactV1{Plan: plan, Ipset: artifact}
	if !validExactKernelPresentIpsetArtifact(whole) {
		t.Fatal("a rendered enforcement artifact did not re-render exactly")
	}
	changed := *artifact
	changed.FastDNSEnforce = false
	whole.Ipset = &changed
	if validExactKernelPresentIpsetArtifact(whole) {
		t.Fatal("changing the enforcement mode passed exact validation")
	}
}
