package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	"wayhop/internal/pbr"
)

// HUNT-K #1: the IPv6 refusals are answered on ip6tables filter rebuilds, read by the postcheck (a
// router without ip6tables is not drift), deleted by the teardown and spared when the next plane keeps them.
func TestKeeneticFastDNSv6Refusals(t *testing.T) {
	plan := &pbr.Plan{Mask: 0x00ff0000, Zones: []pbr.Zone{{Name: "list_alpha", Domains: []string{"alpha.example"}, Mark: 0x00020000}}}
	io := keeneticPBROptions("eth3")
	io.DynamicDomainSets, io.FastDNSEnforce, io.LANIfaces = true, true, []string{"br0"}
	artifact, err := buildKeeneticKernelIpsetArtifact(plan, exactKernelOptions(), io, keeneticPBRTestTools())
	if err != nil {
		t.Fatal(err)
	}
	hook, err := renderKeeneticPBRHook(artifact.Script)
	if err != nil || !strings.Contains(hook, "filter:iptables|filter:ip6tables) ;;") {
		t.Fatalf("hook does not answer ip6tables filter rebuilds (%v):\n%s", err, hook)
	}
	var v6 []keeneticDNSRule
	for _, r := range keeneticDNSRules(artifact.Script) {
		if r.tool == "ip6tables" {
			v6 = append(v6, r)
		}
	}
	if len(v6) != 3 {
		t.Fatalf("v6 DNS rules parsed = %+v", v6)
	}
	// Postcheck: ip6tables -S prints the rule in its canonical form.
	dump6 := "-P FORWARD ACCEPT\n" +
		"-A FORWARD -i br0 -p tcp -m tcp --dport 853 -j REJECT --reject-with tcp-reset\n" +
		"-A FORWARD -i br0 -p tcp -m tcp --dport 53 -j REJECT --reject-with tcp-reset\n" +
		"-A FORWARD -i br0 -p udp -m udp --dport 53 -j REJECT --reject-with icmp6-port-unreachable\n"
	read := func(missing6 bool, v6err error) keeneticToolRun {
		return func(_ context.Context, _ string, name string, args ...string) (string, error) {
			joined := strings.Join(args, " ")
			switch {
			case name == executionToolIp6tables && strings.Contains(joined, "FORWARD"):
				if v6err != nil {
					return "", v6err
				}
				if missing6 {
					return "-P FORWARD ACCEPT\n", nil
				}
				return dump6, nil
			}
			return "", nil
		}
	}
	rules := keeneticDNSRules(artifact.Script)
	check := func(run keeneticToolRun) error {
		dumps := map[keeneticChainRef]string{}
		for _, r := range rules {
			if r.tool != "ip6tables" {
				continue
			}
			d, ok := dumps[r.keeneticChainRef]
			if !ok {
				out, err := run(context.Background(), "", executionToolIp6tables, "-w", "-t", r.table, "-S", r.chain)
				if err != nil {
					d = keeneticDumpUnread
				} else {
					d = out
				}
				dumps[r.keeneticChainRef] = d
			}
			if d != keeneticDumpUnread && !iptablesDumpHasRule(d, r.chain, r.spec) {
				return errors.New("missing " + r.spec)
			}
		}
		return nil
	}
	if err := check(read(false, nil)); err != nil {
		t.Fatalf("canonical dump did not match: %v", err)
	}
	if err := check(read(true, nil)); err == nil {
		t.Fatal("a dropped v6 refusal passed")
	}
	if err := check(read(false, errors.New("no ip6tables"))); err != nil {
		t.Fatalf("a router without ip6tables failed: %v", err)
	}
	program := keeneticTeardownProgram(*artifact)
	for _, r := range v6 {
		del := pbr.DeleteEveryCopy("ip6tables", r.table, r.chain, r.spec)
		if !strings.Contains(program, del) {
			t.Fatalf("teardown lacks %q", del)
		}
		if strings.Contains(keeneticTeardownProgramSparing(*artifact, artifact.Script), del) {
			t.Fatalf("a replacement keeping %q still deletes it", r.spec)
		}
	}
}

// HUNT-K #2: enforcement with no LAN interface to render it on is refused, not silently skipped.
func TestKeeneticFastEnforceRefusal(t *testing.T) {
	io := keeneticPBROptions("eth3")
	io.FastDNSEnforce = true
	if err := keeneticFastEnforceRefusal(io); err == nil || !strings.Contains(err.Error(), "LAN interfaces") {
		t.Fatalf("no LAN: %v", err)
	}
	io.LANIfaces = []string{"bad name"}
	if keeneticFastEnforceRefusal(io) == nil {
		t.Fatal("only invalid LAN names passed")
	}
	io.LANIfaces = []string{"br0"}
	if err := keeneticFastEnforceRefusal(io); err != nil {
		t.Fatal(err)
	}
	io.FastDNSEnforce, io.LANIfaces = false, nil
	if err := keeneticFastEnforceRefusal(io); err != nil {
		t.Fatal(err)
	}
}
