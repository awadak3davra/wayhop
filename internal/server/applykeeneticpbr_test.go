package server

import (
	"strings"
	"testing"
)

func keeneticPBRTestTools() executionKernelIpsetArtifactV1 {
	id := func(tool, path, version string, fill byte) ExecutionToolIdentityV1 {
		return ExecutionToolIdentityV1{
			Tool: tool, ResolvedPath: path, ContentSHA256: strings.Repeat(string(fill), 64),
			Version: version, Runnable: true,
		}
	}
	return executionKernelIpsetArtifactV1{
		IpsetTool:    id(executionToolIpset, "/opt/sbin/ipset", "ipset v7.24", '1'),
		IptablesTool: id(executionToolIptables, "/opt/sbin/iptables", "iptables v1.4.21", '2'),
		IP6Tool:      id(executionToolIp6tables, "/opt/sbin/ip6tables", "ip6tables v1.4.21", '3'),
		IPTool:       id(executionToolIP, "/opt/bin/busybox", executionBusyBoxIPVersion, '4'),
		DnsmasqTool:  id(executionToolDnsmasq, "/opt/sbin/dnsmasq", "Dnsmasq version 2.92", '5'),
		ShellTool:    id(executionToolShell, "/opt/bin/sh", "BusyBox v1.37.0", '6'),
	}
}

func TestKeeneticPBRPreamblePinsEveryToolToItsAuthenticatedPath(t *testing.T) {
	preamble, err := keeneticPBRPreamble(keeneticPBRTestTools())
	if err != nil {
		t.Fatal(err)
	}
	// The body of render_ipset.go calls these by bare name. Each must resolve to the probed binary
	// and nothing else, which is the guarantee the argv runner gives the nft plane for free.
	for _, want := range []string{
		"ipset() { /opt/sbin/ipset \"$@\"; }",
		"iptables() { /opt/sbin/iptables \"$@\"; }",
		"ip6tables() { /opt/sbin/ip6tables \"$@\"; }",
	} {
		if !strings.Contains(preamble, want) {
			t.Fatalf("preamble is missing %q:\n%s", want, preamble)
		}
	}
	// BusyBox multicall needs the applet name as argv[1]; /opt/sbin/ip is a symlink to it on a real
	// Keenetic, so a pin that forgot this would exec busybox with no applet and install nothing.
	if !strings.Contains(preamble, "ip() { /opt/bin/busybox ip \"$@\"; }") {
		t.Fatalf("BusyBox ip applet is not pinned:\n%s", preamble)
	}
}

func TestKeeneticPBRPreambleRefusesAnUnauthenticatedPath(t *testing.T) {
	tools := keeneticPBRTestTools()
	tools.IptablesTool.ResolvedPath = "iptables" // relative: PATH would decide which binary runs
	if _, err := keeneticPBRPreamble(tools); err == nil {
		t.Fatal("a relative tool path produced a preamble")
	}
}

func TestValidExecutionKernelIpsetArtifactFailsClosed(t *testing.T) {
	base := keeneticPBRTestTools()
	base.Script = []byte("iptables -t mangle -N WR_PREROUTING\n")
	base.Teardown = []byte("iptables -t mangle -X WR_PREROUTING\n")
	base.SetNames = []string{"wr_ru_4"}
	base.DnsmasqConf = []byte{}
	if !validExecutionKernelIpsetArtifact(base) {
		t.Fatal("a complete IP-only artifact was rejected")
	}

	// dnsmasq only participates when the plan has domain zones, so a pure IP-CIDR plan must stay
	// installable on a router without it — but a config that IS present must carry its identity.
	noDnsmasq := base
	noDnsmasq.DnsmasqTool = ExecutionToolIdentityV1{}
	if !validExecutionKernelIpsetArtifact(noDnsmasq) {
		t.Fatal("an IP-only artifact required a dnsmasq identity")
	}
	withDomains := noDnsmasq
	withDomains.DnsmasqConf = []byte("ipset=/example.com/wr_ru_4\n")
	if validExecutionKernelIpsetArtifact(withDomains) {
		t.Fatal("domain sets were accepted without an authenticated dnsmasq")
	}

	// An empty program would install no chain while the ledger recorded ensure-present, and
	// postcheck would then confirm nothing as healthy.
	empty := base
	empty.Script = nil
	if validExecutionKernelIpsetArtifact(empty) {
		t.Fatal("an artifact with no script was accepted")
	}
}
