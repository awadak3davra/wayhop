package nativedns

import (
	"errors"
	"strings"
	"testing"
)

const stockDnsmasqDHCP = `dhcp.@dnsmasq[0]=dnsmasq
dhcp.@dnsmasq[0].domainneeded='1'
dhcp.@dnsmasq[0].localise_queries='1'
dhcp.@dnsmasq[0].local='/lan/'
dhcp.@dnsmasq[0].domain='lan'
dhcp.@dnsmasq[0].port='53'
`

func stockRun(dhcp, resolv string) Runner {
	return func(name string, args ...string) (string, error) {
		j := strings.Join(args, " ")
		switch {
		case strings.Contains(j, "https-dns-proxy"):
			return "", errors.New("exit status 1")
		case strings.Contains(j, "show dhcp"):
			return dhcp, nil
		case name == "cat" && strings.Contains(j, "resolv.conf"):
			return resolv, nil
		}
		return "", nil
	}
}

func TestAdoptOpenWrtReadsTheResolvFile(t *testing.T) {
	nd, err := AdoptOpenWrt(stockRun(stockDnsmasqDHCP, "# Interface wan\nnameserver 1.1.1.1\nnameserver 9.9.9.9\nnameserver 127.0.0.1\n"))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range nd.Resolvers {
		got = append(got, r.Kind+":"+r.Address+":"+r.Source)
	}
	if strings.Join(got, " ") != "plain:1.1.1.1:dnsmasq.resolvfile plain:9.9.9.9:dnsmasq.resolvfile" {
		t.Fatalf("resolvers = %v", got)
	}

	// noresolv: dnsmasq ignores the file, and so does the page.
	nd, _ = AdoptOpenWrt(stockRun(stockDnsmasqDHCP+"dhcp.@dnsmasq[0].noresolv='1'\n", "nameserver 1.1.1.1\n"))
	for _, r := range nd.Resolvers {
		if r.Source == "dnsmasq.resolvfile" {
			t.Fatalf("noresolv still read the resolv file: %+v", r)
		}
	}

	// A server named in the config and also in the file is listed once.
	nd, _ = AdoptOpenWrt(stockRun(stockDnsmasqDHCP+"dhcp.@dnsmasq[0].server='8.8.8.8'\n", "nameserver 8.8.8.8\nnameserver 1.0.0.1\n"))
	count := map[string]int{}
	for _, r := range nd.Resolvers {
		count[r.Address]++
	}
	if count["8.8.8.8"] != 1 || count["1.0.0.1"] != 1 {
		t.Fatalf("resolvers = %+v", nd.Resolvers)
	}
}
