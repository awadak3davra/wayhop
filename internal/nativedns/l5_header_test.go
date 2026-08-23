package nativedns

import (
	"strings"
	"testing"
)

// TestRenderedHeaderDescribesTheFileItIsIn (L5): the generated dnsmasq file is read on the router,
// months later, with no panel beside it. Its own header is the only thing explaining it.
//
// It promised "strict-order => tunnel primaries are tried first" whatever the setting, while the
// directive was written only when StrictOrder was on. Without it dnsmasq asks every upstream at once
// and keeps the first reply, which can be the plaintext WAN resolver while an encrypted tunnel one is
// up — the opposite of the tier order the line above it advertises.
func TestRenderedHeaderDescribesTheFileItIsIn(t *testing.T) {
	res := []NativeResolver{{Kind: KindDoH, Address: "https://1.1.1.1/dns-query"}, {Kind: KindPlain, Address: "8.8.8.8"}}

	loose := RenderDnsmasqD(NativeDNS{Resolvers: res})
	if strings.Contains(loose, "strict-order =>") {
		t.Errorf("without the directive the header must not promise strict order:\n%s", loose)
	}
	if strings.Contains(loose, "\nstrict-order\n") {
		t.Errorf("and must not emit it either:\n%s", loose)
	}
	if !strings.Contains(loose, "keeps the first reply") {
		t.Errorf("it must say what dnsmasq actually does instead:\n%s", loose)
	}

	strict := RenderDnsmasqD(NativeDNS{Resolvers: res, StrictOrder: true})
	if !strings.Contains(strict, "strict-order =>") {
		t.Errorf("with the directive the explanation comes back:\n%s", strict)
	}
	if !strings.Contains(strict, "\nstrict-order\n") {
		t.Errorf("and the directive itself is emitted:\n%s", strict)
	}
	if strings.Contains(strict, "keeps the first reply") {
		t.Errorf("and the loose-order sentence must not linger:\n%s", strict)
	}

	// Unchanged either way: the tier line is what the file is about, and both forms still render the
	// upstreams themselves.
	for _, out := range []string{loose, strict} {
		if !strings.Contains(out, "Tier order: VPN-encrypted") || !strings.Contains(out, "server=8.8.8.8") {
			t.Errorf("the file still states its purpose and its upstreams:\n%s", out)
		}
	}
}
