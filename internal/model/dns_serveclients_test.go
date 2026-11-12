package model

import (
	"strings"
	"testing"
)

func serveClientsDNS() *DNSSettings {
	return &DNSSettings{
		Enabled:      true,
		ServeClients: true,
		Servers: []DNSServer{
			{Tag: "secure", Type: "https", Server: "1.1.1.1", Detour: "grp", Enabled: true},
			{Tag: "local", Type: "local", Enabled: true},
		},
		Final: "secure",
	}
}

func TestValidateDNSServeClients(t *testing.T) {
	if err := dnsBase(serveClientsDNS()).ValidateDNS(); err != nil {
		t.Fatalf("valid client-serving DNS rejected: %v", err)
	}

	disabled := serveClientsDNS()
	disabled.Enabled = false
	if err := dnsBase(disabled).ValidateDNS(); err != nil {
		t.Fatalf("DNS disabled with ServeClients should be accepted: %v", err)
	}

	noEncrypted := serveClientsDNS()
	noEncrypted.Servers = []DNSServer{{Tag: "local", Type: "local", Enabled: true}}
	noEncrypted.Final = "local"
	disabledEncrypted := serveClientsDNS()
	disabledEncrypted.Servers[0].Enabled = false
	plaintextFinal := serveClientsDNS()
	plaintextFinal.Servers = append(plaintextFinal.Servers, DNSServer{Tag: "plain", Type: "udp", Server: "9.9.9.9", Enabled: true})
	plaintextFinal.Final = "plain"
	fakeipFinal := serveClientsDNS()
	fakeipFinal.Servers = append(fakeipFinal.Servers, DNSServer{Tag: "fake", Type: "fakeip", Inet4Range: "198.18.0.0/15", Enabled: true})
	fakeipFinal.Final = "fake"
	fakeipFinal.IndependentCache = true
	localFinal := serveClientsDNS()
	localFinal.Final = "local"
	implicitLocal := serveClientsDNS()
	implicitLocal.Final = ""
	implicitLocal.Servers[0], implicitLocal.Servers[1] = implicitLocal.Servers[1], implicitLocal.Servers[0]

	for _, tc := range []struct {
		name string
		dns  *DNSSettings
		want string
	}{
		{"no encrypted server", noEncrypted, "at least one enabled encrypted resolver"},
		{"only a disabled encrypted server", disabledEncrypted, "at least one enabled encrypted resolver"},
		{"plaintext final", plaintextFinal, `serve_clients requires an encrypted final resolver, but "plain" is "udp"`},
		{"fakeip final", fakeipFinal, `serve_clients requires an encrypted final resolver, but "fake" is "fakeip"`},
		{"local final", localFinal, `serve_clients requires an encrypted final resolver, but "local" is "local"`},
		{"implicit local default", implicitLocal, "serve_clients requires an encrypted default resolver"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := dnsBase(tc.dns).ValidateDNS()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want error containing %q", err, tc.want)
			}
		})
	}
}
