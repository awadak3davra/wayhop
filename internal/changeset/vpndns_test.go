package changeset

import (
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/model"
)

// Turning on one of a VPN resolver's switches is a resolver change in the review, said without the
// resolver's details like any other, and undoing it puts the switch back.
func TestDiff_VPNResolverSwitchRowAndUndo(t *testing.T) {
	plane := func(def bool) *model.DNSSettings {
		return &model.DNSSettings{Enabled: true, Final: "doh", Servers: []model.DNSServer{
			{Tag: "doh", Type: "https", Server: "192.0.2.53", Enabled: true},
			{Tag: "office-dns", Type: "openvpn", Endpoint: "ovpn", AcceptDefaultResolvers: def, Enabled: true},
		}}
	}
	base := model.Profile{DNS: plane(false)}
	desired := model.Profile{DNS: plane(true)}
	cs := Diff("", "", base, desired, config.Config{}, config.Config{})
	row := find(t, cs, "dns", "Resolvers")
	if row.Before != SecretSet || row.After != SecretChanged || row.Subsystem != SubDNS {
		t.Fatalf("row = %+v", row)
	}
	gotP, gotC, err := Undo(base, desired, config.Config{}, config.Config{}, reqFor(row))
	if err != nil {
		t.Fatal(err)
	}
	if gotP.DNS.Servers[1].AcceptDefaultResolvers {
		t.Error("undo kept the switch on")
	}
	if after := Diff("", "", base, gotP, config.Config{}, gotC); hasRow(after, row) {
		t.Errorf("the row is still pending after undo: %+v", after.Changes)
	}
}
