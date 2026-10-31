package server

import (
	"strings"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/platform"
)

// TLS fragmentation happens only on connections the core makes itself: the review says so for a
// tunnelled list and for mixed/fast mode, and stays quiet where it works or where nothing is set.
func TestTLSFragmentFindings(t *testing.T) {
	p := &model.Profile{RoutingLists: []model.RoutingList{
		{ID: "yt", Name: "YouTube", Outbound: model.OutboundDirect, TLSFragment: model.TLSFragmentRecord, Enabled: true},
		{ID: "tun", Name: "Via NL", Outbound: "nl", TLSFragment: model.TLSFragmentRecord, Enabled: true},
		{ID: "off", Name: "Off", Outbound: model.OutboundDirect, TLSFragment: model.TLSFragmentRecord, Enabled: false},
		{ID: "plain", Name: "Plain", Outbound: model.OutboundDirect, Enabled: true},
	}}
	names := func(fs []PlanFinding) string {
		var out []string
		for _, f := range fs {
			if f.ID != "list.tls_fragment_unused" || f.Blocks != platform.BlocksNothing {
				t.Errorf("unexpected finding %+v", f)
			}
			out = append(out, f.Item)
		}
		return strings.Join(out, ",")
	}
	for mode, want := range map[string]string{
		"tun": "Via NL", "hybrid": "Via NL", "mixed": "YouTube,Via NL", "fast": "YouTube,Via NL",
	} {
		if got := names(tlsFragmentFindings(p, mode)); got != want {
			t.Errorf("%s mode: findings for %q, want %q", mode, got, want)
		}
	}
}
